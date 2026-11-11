//! Client engine, independent of any UI: keeps the session to the control
//! server alive and runs transfers. The desktop app is a thin shell around it.

pub mod crypto;
pub mod store;
pub mod transfer;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crypto::{key_fingerprint, Identity};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use store::{SavedSession, Settings};
use tokio::io::{split, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use transfer::{FileEntry, Manifest, Plan};
use transfer_proto::{
    read_frame, tls, write_frame, ApiError, Event, FriendStatus, Inbound, Outbound, RelayEndpoint,
    Request, Response,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BACKOFF_SECS: u64 = 30;
const PROGRESS_EVERY: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    LoggedOut,
    Connecting,
    Online,
}

#[derive(Debug, Clone, Serialize)]
pub struct Friend {
    pub username: String,
    pub status: FriendStatus,
    pub online: bool,
    /// Short code to compare with the friend over another channel.
    pub fingerprint: Option<String>,
    /// The server now reports a different key than the one pinned: transfers
    /// are blocked until the user trusts the new one.
    pub key_changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Incoming,
    WaitingPeer,
    Connecting,
    Running,
    Done,
    Failed,
    Declined,
    Cancelled,
}

impl TransferState {
    fn is_finished(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Declined | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferView {
    pub id: String,
    pub peer: String,
    pub sending: bool,
    pub state: TransferState,
    pub message: Option<String>,
    pub first_file: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub done_bytes: u64,
    /// Received file, once saved under its final name.
    pub saved_path: Option<PathBuf>,
    /// What to reveal in the file manager for this download.
    pub saved_location: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEvent {
    Connection { state: Connection, username: Option<String>, reason: Option<String> },
    Friends { friends: Vec<Friend> },
    FriendRequest { username: String },
    Transfer { transfer: TransferView },
    TransferRemoved { id: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub connection: Connection,
    pub username: Option<String>,
    pub friends: Vec<Friend>,
    pub transfers: Vec<TransferView>,
    pub settings: Settings,
    pub my_fingerprint: String,
}

struct ActiveTransfer {
    view: TransferView,
    files: Vec<FileEntry>,
    sources: Vec<PathBuf>,
    cancel: CancellationToken,
}

struct FriendRecord {
    info: Friend,
    key: Option<String>,
}

struct State {
    connection: Connection,
    username: Option<String>,
    friends: Vec<FriendRecord>,
    pins: HashMap<String, String>,
    transfers: HashMap<String, ActiveTransfer>,
    /// Offer ids already processed, so a replayed offer is not shown again.
    seen_offers: HashSet<String>,
    /// Pending friend requests already announced.
    announced: HashSet<String>,
    settings: Settings,
}

type PendingCalls = Mutex<HashMap<u64, oneshot::Sender<Result<Response, ApiError>>>>;

struct Link {
    tx: mpsc::Sender<Inbound>,
    pending: Arc<PendingCalls>,
}

struct Inner {
    dir: PathBuf,
    identity: Identity,
    events: mpsc::UnboundedSender<EngineEvent>,
    state: Mutex<State>,
    link: Mutex<Option<Link>>,
    supervisor: Mutex<Option<CancellationToken>>,
    next_call: AtomicU64,
}

#[derive(Clone)]
pub struct Engine {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Inner {
    fn emit(&self, event: EngineEvent) {
        let _ = self.events.send(event);
    }

    fn emit_connection(&self, reason: Option<String>) {
        let (state, username) = {
            let s = lock(&self.state);
            (s.connection, s.username.clone())
        };
        self.emit(EngineEvent::Connection { state, username, reason });
    }

    fn emit_friends(&self, state: &State) {
        let friends = state.friends.iter().map(|f| f.info.clone()).collect();
        self.emit(EngineEvent::Friends { friends });
    }

    fn update_transfer(&self, id: &str, change: impl FnOnce(&mut TransferView)) {
        let view = {
            let mut state = lock(&self.state);
            let Some(entry) = state.transfers.get_mut(id) else {
                return;
            };
            change(&mut entry.view);
            entry.view.clone()
        };
        self.emit(EngineEvent::Transfer { transfer: view });
    }

    /// Moves a transfer to a final state unless it already reached one.
    fn finish_transfer(&self, id: &str, state: TransferState, message: Option<String>) {
        self.update_transfer(id, |view| {
            if !view.state.is_finished() {
                view.state = state;
                view.message = message;
            }
        });
    }

    async fn call(&self, request: Request) -> Result<Response> {
        let (rx, tx, id) = {
            let link = lock(&self.link);
            let link = link.as_ref().context("not connected to the server")?;
            let id = self.next_call.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            lock(&link.pending).insert(id, tx);
            (rx, link.tx.clone(), id)
        };
        tx.send(Inbound::Req { id, body: request })
            .await
            .map_err(|_| anyhow!("not connected to the server"))?;
        let answer = timeout(CALL_TIMEOUT, rx)
            .await
            .context("the server is not responding")?
            .map_err(|_| anyhow!("lost the connection to the server"))?;
        Ok(answer?)
    }

    fn apply_friends(&self, list: Vec<transfer_proto::FriendInfo>) -> Result<()> {
        let mut state = lock(&self.state);
        let mut pins_dirty = false;
        let mut records = Vec::with_capacity(list.len());
        let mut new_requests = Vec::new();
        for friend in list {
            // First sight of an accepted friend pins their key.
            if let Some(key) = &friend.device_key {
                if !state.pins.contains_key(&friend.username) {
                    state.pins.insert(friend.username.clone(), key.clone());
                    pins_dirty = true;
                }
            }
            let key_changed = friend
                .device_key
                .as_ref()
                .is_some_and(|key| state.pins.get(&friend.username) != Some(key));
            let fingerprint = friend
                .device_key
                .as_ref()
                .and_then(|key| B64.decode(key).ok())
                .map(|key| key_fingerprint(&key));
            if friend.status == FriendStatus::Incoming
                && state.announced.insert(friend.username.clone())
            {
                new_requests.push(friend.username.clone());
            }
            records.push(FriendRecord {
                key: friend.device_key,
                info: Friend {
                    username: friend.username,
                    status: friend.status,
                    online: friend.online,
                    fingerprint,
                    key_changed,
                },
            });
        }
        state.friends = records;
        if pins_dirty {
            if let Some(username) = state.username.clone() {
                store::save_pins(&self.dir, &username, &state.pins)?;
            }
        }
        self.emit_friends(&state);
        drop(state);
        for username in new_requests {
            self.emit(EngineEvent::FriendRequest { username });
        }
        Ok(())
    }

    async fn refresh_friends(&self) -> Result<()> {
        match self.call(Request::Friends).await? {
            Response::Friends { friends } => self.apply_friends(friends),
            _ => bail!("unexpected response from the server"),
        }
    }

    /// The pinned key of a friend, refusing anyone unverified.
    fn trusted_key(&self, username: &str) -> Result<Vec<u8>> {
        let state = lock(&self.state);
        let friend = state
            .friends
            .iter()
            .find(|f| f.info.username == username && f.info.status == FriendStatus::Accepted)
            .ok_or_else(|| anyhow!("{username} is not in your friends list"))?;
        if friend.info.key_changed {
            bail!("{username}'s key has changed: verify it before transferring");
        }
        let key = friend.key.as_ref().context("friend's key not available")?;
        Ok(B64.decode(key)?)
    }

    fn me(&self) -> Result<String> {
        lock(&self.state).username.clone().context("you are not signed in")
    }

    async fn handle_offer(self: Arc<Self>, from: String, id: String, sealed: String) {
        if !lock(&self.state).seen_offers.insert(id.clone()) {
            return;
        }
        match self.open_offer(&from, &id, &sealed).await {
            Ok(manifest) => {
                let view = TransferView {
                    id: id.clone(),
                    peer: from,
                    sending: false,
                    state: TransferState::Incoming,
                    message: None,
                    first_file: manifest.files[0].path.clone(),
                    file_count: manifest.files.len(),
                    total_bytes: manifest.total_bytes(),
                    done_bytes: 0,
                    saved_path: None,
                    saved_location: None,
                };
                let entry = ActiveTransfer {
                    view: view.clone(),
                    files: manifest.files,
                    sources: Vec::new(),
                    cancel: CancellationToken::new(),
                };
                lock(&self.state).transfers.insert(id, entry);
                self.emit(EngineEvent::Transfer { transfer: view });
            }
            Err(e) => {
                tracing::warn!("offer from {from} rejected: {e:#}");
                let request = Request::OfferRespond { transfer_id: id, accept: false };
                let _ = self.call(request).await;
            }
        }
    }

    async fn open_offer(&self, from: &str, id: &str, sealed: &str) -> Result<Manifest> {
        // The friend list may lag behind, e.g. right after accepting a request.
        if self.trusted_key(from).is_err() {
            self.refresh_friends().await?;
        }
        let key = self.trusted_key(from)?;
        let me = self.me()?;
        let context = transfer::seal_context(id, from, &me);
        let plain = crypto::open(&self.identity, &key, &context, &B64.decode(sealed)?)?;
        let manifest: Manifest = serde_json::from_slice(&plain)?;
        if manifest.files.is_empty()
            || manifest.files.iter().any(|f| transfer::safe_relative_path(&f.path).is_none())
        {
            bail!("invalid file list");
        }
        Ok(manifest)
    }

    fn handle_event(self: &Arc<Self>, event: Event) {
        match event {
            Event::FriendsChanged => {
                let inner = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = inner.refresh_friends().await {
                        tracing::warn!("could not refresh friends: {e:#}");
                    }
                });
            }
            Event::Presence { username, online } => {
                let mut state = lock(&self.state);
                if let Some(f) = state.friends.iter_mut().find(|f| f.info.username == username) {
                    f.info.online = online;
                }
                self.emit_friends(&state);
            }
            Event::Offer { from, transfer_id, sealed } => {
                tokio::spawn(self.clone().handle_offer(from, transfer_id, sealed));
            }
            Event::OfferDeclined { transfer_id } => {
                self.finish_transfer(
                    &transfer_id,
                    TransferState::Declined,
                    Some("They declined the transfer".into()),
                );
            }
            Event::TransferReady { transfer_id, relay, ticket } => {
                tokio::spawn(self.clone().run_transfer(transfer_id, relay, ticket));
            }
            Event::TransferCancelled { transfer_id, reason } => {
                self.finish_transfer(&transfer_id, TransferState::Cancelled, Some(reason));
                if let Some(entry) = lock(&self.state).transfers.get(&transfer_id) {
                    entry.cancel.cancel();
                }
            }
            Event::SessionReplaced => {
                self.end_session(Some("You signed in on another device".into()));
            }
        }
    }

    fn plan_for(&self, id: &str) -> Result<(Plan, CancellationToken)> {
        let me = self.me()?;
        let state = lock(&self.state);
        let entry = state.transfers.get(id).context("unknown transfer")?;
        let peer = entry.view.peer.clone();
        let (sender, receiver) =
            if entry.view.sending { (me, peer.clone()) } else { (peer.clone(), me) };
        let plan = Plan {
            id: id.to_string(),
            sender,
            receiver,
            sending: entry.view.sending,
            peer_key: Vec::new(),
            files: entry.files.clone(),
            sources: entry.sources.clone(),
            dest: state.settings.download_dir.clone(),
        };
        Ok((plan, entry.cancel.clone()))
    }

    async fn run_transfer(self: Arc<Self>, id: String, relay: RelayEndpoint, ticket: String) {
        let Ok((mut plan, cancel)) = self.plan_for(&id) else {
            return;
        };
        let peer = if plan.sending { plan.receiver.clone() } else { plan.sender.clone() };
        plan.peer_key = match self.trusted_key(&peer) {
            Ok(key) => key,
            Err(e) => {
                self.finish_transfer(&id, TransferState::Failed, Some(e.to_string()));
                return;
            }
        };
        self.update_transfer(&id, |v| v.state = TransferState::Connecting);

        let last_emit = Mutex::new(Instant::now() - PROGRESS_EVERY);
        let total: u64 = plan.files.iter().map(|f| f.size).sum();
        let progress = |done: u64| {
            let mut last = lock(&last_emit);
            let due = done == 0 || done == total || last.elapsed() >= PROGRESS_EVERY;
            if due {
                *last = Instant::now();
                drop(last);
                self.update_transfer(&id, |v| {
                    if v.state == TransferState::Connecting {
                        v.state = TransferState::Running;
                    }
                    v.done_bytes = done;
                });
            }
        };
        let part = Mutex::new(None);
        let result = tokio::select! {
            _ = cancel.cancelled() => None,
            result = transfer::run(&self.identity, &plan, &relay, ticket, &progress, &part) => {
                Some(result)
            }
        };
        let leftover = lock(&part).take();
        if let Some(path) = leftover {
            transfer::remove_part(&path).await;
        }
        match result {
            Some(Ok(saved)) => {
                if let Some(path) = saved {
                    let location = transfer::saved_location(&plan.dest, &path, plan.files.len());
                    self.update_transfer(&id, |v| {
                        v.saved_path = Some(path);
                        v.saved_location = Some(location);
                    });
                }
                self.finish_transfer(&id, TransferState::Done, None);
            }
            Some(Err(e)) => {
                tracing::warn!("transfer {id} failed: {e:#}");
                self.finish_transfer(&id, TransferState::Failed, Some(format!("{e:#}")));
            }
            None => {}
        }
    }

    /// Stops reconnecting and forgets the local session.
    fn end_session(&self, reason: Option<String>) {
        if let Some(stop) = lock(&self.supervisor).take() {
            stop.cancel();
        }
        *lock(&self.link) = None;
        store::clear_session(&self.dir);
        let transfers: Vec<(String, CancellationToken)> = {
            let mut state = lock(&self.state);
            state.connection = Connection::LoggedOut;
            state.username = None;
            state.friends.clear();
            state.pins.clear();
            state.announced.clear();
            state.transfers.iter().map(|(id, t)| (id.clone(), t.cancel.clone())).collect()
        };
        for (id, cancel) in transfers {
            self.finish_transfer(&id, TransferState::Cancelled, Some("Signed out".into()));
            cancel.cancel();
        }
        self.emit_connection(reason);
        self.emit(EngineEvent::Friends { friends: Vec::new() });
    }

    /// A lost control connection also loses offers still waiting on the server;
    /// running tunnels keep going on their own connection.
    fn fail_pending_offers(&self) {
        let ids: Vec<String> = lock(&self.state)
            .transfers
            .iter()
            .filter(|(_, t)| {
                matches!(t.view.state, TransferState::Incoming | TransferState::WaitingPeer)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.finish_transfer(
                &id,
                TransferState::Failed,
                Some("Lost the connection to the server".into()),
            );
        }
    }

    fn set_connection(&self, connection: Connection) {
        lock(&self.state).connection = connection;
        self.emit_connection(None);
    }

    async fn supervise(self: Arc<Self>, session: SavedSession, stop: CancellationToken) {
        let mut backoff = 1;
        loop {
            self.set_connection(Connection::Connecting);
            match self.clone().connect_once(&session, &stop, &mut backoff).await {
                Ok(true) | Ok(false) if stop.is_cancelled() => return,
                Ok(true) => {}
                Ok(false) => {
                    self.end_session(Some("The session has expired".into()));
                    return;
                }
                Err(e) => tracing::info!("not connected to the server: {e:#}"),
            }
            *lock(&self.link) = None;
            self.fail_pending_offers();
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF_SECS);
        }
    }

    /// Runs one connection until it drops. `Ok(false)` means the server refused
    /// the session token.
    async fn connect_once(
        self: Arc<Self>,
        session: &SavedSession,
        stop: &CancellationToken,
        backoff: &mut u64,
    ) -> Result<bool> {
        let settings = lock(&self.state).settings.clone();
        let config = client_tls(&settings)?;
        let mut stream = timeout(CONNECT_TIMEOUT, tls::connect(&settings.server, config))
            .await
            .context("connection timed out")??;
        let resume = Request::Resume { token: session.token.clone() };
        write_frame(&mut stream, &Inbound::Req { id: 0, body: resume }).await?;
        loop {
            match timeout(CALL_TIMEOUT, read_frame::<_, Outbound>(&mut stream)).await?? {
                Outbound::Res { id: 0, body: Ok(_) } => break,
                Outbound::Res { id: 0, body: Err(ApiError::Unauthorized) } => return Ok(false),
                Outbound::Res { id: 0, body: Err(e) } => bail!(e),
                _ => {}
            }
        }

        let (mut reader, mut writer) = split(stream);
        let (tx, mut rx) = mpsc::channel::<Inbound>(64);
        let pending = Arc::new(PendingCalls::default());
        *lock(&self.link) = Some(Link { tx: tx.clone(), pending: pending.clone() });
        let closed = CancellationToken::new();
        let write_closed = closed.clone();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if write_frame(&mut writer, &message).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
            write_closed.cancel();
        });

        *backoff = 1;
        self.set_connection(Connection::Online);
        let inner = self.clone();
        tokio::spawn(async move {
            if let Err(e) = inner.refresh_friends().await {
                tracing::warn!("could not load friends: {e:#}");
            }
        });

        let mut ping = tokio::time::interval(PING_EVERY);
        loop {
            tokio::select! {
                _ = stop.cancelled() => return Ok(true),
                _ = closed.cancelled() => bail!("connection closed"),
                _ = ping.tick() => {
                    let _ = tx.try_send(Inbound::Req { id: 0, body: Request::Ping });
                }
                frame = timeout(READ_TIMEOUT, read_frame::<_, Outbound>(&mut reader)) => {
                    match frame?? {
                        Outbound::Res { id, body } => {
                            if let Some(waiter) = lock(&pending).remove(&id) {
                                let _ = waiter.send(body);
                            }
                        }
                        Outbound::Event { body } => self.handle_event(body),
                    }
                }
            }
        }
    }
}

fn client_tls(settings: &Settings) -> Result<Arc<transfer_proto::tls::ClientConfig>> {
    let pin = settings.fingerprint.trim();
    Ok(tls::client_config((!pin.is_empty()).then_some(pin))?)
}

impl Engine {
    /// Opens the data directory and, if a session was saved, reconnects.
    /// The caller must be inside a Tokio runtime.
    pub fn start(
        dir: &Path,
        default_downloads: PathBuf,
    ) -> Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
        std::fs::create_dir_all(dir)?;
        let identity = store::load_identity(dir)?;
        let settings = store::load_settings(dir).unwrap_or(Settings {
            server: "127.0.0.1:7443".into(),
            fingerprint: String::new(),
            download_dir: default_downloads,
        });
        let (events, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            dir: dir.to_path_buf(),
            identity,
            events,
            state: Mutex::new(State {
                connection: Connection::LoggedOut,
                username: None,
                friends: Vec::new(),
                pins: HashMap::new(),
                transfers: HashMap::new(),
                seen_offers: HashSet::new(),
                announced: HashSet::new(),
                settings,
            }),
            link: Mutex::new(None),
            supervisor: Mutex::new(None),
            next_call: AtomicU64::new(1),
        });
        let engine = Self { inner };
        if let Some(session) = store::load_session(dir) {
            engine.begin_session(session);
        }
        Ok((engine, rx))
    }

    fn begin_session(&self, session: SavedSession) {
        let stop = CancellationToken::new();
        {
            let mut state = lock(&self.inner.state);
            state.pins = store::load_pins(&self.inner.dir, &session.username);
            state.username = Some(session.username.clone());
            state.connection = Connection::Connecting;
        }
        if let Some(previous) = lock(&self.inner.supervisor).replace(stop.clone()) {
            previous.cancel();
        }
        tokio::spawn(self.inner.clone().supervise(session, stop));
    }

    async fn authenticate(&self, server: &str, fingerprint: &str, request: Request) -> Result<()> {
        let mut settings = lock(&self.inner.state).settings.clone();
        settings.server = server.trim().to_string();
        settings.fingerprint = tls::normalize_fingerprint(fingerprint);
        let config = client_tls(&settings)?;
        let mut stream = timeout(CONNECT_TIMEOUT, tls::connect(&settings.server, config))
            .await
            .context("the server is not responding")?
            .with_context(|| format!("could not connect to {}", settings.server))?;
        write_frame(&mut stream, &Inbound::Req { id: 1, body: request }).await?;
        let session = loop {
            match timeout(CALL_TIMEOUT, read_frame::<_, Outbound>(&mut stream))
                .await
                .context("the server is not responding")??
            {
                Outbound::Res { id: 1, body: Ok(Response::Session { username, token }) } => {
                    break SavedSession { username, token };
                }
                Outbound::Res { id: 1, body: Err(e) } => return Err(e.into()),
                Outbound::Res { id: 1, .. } => bail!("unexpected response from the server"),
                _ => {}
            }
        };
        let _ = stream.shutdown().await;

        store::save_settings(&self.inner.dir, &settings)?;
        store::save_session(&self.inner.dir, &session)?;
        lock(&self.inner.state).settings = settings;
        self.begin_session(session);
        Ok(())
    }

    pub async fn register(
        &self,
        server: &str,
        fingerprint: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let request = Request::Register {
            username: username.to_string(),
            password: password.to_string(),
            device_key: B64.encode(&self.inner.identity.public),
        };
        self.authenticate(server, fingerprint, request).await
    }

    pub async fn login(
        &self,
        server: &str,
        fingerprint: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let request = Request::Login {
            username: username.to_string(),
            password: password.to_string(),
            device_key: B64.encode(&self.inner.identity.public),
        };
        self.authenticate(server, fingerprint, request).await
    }

    pub async fn logout(&self) {
        let _ = self.inner.call(Request::Logout).await;
        self.inner.end_session(None);
    }

    pub async fn change_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        let request = Request::ChangePassword {
            old_password: old_password.to_string(),
            new_password: new_password.to_string(),
        };
        self.inner.call(request).await.map(|_| ())
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = lock(&self.inner.state);
        Snapshot {
            connection: state.connection,
            username: state.username.clone(),
            friends: state.friends.iter().map(|f| f.info.clone()).collect(),
            transfers: state.transfers.values().map(|t| t.view.clone()).collect(),
            settings: state.settings.clone(),
            my_fingerprint: key_fingerprint(&self.inner.identity.public),
        }
    }

    pub fn set_download_dir(&self, dir: PathBuf) -> Result<()> {
        let mut state = lock(&self.inner.state);
        state.settings.download_dir = dir;
        store::save_settings(&self.inner.dir, &state.settings)
    }

    pub async fn add_friend(&self, username: &str) -> Result<()> {
        self.inner.call(Request::FriendAdd { username: username.to_string() }).await?;
        self.inner.refresh_friends().await
    }

    pub async fn respond_friend(&self, username: &str, accept: bool) -> Result<()> {
        let request = Request::FriendRespond { username: username.to_string(), accept };
        self.inner.call(request).await?;
        lock(&self.inner.state).announced.remove(username);
        self.inner.refresh_friends().await
    }

    pub async fn remove_friend(&self, username: &str) -> Result<()> {
        self.inner.call(Request::FriendRemove { username: username.to_string() }).await?;
        self.inner.refresh_friends().await
    }

    /// Accepts the key the server now reports for a friend, after the user
    /// checked it over another channel.
    pub fn trust_key(&self, username: &str) -> Result<()> {
        let mut state = lock(&self.inner.state);
        let key = state
            .friends
            .iter()
            .find(|f| f.info.username == username)
            .and_then(|f| f.key.clone())
            .context("friend's key not available")?;
        state.pins.insert(username.to_string(), key);
        if let Some(friend) = state.friends.iter_mut().find(|f| f.info.username == username) {
            friend.info.key_changed = false;
        }
        let me = state.username.clone().context("you are not signed in")?;
        store::save_pins(&self.inner.dir, &me, &state.pins)?;
        self.inner.emit_friends(&state);
        Ok(())
    }

    /// Offers files or folders to a friend. Returns the transfer id.
    pub async fn send(&self, to: &str, paths: Vec<PathBuf>) -> Result<String> {
        let key = self.inner.trusted_key(to)?;
        let me = self.inner.me()?;
        let (manifest, sources) = tokio::task::spawn_blocking(move || transfer::scan(&paths))
            .await
            .context("error reading the files")??;
        let id = uuid::Uuid::new_v4().to_string();
        let context = transfer::seal_context(&id, &me, to);
        let plain = serde_json::to_vec(&manifest)?;
        let sealed = B64.encode(crypto::seal(&self.inner.identity, &key, &context, &plain)?);
        if sealed.len() > transfer_proto::MAX_SEALED {
            bail!("too many files in a single transfer");
        }

        let view = TransferView {
            id: id.clone(),
            peer: to.to_string(),
            sending: true,
            state: TransferState::WaitingPeer,
            message: None,
            first_file: manifest.files[0].path.clone(),
            file_count: manifest.files.len(),
            total_bytes: manifest.total_bytes(),
            done_bytes: 0,
            saved_path: None,
            saved_location: None,
        };
        let entry = ActiveTransfer {
            view: view.clone(),
            files: manifest.files,
            sources,
            cancel: CancellationToken::new(),
        };
        lock(&self.inner.state).transfers.insert(id.clone(), entry);
        self.inner.emit(EngineEvent::Transfer { transfer: view });

        let request =
            Request::Offer { to: to.to_string(), transfer_id: id.clone(), sealed };
        if let Err(e) = self.inner.call(request).await {
            self.inner.finish_transfer(&id, TransferState::Failed, Some(e.to_string()));
            return Err(e);
        }
        Ok(id)
    }

    pub async fn accept(&self, id: &str) -> Result<()> {
        self.inner.update_transfer(id, |v| v.state = TransferState::Connecting);
        let request = Request::OfferRespond { transfer_id: id.to_string(), accept: true };
        if let Err(e) = self.inner.call(request).await {
            self.inner.finish_transfer(id, TransferState::Failed, Some(e.to_string()));
            return Err(e);
        }
        Ok(())
    }

    pub async fn decline(&self, id: &str) -> Result<()> {
        self.inner.finish_transfer(id, TransferState::Declined, None);
        let request = Request::OfferRespond { transfer_id: id.to_string(), accept: false };
        self.inner.call(request).await.map(|_| ())
    }

    pub async fn cancel(&self, id: &str) {
        self.inner.finish_transfer(id, TransferState::Cancelled, None);
        if let Some(entry) = lock(&self.inner.state).transfers.get(id) {
            entry.cancel.cancel();
        }
        let request = Request::TransferCancel { transfer_id: id.to_string() };
        let _ = self.inner.call(request).await;
    }

    /// The saved file and the location to reveal for a finished download.
    pub fn saved_paths(&self, id: &str) -> Option<(PathBuf, PathBuf)> {
        let state = lock(&self.inner.state);
        let view = &state.transfers.get(id)?.view;
        Some((view.saved_path.clone()?, view.saved_location.clone()?))
    }

    /// Removes finished transfers from the list.
    pub fn clear_finished(&self) {
        let removed: Vec<String> = {
            let mut state = lock(&self.inner.state);
            let ids: Vec<String> = state
                .transfers
                .iter()
                .filter(|(_, t)| t.view.state.is_finished())
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                state.transfers.remove(id);
            }
            ids
        };
        for id in removed {
            self.inner.emit(EngineEvent::TransferRemoved { id });
        }
    }
}

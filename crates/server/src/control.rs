//! Control server: accounts, friends, presence and transfer signalling.
//! File contents never pass through here.

use crate::db::{Db, FriendAdd};
use crate::SharedSecret;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{split, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use transfer_proto::ticket::{self, Role, Ticket};
use transfer_proto::{
    now_secs, read_frame, write_frame, ApiError, Event, FriendInfo, FriendStatus, Inbound,
    Outbound, RelayEndpoint, RelayHello, Request, Response, MAX_SEALED,
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the recipient has to answer an offer.
const OFFER_TTL: u64 = 60 * 10;
/// How long clients have to reach the relay once the offer is accepted.
const TICKET_TTL: u64 = 60;
const MAX_PENDING_PER_USER: usize = 16;
const AUTH_WINDOW: Duration = Duration::from_secs(300);
const AUTH_MAX_FAILURES: u32 = 10;
/// Argon2 is deliberately expensive; this bounds concurrent hashes.
const MAX_CONCURRENT_HASHES: usize = 4;

type ApiResult = Result<Response, ApiError>;

struct Client {
    conn_id: u64,
    tx: mpsc::Sender<Outbound>,
    closed: CancellationToken,
}

struct Transfer {
    from: String,
    to: String,
    accepted: bool,
    expires_at: u64,
}

struct RelayEntry {
    hello: RelayHello,
    load: Arc<AtomicU32>,
    issued: AtomicU64,
}

#[derive(Default)]
struct RateLimiter {
    entries: HashMap<String, (u32, Instant)>,
}

impl RateLimiter {
    fn blocked(&mut self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|(n, at)| *n >= AUTH_MAX_FAILURES && at.elapsed() < AUTH_WINDOW)
    }

    fn hit(&mut self, key: &str) {
        self.entries.retain(|_, (_, at)| at.elapsed() < AUTH_WINDOW);
        self.entries.entry(key.to_string()).or_insert((0, Instant::now())).0 += 1;
    }

    fn clear(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

pub struct Hub {
    db: Arc<Db>,
    secret: SharedSecret,
    clients: Mutex<HashMap<String, Client>>,
    transfers: Mutex<HashMap<String, Transfer>>,
    relays: Mutex<HashMap<String, Arc<RelayEntry>>>,
    limiter: Mutex<RateLimiter>,
    hashing: Semaphore,
    next_conn: AtomicU64,
    /// Verified when the username does not exist, so timing does not reveal it.
    dummy_hash: String,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::Internal)
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn valid_username(name: &str) -> bool {
    (3..=32).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

fn valid_password(password: &str) -> bool {
    (10..=128).contains(&password.chars().count())
}

fn valid_device_key(key: &str) -> bool {
    use base64::engine::general_purpose::STANDARD;
    STANDARD.decode(key).is_ok_and(|k| k.len() == 32)
}

fn valid_transfer_id(id: &str) -> bool {
    uuid::Uuid::try_parse(id).is_ok()
}

fn normalize(username: &str) -> String {
    username.trim().to_lowercase()
}

impl Hub {
    pub fn new(db: Db, secret: SharedSecret) -> anyhow::Result<Arc<Self>> {
        let dummy_hash = hash_password("dummy-password-never-valid")
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Arc::new(Self {
            db: Arc::new(db),
            secret,
            clients: Mutex::default(),
            transfers: Mutex::default(),
            relays: Mutex::default(),
            limiter: Mutex::default(),
            hashing: Semaphore::new(MAX_CONCURRENT_HASHES),
            next_conn: AtomicU64::new(1),
            dummy_hash,
        }))
    }

    /// Registers a relay in this process or one that connected over the network.
    pub fn add_relay(&self, hello: RelayHello, load: Arc<AtomicU32>) {
        tracing::info!(id = %hello.relay_id, addr = %hello.public_addr, "relay online");
        let id = hello.relay_id.clone();
        let entry = RelayEntry { hello, load, issued: AtomicU64::new(0) };
        lock(&self.relays).insert(id, Arc::new(entry));
    }

    fn pick_relay(&self) -> Option<Arc<RelayEntry>> {
        let relays = lock(&self.relays);
        let best = relays
            .values()
            .filter(|r| r.load.load(Ordering::Acquire) < r.hello.capacity)
            .min_by_key(|r| {
                (r.load.load(Ordering::Acquire) as u64 * 1000 / r.hello.capacity.max(1) as u64,
                 r.issued.load(Ordering::Relaxed))
            })?
            .clone();
        best.issued.fetch_add(1, Ordering::Relaxed);
        Some(best)
    }

    async fn db<T, F>(&self, f: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(&Db) -> rusqlite::Result<T> + Send + 'static,
    {
        let db = self.db.clone();
        match tokio::task::spawn_blocking(move || f(&db)).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => {
                tracing::error!("database error: {e}");
                Err(ApiError::Internal)
            }
            Err(e) => {
                tracing::error!("database task failed: {e}");
                Err(ApiError::Internal)
            }
        }
    }

    async fn hash(&self, password: String) -> Result<String, ApiError> {
        let _permit = self.hashing.acquire().await.map_err(|_| ApiError::Internal)?;
        tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(|_| ApiError::Internal)?
    }

    async fn verify(&self, password: String, hash: String) -> Result<bool, ApiError> {
        let _permit = self.hashing.acquire().await.map_err(|_| ApiError::Internal)?;
        tokio::task::spawn_blocking(move || verify_password(&password, &hash))
            .await
            .map_err(|_| ApiError::Internal)
    }

    /// Queues a message. A client too slow to drain its queue gets disconnected
    /// rather than holding memory on the server.
    fn push(&self, username: &str, event: Event) {
        let mut clients = lock(&self.clients);
        if let Some(client) = clients.get(username) {
            if client.tx.try_send(Outbound::Event { body: event }).is_err() {
                client.closed.cancel();
                clients.remove(username);
            }
        }
    }

    fn is_online(&self, username: &str) -> bool {
        lock(&self.clients).contains_key(username)
    }

    async fn notify_presence(&self, username: &str, online: bool) {
        let name = username.to_string();
        let Ok(friends) = self.db(move |db| db.friends(&name)).await else {
            return;
        };
        for friend in friends.iter().filter(|f| f.status == FriendStatus::Accepted) {
            let event = Event::Presence { username: username.to_string(), online };
            self.push(&friend.username, event);
        }
    }

    /// Fails open offers of a user who went away; running tunnels are unaffected.
    fn cancel_pending_of(&self, username: &str) {
        let mut orphaned = Vec::new();
        lock(&self.transfers).retain(|id, t| {
            let involved = t.from == username || t.to == username;
            if involved && !t.accepted {
                orphaned.push((id.clone(), t.from.clone(), t.to.clone()));
                return false;
            }
            true
        });
        for (id, from, to) in orphaned {
            let other = if from == username { to } else { from };
            let event = Event::TransferCancelled {
                transfer_id: id,
                reason: format!("{username} se ha desconectado"),
            };
            self.push(&other, event);
        }
    }

    fn sweep_transfers(&self) {
        let now = now_secs();
        let mut expired = Vec::new();
        lock(&self.transfers).retain(|id, t| {
            let alive = t.expires_at > now;
            if !alive && !t.accepted {
                expired.push((id.clone(), t.from.clone(), t.to.clone()));
            }
            alive
        });
        for (id, from, to) in expired {
            for user in [from, to] {
                let event = Event::TransferCancelled {
                    transfer_id: id.clone(),
                    reason: "la oferta ha caducado".into(),
                };
                self.push(&user, event);
            }
        }
    }

    async fn friend_list(&self, username: &str) -> ApiResult {
        let name = username.to_string();
        let rows = self.db(move |db| db.friends(&name)).await?;
        let friends = rows
            .into_iter()
            .map(|row| {
                let accepted = row.status == FriendStatus::Accepted;
                FriendInfo {
                    online: accepted && self.is_online(&row.username),
                    device_key: accepted.then_some(row.device_key),
                    username: row.username,
                    status: row.status,
                }
            })
            .collect();
        Ok(Response::Friends { friends })
    }

    async fn offer(&self, me: &str, to: String, transfer_id: String, sealed: String) -> ApiResult {
        let to = normalize(&to);
        if !valid_transfer_id(&transfer_id) || sealed.len() > MAX_SEALED {
            return Err(ApiError::BadRequest);
        }
        let (a, b) = (me.to_string(), to.clone());
        if !self.db(move |db| db.are_friends(&a, &b)).await? {
            return Err(ApiError::NotFriends);
        }
        if !self.is_online(&to) {
            return Err(ApiError::PeerOffline);
        }
        {
            let mut transfers = lock(&self.transfers);
            let pending = transfers.values().filter(|t| t.from == me && !t.accepted).count();
            if pending >= MAX_PENDING_PER_USER {
                return Err(ApiError::TooManyTransfers);
            }
            if transfers.contains_key(&transfer_id) {
                return Err(ApiError::BadRequest);
            }
            let transfer = Transfer {
                from: me.to_string(),
                to: to.clone(),
                accepted: false,
                expires_at: now_secs() + OFFER_TTL,
            };
            transfers.insert(transfer_id.clone(), transfer);
        }
        self.push(&to, Event::Offer { from: me.to_string(), transfer_id, sealed });
        Ok(Response::Ok)
    }

    fn offer_respond(&self, me: &str, transfer_id: String, accept: bool) -> ApiResult {
        let from = {
            let transfers = lock(&self.transfers);
            let t = transfers.get(&transfer_id).ok_or(ApiError::UnknownTransfer)?;
            if t.to != me || t.accepted {
                return Err(ApiError::UnknownTransfer);
            }
            t.from.clone()
        };
        if !accept {
            lock(&self.transfers).remove(&transfer_id);
            self.push(&from, Event::OfferDeclined { transfer_id });
            return Ok(Response::Ok);
        }
        let Some(relay) = self.pick_relay() else {
            lock(&self.transfers).remove(&transfer_id);
            let event = Event::TransferCancelled {
                transfer_id,
                reason: ApiError::NoRelay.to_string(),
            };
            self.push(&from, event);
            return Err(ApiError::NoRelay);
        };
        let expires_at = now_secs() + TICKET_TTL;
        if let Some(t) = lock(&self.transfers).get_mut(&transfer_id) {
            t.accepted = true;
            t.expires_at = expires_at;
        }
        let endpoint = RelayEndpoint {
            addr: relay.hello.public_addr.clone(),
            fingerprint: relay.hello.fingerprint.clone(),
        };
        for (user, role) in [(from.as_str(), Role::Sender), (me, Role::Receiver)] {
            let ticket = ticket::sign(
                self.secret.as_ref(),
                &Ticket {
                    transfer_id: transfer_id.clone(),
                    role,
                    relay_id: relay.hello.relay_id.clone(),
                    expires_at,
                },
            );
            let event = Event::TransferReady {
                transfer_id: transfer_id.clone(),
                relay: endpoint.clone(),
                ticket,
            };
            self.push(user, event);
        }
        Ok(Response::Ok)
    }

    fn transfer_cancel(&self, me: &str, transfer_id: String) -> ApiResult {
        let transfer = {
            let mut transfers = lock(&self.transfers);
            match transfers.get(&transfer_id) {
                Some(t) if t.from == me || t.to == me => transfers.remove(&transfer_id),
                _ => None,
            }
        };
        if let Some(t) = transfer {
            let other = if t.from == me { t.to } else { t.from };
            let event = Event::TransferCancelled {
                transfer_id,
                reason: format!("cancelada por {me}"),
            };
            self.push(&other, event);
        }
        Ok(Response::Ok)
    }

    fn authenticated(&self, session: &Session) -> Result<String, ApiError> {
        session.username.clone().ok_or(ApiError::Unauthorized)
    }

    fn check_limit(&self, keys: &[&str]) -> Result<(), ApiError> {
        let mut limiter = lock(&self.limiter);
        if keys.iter().any(|k| limiter.blocked(k)) {
            return Err(ApiError::RateLimited);
        }
        Ok(())
    }

    fn take_session(&self, session: &mut Session, username: &str, replaced: bool) {
        let client = Client {
            conn_id: session.conn_id,
            tx: session.tx.clone(),
            closed: session.closed.clone(),
        };
        if let Some(old) = lock(&self.clients).insert(username.to_string(), client) {
            if replaced {
                let _ = old.tx.try_send(Outbound::Event { body: Event::SessionReplaced });
            }
            // Dropping the sender lets the old writer flush and exit.
            let closed = old.closed;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                closed.cancel();
            });
        }
        session.username = Some(username.to_string());
    }

    async fn new_token(&self, username: String, device_key: String) -> Result<String, ApiError> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token = B64.encode(raw);
        let hash = token_hash(&token);
        self.db(move |db| db.start_session(&username, &hash, &device_key)).await?;
        Ok(token)
    }

    /// Friends must see a new device key at once: their pin depends on it.
    async fn notify_friends_changed(&self, username: &str) {
        let name = username.to_string();
        if let Ok(friends) = self.db(move |db| db.friends(&name)).await {
            for friend in friends {
                self.push(&friend.username, Event::FriendsChanged);
            }
        }
    }

    async fn handle(&self, session: &mut Session, request: Request) -> ApiResult {
        match request {
            Request::Ping => Ok(Response::Ok),
            Request::Register { username, password, device_key } => {
                let ip_key = format!("reg:{}", session.ip);
                self.check_limit(&[&ip_key])?;
                let username = normalize(&username);
                if !valid_username(&username) {
                    return Err(ApiError::InvalidUsername);
                }
                if !valid_password(&password) {
                    return Err(ApiError::WeakPassword);
                }
                if !valid_device_key(&device_key) {
                    return Err(ApiError::BadRequest);
                }
                lock(&self.limiter).hit(&ip_key);
                let hash = self.hash(password).await?;
                let (name, key) = (username.clone(), device_key.clone());
                if !self.db(move |db| db.create_user(&name, &hash, &key)).await? {
                    return Err(ApiError::UsernameTaken);
                }
                let token = self.new_token(username.clone(), device_key).await?;
                self.take_session(session, &username, true);
                Ok(Response::Session { username, token })
            }
            Request::Login { username, password, device_key } => {
                let username = normalize(&username);
                let ip_key = format!("ip:{}", session.ip);
                let user_key = format!("user:{username}");
                self.check_limit(&[&ip_key, &user_key])?;
                if !valid_device_key(&device_key) {
                    return Err(ApiError::BadRequest);
                }
                let name = username.clone();
                let stored = self.db(move |db| db.password_hash(&name)).await?;
                let exists = stored.is_some();
                let hash = stored.unwrap_or_else(|| self.dummy_hash.clone());
                let matches = self.verify(password, hash).await?;
                if !(exists && matches) {
                    let mut limiter = lock(&self.limiter);
                    limiter.hit(&ip_key);
                    limiter.hit(&user_key);
                    return Err(ApiError::BadCredentials);
                }
                lock(&self.limiter).clear(&user_key);
                let token = self.new_token(username.clone(), device_key).await?;
                self.take_session(session, &username, true);
                self.notify_friends_changed(&username).await;
                self.notify_presence(&username, true).await;
                Ok(Response::Session { username, token })
            }
            Request::Resume { token } => {
                let hash = token_hash(&token);
                let username = self
                    .db(move |db| db.resume_session(&hash))
                    .await?
                    .ok_or(ApiError::Unauthorized)?;
                self.take_session(session, &username, false);
                self.notify_presence(&username, true).await;
                Ok(Response::Resumed { username })
            }
            Request::Logout => {
                let me = self.authenticated(session)?;
                let name = me.clone();
                self.db(move |db| db.end_session(&name)).await?;
                session.closed.cancel();
                Ok(Response::Ok)
            }
            Request::ChangePassword { old_password, new_password } => {
                let me = self.authenticated(session)?;
                let user_key = format!("user:{me}");
                self.check_limit(&[&user_key])?;
                if !valid_password(&new_password) {
                    return Err(ApiError::WeakPassword);
                }
                let name = me.clone();
                let stored = self
                    .db(move |db| db.password_hash(&name))
                    .await?
                    .ok_or(ApiError::Unauthorized)?;
                if !self.verify(old_password, stored).await? {
                    lock(&self.limiter).hit(&user_key);
                    return Err(ApiError::BadCredentials);
                }
                let hash = self.hash(new_password).await?;
                self.db(move |db| db.set_password_hash(&me, &hash)).await?;
                Ok(Response::Ok)
            }
            Request::Friends => {
                let me = self.authenticated(session)?;
                self.friend_list(&me).await
            }
            Request::FriendAdd { username } => {
                let me = self.authenticated(session)?;
                let other = normalize(&username);
                if other == me {
                    return Err(ApiError::SelfFriend);
                }
                let (a, b) = (me.clone(), other.clone());
                let outcome = self
                    .db(move |db| db.add_friend(&a, &b))
                    .await?
                    .ok_or(ApiError::UserNotFound)?;
                if !matches!(outcome, FriendAdd::AlreadyLinked) {
                    self.push(&other, Event::FriendsChanged);
                }
                Ok(Response::Ok)
            }
            Request::FriendRespond { username, accept } => {
                let me = self.authenticated(session)?;
                let other = normalize(&username);
                let (a, b) = (me.clone(), other.clone());
                if !self.db(move |db| db.respond_friend(&a, &b, accept)).await? {
                    return Err(ApiError::BadRequest);
                }
                self.push(&other, Event::FriendsChanged);
                Ok(Response::Ok)
            }
            Request::FriendRemove { username } => {
                let me = self.authenticated(session)?;
                let other = normalize(&username);
                let (a, b) = (me.clone(), other.clone());
                self.db(move |db| db.remove_friend(&a, &b)).await?;
                self.push(&other, Event::FriendsChanged);
                Ok(Response::Ok)
            }
            Request::Offer { to, transfer_id, sealed } => {
                let me = self.authenticated(session)?;
                self.offer(&me, to, transfer_id, sealed).await
            }
            Request::OfferRespond { transfer_id, accept } => {
                let me = self.authenticated(session)?;
                self.offer_respond(&me, transfer_id, accept)
            }
            Request::TransferCancel { transfer_id } => {
                let me = self.authenticated(session)?;
                self.transfer_cancel(&me, transfer_id)
            }
        }
    }

    async fn drop_client(&self, conn_id: u64, username: &str) {
        let removed = {
            let mut clients = lock(&self.clients);
            let current = clients.get(username).is_some_and(|c| c.conn_id == conn_id);
            if current {
                clients.remove(username);
            }
            current
        };
        if removed {
            self.cancel_pending_of(username);
            self.notify_presence(username, false).await;
        }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener, acceptor: TlsAcceptor) {
        let sweeper = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                sweeper.sweep_transfers();
            }
        });
        loop {
            let (tcp, addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let hub = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = tcp.set_nodelay(true);
                match timeout(TLS_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => hub.connection(stream, addr).await,
                    Ok(Err(e)) => tracing::debug!(%addr, "tls failed: {e}"),
                    Err(_) => tracing::debug!(%addr, "tls handshake timed out"),
                }
            });
        }
    }

    async fn connection(self: Arc<Self>, stream: TlsStream<TcpStream>, addr: SocketAddr) {
        let (mut reader, writer) = split(stream);
        let (tx, rx) = mpsc::channel(256);
        let closed = CancellationToken::new();
        tokio::spawn(write_loop(writer, rx, closed.clone()));

        let mut session = Session {
            conn_id: self.next_conn.fetch_add(1, Ordering::Relaxed),
            ip: addr.ip(),
            username: None,
            tx: tx.clone(),
            closed: closed.clone(),
        };

        loop {
            let frame = tokio::select! {
                _ = closed.cancelled() => break,
                frame = timeout(IDLE_TIMEOUT, read_frame::<_, Inbound>(&mut reader)) => frame,
            };
            match frame {
                Ok(Ok(Inbound::Req { id, body })) => {
                    let body = self.handle(&mut session, body).await;
                    if tx.send(Outbound::Res { id, body }).await.is_err() {
                        break;
                    }
                }
                Ok(Ok(Inbound::RelayHello(hello))) if session.username.is_none() => {
                    self.relay_session(hello, reader, tx).await;
                    return;
                }
                _ => break,
            }
        }
        if let Some(username) = session.username.take() {
            self.drop_client(session.conn_id, &username).await;
        }
        closed.cancel();
    }

    async fn relay_session<R>(&self, hello: RelayHello, mut reader: R, tx: mpsc::Sender<Outbound>)
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let authorized = hex::decode(&hello.secret)
            .is_ok_and(|s| constant_eq(&s, self.secret.as_ref()));
        let body = if authorized { Ok(Response::Ok) } else { Err(ApiError::Unauthorized) };
        let _ = tx.send(Outbound::Res { id: 0, body }).await;
        if !authorized {
            tracing::warn!("relay rejected: bad secret");
            return;
        }
        let relay_id = hello.relay_id.clone();
        let load = Arc::new(AtomicU32::new(0));
        self.add_relay(hello, load.clone());
        while let Ok(Ok(Inbound::RelayLoad { active })) =
            timeout(Duration::from_secs(20), read_frame(&mut reader)).await
        {
            load.store(active, Ordering::Release);
        }
        let mut relays = lock(&self.relays);
        // A reconnect may already have replaced this entry.
        if relays.get(&relay_id).is_some_and(|r| Arc::ptr_eq(&r.load, &load)) {
            relays.remove(&relay_id);
            tracing::info!(id = %relay_id, "relay offline");
        }
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Session {
    conn_id: u64,
    ip: IpAddr,
    username: Option<String>,
    tx: mpsc::Sender<Outbound>,
    closed: CancellationToken,
}

async fn write_loop<W>(mut writer: W, mut rx: mpsc::Receiver<Outbound>, closed: CancellationToken)
where
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = closed.cancelled() => break,
            message = rx.recv() => match message {
                Some(message) => {
                    if write_frame(&mut writer, &message).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    closed.cancel();
}

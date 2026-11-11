//! End-to-end tests with a real control server, real relays and real TCP/TLS.

use rand::RngCore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_rustls::TlsAcceptor;
use transfer_client_core::{Engine, EngineEvent, TransferState};
use transfer_proto::{tls, ApiError, FriendStatus};
use transfer_server::control::Hub;
use transfer_server::db::Db;
use transfer_server::relay::{register_loop, Relay};

const PASSWORD: &str = "correct horse battery";
const WAIT: Duration = Duration::from_secs(20);

struct Server {
    addr: String,
    fingerprint: String,
    hub: Arc<Hub>,
    secret: Arc<Vec<u8>>,
    dir: tempfile::TempDir,
}

async fn spawn_relay(dir: &Path, name: &str, secret: Arc<Vec<u8>>) -> Arc<Relay> {
    let identity = tls::self_signed_identity(dir, name).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let relay = Relay::new(name.to_string(), addr, 8, identity.fingerprint, secret);
    tokio::spawn(relay.clone().serve(listener, TlsAcceptor::from(identity.config)));
    relay
}

async fn spawn_server(with_relay: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let secret = Arc::new(vec![7u8; 32]);
    let db = Db::open(&dir.path().join("t.db")).unwrap();
    let hub = Hub::new(db, secret.clone()).unwrap();
    if with_relay {
        let relay = spawn_relay(dir.path(), "local", secret.clone()).await;
        hub.add_relay(relay.hello(), relay.active.clone());
    }
    let identity = tls::self_signed_identity(dir.path(), "control").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let fingerprint = identity.fingerprint.clone();
    tokio::spawn(hub.clone().serve(listener, TlsAcceptor::from(identity.config)));
    Server { addr, fingerprint, hub, secret, dir }
}

struct Peer {
    engine: Engine,
    events: UnboundedReceiver<EngineEvent>,
    downloads: PathBuf,
    _home: tempfile::TempDir,
}

impl Peer {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let downloads = home.path().join("downloads");
        let (engine, events) = Engine::start(&home.path().join("data"), downloads.clone()).unwrap();
        Self { engine, events, downloads, _home: home }
    }

    async fn signed_up(server: &Server, name: &str) -> Self {
        let peer = Self::new();
        peer.engine.register(&server.addr, &server.fingerprint, name, PASSWORD).await.unwrap();
        peer
    }

    /// Consumes events until `check` matches.
    async fn wait_for<T>(&mut self, mut check: impl FnMut(&EngineEvent) -> Option<T>) -> T {
        let found = tokio::time::timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.expect("engine alive");
                if let Some(value) = check(&event) {
                    return value;
                }
            }
        });
        found.await.expect("expected event did not arrive")
    }

    async fn online(&mut self) {
        self.wait_for(|e| match e {
            EngineEvent::Connection { state, .. }
                if *state == transfer_client_core::Connection::Online =>
            {
                Some(())
            }
            _ => None,
        })
        .await
    }

    async fn transfer_state(&mut self, wanted: TransferState) -> String {
        self.wait_for(|e| match e {
            EngineEvent::Transfer { transfer } if transfer.state == wanted => {
                Some(transfer.id.clone())
            }
            _ => None,
        })
        .await
    }

    async fn friend_ready(&mut self, name: &str, online: bool) {
        let name = name.to_string();
        self.wait_for(move |e| match e {
            EngineEvent::Friends { friends } => friends
                .iter()
                .any(|f| {
                    f.username == name && f.status == FriendStatus::Accepted && f.online == online
                })
                .then_some(()),
            _ => None,
        })
        .await
    }
}

async fn befriend(a: &mut Peer, a_name: &str, b: &mut Peer, b_name: &str) {
    a.online().await;
    b.online().await;
    a.engine.add_friend(b_name).await.unwrap();
    let from = a_name.to_string();
    b.wait_for(move |e| match e {
        EngineEvent::FriendRequest { username } if *username == from => Some(()),
        _ => None,
    })
    .await;
    b.engine.respond_friend(a_name, true).await.unwrap();
    a.friend_ready(b_name, true).await;
    b.friend_ready(a_name, true).await;
}

fn random_file(path: &Path, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, &data).unwrap();
    data
}

#[tokio::test(flavor = "multi_thread")]
async fn transfers_files_and_folders_through_the_relay() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;

    let work = tempfile::tempdir().unwrap();
    let big = random_file(&work.path().join("video.bin"), 12 * 1024 * 1024 + 123);
    let nested = random_file(&work.path().join("carpeta/sub/doc.txt"), 4096);
    random_file(&work.path().join("carpeta/vacio.dat"), 0);

    ana.engine
        .send("bob", vec![work.path().join("video.bin"), work.path().join("carpeta")])
        .await
        .unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    bob.engine.accept(&id).await.unwrap();
    bob.transfer_state(TransferState::Done).await;
    ana.transfer_state(TransferState::Done).await;

    assert_eq!(std::fs::read(bob.downloads.join("video.bin")).unwrap(), big);
    assert_eq!(std::fs::read(bob.downloads.join("carpeta/sub/doc.txt")).unwrap(), nested);
    assert_eq!(std::fs::metadata(bob.downloads.join("carpeta/vacio.dat")).unwrap().len(), 0);
    assert!(!bob.downloads.join("video.bin.part").exists());
    let done = bob.engine.snapshot().transfers[0].done_bytes;
    assert_eq!(done, big.len() as u64 + nested.len() as u64);
    let (saved, location) = bob.engine.saved_paths(&id).unwrap();
    assert_eq!(saved, bob.downloads.join("video.bin"));
    assert_eq!(location, saved);
    assert!(ana.engine.snapshot().transfers[0].saved_path.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_downloads_are_not_overwritten() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;

    std::fs::create_dir_all(&bob.downloads).unwrap();
    std::fs::write(bob.downloads.join("nota.txt"), b"mia").unwrap();
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("nota.txt"), b"nueva").unwrap();

    ana.engine.send("bob", vec![work.path().join("nota.txt")]).await.unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    bob.engine.accept(&id).await.unwrap();
    bob.transfer_state(TransferState::Done).await;

    assert_eq!(std::fs::read(bob.downloads.join("nota.txt")).unwrap(), b"mia");
    assert_eq!(std::fs::read(bob.downloads.join("nota (1).txt")).unwrap(), b"nueva");
    let (saved, _) = bob.engine.saved_paths(&id).unwrap();
    assert_eq!(saved, bob.downloads.join("nota (1).txt"));
}

#[tokio::test(flavor = "multi_thread")]
async fn declining_notifies_the_sender_and_writes_nothing() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;

    let work = tempfile::tempdir().unwrap();
    random_file(&work.path().join("a.bin"), 100);
    ana.engine.send("bob", vec![work.path().join("a.bin")]).await.unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    bob.engine.decline(&id).await.unwrap();
    ana.transfer_state(TransferState::Declined).await;
    assert!(!bob.downloads.join("a.bin").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_mid_transfer_stops_both_sides_and_removes_partial_file() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;

    let work = tempfile::tempdir().unwrap();
    random_file(&work.path().join("big.bin"), 200 * 1024 * 1024);
    let sent = ana.engine.send("bob", vec![work.path().join("big.bin")]).await.unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    bob.engine.accept(&id).await.unwrap();
    ana.transfer_state(TransferState::Running).await;
    ana.engine.cancel(&sent).await;

    bob.wait_for(|e| match e {
        EngineEvent::Transfer { transfer } => {
            matches!(transfer.state, TransferState::Cancelled | TransferState::Failed).then_some(())
        }
        _ => None,
    })
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(!bob.downloads.join("big.bin").exists());
    assert!(!bob.downloads.join("big.bin.part").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn cannot_send_to_strangers() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    ana.online().await;
    bob.online().await;
    let work = tempfile::tempdir().unwrap();
    random_file(&work.path().join("a.bin"), 10);
    let err = ana.engine.send("bob", vec![work.path().join("a.bin")]).await.unwrap_err();
    assert!(err.to_string().contains("amigos"), "{err}");

    // A pending request is not a friendship.
    ana.engine.add_friend("bob").await.unwrap();
    assert!(ana.engine.send("bob", vec![work.path().join("a.bin")]).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn account_rules() {
    let server = spawn_server(true).await;
    let peer = Peer::new();
    let register = |name: &'static str, pass: &'static str| {
        let (engine, addr, pin) =
            (peer.engine.clone(), server.addr.clone(), server.fingerprint.clone());
        async move { engine.register(&addr, &pin, name, pass).await }
    };
    let code = |r: anyhow::Result<()>| r.unwrap_err().downcast::<ApiError>().unwrap();

    assert_eq!(code(register("ab", PASSWORD).await), ApiError::InvalidUsername);
    assert_eq!(code(register("ana", "corta").await), ApiError::WeakPassword);
    register("ana", PASSWORD).await.unwrap();

    let other = Peer::new();
    let (addr, pin) = (&server.addr, &server.fingerprint);
    let err = other.engine.register(addr, pin, "ANA", PASSWORD).await.unwrap_err();
    assert_eq!(err.downcast::<ApiError>().unwrap(), ApiError::UsernameTaken);
    let err = other.engine.login(addr, pin, "ana", "contraseña mala").await.unwrap_err();
    assert_eq!(err.downcast::<ApiError>().unwrap(), ApiError::BadCredentials);
    let err = other.engine.login(addr, pin, "nadie", PASSWORD).await.unwrap_err();
    assert_eq!(err.downcast::<ApiError>().unwrap(), ApiError::BadCredentials);
}

#[tokio::test(flavor = "multi_thread")]
async fn repeated_bad_logins_are_rate_limited() {
    let server = spawn_server(true).await;
    let _ana = Peer::signed_up(&server, "ana").await;
    let other = Peer::new();
    let (addr, pin) = (&server.addr, &server.fingerprint);
    for _ in 0..10 {
        let err = other.engine.login(addr, pin, "ana", "contraseña mala").await.unwrap_err();
        assert_eq!(err.downcast::<ApiError>().unwrap(), ApiError::BadCredentials);
    }
    let err = other.engine.login(addr, pin, "ana", PASSWORD).await.unwrap_err();
    assert_eq!(err.downcast::<ApiError>().unwrap(), ApiError::RateLimited);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_server_fingerprint_is_refused() {
    let server = spawn_server(true).await;
    let peer = Peer::new();
    let bad_pin = "00".repeat(32);
    assert!(peer.engine.register(&server.addr, &bad_pin, "ana", PASSWORD).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_replaces_the_old_one() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    ana.online().await;
    let new_password = "another long passphrase";
    assert!(ana.engine.change_password("not the password", new_password).await.is_err());
    ana.engine.change_password(PASSWORD, new_password).await.unwrap();
    ana.engine.logout().await;

    let (addr, pin) = (&server.addr, &server.fingerprint);
    assert!(ana.engine.login(addr, pin, "ana", PASSWORD).await.is_err());
    ana.engine.login(addr, pin, "ana", new_password).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn new_device_blocks_transfers_until_key_is_trusted() {
    let server = spawn_server(true).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;

    // Bob logs in from a new device, or someone impersonates Bob's key.
    let mut bob2 = Peer::new();
    bob2.engine.login(&server.addr, &server.fingerprint, "bob", PASSWORD).await.unwrap();
    bob2.online().await;
    ana.wait_for(|e| match e {
        EngineEvent::Friends { friends } => friends.iter().any(|f| f.key_changed).then_some(()),
        _ => None,
    })
    .await;

    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("a.txt"), b"hola").unwrap();
    let err = ana.engine.send("bob", vec![work.path().join("a.txt")]).await.unwrap_err();
    assert!(err.to_string().contains("clave"), "{err}");

    ana.engine.trust_key("bob").unwrap();
    bob2.friend_ready("ana", true).await;
    ana.engine.send("bob", vec![work.path().join("a.txt")]).await.unwrap();
    let id = bob2.transfer_state(TransferState::Incoming).await;
    bob2.engine.accept(&id).await.unwrap();
    bob2.transfer_state(TransferState::Done).await;
    assert_eq!(std::fs::read(bob2.downloads.join("a.txt")).unwrap(), b"hola");
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_relay_registers_and_carries_traffic() {
    let server = spawn_server(false).await;
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("a.txt"), b"por relay remoto").unwrap();

    // Without relays the accept fails cleanly.
    ana.engine.send("bob", vec![work.path().join("a.txt")]).await.unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    assert!(bob.engine.accept(&id).await.is_err());
    ana.transfer_state(TransferState::Cancelled).await;

    let relay = spawn_relay(server.dir.path(), "remote", server.secret.clone()).await;
    tokio::spawn(register_loop(
        relay.clone(),
        server.addr.clone(),
        Some(server.fingerprint.clone()),
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;

    ana.engine.send("bob", vec![work.path().join("a.txt")]).await.unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    bob.engine.accept(&id).await.unwrap();
    bob.transfer_state(TransferState::Done).await;
    assert_eq!(std::fs::read(bob.downloads.join("a.txt")).unwrap(), b"por relay remoto");
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_with_a_wrong_secret_is_refused() {
    let server = spawn_server(false).await;
    let relay = spawn_relay(server.dir.path(), "rogue", Arc::new(vec![1u8; 32])).await;
    tokio::spawn(register_loop(relay, server.addr.clone(), Some(server.fingerprint.clone())));
    let mut ana = Peer::signed_up(&server, "ana").await;
    let mut bob = Peer::signed_up(&server, "bob").await;
    befriend(&mut ana, "ana", &mut bob, "bob").await;

    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("a.txt"), b"x").unwrap();
    ana.engine.send("bob", vec![work.path().join("a.txt")]).await.unwrap();
    let id = bob.transfer_state(TransferState::Incoming).await;
    assert!(bob.engine.accept(&id).await.is_err());
    let _ = &server.hub;
}

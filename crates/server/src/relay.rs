//! Tunnel relay. Two clients present tickets for the same transfer, the relay
//! pairs them and forwards bytes it cannot read: clients encrypt end to end.

use crate::SharedSecret;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use transfer_proto::ticket::{self, Role};
use transfer_proto::{now_secs, read_frame, write_frame, RelayHello, TunnelHello, TunnelStatus};

type Stream = TlsStream<TcpStream>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PAIR_TIMEOUT: Duration = Duration::from_secs(45);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

struct Waiting {
    role: Role,
    peer: oneshot::Sender<Stream>,
}

pub struct Relay {
    pub id: String,
    pub public_addr: String,
    pub capacity: u32,
    pub active: Arc<AtomicU32>,
    pub fingerprint: String,
    secret: SharedSecret,
    waiting: Mutex<HashMap<String, Waiting>>,
    /// Tickets already presented, kept until they expire to block replays.
    used: Mutex<HashMap<(String, Role), u64>>,
}

/// Releases the capacity slot however the tunnel ends.
struct Slot(Arc<AtomicU32>);

impl Slot {
    fn acquire(active: &Arc<AtomicU32>, capacity: u32) -> Option<Self> {
        active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < capacity).then_some(n + 1))
            .ok()
            .map(|_| Slot(active.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Relay {
    pub fn new(
        id: String,
        public_addr: String,
        capacity: u32,
        fingerprint: String,
        secret: SharedSecret,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            public_addr,
            capacity,
            active: Arc::new(AtomicU32::new(0)),
            fingerprint,
            secret,
            waiting: Mutex::new(HashMap::new()),
            used: Mutex::new(HashMap::new()),
        })
    }

    pub fn hello(&self) -> RelayHello {
        RelayHello {
            secret: hex::encode(self.secret.as_ref()),
            relay_id: self.id.clone(),
            public_addr: self.public_addr.clone(),
            fingerprint: self.fingerprint.clone(),
            capacity: self.capacity,
        }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener, acceptor: TlsAcceptor) {
        loop {
            let (tcp, addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("relay accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let relay = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = tcp.set_nodelay(true);
                if let Err(e) = relay.handle(tcp, acceptor).await {
                    tracing::debug!(%addr, "tunnel rejected: {e}");
                }
            });
        }
    }

    fn admit(&self, token: &str) -> Result<ticket::Ticket, &'static str> {
        let now = now_secs();
        let ticket = ticket::verify(self.secret.as_ref(), token, &self.id, now)
            .ok_or("invalid ticket")?;
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        used.retain(|_, expires| *expires > now);
        let key = (ticket.transfer_id.clone(), ticket.role);
        if used.insert(key, ticket.expires_at).is_some() {
            return Err("ticket already used");
        }
        Ok(ticket)
    }

    async fn handle(&self, tcp: TcpStream, acceptor: TlsAcceptor) -> anyhow::Result<()> {
        let slot = Slot::acquire(&self.active, self.capacity);
        let mut stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await??;
        let hello: TunnelHello = timeout(HANDSHAKE_TIMEOUT, read_frame(&mut stream)).await??;
        let Some(slot) = slot else {
            return reject(&mut stream, "relay is full").await;
        };
        let ticket = match self.admit(&hello.ticket) {
            Ok(ticket) => ticket,
            Err(reason) => return reject(&mut stream, reason).await,
        };

        let waiting = {
            let mut map = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
            match map.remove(&ticket.transfer_id) {
                Some(first) if first.role != ticket.role => Ok(first.peer),
                Some(first) => {
                    map.insert(ticket.transfer_id.clone(), first);
                    Err(None)
                }
                None => {
                    let (tx, rx) = oneshot::channel();
                    let entry = Waiting { role: ticket.role, peer: tx };
                    map.insert(ticket.transfer_id.clone(), entry);
                    Err(Some(rx))
                }
            }
        };

        match waiting {
            Ok(peer) => {
                // The first side owns the pipe; hand it this socket and leave.
                drop(slot);
                let _ = peer.send(stream);
                Ok(())
            }
            Err(None) => reject(&mut stream, "duplicate role").await,
            Err(Some(rx)) => match timeout(PAIR_TIMEOUT, rx).await {
                Ok(Ok(peer)) => {
                    let result = pipe(stream, peer).await;
                    drop(slot);
                    result
                }
                _ => {
                    self.waiting
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&ticket.transfer_id);
                    reject(&mut stream, "the other side did not connect").await
                }
            },
        }
    }
}

async fn reject(stream: &mut Stream, reason: &str) -> anyhow::Result<()> {
    let status = TunnelStatus { paired: false, error: Some(reason.to_string()) };
    write_frame(stream, &status).await?;
    anyhow::bail!("{reason}")
}

async fn pipe(mut a: Stream, mut b: Stream) -> anyhow::Result<()> {
    let ready = TunnelStatus { paired: true, error: None };
    write_frame(&mut a, &ready).await?;
    write_frame(&mut b, &ready).await?;

    let started = Instant::now();
    let last_activity = AtomicU64::new(0);
    let touch = || last_activity.store(started.elapsed().as_secs(), Ordering::Relaxed);
    let (mut ar, mut aw) = split(a);
    let (mut br, mut bw) = split(b);
    let watchdog = async {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let idle = started.elapsed().as_secs() - last_activity.load(Ordering::Relaxed);
            if idle >= IDLE_TIMEOUT.as_secs() {
                return;
            }
        }
    };
    tokio::select! {
        _ = forward(&mut ar, &mut bw, &touch) => {}
        _ = forward(&mut br, &mut aw, &touch) => {}
        _ = watchdog => tracing::debug!("tunnel closed for inactivity"),
    }
    let _ = aw.shutdown().await;
    let _ = bw.shutdown().await;
    Ok(())
}

async fn forward<R, W>(from: &mut R, to: &mut W, touch: &impl Fn()) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
        to.flush().await?;
        touch();
    }
}

/// Keeps a standalone relay registered in the control server.
pub async fn register_loop(
    relay: Arc<Relay>,
    control_addr: String,
    control_pin: Option<String>,
) -> anyhow::Result<()> {
    use transfer_proto::{tls, Inbound, Outbound};
    let config = tls::client_config(control_pin.as_deref())?;
    loop {
        let session = async {
            let mut stream = tls::connect(&control_addr, config.clone()).await?;
            write_frame(&mut stream, &Inbound::RelayHello(relay.hello())).await?;
            let answer: Outbound = read_frame(&mut stream).await?;
            if !matches!(answer, Outbound::Res { body: Ok(_), .. }) {
                anyhow::bail!("the control server rejected this relay");
            }
            tracing::info!(addr = %relay.public_addr, "relay registered in {control_addr}");
            loop {
                let active = relay.active.load(Ordering::Acquire);
                write_frame(&mut stream, &Inbound::RelayLoad { active }).await?;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        };
        if let Err(e) = session.await {
            tracing::warn!("control connection lost: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}


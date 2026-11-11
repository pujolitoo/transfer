use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use rand::RngCore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use transfer_proto::tls;
use transfer_server::control::Hub;
use transfer_server::db::Db;
use transfer_server::relay::{register_loop, Relay};
use transfer_server::SharedSecret;

#[derive(Parser)]
#[command(version, about = "Transfer control server and relays")]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Control and a relay in one process: the simplest setup for a single server.
    All {
        #[command(flatten)]
        control: ControlArgs,
        #[command(flatten)]
        relay: RelayArgs,
    },
    /// Only accounts, friends and signalling.
    Control {
        #[command(flatten)]
        control: ControlArgs,
    },
    /// Only a relay, which registers with a remote control server.
    Relay {
        #[command(flatten)]
        relay: RelayArgs,
        /// host:port of the control server.
        #[arg(long, env = "TRANSFER_CONTROL_ADDR")]
        control_addr: String,
        /// SHA-256 fingerprint of the control certificate, if self-signed.
        #[arg(long, env = "TRANSFER_CONTROL_FINGERPRINT")]
        control_fingerprint: Option<String>,
    },
}

#[derive(Args)]
struct ControlArgs {
    #[arg(long, env = "TRANSFER_CONTROL_LISTEN", default_value = "0.0.0.0:7443")]
    control_listen: String,
    /// PEM certificate from a CA. Without it a persistent self-signed one is used.
    #[arg(long, env = "TRANSFER_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, env = "TRANSFER_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

#[derive(Args)]
struct RelayArgs {
    #[arg(long, env = "TRANSFER_RELAY_LISTEN", default_value = "0.0.0.0:7444")]
    relay_listen: String,
    /// host:port that clients use to reach this relay.
    #[arg(long, env = "TRANSFER_RELAY_PUBLIC_ADDR", default_value = "127.0.0.1:7444")]
    relay_public_addr: String,
    #[arg(long, env = "TRANSFER_RELAY_ID")]
    relay_id: Option<String>,
    /// Concurrent tunnels allowed.
    #[arg(long, env = "TRANSFER_RELAY_CAPACITY", default_value_t = 256)]
    relay_capacity: u32,
}

/// Global options live in the environment so `clap` subcommands stay flat.
fn data_dir() -> PathBuf {
    std::env::var_os("TRANSFER_DATA_DIR").map_or_else(|| PathBuf::from("data"), PathBuf::from)
}

fn load_secret(dir: &Path) -> anyhow::Result<SharedSecret> {
    if let Ok(secret) = std::env::var("TRANSFER_RELAY_SECRET") {
        let secret = hex::decode(secret.trim()).context("TRANSFER_RELAY_SECRET must be hex")?;
        anyhow::ensure!(secret.len() >= 32, "TRANSFER_RELAY_SECRET needs at least 32 bytes");
        return Ok(Arc::new(secret));
    }
    let path = dir.join("relay.secret");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        return Ok(Arc::new(hex::decode(existing.trim()).context("relay.secret is corrupt")?));
    }
    let mut secret = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    tls::write_private(&path, hex::encode(&secret).as_bytes())?;
    Ok(Arc::new(secret))
}

fn control_identity(dir: &Path, args: &ControlArgs) -> anyhow::Result<tls::Identity> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Ok(tls::load_identity(cert, key)?),
        _ => Ok(tls::self_signed_identity(dir, "control")?),
    }
}

async fn run_control(args: ControlArgs, hub: Arc<Hub>, identity: tls::Identity) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&args.control_listen)
        .await
        .with_context(|| format!("could not listen on {}", args.control_listen))?;
    tracing::info!(addr = %args.control_listen, fingerprint = %identity.fingerprint, "control listening");
    hub.serve(listener, TlsAcceptor::from(identity.config)).await;
    Ok(())
}

async fn start_relay(
    dir: &Path,
    args: &RelayArgs,
    secret: SharedSecret,
) -> anyhow::Result<(Arc<Relay>, TcpListener, TlsAcceptor)> {
    // The id lives on disk so a restarted relay keeps it.
    let id_path = dir.join("relay.id");
    let id = match (&args.relay_id, std::fs::read_to_string(&id_path)) {
        (Some(id), _) => id.clone(),
        (None, Ok(id)) => id.trim().to_string(),
        (None, Err(_)) => {
            let id = uuid::Uuid::new_v4().to_string();
            std::fs::write(&id_path, &id)?;
            id
        }
    };
    let identity = tls::self_signed_identity(dir, "relay")?;
    let listener = TcpListener::bind(&args.relay_listen)
        .await
        .with_context(|| format!("could not listen on {}", args.relay_listen))?;
    tracing::info!(addr = %args.relay_listen, public = %args.relay_public_addr, "relay listening");
    let relay = Relay::new(
        id,
        args.relay_public_addr.clone(),
        args.relay_capacity,
        identity.fingerprint,
        secret,
    );
    Ok((relay, listener, TlsAcceptor::from(identity.config)))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let secret = load_secret(&dir)?;

    match cli.mode {
        Mode::All { control, relay } => {
            let hub = Hub::new(Db::open(&dir.join("transfer.db"))?, secret.clone())?;
            let identity = control_identity(&dir, &control)?;
            let (relay, listener, acceptor) = start_relay(&dir, &relay, secret).await?;
            hub.add_relay(relay.hello(), relay.active.clone());
            tokio::spawn(relay.serve(listener, acceptor));
            run_control(control, hub, identity).await
        }
        Mode::Control { control } => {
            let hub = Hub::new(Db::open(&dir.join("transfer.db"))?, secret)?;
            let identity = control_identity(&dir, &control)?;
            run_control(control, hub, identity).await
        }
        Mode::Relay { relay, control_addr, control_fingerprint } => {
            let (relay, listener, acceptor) = start_relay(&dir, &relay, secret).await?;
            tokio::spawn(relay.clone().serve(listener, acceptor));
            register_loop(relay, control_addr, control_fingerprint).await
        }
    }
}

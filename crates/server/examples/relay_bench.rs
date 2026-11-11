//! Relay throughput with each TLS cipher suite, using the real relay code:
//!
//!   cargo run --release -p transfer-server --example relay_bench -- 512
//!
//! Sender, receiver and relay share one machine, so the figure is a lower
//! bound for the relay alone. The argument is the megabytes sent per run.

use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{ring, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{self, CipherSuite, ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use transfer_proto::ticket::{self, Role, Ticket};
use transfer_proto::{now_secs, read_frame, tls, write_frame, TunnelHello, TunnelStatus};
use transfer_server::relay::Relay;

/// Same size as the client's tunnel messages.
const CHUNK: usize = 60_000;

#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client offering only `suite`, or the default list when `None`.
fn client(suite: Option<CipherSuite>) -> Arc<ClientConfig> {
    let mut provider = ring::default_provider();
    if let Some(suite) = suite {
        provider.cipher_suites.retain(|s| s.suite() == suite);
    }
    let provider = Arc::new(provider);
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    Arc::new(config)
}

async fn join(
    addr: &str,
    config: Arc<ClientConfig>,
    secret: &[u8],
    id: &str,
    role: Role,
) -> (tokio_rustls::client::TlsStream<TcpStream>, CipherSuite) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let name = ServerName::try_from("transfer.local").unwrap();
    let mut stream = TlsConnector::from(config).connect(name, tcp).await.unwrap();
    let suite = stream.get_ref().1.negotiated_cipher_suite().unwrap().suite();
    let ticket = Ticket {
        transfer_id: id.into(),
        role,
        relay_id: "bench".into(),
        expires_at: now_secs() + 60,
    };
    write_frame(&mut stream, &TunnelHello { ticket: ticket::sign(secret, &ticket) }).await.unwrap();
    let status: TunnelStatus = read_frame(&mut stream).await.unwrap();
    assert!(status.paired, "{:?}", status.error);
    (stream, suite)
}

async fn run(addr: &str, secret: &[u8], id: &str, suite: Option<CipherSuite>, megabytes: usize) {
    let config = client(suite);
    let sender = join(addr, config.clone(), secret, id, Role::Sender);
    let receiver = join(addr, config, secret, id, Role::Receiver);
    let ((mut tx, negotiated), (mut rx, _)) = tokio::join!(sender, receiver);
    let total = megabytes * 1024 * 1024;
    let started = Instant::now();
    let send = async {
        let chunk = vec![7u8; CHUNK];
        let mut sent = 0;
        while sent < total {
            let n = CHUNK.min(total - sent);
            tx.write_all(&chunk[..n]).await.unwrap();
            tx.flush().await.unwrap();
            sent += n;
        }
    };
    let receive = async {
        let mut buf = vec![0u8; 256 * 1024];
        let mut received = 0;
        while received < total {
            received += rx.read(&mut buf).await.unwrap();
        }
    };
    tokio::join!(send, receive);
    let seconds = started.elapsed().as_secs_f64();
    let label = suite.map_or("client default".to_string(), |s| format!("{s:?}"));
    println!(
        "{label:<40} negotiated {:<34} {:>7.1} MB/s  {:>6.0} Mbit/s",
        format!("{negotiated:?}"),
        megabytes as f64 / seconds,
        megabytes as f64 * 8.388_608 / seconds,
    );
}

#[tokio::main]
async fn main() {
    let megabytes = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(256);
    let dir = tempfile_dir();
    let identity = tls::self_signed_identity(&dir, "relay").unwrap();
    let secret: Arc<Vec<u8>> = Arc::new(vec![42; 32]);
    let relay = Relay::new("bench".into(), String::new(), 16, identity.fingerprint, secret.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(relay.serve(listener, TlsAcceptor::from(identity.config)));

    let suites = [
        Some(CipherSuite::TLS13_AES_256_GCM_SHA384),
        Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        None,
    ];
    for (i, suite) in suites.into_iter().enumerate() {
        run(&addr, &secret, &format!("run-{i}"), suite, megabytes).await;
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn tempfile_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("relay-bench-{}", std::process::id()))
}

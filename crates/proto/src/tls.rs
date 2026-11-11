//! TLS setup. Clients either trust the public web PKI or pin the SHA-256 of a
//! self-signed certificate, which is how relays are always authenticated.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
pub use rustls::ClientConfig;
use rustls::{DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

pub fn fingerprint(cert: &[u8]) -> String {
    hex::encode(Sha256::digest(cert))
}

#[derive(Debug)]
struct PinnedCert {
    fingerprint: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// `pin` is the hex SHA-256 of the server certificate; `None` uses the web PKI.
pub fn client_config(pin: Option<&str>) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let config = match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert {
                fingerprint: normalize_fingerprint(pin),
                provider,
            }))
            .with_no_client_auth(),
        None => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

/// Accepts fingerprints pasted with colons, spaces or uppercase.
pub fn normalize_fingerprint(pin: &str) -> String {
    pin.chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub async fn connect(addr: &str, config: Arc<ClientConfig>) -> io::Result<TlsStream<TcpStream>> {
    let (host, _) = addr
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the address is missing the port"))?;
    let host = host.trim_matches(['[', ']']).to_string();
    let name = ServerName::try_from(host)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    TlsConnector::from(config).connect(name, tcp).await
}

pub struct Identity {
    pub config: Arc<ServerConfig>,
    pub fingerprint: String,
}

fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Identity, rustls::Error> {
    let fingerprint = fingerprint(certs.first().map(|c| c.as_ref()).unwrap_or_default());
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Identity { config: Arc::new(config), fingerprint })
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Loads PEM files issued by a CA, e.g. Let's Encrypt.
pub fn load_identity(cert: &Path, key: &Path) -> io::Result<Identity> {
    let mut cert_pem = io::BufReader::new(std::fs::File::open(cert)?);
    let certs = rustls_pemfile::certs(&mut cert_pem).collect::<Result<Vec<_>, _>>()?;
    let mut key_pem = io::BufReader::new(std::fs::File::open(key)?);
    let key = rustls_pemfile::private_key(&mut key_pem)?
        .ok_or_else(|| invalid("no private key found"))?;
    server_config(certs, key).map_err(invalid)
}

/// Loads the self-signed identity in `dir`, creating it on first use so the
/// fingerprint survives restarts.
pub fn self_signed_identity(dir: &Path, name: &str) -> io::Result<Identity> {
    let (cert_path, key_path) = (dir.join(format!("{name}.crt")), dir.join(format!("{name}.key")));
    if !cert_path.exists() || !key_path.exists() {
        let generated = rcgen::generate_simple_self_signed(vec!["transfer.local".to_string()])
            .map_err(invalid)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&cert_path, generated.cert.pem())?;
        write_private(&key_path, generated.key_pair.serialize_pem().as_bytes())?;
    }
    load_identity(&cert_path, &key_path)
}

/// Writes a secret readable only by the owner where the platform supports it.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

//! End-to-end encryption between friends, using Noise so neither the control
//! server nor the relays can read or forge what clients exchange.
//!
//! - Offers are sealed with the one-way `K` pattern.
//! - Tunnels use `KK`, which adds ephemeral keys and forward secrecy.
//!
//! Both patterns assume each side already knows the other's static key, which
//! comes from the pinned friend list.

use anyhow::{bail, Context, Result};
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SEAL_PATTERN: &str = "Noise_K_25519_ChaChaPoly_BLAKE2s";
const TUNNEL_PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
const NOISE_MAX: usize = 65535;
/// Largest payload of one tunnel message, leaving room for the kind byte and
/// the AEAD tag.
pub const MAX_PAYLOAD: usize = 60_000;

pub struct Identity {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let keys = Builder::new(SEAL_PATTERN.parse()?).generate_keypair()?;
        Ok(Self { private: keys.private, public: keys.public })
    }
}

/// Short form of a public key, for people to compare over another channel.
pub fn key_fingerprint(public: &[u8]) -> String {
    let digest = blake3::hash(public).to_hex();
    let hex = digest.as_str();
    (0..6).map(|i| &hex[i * 4..i * 4 + 4]).collect::<Vec<_>>().join(" ")
}

fn handshake(
    pattern: &str,
    identity: &Identity,
    peer: &[u8],
    prologue: &[u8],
    initiator: bool,
) -> Result<HandshakeState> {
    let builder = Builder::new(pattern.parse()?)
        .local_private_key(&identity.private)?
        .remote_public_key(peer)?
        .prologue(prologue)?;
    Ok(if initiator { builder.build_initiator()? } else { builder.build_responder()? })
}

fn push_chunk(out: &mut Vec<u8>, chunk: &[u8]) {
    out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
    out.extend_from_slice(chunk);
}

/// Encrypts for `peer`. The output may hold several Noise messages because each
/// one is limited to 64 KiB and a file list can be larger.
pub fn seal(identity: &Identity, peer: &[u8], prologue: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let mut hs = handshake(SEAL_PATTERN, identity, peer, prologue, true)?;
    let mut buf = vec![0u8; NOISE_MAX];
    let mut out = Vec::with_capacity(plain.len() + 128);
    let n = hs.write_message(&[], &mut buf)?;
    push_chunk(&mut out, &buf[..n]);
    let mut transport = hs.into_transport_mode()?;
    for chunk in plain.chunks(MAX_PAYLOAD) {
        let n = transport.write_message(chunk, &mut buf)?;
        push_chunk(&mut out, &buf[..n]);
    }
    Ok(out)
}

pub fn open(identity: &Identity, peer: &[u8], prologue: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    fn next<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
        let (len, rest) = input.split_first_chunk::<2>().context("oferta truncada")?;
        let len = u16::from_be_bytes(*len) as usize;
        let (chunk, rest) = rest.split_at_checked(len).context("oferta truncada")?;
        *input = rest;
        Ok(chunk)
    }

    let mut input = sealed;
    let mut hs = handshake(SEAL_PATTERN, identity, peer, prologue, false)?;
    let mut buf = vec![0u8; NOISE_MAX];
    hs.read_message(next(&mut input)?, &mut buf)?;
    let mut transport = hs.into_transport_mode()?;
    let mut out = Vec::with_capacity(sealed.len());
    while !input.is_empty() {
        let n = transport.read_message(next(&mut input)?, &mut buf)?;
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Encrypted message stream over any byte pipe.
pub struct Tunnel<S> {
    stream: S,
    noise: TransportState,
    cipher: Vec<u8>,
    plain: Vec<u8>,
}

async fn read_message<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> Result<usize> {
    let len = stream.read_u16().await? as usize;
    stream.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

async fn write_message<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<()> {
    stream.write_u16(data.len() as u16).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

impl<S: AsyncRead + AsyncWrite + Unpin> Tunnel<S> {
    pub async fn establish(
        mut stream: S,
        identity: &Identity,
        peer: &[u8],
        prologue: &[u8],
        initiator: bool,
    ) -> Result<Self> {
        let mut hs = handshake(TUNNEL_PATTERN, identity, peer, prologue, initiator)?;
        let mut cipher = vec![0u8; NOISE_MAX];
        let mut plain = vec![0u8; NOISE_MAX];
        if initiator {
            let n = hs.write_message(&[], &mut cipher)?;
            write_message(&mut stream, &cipher[..n]).await?;
            let n = read_message(&mut stream, &mut cipher).await?;
            hs.read_message(&cipher[..n], &mut plain)?;
        } else {
            let n = read_message(&mut stream, &mut cipher).await?;
            hs.read_message(&cipher[..n], &mut plain)?;
            let n = hs.write_message(&[], &mut cipher)?;
            write_message(&mut stream, &cipher[..n]).await?;
        }
        Ok(Self { stream, noise: hs.into_transport_mode()?, cipher, plain })
    }

    pub async fn send(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_PAYLOAD {
            bail!("mensaje de túnel demasiado grande");
        }
        self.plain[0] = kind;
        self.plain[1..=payload.len()].copy_from_slice(payload);
        let n = self.noise.write_message(&self.plain[..=payload.len()], &mut self.cipher)?;
        write_message(&mut self.stream, &self.cipher[..n]).await
    }

    /// Returns the message kind and its payload, valid until the next call.
    pub async fn recv(&mut self) -> Result<(u8, &[u8])> {
        let n = read_message(&mut self.stream, &mut self.cipher).await?;
        let n = self.noise.read_message(&self.cipher[..n], &mut self.plain)?;
        match self.plain[..n].split_first() {
            Some((kind, payload)) => Ok((*kind, payload)),
            None => bail!("mensaje de túnel vacío"),
        }
    }

    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_handles_large_payloads() {
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let plain = vec![7u8; 200_000];
        let sealed = seal(&a, &b.public, b"ctx", &plain).unwrap();
        assert_eq!(open(&b, &a.public, b"ctx", &sealed).unwrap(), plain);
    }

    #[test]
    fn seal_rejects_wrong_sender_context_or_tampering() {
        let (a, b, c) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let mut sealed = seal(&a, &b.public, b"ctx", b"secret").unwrap();
        assert!(open(&b, &c.public, b"ctx", &sealed).is_err());
        assert!(open(&b, &a.public, b"other", &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&b, &a.public, b"ctx", &sealed).is_err());
    }

    #[tokio::test]
    async fn tunnel_detects_an_impostor() {
        let (a, b, mallory) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let (x, y) = tokio::io::duplex(1 << 16);
        // `a` expects `b`, but `mallory` answers claiming to know `a`.
        let (left, right) = tokio::join!(
            Tunnel::establish(x, &a, &b.public, b"ctx", true),
            Tunnel::establish(y, &mallory, &a.public, b"ctx", false),
        );
        assert!(left.is_err() || right.is_err());
    }

    #[tokio::test]
    async fn tunnel_carries_messages() {
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let (x, y) = tokio::io::duplex(1 << 18);
        let (left, right) = tokio::join!(
            Tunnel::establish(x, &a, &b.public, b"ctx", true),
            Tunnel::establish(y, &b, &a.public, b"ctx", false),
        );
        let (mut left, mut right) = (left.unwrap(), right.unwrap());
        left.send(9, b"hola").await.unwrap();
        let (kind, payload) = right.recv().await.unwrap();
        assert_eq!((kind, payload), (9, &b"hola"[..]));
    }
}

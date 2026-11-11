//! Tickets let a relay admit a client without talking to the control server:
//! the control server signs them with the secret it shares with its relays.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub transfer_id: String,
    pub role: Role,
    pub relay_id: String,
    pub expires_at: u64,
}

fn mac(secret: &[u8], body: &[u8]) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
    m.update(body);
    m
}

pub fn sign(secret: &[u8], ticket: &Ticket) -> String {
    let body = serde_json::to_vec(ticket).expect("ticket serializes");
    let tag = mac(secret, &body).finalize().into_bytes();
    format!("{}.{}", B64.encode(&body), B64.encode(tag))
}

/// Checks signature, destination relay and expiry.
pub fn verify(secret: &[u8], token: &str, relay_id: &str, now: u64) -> Option<Ticket> {
    let (body, tag) = token.split_once('.')?;
    let body = B64.decode(body).ok()?;
    let tag = B64.decode(tag).ok()?;
    mac(secret, &body).verify_slice(&tag).ok()?;
    let ticket: Ticket = serde_json::from_slice(&body).ok()?;
    (ticket.relay_id == relay_id && ticket.expires_at > now).then_some(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Ticket {
        Ticket {
            transfer_id: "t1".into(),
            role: Role::Sender,
            relay_id: "r1".into(),
            expires_at: 100,
        }
    }

    #[test]
    fn accepts_valid_ticket() {
        let t = sign(b"secret", &sample());
        assert_eq!(verify(b"secret", &t, "r1", 99), Some(sample()));
    }

    #[test]
    fn rejects_wrong_secret_relay_or_expired() {
        let t = sign(b"secret", &sample());
        assert!(verify(b"other", &t, "r1", 99).is_none());
        assert!(verify(b"secret", &t, "r2", 99).is_none());
        assert!(verify(b"secret", &t, "r1", 100).is_none());
    }

    #[test]
    fn rejects_tampered_body() {
        let t = sign(b"secret", &sample());
        let (_, tag) = t.split_once('.').unwrap();
        let mut forged = sample();
        forged.role = Role::Receiver;
        let body = B64.encode(serde_json::to_vec(&forged).unwrap());
        assert!(verify(b"secret", &format!("{body}.{tag}"), "r1", 99).is_none());
    }
}

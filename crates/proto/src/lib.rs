//! Protocol shared by the client, the control server and the relays.
//!
//! Control channel: TLS over TCP carrying length-prefixed JSON frames.
//! Tunnel: TLS over TCP to a relay; after pairing the relay only forwards
//! bytes, and the clients run their own end-to-end encrypted session on top.

pub mod ticket;
pub mod tls;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for one control frame. Large because offers carry the sealed
/// file list.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
/// Upper bound for a sealed offer, leaving room for the frame envelope.
pub const MAX_SEALED: usize = 3 * 1024 * 1024;

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

pub async fn read_frame<R, T>(r: &mut R) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// First-level message received by the control port.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Inbound {
    Req { id: u64, body: Request },
    RelayHello(RelayHello),
    RelayLoad { active: u32 },
}

/// First-level message sent by the control port.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Outbound {
    Res { id: u64, body: Result<Response, ApiError> },
    Event { body: Event },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHello {
    pub secret: String,
    pub relay_id: String,
    pub public_addr: String,
    pub fingerprint: String,
    pub capacity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Register { username: String, password: String, device_key: String },
    Login { username: String, password: String, device_key: String },
    Resume { token: String },
    Logout,
    ChangePassword { old_password: String, new_password: String },
    Friends,
    FriendAdd { username: String },
    FriendRespond { username: String, accept: bool },
    FriendRemove { username: String },
    Offer { to: String, transfer_id: String, sealed: String },
    OfferRespond { transfer_id: String, accept: bool },
    TransferCancel { transfer_id: String },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Session { username: String, token: String },
    Resumed { username: String },
    Friends { friends: Vec<FriendInfo> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FriendStatus {
    Accepted,
    /// They asked us; we can accept.
    Incoming,
    /// We asked them; waiting for their answer.
    Outgoing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendInfo {
    pub username: String,
    pub status: FriendStatus,
    pub online: bool,
    /// Base64 X25519 identity key. Only present for accepted friends.
    pub device_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEndpoint {
    pub addr: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "e", rename_all = "snake_case")]
pub enum Event {
    FriendsChanged,
    Presence { username: String, online: bool },
    Offer { from: String, transfer_id: String, sealed: String },
    OfferDeclined { transfer_id: String },
    TransferReady { transfer_id: String, relay: RelayEndpoint, ticket: String },
    TransferCancelled { transfer_id: String, reason: String },
    /// The account logged in elsewhere; this session is no longer valid.
    SessionReplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ApiError {
    #[error("usernames must be 3-32 characters: a-z, 0-9, dot, hyphen or underscore")]
    InvalidUsername,
    #[error("passwords must be between 10 and 128 characters")]
    WeakPassword,
    #[error("that username is already taken")]
    UsernameTaken,
    #[error("wrong username or password")]
    BadCredentials,
    #[error("session expired, please sign in again")]
    Unauthorized,
    #[error("too many attempts, wait a few minutes")]
    RateLimited,
    #[error("that user does not exist")]
    UserNotFound,
    #[error("you cannot add yourself")]
    SelfFriend,
    #[error("you can only send files to your friends")]
    NotFriends,
    #[error("that friend is offline")]
    PeerOffline,
    #[error("that transfer no longer exists")]
    UnknownTransfer,
    #[error("too many pending transfers")]
    TooManyTransfers,
    #[error("no relay available")]
    NoRelay,
    #[error("invalid request")]
    BadRequest,
    #[error("internal server error")]
    Internal,
}

/// First frame a client sends to a relay.
#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelHello {
    pub ticket: String,
}

/// Sent by the relay once, right before the socket turns into a raw pipe.
#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub paired: bool,
    pub error: Option<String>,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

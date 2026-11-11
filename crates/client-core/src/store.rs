//! Local files in the client data directory.

use crate::crypto::Identity;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use transfer_proto::tls::write_private;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// host:port of the control server.
    pub server: String,
    /// Certificate fingerprint for self-signed servers; empty uses the web PKI.
    #[serde(default)]
    pub fingerprint: String,
    pub download_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSession {
    pub username: String,
    pub token: String,
}

/// Replaces the file atomically so a crash cannot leave it half written.
fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("tmp");
    write_private(&tmp, &serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice(&data).ok()
}

pub fn load_identity(dir: &Path) -> Result<Identity> {
    let path = dir.join("identity.key");
    if let Ok(data) = std::fs::read(&path) {
        anyhow::ensure!(data.len() == 64, "identity.key is corrupt");
        return Ok(Identity { private: data[..32].to_vec(), public: data[32..].to_vec() });
    }
    let identity = Identity::generate()?;
    let data = [identity.private.as_slice(), identity.public.as_slice()].concat();
    write_private(&path, &data).context("could not save the identity key")?;
    Ok(identity)
}

pub fn load_settings(dir: &Path) -> Option<Settings> {
    load_json(&dir.join("settings.json"))
}

pub fn save_settings(dir: &Path, settings: &Settings) -> Result<()> {
    save_json(&dir.join("settings.json"), settings)
}

pub fn load_session(dir: &Path) -> Option<SavedSession> {
    load_json(&dir.join("session.json"))
}

pub fn save_session(dir: &Path, session: &SavedSession) -> Result<()> {
    save_json(&dir.join("session.json"), session)
}

pub fn clear_session(dir: &Path) {
    let _ = std::fs::remove_file(dir.join("session.json"));
}

fn pins_path(dir: &Path, username: &str) -> PathBuf {
    dir.join(format!("pins-{username}.json"))
}

pub fn load_pins(dir: &Path, username: &str) -> HashMap<String, String> {
    load_json(&pins_path(dir, username)).unwrap_or_default()
}

pub fn save_pins(dir: &Path, username: &str, pins: &HashMap<String, String>) -> Result<()> {
    save_json(&pins_path(dir, username), pins)
}

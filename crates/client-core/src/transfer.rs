//! File exchange inside a relay tunnel.

use crate::crypto::{Identity, Tunnel, MAX_PAYLOAD};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use transfer_proto::{read_frame, tls, write_frame, RelayEndpoint, TunnelHello, TunnelStatus};
use walkdir::WalkDir;

const MSG_DATA: u8 = 1;
const MSG_FILE_END: u8 = 2;
const MSG_ALL_DONE: u8 = 3;
const MSG_ACK: u8 = 4;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const PAIR_TIMEOUT: Duration = Duration::from_secs(50);
const IO_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_PATH_DEPTH: usize = 64;
const PART_SUFFIX: &str = ".part";

/// The sealed content of an offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path with `/` separators.
    pub path: String,
    pub size: u64,
}

impl Manifest {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// Everything a transfer needs once the relay is known.
pub struct Plan {
    pub id: String,
    pub sender: String,
    pub receiver: String,
    /// True on the sending side.
    pub sending: bool,
    pub peer_key: Vec<u8>,
    pub files: Vec<FileEntry>,
    pub sources: Vec<PathBuf>,
    pub dest: PathBuf,
}

/// Binds a sealed offer to its transfer and participants.
pub fn seal_context(id: &str, sender: &str, receiver: &str) -> Vec<u8> {
    format!("transfer-seal-v1|{id}|{sender}|{receiver}").into_bytes()
}

fn tunnel_context(plan: &Plan) -> Vec<u8> {
    format!("transfer-tunnel-v1|{}|{}|{}", plan.id, plan.sender, plan.receiver).into_bytes()
}

/// Expands files and folders into a manifest. Symlinks are skipped so sending a
/// folder cannot leak what lies outside it.
pub fn scan(paths: &[PathBuf]) -> Result<(Manifest, Vec<PathBuf>)> {
    let mut files = Vec::new();
    let mut sources = Vec::new();
    for root in paths {
        let meta = std::fs::symlink_metadata(root)
            .with_context(|| format!("cannot read {}", root.display()))?;
        let name = root
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| format!("invalid name: {}", root.display()))?;
        if meta.is_file() {
            files.push(FileEntry { path: name.to_string(), size: meta.len() });
            sources.push(root.clone());
        } else if meta.is_dir() {
            for entry in WalkDir::new(root).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let relative = entry.path().strip_prefix(root)?;
                let mut path = name.to_string();
                for part in relative.components() {
                    path.push('/');
                    path.push_str(part.as_os_str().to_str().context("invalid name")?);
                }
                files.push(FileEntry { path, size: entry.metadata()?.len() });
                sources.push(entry.into_path());
            }
        }
    }
    if files.is_empty() {
        bail!("there are no files to send");
    }
    Ok((Manifest { files }, sources))
}

/// Turns a path received from a peer into one safe to create under the download
/// folder. Traversal is refused; characters Windows forbids are replaced, which
/// also blocks NTFS alternate data streams.
pub fn safe_relative_path(path: &str) -> Option<PathBuf> {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_PATH_DEPTH {
        return None;
    }
    let mut safe = PathBuf::new();
    for part in parts {
        if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
            return None;
        }
        let clean: String = part
            .chars()
            .map(|c| if c.is_control() || "<>:\"|?*".contains(c) { '_' } else { c })
            .collect();
        let clean = clean.trim_end_matches([' ', '.']);
        if clean.is_empty() || clean.len() > 240 {
            return None;
        }
        let stem = clean.split('.').next().unwrap_or(clean).to_ascii_uppercase();
        if RESERVED.contains(&stem.as_str()) {
            safe.push(format!("_{clean}"));
        } else {
            safe.push(clean);
        }
    }
    Some(safe)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// First free name: `a.txt`, `a (1).txt`, `a (2).txt`…
fn free_path(path: &Path) -> PathBuf {
    let taken = |p: &Path| p.exists() || with_suffix(p, PART_SUFFIX).exists();
    if !taken(path) {
        return path.to_path_buf();
    }
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let ext = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    (1u32..)
        .map(|n| path.with_file_name(format!("{stem} ({n}){ext}")))
        .find(|p| !taken(p))
        .expect("an unused name exists")
}

/// Removes a partial download, retrying because Windows refuses while the file
/// is still closing in the background.
pub async fn remove_part(path: &Path) {
    for _ in 0..20 {
        match fs::remove_file(path).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            _ => return,
        }
    }
    tracing::warn!("could not delete {}", path.display());
}

/// Connects to the relay and transfers everything. `progress` receives the
/// bytes done so far; `part` tracks the file being written so the caller can
/// clean up even if this future is dropped. On the receiving side, returns
/// where the first file was saved.
pub async fn run(
    identity: &Identity,
    plan: &Plan,
    relay: &RelayEndpoint,
    ticket: String,
    progress: &(dyn Fn(u64) + Send + Sync),
    part: &Mutex<Option<PathBuf>>,
) -> Result<Option<PathBuf>> {
    let config = tls::client_config(Some(&relay.fingerprint))?;
    let mut stream = timeout(CONNECT_TIMEOUT, tls::connect(&relay.addr, config))
        .await
        .context("the relay is not responding")?
        .context("could not connect to the relay")?;
    write_frame(&mut stream, &TunnelHello { ticket }).await?;
    let status: TunnelStatus = timeout(PAIR_TIMEOUT, read_frame(&mut stream))
        .await
        .context("the other side did not connect")?
        .context("the relay closed the connection")?;
    if !status.paired {
        bail!(status.error.unwrap_or_else(|| "the relay rejected the tunnel".into()));
    }

    let context = tunnel_context(plan);
    let mut tunnel =
        Tunnel::establish(stream, identity, &plan.peer_key, &context, plan.sending)
            .await
            .context("could not verify the identity of the other side")?;
    progress(0);
    let saved = if plan.sending {
        send_files(&mut tunnel, plan, progress).await?;
        None
    } else {
        receive_files(&mut tunnel, plan, progress, part).await?
    };
    tunnel.shutdown().await;
    Ok(saved)
}

async fn send_files<S>(
    tunnel: &mut Tunnel<S>,
    plan: &Plan,
    progress: &(dyn Fn(u64) + Send + Sync),
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let mut done = 0u64;
    for (entry, source) in plan.files.iter().zip(&plan.sources) {
        let mut file = File::open(source)
            .await
            .with_context(|| format!("cannot open {}", source.display()))?;
        let mut hasher = blake3::Hasher::new();
        let mut sent = 0u64;
        loop {
            let want = (entry.size - sent).min(buf.len() as u64) as usize;
            if want == 0 {
                break;
            }
            let n = file.read(&mut buf[..want]).await?;
            if n == 0 {
                bail!("{} changed while being sent", source.display());
            }
            hasher.update(&buf[..n]);
            timeout(IO_TIMEOUT, tunnel.send(MSG_DATA, &buf[..n]))
                .await
                .context("the other side is not receiving data")??;
            sent += n as u64;
            done += n as u64;
            progress(done);
        }
        tunnel.send(MSG_FILE_END, hasher.finalize().as_bytes()).await?;
    }
    tunnel.send(MSG_ALL_DONE, &[]).await?;
    let (kind, _) = timeout(IO_TIMEOUT, tunnel.recv())
        .await
        .context("no confirmation from the receiver")??;
    if kind != MSG_ACK {
        bail!("unexpected response from the receiver");
    }
    Ok(())
}

async fn receive_files<S>(
    tunnel: &mut Tunnel<S>,
    plan: &Plan,
    progress: &(dyn Fn(u64) + Send + Sync),
    part_slot: &Mutex<Option<PathBuf>>,
) -> Result<Option<PathBuf>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let set_part = |value: Option<PathBuf>| {
        *part_slot.lock().unwrap_or_else(|e| e.into_inner()) = value;
    };
    let mut done = 0u64;
    let mut first_saved = None;
    for entry in &plan.files {
        let relative = safe_relative_path(&entry.path).context("invalid path in the offer")?;
        let target = free_path(&plan.dest.join(relative));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await?;
        }
        let part = with_suffix(&target, PART_SUFFIX);
        let mut file = OpenOptions::new().write(true).create_new(true).open(&part).await?;
        set_part(Some(part.clone()));

        let mut hasher = blake3::Hasher::new();
        let mut written = 0u64;
        loop {
            let (kind, payload) = timeout(IO_TIMEOUT, tunnel.recv())
                .await
                .context("the sender stopped sending")?
                .context("lost the connection to the sender")?;
            match kind {
                MSG_DATA => {
                    written += payload.len() as u64;
                    if written > entry.size {
                        bail!("the sender sent more data than announced");
                    }
                    hasher.update(payload);
                    file.write_all(payload).await?;
                    done += payload.len() as u64;
                    progress(done);
                }
                MSG_FILE_END => {
                    if written != entry.size || payload != hasher.finalize().as_bytes() {
                        bail!("{} arrived corrupted", entry.path);
                    }
                    break;
                }
                _ => bail!("unexpected message from the sender"),
            }
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        // Something else may have claimed the name during a long download.
        let target = if target.exists() { free_path(&target) } else { target };
        fs::rename(&part, &target).await?;
        set_part(None);
        first_saved.get_or_insert(target);
    }
    let (kind, _) = timeout(IO_TIMEOUT, tunnel.recv())
        .await
        .context("the sender did not finish the transfer")??;
    if kind != MSG_ALL_DONE {
        bail!("the sender sent more files than announced");
    }
    tunnel.send(MSG_ACK, &[]).await?;
    Ok(first_saved)
}

/// What to show for a finished download: the file itself, or for several files
/// the top-level item they arrived in.
pub fn saved_location(dest: &Path, first_saved: &Path, file_count: usize) -> PathBuf {
    let top_level = first_saved.strip_prefix(dest).ok().and_then(|p| p.components().next());
    match top_level {
        Some(item) if file_count > 1 => dest.join(item),
        _ => first_saved.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_is_refused() {
        for bad in ["../evil", "a/../../evil", "/etc/passwd", "a//b", "a\\..\\b", "..", "...", ""] {
            assert!(safe_relative_path(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn windows_tricks_are_neutralized() {
        let safe = |p: &str| safe_relative_path(p).unwrap();
        assert_eq!(safe("C:evil"), PathBuf::from("C_evil"));
        assert_eq!(safe("doc.txt:stream"), PathBuf::from("doc.txt_stream"));
        assert_eq!(safe("trailing. "), PathBuf::from("trailing"));
        assert_eq!(safe("NUL"), PathBuf::from("_NUL"));
        assert_eq!(safe("con.txt"), PathBuf::from("_con.txt"));
        assert_eq!(safe("folder/ok.txt"), PathBuf::from("folder").join("ok.txt"));
    }

    #[test]
    fn free_path_never_collides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        assert_eq!(free_path(&path), path);
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(free_path(&path), dir.path().join("a (1).txt"));
        std::fs::write(dir.path().join("a (1).txt.part"), b"x").unwrap();
        assert_eq!(free_path(&path), dir.path().join("a (2).txt"));
    }

    #[test]
    fn location_of_several_files_is_their_top_level_item() {
        let dest = Path::new("descargas");
        let file = dest.join("photos").join("2026").join("a.jpg");
        assert_eq!(saved_location(dest, &file, 1), file);
        assert_eq!(saved_location(dest, &file, 3), dest.join("photos"));
    }

    #[test]
    fn scan_walks_folders_with_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("photos");
        std::fs::create_dir_all(root.join("2026")).unwrap();
        std::fs::write(root.join("2026").join("a.jpg"), b"123").unwrap();
        let (manifest, sources) = scan(&[root]).unwrap();
        assert_eq!(manifest.files[0].path, "photos/2026/a.jpg");
        assert_eq!(manifest.total_bytes(), 3);
        assert_eq!(sources.len(), 1);
    }
}

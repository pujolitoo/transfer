# Transfer

File transfer between friends over TCP tunnels. Each user has an account and an app in the system tray; files travel through intermediary servers that only ever see encrypted data.

```text
 Client A ──TLS──► Control server ◄──TLS── Client B
     │             accounts · friends · presence │
     │             signalling · picks a relay    │
     │                                           │
     └──TLS──────►  Relay (one or more)  ◄──TLS──┘
                    pairs and forwards bytes
          ═══════ end-to-end Noise encryption ═══════
```

| Crate | Contents |
| --- | --- |
| `crates/proto` | Shared protocol, tickets and TLS |
| `crates/server` | `transfer-server` binary: control, relay and SQLite database |
| `crates/client-core` | Client engine: session, reconnection, encryption and transfers |
| `crates/app` | Tauri 2 desktop app: tray, window and notifications |

## Running locally

Requires stable Rust. On Windows you also need the Visual Studio Build Tools; WebView2 ships with Windows 11.

```bash
cargo build --release -p transfer-server -p transfer-app
```

Start the server in a terminal:

```bash
./target/release/transfer-server all
```

It creates `data/` and prints the `fingerprint` of its self-signed certificate. Open `target/release/transfer.exe`, expand **Server**, paste that fingerprint and create an account.

To try two clients on the same machine, start the second one with its own data. In PowerShell:

```powershell
$env:TRANSFER_DATA_DIR = "$env:TEMP\transfer-b"; $env:WEBVIEW2_USER_DATA_FOLDER = "$env:TEMP\transfer-b\wv"; .\target\release\transfer.exe
```

## Deployment

### Single server

Open TCP ports 7443 (control) and 7444 (relay). `--relay-public-addr` is required: it is the address clients are given, and its default only works locally.

```bash
TRANSFER_DATA_DIR=/var/lib/transfer transfer-server all --relay-public-addr my-server.com:7444
```

There is also a `Dockerfile` and a `docker-compose.yml`. Put the public address in `.env` as `RELAY_PUBLIC_ADDR=my-server.com:7444` and start it:

```bash
docker compose up -d --build
```

The certificate fingerprint shows up in the logs and survives restarts, like the accounts, in the `transfer-data` volume:

```bash
docker compose logs transfer
```

### Several relays

Generate a secret and use it on every server:

```bash
openssl rand -hex 32
```

On the control server:

```bash
TRANSFER_RELAY_SECRET=<secret> transfer-server control
```

On each relay:

```bash
TRANSFER_RELAY_SECRET=<secret> transfer-server relay --control-addr control.my-domain.com:7443 --control-fingerprint <fingerprint> --relay-public-addr relay1.my-domain.com:7444
```

Each relay registers itself and reports its load; the control server assigns each transfer to the least busy one.

### Control certificate

With no configuration a self-signed certificate is used and every client has to paste its fingerprint. With a Let's Encrypt certificate, clients leave the fingerprint empty:

```bash
transfer-server all --tls-cert fullchain.pem --tls-key privkey.pem --relay-public-addr my-server.com:7444
```

Relays always use self-signed certificates: the control server hands their fingerprints to clients.

## How a transfer works

1. The sender encrypts the file list for the receiver and sends it as an offer. The server sees neither names nor sizes.
2. On acceptance, the control server picks a relay and gives each client a signed ticket: valid for 60 seconds, single use and bound to that relay.
3. Both clients connect to the relay, which pairs them and starts forwarding bytes.
4. Over that tunnel they negotiate a `Noise_KK` session with ephemeral keys and their identity keys.
5. Each file is written as `.part`, verified with BLAKE3, and only then given its final name.

## Security

- **Passwords:** Argon2id, with attempt limits per IP and per user.
- **Sessions:** the server only stores the SHA-256 hash of the token, which expires after 30 days without use.
- **Friends' keys:** pinned the first time they are seen. If they change, transfers are blocked until the user trusts the new key. To be protected from a malicious server from the start, compare fingerprints through another channel.
- **Received paths:** `..` is rejected, and absolute paths, NTFS alternate data streams and reserved Windows names are neutralised. Symbolic links are not sent.

## Known limitations

- An account has a single active device: signing in on another one disconnects the previous one and changes the key.
- An interrupted transfer starts again from scratch.
- Both users must be online.
- There is no password recovery, email verification or account deletion.
- Registration is open to anyone who can reach the server, with a per-IP limit.
- Relay quota and bandwidth are not limited per user.
- On the client, the identity key and the token are stored unencrypted in the user's data folder. Any program running under that account can read them.

## Development

```bash
cargo test --workspace
```

The tests in `crates/client-core/tests/e2e.rs` start a real server and relays and connect clients over TCP and TLS.

## Windows installer

You need `tauri-cli`:

```bash
cargo install tauri-cli --version "^2" --locked
```

The build signs the update files, so it needs the signing key described under [Updates](#updates):

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY = "$env:USERPROFILE\.tauri\transfer-updater.key"; $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ""
```

Build the installer with its own build directory, so it works even while the app in `target/release` is open:

```bash
cd crates/app && CARGO_TARGET_DIR=../../target/installer cargo tauri build
```

The result lands in `target/installer/release/bundle/nsis/`. It needs no administrator rights: it installs for the current user and downloads WebView2 if missing.

The installer adds the start-with-Windows entry and a **Send with Transfer** option to the context menu of files and folders; uninstalling removes them. On Windows 11 that option appears under **Show more options**, because the new menu only accepts packaged apps. If the user turned off autostart in Settings, an update respects that choice.

## Updates

The client looks for a new version 20 seconds after starting and then every 6 hours, in `latest.json` of the latest GitHub release. If there is one, it downloads it in the background and checks its signature. It then announces it with a notification, a banner in the window and an **Install version…** entry in the tray menu. The update is installed when the user asks for it, or on **Quit**. If transfers are in progress, it asks for confirmation before restarting. **Check for updates** checks right away, from the tray or from Settings.

Updates are signed with a key of their own, separate from any Windows code-signing certificate. The public key is in `tauri.conf.json`. The private key is generated once, outside the repository:

```bash
cargo tauri signer generate -w "$env:USERPROFILE\.tauri\transfer-updater.key"
```

Keep a backup of that key: if it is lost, installed clients will not accept any more updates and will have to be reinstalled by hand.

To publish a version, with everything committed and the GitHub CLI signed in:

```bash
.\scripts\release.ps1 -Version 0.2.1 -Notes "What changed"
```

The script bumps the version, builds and signs the installer and generates `latest.json`. It then commits, tags, pushes and publishes the release. Clients pick it up on their next check.

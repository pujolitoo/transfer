//! Updates published as GitHub releases, at the endpoint in tauri.conf.json.
//! They are downloaded in the background and installed when the user asks or
//! quits, since installing restarts the app and cuts any transfer.

use std::time::Duration;
use serde::Serialize;
use tauri::menu::MenuItem;
use tauri::{AppHandle, Emitter, Manager, State, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::sync::Mutex;
use transfer_client_core::{Engine, TransferState};

use crate::{ask, notify, text_err, CmdResult};

/// Leaves time for the connection and the window before the first check.
const FIRST_CHECK: Duration = Duration::from_secs(20);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
const CHECK_LABEL: &str = "Buscar actualizaciones";

/// An update already downloaded and verified against the public key.
struct Ready {
    update: Update,
    bytes: Vec<u8>,
}

/// Held across a whole check, so two checks never download the same update.
#[derive(Default)]
pub struct Updates(Mutex<Option<Ready>>);

/// The tray entry, which checks or installs depending on the state.
pub struct UpdateItem(pub MenuItem<Wry>);

#[derive(Clone, Serialize)]
pub struct UpdateStatus {
    current: String,
    ready: Option<String>,
}

fn status(app: &AppHandle, ready: Option<String>) -> UpdateStatus {
    UpdateStatus { current: app.package_info().version.to_string(), ready }
}

/// Returns the version waiting to be installed, downloading it if needed.
async fn check(app: &AppHandle) -> anyhow::Result<Option<String>> {
    let state = app.state::<Updates>();
    let mut ready = state.0.lock().await;
    if let Some(ready) = ready.as_ref() {
        return Ok(Some(ready.update.version.clone()));
    }
    let Some(update) = app.updater()?.check().await? else {
        return Ok(None);
    };
    let bytes = update.download(|_, _| {}, || {}).await?;
    let version = update.version.clone();
    tracing::info!(%version, "update downloaded");
    *ready = Some(Ready { update, bytes });
    announce(app, &version);
    Ok(Some(version))
}

fn announce(app: &AppHandle, version: &str) {
    let _ = app.state::<UpdateItem>().0.set_text(format!("Instalar la versión {version}"));
    let _ = app.emit("update", status(app, Some(version.to_string())));
    notify(app, "Actualización disponible", &format!("Transfer {version} está lista para instalarse"));
}

pub async fn check_periodically(app: AppHandle) {
    tokio::time::sleep(FIRST_CHECK).await;
    loop {
        if let Err(e) = check(&app).await {
            tracing::warn!("update check failed: {e:#}");
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// Runs the installer and exits. With `restart`, the installer starts the app
/// again with the same arguments.
async fn install(app: &AppHandle, confirm: bool, restart: bool) -> anyhow::Result<()> {
    let state = app.state::<Updates>();
    let ready = state.0.lock().await;
    let Some(ready) = ready.as_ref() else {
        return Ok(());
    };
    let busy = app.state::<Engine>().snapshot().transfers.iter().any(|t| {
        matches!(t.state, TransferState::WaitingPeer | TransferState::Connecting | TransferState::Running)
    });
    if confirm && busy {
        let message = "Hay transferencias en curso y se cancelarán al reiniciar Transfer.".to_string();
        if !ask(app, message, "Actualizar".into()).await {
            return Ok(());
        }
    }
    ready.update.clone().restart_after_install(restart).install(&ready.bytes)?;
    Ok(())
}

/// Installs a downloaded update on the way out, without asking: the user
/// already chose to stop the app.
pub async fn install_on_exit(app: &AppHandle) {
    if let Err(e) = install(app, false, false).await {
        tracing::warn!("update install failed: {e:#}");
    }
}

fn info(app: &AppHandle, message: String) {
    app.dialog().message(message).title("Transfer").kind(MessageDialogKind::Info).show(|_| {});
}

/// The tray entry: installs what is ready, or checks now and says what it found.
pub fn tray_clicked(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let item = &app.state::<UpdateItem>().0;
        let _ = item.set_enabled(false);
        let _ = item.set_text("Buscando actualizaciones…");
        let result = check(&app).await;
        let _ = item.set_enabled(true);
        match result {
            Ok(Some(version)) => {
                let _ = item.set_text(format!("Instalar la versión {version}"));
                if let Err(e) = install(&app, true, true).await {
                    info(&app, format!("No se pudo instalar la actualización: {e:#}"));
                }
            }
            Ok(None) => {
                let _ = item.set_text(CHECK_LABEL);
                let version = app.package_info().version.to_string();
                info(&app, format!("Transfer está actualizado (versión {version})."));
            }
            Err(e) => {
                let _ = item.set_text(CHECK_LABEL);
                info(&app, format!("No se pudo comprobar si hay actualizaciones: {e:#}"));
            }
        }
    });
}

pub fn tray_item(app: &AppHandle) -> tauri::Result<MenuItem<Wry>> {
    MenuItem::with_id(app, "update", CHECK_LABEL, true, None::<&str>)
}

#[tauri::command]
pub async fn update_status(app: AppHandle, updates: State<'_, Updates>) -> CmdResult<UpdateStatus> {
    let ready = updates.0.lock().await.as_ref().map(|r| r.update.version.clone());
    Ok(status(&app, ready))
}

#[tauri::command]
pub async fn check_updates(app: AppHandle) -> CmdResult<UpdateStatus> {
    let ready = check(&app).await.map_err(text_err)?;
    Ok(status(&app, ready))
}

#[tauri::command]
pub async fn install_update(app: AppHandle) -> CmdResult {
    install(&app, true, true).await.map_err(text_err)
}

// No console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, RunEvent, State, WebviewWindowBuilder,
    WindowEvent, Wry,
};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as _};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::mpsc::UnboundedReceiver;
use transfer_client_core::{Connection, Engine, EngineEvent, Snapshot, TransferState, TransferView};

mod update;

const TRAY_ID: &str = "main";
const HIDDEN_ARG: &str = "--hidden";
/// Followed by a path. Written by the installer into the Explorer context menu.
const SEND_ARG: &str = "--send";
const SEND_LABEL: &str = "send";
const POPUP_LABEL: &str = "popup";
/// Gap between the popup and the screen edge, in logical pixels.
const POPUP_MARGIN: f64 = 12.0;
/// Lets several clients run on one machine, for testing.
const DATA_DIR_ENV: &str = "TRANSFER_DATA_DIR";
/// Opening one of these runs it instead of showing it.
const EXECUTABLE_EXTENSIONS: [&str; 24] = [
    "appx", "bat", "cmd", "com", "cpl", "exe", "hta", "jar", "js", "jse", "lnk", "msc", "msi",
    "msix", "pif", "ps1", "reg", "scr", "url", "vbe", "vbs", "wsf", "wsh", "wsc",
];

pub(crate) type CmdResult<T = ()> = Result<T, String>;

/// Paths chosen in Explorer, waiting for the user to pick a recipient. They stay
/// here rather than in the page, which only ever receives their names.
#[derive(Default)]
struct PendingSend(Mutex<Vec<PathBuf>>);

impl PendingSend {
    fn paths(&self) -> MutexGuard<'_, Vec<PathBuf>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Includes the whole error chain, which holds the actual cause.
pub(crate) fn text_err<E: std::fmt::Display>(e: E) -> String {
    format!("{e:#}")
}

fn paths_to_send(args: &[String]) -> Vec<PathBuf> {
    args.iter()
        .zip(args.iter().skip(1))
        .filter(|(flag, _)| *flag == SEND_ARG)
        .map(|(_, path)| PathBuf::from(path))
        .collect()
}

/// Explorer starts one process per selected item, and each one lands here in
/// turn, so the picker simply grows while it is open. Returns false if the
/// arguments ask to send nothing.
fn queue_send(app: &AppHandle, args: &[String]) -> bool {
    let paths = paths_to_send(args);
    if paths.is_empty() {
        return false;
    }
    {
        let state = app.state::<PendingSend>();
        let mut pending = state.paths();
        for path in paths {
            if !pending.contains(&path) {
                pending.push(path);
            }
        }
    }
    let _ = app.emit("pending-send", ());
    show_send_window(app);
    true
}

fn show_send_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(SEND_LABEL) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn hide_send_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(SEND_LABEL) {
        let _ = window.hide();
    }
}

#[tauri::command]
fn pending_send(pending: State<'_, PendingSend>) -> Vec<String> {
    let name = |p: &PathBuf| p.file_name().unwrap_or(p.as_os_str()).to_string_lossy().into_owned();
    pending.paths().iter().map(name).collect()
}

#[tauri::command]
async fn send_pending(
    app: AppHandle,
    engine: State<'_, Engine>,
    pending: State<'_, PendingSend>,
    to: String,
) -> CmdResult {
    let paths = pending.paths().clone();
    engine.send(&to, paths).await.map_err(text_err)?;
    pending.paths().clear();
    hide_send_window(&app);
    show_window(&app, true);
    Ok(())
}

#[tauri::command]
fn cancel_send(app: AppHandle, pending: State<'_, PendingSend>) {
    pending.paths().clear();
    hide_send_window(&app);
}

#[tauri::command]
fn snapshot(engine: State<'_, Engine>) -> Snapshot {
    engine.snapshot()
}

#[tauri::command]
async fn register(
    engine: State<'_, Engine>,
    server: String,
    fingerprint: String,
    username: String,
    password: String,
) -> CmdResult {
    engine.register(&server, &fingerprint, &username, &password).await.map_err(text_err)
}

#[tauri::command]
async fn login(
    engine: State<'_, Engine>,
    server: String,
    fingerprint: String,
    username: String,
    password: String,
) -> CmdResult {
    engine.login(&server, &fingerprint, &username, &password).await.map_err(text_err)
}

#[tauri::command]
async fn logout(engine: State<'_, Engine>) -> CmdResult {
    engine.logout().await;
    Ok(())
}

#[tauri::command]
async fn change_password(engine: State<'_, Engine>, current: String, next: String) -> CmdResult {
    engine.change_password(&current, &next).await.map_err(text_err)
}

#[tauri::command]
async fn add_friend(engine: State<'_, Engine>, username: String) -> CmdResult {
    engine.add_friend(&username).await.map_err(text_err)
}

#[tauri::command]
async fn respond_friend(engine: State<'_, Engine>, username: String, accept: bool) -> CmdResult {
    engine.respond_friend(&username, accept).await.map_err(text_err)
}

#[tauri::command]
async fn remove_friend(engine: State<'_, Engine>, username: String) -> CmdResult {
    engine.remove_friend(&username).await.map_err(text_err)
}

#[tauri::command]
fn trust_key(engine: State<'_, Engine>, username: String) -> CmdResult {
    engine.trust_key(&username).map_err(text_err)
}

#[tauri::command]
async fn send_paths(engine: State<'_, Engine>, to: String, paths: Vec<PathBuf>) -> CmdResult {
    engine.send(&to, paths).await.map(|_| ()).map_err(text_err)
}

async fn run_dialog<T, F>(pick: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> Option<T> + Send + 'static,
{
    // Native dialogs block their thread until the user answers.
    tokio::task::spawn_blocking(pick).await.ok().flatten()
}

#[tauri::command]
async fn pick_and_send(
    app: AppHandle,
    engine: State<'_, Engine>,
    to: String,
    folder: bool,
) -> CmdResult {
    let dialog = app.dialog().clone();
    let paths = run_dialog(move || {
        if folder {
            dialog.file().blocking_pick_folder().map(|p| vec![p])
        } else {
            dialog.file().blocking_pick_files()
        }
    })
    .await
    .unwrap_or_default();
    let paths: Vec<PathBuf> = paths.into_iter().filter_map(|p| p.into_path().ok()).collect();
    if paths.is_empty() {
        return Ok(());
    }
    engine.send(&to, paths).await.map(|_| ()).map_err(text_err)
}

#[tauri::command]
async fn accept(engine: State<'_, Engine>, id: String) -> CmdResult {
    engine.accept(&id).await.map_err(text_err)
}

#[tauri::command]
async fn decline(engine: State<'_, Engine>, id: String) -> CmdResult {
    engine.decline(&id).await.map_err(text_err)
}

#[tauri::command]
async fn cancel(engine: State<'_, Engine>, id: String) -> CmdResult {
    engine.cancel(&id).await;
    Ok(())
}

#[tauri::command]
fn clear_finished(engine: State<'_, Engine>) {
    engine.clear_finished();
}

#[tauri::command]
async fn pick_download_dir(app: AppHandle, engine: State<'_, Engine>) -> CmdResult<Option<String>> {
    let dialog = app.dialog().clone();
    let Some(dir) = run_dialog(move || dialog.file().blocking_pick_folder()).await else {
        return Ok(None);
    };
    let dir = dir.into_path().map_err(text_err)?;
    engine.set_download_dir(dir.clone()).map_err(text_err)?;
    Ok(Some(dir.display().to_string()))
}

#[tauri::command]
fn open_downloads(app: AppHandle, engine: State<'_, Engine>) -> CmdResult {
    let dir = engine.snapshot().settings.download_dir;
    std::fs::create_dir_all(&dir).map_err(text_err)?;
    app.opener().open_path(dir.display().to_string(), None::<&str>).map_err(text_err)
}

fn missing_file() -> String {
    "The file is no longer in that location".into()
}

fn is_executable(path: &std::path::Path) -> bool {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    EXECUTABLE_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
}

/// Native confirmation. `window.confirm` is not usable here: Tauri replaces it
/// with an async version whose Promise is always truthy.
pub(crate) async fn ask(app: &AppHandle, message: String, confirm: String) -> bool {
    let mut builder = app
        .dialog()
        .message(message)
        .title("Transfer")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(confirm, "Cancel".into()));
    if let Some(window) = app.get_webview_window("main") {
        builder = builder.parent(&window);
    }
    run_dialog(move || Some(builder.blocking_show())).await.unwrap_or(false)
}

#[tauri::command]
async fn ask_confirmation(app: AppHandle, message: String, confirm: String) -> CmdResult<bool> {
    Ok(ask(&app, message, confirm).await)
}

#[tauri::command]
async fn open_received(app: AppHandle, engine: State<'_, Engine>, id: String) -> CmdResult {
    let (file, _) = engine.saved_paths(&id).ok_or_else(missing_file)?;
    if !file.exists() {
        return Err(missing_file());
    }
    // Checked here, not in the page, so this path cannot run a program unasked.
    if is_executable(&file) {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        let message = format!(
            "{name} is a program or script and will run on your computer.\n\n\
             Only run it if you trust whoever sent it."
        );
        if !ask(&app, message, "Run".into()).await {
            return Ok(());
        }
    }
    app.opener().open_path(file.display().to_string(), None::<&str>).map_err(text_err)
}

#[tauri::command]
fn reveal_received(app: AppHandle, engine: State<'_, Engine>, id: String) -> CmdResult {
    let (_, location) = engine.saved_paths(&id).ok_or_else(missing_file)?;
    if !location.exists() {
        return Err(missing_file());
    }
    app.opener().reveal_item_in_dir(location).map_err(text_err)
}

#[tauri::command]
fn get_autostart(app: AppHandle) -> CmdResult<bool> {
    app.autolaunch().is_enabled().map_err(text_err)
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> CmdResult {
    let manager = app.autolaunch();
    if enabled { manager.enable() } else { manager.disable() }.map_err(text_err)
}

fn show_window(app: &AppHandle, focus: bool) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        if focus {
            let _ = window.set_focus();
        }
    }
}

/// Bottom-right corner, just above the taskbar. This is a window of our own
/// rather than a system notification because those cannot carry buttons and
/// never appear if the user turned them off.
fn show_popup(app: &AppHandle) {
    let Some(popup) = app.get_webview_window(POPUP_LABEL) else {
        return;
    };
    if let (Ok(Some(monitor)), Ok(size)) = (popup.primary_monitor(), popup.outer_size()) {
        let area = monitor.work_area();
        let margin = (POPUP_MARGIN * monitor.scale_factor()) as i32;
        let x = area.position.x + area.size.width as i32 - size.width as i32 - margin;
        let y = area.position.y + area.size.height as i32 - size.height as i32 - margin;
        let _ = popup.set_position(PhysicalPosition::new(x, y));
    }
    let _ = popup.show();
}

#[tauri::command]
fn hide_popup(app: AppHandle) {
    if let Some(popup) = app.get_webview_window(POPUP_LABEL) {
        let _ = popup.hide();
    }
}

#[tauri::command]
fn show_main(app: AppHandle) {
    show_window(&app, true);
}

pub(crate) fn notify(app: &AppHandle, title: &str, body: &str) {
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        tracing::warn!("notification failed: {e}");
    }
}

fn describe(transfer: &TransferView) -> String {
    match transfer.file_count {
        1 => transfer.first_file.clone(),
        n => format!("{n} files"),
    }
}

/// What is shown on the tray for each connection state.
struct TrayStatus {
    item: MenuItem<Wry>,
    online: Image<'static>,
    offline: Image<'static>,
}

impl TrayStatus {
    fn update(&self, app: &AppHandle, state: Connection, username: Option<&str>) {
        let (label, icon) = match (state, username) {
            (Connection::Online, Some(name)) => (format!("Signed in as {name}"), &self.online),
            (Connection::Connecting, _) => ("Connecting…".to_string(), &self.offline),
            _ => ("Not signed in".to_string(), &self.offline),
        };
        let _ = self.item.set_text(&label);
        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            let _ = tray.set_icon(Some(icon.clone()));
            let _ = tray.set_tooltip(Some(format!("Transfer: {label}")));
        }
    }
}

/// Forwards engine events to the window and raises desktop notifications,
/// which keep working while the window is hidden.
async fn forward_events(
    app: AppHandle,
    status: TrayStatus,
    mut events: UnboundedReceiver<EngineEvent>,
) {
    let mut notified: HashSet<(String, &'static str)> = HashSet::new();
    while let Some(event) = events.recv().await {
        let mut open_popup = false;
        match &event {
            EngineEvent::Connection { state, username, reason } => {
                status.update(&app, *state, username.as_deref());
                if let Some(reason) = reason {
                    notify(&app, "Transfer", reason);
                }
            }
            EngineEvent::FriendRequest { username } => {
                notify(&app, "Friend request", &format!("{username} wants to be your friend"));
            }
            EngineEvent::Transfer { transfer } => {
                let once = |notified: &mut HashSet<_>, tag| {
                    notified.insert((transfer.id.clone(), tag))
                };
                match transfer.state {
                    TransferState::Incoming if once(&mut notified, "incoming") => {
                        open_popup = true;
                    }
                    TransferState::Done if once(&mut notified, "done") => {
                        let (title, verb) = if transfer.sending {
                            ("Sent", "sent to")
                        } else {
                            ("Received", "received from")
                        };
                        let body = format!("{} {verb} {}", describe(transfer), transfer.peer);
                        notify(&app, title, &body);
                    }
                    TransferState::Failed if once(&mut notified, "failed") => {
                        let reason = transfer.message.as_deref().unwrap_or("Unknown error");
                        notify(&app, "The transfer failed", reason);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        // The popup renders from this event, so it is shown only afterwards.
        let _ = app.emit("engine", &event);
        if open_popup {
            show_popup(&app);
        } else if let EngineEvent::Transfer { transfer } = &event {
            let unanswered = || {
                let transfers = app.state::<Engine>().snapshot().transfers;
                transfers.iter().any(|t| t.state == TransferState::Incoming)
            };
            if transfer.state != TransferState::Running && !unanswered() {
                hide_popup(app.clone());
            }
        }
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<TrayStatus> {
    let status = MenuItem::new(app, "Connecting…", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open Transfer", true, None::<&str>)?;
    let update = update::tray_item(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&status, &separator, &open, &update, &quit])?;
    let online = Image::from_bytes(include_bytes!("../icons/tray-online.png"))?.to_owned();
    let offline = Image::from_bytes(include_bytes!("../icons/tray-offline.png"))?.to_owned();

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(offline.clone())
        .tooltip("Transfer")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_window(app, true),
            "update" => update::tray_clicked(app),
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    update::install_on_exit(&app).await;
                    app.exit(0);
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle(), true);
            }
        })
        .build(app)?;
    app.manage(update::UpdateItem(update));
    Ok(TrayStatus { item: status, online, offline })
}

/// Living in the tray only works if the app starts with the system, so it is
/// switched on once; after that the user's choice in settings stands.
fn enable_autostart_once(app: &AppHandle, dir: &std::path::Path) {
    let marker = dir.join("autostart.configured");
    if marker.exists() {
        return;
    }
    match app.autolaunch().enable() {
        Ok(()) => {
            let _ = std::fs::write(marker, b"");
        }
        Err(e) => tracing::warn!("autostart failed: {e}"),
    }
}

fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let handle = app.handle().clone();
    let custom_dir = std::env::var_os(DATA_DIR_ENV).map(PathBuf::from);
    let dir = match &custom_dir {
        Some(dir) => dir.clone(),
        None => app.path().app_data_dir()?,
    };
    let downloads = match &custom_dir {
        Some(dir) => dir.join("downloads"),
        None => app.path().download_dir()?.join("Transfer"),
    };

    let (engine, events) =
        tauri::async_runtime::block_on(async { Engine::start(&dir, downloads) })?;
    let logged_in = engine.snapshot().username.is_some();
    app.manage(engine);

    // Created here, not from the config, so no page can call a command before
    // the engine is registered.
    for config in app.config().app.windows.clone() {
        WebviewWindowBuilder::from_config(&handle, &config)?.build()?;
    }

    let status = build_tray(&handle)?;
    tauri::async_runtime::spawn(forward_events(handle.clone(), status, events));
    tauri::async_runtime::spawn(update::check_periodically(handle.clone()));

    if custom_dir.is_none() {
        enable_autostart_once(&handle, &dir);
    }
    let args: Vec<String> = std::env::args().collect();
    queue_send(&handle, &args);
    let start_hidden = args.iter().any(|a| a == HIDDEN_ARG);
    // Also covers items forwarded by other processes while this one started.
    if !app.state::<PendingSend>().paths().is_empty() {
        show_send_window(&handle);
    } else if !start_hidden || !logged_in {
        show_window(&handle, true);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_executable, paths_to_send};
    use std::path::{Path, PathBuf};

    #[test]
    fn send_paths_come_only_from_the_send_flag() {
        let args = ["transfer.exe", "--hidden", "--send", r"C:\a b\c.txt"].map(String::from);
        assert_eq!(paths_to_send(&args), [PathBuf::from(r"C:\a b\c.txt")]);
        assert!(paths_to_send(&args[..2]).is_empty());
        assert!(paths_to_send(&["--send".to_string()]).is_empty());
    }

    #[test]
    fn detects_programs_whatever_their_case() {
        for name in ["setup.exe", "SETUP.EXE", "photo.jpg.Bat", "run.ps1"] {
            assert!(is_executable(Path::new(name)), "{name}");
        }
        for name in ["photo.jpg", "exe", "note.txt", "no-extension"] {
            assert!(!is_executable(Path::new(name)), "{name}");
        }
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut builder = tauri::Builder::default()
        .manage(PendingSend::default())
        .manage(update::Updates::default());
    if std::env::var_os(DATA_DIR_ENV).is_none() {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _| {
            if !queue_send(app, &args) {
                show_window(app, true);
            }
        }));
    }
    builder
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![HIDDEN_ARG]),
        ))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            register,
            login,
            logout,
            change_password,
            add_friend,
            respond_friend,
            remove_friend,
            trust_key,
            send_paths,
            pick_and_send,
            accept,
            decline,
            cancel,
            clear_finished,
            pick_download_dir,
            open_downloads,
            ask_confirmation,
            open_received,
            reveal_received,
            get_autostart,
            set_autostart,
            pending_send,
            send_pending,
            cancel_send,
            hide_popup,
            show_main,
            update::update_status,
            update::check_updates,
            update::install_update,
        ])
        .setup(setup)
        .on_window_event(|window, event| {
            // Closing the window sends the app to the tray; "Quit" really quits.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                if window.label() == SEND_LABEL {
                    window.state::<PendingSend>().paths().clear();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to start Transfer")
        .run(|_, event| {
            if let RunEvent::ExitRequested { api, code, .. } = event {
                // Keep running with no windows, unless the user chose to quit.
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}

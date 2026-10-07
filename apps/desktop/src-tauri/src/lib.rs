mod clash;
mod commands;
mod core;
mod credentials;
mod mudfish_probe;
mod nodes;
mod paths;
mod store;
mod system;
mod traffic;
mod tray;
mod warp;

use std::sync::Arc;

use proxy_core::Profile;
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tokio::sync::RwLock;

use crate::core::{CoreEvents, CoreManager, CoreStatus, LogBatch, SingBox};
use crate::paths::Paths;

pub struct AppState {
    pub paths: Paths,
    pub profile: RwLock<Profile>,
    pub core: Arc<CoreManager>,
    pub http: reqwest::Client,
    /// Something the user should know from startup: the profile was unreadable and the defaults
    /// replaced it. Set once, shown by the UI for as long as the app runs.
    pub notice: Option<String>,
}

/// Forwards core notifications to the webview (`core-status`, batched `core-log`) and the tray.
struct TauriEvents(AppHandle);

impl CoreEvents for TauriEvents {
    fn status(&self, status: &CoreStatus) {
        let _ = self.0.emit("core-status", status);
        // Queued, not awaited: tray calls wait for the main thread, and the caller holds the
        // core's state lock (the main thread may itself be waiting on the core at exit).
        let (app, status) = (self.0.clone(), status.clone());
        let _ = self.0.run_on_main_thread(move || tray::update(&app, &status));
    }
    fn logs(&self, batch: &LogBatch) {
        let _ = self.0.emit("core-log", batch);
    }
}

/// Setup failures (e.g. the admin-only data directory cannot be secured) would otherwise end
/// the GUI without a word.
fn fatal(message: &str) -> ! {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (text, title) = (wide(message), wide("ProxyDesk 無法啟動"));
        unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR) };
    }
    eprintln!("{message}");
    std::process::exit(1);
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Stops the core, then exits. Used by the tray "結束" item.
pub fn quit(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<AppState>() {
            state.core.stop().await;
        }
        app.exit(0);
    });
}

/// Built in code rather than tauri.conf.json so debug builds can expose the WebView2
/// DevTools protocol (`PROXYDESK_CDP_PORT`) for UI automation; wry ignores the
/// `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` env var because it sets its own arguments.
/// Debug only: any local process could drive the elevated webview through that port.
fn create_main_window(app: &AppHandle) -> tauri::Result<()> {
    #[allow(unused_mut)]
    let mut args = String::from("--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection");
    #[cfg(debug_assertions)]
    if let Ok(port) = std::env::var("PROXYDESK_CDP_PORT") {
        args.push_str(&format!(" --remote-debugging-port={port}"));
    }
    tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
        .title("ProxyDesk")
        .inner_size(1200.0, 780.0)
        .min_inner_size(960.0, 600.0)
        .center()
        .additional_browser_args(&args)
        .build()?;
    Ok(())
}

/// Everything `setup` needs; any error is shown to the user by `fatal`.
fn setup(app: &mut tauri::App) -> Result<(), String> {
    let paths = Paths::resolve(app.handle())?;
    let (profile, notice) = store::load_profile(&paths.profile_file())?;
    let launcher = Arc::new(SingBox { exe: paths.sing_box.clone(), run_dir: paths.run_dir.clone() });
    let core = CoreManager::new(launcher, Arc::new(TauriEvents(app.handle().clone())));
    tauri::async_runtime::spawn(core.log_task());
    tauri::async_runtime::block_on(core.begin_orphan_sweep());
    // Own HTTP (Mudfish list, WARP API) ignores any system proxy, like the Clash client.
    let http = reqwest::Client::builder()
        .user_agent(concat!("ProxyDesk/", env!("CARGO_PKG_VERSION")))
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    app.manage(AppState { paths, profile: RwLock::new(profile), core, http, notice });
    create_main_window(app.handle()).map_err(|e| e.to_string())?;
    tray::create(app.handle()).map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn(traffic::run(app.handle().clone()));
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main_window(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            setup(app).unwrap_or_else(|e| fatal(&e));
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the app (and the proxy) running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_snapshot,
            commands::save_profile,
            commands::set_credentials,
            commands::clear_credentials,
            commands::verify_account,
            commands::get_nodes,
            commands::warp_create,
            commands::warp_discard,
            commands::ping_nodes,
            commands::core_start,
            commands::core_stop,
            commands::core_logs,
            commands::clash_proxies,
            commands::clash_delay,
            commands::clash_close_connection,
            commands::clash_close_all,
            commands::list_processes,
            commands::rule_set_catalog,
            commands::open_data_dir,
        ])
        .build(tauri::generate_context!())
        .expect("error while building ProxyDesk");

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            // Last-chance cleanup if the app exits without going through `quit`.
            if let Some(state) = app.try_state::<AppState>() {
                tauri::async_runtime::block_on(state.core.stop());
            }
        }
    });
}

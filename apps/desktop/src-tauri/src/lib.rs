mod clash;
mod commands;
mod core;
mod credentials;
mod nodes;
mod paths;
mod store;
mod system;
mod tray;
mod warp;

use std::sync::Arc;

use proxy_core::Profile;
use tauri::{AppHandle, Manager, RunEvent, WindowEvent};
use tokio::sync::RwLock;

use crate::core::CoreManager;
use crate::paths::Paths;

pub struct AppState {
    pub paths: Paths,
    pub profile: RwLock<Profile>,
    pub core: Arc<CoreManager>,
    pub http: reqwest::Client,
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub(crate) async fn on_core_crashed(app: &AppHandle, message: String) {
    if let Some(state) = app.try_state::<AppState>() {
        state.core.mark_crashed(message).await;
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main_window(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let paths = Paths::resolve(app.handle())?;
            core::kill_orphans(&paths.sing_box);
            let mut profile: Profile = store::load_or_default(&paths.profile_file());
            if profile.migrate() {
                store::save(&paths.profile_file(), &profile)?;
            }
            let core = Arc::new(CoreManager::new(app.handle().clone(), paths.clone()));
            let http = reqwest::Client::builder().user_agent(concat!("ProxyDesk/", env!("CARGO_PKG_VERSION"))).build()?;
            app.manage(AppState { paths, profile: RwLock::new(profile), core, http });
            create_main_window(app.handle())?;
            tray::create(app.handle())?;
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
            commands::get_nodes,
            commands::warp_create,
            commands::ping_nodes,
            commands::core_start,
            commands::core_stop,
            commands::core_logs,
            commands::select_outbound,
            commands::select_group_outbound,
            commands::set_mode,
            commands::clash_proxies,
            commands::clash_delay,
            commands::clash_connections,
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

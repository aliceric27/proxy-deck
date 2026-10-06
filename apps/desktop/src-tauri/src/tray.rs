use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Listener, Manager};

use crate::core::CoreStatus;
use crate::AppState;

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "顯示主視窗", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "連線", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "結束 ProxyDesk", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &PredefinedMenuItem::separator(app)?, &quit])?;

    let tray = TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().expect("bundle icon"))
        .tooltip("ProxyDesk：未連線")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => crate::show_main_window(app),
            "toggle" => toggle_core(app),
            "quit" => crate::quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                crate::show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    // Keep the menu label and tooltip in sync with the core state.
    app.listen("core-status", move |event| {
        let Ok(status) = serde_json::from_str::<CoreStatus>(event.payload()) else { return };
        let (label, tip) = match status {
            CoreStatus::Running { .. } => ("中斷連線", "ProxyDesk：已連線"),
            CoreStatus::Starting => ("中斷連線", "ProxyDesk：連線中…"),
            CoreStatus::Error { .. } => ("連線", "ProxyDesk：錯誤"),
            CoreStatus::Stopped => ("連線", "ProxyDesk：未連線"),
        };
        let _ = toggle.set_text(label);
        let _ = tray.set_tooltip(Some(tip));
    });
    Ok(())
}

fn toggle_core(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        match state.core.status().await {
            CoreStatus::Running { .. } | CoreStatus::Starting => state.core.stop().await,
            _ => {
                let profile = state.profile.read().await.clone();
                if let Err(e) = state.core.start(&profile, crate::credentials::load().as_ref()).await {
                    crate::show_main_window(&app);
                    let _ = app.emit("core-error", e);
                }
            }
        }
    });
}

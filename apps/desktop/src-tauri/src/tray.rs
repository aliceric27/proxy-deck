use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::core::CoreStatus;
use crate::AppState;

/// The menu item whose label follows the core state.
struct ToggleItem(MenuItem<Wry>);

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "顯示主視窗", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "連線", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "結束 ProxyDesk", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &PredefinedMenuItem::separator(app)?, &quit])?;

    TrayIconBuilder::with_id("main")
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
    app.manage(ToggleItem(toggle));
    Ok(())
}

/// Keeps the menu label and tooltip in sync with the core state.
pub fn update(app: &AppHandle, status: &CoreStatus) {
    let (label, tip) = match status {
        CoreStatus::Running { .. } => ("中斷連線", "ProxyDesk：已連線"),
        CoreStatus::Starting => ("中斷連線", "ProxyDesk：連線中…"),
        CoreStatus::Reconnecting { .. } => ("中斷連線", "ProxyDesk：重新連線中…"),
        CoreStatus::Error { .. } => ("連線", "ProxyDesk：錯誤"),
        CoreStatus::Stopped => ("連線", "ProxyDesk：未連線"),
    };
    if let Some(item) = app.try_state::<ToggleItem>() {
        let _ = item.0.set_text(label);
    }
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(tip));
    }
}

fn toggle_core(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        match state.core.status().await {
            CoreStatus::Running { .. } | CoreStatus::Starting | CoreStatus::Reconnecting { .. } => state.core.stop().await,
            _ => {
                if let Err(e) = crate::commands::start_core(&state).await {
                    crate::show_main_window(&app);
                    let _ = app.emit("core-error", e);
                }
            }
        }
    });
}

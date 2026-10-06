//! Live traffic for the UI: one poll of the Clash API per second while connected and the
//! window is visible, pushed as a typed `traffic` event. Rates are computed here, so they do
//! not reset when the user switches pages.

use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use ts_rs::TS;

use crate::clash::Connection;
use crate::AppState;

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
pub struct Traffic {
    /// Bytes per second since the previous sample.
    #[ts(type = "number")]
    pub up_rate: u64,
    #[ts(type = "number")]
    pub down_rate: u64,
    #[ts(type = "number")]
    pub upload_total: u64,
    #[ts(type = "number")]
    pub download_total: u64,
    pub connections: Vec<Connection>,
}

fn rate(now: u64, before: u64, secs: f64) -> u64 {
    if secs <= 0.0 {
        0
    } else {
        (now.saturating_sub(before) as f64 / secs) as u64
    }
}

fn window_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main").is_some_and(|w| w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false))
}

pub async fn run(app: AppHandle) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut prev: Option<(Instant, u64, u64)> = None;
    loop {
        tick.tick().await;
        let clash = match app.try_state::<AppState>() {
            Some(state) if window_visible(&app) => state.core.clash().await,
            _ => None,
        };
        let Some(clash) = clash else {
            prev = None;
            continue;
        };
        let Ok(c) = clash.connections().await else {
            prev = None;
            continue;
        };
        let now = Instant::now();
        let (up_rate, down_rate) = match prev {
            Some((t, up, down)) => {
                let secs = now.duration_since(t).as_secs_f64();
                (rate(c.upload_total, up, secs), rate(c.download_total, down, secs))
            }
            None => (0, 0),
        };
        prev = Some((now, c.upload_total, c.download_total));
        let _ = app.emit(
            "traffic",
            Traffic { up_rate, down_rate, upload_total: c.upload_total, download_total: c.download_total, connections: c.connections },
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rate_handles_resets_and_zero_intervals() {
        assert_eq!(super::rate(3000, 1000, 2.0), 1000);
        assert_eq!(super::rate(10, 1000, 1.0), 0, "counter reset after a core restart");
        assert_eq!(super::rate(10, 0, 0.0), 0);
    }
}

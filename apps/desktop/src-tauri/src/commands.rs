//! Tauri commands invoked by the frontend. Argument and result types derive `ts_rs::TS`;
//! `cargo test` regenerates their TypeScript in `apps/desktop/src/lib/bindings/`.

use std::collections::BTreeMap;

use proxy_core::singbox::restart_fingerprint;
use proxy_core::{Profile, ProxyNode};
use serde::Serialize;
use tauri::State;
use ts_rs::TS;

use crate::clash::ClashProxy;
use crate::core::{CoreStatus, LogBatch};
use crate::credentials::{self, Credentials};
use crate::nodes::{self, NodeList, PingResult};
use crate::system::{self, ProcessInfo, RuleSetCatalog};
use crate::AppState;

type CmdResult<T> = Result<T, String>;

/// How the saved profile relates to the running core.
#[derive(Serialize, TS)]
#[ts(export)]
pub struct ProfileState {
    /// The running core lags the profile in something only a reconnect applies.
    stale: bool,
    /// Why the profile cannot be turned into a config (e.g. a group without matchers).
    invalid: Option<String>,
}

async fn profile_state(state: &AppState, profile: &Profile) -> ProfileState {
    let fingerprint = restart_fingerprint(profile, &state.paths.ruleset_dir);
    ProfileState { stale: state.core.is_stale(fingerprint.as_deref().ok()).await, invalid: fingerprint.err() }
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct Snapshot {
    profile: Profile,
    state: ProfileState,
    username: Option<String>,
    core: CoreStatus,
    elevated: bool,
    version: String,
    sing_box_found: bool,
    /// A problem found while loading the profile at startup (the file was unreadable, so the
    /// defaults are in use); shown as a warning for the whole session.
    notice: Option<String>,
}

#[tauri::command]
pub async fn get_snapshot(state: State<'_, AppState>) -> CmdResult<Snapshot> {
    let profile = state.profile.read().await.clone();
    Ok(Snapshot {
        state: profile_state(&state, &profile).await,
        profile,
        username: credentials::load().map(|c| c.username),
        core: state.core.status().await,
        elevated: system::is_elevated(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        sing_box_found: state.paths.sing_box.is_file(),
        notice: state.notice.clone(),
    })
}

/// The single write path for the profile. Persists it, applies live-switchable choices
/// (what each selector — Global, final, GeoIP, every group — points at, and the mode) to a
/// running core, and reports what still needs a reconnect.
#[tauri::command]
pub async fn save_profile(state: State<'_, AppState>, profile: Profile) -> CmdResult<ProfileState> {
    let removed_warp: Vec<String> = {
        let mut current = state.profile.write().await;
        crate::store::save(&state.paths.profile_file(), &profile)?;
        let removed = current
            .nodes
            .iter()
            .filter(|n| n.is_wireguard() && profile.node(&n.tag).is_none())
            .map(|n| n.tag.clone())
            .collect();
        *current = profile.clone();
        removed
    };
    for tag in removed_warp {
        let http = state.http.clone();
        tauri::async_runtime::spawn(async move { crate::warp::deregister(&http, &tag).await });
    }
    state.core.set_selections(profile.selections()).await.map_err(|e| format!("設定已儲存，但無法即時套用：{e}"))?;
    Ok(profile_state(&state, &profile).await)
}

/// Registers a new Cloudflare WARP device and returns its node; the caller adds it to the
/// profile through `save_profile`.
#[tauri::command]
pub async fn warp_create(state: State<'_, AppState>) -> CmdResult<ProxyNode> {
    let index = state.profile.read().await.nodes.iter().filter(|n| n.is_wireguard()).count();
    crate::warp::create(&state.http, &state.paths.sing_box, index).await
}

/// Unregisters a WARP device whose node never made it into the profile (save failed).
#[tauri::command]
pub async fn warp_discard(state: State<'_, AppState>, tag: String) -> CmdResult<()> {
    if state.profile.read().await.node(&tag).is_none() {
        crate::warp::deregister(&state.http, &tag).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn set_credentials(username: String, password: String) -> CmdResult<()> {
    let username = username.trim().to_string();
    if username.is_empty() || password.is_empty() {
        return Err("請輸入 Mudfish ID 與密碼".into());
    }
    credentials::store(&Credentials { username, password })
}

#[tauri::command]
pub async fn clear_credentials() -> CmdResult<()> {
    credentials::clear()
}

#[tauri::command]
pub async fn get_nodes(state: State<'_, AppState>, force: bool) -> CmdResult<NodeList> {
    nodes::get(&state.paths, &state.http, force).await.map(NodeList::from)
}

#[tauri::command]
pub async fn ping_nodes(ips: Vec<String>) -> CmdResult<Vec<PingResult>> {
    Ok(nodes::ping(ips).await)
}

/// Starts the core with the current profile (also used by the tray).
pub async fn start_core(state: &AppState) -> CmdResult<()> {
    let profile = state.profile.read().await.clone();
    let plan = crate::core::build_plan(&profile, credentials::load().as_ref(), &state.paths);
    match plan {
        Ok(plan) => state.core.start(plan, profile.selections()).await,
        Err(e) => {
            state.core.fail(e.clone()).await;
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn core_start(state: State<'_, AppState>) -> CmdResult<()> {
    start_core(&state).await
}

#[tauri::command]
pub async fn core_stop(state: State<'_, AppState>) -> CmdResult<()> {
    state.core.stop().await;
    Ok(())
}

#[tauri::command]
pub async fn core_logs(state: State<'_, AppState>) -> CmdResult<LogBatch> {
    Ok(state.core.logs())
}

async fn clash(state: &State<'_, AppState>) -> CmdResult<crate::clash::ClashClient> {
    state.core.clash().await.ok_or_else(|| "尚未連線".to_string())
}

#[tauri::command]
pub async fn clash_proxies(state: State<'_, AppState>) -> CmdResult<BTreeMap<String, ClashProxy>> {
    clash(&state).await?.proxies().await
}

#[tauri::command]
pub async fn clash_delay(state: State<'_, AppState>, tag: String) -> CmdResult<u32> {
    clash(&state).await?.delay(&tag).await
}

#[tauri::command]
pub async fn clash_close_connection(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    clash(&state).await?.close_connection(&id).await
}

#[tauri::command]
pub async fn clash_close_all(state: State<'_, AppState>) -> CmdResult<()> {
    clash(&state).await?.close_all().await
}

#[tauri::command]
pub async fn list_processes() -> CmdResult<Vec<ProcessInfo>> {
    tokio::task::spawn_blocking(system::list_processes).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn rule_set_catalog(state: State<'_, AppState>) -> CmdResult<RuleSetCatalog> {
    Ok(system::rule_set_catalog(&state.paths.ruleset_dir))
}

#[tauri::command]
pub async fn open_data_dir(state: State<'_, AppState>) -> CmdResult<()> {
    tauri_plugin_opener::open_path(&state.paths.config_dir, None::<&str>).map_err(|e| e.to_string())
}

//! Tauri commands invoked by the frontend (`src/lib/ipc.ts` mirrors these signatures).

use proxy_core::{Mode, Profile};
use serde::Serialize;
use serde_json::Value;
use tauri::State;

use crate::core::CoreStatus;
use crate::credentials::{self, Credentials};
use crate::nodes::{self, NodeCache, PingResult};
use crate::system::{self, ProcessInfo, RuleSetCatalog};
use crate::AppState;

type CmdResult<T> = Result<T, String>;

#[derive(Serialize)]
pub struct Snapshot {
    profile: Profile,
    username: Option<String>,
    core: CoreStatus,
    elevated: bool,
    version: String,
    sing_box_found: bool,
}

#[tauri::command]
pub async fn get_snapshot(state: State<'_, AppState>) -> CmdResult<Snapshot> {
    Ok(Snapshot {
        profile: state.profile.read().await.clone(),
        username: credentials::load().map(|c| c.username),
        core: state.core.status().await,
        elevated: system::is_elevated(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        sing_box_found: state.paths.sing_box.is_file(),
    })
}

/// Persists the profile. Returns whether the running core must restart for it to take effect.
#[tauri::command]
pub async fn save_profile(state: State<'_, AppState>, profile: Profile) -> CmdResult<bool> {
    crate::store::save(&state.paths.profile_file(), &profile)?;
    let mut current = state.profile.write().await;
    // Drop the stored keys of WARP nodes the user removed.
    for old in current.nodes.iter().filter(|n| n.is_wireguard()) {
        if profile.node(&old.tag).is_none() {
            credentials::delete_node_secret(&old.tag);
        }
    }
    *current = profile;
    drop(current);
    Ok(matches!(state.core.status().await, CoreStatus::Running { .. }))
}

/// Registers a new Cloudflare WARP device and appends it as a node. Returns the new profile.
#[tauri::command]
pub async fn warp_create(state: State<'_, AppState>) -> CmdResult<Profile> {
    let index = state.profile.read().await.nodes.iter().filter(|n| n.is_wireguard()).count();
    let node = crate::warp::create(&state.http, &state.paths.sing_box, index).await?;
    let mut p = state.profile.write().await;
    p.nodes.push(node);
    crate::store::save(&state.paths.profile_file(), &*p)?;
    Ok(p.clone())
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
pub async fn get_nodes(state: State<'_, AppState>, force: bool) -> CmdResult<NodeCache> {
    nodes::get(&state.paths, &state.http, force).await
}

#[tauri::command]
pub async fn ping_nodes(ips: Vec<String>) -> CmdResult<Vec<PingResult>> {
    Ok(nodes::ping(ips).await)
}

#[tauri::command]
pub async fn core_start(state: State<'_, AppState>) -> CmdResult<()> {
    let profile = state.profile.read().await.clone();
    state.core.start(&profile, credentials::load().as_ref()).await
}

#[tauri::command]
pub async fn core_stop(state: State<'_, AppState>) -> CmdResult<()> {
    state.core.stop().await;
    Ok(())
}

#[tauri::command]
pub async fn core_logs(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    Ok(state.core.logs())
}

async fn clash(state: &State<'_, AppState>) -> CmdResult<crate::clash::ClashClient> {
    state.core.clash().await.ok_or_else(|| "尚未連線".to_string())
}

/// Switches the `proxy` selector (live if running) and remembers the choice.
#[tauri::command]
pub async fn select_outbound(state: State<'_, AppState>, tag: String) -> CmdResult<()> {
    if let Some(c) = state.core.clash().await {
        c.select(proxy_core::TAG_PROXY, &tag).await?;
        // Existing connections keep their old node; drop them so traffic moves now.
        let _ = c.close_all().await;
    }
    let mut p = state.profile.write().await;
    p.selected = tag;
    crate::store::save(&state.paths.profile_file(), &*p)
}

/// Switches one group's own selector (live if running) and remembers the choice.
#[tauri::command]
pub async fn select_group_outbound(state: State<'_, AppState>, group_id: String, outbound: String) -> CmdResult<()> {
    let mut p = state.profile.write().await;
    let group = p.groups.iter_mut().find(|g| g.id == group_id).ok_or("找不到這個群組")?;
    if let Some(c) = state.core.clash().await {
        c.select(&group.selector_tag(), &outbound).await?;
        let _ = c.close_all().await;
    }
    group.outbound = outbound;
    crate::store::save(&state.paths.profile_file(), &*p)
}

#[tauri::command]
pub async fn set_mode(state: State<'_, AppState>, mode: Mode) -> CmdResult<()> {
    if let Some(c) = state.core.clash().await {
        c.set_mode(mode.as_clash()).await?;
        let _ = c.close_all().await;
    }
    let mut p = state.profile.write().await;
    p.mode = mode;
    crate::store::save(&state.paths.profile_file(), &*p)
}

#[tauri::command]
pub async fn clash_proxies(state: State<'_, AppState>) -> CmdResult<Value> {
    clash(&state).await?.proxies().await
}

#[tauri::command]
pub async fn clash_delay(state: State<'_, AppState>, tag: String) -> CmdResult<u32> {
    clash(&state).await?.delay(&tag).await
}

#[tauri::command]
pub async fn clash_connections(state: State<'_, AppState>) -> CmdResult<Value> {
    clash(&state).await?.connections().await
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

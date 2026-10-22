//! Tauri commands invoked by the frontend. Argument and result types derive `ts_rs::TS`;
//! `cargo test` regenerates their TypeScript in `apps/desktop/src/lib/bindings/`.

use std::collections::BTreeMap;

use proxy_core::custom::{self, CustomNodeInput, ProxyLink};
use proxy_core::import::{self, GroupImport, ImportContext};
use proxy_core::singbox::restart_fingerprint;
use proxy_core::{Profile, ProxyNode};
use serde::Serialize;
use tauri::State;
use ts_rs::TS;

use crate::clash::ClashProxy;
use crate::core::{CoreStatus, LogBatch};
use crate::credentials::{self, Credentials};
use crate::nodes::{self, NodeList, PingResult};
use crate::stats::{TrafficHistory, TrafficSession};
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
    let removed: Vec<ProxyNode> = {
        let mut current = state.profile.write().await;
        crate::store::save(&state.paths.profile_file(), &profile)?;
        let removed = current.nodes.iter().filter(|n| profile.node(&n.tag).is_none()).cloned().collect();
        *current = profile.clone();
        removed
    };
    // A removed node takes its secrets along: a WARP device is unregistered, a hand-added
    // node's account is forgotten.
    for n in removed {
        if n.is_wireguard() {
            let http = state.http.clone();
            tauri::async_runtime::spawn(async move { crate::warp::deregister(&http, &n.tag).await });
        } else if n.is_custom() {
            credentials::delete_node_secret(&n.tag);
        }
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

/// Splits a pasted proxy link (`http://user:pass@host:port`, `socks5://…`, a `host:port:user:pass`
/// line of a Webshare list) for the add dialog to fill in.
#[tauri::command]
pub async fn parse_proxy_link(text: String) -> CmdResult<ProxyLink> {
    custom::parse_proxy_link(&text)
}

/// Validates a hand-added HTTP/SOCKS5 node and returns it: a new node under a fresh tag (no `tag`)
/// or the edit of an existing one. Nothing is stored: the caller saves the node through
/// `save_profile` first and then hands the same input to `custom_node_store_auth`.
#[tauri::command]
pub async fn custom_node_build(state: State<'_, AppState>, tag: Option<String>, input: CustomNodeInput) -> CmdResult<ProxyNode> {
    let profile = state.profile.read().await;
    let tag = match tag {
        Some(tag) if profile.node(&tag).is_some_and(ProxyNode::is_custom) => tag,
        Some(_) => return Err("找不到這個自訂節點，可能已經被移除".into()),
        None => loop {
            let tag = format!("custom-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            if profile.node(&tag).is_none() {
                break tag;
            }
        },
    };
    // The password does not shape the node; this only checks it against the username.
    input.into_node(tag, None).map(|(node, _)| node)
}

/// Stores the account of a hand-added node, once the profile holds exactly the node built from
/// this input: after a failed profile save the stored account keeps matching the server the profile
/// still has (and a new node that was never saved gets none). A `None` password keeps the stored one.
#[tauri::command]
pub async fn custom_node_store_auth(state: State<'_, AppState>, tag: String, input: CustomNodeInput) -> CmdResult<()> {
    // Held until the account is written: a save that removes the node meanwhile waits, then deletes it.
    let profile = state.profile.read().await;
    let auth = input.account_for_saved(tag.clone(), profile.node(&tag), credentials::load_proxy_auth(&tag))?;
    credentials::store_proxy_auth(&tag, &auth)
}

/// The stored username of a hand-added node, for the edit dialog: empty for a node without
/// authentication, `None` when Credential Manager has no readable account for it. The password
/// never leaves Credential Manager.
#[tauri::command]
pub async fn custom_node_username(state: State<'_, AppState>, tag: String) -> CmdResult<Option<String>> {
    if !state.profile.read().await.node(&tag).is_some_and(ProxyNode::is_custom) {
        return Ok(None);
    }
    Ok(credentials::load_proxy_auth(&tag).map(|a| a.username))
}

/// Reads pasted or uploaded JSON (ProxyDesk groups, Karing diversion rules, a sing-box rule set or
/// config) into groups for the import dialog to show; nothing is stored, the dialog adds the groups
/// it keeps through `save_profile`. `name` (the uploaded file's) names a group the JSON leaves unnamed.
#[tauri::command]
pub async fn parse_group_import(state: State<'_, AppState>, text: String, name: Option<String>) -> CmdResult<GroupImport> {
    let catalog = system::rule_set_catalog(&state.paths.ruleset_dir);
    let rule_sets: Vec<String> = [("geosite", &catalog.geosite), ("geoip", &catalog.geoip), ("acl", &catalog.acl)]
        .into_iter()
        .flat_map(|(kind, codes)| codes.iter().map(move |c| format!("{kind}:{c}")))
        .collect();
    let profile = state.profile.read().await;
    import::parse_group_import(&text, &ImportContext { profile: &profile, rule_sets: &rule_sets, name: name.as_deref().unwrap_or_default() })
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

/// Tests whether the stored Mudfish account can authenticate against live nodes. Auth only, so it
/// costs no traffic; it cannot tell a wrong password from an account out of credit (Mudfish rejects
/// both the same way).
#[tauri::command]
pub async fn verify_account(state: State<'_, AppState>) -> CmdResult<crate::mudfish_probe::AccountCheck> {
    let creds = credentials::load().ok_or("尚未設定 Mudfish 帳號")?;
    // The cached list is enough (no network round trip); only an empty cache fetches one.
    let mut ips: Vec<String> = crate::store::load_or_default::<crate::nodes::NodeCache>(&state.paths.node_cache_file())
        .nodes
        .into_iter()
        .map(|n| n.ip)
        .collect();
    if ips.is_empty() {
        ips = state.node_list.get(&state.http, false).await?.nodes.into_iter().map(|e| e.node.ip).collect();
    }
    if ips.is_empty() {
        return Err("沒有可用的節點可供測試".into());
    }
    Ok(crate::mudfish_probe::check_account(&creds, &ips).await)
}

/// The Mudfish node list: fetched by the first load of each run (the frontend makes it at startup),
/// then reused unless `force`. Offline, the saved list comes back with `error` set.
#[tauri::command]
pub async fn get_nodes(state: State<'_, AppState>, force: bool) -> CmdResult<NodeList> {
    state.node_list.get(&state.http, force).await
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

/// Every recorded connection session, oldest first; the running one is last (`ended_at: null`).
#[tauri::command]
pub async fn traffic_history(state: State<'_, AppState>) -> CmdResult<TrafficHistory> {
    Ok(state.stats.history())
}

/// The running session alone (`null`: none), for refreshing it without the whole history.
#[tauri::command]
pub async fn traffic_current(state: State<'_, AppState>) -> CmdResult<Option<TrafficSession>> {
    Ok(state.stats.current())
}

/// Forgets the closed sessions; a running session keeps counting.
#[tauri::command]
pub async fn traffic_history_clear(state: State<'_, AppState>) -> CmdResult<()> {
    state.stats.clear()
}

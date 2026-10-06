//! Mudfish node list fetching/caching and TCP reachability probes.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proxy_core::mudfish::{self, MudfishNode};
use proxy_core::{ProxyNode, MUDFISH_SOCKS_PORT};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::paths::Paths;

/// Refetch at most this often unless forced; the list changes rarely.
const CACHE_TTL_SECS: u64 = 6 * 3600;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NodeCache {
    pub fetched_at: u64,
    pub nodes: Vec<MudfishNode>,
}

/// The node list as the UI gets it: each entry carries the `ProxyNode` to add, so the
/// Mudfish → node conversion exists only in proxy-core.
#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct NodeList {
    #[ts(type = "number")]
    pub fetched_at: u64,
    pub nodes: Vec<NodeEntry>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct NodeEntry {
    #[serde(flatten)]
    pub node: MudfishNode,
    pub proxy: ProxyNode,
}

impl From<NodeCache> for NodeList {
    fn from(c: NodeCache) -> Self {
        let nodes = c.nodes.into_iter().map(|node| NodeEntry { proxy: node.to_proxy_node(), node }).collect();
        Self { fetched_at: c.fetched_at, nodes }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub async fn get(paths: &Paths, http: &reqwest::Client, force: bool) -> Result<NodeCache, String> {
    let cached: NodeCache = crate::store::load_or_default(&paths.node_cache_file());
    if !force && !cached.nodes.is_empty() && now().saturating_sub(cached.fetched_at) < CACHE_TTL_SECS {
        return Ok(cached);
    }
    match fetch(http).await {
        Ok(nodes) => {
            let fresh = NodeCache { fetched_at: now(), nodes };
            crate::store::save(&paths.node_cache_file(), &fresh)?;
            Ok(fresh)
        }
        // Offline: keep working from the last list.
        Err(e) if !cached.nodes.is_empty() => {
            log::warn!("節點清單更新失敗，使用快取: {e}");
            Ok(cached)
        }
        Err(e) => Err(e),
    }
}

async fn fetch(http: &reqwest::Client) -> Result<Vec<MudfishNode>, String> {
    let body = http
        .get(mudfish::STATIC_NODES_URL)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("無法取得 Mudfish 節點清單: {e}"))?
        .text()
        .await
        .map_err(|e| e.to_string())?;
    mudfish::parse_static_nodes(&body).map_err(|e| e.to_string())
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct PingResult {
    pub ip: String,
    /// TCP handshake time to the SOCKS port; `None` when unreachable within the timeout.
    pub ms: Option<u32>,
}

/// TCP connect time to `ip:18081`. Costs no Mudfish traffic and works while the core is stopped.
pub async fn ping(ips: Vec<String>) -> Vec<PingResult> {
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    let tasks: Vec<_> = ips
        .into_iter()
        .map(|ip| {
            let sem = sem.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await;
                let start = Instant::now();
                let ok = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::net::TcpStream::connect((ip.as_str(), MUDFISH_SOCKS_PORT)),
                )
                .await
                .is_ok_and(|r| r.is_ok());
                PingResult { ms: ok.then(|| start.elapsed().as_millis() as u32), ip }
            })
        })
        .collect();
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(r) = t.await {
            out.push(r);
        }
    }
    out
}

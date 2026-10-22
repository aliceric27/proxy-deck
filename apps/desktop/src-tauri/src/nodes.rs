//! Mudfish node list fetching/caching and TCP reachability probes.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proxy_core::mudfish::{self, MudfishNode};
use proxy_core::{ProxyNode, MUDFISH_SOCKS_PORT};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use ts_rs::TS;

/// Within one run, a fetched list is reused this long unless a refresh is forced; the list changes
/// rarely. A list saved by an earlier run is never reused this way.
const REFETCH_AFTER: Duration = Duration::from_secs(6 * 3600);
/// After a failed fetch the saved list stands in, and the next load tries again once this has passed.
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// The list saved by the last successful fetch (`mudfish-nodes.json`), for when Mudfish cannot be
/// reached.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Why the list could not be updated: `nodes` is then the list saved at `fetched_at`.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[ts(export)]
pub struct NodeEntry {
    #[serde(flatten)]
    pub node: MudfishNode,
    pub proxy: ProxyNode,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Where the node list comes from. The first load of each run of the app fetches it from Mudfish,
/// so the saved list is only used while Mudfish cannot be reached.
pub struct NodeSource {
    url: String,
    file: PathBuf,
    /// This run's list. The lock is held across a fetch: a load that comes in meanwhile waits for
    /// its result instead of fetching again.
    loaded: Mutex<Option<Loaded>>,
}

struct Loaded {
    list: NodeCache,
    /// Why the last fetch failed; `list` is then the saved one.
    error: Option<String>,
    at: Instant,
}

impl Loaded {
    fn to_list(&self) -> NodeList {
        let nodes = self.list.nodes.iter().map(|node| NodeEntry { proxy: node.to_proxy_node(), node: node.clone() }).collect();
        NodeList { fetched_at: self.list.fetched_at, nodes, error: self.error.clone() }
    }
}

impl NodeSource {
    pub fn new(file: PathBuf) -> Self {
        Self { url: mudfish::STATIC_NODES_URL.to_string(), file, loaded: Mutex::new(None) }
    }

    /// The first load of a run fetches the list; later loads reuse it (for `REFETCH_AFTER`, or
    /// `RETRY_AFTER` after a failed fetch) unless `force`. When the fetch fails, the saved list
    /// comes back with `error` set, or the error itself when nothing was saved yet.
    pub async fn get(&self, http: &reqwest::Client, force: bool) -> Result<NodeList, String> {
        let mut loaded = self.loaded.lock().await;
        if let Some(l) = loaded.as_ref() {
            let keep = if l.error.is_some() { RETRY_AFTER } else { REFETCH_AFTER };
            if !force && l.at.elapsed() < keep {
                return Ok(l.to_list());
            }
        }
        let next = match fetch(http, &self.url).await {
            Ok(nodes) => {
                let fresh = NodeCache { fetched_at: now(), nodes };
                crate::store::save(&self.file, &fresh)?;
                Loaded { list: fresh, error: None, at: Instant::now() }
            }
            // Offline: keep working from the last list.
            Err(e) => {
                let saved: NodeCache = crate::store::load_or_default(&self.file);
                if saved.nodes.is_empty() {
                    return Err(e);
                }
                log::warn!("節點清單更新失敗，使用上次的清單: {e}");
                Loaded { list: saved, error: Some(e), at: Instant::now() }
            }
        };
        Ok(loaded.insert(next).to_list())
    }
}

async fn fetch(http: &reqwest::Client, url: &str) -> Result<Vec<MudfishNode>, String> {
    let body = http
        .get(url)
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const LIST: &str = r#"{"status": 200, "staticnodes": [
      {"commercial_node": 1, "commercial_node_premium_enabled": 1, "hostname": "node-tw-00591.mudfish.net",
       "ip": "35.236.137.214", "location": "TW Asia (Taiwan - Google 1)", "private_ip": "10.0.0.1", "sid": 591}]}"#;

    /// Stands in for `mudfish.net/api/staticnodes`: answers `LIST` while `up`, 503 otherwise, and
    /// counts the requests.
    struct Mudfish {
        url: String,
        up: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
    }

    impl Mudfish {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/api/staticnodes", listener.local_addr().unwrap());
            let (up, hits) = (Arc::new(AtomicBool::new(true)), Arc::new(AtomicUsize::new(0)));
            let (serving, counter) = (up.clone(), hits.clone());
            tokio::spawn(async move {
                while let Ok((mut s, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let reply = if serving.load(Ordering::SeqCst) {
                        format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{LIST}", LIST.len())
                    } else {
                        "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
                    };
                    tokio::spawn(async move {
                        let _ = s.read(&mut [0u8; 4096]).await; // the request; any will do
                        let _ = s.write_all(reply.as_bytes()).await;
                    });
                }
            });
            Self { url, up, hits }
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    /// A source on `server` whose saved list lives in a fresh scratch directory.
    fn source(name: &str, server: &Mudfish) -> NodeSource {
        let dir = std::env::temp_dir().join(format!("proxydesk-nodes-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        NodeSource { url: server.url.clone(), file: dir.join("mudfish-nodes.json"), loaded: Mutex::new(None) }
    }

    /// What an earlier run saved a minute ago, with node 591 still at an old address. Returns its
    /// `fetched_at`.
    fn save_old_list(file: &Path) -> u64 {
        let mut node = mudfish::parse_static_nodes(LIST).unwrap().remove(0);
        node.ip = "1.2.3.4".into();
        let fetched_at = now() - 60;
        crate::store::save(file, &NodeCache { fetched_at, nodes: vec![node] }).unwrap();
        fetched_at
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn every_run_starts_from_a_fresh_list() {
        let server = Mudfish::start().await;
        let source = source("fresh", &server);
        save_old_list(&source.file);

        let list = source.get(&http(), false).await.unwrap();
        assert_eq!(server.hits(), 1, "a list saved by an earlier run is not reused, however recent");
        assert_eq!((list.nodes[0].node.ip.as_str(), list.nodes[0].proxy.server.as_str()), ("35.236.137.214", "35.236.137.214"));
        assert_eq!(list.error, None);
        let saved: NodeCache = crate::store::load_or_default(&source.file);
        assert_eq!((saved.fetched_at, saved.nodes[0].ip.as_str()), (list.fetched_at, "35.236.137.214"), "saved for when Mudfish cannot be reached");

        // the rest of the run reuses it; a refresh fetches again
        source.get(&http(), false).await.unwrap();
        assert_eq!(server.hits(), 1);
        source.get(&http(), true).await.unwrap();
        assert_eq!(server.hits(), 2);
        let _ = std::fs::remove_dir_all(source.file.parent().unwrap());
    }

    #[tokio::test]
    async fn loads_during_a_fetch_wait_for_it() {
        let server = Mudfish::start().await;
        let source = source("shared", &server);
        let http = http();
        let (a, b) = tokio::join!(source.get(&http, false), source.get(&http, false));
        assert_eq!(a.unwrap().fetched_at, b.unwrap().fetched_at);
        assert_eq!(server.hits(), 1, "the startup load and the node page's load share one fetch");
        let _ = std::fs::remove_dir_all(source.file.parent().unwrap());
    }

    #[tokio::test]
    async fn offline_the_saved_list_stands_in_and_says_so() {
        let server = Mudfish::start().await;
        server.up.store(false, Ordering::SeqCst);
        let source = source("offline", &server);
        let fetched_at = save_old_list(&source.file);

        let list = source.get(&http(), false).await.unwrap();
        assert_eq!((list.fetched_at, list.nodes[0].node.ip.as_str()), (fetched_at, "1.2.3.4"));
        let error = list.error.expect("the UI must be able to tell");
        assert!(error.contains("無法取得 Mudfish 節點清單"), "{error}");

        // the node page right after does not wait for another attempt; a refresh tries again
        assert!(source.get(&http(), false).await.unwrap().error.is_some());
        assert_eq!(server.hits(), 1);
        server.up.store(true, Ordering::SeqCst);
        let list = source.get(&http(), true).await.unwrap();
        assert_eq!(list.error, None);
        assert_eq!(list.nodes[0].node.ip, "35.236.137.214");
        assert_eq!(server.hits(), 2);
        let _ = std::fs::remove_dir_all(source.file.parent().unwrap());
    }

    #[tokio::test]
    async fn offline_without_a_saved_list_is_an_error_and_retried() {
        let server = Mudfish::start().await;
        server.up.store(false, Ordering::SeqCst);
        let source = source("none", &server);

        let error = source.get(&http(), false).await.unwrap_err();
        assert!(error.contains("無法取得 Mudfish 節點清單"), "{error}");
        // with nothing to show, the next load tries again at once
        source.get(&http(), false).await.unwrap_err();
        assert_eq!(server.hits(), 2);
        let _ = std::fs::remove_dir_all(source.file.parent().unwrap());
    }
}

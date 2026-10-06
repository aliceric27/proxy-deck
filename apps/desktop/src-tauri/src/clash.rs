//! Client for sing-box's Clash-compatible API (endpoints verified in M0).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ts_rs::TS;

/// One entry of `GET /proxies` (the fields the UI uses).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ClashProxy {
    #[serde(rename = "type")]
    pub kind: String,
    /// Current choice of a selector/urltest.
    #[serde(default)]
    #[ts(optional)]
    pub now: Option<String>,
    #[serde(default)]
    pub history: Vec<DelayRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DelayRecord {
    pub delay: u32,
}

#[derive(Deserialize)]
struct ProxiesResponse {
    proxies: BTreeMap<String, ClashProxy>,
}

/// `GET /connections` totals and entries.
#[derive(Debug, Clone, Default)]
pub struct ClashConnections {
    pub upload_total: u64,
    pub download_total: u64,
    pub connections: Vec<Connection>,
}

/// sing-box sends `"connections": null` when there are none.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConnections {
    upload_total: u64,
    download_total: u64,
    #[serde(default)]
    connections: Option<Vec<Connection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Connection {
    pub id: String,
    #[ts(type = "number")]
    pub upload: u64,
    #[ts(type = "number")]
    pub download: u64,
    pub start: String,
    /// From the actual outbound back to the selector that picked it: [node, …, group-x].
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub metadata: ConnectionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ConnectionMetadata {
    pub network: String,
    #[serde(default)]
    pub host: String,
    #[serde(rename = "destinationIP", default)]
    pub destination_ip: String,
    #[serde(default)]
    pub destination_port: String,
    #[serde(default)]
    #[ts(optional)]
    pub process_path: Option<String>,
}


#[derive(Clone)]
pub struct ClashClient {
    base: String,
    secret: String,
    http: reqwest::Client,
}

impl ClashClient {
    pub fn new(listen: &str, secret: &str) -> Self {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");
        Self { base: format!("http://{listen}"), secret: secret.to_string(), http }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value, String> {
        let resp = req.bearer_auth(&self.secret).send().await.map_err(|e| format!("Clash API 無回應: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("Clash API {status}: {body}"));
        }
        Ok(if body.trim().is_empty() { Value::Null } else { serde_json::from_str(&body).unwrap_or(Value::String(body)) })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        serde_json::from_value(self.send(self.http.get(self.url(path))).await?).map_err(|e| format!("Clash API 回應格式錯誤: {e}"))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub async fn version(&self) -> Result<Value, String> {
        self.send(self.http.get(self.url("/version")).timeout(Duration::from_secs(1))).await
    }

    pub async fn proxies(&self) -> Result<BTreeMap<String, ClashProxy>, String> {
        Ok(self.get::<ProxiesResponse>("/proxies").await?.proxies)
    }

    pub async fn select(&self, group: &str, name: &str) -> Result<(), String> {
        self.send(self.http.put(self.url(&format!("/proxies/{group}"))).json(&json!({ "name": name }))).await.map(|_| ())
    }

    /// Latency in ms through `tag`, or an error when the node does not answer in time.
    pub async fn delay(&self, tag: &str) -> Result<u32, String> {
        let v = self
            .send(self.http.get(self.url(&format!("/proxies/{tag}/delay"))).query(&[
                ("url", "https://www.gstatic.com/generate_204"),
                ("timeout", "5000"),
            ]))
            .await?;
        v["delay"].as_u64().map(|d| d as u32).ok_or_else(|| "逾時".to_string())
    }

    pub async fn connections(&self) -> Result<ClashConnections, String> {
        let raw: RawConnections = self.get("/connections").await?;
        Ok(ClashConnections { upload_total: raw.upload_total, download_total: raw.download_total, connections: raw.connections.unwrap_or_default() })
    }

    pub async fn close_connection(&self, id: &str) -> Result<(), String> {
        self.send(self.http.delete(self.url(&format!("/connections/{id}")))).await.map(|_| ())
    }

    pub async fn close_all(&self) -> Result<(), String> {
        self.send(self.http.delete(self.url("/connections"))).await.map(|_| ())
    }

    /// Switches the Clash mode and confirms it: sing-box answers 204 even when it ignores a
    /// mode that is not in its mode list.
    pub async fn set_mode(&self, mode: &str) -> Result<(), String> {
        self.send(self.http.patch(self.url("/configs")).json(&json!({ "mode": mode }))).await?;
        let now = self.send(self.http.get(self.url("/configs"))).await?;
        if now["mode"].as_str().is_some_and(|m| m.eq_ignore_ascii_case(mode)) {
            Ok(())
        } else {
            Err(format!("sing-box 沒有切換到 {mode} 模式（目前 {}）", now["mode"]))
        }
    }
}

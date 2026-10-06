//! Client for sing-box's Clash-compatible API (endpoints verified in M0).

use std::time::Duration;

use serde_json::{json, Value};

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

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub async fn version(&self) -> Result<Value, String> {
        self.send(self.http.get(self.url("/version")).timeout(Duration::from_secs(1))).await
    }

    pub async fn proxies(&self) -> Result<Value, String> {
        self.send(self.http.get(self.url("/proxies"))).await
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

    pub async fn connections(&self) -> Result<Value, String> {
        self.send(self.http.get(self.url("/connections"))).await
    }

    pub async fn close_connection(&self, id: &str) -> Result<(), String> {
        self.send(self.http.delete(self.url(&format!("/connections/{id}")))).await.map(|_| ())
    }

    pub async fn close_all(&self) -> Result<(), String> {
        self.send(self.http.delete(self.url("/connections"))).await.map(|_| ())
    }

    pub async fn set_mode(&self, mode: &str) -> Result<(), String> {
        self.send(self.http.patch(self.url("/configs")).json(&json!({ "mode": mode }))).await.map(|_| ())
    }
}

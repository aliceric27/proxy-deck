//! Cloudflare WARP device registration, following lanrat/wireguard-warp-generator
//! (scripts/warp-register.sh): generate a WireGuard keypair locally, register the public key,
//! and read the peer/interface config from the response.

use std::time::Duration;

use proxy_core::{ProxyNode, WireguardPeer};
use serde::Deserialize;
use serde_json::json;
use tokio::process::Command;

use crate::credentials::{self, WarpSecret};

const REG_URL: &str = "https://api.cloudflareclient.com/v0a737/reg";
const WARP_MTU: u32 = 1280;
const DEFAULT_ENDPOINT: (&str, u16) = ("engage.cloudflareclient.com", 2408);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Deserialize)]
struct RegResponse {
    id: String,
    token: String,
    config: RegConfig,
}

#[derive(Deserialize)]
struct RegConfig {
    #[serde(default)]
    client_id: String,
    peers: Vec<RegPeer>,
    interface: RegInterface,
}

#[derive(Deserialize)]
struct RegPeer {
    public_key: String,
    endpoint: RegEndpoint,
}

#[derive(Deserialize)]
struct RegEndpoint {
    #[serde(default)]
    host: String,
}

#[derive(Deserialize)]
struct RegInterface {
    addresses: RegAddresses,
}

#[derive(Deserialize)]
struct RegAddresses {
    v4: String,
    #[serde(default)]
    v6: String,
}

/// `sing-box generate wg-keypair` → (private, public), both base64.
async fn keypair(sing_box: &std::path::Path) -> Result<(String, String), String> {
    let out = Command::new(sing_box)
        .args(["generate", "wg-keypair"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .await
        .map_err(|e| format!("無法執行 sing-box 產生金鑰: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim_start_matches(':').trim().to_string()))
            .filter(|v| !v.is_empty())
    };
    match (field("PrivateKey"), field("PublicKey")) {
        (Some(private), Some(public)) => Ok((private, public)),
        _ => Err(format!("無法解析 sing-box 金鑰輸出: {text}")),
    }
}

/// `"engage.cloudflareclient.com:2408"` → host, port (falls back to the well-known endpoint).
fn split_endpoint(host: &str) -> (String, u16) {
    match host.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.contains(':') => (h.to_string(), p.parse().unwrap_or(DEFAULT_ENDPOINT.1)),
        _ if !host.is_empty() && !host.contains(':') => (host.to_string(), DEFAULT_ENDPOINT.1),
        _ => (DEFAULT_ENDPOINT.0.to_string(), DEFAULT_ENDPOINT.1),
    }
}

/// `client_id` is base64 of the 3 WireGuard reserved bytes some WARP edges require.
fn reserved_bytes(client_id: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = Vec::new();
    for c in client_id.bytes().take_while(|&c| c != b'=') {
        let Some(v) = ALPHABET.iter().position(|&a| a == c) else { return Vec::new() };
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    if out.len() == 3 {
        out
    } else {
        Vec::new()
    }
}

/// Registers a new WARP device and returns the node (public parts) after storing its secrets.
pub async fn create(http: &reqwest::Client, sing_box: &std::path::Path, index: usize) -> Result<ProxyNode, String> {
    let (private_key, public_key) = keypair(sing_box).await?;
    let tos = chrono_like_now();
    let resp = http
        .post(REG_URL)
        .timeout(Duration::from_secs(20))
        .json(&json!({
            "key": public_key,
            "install_id": "",
            "warp_enabled": true,
            "tos": tos,
            "type": "Linux",
            "locale": "en_US",
        }))
        .send()
        .await
        .map_err(|e| format!("無法連線到 Cloudflare WARP API: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err("Cloudflare 暫時限制了註冊次數（429），請過幾分鐘再試。".into());
    }
    if !status.is_success() {
        return Err(format!("WARP 註冊失敗（{status}）：{}", body.chars().take(300).collect::<String>()));
    }
    let reg: RegResponse = serde_json::from_str(&body).map_err(|e| format!("無法解析 WARP 回應: {e}"))?;
    let peer = reg.config.peers.first().ok_or("WARP 回應沒有 peer")?;
    let (server, port) = split_endpoint(&peer.endpoint.host);

    let tag = format!("warp-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    credentials::store_warp(&tag, &WarpSecret { private_key, device_id: reg.id, token: reg.token })?;

    Ok(ProxyNode {
        tag,
        sid: 0,
        name: if index == 0 { "Cloudflare WARP".to_string() } else { format!("Cloudflare WARP {}", index + 1) },
        server,
        port,
        country: "CF".to_string(),
        udp: true,
        wireguard: Some(WireguardPeer {
            peer_public_key: peer.public_key.clone(),
            address_v4: reg.config.interface.addresses.v4,
            address_v6: reg.config.interface.addresses.v6,
            reserved: reserved_bytes(&reg.config.client_id),
            mtu: WARP_MTU,
        }),
    })
}

/// Unregisters the WARP device behind a removed node (best effort), then forgets its secret.
pub async fn deregister(http: &reqwest::Client, tag: &str) {
    if let Some(secret) = credentials::load_warp(tag) {
        let res = http
            .delete(format!("{REG_URL}/{}", secret.device_id))
            .bearer_auth(&secret.token)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .and_then(|r| r.error_for_status());
        if let Err(e) = res {
            log::warn!("WARP 裝置註銷失敗（{tag}）: {e}");
        }
    }
    credentials::delete_node_secret(tag);
}

/// RFC 3339 UTC timestamp with millisecond precision, as the WARP client sends for `tos`.
fn chrono_like_now() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_endpoint_host() {
        assert_eq!(split_endpoint("engage.cloudflareclient.com:2408"), ("engage.cloudflareclient.com".into(), 2408));
        assert_eq!(split_endpoint("162.159.192.1:500"), ("162.159.192.1".into(), 500));
        assert_eq!(split_endpoint(""), ("engage.cloudflareclient.com".into(), 2408));
        assert_eq!(split_endpoint("[2606:4700:d0::a29f:c001]:2408"), ("engage.cloudflareclient.com".into(), 2408));
    }

    #[test]
    fn decodes_reserved_from_client_id() {
        assert_eq!(reserved_bytes("AQID"), vec![1, 2, 3]);
        assert_eq!(reserved_bytes("Zm9v"), b"foo".to_vec());
        assert!(reserved_bytes("").is_empty());
        assert!(reserved_bytes("not*base64").is_empty());
    }

    #[test]
    fn tos_timestamp_shape() {
        let t = chrono_like_now();
        assert_eq!(t.len(), "2026-10-06T03:04:05.123+00:00".len());
        assert!(t.ends_with("+00:00") && t.as_bytes()[10] == b'T');
    }
}

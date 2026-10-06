//! Mudfish node list: `GET https://mudfish.net/api/staticnodes` (public, no auth).

use serde::{Deserialize, Serialize};

use crate::model::{ProxyNode, MUDFISH_SOCKS_PORT};

pub const STATIC_NODES_URL: &str = "https://mudfish.net/api/staticnodes";

#[derive(Debug, Deserialize)]
struct StaticNodesResponse {
    staticnodes: Vec<RawNode>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    sid: u32,
    hostname: String,
    ip: String,
    location: String,
    #[serde(default)]
    commercial_node: u8,
    #[serde(default)]
    commercial_node_premium_enabled: u8,
}

/// A node from the Mudfish list, with `location` split into display parts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ts_rs::TS)]
#[ts(export)]
pub struct MudfishNode {
    pub sid: u32,
    pub hostname: String,
    pub ip: String,
    pub location: String,
    /// ISO 3166-1 alpha-2, upper case (first two characters of `location`).
    pub country: String,
    pub region: String,
    pub city: String,
    pub provider: String,
    pub commercial: bool,
    pub premium: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid node list JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_static_nodes(body: &str) -> Result<Vec<MudfishNode>, ParseError> {
    let resp: StaticNodesResponse = serde_json::from_str(body)?;
    Ok(resp
        .staticnodes
        .into_iter()
        .filter(|n| !n.ip.is_empty())
        .map(|n| {
            let loc = parse_location(&n.location);
            MudfishNode {
                sid: n.sid,
                hostname: n.hostname,
                ip: n.ip,
                country: loc.country,
                region: loc.region,
                city: loc.city,
                provider: loc.provider,
                location: n.location,
                commercial: n.commercial_node == 1,
                premium: n.commercial_node_premium_enabled == 1,
            }
        })
        .collect())
}

struct Location {
    country: String,
    region: String,
    city: String,
    provider: String,
}

/// `"TW Asia (Taiwan - Google 1)"` → TW / Asia / Taiwan / Google 1.
/// About 3% of entries deviate (`"KR Asia (S. Korea - GNJ IDC) 10"`); unparsed parts fall back
/// to the raw text so nothing is lost.
fn parse_location(raw: &str) -> Location {
    let country: String = raw.chars().take(2).collect::<String>().to_ascii_uppercase();
    let rest = raw.get(2..).unwrap_or("").trim();
    let (region, inner, suffix) = match (rest.find('('), rest.rfind(')')) {
        (Some(open), Some(close)) if close > open => (
            rest[..open].trim(),
            &rest[open + 1..close],
            rest[close + 1..].trim().trim_start_matches('-').trim(),
        ),
        _ => (rest, "", ""),
    };
    let (city, mut provider) = match inner.split_once(" - ") {
        Some((c, p)) => (c.trim().to_string(), p.trim().to_string()),
        None => (inner.trim().to_string(), String::new()),
    };
    if !suffix.is_empty() {
        provider = if provider.is_empty() { suffix.to_string() } else { format!("{provider} {suffix}") };
    }
    Location { country, region: region.to_string(), city, provider }
}

impl MudfishNode {
    pub fn tag(&self) -> String {
        format!("mudfish-{}", self.sid)
    }

    pub fn display_name(&self) -> String {
        match (self.city.is_empty(), self.provider.is_empty()) {
            (false, false) => format!("{} {} - {}", self.country, self.city, self.provider),
            (false, true) => format!("{} {}", self.country, self.city),
            _ => self.location.clone(),
        }
    }

    pub fn to_proxy_node(&self) -> ProxyNode {
        ProxyNode {
            tag: self.tag(),
            sid: self.sid,
            name: self.display_name(),
            server: self.ip.clone(),
            port: MUDFISH_SOCKS_PORT,
            country: self.country.clone(),
            udp: true,
            wireguard: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"status": 200, "staticnodes": [
      {"commercial_node": 1, "commercial_node_premium_enabled": 1, "hostname": "node-tw-00591.mudfish.net",
       "ip": "35.236.137.214", "location": "TW Asia (Taiwan - Google 1)", "private_ip": "10.0.0.1", "sid": 591},
      {"commercial_node": 1, "commercial_node_premium_enabled": 0, "hostname": "node-kr-00010.mudfish.net",
       "ip": "1.2.3.4", "location": "KR Asia (S. Korea - GNJ IDC) 10", "private_ip": "10.0.0.2", "sid": 10},
      {"commercial_node": 0, "commercial_node_premium_enabled": 0, "hostname": "node-ee-00001.mudfish.net",
       "ip": "5.6.7.8", "location": "EE Europe (Tallinn - VPS2Day 2) - PBE", "private_ip": "10.0.0.3", "sid": 1}
    ]}"#;

    #[test]
    fn parses_regular_and_irregular_locations() {
        let nodes = parse_static_nodes(SAMPLE).unwrap();
        assert_eq!(nodes.len(), 3);

        let tw = &nodes[0];
        assert_eq!((tw.country.as_str(), tw.region.as_str()), ("TW", "Asia"));
        assert_eq!((tw.city.as_str(), tw.provider.as_str()), ("Taiwan", "Google 1"));
        assert!(tw.premium && tw.commercial);
        assert_eq!(tw.display_name(), "TW Taiwan - Google 1");

        assert_eq!(nodes[1].city, "S. Korea");
        assert_eq!(nodes[1].provider, "GNJ IDC 10");
        assert_eq!(nodes[2].provider, "VPS2Day 2 PBE");
        assert!(!nodes[2].commercial);
    }

    #[test]
    fn proxy_node_uses_public_socks_port() {
        let n = parse_static_nodes(SAMPLE).unwrap()[0].to_proxy_node();
        assert_eq!(n.tag, "mudfish-591");
        assert_eq!((n.server.as_str(), n.port), ("35.236.137.214", 18081));
    }

    #[test]
    fn parses_live_snapshot_if_present() {
        // Optional: PROXYDESK_STATICNODES=<path to a saved staticnodes.json>
        let Ok(path) = std::env::var("PROXYDESK_STATICNODES") else { return };
        let nodes = parse_static_nodes(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(nodes.len() > 100);
        assert!(nodes.iter().all(|n| n.country.len() == 2 && !n.city.is_empty()));
    }
}

//! Mudfish account check: a SOCKS5 username/password handshake against live nodes.
//!
//! Auth only — it never issues a CONNECT, so it spends no credit. Mudfish rejects a wrong
//! password and a valid account with no credit the same way (RFC 1929 status 0x02 + close), so
//! this can only tell "usable" from "not usable", never which of the two it is.

use std::time::Duration;

use proxy_core::MUDFISH_SOCKS_PORT;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use ts_rs::TS;

use crate::credentials::Credentials;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum AccountCheck {
    /// A node accepted the credentials: the account is valid and has credit.
    Usable,
    /// A node cleanly rejected the credentials: wrong password OR no credit (indistinguishable).
    Unusable,
    /// No node could be reached to test (all refused/timed out).
    Unreachable,
}

/// The RFC 1929 username/password request, or `None` if either exceeds 255 bytes.
fn auth_request(user: &str, pass: &str) -> Option<Vec<u8>> {
    let (u, p) = (user.as_bytes(), pass.as_bytes());
    if u.len() > 255 || p.len() > 255 {
        return None;
    }
    let mut req = vec![0x01, u.len() as u8];
    req.extend_from_slice(u);
    req.push(p.len() as u8);
    req.extend_from_slice(p);
    Some(req)
}

/// Picks up to `n` IPs spread across the list, for provider/region diversity.
fn sample_nodes(ips: &[String], n: usize) -> Vec<String> {
    if ips.is_empty() || n == 0 {
        return Vec::new();
    }
    if ips.len() <= n {
        return ips.to_vec();
    }
    let step = ips.len() / n;
    (0..n).map(|i| ips[i * step].clone()).collect()
}

/// One SOCKS5 greeting + RFC1929 auth. Ok(true)=accepted, Ok(false)=rejected, Err=network/proto.
async fn auth_once(ip: &str, req: &[u8]) -> Result<bool, String> {
    let work = async {
        let mut s = TcpStream::connect((ip, MUDFISH_SOCKS_PORT)).await.map_err(|e| e.to_string())?;
        s.write_all(&[0x05, 0x01, 0x02]).await.map_err(|e| e.to_string())?;
        let mut greet = [0u8; 2];
        s.read_exact(&mut greet).await.map_err(|e| e.to_string())?;
        if greet[1] != 0x02 {
            return Err("伺服器不接受帳密認證".to_string());
        }
        s.write_all(req).await.map_err(|e| e.to_string())?;
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
        Ok(reply[1] == 0x00)
    };
    tokio::time::timeout(Duration::from_secs(8), work).await.map_err(|_| "逾時".to_string())?
}

/// Tries a spread of nodes in parallel; any success => Usable, else any clean rejection =>
/// Unusable, else Unreachable.
pub async fn check_account(creds: &Credentials, node_ips: &[String]) -> AccountCheck {
    let Some(req) = auth_request(&creds.username, &creds.password) else {
        return AccountCheck::Unusable;
    };
    let mut set = tokio::task::JoinSet::new();
    for ip in sample_nodes(node_ips, 6) {
        let req = req.clone();
        set.spawn(async move { auth_once(&ip, &req).await });
    }
    let mut saw_rejection = false;
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(true)) => return AccountCheck::Usable,
            Ok(Ok(false)) => saw_rejection = true,
            _ => {}
        }
    }
    if saw_rejection {
        AccountCheck::Unusable
    } else {
        AccountCheck::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_encodes_lengths() {
        assert_eq!(auth_request("ab", "cd"), Some(vec![0x01, 2, b'a', b'b', 2, b'c', b'd']));
        assert_eq!(auth_request(&"x".repeat(256), "y"), None);
    }

    #[test]
    fn sample_nodes_spreads_and_caps() {
        let ips: Vec<String> = (0..12).map(|i| i.to_string()).collect();
        let s = sample_nodes(&ips, 6);
        assert_eq!(s, ["0", "2", "4", "6", "8", "10"]);
        assert_eq!(sample_nodes(&ips[..3], 6), ["0", "1", "2"]);
        assert!(sample_nodes(&[], 6).is_empty());
    }
}

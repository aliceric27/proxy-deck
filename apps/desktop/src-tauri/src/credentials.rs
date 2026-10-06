//! Mudfish account (ID + password) in Windows Credential Manager. These are the account
//! credentials themselves, so they never touch profile.json or the logs.

use serde::{Deserialize, Serialize};

const SERVICE: &str = "ProxyDesk";
const ACCOUNT: &str = "mudfish-account";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("無法存取認證管理員: {e}"))
}

pub fn load() -> Option<Credentials> {
    let secret = entry().ok()?.get_password().ok()?;
    serde_json::from_str(&secret).ok()
}

pub fn store(creds: &Credentials) -> Result<(), String> {
    let secret = serde_json::to_string(creds).map_err(|e| e.to_string())?;
    entry()?.set_password(&secret).map_err(|e| format!("儲存帳號失敗: {e}"))
}

pub fn clear() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("刪除帳號失敗: {e}")),
    }
}

/// Per-node secrets (WARP private key + device token), one entry per node tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpSecret {
    pub private_key: String,
    pub device_id: String,
    pub token: String,
}

fn node_entry(tag: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, &format!("node-{tag}")).map_err(|e| format!("無法存取認證管理員: {e}"))
}

pub fn load_warp(tag: &str) -> Option<WarpSecret> {
    serde_json::from_str(&node_entry(tag).ok()?.get_password().ok()?).ok()
}

pub fn store_warp(tag: &str, secret: &WarpSecret) -> Result<(), String> {
    let s = serde_json::to_string(secret).map_err(|e| e.to_string())?;
    node_entry(tag)?.set_password(&s).map_err(|e| format!("儲存 WARP 金鑰失敗: {e}"))
}

pub fn delete_node_secret(tag: &str) {
    if let Ok(e) = node_entry(tag) {
        let _ = e.delete_credential();
    }
}

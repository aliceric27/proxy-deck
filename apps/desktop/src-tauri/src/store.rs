//! JSON persistence with atomic replace, so a crash mid-write never leaves a truncated profile.

use std::path::Path;

use serde::{de::DeserializeOwned, Serialize};

pub fn load_or_default<T: DeserializeOwned + Default>(path: &Path) -> T {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            log::warn!("{} 無法解析，改用預設值: {e}", path.display());
            let _ = std::fs::rename(path, path.with_extension("json.bad"));
            T::default()
        }),
        Err(_) => T::default(),
    }
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, bytes).map_err(|e| format!("寫入 {} 失敗: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("取代 {} 失敗: {e}", path.display()))
}

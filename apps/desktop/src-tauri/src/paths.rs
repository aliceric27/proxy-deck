use std::path::PathBuf;

use tauri::{AppHandle, Manager};

/// Filesystem locations used by the app.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `%APPDATA%\tw.proxydesk.desktop` — profile.json, node cache.
    pub config_dir: PathBuf,
    /// `%LOCALAPPDATA%\tw.proxydesk.desktop\run` — generated config.json (contains credentials), cache.db.
    pub run_dir: PathBuf,
    /// Bundled `.srs` rule sets (`geosite/`, `geoip/`, `acl/`, `*_codes.txt`).
    pub ruleset_dir: PathBuf,
    /// sing-box sidecar; Tauri places `externalBin` next to the app executable.
    pub sing_box: PathBuf,
}

impl Paths {
    pub fn resolve(app: &AppHandle) -> Result<Self, String> {
        let pr = app.path();
        let config_dir = pr.app_config_dir().map_err(|e| e.to_string())?;
        let run_dir = pr.app_local_data_dir().map_err(|e| e.to_string())?.join("run");
        let ruleset_dir = pr.resource_dir().map_err(|e| e.to_string())?.join("resources").join("rulesets");
        let exe_dir = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("executable has no parent directory")?
            .to_path_buf();
        for d in [&config_dir, &run_dir] {
            std::fs::create_dir_all(d).map_err(|e| format!("無法建立 {}: {e}", d.display()))?;
        }
        Ok(Self { config_dir, run_dir, ruleset_dir, sing_box: exe_dir.join("sing-box.exe") })
    }

    pub fn profile_file(&self) -> PathBuf {
        self.config_dir.join("profile.json")
    }

    pub fn node_cache_file(&self) -> PathBuf {
        self.config_dir.join("mudfish-nodes.json")
    }

    pub fn core_config_file(&self) -> PathBuf {
        self.run_dir.join("config.json")
    }
}

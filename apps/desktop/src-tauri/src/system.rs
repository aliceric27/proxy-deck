//! OS helpers: running-process listing for the app picker, elevation check, rule-set catalogs.

use std::collections::BTreeMap;

use serde::Serialize;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export)]
pub struct ProcessInfo {
    pub name: String,
    pub path: String,
}

/// Distinct executables currently running (by path), sorted by name.
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::Always));
    let mut by_path = BTreeMap::new();
    for p in sys.processes().values() {
        let Some(exe) = p.exe() else { continue };
        let path = exe.to_string_lossy().to_string();
        if path.is_empty() || path.to_ascii_lowercase().starts_with(r"c:\windows\") {
            continue;
        }
        let name = exe.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        by_path.entry(path.to_ascii_lowercase()).or_insert(ProcessInfo { name, path });
    }
    let mut list: Vec<ProcessInfo> = by_path.into_values().collect();
    list.sort_by_key(|p| p.name.to_ascii_lowercase());
    list
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export)]
pub struct RuleSetCatalog {
    pub geosite: Vec<String>,
    pub geoip: Vec<String>,
    pub acl: Vec<String>,
}

pub fn rule_set_catalog(dir: &std::path::Path) -> RuleSetCatalog {
    let read = |name: &str| -> Vec<String> {
        std::fs::read_to_string(dir.join(format!("{name}_codes.txt")))
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect())
            .unwrap_or_default()
    };
    RuleSetCatalog { geosite: read("geosite"), geoip: read("geoip"), acl: read("acl") }
}

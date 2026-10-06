use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager};

/// Filesystem locations used by the app.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `%APPDATA%\tw.proxydesk.desktop` — profile.json, node cache.
    pub config_dir: PathBuf,
    /// `%ProgramData%\ProxyDesk\run` — sing-box working directory (`cache.db`). Only
    /// administrators can write there: the elevated sing-box must not open files a
    /// non-elevated process could plant or redirect. The config itself never touches the
    /// disk (it goes over stdin).
    pub run_dir: PathBuf,
    /// Bundled `.srs` rule sets (`geosite/`, `geoip/`, `acl/`, `*_codes.txt`).
    pub ruleset_dir: PathBuf,
    /// sing-box sidecar; Tauri places `externalBin` next to the app executable.
    pub sing_box: PathBuf,
    /// This executable; its own connections are routed direct.
    pub self_exe: PathBuf,
}

impl Paths {
    pub fn resolve(app: &AppHandle) -> Result<Self, String> {
        let pr = app.path();
        let config_dir = pr.app_config_dir().map_err(|e| e.to_string())?;
        let ruleset_dir = pr.resource_dir().map_err(|e| e.to_string())?.join("resources").join("rulesets");
        let self_exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_dir = self_exe.parent().ok_or("executable has no parent directory")?.to_path_buf();
        std::fs::create_dir_all(&config_dir).map_err(|e| format!("無法建立 {}: {e}", config_dir.display()))?;

        let program_data = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let private = program_data.join("ProxyDesk");
        secure::ensure_admin_only_dir(&private)?;
        let run_dir = private.join("run");
        secure::ensure_admin_only_dir(&run_dir)?;
        // ≤ v0.3.1 kept config.json and cache.db in the user-writable local app data.
        if let Ok(old) = pr.app_local_data_dir() {
            let _ = std::fs::remove_dir_all(old.join("run"));
        }

        Ok(Self { config_dir, run_dir, ruleset_dir, sing_box: exe_dir.join("sing-box.exe"), self_exe })
    }

    pub fn profile_file(&self) -> PathBuf {
        self.config_dir.join("profile.json")
    }

    pub fn node_cache_file(&self) -> PathBuf {
        self.config_dir.join("mudfish-nodes.json")
    }
}

#[cfg(windows)]
pub mod secure {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    /// Owner Administrators; protected DACL: SYSTEM and Administrators full control
    /// (inherited by everything inside), Users read & execute.
    const SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Whether `dir` is owned by Administrators or SYSTEM (i.e. created elevated).
    pub fn owned_by_admins(dir: &Path) -> bool {
        let path = wide(dir.as_os_str());
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        unsafe {
            let rc = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            let ok = rc == ERROR_SUCCESS
                && !owner.is_null()
                && (IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 || IsWellKnownSid(owner, WinLocalSystemSid) != 0);
            if !sd.is_null() {
                LocalFree(sd as _);
            }
            ok
        }
    }

    /// The parsed `SDDL`; freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        fn new() -> Result<Self, String> {
            let sddl = wide(std::ffi::OsStr::new(SDDL));
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
                return Err(format!("無法建立安全性描述元: {}", std::io::Error::last_os_error()));
            }
            Ok(Self(sd))
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0 as _) };
        }
    }

    fn create(dir: &Path) -> Result<(), String> {
        let sd = Descriptor::new()?;
        let path = wide(dir.as_os_str());
        let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: 0 };
        if unsafe { CreateDirectoryW(path.as_ptr(), &sa) } == 0 {
            return Err(format!("無法建立 {}: {}", dir.display(), std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Whether `dir` carries exactly our protected DACL (not one inherited or edited elsewhere).
    fn has_our_dacl(dir: &Path) -> bool {
        let path = wide(dir.as_os_str());
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        unsafe {
            let rc = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != ERROR_SUCCESS || sd.is_null() {
                return false;
            }
            let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut text, std::ptr::null_mut()) != 0;
            LocalFree(sd as _);
            if !ok || text.is_null() {
                return false;
            }
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let dacl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text as _);
            dacl == SDDL[SDDL.find("D:").unwrap()..]
        }
    }

    /// Makes sure `dir` exists, is a real directory, and only administrators can change it.
    /// Anything else in its place — a link, a directory someone else created first, or one
    /// with other permissions (its contents might have been planted) — is removed and
    /// recreated; losing `cache.db` once is harmless.
    pub fn ensure_admin_only_dir(dir: &Path) -> Result<(), String> {
        if let Ok(m) = std::fs::symlink_metadata(dir) {
            let link = m.file_type().is_symlink();
            if m.is_dir() && !link && owned_by_admins(dir) && has_our_dacl(dir) {
                return Ok(());
            }
            let removed = if link {
                std::fs::remove_dir(dir).or_else(|_| std::fs::remove_file(dir))
            } else if m.is_dir() {
                std::fs::remove_dir_all(dir)
            } else {
                std::fs::remove_file(dir)
            };
            removed.map_err(|e| format!("{} 的權限不符，且無法移除（{e}）。請手動刪除後再開啟 ProxyDesk。", dir.display()))?;
        }
        create(dir)?;
        if owned_by_admins(dir) {
            Ok(())
        } else {
            Err(format!("無法確認 {} 的擁有者", dir.display()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Needs an elevated shell (like the app itself).
        #[test]
        fn creates_admin_owned_dir_and_replaces_links() {
            let base = std::env::temp_dir().join(format!("proxydesk-secure-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            ensure_admin_only_dir(&base).unwrap();
            assert!(owned_by_admins(&base) && has_our_dacl(&base));
            ensure_admin_only_dir(&base).unwrap(); // idempotent
            let acl = |p: &Path| String::from_utf8_lossy(&std::process::Command::new("icacls").arg(p).output().unwrap().stdout).to_string();
            assert!(!acl(&base).contains("(I)"), "protected: nothing inherited from the parent\n{}", acl(&base));

            // An admin-owned directory with other ACEs is recreated, planted contents included.
            let plain = base.join("plain");
            std::fs::create_dir(&plain).unwrap();
            std::fs::write(plain.join("cache.db"), b"planted").unwrap();
            let st = std::process::Command::new("icacls").arg(&plain).args(["/grant", "*S-1-5-32-545:(OI)(CI)F"]).output().unwrap();
            assert!(st.status.success());
            ensure_admin_only_dir(&plain).unwrap();
            let a = acl(&plain);
            assert!(a.contains("BUILTIN\\Users:(OI)(CI)(RX)") && !a.contains("Users:(OI)(CI)(F)"), "{a}");
            assert!(!plain.join("cache.db").exists(), "planted file removed with the directory");

            let target = base.join("target");
            std::fs::create_dir(&target).unwrap();
            let link = base.join("link");
            let st = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(&link).arg(&target).output().unwrap();
            assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
            ensure_admin_only_dir(&link).unwrap();
            assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "junction replaced by a real directory");
            assert!(target.is_dir(), "the junction target is left alone");
            std::fs::remove_dir_all(&base).unwrap();
        }
    }
}

#[cfg(not(windows))]
pub mod secure {
    use super::*;

    pub fn ensure_admin_only_dir(dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("無法建立 {}: {e}", dir.display()))
    }
}

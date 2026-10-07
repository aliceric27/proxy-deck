//! JSON persistence with atomic replace, so a crash mid-write never leaves a truncated profile.

use std::path::{Path, PathBuf};

use proxy_core::Profile;
use serde::{de::DeserializeOwned, Serialize};

/// A file that exists but could not be read or parsed.
#[derive(Debug, PartialEq)]
pub struct LoadFailure {
    /// The parser's or the OS's message.
    pub reason: String,
    /// Where the file went (`<name>.bad`, never over an earlier copy). `None`: moving it failed
    /// too, so it is still where it was.
    pub moved_to: Option<PathBuf>,
}

impl LoadFailure {
    /// What follows for a file the app cannot do without.
    /// - Moved aside: `Ok(notice)`. The defaults take its place and the notice tells the user.
    /// - Still in place, typically because another process holds it for the moment: `Err(message)`.
    ///   Going on with the defaults would let the first save overwrite an original that is most
    ///   likely fine, so the app must not start.
    pub fn verdict(&self, file: &Path) -> Result<String, String> {
        match &self.moved_to {
            Some(copy) => Ok(format!(
                "設定檔 {} 無法讀取（{}），已改用預設設定；原檔保留為 {}。可在「設定」頁開啟資料夾查看。",
                file_name(file),
                self.reason,
                file_name(copy)
            )),
            None => Err(format!(
                "設定檔 {} 無法讀取（{}），也無法移開。\n為避免覆寫原本的設定，ProxyDesk 沒有啟動。\n請關閉可能正在使用這個檔案的程式（例如防毒軟體或文字編輯器），再重新啟動 ProxyDesk。",
                file.display(),
                self.reason
            )),
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Reads JSON from `path`. A missing file is no failure: the defaults come back, nothing moves.
/// A file that exists but cannot be read or parsed is moved aside to the first free `<name>.bad`,
/// `<name>.bad-2`, … (an earlier copy is never overwritten, and the next save cannot clobber the
/// original), and the defaults come back together with the failure.
pub fn load_checked<T: DeserializeOwned + Default>(path: &Path) -> (T, Option<LoadFailure>) {
    let parsed = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<T>(&bytes).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (T::default(), None),
        Err(e) => Err(e.to_string()),
    };
    match parsed {
        Ok(value) => (value, None),
        Err(reason) => {
            log::warn!("{} 無法讀取，改用預設值: {reason}", path.display());
            (T::default(), Some(LoadFailure { moved_to: set_aside(path), reason }))
        }
    }
}

/// Like [`load_checked`] for callers that only need the data (the failure is still logged and
/// the file still set aside).
pub fn load_or_default<T: DeserializeOwned + Default>(path: &Path) -> T {
    load_checked(path).0
}

/// Moves an unreadable file to the first free `.bad` name.
fn set_aside(path: &Path) -> Option<PathBuf> {
    let dest = free_bad_name(path);
    match std::fs::rename(path, &dest) {
        Ok(()) => Some(dest),
        Err(e) => {
            log::warn!("無法把 {} 移到 {}: {e}", path.display(), dest.display());
            None
        }
    }
}

/// `<file>.bad`, or `<file>.bad-2`, `<file>.bad-3`, …: the first name nothing sits on yet.
fn free_bad_name(path: &Path) -> PathBuf {
    let name = file_name(path);
    let candidates = std::iter::once(format!("{name}.bad")).chain((2..).map(|n| format!("{name}.bad-{n}")));
    candidates.map(|c| path.with_file_name(c)).find(|p| std::fs::symlink_metadata(p).is_err()).expect("the candidates never run out")
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, bytes).map_err(|e| format!("寫入 {} 失敗: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("取代 {} 失敗: {e}", path.display()))
}

/// Loads the profile. A file that cannot be read or parsed has two outcomes:
/// - It was moved aside (`profile.json.bad`): the defaults take its place and the notice for the
///   user comes back with them. Nothing is written; the first change the user makes saves them.
/// - It could not even be moved (usually another process holds it for the moment): `Err`, so the
///   app does not start and nothing is written. Starting on the defaults would let the first save
///   overwrite an original that is most likely fine.
///
/// A file of an older schema is upgraded first: saving the migrated profile drops the old fields
/// for good, so the original stays beside it as `profile.v<old>-backup.json`.
pub fn load_profile(path: &Path) -> Result<(Profile, Option<String>), String> {
    let (mut profile, failure): (Profile, _) = load_checked(path);
    let notice = failure.map(|f| f.verdict(path)).transpose()?;
    let schema_version = profile.schema_version;
    if profile.migrate() {
        backup(path, schema_version)?;
        save(path, &profile)?;
    }
    Ok((profile, notice))
}

/// Copies `path` to `<name>.v<schema_version>-backup.json` beside it. An existing backup is
/// never overwritten, and the copy only appears under its final name once it is complete.
fn backup(path: &Path, schema_version: u32) -> Result<(), String> {
    let dest = path.with_extension(format!("v{schema_version}-backup.json"));
    if dest.exists() {
        return Ok(());
    }
    let tmp = dest.with_extension("json.tmp");
    let fail = |e: std::io::Error| format!("備份 {} 失敗: {e}", path.display());
    std::fs::copy(path, &tmp).map_err(fail)?;
    std::fs::rename(&tmp, &dest).map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty scratch directory, unique per test.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("proxydesk-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A v0.4 file: the default node is `direct`, group `a` follows it.
    const V2_FILE: &str = r#"{
  "schema_version": 2,
  "nodes": [],
  "selected": "direct",
  "groups": [
    {"id": "a", "name": "a", "enabled": true, "target": "proxy", "outbound": "proxy", "domain_suffixes": ["a.com"]},
    {"id": "ads", "name": "ads", "enabled": false, "target": "reject", "outbound": "proxy", "rule_sets": ["geosite:category-ads-all"]}
  ],
  "final_target": "proxy"
}"#;

    #[test]
    fn backup_copies_once_and_never_overwrites() {
        let dir = scratch("backup");
        let profile = dir.join("profile.json");
        std::fs::write(&profile, br#"{"schema_version": 2}"#).unwrap();

        backup(&profile, 2).unwrap();
        let backup_file = dir.join("profile.v2-backup.json");
        assert_eq!(std::fs::read(&backup_file).unwrap(), br#"{"schema_version": 2}"#);
        assert!(!dir.join("profile.v2-backup.json.tmp").exists(), "no temporary copy is left behind");

        // the file is rewritten by the migration; a second backup must keep the first copy
        std::fs::write(&profile, br#"{"schema_version": 3}"#).unwrap();
        backup(&profile, 2).unwrap();
        assert_eq!(std::fs::read(&backup_file).unwrap(), br#"{"schema_version": 2}"#);

        // another version gets its own file
        backup(&profile, 1).unwrap();
        assert_eq!(std::fs::read(dir.join("profile.v1-backup.json")).unwrap(), br#"{"schema_version": 3}"#);

        assert!(backup(&dir.join("missing.json"), 2).is_err(), "nothing to copy is an error, not a silent skip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_profile_migrates_a_v2_file_after_backing_it_up() {
        let dir = scratch("v2");
        let file = dir.join("profile.json");
        std::fs::write(&file, V2_FILE).unwrap();

        let (p, notice) = load_profile(&file).unwrap();
        assert_eq!(notice, None, "a migration is not a problem");
        assert_eq!(p.schema_version, 3);
        assert_eq!(p.groups[0].outbound, "direct", "it followed the direct default node");
        assert_eq!(p.groups[1].outbound, "reject");
        assert_eq!(p.final_outbound, "direct");
        assert_eq!(std::fs::read_to_string(dir.join("profile.v2-backup.json")).unwrap(), V2_FILE, "the original, byte for byte");

        // the file on disk is v3 now, and loading it again changes nothing
        let saved = std::fs::read_to_string(&file).unwrap();
        let json: serde_json::Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(json["schema_version"], 3);
        assert!(json.get("selected").is_none() && json.get("final_target").is_none());
        assert!(json["groups"][0].get("target").is_none());
        assert_eq!(load_profile(&file).unwrap().0, p);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), saved);
        assert!(!dir.join("profile.v3-backup.json").exists(), "a v3 file needs no backup");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_profile_backs_up_a_v1_file_under_its_own_version() {
        let dir = scratch("v1");
        let file = dir.join("profile.json");
        let v1 = r#"{"schema_version": 1, "nodes": [], "rules": [
          {"id": "a", "name": "a", "enabled": true, "target": "reject", "kind": "domain", "suffixes": ["a.com"], "keywords": []}]}"#;
        std::fs::write(&file, v1).unwrap();

        let (p, _) = load_profile(&file).unwrap();
        assert_eq!((p.schema_version, p.groups.len(), p.groups[0].outbound.as_str()), (3, 1, "reject"));
        assert_eq!(std::fs::read_to_string(dir.join("profile.v1-backup.json")).unwrap(), v1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_profile_is_no_failure() {
        let dir = scratch("none");
        let (p, notice) = load_profile(&dir.join("profile.json")).unwrap();
        assert_eq!(p, Profile::default());
        assert_eq!(notice, None, "a first run is not a problem");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "nothing is written or moved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_profile_gives_the_defaults_a_notice_and_a_bad_copy() {
        let dir = scratch("corrupt");
        let file = dir.join("profile.json");
        std::fs::write(&file, "{ this is not json").unwrap();

        let (p, notice) = load_profile(&file).unwrap();
        assert_eq!(p, Profile::default());
        let notice = notice.expect("the user must hear about it");
        assert!(notice.contains("設定檔 profile.json 無法讀取"), "{notice}");
        assert!(notice.contains("line 1 column"), "it says what failed: {notice}");
        assert!(notice.contains("原檔保留為 profile.json.bad。"), "{notice}");
        assert!(notice.contains("「設定」頁"), "{notice}");
        assert_eq!(std::fs::read_to_string(dir.join("profile.json.bad")).unwrap(), "{ this is not json");
        assert!(!file.exists(), "nothing is written until the user changes something");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_files_never_overwrite_an_earlier_bad_copy() {
        let dir = scratch("bad-names");
        let file = dir.join("profile.json");
        for (n, (body, kept)) in [("first", "profile.json.bad"), ("second", "profile.json.bad-2"), ("third", "profile.json.bad-3")].into_iter().enumerate() {
            std::fs::write(&file, body).unwrap();
            let (p, notice) = load_profile(&file).unwrap();
            assert_eq!(p, Profile::default());
            assert!(notice.unwrap().contains(&format!("原檔保留為 {kept}。")), "load {n}");
        }
        assert_eq!(std::fs::read_to_string(dir.join("profile.json.bad")).unwrap(), "first");
        assert_eq!(std::fs::read_to_string(dir.join("profile.json.bad-2")).unwrap(), "second");
        assert_eq!(std::fs::read_to_string(dir.join("profile.json.bad-3")).unwrap(), "third");

        // the other callers of `load_or_default` get the same protection
        let cache = dir.join("mudfish-nodes.json");
        for (body, kept) in [("old", "mudfish-nodes.json.bad"), ("older", "mudfish-nodes.json.bad-2")] {
            std::fs::write(&cache, body).unwrap();
            assert_eq!(load_or_default::<Vec<u32>>(&cache), Vec::<u32>::new());
            assert_eq!(std::fs::read_to_string(dir.join(kept)).unwrap(), body);
        }
        assert_eq!(std::fs::read_to_string(dir.join("mudfish-nodes.json.bad")).unwrap(), "old", "the first copy stayed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_cannot_be_read_is_set_aside_like_a_corrupt_one() {
        let dir = scratch("unreadable");
        let file = dir.join("profile.json");
        std::fs::create_dir(&file).unwrap(); // reading a directory fails with an OS error, not a parse error

        let (p, notice) = load_profile(&file).unwrap();
        assert_eq!(p, Profile::default());
        assert!(notice.expect("reported").contains("原檔保留為 profile.json.bad。"));
        assert!(dir.join("profile.json.bad").is_dir() && !file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The decision itself: a moved file continues on the defaults with a notice, a file that
    /// is still in place stops the start with a message that names it and says what to do.
    #[test]
    fn a_moved_file_gives_a_notice_and_a_stuck_one_refuses_to_start() {
        let file = Path::new(r"C:\data\profile.json");
        let moved = LoadFailure { reason: "expected value at line 1 column 1".into(), moved_to: Some(PathBuf::from(r"C:\data\profile.json.bad-2")) };
        assert_eq!(
            moved.verdict(file),
            Ok("設定檔 profile.json 無法讀取（expected value at line 1 column 1），已改用預設設定；原檔保留為 profile.json.bad-2。可在「設定」頁開啟資料夾查看。".to_string())
        );

        let stuck = LoadFailure { reason: "程序無法存取檔案，因為檔案正由另一個程序使用".into(), moved_to: None };
        let message = stuck.verdict(file).unwrap_err();
        assert!(message.contains(r"C:\data\profile.json"), "it names the file: {message}");
        assert!(message.contains("程序無法存取檔案"), "it says what failed: {message}");
        assert!(message.contains("沒有啟動") && message.contains("覆寫"), "it says why the app did not start: {message}");
        assert!(message.contains("關閉") && message.contains("重新啟動"), "it says what to do: {message}");
    }

    /// Holds `file` open the way a virus scanner or another program might. `share` is the Windows
    /// share mode: 0 lets nobody else open the file, 1 (`FILE_SHARE_READ`) lets others read it
    /// but not rename or delete it.
    #[cfg(windows)]
    fn hold(file: &Path, share: u32) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(share).open(file).unwrap()
    }

    #[cfg(windows)]
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    /// A good profile that another process holds locked: it can neither be read nor moved. The
    /// app must not start on the defaults, or the first save would overwrite it.
    #[cfg(windows)]
    #[test]
    fn a_locked_profile_stops_the_start_and_is_left_alone() {
        let dir = scratch("locked");
        let file = dir.join("profile.json");
        std::fs::write(&file, V2_FILE).unwrap();
        let held = hold(&file, 0);

        let message = load_profile(&file).unwrap_err();
        assert!(message.contains("profile.json") && message.contains("沒有啟動") && message.contains("重新啟動"), "{message}");
        // underneath: a failure whose file could not be moved
        let (_, failure) = load_checked::<Profile>(&file);
        assert_eq!(failure.expect("the lock is a failure").moved_to, None);
        // the node cache and other `load_or_default` callers still just carry on with the defaults
        assert_eq!(load_or_default::<Vec<u32>>(&file), Vec::<u32>::new());

        drop(held);
        assert_eq!(names(&dir), ["profile.json"], "nothing was moved, written or backed up");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), V2_FILE, "the original, byte for byte");

        // once whatever held it lets go, the next start works and migrates it as usual
        let (p, notice) = load_profile(&file).unwrap();
        assert_eq!((p.schema_version, notice), (3, None));
        assert_eq!(std::fs::read_to_string(dir.join("profile.v2-backup.json")).unwrap(), V2_FILE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt profile that can be read but not moved (someone shares it for reading only):
    /// the parse error alone must not send the app on with the defaults.
    #[cfg(windows)]
    #[test]
    fn a_corrupt_profile_that_cannot_be_moved_stops_the_start_too() {
        let dir = scratch("stuck-corrupt");
        let file = dir.join("profile.json");
        std::fs::write(&file, "{ this is not json").unwrap();
        let held = hold(&file, 1);

        let message = load_profile(&file).unwrap_err();
        assert!(message.contains("line 1 column") && message.contains("沒有啟動"), "it says what failed: {message}");
        drop(held);
        assert_eq!(names(&dir), ["profile.json"]);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{ this is not json");

        // freed, it is an ordinary corrupt file again: moved aside, defaults, a notice
        let (p, notice) = load_profile(&file).unwrap();
        assert_eq!(p, Profile::default());
        assert!(notice.unwrap().contains("原檔保留為 profile.json.bad。"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

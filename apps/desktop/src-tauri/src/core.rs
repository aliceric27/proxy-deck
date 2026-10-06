//! sing-box sidecar lifecycle: generate config → `check` → spawn → health check → supervise.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use proxy_core::singbox::{self, GenerateOptions};
use proxy_core::Profile;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::{oneshot, Mutex};

use crate::clash::ClashClient;
use crate::credentials::Credentials;
use crate::paths::Paths;

const LOG_CAPACITY: usize = 3000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CoreStatus {
    Stopped,
    Starting,
    Running { started_at: u64 },
    Error { message: String },
}

struct Running {
    clash: ClashClient,
    /// Dropping or sending stops the supervisor, which kills the child.
    kill: oneshot::Sender<()>,
    exited: oneshot::Receiver<()>,
}

pub struct CoreManager {
    app: AppHandle,
    paths: Paths,
    status: Mutex<CoreStatus>,
    running: Mutex<Option<Running>>,
    logs: Arc<std::sync::Mutex<VecDeque<String>>>,
    /// Serializes start/stop so concurrent clicks cannot spawn two cores.
    op: Mutex<()>,
}

impl CoreManager {
    pub fn new(app: AppHandle, paths: Paths) -> Self {
        Self {
            app,
            paths,
            status: Mutex::new(CoreStatus::Stopped),
            running: Mutex::new(None),
            logs: Arc::new(std::sync::Mutex::new(VecDeque::with_capacity(LOG_CAPACITY))),
            op: Mutex::new(()),
        }
    }

    pub async fn status(&self) -> CoreStatus {
        self.status.lock().await.clone()
    }

    pub fn logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    pub async fn clash(&self) -> Option<ClashClient> {
        self.running.lock().await.as_ref().map(|r| r.clash.clone())
    }

    async fn set_status(&self, s: CoreStatus) {
        *self.status.lock().await = s.clone();
        let _ = self.app.emit("core-status", &s);
    }

    pub async fn start(&self, profile: &Profile, creds: Option<&Credentials>) -> Result<(), String> {
        let _guard = self.op.lock().await;
        self.stop_locked().await;
        self.set_status(CoreStatus::Starting).await;
        match self.start_locked(profile, creds).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stop_locked().await;
                self.remove_config();
                self.set_status(CoreStatus::Error { message: e.clone() }).await;
                Err(e)
            }
        }
    }

    async fn start_locked(&self, profile: &Profile, creds: Option<&Credentials>) -> Result<(), String> {
        if !self.paths.sing_box.is_file() {
            return Err(format!("找不到 sing-box：{}", self.paths.sing_box.display()));
        }

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map_err(|e| format!("無法取得可用連接埠: {e}"))?
            .port();
        let listen = format!("127.0.0.1:{port}");
        let secret = uuid::Uuid::new_v4().simple().to_string();

        // WARP private keys live in the credential store; read them only for this config write.
        let wireguard_keys: std::collections::BTreeMap<String, String> = profile
            .nodes
            .iter()
            .filter(|n| n.is_wireguard())
            .filter_map(|n| Some((n.tag.clone(), crate::credentials::load_warp(&n.tag)?.private_key)))
            .collect();
        let config = singbox::generate(
            profile,
            &GenerateOptions {
                username: creds.map(|c| c.username.as_str()).unwrap_or_default(),
                password: creds.map(|c| c.password.as_str()).unwrap_or_default(),
                wireguard_keys: &wireguard_keys,
                ruleset_dir: &self.paths.ruleset_dir,
                clash_listen: &listen,
                clash_secret: &secret,
                log_level: "info",
            },
        )
        .map_err(|e| e.to_string())?;
        let config_path = self.paths.core_config_file();
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap())
            .map_err(|e| format!("寫入設定檔失敗: {e}"))?;

        let check = Command::new(&self.paths.sing_box)
            .args(["check", "-c"])
            .arg(&config_path)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .await
            .map_err(|e| format!("無法執行 sing-box: {e}"))?;
        if !check.status.success() {
            return Err(format!("設定檢查失敗：{}", strip_ansi(&String::from_utf8_lossy(&check.stderr)).trim()));
        }

        self.push_log(format!("---- 啟動 sing-box（Clash API {listen}）----"));
        let mut child = Command::new(&self.paths.sing_box)
            .args(["run", "-c"])
            .arg(&config_path)
            .arg("-D")
            .arg(&self.paths.run_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("無法啟動 sing-box: {e}"))?;

        #[cfg(windows)]
        if let Some(handle) = child.raw_handle() {
            job::assign(handle);
        }
        if let Some(out) = child.stdout.take() {
            self.pump_logs(out);
        }
        if let Some(err) = child.stderr.take() {
            self.pump_logs(err);
        }

        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        let (exited_tx, exited_rx) = oneshot::channel::<()>();
        let (early_tx, mut early_rx) = oneshot::channel::<String>();
        let app = self.app.clone();
        tokio::spawn(async move {
            tokio::select! {
                status = child.wait() => {
                    let msg = match status {
                        Ok(s) => format!("sing-box 意外結束（{s}）"),
                        Err(e) => format!("sing-box 意外結束: {e}"),
                    };
                    // Before the health check completes, report through `early_tx`; afterwards, as a status event.
                    if let Err(msg) = early_tx.send(msg) {
                        crate::on_core_crashed(&app, msg).await;
                    }
                }
                _ = kill_rx => {
                    let _ = child.kill().await;
                }
            }
            let _ = exited_tx.send(());
        });

        let clash = ClashClient::new(&listen, &secret);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(msg) = early_rx.try_recv() {
                let tail: Vec<String> = self.logs().into_iter().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect();
                return Err(format!("{msg}\n{}", tail.join("\n")));
            }
            if clash.version().await.is_ok() {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let _ = kill_tx.send(());
                return Err("sing-box 啟動逾時（10 秒內 Clash API 沒有回應）".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // From here on, an exit is a crash reported via `on_core_crashed`.
        drop(early_rx);

        // With cache_file enabled, sing-box restores each selector's last live choice and
        // ignores `default`, so choices made while disconnected would be lost. The profile
        // is the source of truth: re-apply it. (cache_file stays for the FakeIP store.)
        let _ = clash.select(proxy_core::TAG_PROXY, profile.effective_selected()).await;
        for g in profile.groups.iter().filter(|g| g.enabled && g.target == proxy_core::Target::Proxy) {
            let _ = clash.select(&g.selector_tag(), profile.effective_group_outbound(g)).await;
        }

        *self.running.lock().await = Some(Running { clash, kill: kill_tx, exited: exited_rx });
        let started_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        self.set_status(CoreStatus::Running { started_at }).await;
        Ok(())
    }

    pub async fn stop(&self) {
        let _guard = self.op.lock().await;
        self.stop_locked().await;
        self.set_status(CoreStatus::Stopped).await;
    }

    async fn stop_locked(&self) {
        let Some(r) = self.running.lock().await.take() else { return };
        let _ = r.kill.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), r.exited).await;
        self.remove_config();
        self.push_log("---- sing-box 已停止 ----".into());
        // FakeIP answers cached by Windows would point at the now-closed TUN.
        let _ = Command::new("ipconfig").arg("/flushdns").creation_flags(CREATE_NO_WINDOW).output().await;
    }

    /// Called by the supervisor after an unexpected exit post-startup.
    pub async fn mark_crashed(&self, message: String) {
        self.running.lock().await.take();
        self.remove_config();
        self.push_log(format!("---- {message} ----"));
        self.set_status(CoreStatus::Error { message }).await;
    }

    /// sing-box reads its config only at startup; deleting it afterwards keeps the
    /// Mudfish credentials off disk while disconnected.
    fn remove_config(&self) {
        let _ = std::fs::remove_file(self.paths.core_config_file());
    }

    fn push_log(&self, line: String) {
        push_line(&self.logs, &self.app, line);
    }

    fn pump_logs<R: AsyncRead + Unpin + Send + 'static>(&self, reader: R) {
        let logs = self.logs.clone();
        let app = self.app.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                push_line(&logs, &app, strip_ansi(&line));
            }
        });
    }
}

fn push_line(logs: &std::sync::Mutex<VecDeque<String>>, app: &AppHandle, line: String) {
    {
        let mut l = logs.lock().unwrap();
        if l.len() == LOG_CAPACITY {
            l.pop_front();
        }
        l.push_back(line.clone());
    }
    let _ = app.emit("core-log", line);
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Ties sing-box to this process: a job object with KILL_ON_JOB_CLOSE ends the child when
/// ProxyDesk exits for any reason (including a crash or Task Manager), so the TUN never
/// outlives the app that controls it.
#[cfg(windows)]
mod job {
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    struct Job(HANDLE);
    // The handle is only passed to thread-safe Win32 calls and lives for the whole process.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    static JOB: OnceLock<Option<Job>> = OnceLock::new();

    fn job() -> Option<HANDLE> {
        JOB.get_or_init(|| unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                log::warn!("CreateJobObjectW failed");
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            (ok != 0).then_some(Job(h))
        })
        .as_ref()
        .map(|j| j.0)
    }

    pub fn assign(process: std::os::windows::io::RawHandle) {
        if let Some(j) = job() {
            if unsafe { AssignProcessToJobObject(j, process as HANDLE) } == 0 {
                log::warn!("AssignProcessToJobObject failed; sing-box may outlive a crash");
            }
        }
    }
}

/// Kills sing-box processes left over from a previous crash of this app (same executable path).
pub fn kill_orphans(sing_box: &std::path::Path) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::Always));
    for p in sys.processes().values() {
        if p.exe().is_some_and(|e| e.eq_ignore_ascii_case(sing_box)) {
            log::warn!("結束殘留的 sing-box（pid {}）", p.pid());
            p.kill();
        }
    }
}

trait PathEqIgnoreCase {
    fn eq_ignore_ascii_case(&self, other: &std::path::Path) -> bool;
}

impl PathEqIgnoreCase for std::path::Path {
    fn eq_ignore_ascii_case(&self, other: &std::path::Path) -> bool {
        self.as_os_str().to_string_lossy().eq_ignore_ascii_case(&other.as_os_str().to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn strips_ansi_colors() {
        assert_eq!(super::strip_ansi("+0000 \u{1b}[36mINFO\u{1b}[0m started"), "+0000 INFO started");
    }
}

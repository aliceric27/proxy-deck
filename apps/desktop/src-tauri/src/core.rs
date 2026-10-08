//! sing-box sidecar lifecycle: build config → `check` → spawn → health check → apply live
//! selections → supervise (bounded auto-restart on crashes).
//!
//! `CoreManager` knows nothing about Tauri: process work goes through [`Launcher`] and
//! notifications through [`CoreEvents`], so the state machine runs against fakes in tests and
//! can later sit behind a privileged service.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proxy_core::custom::ProxyAuth;
use proxy_core::singbox::{self, GenerateOptions};
use proxy_core::{Mode, Profile, Selections};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, Mutex};
use ts_rs::TS;

use crate::clash::ClashClient;
use crate::credentials::Credentials;
use crate::paths::Paths;

const LOG_CAPACITY: usize = 3000;
const LOG_BATCH: Duration = Duration::from_millis(250);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(tag = "state", rename_all = "snake_case")]
#[ts(export)]
pub enum CoreStatus {
    Stopped,
    Starting,
    Running {
        #[ts(type = "number")]
        started_at: u64,
    },
    /// The core crashed after a successful start; restart `attempt` is scheduled.
    Reconnecting { attempt: u32, message: String },
    Error { message: String },
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A spawned core process.
pub struct Child {
    /// Sending (or dropping) kills the process.
    pub kill: oneshot::Sender<()>,
    /// Resolves with a description once the process has exited, for whatever reason.
    pub exit: oneshot::Receiver<String>,
}

/// A change the running core applies through the Clash API.
#[derive(Debug, Clone, PartialEq)]
pub enum LiveOp {
    Select { selector: String, outbound: String },
    Mode(Mode),
    /// Mode switches have no per-connection interrupt, unlike selectors.
    CloseAll,
}

/// Process-level operations behind the state machine.
pub trait Launcher: Send + Sync + 'static {
    /// Validates a config without running it.
    fn check<'a>(&'a self, config: &'a [u8]) -> BoxFut<'a, Result<(), String>>;
    /// Starts the core; its output lines go to `log`.
    fn spawn<'a>(&'a self, config: &'a [u8], log: mpsc::UnboundedSender<String>) -> BoxFut<'a, Result<Child, String>>;
    fn healthy<'a>(&'a self, clash: &'a ClashClient) -> BoxFut<'a, bool>;
    fn apply<'a>(&'a self, clash: &'a ClashClient, ops: &'a [LiveOp]) -> BoxFut<'a, Result<(), String>>;
    /// Drops the connections a live selector switch replaced — those still on a selector's previous
    /// member, given as `(selector, old_member)` pairs — so the switch bites existing connections
    /// too, without touching ones re-dialed onto the new member. Best-effort.
    fn interrupt<'a>(&'a self, clash: &'a ClashClient, switches: &'a [(String, String)]) -> BoxFut<'a, ()>;
    /// After the core is gone (stopped or crashed): undo system side effects.
    fn cleanup(&self) -> BoxFut<'_, ()>;
    /// Kills cores left over from a previous crash of the app. Blocking.
    fn sweep_orphans(&self);
}

pub trait CoreEvents: Send + Sync + 'static {
    fn status(&self, status: &CoreStatus);
    fn logs(&self, batch: &LogBatch);
}

/// Consecutive core output lines; `first` is the sequence number of `lines[0]`, so a reader
/// can join a snapshot (`CoreManager::logs`) with later batches without gaps or duplicates.
#[derive(Debug, Clone, Default, Serialize, TS)]
#[ts(export)]
pub struct LogBatch {
    #[ts(type = "number")]
    pub first: u64,
    pub lines: Vec<String>,
}

/// Everything needed to (re)start the core with one profile.
pub struct StartPlan {
    pub config: Vec<u8>,
    pub clash: ClashClient,
    /// `restart_fingerprint` of the profile the config came from.
    pub fingerprint: String,
    /// Selector tag → member tags in this config. Live switches to anything else (a group or
    /// node added after the start) wait for the next start instead of failing.
    pub selectors: BTreeMap<String, BTreeSet<String>>,
}

/// Generates the config for `profile`. Secrets are read here and live only in the returned
/// bytes, which go to sing-box over stdin and never touch the disk.
pub fn build_plan(profile: &Profile, creds: Option<&Credentials>, paths: &Paths) -> Result<StartPlan, String> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(|e| format!("無法取得可用連接埠: {e}"))?
        .port();
    let listen = format!("127.0.0.1:{port}");
    let secret = uuid::Uuid::new_v4().simple().to_string();
    let cache_id = uuid::Uuid::new_v4().simple().to_string();
    let wireguard_keys: std::collections::BTreeMap<String, String> = profile
        .nodes
        .iter()
        .filter(|n| n.is_wireguard())
        .filter_map(|n| Some((n.tag.clone(), crate::credentials::load_warp(&n.tag)?.private_key)))
        .collect();
    let proxy_auth: std::collections::BTreeMap<String, ProxyAuth> = profile
        .nodes
        .iter()
        .filter(|n| n.is_custom())
        .filter_map(|n| Some((n.tag.clone(), crate::credentials::load_proxy_auth(&n.tag)?)))
        .collect();
    let self_exe = paths.self_exe.to_string_lossy();
    let config = singbox::generate(
        profile,
        &GenerateOptions {
            username: creds.map(|c| c.username.as_str()).unwrap_or_default(),
            password: creds.map(|c| c.password.as_str()).unwrap_or_default(),
            wireguard_keys: &wireguard_keys,
            proxy_auth: &proxy_auth,
            ruleset_dir: &paths.ruleset_dir,
            clash_listen: &listen,
            clash_secret: &secret,
            cache_id: &cache_id,
            self_exe: Some(&self_exe),
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(StartPlan {
        config: serde_json::to_vec(&config).map_err(|e| e.to_string())?,
        clash: ClashClient::new(&listen, &secret),
        fingerprint: singbox::restart_fingerprint(profile, &paths.ruleset_dir)?,
        selectors: singbox::selector_members(&config),
    })
}

struct Run {
    clash: ClashClient,
    kill: Option<oneshot::Sender<()>>,
    done: oneshot::Receiver<()>,
    started: Instant,
}

#[derive(Default)]
struct Inner {
    status: Option<CoreStatus>,
    /// Bumped by every start, restart and stop; exits of older runs are then ignored.
    generation: u64,
    run: Option<Run>,
    /// Exit of a process that had not finished starting: (generation, message).
    early_exit: Option<(u64, String)>,
    /// The plan of the current session, kept for auto-restarts.
    plan: Option<Arc<StartPlan>>,
    /// Selections the profile wants; applied live and after every (re)start.
    desired: Selections,
    /// Selections the running core is known to have.
    live: Option<Selections>,
    /// A live apply failed: the core may not match the profile until it restarts.
    live_failed: bool,
    /// Consecutive crashes without a stable run in between.
    crashes: u32,
}

pub struct CoreManager {
    launcher: Arc<dyn Launcher>,
    events: Arc<dyn CoreEvents>,
    inner: Mutex<Inner>,
    /// Serializes start, stop and restart.
    op: Mutex<()>,
    /// Serializes Clash API selection changes against each other and against startup.
    live: Mutex<()>,
    /// Recent core output and the sequence number of the line after the last one.
    logs: std::sync::Mutex<(VecDeque<String>, u64)>,
    log_tx: mpsc::UnboundedSender<String>,
    log_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<String>>>,
    sweep: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Delay before each automatic restart; its length is the restart budget.
    restart_delays: Vec<Duration>,
    /// A run lasting this long resets the crash budget.
    stable_after: Duration,
    health_timeout: Duration,
}

impl CoreManager {
    pub fn new(launcher: Arc<dyn Launcher>, events: Arc<dyn CoreEvents>) -> Arc<Self> {
        Self::with_policy(
            launcher,
            events,
            vec![Duration::from_secs(2), Duration::from_secs(5), Duration::from_secs(10)],
            Duration::from_secs(60),
        )
    }

    fn with_policy(launcher: Arc<dyn Launcher>, events: Arc<dyn CoreEvents>, restart_delays: Vec<Duration>, stable_after: Duration) -> Arc<Self> {
        let (log_tx, log_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            launcher,
            events,
            inner: Mutex::new(Inner { status: Some(CoreStatus::Stopped), ..Inner::default() }),
            op: Mutex::new(()),
            live: Mutex::new(()),
            logs: std::sync::Mutex::new((VecDeque::with_capacity(LOG_CAPACITY), 0)),
            log_tx,
            log_rx: std::sync::Mutex::new(Some(log_rx)),
            sweep: Mutex::new(None),
            restart_delays,
            stable_after,
            health_timeout: HEALTH_TIMEOUT,
        })
    }

    /// Starts the orphan sweep in the background; the first start waits for it.
    pub async fn begin_orphan_sweep(&self) {
        let launcher = self.launcher.clone();
        *self.sweep.lock().await = Some(tokio::task::spawn_blocking(move || launcher.sweep_orphans()));
    }

    /// Records core output into the ring buffer as it arrives and forwards it to `CoreEvents`
    /// in batches (one event per `LOG_BATCH`). Spawn once on the async runtime.
    pub fn log_task(self: &Arc<Self>) -> impl Future<Output = ()> + Send + 'static {
        let rx = self.log_rx.lock().unwrap().take();
        let me = Arc::downgrade(self);
        async move {
            let Some(mut rx) = rx else { return };
            while let Some(line) = rx.recv().await {
                let Some(me) = me.upgrade() else { return };
                let mut batch = LogBatch { first: me.record(&line), lines: vec![line] };
                let deadline = tokio::time::Instant::now() + LOG_BATCH;
                loop {
                    tokio::select! {
                        next = rx.recv() => match next {
                            Some(line) => {
                                me.record(&line);
                                batch.lines.push(line);
                            }
                            None => break,
                        },
                        _ = tokio::time::sleep_until(deadline) => break,
                    }
                }
                me.events.logs(&batch);
            }
        }
    }

    /// Appends one line to the ring buffer and returns its sequence number.
    fn record(&self, line: &str) -> u64 {
        let mut guard = self.logs.lock().unwrap();
        let (ring, next) = &mut *guard;
        if ring.len() == LOG_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(line.to_string());
        *next += 1;
        *next - 1
    }

    pub async fn status(&self) -> CoreStatus {
        self.inner.lock().await.status.clone().unwrap_or(CoreStatus::Stopped)
    }

    pub fn logs(&self) -> LogBatch {
        let guard = self.logs.lock().unwrap();
        let (ring, next) = &*guard;
        LogBatch { first: next - ring.len() as u64, lines: ring.iter().cloned().collect() }
    }

    pub async fn clash(&self) -> Option<ClashClient> {
        self.inner.lock().await.run.as_ref().map(|r| r.clash.clone())
    }

    /// Whether the running (or starting) core differs from a profile with `fingerprint` in
    /// something that only a restart applies, or missed a live change. `None` = the profile
    /// cannot be turned into a config at all.
    pub async fn is_stale(&self, fingerprint: Option<&str>) -> bool {
        let inner = self.inner.lock().await;
        match &inner.plan {
            Some(plan) => fingerprint != Some(plan.fingerprint.as_str()) || inner.live_failed,
            None => false,
        }
    }

    fn push_log(&self, line: String) {
        let _ = self.log_tx.send(line);
    }

    fn set_status(&self, inner: &mut Inner, s: CoreStatus) {
        self.events.status(&s);
        inner.status = Some(s);
    }

    /// Starts (or restarts) the core with `plan`, then applies `desired`.
    pub async fn start(self: &Arc<Self>, plan: StartPlan, desired: Selections) -> Result<(), String> {
        let _op = self.op.lock().await;
        if let Some(sweep) = self.sweep.lock().await.take() {
            let _ = sweep.await;
        }
        // Validate first: a config sing-box rejects must not cost the user a working connection.
        if let Err(e) = self.launcher.check(&plan.config).await {
            let e = format!("設定檢查失敗：{e}");
            self.fail(e.clone()).await;
            return Err(e);
        }
        self.stop_locked().await;
        let plan = Arc::new(plan);
        let generation = {
            let mut inner = self.inner.lock().await;
            inner.generation += 1;
            inner.plan = Some(plan.clone());
            inner.desired = desired;
            inner.crashes = 0;
            self.set_status(&mut inner, CoreStatus::Starting);
            inner.generation
        };
        match self.launch(&plan, generation).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.stop_locked().await;
                let mut inner = self.inner.lock().await;
                self.set_status(&mut inner, CoreStatus::Error { message: e.clone() });
                Err(e)
            }
        }
    }

    /// spawn → health → apply selections → Running. Caller holds `op`; `plan` is checked.
    async fn launch(self: &Arc<Self>, plan: &StartPlan, generation: u64) -> Result<(), String> {
        self.push_log("---- 啟動 sing-box ----".into());
        let child = self.launcher.spawn(&plan.config, self.log_tx.clone()).await?;
        let (done_tx, done_rx) = oneshot::channel();
        let me = self.clone();
        tokio::spawn(async move {
            let msg = child.exit.await.unwrap_or_else(|_| "sing-box 已結束".to_string());
            let _ = done_tx.send(());
            me.on_exit(generation, msg).await;
        });
        let mut kill = Some(child.kill);

        let deadline = Instant::now() + self.health_timeout;
        let failure = loop {
            if let Some((_, msg)) = self.inner.lock().await.early_exit.take_if(|(g, _)| *g == generation) {
                // The last lines (often the FATAL reason) may still be in the pipe.
                tokio::time::sleep(LOG_BATCH).await;
                let lines = self.logs().lines;
                let tail = &lines[lines.len().saturating_sub(8)..];
                break Some(format!("{msg}\n{}", tail.join("\n")));
            }
            if self.launcher.healthy(&plan.clash).await {
                break None;
            }
            if Instant::now() > deadline {
                break Some("sing-box 啟動逾時（10 秒內 Clash API 沒有回應）".to_string());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        if let Some(e) = failure {
            if let Some(k) = kill.take() {
                let _ = k.send(());
            }
            let _ = tokio::time::timeout(Duration::from_secs(5), done_rx).await;
            // The TUN may have been up for a moment.
            self.launcher.cleanup().await;
            return Err(e);
        }

        let _live = self.live.lock().await;
        let desired = {
            let mut inner = self.inner.lock().await;
            // The process may have died between the last health probe and here.
            if let Some((_, msg)) = inner.early_exit.take_if(|(g, _)| *g == generation) {
                return Err(msg);
            }
            inner.run = Some(Run { clash: plan.clash.clone(), kill: kill.take(), done: done_rx, started: Instant::now() });
            inner.desired.clone()
        };
        // The fresh cache_id already starts every selector from the profile; applying the
        // full set again covers auto-restarts and changes made while starting.
        let ops = applicable(plan, diff(None, &desired));
        let applied = self.launcher.apply(&plan.clash, &ops).await;
        let mut inner = self.inner.lock().await;
        if inner.generation != generation || inner.run.is_none() {
            // Stopped meanwhile, or the process died while we applied (`on_exit` took the run
            // and owns the crash handling — do not paint over its status).
            return Ok(());
        }
        match applied {
            Ok(()) => {
                inner.live = Some(applied_part(plan, &desired));
                inner.live_failed = false;
            }
            Err(e) => {
                self.push_log(format!("---- 套用節點選擇失敗：{e} ----"));
                inner.live_failed = true;
            }
        }
        let started_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        self.set_status(&mut inner, CoreStatus::Running { started_at });
        Ok(())
    }

    /// Records the profile's live choices and applies the changes to a running core. A switched
    /// selector also loses its existing connections, so they re-dial through the new choice.
    pub async fn set_selections(&self, desired: Selections) -> Result<(), String> {
        let _live = self.live.lock().await;
        let (clash, ops, switched) = {
            let mut inner = self.inner.lock().await;
            inner.desired = desired.clone();
            match (&inner.run, &inner.status, &inner.plan) {
                (Some(run), Some(CoreStatus::Running { .. }), Some(plan)) => {
                    let ops = applicable(plan, diff(inner.live.as_ref(), &desired));
                    // The previous member of each selector we are actually switching, so the backstop
                    // drops only the connections the switch replaced. Known only when `live` is: after
                    // a failed apply `live` is None and `diff` re-sends every selector unchanged —
                    // those are no-ops in the core, so there is nothing to interrupt.
                    let switched: Vec<(String, String)> = match &inner.live {
                        Some(live) => ops
                            .iter()
                            .filter_map(|o| match o {
                                LiveOp::Select { selector, .. } => live.selectors.get(selector).map(|old| (selector.clone(), old.clone())),
                                _ => None,
                            })
                            .collect(),
                        None => Vec::new(),
                    };
                    (run.clash.clone(), ops, switched)
                }
                _ => return Ok(()), // applied after the next (re)start
            }
        };
        let result = if ops.is_empty() { Ok(()) } else { self.launcher.apply(&clash, &ops).await };
        // After a successful switch, drop the connections still on each selector's old member so the
        // change bites existing connections at once. A mode change closed everything via CloseAll.
        if result.is_ok() && !switched.is_empty() && !ops.iter().any(|o| matches!(o, LiveOp::CloseAll)) {
            self.launcher.interrupt(&clash, &switched).await;
        }
        let mut inner = self.inner.lock().await;
        match &result {
            Ok(()) => {
                inner.live = inner.plan.as_ref().map(|plan| applied_part(plan, &desired));
                inner.live_failed = false;
            }
            Err(e) => {
                inner.live = None; // unknown now: the next change resends everything
                inner.live_failed = true;
                self.push_log(format!("---- 套用節點選擇失敗：{e} ----"));
            }
        }
        result
    }

    /// Reports a start that failed before reaching the core (no credentials, invalid
    /// profile, rejected config). A running core keeps running; only an idle one shows it.
    pub async fn fail(&self, message: String) {
        let mut inner = self.inner.lock().await;
        if matches!(inner.status, None | Some(CoreStatus::Stopped | CoreStatus::Error { .. })) {
            self.set_status(&mut inner, CoreStatus::Error { message });
        }
    }

    pub async fn stop(&self) {
        let _op = self.op.lock().await;
        self.stop_locked().await;
        let mut inner = self.inner.lock().await;
        self.set_status(&mut inner, CoreStatus::Stopped);
    }

    /// Kills the current run (if any) and forgets the session. Caller holds `op`.
    async fn stop_locked(&self) {
        let run = {
            let mut inner = self.inner.lock().await;
            inner.generation += 1; // the exit that follows is intentional
            inner.plan = None;
            inner.live = None;
            inner.live_failed = false;
            inner.early_exit = None;
            inner.run.take()
        };
        let Some(mut run) = run else { return };
        if let Some(k) = run.kill.take() {
            let _ = k.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), run.done).await;
        self.push_log("---- sing-box 已停止 ----".into());
        self.launcher.cleanup().await;
    }

    /// Called by the per-run monitor when the process exits.
    async fn on_exit(self: Arc<Self>, generation: u64, message: String) {
        let mut inner = self.inner.lock().await;
        if inner.generation != generation {
            return; // stopped or replaced on purpose
        }
        let Some(run) = inner.run.take() else {
            // Still starting: `launch` picks this up.
            inner.early_exit = Some((generation, message));
            return;
        };
        inner.live = None;
        if run.started.elapsed() >= self.stable_after {
            inner.crashes = 0;
        }
        self.after_crash(inner, generation, message).await;
    }

    /// Schedules the next automatic restart, or gives up once the budget is spent.
    async fn after_crash(self: &Arc<Self>, mut inner: tokio::sync::MutexGuard<'_, Inner>, generation: u64, message: String) {
        let attempt = inner.crashes;
        self.push_log(format!("---- {message} ----"));
        match self.restart_delays.get(attempt as usize).copied() {
            Some(delay) => {
                inner.crashes += 1;
                self.set_status(&mut inner, CoreStatus::Reconnecting { attempt: attempt + 1, message });
                drop(inner);
                self.launcher.cleanup().await;
                let me = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    me.restart(generation).await;
                });
            }
            None => {
                inner.plan = None;
                self.set_status(&mut inner, CoreStatus::Error { message: format!("{message}（已自動重試 {attempt} 次）") });
                drop(inner);
                self.launcher.cleanup().await;
            }
        }
    }

    /// Boxed: restart → after_crash → (spawned) restart would otherwise be a recursive type.
    fn restart(self: Arc<Self>, crashed_generation: u64) -> BoxFut<'static, ()> {
        Box::pin(async move { self.restart_inner(crashed_generation).await })
    }

    async fn restart_inner(self: &Arc<Self>, crashed_generation: u64) {
        let _op = self.op.lock().await;
        let (plan, generation) = {
            let mut inner = self.inner.lock().await;
            if inner.generation != crashed_generation || !matches!(inner.status, Some(CoreStatus::Reconnecting { .. })) {
                return; // the user stopped or restarted meanwhile
            }
            let Some(plan) = inner.plan.clone() else { return };
            inner.generation += 1;
            (plan, inner.generation)
        };
        if let Err(e) = self.launch(&plan, generation).await {
            // A failed restart counts like another crash of the same session.
            let inner = self.inner.lock().await;
            if inner.generation == generation {
                self.after_crash(inner, generation, format!("自動重啟失敗：{e}")).await;
            }
        }
    }
}

/// Whether the running config has `selector` and it lists `outbound` as a member, i.e. whether
/// the Clash API can switch it there.
fn fits(plan: &StartPlan, selector: &str, outbound: &str) -> bool {
    plan.selectors.get(selector).is_some_and(|members| members.contains(outbound))
}

/// Drops switches the running config cannot take (selector or member added since it started,
/// or a selector that did not exist because its group was blocked); the fingerprint already
/// marks those as needing a reconnect.
fn applicable(plan: &StartPlan, ops: Vec<LiveOp>) -> Vec<LiveOp> {
    ops.into_iter()
        .filter(|op| match op {
            LiveOp::Select { selector, outbound } => fits(plan, selector, outbound),
            LiveOp::Mode(_) | LiveOp::CloseAll => true,
        })
        .collect()
}

/// The part of `desired` the running config can hold; skipped choices are left out (unknown),
/// so `live` only ever records what was really sent.
fn applied_part(plan: &StartPlan, desired: &Selections) -> Selections {
    Selections {
        mode: desired.mode,
        selectors: desired.selectors.iter().filter(|(s, o)| fits(plan, s, o)).map(|(s, o)| (s.clone(), o.clone())).collect(),
    }
}

/// Clash API calls that turn `from` (unknown → everything) into `to`, one per selector whose
/// choice differs.
fn diff(from: Option<&Selections>, to: &Selections) -> Vec<LiveOp> {
    let mut ops = Vec::new();
    for (selector, outbound) in &to.selectors {
        if from.and_then(|f| f.selectors.get(selector)) != Some(outbound) {
            ops.push(LiveOp::Select { selector: selector.clone(), outbound: outbound.clone() });
        }
    }
    if from.map(|f| f.mode) != Some(to.mode) {
        ops.push(LiveOp::Mode(to.mode));
        if from.is_some() {
            ops.push(LiveOp::CloseAll);
        }
    }
    ops
}

/// The real sing-box sidecar.
pub struct SingBox {
    pub exe: std::path::PathBuf,
    /// sing-box working directory (`cache.db`); writable by administrators only.
    pub run_dir: std::path::PathBuf,
}

/// Cache files only grow (one bucket per start id); start over past this size.
const CACHE_LIMIT: u64 = 16 * 1024 * 1024;

#[cfg(windows)]
mod spawn {
    use std::process::Stdio;

    use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
    use tokio::process::Command;
    use tokio::sync::mpsc;

    pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub fn command(exe: &std::path::Path) -> Command {
        let mut c = Command::new(exe);
        c.creation_flags(CREATE_NO_WINDOW);
        c
    }

    /// Feeds the config over stdin and closes it, so sing-box reads it once (`-c stdin`).
    pub async fn feed(child: &mut tokio::process::Child, config: &[u8]) -> Result<(), String> {
        let mut stdin = child.stdin.take().ok_or("sing-box stdin 無法使用")?;
        stdin.write_all(config).await.map_err(|e| format!("無法傳送設定給 sing-box: {e}"))?;
        drop(stdin);
        Ok(())
    }

    pub fn pump<R: AsyncRead + Unpin + Send + 'static>(reader: R, log: mpsc::UnboundedSender<String>) {
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = log.send(super::strip_ansi(&line));
            }
        });
    }

    pub fn piped(c: &mut Command) -> &mut Command {
        c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
    }
}

#[cfg(windows)]
impl Launcher for SingBox {
    fn check<'a>(&'a self, config: &'a [u8]) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let mut cmd = spawn::command(&self.exe);
            cmd.args(["check", "-c", "stdin"]);
            let mut child = spawn::piped(&mut cmd).spawn().map_err(|e| format!("無法執行 sing-box: {e}"))?;
            spawn::feed(&mut child, config).await?;
            let out = child.wait_with_output().await.map_err(|e| format!("無法執行 sing-box: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(strip_ansi(String::from_utf8_lossy(&out.stderr).trim()))
            }
        })
    }

    fn spawn<'a>(&'a self, config: &'a [u8], log: mpsc::UnboundedSender<String>) -> BoxFut<'a, Result<Child, String>> {
        Box::pin(async move {
            if !self.exe.is_file() {
                return Err(format!("找不到 sing-box：{}", self.exe.display()));
            }
            let cache = self.run_dir.join("cache.db");
            if std::fs::metadata(&cache).is_ok_and(|m| m.len() > CACHE_LIMIT) {
                let _ = std::fs::remove_file(&cache);
            }
            let mut cmd = spawn::command(&self.exe);
            cmd.args(["run", "-c", "stdin", "-D"]).arg(&self.run_dir).kill_on_drop(true);
            let mut child = spawn::piped(&mut cmd).spawn().map_err(|e| format!("無法啟動 sing-box: {e}"))?;
            if let Some(handle) = child.raw_handle() {
                job::assign(handle);
            }
            if let Some(out) = child.stdout.take() {
                spawn::pump(out, log.clone());
            }
            if let Some(err) = child.stderr.take() {
                spawn::pump(err, log);
            }
            spawn::feed(&mut child, config).await?;

            let (kill_tx, kill_rx) = oneshot::channel::<()>();
            let (exit_tx, exit_rx) = oneshot::channel::<String>();
            tokio::spawn(async move {
                let msg = tokio::select! {
                    status = child.wait() => match status {
                        Ok(s) => format!("sing-box 意外結束（{s}）"),
                        Err(e) => format!("sing-box 意外結束: {e}"),
                    },
                    _ = kill_rx => {
                        let _ = child.kill().await;
                        "sing-box 已停止".to_string()
                    }
                };
                let _ = exit_tx.send(msg);
            });
            Ok(Child { kill: kill_tx, exit: exit_rx })
        })
    }

    fn healthy<'a>(&'a self, clash: &'a ClashClient) -> BoxFut<'a, bool> {
        Box::pin(async move { clash.version().await.is_ok() })
    }

    fn apply<'a>(&'a self, clash: &'a ClashClient, ops: &'a [LiveOp]) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            for op in ops {
                match op {
                    LiveOp::Select { selector, outbound } => clash.select(selector, outbound).await?,
                    LiveOp::Mode(m) => clash.set_mode(m.as_clash()).await?,
                    LiveOp::CloseAll => clash.close_all().await?,
                }
            }
            Ok(())
        })
    }

    fn interrupt<'a>(&'a self, clash: &'a ClashClient, switches: &'a [(String, String)]) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let _ = clash.close_switched_connections(switches).await;
        })
    }

    fn cleanup(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            // FakeIP answers cached by Windows would point at the now-closed TUN.
            let _ = spawn::command(std::path::Path::new("ipconfig")).arg("/flushdns").output().await;
        })
    }

    fn sweep_orphans(&self) {
        kill_orphans(&self.exe);
    }
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
    let target = sing_box.to_string_lossy();
    for p in sys.processes().values() {
        if p.exe().is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case(&target)) {
            log::warn!("結束殘留的 sing-box（pid {}）", p.pid());
            p.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn strips_ansi_colors() {
        assert_eq!(strip_ansi("+0000 \u{1b}[36mINFO\u{1b}[0m started"), "+0000 INFO started");
    }

    /// Scripted launcher: each spawn takes the next behaviour; exits are triggered by tests.
    #[derive(Default)]
    struct Fake {
        check_error: std::sync::Mutex<Option<String>>,
        /// Per spawn: `true` = becomes healthy.
        healthy: std::sync::Mutex<VecDeque<bool>>,
        spawns: AtomicU32,
        cleanups: AtomicU32,
        exits: std::sync::Mutex<Vec<oneshot::Sender<String>>>,
        current_healthy: std::sync::atomic::AtomicBool,
        applied: std::sync::Mutex<Vec<LiveOp>>,
        /// `(selector, old_member)` pairs whose connections were dropped after a live switch.
        interrupted: std::sync::Mutex<Vec<(String, String)>>,
        /// The next apply kills the process mid-way (it died while selections were sent).
        crash_in_apply: std::sync::atomic::AtomicBool,
        /// While set, apply returns an error without the process dying (a transient Clash hiccup).
        fail_apply: std::sync::atomic::AtomicBool,
    }

    impl Fake {
        /// Simulates the latest process dying on its own.
        fn crash(&self) {
            if let Some(tx) = self.exits.lock().unwrap().pop() {
                let _ = tx.send("boom".into());
            }
        }
    }

    impl Launcher for Fake {
        fn check<'a>(&'a self, _: &'a [u8]) -> BoxFut<'a, Result<(), String>> {
            let e = self.check_error.lock().unwrap().clone();
            Box::pin(async move { e.map_or(Ok(()), Err) })
        }
        fn spawn<'a>(&'a self, _: &'a [u8], _: mpsc::UnboundedSender<String>) -> BoxFut<'a, Result<Child, String>> {
            self.spawns.fetch_add(1, Ordering::SeqCst);
            let healthy = self.healthy.lock().unwrap().pop_front().unwrap_or(true);
            self.current_healthy.store(healthy, Ordering::SeqCst);
            let (kill_tx, kill_rx) = oneshot::channel::<()>();
            let (exit_tx, exit_rx) = oneshot::channel::<String>();
            let (crash_tx, crash_rx) = oneshot::channel::<String>();
            self.exits.lock().unwrap().push(crash_tx);
            tokio::spawn(async move {
                let msg = tokio::select! {
                    m = crash_rx => m.unwrap_or_else(|_| "gone".into()),
                    _ = kill_rx => "killed".into(),
                };
                let _ = exit_tx.send(msg);
            });
            Box::pin(async move { Ok(Child { kill: kill_tx, exit: exit_rx }) })
        }
        fn healthy<'a>(&'a self, _: &'a ClashClient) -> BoxFut<'a, bool> {
            let h = self.current_healthy.load(Ordering::SeqCst);
            Box::pin(async move { h })
        }
        fn apply<'a>(&'a self, _: &'a ClashClient, ops: &'a [LiveOp]) -> BoxFut<'a, Result<(), String>> {
            self.applied.lock().unwrap().extend(ops.iter().cloned());
            let crash = self.crash_in_apply.swap(false, Ordering::SeqCst);
            if crash {
                self.crash();
            }
            let fail = self.fail_apply.load(Ordering::SeqCst);
            Box::pin(async move {
                if crash {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    return Err("connection refused".into());
                }
                if fail {
                    return Err("clash hiccup".into());
                }
                Ok(())
            })
        }
        fn interrupt<'a>(&'a self, _: &'a ClashClient, switches: &'a [(String, String)]) -> BoxFut<'a, ()> {
            self.interrupted.lock().unwrap().extend(switches.iter().cloned());
            Box::pin(async {})
        }
        fn cleanup(&self) -> BoxFut<'_, ()> {
            self.cleanups.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
        fn sweep_orphans(&self) {}
    }

    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<CoreStatus>>);
    impl CoreEvents for Recorder {
        fn status(&self, s: &CoreStatus) {
            self.0.lock().unwrap().push(s.clone());
        }
        fn logs(&self, _: &LogBatch) {}
    }

    /// A config with Global mode, `final` and one group `a`.
    fn plan(fp: &str) -> StartPlan {
        let members = |m: &[&str]| m.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        StartPlan {
            config: b"{}".to_vec(),
            clash: ClashClient::new("127.0.0.1:9", "s"),
            fingerprint: fp.into(),
            selectors: BTreeMap::from([
                ("final".to_string(), members(&["direct", "auto", "mudfish-1", "mudfish-2"])),
                ("global".to_string(), members(&["auto", "mudfish-1", "mudfish-2"])),
                ("group-a".to_string(), members(&["direct", "auto", "mudfish-1", "mudfish-2"])),
            ]),
        }
    }

    /// `final` on `node`, group `a` direct, Global mode on `auto`.
    fn sel(node: &str) -> Selections {
        Selections {
            mode: Mode::Rule,
            selectors: BTreeMap::from([("final".into(), node.into()), ("global".into(), "auto".into()), ("group-a".into(), "direct".into())]),
        }
    }

    fn setup() -> (Arc<CoreManager>, Arc<Fake>, Arc<Recorder>) {
        let fake = Arc::new(Fake::default());
        let rec = Arc::new(Recorder::default());
        let mut m = CoreManager::with_policy(fake.clone(), rec.clone(), vec![Duration::from_millis(10); 2], Duration::from_secs(60));
        Arc::get_mut(&mut m).unwrap().health_timeout = Duration::from_millis(300);
        (m, fake, rec)
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn start_applies_selections_and_tracks_staleness() {
        let (m, fake, _) = setup();
        m.start(plan("fp1"), sel("auto")).await.unwrap();
        assert!(matches!(m.status().await, CoreStatus::Running { .. }));
        let applied = fake.applied.lock().unwrap().clone();
        assert_eq!(applied[0], LiveOp::Select { selector: "final".into(), outbound: "auto".into() });
        assert!(applied.contains(&LiveOp::Select { selector: "global".into(), outbound: "auto".into() }));
        assert!(applied.contains(&LiveOp::Select { selector: "group-a".into(), outbound: "direct".into() }));
        assert!(applied.contains(&LiveOp::Mode(Mode::Rule)));
        assert!(!applied.contains(&LiveOp::CloseAll), "no connections to close on a fresh start");
        assert!(!m.is_stale(Some("fp1")).await);
        assert!(m.is_stale(Some("fp2")).await);
        assert!(m.is_stale(None).await, "an invalid profile is never what is running");

        // live change: only the difference, no CloseAll for selectors
        fake.applied.lock().unwrap().clear();
        m.set_selections(sel("direct")).await.unwrap();
        assert_eq!(*fake.applied.lock().unwrap(), vec![LiveOp::Select { selector: "final".into(), outbound: "direct".into() }]);
        // ...and the connections still on final's old member (`auto`) are dropped, so the switch bites at once
        assert_eq!(*fake.interrupted.lock().unwrap(), vec![("final".to_string(), "auto".to_string())]);
        fake.interrupted.lock().unwrap().clear();
        let mut global = sel("direct");
        global.mode = Mode::Global;
        fake.applied.lock().unwrap().clear();
        m.set_selections(global).await.unwrap();
        assert_eq!(*fake.applied.lock().unwrap(), vec![LiveOp::Mode(Mode::Global), LiveOp::CloseAll]);
        assert!(fake.interrupted.lock().unwrap().is_empty(), "a mode change closed everything already: no per-selector interrupt");

        m.stop().await;
        assert_eq!(m.status().await, CoreStatus::Stopped);
        assert!(!m.is_stale(Some("fp2")).await, "nothing is stale while stopped");
        assert_eq!(fake.cleanups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn selections_while_stopped_apply_on_next_start() {
        let (m, fake, _) = setup();
        m.set_selections(sel("mudfish-1")).await.unwrap();
        assert!(fake.applied.lock().unwrap().is_empty());
        m.start(plan("fp"), sel("mudfish-2")).await.unwrap();
        assert!(fake.applied.lock().unwrap().contains(&LiveOp::Select { selector: "final".into(), outbound: "mudfish-2".into() }));
    }

    #[tokio::test]
    async fn crash_while_applying_selections_still_restarts() {
        let (m, fake, rec) = setup();
        fake.crash_in_apply.store(true, Ordering::SeqCst);
        m.start(plan("fp"), sel("auto")).await.unwrap();
        settle().await;
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 2, "the crash during apply was not swallowed");
        assert!(matches!(m.status().await, CoreStatus::Running { .. }));
        assert!(m.clash().await.is_some(), "Running really has a process behind it");
        assert!(rec.0.lock().unwrap().iter().any(|s| matches!(s, CoreStatus::Reconnecting { .. })));
    }

    #[tokio::test]
    async fn switches_the_running_config_lacks_wait_for_restart() {
        let (m, fake, _) = setup();
        m.start(plan("fp"), sel("auto")).await.unwrap();
        fake.applied.lock().unwrap().clear();
        let mut s = sel("mudfish-3"); // node added after the start
        s.selectors.insert("group-new".into(), "direct".into()); // group added after the start
        s.selectors.insert("group-a".into(), "auto".into());
        m.set_selections(s).await.unwrap();
        assert_eq!(*fake.applied.lock().unwrap(), vec![LiveOp::Select { selector: "group-a".into(), outbound: "auto".into() }]);
        assert_eq!(
            *fake.interrupted.lock().unwrap(),
            vec![("group-a".to_string(), "direct".to_string())],
            "only a switch that was really sent drops connections, and only those on its old member"
        );
        assert!(!m.is_stale(Some("fp")).await, "skipped switches are not failures");
    }

    #[tokio::test]
    async fn resync_after_a_failed_apply_does_not_interrupt() {
        let (m, fake, _) = setup();
        m.start(plan("fp"), sel("auto")).await.unwrap();
        fake.fail_apply.store(true, Ordering::SeqCst);
        let _ = m.set_selections(sel("direct")).await; // apply fails → live becomes unknown (None)
        assert!(m.is_stale(Some("fp")).await, "a failed live apply marks the session stale");
        fake.fail_apply.store(false, Ordering::SeqCst);
        fake.interrupted.lock().unwrap().clear();
        // A later save re-sends every selector (live is None) but they are no-ops in the core, so
        // nothing was really switched: the backstop must not drop any connection.
        m.set_selections(sel("direct")).await.unwrap();
        assert!(
            fake.interrupted.lock().unwrap().is_empty(),
            "a resync of unchanged selectors after a hiccup must not disconnect anything"
        );
    }

    #[tokio::test]
    async fn rejected_config_or_invalid_profile_keeps_the_running_core() {
        let (m, fake, _) = setup();
        m.start(plan("fp"), sel("auto")).await.unwrap();
        *fake.check_error.lock().unwrap() = Some("bad rule".into());
        assert!(m.start(plan("fp2"), sel("auto")).await.unwrap_err().contains("bad rule"));
        m.fail("群組沒有條件".into()).await;
        assert!(matches!(m.status().await, CoreStatus::Running { .. }));
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 1);
        assert_eq!(fake.exits.lock().unwrap().iter().filter(|t| !t.is_closed()).count(), 1, "still alive");
        m.stop().await;
        m.fail("群組沒有條件".into()).await;
        assert!(matches!(m.status().await, CoreStatus::Error { .. }), "an idle core shows the failure");
    }

    #[tokio::test]
    async fn log_snapshot_and_batches_share_sequence_numbers() {
        let (m, _, _) = setup();
        tokio::spawn(m.log_task());
        for i in 0..3 {
            m.push_log(format!("line {i}"));
        }
        tokio::time::sleep(LOG_BATCH * 2).await;
        let snap = m.logs();
        assert_eq!(snap.first, 0);
        assert_eq!(snap.lines, ["line 0", "line 1", "line 2"]);
    }

    #[tokio::test]
    async fn check_failure_and_health_timeout_report_errors() {
        let (m, fake, _) = setup();
        *fake.check_error.lock().unwrap() = Some("bad rule".into());
        let e = m.start(plan("fp"), sel("auto")).await.unwrap_err();
        assert!(e.contains("bad rule"));
        assert!(matches!(m.status().await, CoreStatus::Error { .. }));
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 0);

        *fake.check_error.lock().unwrap() = None;
        fake.healthy.lock().unwrap().push_back(false);
        let e = m.start(plan("fp"), sel("auto")).await.unwrap_err();
        assert!(e.contains("逾時"));
        assert_eq!(fake.exits.lock().unwrap().iter().filter(|t| !t.is_closed()).count(), 0, "unhealthy core was killed");
    }

    #[tokio::test]
    async fn exit_before_health_fails_start() {
        let (m, fake, _) = setup();
        fake.healthy.lock().unwrap().push_back(false);
        let start = tokio::spawn({
            let m = m.clone();
            async move { m.start(plan("fp"), sel("auto")).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        fake.crash();
        let e = start.await.unwrap().unwrap_err();
        assert!(e.contains("boom"));
        assert!(matches!(m.status().await, CoreStatus::Error { .. }));
    }

    #[tokio::test]
    async fn crash_restarts_with_budget_then_errors() {
        let (m, fake, rec) = setup();
        m.start(plan("fp"), sel("auto")).await.unwrap();
        fake.crash();
        settle().await;
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 2, "first crash restarts");
        assert!(matches!(m.status().await, CoreStatus::Running { .. }));
        assert!(rec.0.lock().unwrap().iter().any(|s| matches!(s, CoreStatus::Reconnecting { attempt: 1, .. })));
        assert!(fake.cleanups.load(Ordering::SeqCst) >= 1, "DNS cleanup also runs after a crash");

        fake.crash();
        settle().await;
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 3);
        fake.crash();
        settle().await;
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 3, "budget of 2 restarts used up");
        let CoreStatus::Error { message } = m.status().await else { panic!("expected error") };
        assert!(message.contains("2 次"));
        assert!(!m.is_stale(Some("other")).await, "a dead session is not stale");
    }

    #[tokio::test]
    async fn stop_during_restart_backoff_wins() {
        let fake = Arc::new(Fake::default());
        let rec = Arc::new(Recorder::default());
        let m = CoreManager::with_policy(fake.clone(), rec.clone(), vec![Duration::from_millis(200)], Duration::from_secs(60));
        m.start(plan("fp"), sel("auto")).await.unwrap();
        fake.crash();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(m.status().await, CoreStatus::Reconnecting { .. }));
        m.stop().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(m.status().await, CoreStatus::Stopped);
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 1, "no restart after the user stopped");
    }

    #[tokio::test]
    async fn intentional_stop_never_reports_error() {
        let (m, _fake, rec) = setup();
        m.start(plan("fp"), sel("auto")).await.unwrap();
        m.stop().await;
        settle().await;
        let seen = rec.0.lock().unwrap().clone();
        assert!(!seen.iter().any(|s| matches!(s, CoreStatus::Error { .. } | CoreStatus::Reconnecting { .. })), "{seen:?}");
        assert_eq!(seen.last(), Some(&CoreStatus::Stopped));
    }

    #[tokio::test]
    async fn concurrent_starts_leave_one_core() {
        let (m, fake, _) = setup();
        let a = tokio::spawn({
            let m = m.clone();
            async move { m.start(plan("a"), sel("auto")).await }
        });
        let b = tokio::spawn({
            let m = m.clone();
            async move { m.start(plan("b"), sel("auto")).await }
        });
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        settle().await;
        assert_eq!(fake.spawns.load(Ordering::SeqCst), 2);
        assert_eq!(fake.exits.lock().unwrap().iter().filter(|t| !t.is_closed()).count(), 1, "the first core was killed");
        assert!(matches!(m.status().await, CoreStatus::Running { .. }));
    }

    #[test]
    fn diff_from_unknown_sets_everything() {
        let ops = diff(None, &sel("auto"));
        assert_eq!(ops.len(), 4, "three selectors and the mode");
        assert!(diff(Some(&sel("auto")), &sel("auto")).is_empty());
    }

    #[test]
    fn diff_compares_selector_by_selector() {
        let mut to = sel("auto");
        to.selectors.insert("group-a".into(), "mudfish-1".into());
        to.selectors.insert("global".into(), "mudfish-2".into());
        assert_eq!(
            diff(Some(&sel("auto")), &to),
            vec![
                LiveOp::Select { selector: "global".into(), outbound: "mudfish-2".into() },
                LiveOp::Select { selector: "group-a".into(), outbound: "mudfish-1".into() },
            ]
        );
    }

    #[test]
    fn live_state_only_records_what_the_config_can_hold() {
        let mut s = sel("mudfish-3"); // a node the config does not know
        s.selectors.insert("group-new".into(), "auto".into()); // a selector it does not have
        let held = applied_part(&plan("fp"), &s);
        assert_eq!(held.selectors, BTreeMap::from([("global".to_string(), "auto".to_string()), ("group-a".to_string(), "direct".to_string())]));
        // so a later switch to a node the config does have is still sent
        assert_eq!(diff(Some(&held), &sel("mudfish-1")), vec![LiveOp::Select { selector: "final".into(), outbound: "mudfish-1".into() }]);
    }
}

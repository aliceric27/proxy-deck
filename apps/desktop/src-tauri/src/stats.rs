//! Traffic history: one record per connection session, from the user's connect until the
//! disconnect (or the next connect). Automatic restarts after a crash stay in the same session;
//! the new core's counters start at zero again and are added on.
//!
//! The totals come from sing-box's own counters (`uploadTotal` / `downloadTotal`), so they are
//! exact. The split by exit and by program adds up each connection's growth between two samples;
//! the last bytes of a connection that closes between samples cannot be attributed, so the split
//! can fall slightly short of the totals (the UI shows the rest as 「其他」, together with exits
//! that are neither a node nor `direct`).
//!
//! Stored per session: byte counts, times, node display names and program file names — no
//! hosts, IP addresses or full paths.
//!
//! `Recorder` is the pure state machine (status changes and samples in, sessions out);
//! `TrafficStats` adds the files: closed sessions in `traffic-history.json`, the running one in
//! `traffic-current.json` (rewritten once a minute, so an app that is killed loses at most a
//! minute; the next start files it as interrupted). Both are compact JSON: a long history of
//! timelines would be several MB pretty-printed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use proxy_core::Profile;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::clash::ClashConnections;
use crate::core::CoreStatus;

/// Closed sessions kept on disk; the oldest go first.
const MAX_SESSIONS: usize = 200;
/// Programs listed per session; the rest are added up as one 「其他程式」 entry.
const MAX_APPS: usize = 12;
/// Timeline resolution of a fresh session. Once a session has `MAX_BUCKETS` buckets, neighbours
/// are merged and the bucket length doubles, so a long session stays the same size.
const FIRST_BUCKET_SECS: u64 = 10;
const MAX_BUCKETS: usize = 240;
/// The running session goes to disk this often.
const CURRENT_SAVE_SECS: u64 = 60;

pub const OTHER_APPS: &str = "*other";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ExitKind {
    Direct,
    Mudfish,
    Warp,
    Custom,
    /// Not a node of the profile and not `direct` (a connection without a chain).
    Other,
}

impl ExitKind {
    fn proxied(self) -> bool {
        matches!(self, ExitKind::Mudfish | ExitKind::Warp | ExitKind::Custom)
    }
}

/// Bytes of one exit or one program within a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct Usage {
    /// Exit: the outbound tag (`direct`, `mudfish-591`, …). Program: its file name in lower case,
    /// `""` when sing-box did not know it, or `*other` for the programs past the listed ones.
    pub key: String,
    /// Display name, fixed when the session first saw it (a node removed later keeps its name).
    pub label: String,
    /// Set for exits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub kind: Option<ExitKind>,
    #[ts(type = "number")]
    pub upload: u64,
    #[ts(type = "number")]
    pub download: u64,
    /// Of `upload + download`, the bytes that went through a node.
    #[ts(type = "number")]
    pub proxied: u64,
}

impl Usage {
    fn new(key: &str, label: String, kind: Option<ExitKind>) -> Self {
        Self { key: key.to_string(), label, kind, upload: 0, download: 0, proxied: 0 }
    }

    fn total(&self) -> u64 {
        self.upload + self.download
    }

    fn add(&mut self, upload: u64, download: u64, proxied: bool) {
        self.upload += upload;
        self.download += download;
        if proxied {
            self.proxied += upload + download;
        }
    }
}

/// Bytes per time bucket; bucket `i` covers `started_at + i * bucket_secs` onwards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct Timeline {
    #[ts(type = "number")]
    pub bucket_secs: u64,
    #[ts(type = "Array<number>")]
    pub upload: Vec<u64>,
    #[ts(type = "Array<number>")]
    pub download: Vec<u64>,
    /// Attributed to a node / to `direct` (both directions); short-lived connections may be missing.
    #[ts(type = "Array<number>")]
    pub proxied: Vec<u64>,
    #[ts(type = "Array<number>")]
    pub direct: Vec<u64>,
}

impl Default for Timeline {
    fn default() -> Self {
        Self { bucket_secs: FIRST_BUCKET_SECS, upload: Vec::new(), download: Vec::new(), proxied: Vec::new(), direct: Vec::new() }
    }
}

impl Timeline {
    fn add(&mut self, offset_secs: u64, upload: u64, download: u64, proxied: u64, direct: u64) {
        let mut i = (offset_secs / self.bucket_secs) as usize;
        while i >= MAX_BUCKETS {
            self.bucket_secs *= 2;
            for v in [&mut self.upload, &mut self.download, &mut self.proxied, &mut self.direct] {
                *v = v.chunks(2).map(|pair| pair.iter().sum()).collect();
            }
            i = (offset_secs / self.bucket_secs) as usize;
        }
        for (v, n) in [(&mut self.upload, upload), (&mut self.download, download), (&mut self.proxied, proxied), (&mut self.direct, direct)] {
            if v.len() <= i {
                v.resize(i + 1, 0);
            }
            v[i] += n;
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SessionEnd {
    /// Disconnected (also when the app quits).
    Stopped,
    /// Connected again, e.g. to apply a changed profile; the next session follows at once.
    Reconnected,
    /// The core failed and the automatic restarts gave up.
    Error,
    /// The app ended without closing the session (killed, power loss); it ends at the last sample
    /// written to the running file, so up to a minute of it may be missing.
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct TrafficSession {
    pub id: String,
    /// Unix seconds; the moment the core first reported running.
    #[ts(type = "number")]
    pub started_at: u64,
    /// Unix seconds of the last sample; `None` while the session is still running.
    #[ts(type = "number | null")]
    pub ended_at: Option<u64>,
    pub end: Option<SessionEnd>,
    /// Unix seconds of the latest sample.
    #[ts(type = "number")]
    pub last_seen: u64,
    #[ts(type = "number")]
    pub upload: u64,
    #[ts(type = "number")]
    pub download: u64,
    /// Highest bytes per second between two samples.
    #[ts(type = "number")]
    pub peak_up_rate: u64,
    #[ts(type = "number")]
    pub peak_down_rate: u64,
    /// Automatic restarts after a crash that brought the core back within this session.
    pub restarts: u32,
    /// By the outbound that carried the bytes, largest first.
    pub exits: Vec<Usage>,
    /// By program, largest first; at most `MAX_APPS` plus one `*other` entry.
    pub apps: Vec<Usage>,
    pub timeline: Timeline,
}

impl TrafficSession {
    fn total(&self) -> u64 {
        self.upload + self.download
    }
}

/// All sessions, oldest first; the running one (if any) is last, with `ended_at: null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TrafficHistory {
    pub sessions: Vec<TrafficSession>,
}

/// Where an exit tag goes and what it is called. Called once per tag and session.
pub fn classify_exit(profile: &Profile, tag: &str) -> (String, ExitKind) {
    if tag == proxy_core::model::TAG_DIRECT {
        return ("直接連線".into(), ExitKind::Direct);
    }
    match profile.node(tag) {
        Some(n) if n.is_wireguard() => (n.name.clone(), ExitKind::Warp),
        Some(n) if n.is_custom() => (n.name.clone(), ExitKind::Custom),
        Some(n) => (n.name.clone(), ExitKind::Mudfish),
        None if tag.is_empty() => ("未知出口".into(), ExitKind::Other),
        None => (tag.to_string(), ExitKind::Other),
    }
}

/// The file name of a process path (either separator).
fn program(path: Option<&str>) -> &str {
    let path = path.unwrap_or_default();
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

struct Seen {
    upload: u64,
    download: u64,
}

struct Open {
    session: TrafficSession,
    exits: BTreeMap<String, Usage>,
    apps: BTreeMap<String, Usage>,
    /// Connections of the latest sample and their byte counts then.
    conns: BTreeMap<String, Seen>,
    /// The core's counters at the latest sample; zero right after the core (re)started.
    last_totals: (u64, u64),
    /// Unix ms of the latest sample of the current core; `None` before its first one.
    last_ms: Option<u64>,
    /// Changed since the current file was last written.
    dirty: bool,
}

impl Open {
    fn new(started_at: u64) -> Self {
        Self {
            session: TrafficSession {
                id: uuid::Uuid::new_v4().simple().to_string(),
                started_at,
                ended_at: None,
                end: None,
                last_seen: started_at,
                upload: 0,
                download: 0,
                peak_up_rate: 0,
                peak_down_rate: 0,
                restarts: 0,
                exits: Vec::new(),
                apps: Vec::new(),
                timeline: Timeline::default(),
            },
            exits: BTreeMap::new(),
            apps: BTreeMap::new(),
            conns: BTreeMap::new(),
            last_totals: (0, 0),
            last_ms: None,
            dirty: true,
        }
    }

    /// A fresh core: its counters and connection ids start over.
    fn core_restarted(&mut self) {
        self.conns.clear();
        self.last_totals = (0, 0);
        self.last_ms = None;
    }

    /// The session with the exits and programs folded in.
    fn snapshot(&self) -> TrafficSession {
        let by_size = |m: &BTreeMap<String, Usage>| {
            let mut v: Vec<Usage> = m.values().filter(|u| u.total() > 0).cloned().collect();
            v.sort_by(|a, b| b.total().cmp(&a.total()).then_with(|| a.key.cmp(&b.key)));
            v
        };
        let mut apps = by_size(&self.apps);
        if apps.len() > MAX_APPS {
            let mut other = Usage::new(OTHER_APPS, "其他程式".into(), None);
            for u in apps.drain(MAX_APPS..) {
                other.upload += u.upload;
                other.download += u.download;
                other.proxied += u.proxied;
            }
            apps.push(other);
        }
        TrafficSession { exits: by_size(&self.exits), apps, ..self.session.clone() }
    }
}

/// Session bookkeeping without files or clocks; see the module docs.
#[derive(Default)]
pub struct Recorder {
    open: Option<Open>,
    /// A start is under way: its first `Running` opens a new session.
    armed: bool,
    /// The session a start replaced. How it ended is known once that start succeeds
    /// (reconnected) or fails (error, or stopped when the user gave up on it).
    replaced: Option<TrafficSession>,
    /// Bumped by every status change; a sample taken across one is dropped, since it may belong
    /// to the core before or after the change.
    epoch: u64,
    /// Closed sessions waiting to be saved.
    finished: Vec<TrafficSession>,
}

impl Recorder {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Follows the core's status.
    pub fn on_status(&mut self, status: &CoreStatus) {
        self.epoch += 1;
        match status {
            CoreStatus::Starting => {
                self.settle(SessionEnd::Reconnected);
                self.replaced = self.close();
                self.armed = true;
            }
            CoreStatus::Running { started_at } => match &mut self.open {
                // `Reconnecting` already reset the counters. Resetting them again here would count
                // twice what was sampled between the new core coming up and this status.
                Some(open) if !self.armed => open.session.restarts += 1,
                _ => {
                    self.settle(SessionEnd::Reconnected);
                    if let Some(s) = self.close() {
                        self.finish(s, SessionEnd::Reconnected);
                    }
                    self.open = Some(Open::new(*started_at));
                    self.armed = false;
                }
            },
            CoreStatus::Reconnecting { .. } => {
                if let Some(open) = &mut self.open {
                    open.core_restarted();
                }
            }
            CoreStatus::Stopped | CoreStatus::Error { .. } => {
                let end = if matches!(status, CoreStatus::Stopped) { SessionEnd::Stopped } else { SessionEnd::Error };
                self.armed = false;
                self.settle(end);
                if let Some(s) = self.close() {
                    self.finish(s, end);
                }
            }
        }
    }

    /// Takes the running session, ended at its last sample: the core's own stop and cleanup,
    /// which come before the status change, are not part of it.
    fn close(&mut self) -> Option<TrafficSession> {
        let mut session = self.open.take()?.snapshot();
        session.ended_at = Some(session.last_seen.max(session.started_at));
        Some(session)
    }

    fn finish(&mut self, mut session: TrafficSession, end: SessionEnd) {
        session.end = Some(end);
        // A session that moved no bytes (connected and at once disconnected) is not worth a row.
        if session.total() > 0 {
            self.finished.push(session);
        }
    }

    /// Ends the session the last start replaced, now that the start's outcome is known.
    fn settle(&mut self, end: SessionEnd) {
        if let Some(s) = self.replaced.take() {
            self.finish(s, end);
        }
    }

    /// Adds one `GET /connections` taken while `epoch` was current; `now_ms` is unix ms.
    /// `label` names an exit tag the session has not seen yet.
    pub fn on_sample(&mut self, epoch: u64, sample: &ClashConnections, now_ms: u64, label: impl Fn(&str) -> (String, ExitKind)) {
        if epoch != self.epoch {
            return;
        }
        let Some(open) = &mut self.open else { return };
        let now = now_ms / 1000;
        // A counter below the previous sample means a core we did not hear restart: count from zero.
        let grown = |total: u64, before: u64| total.checked_sub(before).unwrap_or(total);
        let up = grown(sample.upload_total, open.last_totals.0);
        let down = grown(sample.download_total, open.last_totals.1);
        open.last_totals = (sample.upload_total, sample.download_total);

        let (mut proxied, mut direct) = (0, 0);
        let mut conns = BTreeMap::new();
        for c in &sample.connections {
            let before = open.conns.remove(&c.id).unwrap_or(Seen { upload: 0, download: 0 });
            let (du, dd) = (c.upload.saturating_sub(before.upload), c.download.saturating_sub(before.download));
            conns.insert(c.id.clone(), Seen { upload: c.upload, download: c.download });
            if du + dd == 0 {
                continue;
            }
            let tag = c.chains.first().map(String::as_str).unwrap_or_default();
            let exit = open.exits.entry(tag.to_string()).or_insert_with(|| {
                let (name, kind) = label(tag);
                Usage::new(tag, name, Some(kind))
            });
            let is_proxied = exit.kind.is_some_and(ExitKind::proxied);
            exit.add(du, dd, is_proxied);
            if is_proxied {
                proxied += du + dd;
            } else if exit.kind == Some(ExitKind::Direct) {
                direct += du + dd;
            }
            // Windows file names are case-insensitive: one entry per program, named as first seen.
            let app = program(c.metadata.process_path.as_deref());
            let key = app.to_lowercase();
            open.apps
                .entry(key.clone())
                .or_insert_with(|| Usage::new(&key, if app.is_empty() { "未知程式".into() } else { app.to_string() }, None))
                .add(du, dd, is_proxied);
        }
        open.conns = conns;

        let s = &mut open.session;
        s.upload += up;
        s.download += down;
        if let Some(before) = open.last_ms {
            let ms = now_ms.saturating_sub(before);
            if ms >= 500 {
                s.peak_up_rate = s.peak_up_rate.max(up * 1000 / ms);
                s.peak_down_rate = s.peak_down_rate.max(down * 1000 / ms);
            }
        }
        open.last_ms = Some(now_ms);
        s.last_seen = s.last_seen.max(now);
        s.timeline.add(now.saturating_sub(s.started_at), up, down, proxied, direct);
        // Also without bytes: `last_seen` is where an interrupted session will end.
        open.dirty = true;
    }

    /// The running session, if any.
    pub fn current(&self) -> Option<TrafficSession> {
        self.open.as_ref().map(Open::snapshot)
    }

    /// Closed sessions not handed to `take_finished` yet, oldest first. A session that a start
    /// under way replaced shows as reconnected until the start's outcome is known.
    fn closed(&self) -> Vec<TrafficSession> {
        let replaced = self.replaced.iter().map(|s| TrafficSession { end: Some(SessionEnd::Reconnected), ..s.clone() });
        self.finished.iter().cloned().chain(replaced).collect()
    }

    pub fn take_finished(&mut self) -> Vec<TrafficSession> {
        std::mem::take(&mut self.finished)
    }

    /// The running session when it changed since the last call.
    fn take_dirty(&mut self) -> Option<TrafficSession> {
        let open = self.open.as_mut().filter(|o| o.dirty)?;
        open.dirty = false;
        Some(open.snapshot())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or_default()
}

#[derive(Default)]
struct History {
    sessions: Vec<TrafficSession>,
    /// The file lags `sessions` (a write failed); every `persist` tries again.
    unsaved: bool,
}

#[derive(Default)]
struct CurrentFile {
    /// Unix seconds of the last write.
    saved_at: u64,
    /// The session in the file. The file goes once that session is safely in the history file.
    id: Option<String>,
}

/// The recorder plus its files; shared by the core's status hook, the traffic poller and the
/// commands. Lock order: `recorder`, then `current`, then `history`; none is held across an await.
pub struct TrafficStats {
    recorder: Mutex<Recorder>,
    current: Mutex<CurrentFile>,
    history: Mutex<History>,
    history_file: PathBuf,
    current_file: PathBuf,
}

impl TrafficStats {
    /// Loads the history and files a session the previous run left open as interrupted.
    pub fn load(history_file: PathBuf, current_file: PathBuf) -> Self {
        let mut sessions = crate::store::load_or_default::<TrafficHistory>(&history_file).sessions;
        let left: Option<TrafficSession> = crate::store::load_or_default(&current_file);
        let mut filed = true;
        if let Some(mut s) = left {
            s.ended_at = Some(s.last_seen);
            s.end = Some(SessionEnd::Interrupted);
            if s.total() > 0 && !sessions.iter().any(|h| h.id == s.id) {
                sessions.push(s);
                trim(&mut sessions);
                filed = save_history(&history_file, &sessions);
            }
        }
        // Kept while its session could not reach the history file: the next start tries again.
        if filed {
            let _ = std::fs::remove_file(&current_file);
        }
        Self {
            recorder: Mutex::default(),
            current: Mutex::default(),
            history: Mutex::new(History { sessions, unsaved: false }),
            history_file,
            current_file,
        }
    }

    pub fn on_status(&self, status: &CoreStatus) {
        self.recorder.lock().unwrap().on_status(status);
    }

    pub fn epoch(&self) -> u64 {
        self.recorder.lock().unwrap().epoch()
    }

    pub fn on_sample(&self, epoch: u64, sample: &ClashConnections, profile: &Profile) {
        self.recorder.lock().unwrap().on_sample(epoch, sample, now_ms(), |tag| classify_exit(profile, tag));
    }

    /// Writes what changed: closed sessions at once (retried until it works), the running one
    /// once a minute (`force`: now).
    pub fn persist(&self, force: bool) {
        let now = now_ms() / 1000;
        let mut rec = self.recorder.lock().unwrap();
        let mut current = self.current.lock().unwrap();
        let running = if force || now >= current.saved_at + CURRENT_SAVE_SECS { rec.take_dirty() } else { None };
        let finished = rec.take_finished();
        drop(rec);
        if let Some(running) = running {
            match crate::store::save_compact(&self.current_file, &running) {
                Ok(()) => *current = CurrentFile { saved_at: now, id: Some(running.id) },
                Err(e) => log::warn!("{e}"),
            }
        }
        let mut history = self.history.lock().unwrap();
        if !finished.is_empty() {
            history.sessions.extend(finished);
            trim(&mut history.sessions);
            history.unsaved = true;
        }
        if history.unsaved && save_history(&self.history_file, &history.sessions) {
            history.unsaved = false;
            // The running file is only needed while its session is not in the history file.
            if current.id.as_ref().is_some_and(|id| history.sessions.iter().any(|s| &s.id == id)) {
                let _ = std::fs::remove_file(&self.current_file);
                current.id = None;
            }
        }
    }

    /// All sessions: saved, closed but not saved yet, then the running one.
    pub fn history(&self) -> TrafficHistory {
        let (closed, running) = {
            let rec = self.recorder.lock().unwrap();
            (rec.closed(), rec.current())
        };
        let mut sessions = self.history.lock().unwrap().sessions.clone();
        sessions.extend(closed);
        sessions.extend(running);
        TrafficHistory { sessions }
    }

    /// The running session alone, for a page that refreshes it often.
    pub fn current(&self) -> Option<TrafficSession> {
        self.recorder.lock().unwrap().current()
    }

    /// Forgets the closed sessions, saved or not; a running one keeps counting.
    pub fn clear(&self) -> Result<(), String> {
        let mut rec = self.recorder.lock().unwrap();
        let mut history = self.history.lock().unwrap();
        crate::store::save_compact(&self.history_file, &TrafficHistory::default())?;
        history.sessions.clear();
        history.unsaved = false;
        rec.finished.clear();
        rec.replaced = None;
        Ok(())
    }
}

/// Whether the write worked; a failure is logged and the caller tries again later.
fn save_history(path: &std::path::Path, sessions: &[TrafficSession]) -> bool {
    match crate::store::save_compact(path, &TrafficHistory { sessions: sessions.to_vec() }) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("{e}");
            false
        }
    }
}

fn trim(history: &mut Vec<TrafficSession>) {
    history.sort_by_key(|s| s.started_at);
    let excess = history.len().saturating_sub(MAX_SESSIONS);
    history.drain(..excess);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clash::{Connection, ConnectionMetadata};

    fn conn(id: &str, chains: &[&str], process: Option<&str>, upload: u64, download: u64) -> Connection {
        Connection {
            id: id.into(),
            upload,
            download,
            start: String::new(),
            chains: chains.iter().map(|s| s.to_string()).collect(),
            rule: String::new(),
            rule_payload: String::new(),
            metadata: ConnectionMetadata {
                network: "tcp".into(),
                host: String::new(),
                destination_ip: String::new(),
                destination_port: String::new(),
                process_path: process.map(str::to_string),
            },
        }
    }

    fn sample(upload_total: u64, download_total: u64, connections: Vec<Connection>) -> ClashConnections {
        ClashConnections { upload_total, download_total, connections }
    }

    fn label(tag: &str) -> (String, ExitKind) {
        match tag {
            "direct" => ("直接連線".into(), ExitKind::Direct),
            "" => ("未知出口".into(), ExitKind::Other),
            t => (format!("node {t}"), ExitKind::Mudfish),
        }
    }

    /// A recorder with one session that started at unix second 1000.
    fn running() -> Recorder {
        let mut r = Recorder::default();
        r.on_status(&CoreStatus::Starting);
        r.on_status(&CoreStatus::Running { started_at: 1000 });
        r
    }

    fn feed(r: &mut Recorder, at_secs: u64, s: ClashConnections) {
        let epoch = r.epoch();
        r.on_sample(epoch, &s, at_secs * 1000, label);
    }

    fn ends(sessions: &[TrafficSession]) -> Vec<(Option<u64>, Option<SessionEnd>)> {
        sessions.iter().map(|s| (s.ended_at, s.end)).collect()
    }

    #[test]
    fn totals_follow_the_counters_and_the_split_follows_each_connection() {
        let mut r = running();
        let p = r"C:\Program Files\Game\game.exe";
        feed(&mut r, 1001, sample(300, 1000, vec![conn("a", &["mudfish-1", "auto", "final"], Some(p), 100, 800), conn("b", &["direct"], Some("C:/x/chrome.exe"), 200, 200)]));
        // `b` closed after 50 more bytes we never saw; `a` grew; `c` is new
        feed(&mut r, 1002, sample(450, 2050, vec![conn("a", &["mudfish-1", "auto", "final"], Some(p), 150, 1800), conn("c", &[], None, 50, 0)]));

        let s = r.current().unwrap();
        assert_eq!((s.upload, s.download), (450, 2050), "the counters are exact");
        assert_eq!((s.started_at, s.last_seen, s.ended_at), (1000, 1002, None));
        assert_eq!(s.peak_down_rate, 1050, "1000 → 2050 within one second");

        let exits: Vec<_> = s.exits.iter().map(|u| (u.key.as_str(), u.label.as_str(), u.kind, u.upload, u.download, u.proxied)).collect();
        assert_eq!(
            exits,
            [
                ("mudfish-1", "node mudfish-1", Some(ExitKind::Mudfish), 150, 1800, 1950),
                ("direct", "直接連線", Some(ExitKind::Direct), 200, 200, 0),
                ("", "未知出口", Some(ExitKind::Other), 50, 0, 0),
            ]
        );
        let apps: Vec<_> = s.apps.iter().map(|u| (u.key.as_str(), u.label.as_str(), u.total(), u.proxied)).collect();
        assert_eq!(apps, [("game.exe", "game.exe", 1950, 1950), ("chrome.exe", "chrome.exe", 400, 0), ("", "未知程式", 50, 0)]);

        let t = &s.timeline;
        assert_eq!(t.bucket_secs, 10);
        assert_eq!((t.upload.clone(), t.download.clone()), (vec![450], vec![2050]));
        assert_eq!((t.proxied.clone(), t.direct.clone()), (vec![1950], vec![400]), "the 50 lost bytes and the unknown exit are in neither");
    }

    #[test]
    fn a_crash_restart_stays_in_the_session_and_its_counters_add_on() {
        let mut r = running();
        feed(&mut r, 1001, sample(100, 1000, vec![conn("a", &["direct"], None, 100, 1000)]));
        r.on_status(&CoreStatus::Reconnecting { attempt: 1, message: "crash".into() });
        r.on_status(&CoreStatus::Running { started_at: 1008 });
        // the new core counts from zero and may reuse connection ids
        feed(&mut r, 1009, sample(10, 20, vec![conn("a", &["direct"], None, 10, 20)]));

        let s = r.current().unwrap();
        assert_eq!((s.upload, s.download, s.restarts, s.started_at), (110, 1020, 1, 1000));
        assert_eq!(s.exits[0].total(), 1130);
        assert_eq!(s.peak_down_rate, 0, "no rate across the restart gap");
        assert!(r.take_finished().is_empty());
    }

    /// `launch` sets up the new core's Clash client before it reports `Running`, so the poller
    /// can sample it in between; `Running` must not count those bytes again.
    #[test]
    fn a_sample_before_the_restarted_core_reports_running_counts_once() {
        let mut r = running();
        feed(&mut r, 1001, sample(100, 1000, vec![conn("a", &["direct"], None, 100, 1000)]));
        r.on_status(&CoreStatus::Reconnecting { attempt: 1, message: "crash".into() });
        feed(&mut r, 1004, sample(10, 20, vec![conn("b", &["direct"], None, 10, 20)]));
        r.on_status(&CoreStatus::Running { started_at: 1004 });
        feed(&mut r, 1005, sample(15, 30, vec![conn("b", &["direct"], None, 15, 30)]));

        let s = r.current().unwrap();
        assert_eq!((s.upload, s.download, s.restarts), (115, 1030, 1));
        assert_eq!(s.exits[0].total(), 1145, "the split agrees with the totals");
    }

    #[test]
    fn connecting_again_closes_the_session_and_starts_another() {
        let mut r = running();
        feed(&mut r, 1001, sample(1, 2, vec![]));
        r.on_status(&CoreStatus::Starting);
        assert!(r.current().is_none(), "nothing runs while starting");
        assert!(r.take_finished().is_empty(), "how it ended waits for the start's outcome");
        assert_eq!(ends(&r.closed()), [(Some(1001), Some(SessionEnd::Reconnected))], "shown meanwhile, ended at its last sample");

        r.on_status(&CoreStatus::Running { started_at: 1502 });
        let done = r.take_finished();
        assert_eq!(ends(&done), [(Some(1001), Some(SessionEnd::Reconnected))]);
        feed(&mut r, 1503, sample(5, 5, vec![]));
        let s = r.current().unwrap();
        assert_ne!(s.id, done[0].id);
        assert_eq!((s.started_at, s.upload, s.restarts), (1502, 5, 0));

        r.on_status(&CoreStatus::Error { message: "gave up".into() });
        r.on_status(&CoreStatus::Stopped);
        assert_eq!(ends(&r.take_finished()), [(Some(1503), Some(SessionEnd::Error))]);
    }

    #[test]
    fn a_reconnect_that_fails_ends_the_old_session_with_the_failure() {
        let mut r = running();
        feed(&mut r, 1001, sample(1, 2, vec![]));
        r.on_status(&CoreStatus::Starting);
        r.on_status(&CoreStatus::Error { message: "health check timed out".into() });
        assert_eq!(ends(&r.take_finished()), [(Some(1001), Some(SessionEnd::Error))]);

        // the user gives up on a start that is still under way
        let mut r = running();
        feed(&mut r, 1001, sample(1, 2, vec![]));
        r.on_status(&CoreStatus::Starting);
        r.on_status(&CoreStatus::Stopped);
        assert_eq!(ends(&r.take_finished()), [(Some(1001), Some(SessionEnd::Stopped))]);
        assert!(r.closed().is_empty() && r.current().is_none());
    }

    #[test]
    fn a_sample_taken_across_a_status_change_is_dropped() {
        let mut r = running();
        let epoch = r.epoch();
        r.on_status(&CoreStatus::Stopped);
        r.on_status(&CoreStatus::Starting);
        r.on_status(&CoreStatus::Running { started_at: 1012 });
        // taken from the old core before the stop, answered after the new start
        r.on_sample(epoch, &sample(5000, 5000, vec![]), 1_012_500, label);
        assert_eq!(r.current().unwrap().upload, 0);
        // a sample before the first `Running` has no session to go to
        let mut r = Recorder::default();
        r.on_status(&CoreStatus::Starting);
        feed(&mut r, 2, sample(5, 5, vec![]));
        assert!(r.current().is_none());
    }

    #[test]
    fn a_session_without_bytes_leaves_no_record() {
        let mut r = running();
        feed(&mut r, 1001, sample(0, 0, vec![]));
        r.on_status(&CoreStatus::Stopped);
        assert!(r.take_finished().is_empty());
        // a failed start never opened one
        let mut r = Recorder::default();
        r.on_status(&CoreStatus::Starting);
        r.on_status(&CoreStatus::Error { message: "check failed".into() });
        assert!(r.take_finished().is_empty() && r.current().is_none());
    }

    #[test]
    fn a_long_session_merges_buckets_and_keeps_every_byte() {
        let mut t = Timeline::default();
        for sec in (0..10_000).step_by(5) {
            t.add(sec, 1, 2, 3, 0);
        }
        assert!(t.upload.len() <= MAX_BUCKETS, "{} buckets", t.upload.len());
        assert_eq!(t.bucket_secs, 80, "10 s doubled until 10 000 s fit into 240 buckets");
        assert_eq!(t.upload.iter().sum::<u64>(), 2000);
        assert_eq!(t.download.iter().sum::<u64>(), 4000);
        assert_eq!(t.proxied.iter().sum::<u64>(), 6000);
        assert_eq!(t.upload[0], 16, "the first bucket covers 80 s at one sample per 5 s");
    }

    #[test]
    fn programs_past_the_limit_are_added_up_as_one() {
        let mut r = running();
        let conns: Vec<_> = (0..15).map(|i| conn(&i.to_string(), &["direct"], Some(&format!("app{i:02}.exe")), 0, 100 + i)).collect();
        feed(&mut r, 1001, sample(0, conns.iter().map(|c| c.download).sum(), conns));
        let apps = r.current().unwrap().apps;
        assert_eq!(apps.len(), MAX_APPS + 1);
        assert_eq!(apps[0].key, "app14.exe", "largest first");
        let other = apps.last().unwrap();
        assert_eq!((other.key.as_str(), other.label.as_str(), other.download), (OTHER_APPS, "其他程式", 100 + 101 + 102));

        // one program however its path is spelled, named as first seen
        let mut r = running();
        feed(&mut r, 1001, sample(0, 3, vec![conn("a", &["direct"], Some(r"C:\Game\Game.exe"), 0, 1), conn("b", &["direct"], Some(r"c:\game\GAME.EXE"), 0, 2)]));
        let apps: Vec<_> = r.current().unwrap().apps.into_iter().map(|u| (u.key, u.label, u.download)).collect();
        assert_eq!(apps, [("game.exe".to_string(), "Game.exe".to_string(), 3)]);
    }

    #[test]
    fn classify_exit_names_nodes_by_kind() {
        let mut profile = Profile::default();
        let node = |tag: &str| proxy_core::ProxyNode {
            tag: tag.into(),
            sid: 0,
            name: format!("name of {tag}"),
            server: "1.2.3.4".into(),
            port: 1080,
            country: String::new(),
            udp: true,
            wireguard: None,
            custom: None,
        };
        profile.nodes.push(node("mudfish-1"));
        let mut custom = node("custom-1");
        custom.custom = Some(proxy_core::model::CustomProxy { protocol: proxy_core::model::ProxyProtocol::Socks5 });
        profile.nodes.push(custom);

        assert_eq!(classify_exit(&profile, "direct"), ("直接連線".into(), ExitKind::Direct));
        assert_eq!(classify_exit(&profile, "mudfish-1"), ("name of mudfish-1".into(), ExitKind::Mudfish));
        assert_eq!(classify_exit(&profile, "custom-1"), ("name of custom-1".into(), ExitKind::Custom));
        assert_eq!(classify_exit(&profile, "mudfish-9"), ("mudfish-9".into(), ExitKind::Other), "a node removed meanwhile");
        assert_eq!(classify_exit(&profile, ""), ("未知出口".into(), ExitKind::Other));
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("proxydesk-stats-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sessions_reach_the_history_file_and_a_left_open_one_comes_back_interrupted() {
        let dir = scratch("files");
        let (history, current) = (dir.join("traffic-history.json"), dir.join("traffic-current.json"));
        let stats = TrafficStats::load(history.clone(), current.clone());
        stats.on_status(&CoreStatus::Starting);
        stats.on_status(&CoreStatus::Running { started_at: 1000 });
        stats.on_sample(stats.epoch(), &sample(10, 20, vec![]), &Profile::default());
        stats.persist(true);
        assert!(current.exists() && !history.exists(), "only the running session was written");
        let running_id = stats.history().sessions[0].id.clone();

        stats.on_status(&CoreStatus::Stopped);
        stats.persist(false);
        assert!(!current.exists(), "the closed session left the running file");
        let saved: TrafficHistory = serde_json::from_slice(&std::fs::read(&history).unwrap()).unwrap();
        assert_eq!(saved.sessions.len(), 1);
        assert_eq!((saved.sessions[0].id.as_str(), saved.sessions[0].end), (running_id.as_str(), Some(SessionEnd::Stopped)));

        // a run killed while connected: its last write of the running file is all there is
        stats.on_status(&CoreStatus::Starting);
        stats.on_status(&CoreStatus::Running { started_at: 2000 });
        stats.on_sample(stats.epoch(), &sample(1, 1, vec![]), &Profile::default());
        stats.persist(true);
        let last_seen = stats.history().sessions[1].last_seen;
        drop(stats);

        let stats = TrafficStats::load(history.clone(), current.clone());
        let sessions = stats.history().sessions;
        assert_eq!(sessions.len(), 2);
        assert_eq!((sessions[1].end, sessions[1].ended_at), (Some(SessionEnd::Interrupted), Some(last_seen)));
        assert!(!current.exists());
        assert_eq!(TrafficStats::load(history.clone(), current.clone()).history().sessions.len(), 2, "filed once");

        stats.clear().unwrap();
        assert!(stats.history().sessions.is_empty());
        assert!(TrafficStats::load(history, current).history().sessions.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_closed_session_is_listed_at_once_and_kept_until_its_file_is_written() {
        let dir = scratch("unsaved");
        let (history, current) = (dir.join("traffic-history.json"), dir.join("traffic-current.json"));
        let stats = TrafficStats::load(history.clone(), current.clone());
        stats.on_status(&CoreStatus::Starting);
        stats.on_status(&CoreStatus::Running { started_at: 1000 });
        stats.on_sample(stats.epoch(), &sample(10, 20, vec![]), &Profile::default());
        stats.persist(true);

        // the page reloads on the status change, before the poller's next `persist`
        stats.on_status(&CoreStatus::Stopped);
        assert_eq!(ends(&stats.history().sessions).len(), 1, "the closed session does not vanish meanwhile");
        assert_eq!(stats.history().sessions[0].end, Some(SessionEnd::Stopped));

        // the history file cannot be written (a directory sits on its name)
        std::fs::create_dir(&history).unwrap();
        stats.persist(false);
        assert_eq!(stats.history().sessions.len(), 1);
        assert!(current.exists(), "the running file stays: it is the only copy on disk");

        std::fs::remove_dir(&history).unwrap();
        stats.persist(false);
        assert!(!current.exists(), "written on the next try, the running file goes");
        let saved: TrafficHistory = serde_json::from_slice(&std::fs::read(&history).unwrap()).unwrap();
        assert_eq!(saved.sessions.len(), 1);
        assert!(!std::fs::read_to_string(&history).unwrap().contains('\n'), "compact JSON");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_history_keeps_the_newest_sessions() {
        let mut history: Vec<TrafficSession> = (0..MAX_SESSIONS as u64 + 5)
            .rev()
            .map(|i| {
                let mut s = Open::new(i).snapshot();
                s.upload = 1;
                s
            })
            .collect();
        trim(&mut history);
        assert_eq!(history.len(), MAX_SESSIONS);
        assert_eq!((history[0].started_at, history.last().unwrap().started_at), (5, MAX_SESSIONS as u64 + 4), "oldest first, the five oldest gone");
    }
}

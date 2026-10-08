//! Group import (「新增群組 → 匯入設定」): turns pasted or uploaded JSON into custom groups.
//!
//! The shape is recognised by its keys:
//! - ProxyDesk: a group as the editor's「複製 JSON」writes it, a list of them, or anything with a
//!   `groups` list (a whole `profile.json`).
//! - Karing: a diversion group as its rule screen shows it (`rule_set_build_in`,
//!   `process_name_windows`, `or`, …) and its preset files (`{"rules": [{"name", "outbound", "switch", …}]}`).
//! - sing-box: a rule-set source (`{"version": 3, "rules": [...]}`, read as one group), a config's
//!   `route.rules` (a group per routing rule) or loose rules.
//!
//! A ProxyDesk or Karing group combines its kinds by its own setting (`match_mode`, `or`). A sing-box
//! rule ANDs its fields except that its domain and IP fields OR, so a rule with several kinds becomes
//! an AND group, split in two where its domain-or-IP part cannot be one ProxyDesk kind. Whatever a
//! group cannot express (regexes, ports, other platforms' apps, unknown rule sets, …) is left out and
//! reported in the notes, so nothing changes meaning silently. Nothing is stored here.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;
use serde_json::{Map, Value};
use ts_rs::TS;

use crate::model::{MatchMode, Profile, RuleGroup, UdpPolicy, TAG_AUTO, TAG_DIRECT, TAG_REJECT};

/// Upper bound on the pasted or uploaded text, in bytes.
pub const MAX_IMPORT_BYTES: usize = 5 * 1024 * 1024;
/// Upper bounds on one import. Each condition becomes a chip in the editor and travels with every
/// profile save, so long lists belong in a built-in rule set.
pub const MAX_IMPORT_CONDITIONS: usize = 10_000;
pub const MAX_IMPORT_GROUPS: usize = 200;

/// What an import found: the groups to add, in the input's order.
#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[ts(export)]
pub struct GroupImport {
    /// What the JSON was read as, e.g.「sing-box 規則集」.
    pub format: String,
    /// Their ids are empty: the caller assigns fresh ones when it adds them.
    pub groups: Vec<ImportedGroup>,
    /// Rules and groups that became no group, and why.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[ts(export)]
pub struct ImportedGroup {
    pub group: RuleGroup,
    /// What was left out or changed while converting it.
    pub notes: Vec<String>,
}

/// What an import is checked against.
pub struct ImportContext<'a> {
    /// The profile the groups go into: an outbound naming a node it lacks becomes `auto`.
    pub profile: &'a Profile,
    /// The built-in rule sets as `catalog:code` (`geosite:netflix`, `acl:BanAD`); others are left out.
    pub rule_sets: &'a [String],
    /// Name for a group the JSON leaves unnamed (the uploaded file's name); empty for the default.
    pub name: &'a str,
}

pub fn parse_group_import(text: &str, ctx: &ImportContext) -> Result<GroupImport, String> {
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err("請貼上 JSON，或選擇 JSON 檔".into());
    }
    if text.len() > MAX_IMPORT_BYTES {
        return Err(format!("內容超過 {} MB。大型清單請改用內建規則集", MAX_IMPORT_BYTES >> 20));
    }
    let doc: Value = serde_json::from_str(text)
        .map_err(|e| format!("不是有效的 JSON：第 {} 行第 {} 欄附近格式錯誤", e.line(), e.column()))?;
    let mut importer = Importer::new(ctx);
    let format = importer.document(&doc)?;
    importer.finish(format)
}

/// The shape an object is written in, told by its keys; it decides how the kinds combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Dialect {
    ProxyDesk,
    Karing,
    SingBox,
}

impl Dialect {
    fn of(m: &Map<String, Value>) -> Self {
        const PROXYDESK: &[&str] =
            &["process_names", "process_paths", "directories", "domain_suffixes", "domain_keywords", "rule_sets", "ip_cidrs", "match_mode", "udp"];
        const KARING: &[&str] =
            &["rule_set_build_in", "process_name_windows", "process_path_windows", "process_dir_windows", "processName", "package", "switch", "or", "groupid"];
        if PROXYDESK.iter().any(|k| m.contains_key(*k)) {
            Dialect::ProxyDesk
        } else if KARING.iter().any(|k| m.contains_key(*k)) {
            Dialect::Karing
        } else {
            Dialect::SingBox
        }
    }

    fn label(self) -> &'static str {
        match self {
            Dialect::ProxyDesk => "ProxyDesk 群組",
            Dialect::Karing => "Karing 分流規則",
            Dialect::SingBox => "sing-box 規則",
        }
    }
}

/// The group list a key fills.
#[derive(Clone, Copy, PartialEq)]
enum Field {
    Names,
    Paths,
    Dirs,
    Suffixes,
    /// sing-box `domain` (exact): ProxyDesk only has suffixes, which also match the subdomains.
    Domains,
    Keywords,
    RuleSets,
    /// Old sing-box `geosite` / `geoip`: bare codes of that catalog.
    Catalog(&'static str),
    Cidrs,
}

fn field(key: &str) -> Option<Field> {
    Some(match key {
        "process_names" | "process_name" | "process_name_windows" | "processName" => Field::Names,
        "process_paths" | "process_path" | "process_path_windows" => Field::Paths,
        "directories" | "process_dir" | "process_dir_windows" => Field::Dirs,
        "domain_suffixes" | "domain_suffix" => Field::Suffixes,
        "domain" | "domains" => Field::Domains,
        "domain_keywords" | "domain_keyword" => Field::Keywords,
        "rule_sets" | "rule_set" | "rule_set_build_in" => Field::RuleSets,
        "geosite" => Field::Catalog("geosite"),
        "geoip" => Field::Catalog("geoip"),
        "ip_cidrs" | "ip_cidr" => Field::Cidrs,
        _ => return None,
    })
}

/// Matchers of other platforms, inert on Windows. Karing keeps one list per platform and ORs them,
/// so they go quietly there; a sing-box rule ANDs them with the rest, so they are reported.
const OTHER_PLATFORMS: &[&str] = &[
    "package",
    "package_name",
    "package_name_regex",
    "process_name_macos",
    "process_path_macos",
    "process_dir_macos",
    "process_name_linux",
    "process_path_linux",
    "process_dir_linux",
];

/// Matchers ProxyDesk has no counterpart for.
const UNSUPPORTED: &[&str] = &[
    "domain_regex",
    "process_path_regex",
    "ip_is_private",
    "ip_version",
    "ip_accept_any",
    "port",
    "port_range",
    "source_port",
    "source_port_range",
    "source_ip_cidr",
    "source_ip_is_private",
    "source_geoip",
    "network",
    "protocol",
    "client",
    "network_type",
    "network_is_expensive",
    "network_is_constrained",
    "network_interface_address",
    "default_interface_address",
    "wifi_ssid",
    "wifi_bssid",
    "query_type",
    "user",
    "user_id",
    "auth_user",
    "inbound",
    "clash_mode",
];

/// What converting one object left out or changed; becomes its group's notes.
#[derive(Default)]
struct Notes {
    unknown_outbound: Option<String>,
    unsupported: BTreeSet<String>,
    /// Logical rules that cannot be a group (`invert`, or an AND that needs two values of one kind).
    skipped_rules: usize,
    unknown_rule_sets: BTreeSet<String>,
    exact_domains: usize,
    bad_domains: usize,
    bad_cidrs: usize,
    foreign_paths: usize,
}

impl Notes {
    fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(o) = &self.unknown_outbound {
            out.push(format!("出口「{o}」在這裡沒有對應，改為「自動選擇」"));
        }
        if !self.unsupported.is_empty() {
            out.push(format!("略過不支援的條件：{}", list(&self.unsupported)));
        }
        if self.skipped_rules > 0 {
            out.push(format!("略過 {} 條無法轉換的規則（反向比對，或要同時符合同一類條件的 AND）", self.skipped_rules));
        }
        if !self.unknown_rule_sets.is_empty() {
            out.push(format!("略過找不到的內建規則集：{}", list(&self.unknown_rule_sets)));
        }
        if self.exact_domains > 0 {
            out.push(format!("{} 個完整網域改以網域比對，也會比對它們的子網域", self.exact_domains));
        }
        if self.bad_domains > 0 {
            out.push(format!("略過 {} 個格式不正確的網域或關鍵字", self.bad_domains));
        }
        if self.bad_cidrs > 0 {
            out.push(format!("略過 {} 個無效的 IP 範圍", self.bad_cidrs));
        }
        if self.foreign_paths > 0 {
            out.push(format!("略過 {} 個不是 Windows 的路徑", self.foreign_paths));
        }
        out
    }
}

/// `a、b、c`: at most five, then how many more.
fn list<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    let items: Vec<&String> = items.into_iter().collect();
    let shown = items.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join("、");
    if items.len() > 5 { format!("{shown} 等 {} 個", items.len()) } else { shown }
}

/// One way a sing-box rule can match: its conditions, and whether all their kinds have to match.
/// A rule is the union of its alternatives.
struct Alt {
    conds: RuleGroup,
    all: bool,
}

struct Importer<'c> {
    ctx: &'c ImportContext<'c>,
    /// Built-in rule sets by lower-cased `catalog:code`, to the catalog's spelling.
    rule_sets: HashMap<String, String>,
    /// A sing-box config's rule-set definitions: tag → the file names in its `url` / `path`.
    rule_set_files: HashMap<String, Vec<String>>,
    /// A sing-box config's outbounds: tag → type.
    outbound_types: HashMap<String, String>,
    groups: Vec<ImportedGroup>,
    dialects: BTreeSet<Dialect>,
    /// Named groups with nothing ProxyDesk can match on.
    empty_named: Vec<String>,
    /// Unnamed rules with nothing ProxyDesk can match on.
    empty_rules: usize,
    /// What those left out: the reason, should nothing at all be importable.
    skipped_notes: Vec<String>,
    not_objects: usize,
}

impl<'c> Importer<'c> {
    fn new(ctx: &'c ImportContext<'c>) -> Self {
        Self {
            ctx,
            rule_sets: ctx.rule_sets.iter().map(|c| (c.to_ascii_lowercase(), c.clone())).collect(),
            rule_set_files: HashMap::new(),
            outbound_types: HashMap::new(),
            groups: Vec::new(),
            dialects: BTreeSet::new(),
            empty_named: Vec::new(),
            empty_rules: 0,
            skipped_notes: Vec::new(),
            not_objects: 0,
        }
    }

    /// Reads the document; returns what it was read as.
    fn document(&mut self, doc: &Value) -> Result<String, String> {
        match doc {
            Value::Array(items) => self.objects(items),
            Value::Object(m) => {
                if let Some(groups) = m.get("groups").and_then(Value::as_array) {
                    self.objects(groups);
                } else if let Some(route) = m.get("route").and_then(Value::as_object) {
                    self.config_outbounds(m);
                    self.rule_set_definitions(route.get("rule_set"));
                    for rule in route.get("rules").and_then(Value::as_array).into_iter().flatten() {
                        match rule.as_object() {
                            Some(r) => self.rule(r),
                            None => self.not_objects += 1,
                        }
                    }
                    return Ok("sing-box 設定（route.rules）".into());
                } else if let Some(rules) = m.get("rules").and_then(Value::as_array) {
                    if !m.contains_key("version") {
                        self.objects(rules);
                    } else {
                        self.rule_set_source(rules);
                        return Ok("sing-box 規則集".into());
                    }
                } else {
                    self.object(m);
                }
            }
            _ => return Err("看不懂這份 JSON：最外層要是物件 {…} 或陣列 […]".into()),
        }
        let labels: Vec<&str> = self.dialects.iter().map(|d| d.label()).collect();
        Ok(if labels.is_empty() { "JSON".into() } else { labels.join("、") })
    }

    fn objects(&mut self, items: &[Value]) {
        for item in items {
            match item.as_object() {
                Some(m) => self.object(m),
                None => self.not_objects += 1,
            }
        }
    }

    fn object(&mut self, m: &Map<String, Value>) {
        let dialect = Dialect::of(m);
        self.dialects.insert(dialect);
        match dialect {
            Dialect::SingBox => self.rule(m),
            _ => self.group(m, dialect),
        }
    }

    /// A ProxyDesk or Karing group: one group, its kinds combined by its own setting.
    fn group(&mut self, m: &Map<String, Value>, dialect: Dialect) {
        let mut notes = Notes::default();
        let outbound = self.outbound(str_of(m, "outbound"), &mut notes);
        let mut g = RuleGroup::new(String::new(), name_of(m), outbound);
        g.enabled = enabled_of(m);
        g.match_mode = match (str_of(m, "match_mode"), m.get("or").and_then(Value::as_bool)) {
            (Some("all"), _) | (None, Some(false)) => MatchMode::All,
            _ => MatchMode::Any,
        };
        g.udp = match str_of(m, "udp") {
            Some("direct") => UdpPolicy::Direct,
            Some("reject") => UdpPolicy::Reject,
            _ => UdpPolicy::Follow,
        };
        for (key, value) in m {
            self.read_field(&mut g, key, value, dialect, &mut notes);
        }
        dedupe(&mut g);
        if g.is_empty() {
            self.skip_empty(g.name, &notes);
        } else {
            self.groups.push(ImportedGroup { group: g, notes: notes.lines() });
        }
    }

    /// A sing-box routing rule: a group per alternative it needs (usually one). Rules that route
    /// nowhere (sniff, DNS hijack, …) are not routes and are passed over.
    fn rule(&mut self, m: &Map<String, Value>) {
        let mut notes = Notes::default();
        let outbound = match str_of(m, "action") {
            Some("reject") => TAG_REJECT.to_string(),
            None | Some("route") => {
                let o = str_of(m, "outbound");
                if o.is_some_and(|o| o == "dns-out" || self.outbound_types.get(o).is_some_and(|t| t == "dns")) {
                    return;
                }
                self.outbound(o, &mut notes)
            }
            Some(_) => return,
        };
        let alts = self.alternatives(m, &mut notes);
        self.push_alternatives(alts, name_of(m), outbound, enabled_of(m), notes);
    }

    /// A sing-box rule-set source: its rules OR together, so they make one group (an AND rule in it
    /// gets a group of its own).
    fn rule_set_source(&mut self, rules: &[Value]) {
        let mut notes = Notes::default();
        let alts: Vec<Alt> = rules.iter().filter_map(Value::as_object).flat_map(|r| self.alternatives(r, &mut notes)).collect();
        if alts.is_empty() {
            // Not one rule to count: say only what was left out.
            return self.skipped_notes.extend(notes.lines());
        }
        self.push_alternatives(alts, String::new(), TAG_AUTO.into(), true, notes);
    }

    /// The alternatives of a sing-box rule: a default rule's own, a logical OR's sub-rules', or one
    /// AND alternative for a logical AND whose sub-rules are distinct kinds.
    fn alternatives(&self, m: &Map<String, Value>, notes: &mut Notes) -> Vec<Alt> {
        if m.get("invert").and_then(Value::as_bool) == Some(true) {
            notes.skipped_rules += 1;
            return Vec::new();
        }
        if str_of(m, "type") == Some("logical") {
            let subs: Vec<Vec<Alt>> = m
                .get("rules")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_object)
                .map(|sub| self.alternatives(sub, notes))
                .collect();
            if str_of(m, "mode") != Some("and") {
                return subs.into_iter().flatten().collect();
            }
            return match and_of(subs) {
                Some(alt) => vec![alt],
                None => {
                    notes.skipped_rules += 1;
                    Vec::new()
                }
            };
        }
        let mut conds = RuleGroup::new(String::new(), String::new(), TAG_AUTO);
        for (key, value) in m {
            self.read_field(&mut conds, key, value, Dialect::SingBox, notes);
        }
        split_default_rule(conds)
    }

    /// Groups for a sing-box rule's alternatives: the OR ones merge into one group, each AND one gets
    /// its own. They share the rule's name (numbered), outbound and switch; its notes go on the first.
    fn push_alternatives(&mut self, alts: Vec<Alt>, name: String, outbound: String, enabled: bool, notes: Notes) {
        let mut any = RuleGroup::new(String::new(), String::new(), outbound.clone());
        let mut groups = Vec::new();
        for alt in alts {
            if alt.all {
                let mut g = alt.conds;
                g.match_mode = MatchMode::All;
                g.outbound = outbound.clone();
                groups.push(g);
            } else {
                merge(&mut any, alt.conds);
            }
        }
        if !any.is_empty() {
            groups.insert(0, any);
        }
        if groups.is_empty() {
            return self.skip_empty(name, &notes);
        }
        let mut notes = Some(notes);
        for (i, mut g) in groups.into_iter().enumerate() {
            g.enabled = enabled;
            g.name = match i {
                _ if name.is_empty() => String::new(),
                0 => name.clone(),
                i => format!("{name} {}", i + 1),
            };
            dedupe(&mut g);
            let mut lines = notes.take().map(|n| n.lines()).unwrap_or_default();
            if g.match_mode == MatchMode::All {
                lines.push("原規則要同時符合這些條件，匯入為「符合全部條件 (AND)」".into());
            }
            self.groups.push(ImportedGroup { group: g, notes: lines });
        }
    }

    fn skip_empty(&mut self, name: String, notes: &Notes) {
        if name.is_empty() {
            self.empty_rules += 1;
        } else {
            self.empty_named.push(name);
        }
        self.skipped_notes.extend(notes.lines());
    }

    /// The group outbound for an imported one: a node of this profile stays, direct and block keep
    /// their meaning (also through a sing-box config's outbound types), anything else is `auto`.
    fn outbound(&self, raw: Option<&str>, notes: &mut Notes) -> String {
        let Some(o) = raw.map(str::trim).filter(|o| !o.is_empty()) else { return TAG_AUTO.into() };
        if self.ctx.profile.node(o).is_some() {
            return o.into();
        }
        let kind = self.outbound_types.get(o).map_or(o, String::as_str);
        if kind.eq_ignore_ascii_case("direct") {
            TAG_DIRECT.into()
        } else if kind.eq_ignore_ascii_case("block") || kind.eq_ignore_ascii_case("reject") {
            TAG_REJECT.into()
        } else if o == TAG_AUTO || kind == "currentSelected" {
            TAG_AUTO.into()
        } else {
            notes.unknown_outbound = Some(o.into());
            TAG_AUTO.into()
        }
    }

    /// Adds the values of `key` to `g`, or notes why they cannot be.
    fn read_field(&self, g: &mut RuleGroup, key: &str, value: &Value, dialect: Dialect, notes: &mut Notes) {
        let Some(f) = field(key) else {
            let reported = UNSUPPORTED.contains(&key) || (dialect == Dialect::SingBox && OTHER_PLATFORMS.contains(&key));
            if reported && !is_blank(value) {
                notes.unsupported.insert(key.to_string());
            }
            return;
        };
        for v in strings(value).into_iter().map(str::trim).filter(|v| !v.is_empty()) {
            match f {
                Field::Names if is_windows_path(v) => g.process_paths.push(v.into()),
                Field::Names => g.process_names.push(normalize_exe(v)),
                Field::Paths | Field::Dirs if !is_windows_path(v) => notes.foreign_paths += 1,
                Field::Paths => g.process_paths.push(v.into()),
                Field::Dirs => g.directories.push(v.into()),
                Field::Suffixes | Field::Domains => match domain_suffix(v) {
                    Some(d) => {
                        notes.exact_domains += usize::from(f == Field::Domains);
                        g.domain_suffixes.push(d);
                    }
                    None => notes.bad_domains += 1,
                },
                Field::Keywords if is_word(v) => g.domain_keywords.push(v.to_ascii_lowercase()),
                Field::Keywords => notes.bad_domains += 1,
                Field::RuleSets | Field::Catalog(_) => {
                    let code = match f {
                        Field::Catalog(catalog) => format!("{catalog}:{v}"),
                        _ => v.to_string(),
                    };
                    match self.rule_set(&code) {
                        Some(c) => g.rule_sets.push(c),
                        None => {
                            notes.unknown_rule_sets.insert(code);
                        }
                    }
                }
                Field::Cidrs if is_cidr(v) => g.ip_cidrs.push(v.into()),
                Field::Cidrs => notes.bad_cidrs += 1,
            }
        }
    }

    /// The built-in rule set a reference names (`geosite:netflix`, a sing-box tag `geosite-netflix`,
    /// or a config tag whose file is one of those), spelled as the catalog spells it.
    fn rule_set(&self, reference: &str) -> Option<String> {
        let files = self.rule_set_files.get(reference).map(Vec::as_slice).unwrap_or_default();
        std::iter::once(reference).chain(files.iter().map(String::as_str)).find_map(|name| {
            let name = name.strip_suffix(".srs").or_else(|| name.strip_suffix(".json")).unwrap_or(name);
            let code = match name.split_once(':') {
                Some((catalog, code)) => format!("{catalog}:{code}"),
                None => {
                    let (catalog, code) = name.split_once('-')?;
                    format!("{catalog}:{}", code.replace("-at-", "@"))
                }
            };
            self.rule_sets.get(&code.to_ascii_lowercase()).cloned()
        })
    }

    /// Remembers a sing-box config's rule-set definitions, to read a tag through its file name.
    fn rule_set_definitions(&mut self, defs: Option<&Value>) {
        for d in defs.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
            if let Some(tag) = str_of(d, "tag") {
                let files = ["url", "path"].iter().filter_map(|k| str_of(d, k)).map(|s| file_name(s).to_string()).collect();
                self.rule_set_files.insert(tag.to_string(), files);
            }
        }
    }

    /// Remembers a sing-box config's outbound (and endpoint) types, to tell direct and block apart.
    fn config_outbounds(&mut self, config: &Map<String, Value>) {
        let lists = ["outbounds", "endpoints"].map(|k| config.get(k).and_then(Value::as_array));
        for o in lists.into_iter().flatten().flatten().filter_map(Value::as_object) {
            if let (Some(tag), Some(kind)) = (str_of(o, "tag"), str_of(o, "type")) {
                self.outbound_types.insert(tag.to_string(), kind.to_string());
            }
        }
    }

    fn finish(mut self, format: String) -> Result<GroupImport, String> {
        let mut notes = Vec::new();
        if !self.empty_named.is_empty() {
            notes.push(format!("沒有 ProxyDesk 可用的條件，已略過：{}", list(&self.empty_named)));
        }
        if self.empty_rules > 0 {
            notes.push(format!("略過 {} 條沒有 ProxyDesk 可用條件的規則", self.empty_rules));
        }
        if self.not_objects > 0 {
            notes.push(format!("略過 {} 個不是物件的項目", self.not_objects));
        }
        if self.groups.is_empty() {
            for n in self.skipped_notes {
                if !notes.contains(&n) {
                    notes.push(n);
                }
            }
            let why = if notes.is_empty() { String::new() } else { format!("（{}）", notes.join("；")) };
            return Err(format!("找不到可以匯入的條件{why}"));
        }
        if self.groups.len() > MAX_IMPORT_GROUPS {
            return Err(format!("群組太多（{} 個），一次最多匯入 {MAX_IMPORT_GROUPS} 個", self.groups.len()));
        }
        let total: usize = self.groups.iter().map(|g| values(&g.group).count()).sum();
        if total > MAX_IMPORT_CONDITIONS {
            return Err(format!("條件太多（共 {total} 項），一次最多匯入 {MAX_IMPORT_CONDITIONS} 項。大型清單請改用內建規則集"));
        }
        // An only unnamed group takes the file's name (or the default); several are named after their first condition.
        let base = Some(self.ctx.name.trim()).filter(|n| !n.is_empty()).unwrap_or("匯入的群組");
        let unnamed = self.groups.iter().filter(|g| g.group.name.is_empty()).count();
        for ig in self.groups.iter_mut().filter(|g| g.group.name.is_empty()) {
            ig.group.name = if unnamed == 1 { base.to_string() } else { describe(&ig.group) };
        }
        Ok(GroupImport { format, groups: self.groups, notes })
    }
}

/// A sing-box default rule as alternatives. Its domain and IP fields OR, and that ANDs with its app
/// and rule-set fields; ProxyDesk's AND treats domain and IP as two kinds, so such a rule with both
/// becomes two AND alternatives (app ∧ domain, app ∧ IP).
fn split_default_rule(conds: RuleGroup) -> Vec<Alt> {
    let [app, domain, ip, rule_set] = kinds(&conds);
    let parts = [app, rule_set, domain || ip].into_iter().filter(|p| *p).count();
    match parts {
        0 => Vec::new(),
        1 => vec![Alt { conds, all: false }],
        _ if domain && ip => {
            let mut by_ip = conds.clone();
            by_ip.domain_suffixes.clear();
            by_ip.domain_keywords.clear();
            let mut by_domain = conds;
            by_domain.ip_cidrs.clear();
            vec![Alt { conds: by_domain, all: true }, Alt { conds: by_ip, all: true }]
        }
        _ => vec![Alt { conds, all: true }],
    }
}

/// A logical AND of sub-rules as one alternative: only when each sub-rule is one alternative whose
/// kinds all have to match and no two of them share a kind (ProxyDesk's AND ORs the values within a kind).
fn and_of(subs: Vec<Vec<Alt>>) -> Option<Alt> {
    let mut conds = RuleGroup::new(String::new(), String::new(), TAG_AUTO);
    let mut seen = [false; 4];
    for sub in subs {
        let [alt] = <[Alt; 1]>::try_from(sub).ok()?;
        let k = kinds(&alt.conds);
        let n = k.iter().filter(|x| **x).count();
        if n == 0 || (n > 1 && !alt.all) {
            return None;
        }
        for (s, k) in seen.iter_mut().zip(k) {
            if k && std::mem::replace(s, true) {
                return None;
            }
        }
        merge(&mut conds, alt.conds);
    }
    let n = seen.iter().filter(|s| **s).count();
    (n > 0).then_some(Alt { conds, all: n > 1 })
}

/// Which user-facing kinds are populated: app, domain, IP, rule set.
fn kinds(g: &RuleGroup) -> [bool; 4] {
    [
        !(g.process_names.is_empty() && g.process_paths.is_empty() && g.directories.is_empty()),
        !(g.domain_suffixes.is_empty() && g.domain_keywords.is_empty()),
        !g.ip_cidrs.is_empty(),
        !g.rule_sets.is_empty(),
    ]
}

fn lists_mut(g: &mut RuleGroup) -> [&mut Vec<String>; 7] {
    [&mut g.process_names, &mut g.process_paths, &mut g.directories, &mut g.domain_suffixes, &mut g.domain_keywords, &mut g.rule_sets, &mut g.ip_cidrs]
}

/// Every condition value, in the order the editor lists them.
fn values(g: &RuleGroup) -> impl Iterator<Item = &String> {
    [&g.process_names, &g.process_paths, &g.directories, &g.domain_suffixes, &g.domain_keywords, &g.rule_sets, &g.ip_cidrs].into_iter().flatten()
}

fn merge(into: &mut RuleGroup, from: RuleGroup) {
    let mut from = from;
    for (a, b) in lists_mut(into).into_iter().zip(lists_mut(&mut from)) {
        a.append(b);
    }
}

fn dedupe(g: &mut RuleGroup) {
    for l in lists_mut(g) {
        let mut seen = HashSet::new();
        l.retain(|v| seen.insert(v.clone()));
    }
}

/// `steam.exe 等 3 項`: a name for an unnamed group, from its first condition.
fn describe(g: &RuleGroup) -> String {
    let first = values(g).next().map(|v| if is_windows_path(v) { file_name(v) } else { v.as_str() }).unwrap_or_default();
    match values(g).count() {
        1 => first.to_string(),
        n => format!("{first} 等 {n} 項"),
    }
}

fn str_of<'v>(m: &'v Map<String, Value>, key: &str) -> Option<&'v str> {
    m.get(key).and_then(Value::as_str)
}

fn name_of(m: &Map<String, Value>) -> String {
    str_of(m, "name").unwrap_or_default().trim().to_string()
}

/// ProxyDesk's `enabled`, Karing's `switch`; on unless the JSON says otherwise.
fn enabled_of(m: &Map<String, Value>) -> bool {
    m.get("enabled").or_else(|| m.get("switch")).and_then(Value::as_bool).unwrap_or(true)
}

/// A string, or the strings of a list (sing-box takes either for its list fields).
fn strings(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s.as_str()],
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn is_blank(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// Mirrors the editor: Windows matches the full file name, so `steam` becomes `steam.exe`.
fn normalize_exe(name: &str) -> String {
    let has_ext = name.rsplit_once('.').is_some_and(|(_, ext)| !ext.is_empty() && ext.bytes().all(|b| b.is_ascii_alphanumeric()));
    if has_ext { name.to_string() } else { format!("{name}.exe") }
}

/// `C:\…`, `C:/…` or a UNC path `\\server\…`.
fn is_windows_path(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')) || (p.len() > 2 && p.starts_with(r"\\"))
}

/// A value with nothing that cannot be part of a domain name (no spaces, separators or wildcards).
fn is_word(v: &str) -> bool {
    !v.is_empty() && !v.contains(|c: char| c.is_whitespace() || matches!(c, '/' | '\\' | ',' | '*' | '?' | '#' | '@' | ':' | '"'))
}

/// A domain suffix as sing-box takes it, lower-cased and without the root dot (`example.com.`).
/// Clash's `+.example.com` (the domain and its subdomains) is `example.com`; `*.example.com`
/// (subdomains only) is `.example.com`.
fn domain_suffix(v: &str) -> Option<String> {
    let v = v.strip_suffix('.').unwrap_or(v);
    let d = match (v.strip_prefix("+."), v.strip_prefix("*.")) {
        (Some(rest), _) => rest.to_string(),
        (_, Some(rest)) => format!(".{rest}"),
        _ => v.to_string(),
    };
    (is_word(&d) && !d.trim_start_matches('.').is_empty()).then(|| d.to_ascii_lowercase())
}

/// An IP or a CIDR range, as sing-box's `ip_cidr` takes them (`203.0.113.5`, `100.64.0.0/10`, `2001:db8::/32`).
fn is_cidr(v: &str) -> bool {
    let (addr, bits) = match v.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (v, None),
    };
    let Ok(ip) = addr.parse::<IpAddr>() else { return false };
    let Some(bits) = bits else { return true };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let canonical = bits == "0" || (!bits.starts_with('0') && bits.len() <= 3 && bits.bytes().all(|b| b.is_ascii_digit()));
    canonical && bits.parse::<u32>().is_ok_and(|n| n <= max)
}

/// The last segment of a path or URL, without a query.
fn file_name(s: &str) -> &str {
    let s = s.split(['?', '#']).next().unwrap_or(s);
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProxyNode, MUDFISH_SOCKS_PORT};

    fn profile() -> Profile {
        Profile {
            nodes: vec![ProxyNode {
                tag: "mudfish-591".into(),
                sid: 591,
                name: "TW Taiwan - Google 1".into(),
                server: "35.236.137.214".into(),
                port: MUDFISH_SOCKS_PORT,
                country: "TW".into(),
                udp: true,
                wireguard: None,
                custom: None,
            }],
            ..Profile::default()
        }
    }

    fn catalog() -> Vec<String> {
        ["geosite:netflix", "geosite:category-ads-all", "geosite:category-ads-all@!cn", "geosite:steam", "geoip:tw", "geoip:jp", "acl:BanAD", "acl:Steam"]
            .map(String::from)
            .to_vec()
    }

    fn import_named(json: &str, name: &str) -> Result<GroupImport, String> {
        let (p, c) = (profile(), catalog());
        parse_group_import(json, &ImportContext { profile: &p, rule_sets: &c, name })
    }

    fn import(json: &str) -> GroupImport {
        import_named(json, "").unwrap()
    }

    fn strs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn reads_back_what_the_editor_copies() {
        let mut g = RuleGroup::new("abc", "遊戲", "mudfish-591");
        g.enabled = false;
        g.process_names = vec!["game.exe".into()];
        g.process_paths = vec![r"C:\Games\Game\game.exe".into()];
        g.directories = vec![r"D:\Riot Games".into()];
        g.domain_suffixes = vec!["riotgames.com".into()];
        g.domain_keywords = vec!["riot".into()];
        g.rule_sets = vec!["acl:Steam".into()];
        g.ip_cidrs = vec!["203.0.113.0/24".into()];
        g.udp = UdpPolicy::Direct;
        g.match_mode = MatchMode::All;
        let r = import(&serde_json::to_string_pretty(&g).unwrap());
        assert_eq!(r.format, "ProxyDesk 群組");
        assert_eq!(r.groups.len(), 1);
        let got = &r.groups[0];
        assert!(got.notes.is_empty(), "{:?}", got.notes);
        assert_eq!(got.group, RuleGroup { id: String::new(), ..g }, "everything but the id comes back");
    }

    #[test]
    fn reads_every_group_of_a_list_or_a_profile() {
        let mut a = RuleGroup::new("a", "A", TAG_DIRECT);
        a.ip_cidrs = vec!["10.0.0.0/8".into()];
        let mut b = RuleGroup::new("b", "B", "mudfish-999");
        b.domain_suffixes = vec!["example.com".into()];
        let list = import(&serde_json::to_string(&[&a, &b]).unwrap());
        assert_eq!(list.groups.iter().map(|g| g.group.name.as_str()).collect::<Vec<_>>(), ["A", "B"]);
        assert_eq!(list.groups[0].group.outbound, TAG_DIRECT);
        // A node this profile does not have falls back to auto, and says so.
        assert_eq!(list.groups[1].group.outbound, TAG_AUTO);
        assert_eq!(list.groups[1].notes, ["出口「mudfish-999」在這裡沒有對應，改為「自動選擇」"]);

        let profile = Profile { groups: vec![a, b], ..profile() };
        let whole = import(&serde_json::to_string(&profile).unwrap());
        assert_eq!(whole.groups.len(), 2);
        assert!(whole.groups.iter().all(|g| g.group.id.is_empty()), "ids are the caller's to assign");
    }

    #[test]
    fn reads_karing_presets() {
        let preset = r#"{"rules": [
            {"rule_set_build_in": ["acl:BanAD", "geosite:category-ads-all"], "outbound": "block", "name": "🛑 Adblock", "switch": false},
            {"rule_set_build_in": ["geosite:no-such-set"], "package": ["com.whatsapp"], "processName": ["WhatsApp.exe", "WhatsApp"],
             "outbound": "currentSelected", "name": "📲 WhatsApp", "switch": true},
            {"rule_set_build_in": ["geosite:apple"], "outbound": "direct", "name": "🍎 Apple", "switch": true},
            {"package": ["com.android.vending"], "outbound": "currentSelected", "name": "Play", "switch": true}
        ]}"#;
        let r = import(preset);
        assert_eq!(r.format, "Karing 分流規則");
        let ads = &r.groups[0].group;
        assert_eq!((ads.name.as_str(), ads.outbound.as_str(), ads.enabled), ("🛑 Adblock", TAG_REJECT, false));
        assert_eq!(strs(&ads.rule_sets), ["acl:BanAD", "geosite:category-ads-all"]);

        // The Windows and macOS names are one app on Windows; the Android package is no Windows matcher.
        let wa = &r.groups[1];
        assert_eq!((wa.group.outbound.as_str(), wa.group.enabled), (TAG_AUTO, true));
        assert_eq!(strs(&wa.group.process_names), ["WhatsApp.exe"]);
        assert_eq!(wa.notes, ["略過找不到的內建規則集：geosite:no-such-set"]);

        // Apple's rule set is not in this catalog and Play only has an Android package: no group.
        assert_eq!(r.groups.len(), 2);
        assert_eq!(r.notes, ["沒有 ProxyDesk 可用的條件，已略過：🍎 Apple、Play"]);
    }

    #[test]
    fn reads_a_karing_group_and_its_logic() {
        let group = r#"{"name": "Game", "type": "", "or": false,
            "process_name_windows": ["Game.exe"], "process_dir_windows": ["C:\\Games\\Game"],
            "process_name_macos": ["Game"], "domain_suffix": ["game.com"], "domain_regex": ["^cdn\\d+\\.game\\.com$"],
            "port": [443], "rule_set": ["my-remote-set"]}"#;
        let r = import(group);
        let g = &r.groups[0];
        assert_eq!(g.group.match_mode, MatchMode::All, "or: false is an AND");
        assert_eq!(strs(&g.group.process_names), ["Game.exe"], "the macOS list is not read");
        assert_eq!(strs(&g.group.directories), [r"C:\Games\Game"]);
        assert_eq!(strs(&g.group.domain_suffixes), ["game.com"]);
        assert_eq!(g.notes, ["略過不支援的條件：domain_regex、port", "略過找不到的內建規則集：my-remote-set"]);
    }

    #[test]
    fn a_rule_set_source_is_one_group() {
        let source = r#"{"version": 3, "rules": [
            {"domain": ["login.game.com"], "domain_suffix": ["game.com", "+.cdn.game.net", "*.edge.game.org", "bad domain", "Game.COM."],
             "domain_keyword": ["Game"], "domain_regex": ["^x$"]},
            {"ip_cidr": ["203.0.113.0/24", "198.51.100.7", "2001:db8::/32", "1.2.3.0/33", "300.1.1.1"]},
            {"type": "logical", "mode": "or", "rules": [{"process_name": ["game"]}, {"domain_suffix": ["game.com"]}]},
            {"domain_suffix": ["never.example"], "invert": true}
        ]}"#;
        let r = import_named(source, "game-rules").unwrap();
        assert_eq!(r.format, "sing-box 規則集");
        assert_eq!(r.groups.len(), 1);
        let g = &r.groups[0];
        assert_eq!((g.group.name.as_str(), g.group.outbound.as_str(), g.group.match_mode), ("game-rules", TAG_AUTO, MatchMode::Any));
        assert_eq!(strs(&g.group.process_names), ["game.exe"]);
        assert_eq!(strs(&g.group.domain_suffixes), ["login.game.com", "game.com", "cdn.game.net", ".edge.game.org"]);
        assert_eq!(strs(&g.group.domain_keywords), ["game"]);
        assert_eq!(strs(&g.group.ip_cidrs), ["203.0.113.0/24", "198.51.100.7", "2001:db8::/32"]);
        assert_eq!(
            g.notes,
            [
                "略過不支援的條件：domain_regex",
                "略過 1 條無法轉換的規則（反向比對，或要同時符合同一類條件的 AND）",
                "1 個完整網域改以網域比對，也會比對它們的子網域",
                "略過 1 個格式不正確的網域或關鍵字",
                "略過 2 個無效的 IP 範圍",
            ]
        );
    }

    #[test]
    fn a_rule_that_ands_kinds_becomes_an_and_group() {
        // sing-box: app AND (domain OR IP). ProxyDesk's AND would need domain AND IP, so it splits.
        let source = r#"{"version": 2, "rules": [
            {"domain_suffix": ["a.com"]},
            {"process_name": ["game.exe"], "domain_suffix": ["game.com"], "ip_cidr": ["1.2.3.0/24"]},
            {"type": "logical", "mode": "and", "rules": [{"process_name": ["x.exe"]}, {"rule_set": ["geosite:steam"]}]},
            {"type": "logical", "mode": "and", "rules": [{"domain_suffix": ["b.com"]}, {"domain_keyword": ["c"]}]}
        ]}"#;
        let r = import_named(source, "rules").unwrap();
        let groups: Vec<_> = r.groups.iter().map(|g| &g.group).collect();
        assert_eq!(groups.len(), 4);
        assert_eq!((groups[0].match_mode, strs(&groups[0].domain_suffixes)), (MatchMode::Any, vec!["a.com"]));
        assert_eq!(groups[1].match_mode, MatchMode::All);
        assert_eq!((strs(&groups[1].process_names), strs(&groups[1].domain_suffixes), groups[1].ip_cidrs.len()), (vec!["game.exe"], vec!["game.com"], 0));
        assert_eq!((strs(&groups[2].process_names), groups[2].domain_suffixes.len(), strs(&groups[2].ip_cidrs)), (vec!["game.exe"], 0, vec!["1.2.3.0/24"]));
        assert_eq!((groups[3].match_mode, strs(&groups[3].process_names), strs(&groups[3].rule_sets)), (MatchMode::All, vec!["x.exe"], vec!["geosite:steam"]));
        // Several unnamed groups are named after their first condition.
        assert_eq!(groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(), ["a.com", "game.exe 等 2 項", "game.exe 等 2 項", "x.exe 等 2 項"]);
        // The source's notes go on its first group; each AND group says why it is one.
        assert_eq!(r.groups[0].notes, ["略過 1 條無法轉換的規則（反向比對，或要同時符合同一類條件的 AND）"]);
        assert!(r.groups[1..].iter().all(|g| g.notes == ["原規則要同時符合這些條件，匯入為「符合全部條件 (AND)」"]));
    }

    #[test]
    fn reads_the_routing_rules_of_a_config() {
        let config = r#"{
            "outbounds": [{"type": "direct", "tag": "DIRECT"}, {"type": "block", "tag": "no"}, {"type": "selector", "tag": "Proxy"},
                          {"type": "urltest", "tag": "auto"}, {"type": "dns", "tag": "dns-out"}],
            "route": {
                "rule_set": [{"tag": "nf", "type": "remote", "format": "binary", "url": "https://example.org/sing/geosite-netflix.srs?raw=1"},
                             {"tag": "mine", "type": "remote", "url": "https://example.org/mine.srs"}],
                "rules": [
                    {"action": "sniff"},
                    {"protocol": "dns", "action": "hijack-dns"},
                    {"port": 53, "outbound": "dns-out"},
                    {"ip_is_private": true, "outbound": "DIRECT"},
                    {"rule_set": ["nf", "mine"], "outbound": "Proxy"},
                    {"rule_set": "geosite-category-ads-all", "action": "reject"},
                    {"domain_suffix": ["ads.example"], "outbound": "no"},
                    {"process_name": ["steam.exe"], "outbound": "mudfish-591", "port": [27015]},
                    {"domain_suffix": ["fast.example"], "outbound": "auto"},
                    "not a rule"
                ]
            }
        }"#;
        let r = import(config);
        assert_eq!(r.format, "sing-box 設定（route.rules）");
        let got: Vec<(&str, Vec<&str>)> = r.groups.iter().map(|g| (g.group.outbound.as_str(), values(&g.group).map(String::as_str).collect())).collect();
        assert_eq!(
            got,
            [
                (TAG_AUTO, vec!["geosite:netflix"]),
                (TAG_REJECT, vec!["geosite:category-ads-all"]),
                (TAG_REJECT, vec!["ads.example"]),
                ("mudfish-591", vec!["steam.exe"]),
                (TAG_AUTO, vec!["fast.example"]),
            ]
        );
        assert_eq!(r.groups[0].notes, ["出口「Proxy」在這裡沒有對應，改為「自動選擇」", "略過找不到的內建規則集：mine"]);
        assert_eq!(r.groups[3].notes, ["略過不支援的條件：port"]);
        assert!(r.groups[4].notes.is_empty(), "a config's own `auto` is ProxyDesk's auto");
        assert_eq!(r.notes, ["略過 1 條沒有 ProxyDesk 可用條件的規則", "略過 1 個不是物件的項目"]);
    }

    #[test]
    fn other_platforms_are_reported_where_a_rule_ands_them() {
        let r = import(r#"{"package_name": ["com.game"], "domain_suffix": ["game.com"]}"#);
        assert_eq!(r.format, "sing-box 規則");
        assert_eq!(r.groups[0].notes, ["略過不支援的條件：package_name"]);
    }

    #[test]
    fn names_values_and_paths_are_cleaned_up() {
        let r = import(
            r#"{"name": "  apps  ", "process_names": ["steam", "steam.exe", "C:\\Games\\x.exe", "Game.Launcher"],
                "process_paths": ["/usr/bin/game", "D:/Games/game.exe", "\\\\nas\\games\\g.exe"],
                "directories": ["~/Games", "E:\\Games"], "rule_sets": ["ACL:banad", "geosite-category-ads-all-at-!cn"]}"#,
        );
        let g = &r.groups[0];
        assert_eq!(g.group.name, "apps");
        assert_eq!(strs(&g.group.process_names), ["steam.exe", "Game.Launcher"]);
        assert_eq!(strs(&g.group.process_paths), [r"C:\Games\x.exe", "D:/Games/game.exe", r"\\nas\games\g.exe"]);
        assert_eq!(strs(&g.group.directories), [r"E:\Games"]);
        assert_eq!(strs(&g.group.rule_sets), ["acl:BanAD", "geosite:category-ads-all@!cn"], "spelled as the catalog spells them");
        assert_eq!(g.notes, ["略過 2 個不是 Windows 的路徑"]);
    }

    #[test]
    fn checks_ip_ranges_like_sing_box() {
        for ok in ["1.2.3.4", "1.2.3.0/24", "0.0.0.0/0", "10.0.0.1/32", "::1", "2001:db8::/32", "::/0"] {
            assert!(is_cidr(ok), "{ok}");
        }
        for bad in ["1.2.3.0/33", "2001:db8::/129", "1.2.3.0/024", "1.2.3.0/", "1.2.3", "01.2.3.4", "1.2.3.4/8x", "example.com", ""] {
            assert!(!is_cidr(bad), "{bad}");
        }
    }

    #[test]
    fn says_why_nothing_can_be_imported() {
        let err = |json: &str| import_named(json, "").unwrap_err();
        assert_eq!(err("  "), "請貼上 JSON，或選擇 JSON 檔");
        assert_eq!(err("{\"name\": \"x\",\n  oops}"), "不是有效的 JSON：第 2 行第 3 欄附近格式錯誤");
        assert_eq!(err("42"), "看不懂這份 JSON：最外層要是物件 {…} 或陣列 […]");
        assert_eq!(err(r#"{"domain_regex": ["^a$"]}"#), "找不到可以匯入的條件（略過 1 條沒有 ProxyDesk 可用條件的規則；略過不支援的條件：domain_regex）");
        assert_eq!(err(r#"{"name": "Mobile", "package": ["com.x"], "switch": true}"#), "找不到可以匯入的條件（沒有 ProxyDesk 可用的條件，已略過：Mobile）");
        assert_eq!(err(r#"{"version": 2, "rules": []}"#), "找不到可以匯入的條件");
        let many = serde_json::json!({ "domain_suffix": (0..=MAX_IMPORT_CONDITIONS).map(|i| format!("d{i}.example")).collect::<Vec<_>>() });
        assert_eq!(err(&many.to_string()), "條件太多（共 10001 項），一次最多匯入 10000 項。大型清單請改用內建規則集");
        // A byte order mark (Notepad's UTF-8) is no error.
        assert_eq!(import("\u{feff}{\"domain_suffix\": \"a.com\"}").groups[0].group.name, "匯入的群組");
    }

    /// The imported values form a config the generator accepts; with SINGBOX_BIN set, sing-box too.
    #[test]
    fn imported_groups_make_a_valid_config() {
        use std::collections::BTreeMap;

        use crate::custom::ProxyAuth;
        use crate::singbox::{generate, GenerateOptions};

        let source = r#"[
            {"name": "mixed", "process_name": ["game"], "domain_suffix": ["*.edge.example.org", "+.example.net"], "ip_cidr": ["198.51.100.7", "2001:db8::/32"]},
            {"name": "sets", "rule_set_build_in": ["geosite:category-ads-all@!cn", "acl:Steam", "geoip:jp"], "domain_keyword": ["Game"], "or": true},
            {"rules": [{"domain_suffix": ["x.example"]}, {"process_path": ["C:/Games/x.exe"]}], "type": "logical", "mode": "or", "outbound": "mudfish-591"}
        ]"#;
        let mut p = profile();
        p.groups = import(source).groups.into_iter().enumerate().map(|(i, g)| RuleGroup { id: format!("g{i}"), ..g.group }).collect();
        assert_eq!(p.groups.len(), 4, "the mixed rule splits into app+domain and app+IP");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/src-tauri/resources/rulesets");
        let (keys, auth) = (BTreeMap::new(), BTreeMap::<String, ProxyAuth>::new());
        let opts = GenerateOptions {
            username: "user",
            password: "pass",
            wireguard_keys: &keys,
            proxy_auth: &auth,
            ruleset_dir: &dir,
            clash_listen: "127.0.0.1:19090",
            clash_secret: "secret",
            cache_id: "run-1",
            self_exe: None,
        };
        let config = generate(&p, &opts).unwrap();
        let Ok(bin) = std::env::var("SINGBOX_BIN") else { return };
        let path = std::env::temp_dir().join("proxydesk-check-import.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let out = std::process::Command::new(bin).args(["check", "-c"]).arg(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(out.status.success(), "sing-box check failed: {}", String::from_utf8_lossy(&out.stderr));
    }
}

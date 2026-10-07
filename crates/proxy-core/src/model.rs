use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// v3: every group, the fixed GeoIP group and `final` take one `outbound` value; the default
/// node and `final_target` are gone (v2: groups had a target plus an outbound).
pub const PROFILE_SCHEMA_VERSION: u32 = 3;
pub const MUDFISH_SOCKS_PORT: u16 = 18081;

/// Outbound tag of the lowest-latency urltest group.
pub const TAG_AUTO: &str = "auto";
pub const TAG_DIRECT: &str = "direct";
/// Profile-only pseudo outbound ("block"). The generator turns it into a `reject` rule action;
/// it is never an outbound tag or a selector member in the sing-box config.
pub const TAG_REJECT: &str = "reject";
/// Selector tags of the fixed GeoIP and final groups and of Global mode (custom groups use
/// `RuleGroup::selector_tag`).
pub const TAG_GEOIP: &str = "geoip";
pub const TAG_FINAL: &str = "final";
pub const TAG_GLOBAL: &str = "global";

/// Everything the user configures. Persisted as JSON; credentials are never stored here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(default)]
#[ts(export)]
pub struct Profile {
    pub schema_version: u32,
    /// Nodes the user picked from the Mudfish list; order is display order.
    pub nodes: Vec<ProxyNode>,
    /// Custom groups in priority order; the first group that matches decides. GeoIP and
    /// `final` are tried after all of them.
    /// Field-level default: a v1 file without `groups` must not pick up the preset group,
    /// because `migrate` converts its `rules` instead.
    #[serde(default)]
    pub groups: Vec<RuleGroup>,
    /// Fixed group after the custom ones: traffic to the IPs of some countries.
    pub geoip: GeoIpGroup,
    /// Fixed last group, for what nothing above matched: `direct`, `reject`, `auto` or a node tag.
    pub final_outbound: String,
    /// Outbound of Global mode: `auto` or a node tag (Direct mode covers `direct`).
    pub global_outbound: String,
    pub mode: Mode,
    pub dns: DnsSettings,
    pub tun: TunSettings,
    /// sing-box log level; `info` logs every connection and DNS query.
    pub log_level: LogLevel,
    /// v1 `rules`, read only to migrate them into `groups`.
    #[serde(rename = "rules", default, skip_serializing)]
    #[ts(skip)]
    pub(crate) legacy_rules: Vec<legacy::Rule>,
    /// v2 `selected` (the default node), read only to migrate it.
    #[serde(rename = "selected", default, skip_serializing)]
    #[ts(skip)]
    pub(crate) legacy_selected: Option<String>,
    /// v2 `final_target`, read only to migrate it into `final_outbound`.
    #[serde(rename = "final_target", default, skip_serializing)]
    #[ts(skip)]
    pub(crate) legacy_final_target: Option<legacy::Target>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            nodes: Vec::new(),
            groups: default_groups(),
            geoip: GeoIpGroup::default(),
            final_outbound: TAG_DIRECT.to_string(),
            global_outbound: TAG_AUTO.to_string(),
            mode: Mode::Rule,
            dns: DnsSettings::default(),
            tun: TunSettings::default(),
            log_level: LogLevel::default(),
            legacy_rules: Vec::new(),
            legacy_selected: None,
            legacy_final_target: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct ProxyNode {
    /// sing-box outbound/endpoint tag, unique within the profile (`mudfish-591`, `warp-1a2b3c4d`).
    pub tag: String,
    /// Mudfish `sid`; 0 for non-Mudfish nodes.
    #[serde(default)]
    pub sid: u32,
    pub name: String,
    /// SOCKS server, or the WireGuard peer host for WARP.
    pub server: String,
    pub port: u16,
    pub country: String,
    /// UDP over this node; Mudfish nodes support UDP ASSOCIATE, but a node can be forced TCP-only.
    #[serde(default = "default_true")]
    pub udp: bool,
    /// Present for Cloudflare WARP (WireGuard) nodes; absent means Mudfish SOCKS5.
    /// The private key is not stored here (Windows Credential Manager, keyed by `tag`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub wireguard: Option<WireguardPeer>,
}

impl ProxyNode {
    pub fn is_wireguard(&self) -> bool {
        self.wireguard.is_some()
    }
}

/// Public half of a WireGuard (WARP) device registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct WireguardPeer {
    pub peer_public_key: String,
    /// Interface addresses assigned by the server, without prefix length.
    pub address_v4: String,
    #[serde(default)]
    pub address_v6: String,
    /// Cloudflare `client_id` bytes (WireGuard reserved field); empty if not provided.
    #[serde(default)]
    pub reserved: Vec<u8>,
    pub mtu: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, TS)]
#[ts(export)]
pub enum Mode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl Mode {
    /// Value used by sing-box `clash_mode` and the Clash API.
    pub fn as_clash(self) -> &'static str {
        match self {
            Mode::Rule => "Rule",
            Mode::Global => "Global",
            Mode::Direct => "Direct",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum LogLevel {
    Debug,
    Info,
    #[default]
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// The parts of a profile that the running core applies live through the Clash API.
/// Everything else in the profile only takes effect on the next start.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selections {
    pub mode: Mode,
    /// Selector tag → the member it is switched to: `global`, `final`, `geoip` and the
    /// `group-<id>` of every enabled group. A blocked (`reject`) group has no selector.
    pub selectors: BTreeMap<String, String>,
}

/// What to do with the UDP traffic of a group routed to the proxy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UdpPolicy {
    /// Same outbound as the group.
    #[default]
    Follow,
    Direct,
    Reject,
}

/// How a group combines its matcher kinds: match any kind (OR) or every populated kind (AND).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum MatchMode {
    /// Match when any matcher kind matches (the original behaviour).
    #[default]
    Any,
    /// Match only when every populated matcher kind matches.
    All,
}

/// A routing group: traffic matching its matchers (apps, domains, rule sets, IP ranges) goes
/// to the group's outbound. `match_mode` says whether any one matcher kind is enough or every
/// populated kind must match; the values within one kind always OR. Groups are tried in
/// priority order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// `TAG_DIRECT`, `TAG_REJECT`, `TAG_AUTO` or a node tag. Every group that is not blocked
    /// has its own selector, so it can switch between direct and a node live via the Clash API.
    #[serde(default = "default_group_outbound")]
    pub outbound: String,
    /// Executable file names (`game.exe`).
    #[serde(default)]
    pub process_names: Vec<String>,
    /// Exact executable paths.
    #[serde(default)]
    pub process_paths: Vec<String>,
    /// Directories; any executable under them matches.
    #[serde(default)]
    pub directories: Vec<String>,
    /// `example.com` matches `example.com` and `*.example.com`.
    #[serde(default)]
    pub domain_suffixes: Vec<String>,
    #[serde(default)]
    pub domain_keywords: Vec<String>,
    /// Built-in rule sets: `geosite:netflix`, `geoip:tw`, `acl:BanAD`.
    #[serde(default)]
    pub rule_sets: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    /// Only applies while the group is proxied; a direct or blocked group keeps the value but
    /// ignores it.
    #[serde(default)]
    pub udp: UdpPolicy,
    /// Combine the matcher kinds with OR (any) or AND (all). Defaults to `Any`, so existing
    /// profiles and migrated groups keep their behaviour; changing it needs a reconnect.
    #[serde(default)]
    pub match_mode: MatchMode,
    /// v2 `target`, read only to migrate it into `outbound`.
    #[serde(rename = "target", default, skip_serializing)]
    #[ts(skip)]
    pub(crate) legacy_target: Option<legacy::Target>,
}

impl RuleGroup {
    pub fn new(id: impl Into<String>, name: impl Into<String>, outbound: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            enabled: true,
            outbound: outbound.into(),
            process_names: Vec::new(),
            process_paths: Vec::new(),
            directories: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_keywords: Vec::new(),
            rule_sets: Vec::new(),
            ip_cidrs: Vec::new(),
            udp: UdpPolicy::Follow,
            match_mode: MatchMode::default(),
            legacy_target: None,
        }
    }

    /// sing-box tag of this group's own selector (stable across restarts).
    pub fn selector_tag(&self) -> String {
        format!("group-{}", self.id)
    }

    pub fn is_empty(&self) -> bool {
        [
            &self.process_names,
            &self.process_paths,
            &self.directories,
            &self.domain_suffixes,
            &self.domain_keywords,
            &self.rule_sets,
            &self.ip_cidrs,
        ]
        .iter()
        .all(|v| v.iter().all(|s| s.trim().is_empty()))
    }
}

/// The fixed group below the custom ones: traffic whose destination IP belongs to one of
/// the countries. It cannot be removed or disabled; the generator only skips it while
/// `countries` is empty.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(default)]
#[ts(export)]
pub struct GeoIpGroup {
    /// geoip rule-set codes (`tw`, `jp`), each backed by `geoip/<code>.srs`.
    pub countries: Vec<String>,
    /// `direct`, `reject`, `auto` or a node tag.
    pub outbound: String,
}

impl Default for GeoIpGroup {
    fn default() -> Self {
        Self { countries: vec!["tw".to_string()], outbound: TAG_DIRECT.to_string() }
    }
}

impl GeoIpGroup {
    /// The country codes without blanks and repeats, in the user's order.
    pub fn codes(&self) -> Vec<&str> {
        let mut seen = BTreeSet::new();
        self.countries.iter().map(|c| c.trim()).filter(|c| !c.is_empty() && seen.insert(*c)).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(default)]
#[ts(export)]
pub struct DnsSettings {
    /// Proxied domains resolve to fake IPs so the node resolves them remotely.
    /// Required for remote resolution: sing-box hands SOCKS5 the IP otherwise (verified in M0).
    /// Only the domains of proxied custom groups get fake IPs: everything else resolves to its
    /// real IP, which GeoIP matches on.
    pub fakeip: bool,
    /// Reject UDP 443 for proxied domains so browsers fall back to TCP through the proxy.
    pub block_quic_for_proxied: bool,
    /// Answer only A records. Mudfish nodes are IPv4-only, so an app that picks an AAAA
    /// answer gets its proxied connection dropped (EOF); DNS cannot be split per app on
    /// Windows (queries come from the DNS Client service), so this is global.
    pub ipv4_only: bool,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self { fakeip: true, block_quic_for_proxied: true, ipv4_only: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(default)]
#[ts(export)]
pub struct TunSettings {
    pub mtu: u32,
    /// Windows: prevents DNS leaks from multihomed resolution; may break e.g. VirtualBox.
    pub strict_route: bool,
    /// LAN / private addresses always go direct.
    pub bypass_lan: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self { mtu: 9000, strict_route: true, bypass_lan: true }
    }
}

fn default_true() -> bool {
    true
}

fn default_group_outbound() -> String {
    TAG_AUTO.to_string()
}

fn default_groups() -> Vec<RuleGroup> {
    let mut ads = RuleGroup::new("preset-ads", "廣告阻擋", TAG_REJECT);
    ads.enabled = false;
    ads.rule_sets = vec!["geosite:category-ads-all".into()];
    vec![ads]
}

/// `auto` or a node that is still in the list.
fn outbound_exists(nodes: &[ProxyNode], tag: &str) -> bool {
    tag == TAG_AUTO || nodes.iter().any(|n| n.tag == tag)
}

impl Profile {
    pub fn node(&self, tag: &str) -> Option<&ProxyNode> {
        self.nodes.iter().find(|n| n.tag == tag)
    }

    /// `outbound` if it still refers to something that exists, otherwise `auto` (a node that
    /// was removed). `direct` and `reject` always exist.
    pub fn effective_outbound<'a>(&self, outbound: &'a str) -> &'a str {
        if matches!(outbound, TAG_DIRECT | TAG_REJECT) || outbound_exists(&self.nodes, outbound) {
            outbound
        } else {
            TAG_AUTO
        }
    }

    /// Global mode's outbound: `auto` or an existing node, otherwise `auto`.
    pub fn effective_global(&self) -> &str {
        if outbound_exists(&self.nodes, &self.global_outbound) {
            &self.global_outbound
        } else {
            TAG_AUTO
        }
    }

    /// Whether traffic sent to `outbound` leaves through a node, i.e. it is neither direct
    /// nor blocked. Drives FakeIP DNS rules, the QUIC block and the UDP guard.
    pub fn is_proxied(&self, outbound: &str) -> bool {
        !matches!(self.effective_outbound(outbound), TAG_DIRECT | TAG_REJECT)
    }

    /// Effective live choices (stale references already resolved to their fallbacks). Global
    /// mode always has a selector; `final`, GeoIP (only while it has countries) and each enabled
    /// group have one unless blocked. The generator builds its selectors from this same list,
    /// so the config and the live switches cannot diverge.
    pub fn selections(&self) -> Selections {
        let mut selectors = BTreeMap::new();
        selectors.insert(TAG_GLOBAL.to_string(), self.effective_global().to_string());
        let mut put = |selector: String, outbound: &str| {
            let outbound = self.effective_outbound(outbound);
            if outbound != TAG_REJECT {
                selectors.insert(selector, outbound.to_string());
            }
        };
        put(TAG_FINAL.to_string(), &self.final_outbound);
        if !self.geoip.codes().is_empty() {
            put(TAG_GEOIP.to_string(), &self.geoip.outbound);
        }
        for g in self.groups.iter().filter(|g| g.enabled) {
            put(g.selector_tag(), &g.outbound);
        }
        Selections { mode: self.mode, selectors }
    }

    /// Upgrades older files in place. Returns whether anything changed: the caller then keeps a
    /// backup of the old file and saves, because the old fields are not written back. A file of
    /// the current schema is never converted again: old keys that linger in it (a hand edit, a
    /// downgrade) are ignored and the next save drops them.
    pub fn migrate(&mut self) -> bool {
        if self.schema_version >= PROFILE_SCHEMA_VERSION {
            return false;
        }
        // v1 → v2: one-matcher rules become groups (still carrying their `target`).
        if self.groups.is_empty() {
            self.groups = self.legacy_rules.drain(..).map(legacy::Rule::into_group).collect();
        }
        self.legacy_rules.clear();
        self.migrate_v2();
        self.schema_version = PROFILE_SCHEMA_VERSION;
        true
    }

    /// v2 → v3. The old default node S (`selected`: `direct`, `auto` or an existing node,
    /// otherwise `auto`) is what "use the default node" meant, so it becomes the outbound of
    /// everything that followed it and every route stays as it was. GeoIP starts out with the
    /// same outbound as `final`, so it changes no traffic either.
    ///
    /// Two old behaviours with a direct S cannot be carried over as they were:
    /// - Global mode followed S, so it sent everything direct. v3's Global has no `direct`; the
    ///   profile becomes Direct mode instead, which does exactly that.
    /// - A group that followed S is a plain direct group now, and a direct group has no UDP
    ///   guard, QUIC block or FakeIP rule. Its `udp` policy stays in the file but is inert (a
    ///   `reject` policy no longer blocks UDP) until the group is pointed at a node again.
    fn migrate_v2(&mut self) {
        let selected = self.legacy_selected.take().unwrap_or_default();
        let s = if selected == TAG_DIRECT || outbound_exists(&self.nodes, &selected) { selected } else { TAG_AUTO.to_string() };

        for g in &mut self.groups {
            let Some(target) = g.legacy_target.take() else { continue };
            // A v2 proxied group used S when it followed the default node or its node was removed.
            let uses_default = g.outbound == legacy::FOLLOW_DEFAULT || !outbound_exists(&self.nodes, &g.outbound);
            g.outbound = match target {
                legacy::Target::Direct => TAG_DIRECT.to_string(),
                legacy::Target::Reject => TAG_REJECT.to_string(),
                legacy::Target::Proxy if uses_default => s.clone(),
                legacy::Target::Proxy => g.outbound.clone(),
            };
        }

        let final_outbound = match self.legacy_final_target.take() {
            Some(legacy::Target::Proxy) => s.clone(),
            Some(legacy::Target::Reject) => TAG_REJECT.to_string(),
            Some(legacy::Target::Direct) | None => TAG_DIRECT.to_string(),
        };
        // Global mode followed the default node. A direct one sent everything direct, which is
        // what Direct mode does; Global itself only knows `auto` and nodes.
        if s == TAG_DIRECT && self.mode == Mode::Global {
            self.mode = Mode::Direct;
        }
        self.global_outbound = if s == TAG_DIRECT { TAG_AUTO.to_string() } else { s };
        self.geoip = GeoIpGroup { outbound: final_outbound.clone(), ..GeoIpGroup::default() };
        self.final_outbound = final_outbound;
    }
}

/// Shapes of older schema versions, kept only to migrate them.
mod legacy {
    use super::*;

    /// v2 `target` of a group and `final_target` of the profile; v1 rules had it too.
    #[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum Target {
        Proxy,
        Direct,
        Reject,
    }

    /// v2 `outbound` of a proxied group that followed the default node.
    pub const FOLLOW_DEFAULT: &str = "proxy";

    /// Schema v1 rule shape (one matcher kind per rule).
    #[derive(Debug, Clone, Deserialize, PartialEq)]
    pub struct Rule {
        id: String,
        name: String,
        enabled: bool,
        target: Target,
        #[serde(flatten)]
        matcher: Matcher,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Matcher {
        App {
            #[serde(default)]
            process_names: Vec<String>,
            #[serde(default)]
            process_paths: Vec<String>,
            #[serde(default)]
            directories: Vec<String>,
            #[serde(default)]
            udp: UdpPolicy,
        },
        Domain {
            #[serde(default)]
            suffixes: Vec<String>,
            #[serde(default)]
            keywords: Vec<String>,
        },
        RuleSet {
            codes: Vec<String>,
        },
        IpCidr {
            cidrs: Vec<String>,
        },
    }

    impl Rule {
        /// A v2 group, still to be converted by `Profile::migrate_v2`. v1 proxy rules used
        /// the default node, which is what `FOLLOW_DEFAULT` stands for.
        pub fn into_group(self) -> RuleGroup {
            let mut g = RuleGroup::new(self.id, self.name, FOLLOW_DEFAULT);
            g.legacy_target = Some(self.target);
            g.enabled = self.enabled;
            match self.matcher {
                Matcher::App { process_names, process_paths, directories, udp } => {
                    g.process_names = process_names;
                    g.process_paths = process_paths;
                    g.directories = directories;
                    g.udp = udp;
                }
                Matcher::Domain { suffixes, keywords } => {
                    g.domain_suffixes = suffixes;
                    g.domain_keywords = keywords;
                }
                Matcher::RuleSet { codes } => g.rule_sets = codes,
                Matcher::IpCidr { cidrs } => g.ip_cidrs = cidrs,
            }
            g
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(tag: &str) -> ProxyNode {
        ProxyNode {
            tag: tag.into(),
            sid: 1,
            name: "n".into(),
            server: "1.1.1.1".into(),
            port: MUDFISH_SOCKS_PORT,
            country: "TW".into(),
            udp: true,
            wireguard: None,
        }
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn outbounds(p: &Profile) -> Vec<&str> {
        p.groups.iter().map(|g| g.outbound.as_str()).collect()
    }

    #[test]
    fn migrates_v1_rules_into_groups() {
        let v1 = r#"{
          "schema_version": 1,
          "nodes": [],
          "rules": [
            {"id": "a", "name": "Game", "enabled": true, "target": "proxy", "kind": "app",
             "process_names": ["game.exe"], "process_paths": [], "directories": ["C:\\Games"], "udp": "direct"},
            {"id": "b", "name": "Site", "enabled": false, "target": "direct", "kind": "domain",
             "suffixes": ["example.com"], "keywords": ["foo"]},
            {"id": "c", "name": "Ads", "enabled": true, "target": "reject", "kind": "rule_set", "codes": ["geosite:category-ads-all"]}
          ]
        }"#;
        let mut p: Profile = serde_json::from_str(v1).unwrap();
        assert!(p.migrate());
        assert_eq!(p.schema_version, 3);
        assert_eq!(p.groups.len(), 3);
        assert_eq!(p.groups[0].process_names, ["game.exe"]);
        assert_eq!(p.groups[0].directories, ["C:\\Games"]);
        assert_eq!(p.groups[0].udp, UdpPolicy::Direct);
        assert!(!p.groups[1].enabled);
        assert_eq!(p.groups[1].domain_keywords, ["foo"]);
        assert_eq!(p.groups[2].rule_sets, ["geosite:category-ads-all"]);
        // v1 rules followed the default node; the file has none, so it was `auto`
        assert_eq!(outbounds(&p), [TAG_AUTO, TAG_DIRECT, TAG_REJECT]);
        assert_eq!(p.final_outbound, TAG_DIRECT);
        assert_eq!(p.global_outbound, TAG_AUTO);
        assert_eq!(p.geoip, GeoIpGroup { countries: vec!["tw".into()], outbound: TAG_DIRECT.into() });

        let saved = serde_json::to_value(&p).unwrap();
        for legacy_key in ["rules", "selected", "final_target"] {
            assert!(saved.get(legacy_key).is_none(), "{legacy_key} is not written back");
        }
        assert!(saved["groups"][0].get("target").is_none());
        assert!(!p.migrate(), "second migrate is a no-op");
    }

    /// A v0.4 profile whose default node is `direct`: groups that followed it go direct, and
    /// Global mode (which then sent everything direct) becomes Direct mode.
    #[test]
    fn migrates_v2_with_direct_default_node() {
        let v2 = r#"{
          "schema_version": 2,
          "nodes": [
            {"tag": "mudfish-1", "sid": 1, "name": "JP", "server": "1.1.1.1", "port": 18081, "country": "JP"},
            {"tag": "warp-1", "name": "WARP", "server": "engage.cloudflareclient.com", "port": 2408, "country": "CF",
             "wireguard": {"peer_public_key": "k", "address_v4": "172.16.0.2", "mtu": 1280}}
          ],
          "selected": "direct",
          "groups": [
            {"id": "ads", "name": "ads", "enabled": false, "target": "reject", "outbound": "proxy", "rule_sets": ["geosite:category-ads-all"]},
            {"id": "ipsb", "name": "ip.sb", "enabled": true, "target": "proxy", "outbound": "warp-1", "domain_suffixes": ["ip.sb"]},
            {"id": "cs", "name": "cs", "enabled": true, "target": "direct", "outbound": "proxy", "process_names": ["cs2.exe"]},
            {"id": "web", "name": "web", "enabled": true, "target": "proxy", "outbound": "proxy", "domain_suffixes": ["example.com"], "udp": "reject"}
          ],
          "final_target": "direct",
          "mode": "Global"
        }"#;
        let mut p: Profile = serde_json::from_str(v2).unwrap();
        assert!(p.migrate());
        assert_eq!(p.schema_version, 3);
        assert_eq!(outbounds(&p), [TAG_REJECT, "warp-1", TAG_DIRECT, TAG_DIRECT], "WARP stays; \"proxy\" became the default node, direct");
        assert_eq!(p.final_outbound, TAG_DIRECT);
        assert_eq!(p.global_outbound, TAG_AUTO, "Global has no `direct`, so it keeps the default choice");
        assert_eq!(p.mode, Mode::Direct, "Global followed the direct default node: everything went direct, as Direct mode does");
        assert_eq!(p.geoip, GeoIpGroup { countries: vec!["tw".into()], outbound: TAG_DIRECT.into() });
        assert_eq!(p.groups[0].rule_sets, ["geosite:category-ads-all"]);
        assert!(!p.groups[0].enabled);
        assert_eq!(p.groups[3].udp, UdpPolicy::Reject, "the UDP policy is kept, though a direct group ignores it");
        assert!(!p.migrate());
    }

    /// Global mode followed the default node: it stays Global unless that node was `direct`.
    #[test]
    fn migration_keeps_global_mode_unless_the_default_node_was_direct() {
        let v2 = |selected: &str, mode: &str| {
            format!(
                r#"{{"schema_version": 2, "mode": "{mode}", "selected": "{selected}",
                    "nodes": [{{"tag": "mudfish-1", "sid": 1, "name": "JP", "server": "1.1.1.1", "port": 18081, "country": "JP"}}],
                    "groups": [], "final_target": "direct"}}"#
            )
        };
        let migrated = |selected: &str, mode: &str| {
            let mut p: Profile = serde_json::from_str(&v2(selected, mode)).unwrap();
            assert!(p.migrate());
            (p.mode, p.global_outbound)
        };
        assert_eq!(migrated("mudfish-1", "Global"), (Mode::Global, "mudfish-1".to_string()), "a node default: Global keeps that node");
        assert_eq!(migrated("auto", "Global"), (Mode::Global, TAG_AUTO.to_string()));
        assert_eq!(migrated("gone", "Global"), (Mode::Global, TAG_AUTO.to_string()), "a removed default node was `auto`");
        assert_eq!(migrated("direct", "Global"), (Mode::Direct, TAG_AUTO.to_string()), "a direct default node: Global became Direct");
        // only Global mode is converted
        assert_eq!(migrated("direct", "Rule"), (Mode::Rule, TAG_AUTO.to_string()));
        assert_eq!(migrated("direct", "Direct"), (Mode::Direct, TAG_AUTO.to_string()));
        assert_eq!(migrated("mudfish-1", "Rule"), (Mode::Rule, "mudfish-1".to_string()));
    }

    /// A file that already has the current schema is left alone, whatever old keys it carries.
    #[test]
    fn a_current_schema_file_is_never_converted_again() {
        let v3 = r#"{
          "schema_version": 3,
          "nodes": [{"tag": "mudfish-1", "sid": 1, "name": "JP", "server": "1.1.1.1", "port": 18081, "country": "JP"}],
          "groups": [{"id": "a", "name": "a", "enabled": true, "target": "reject", "outbound": "mudfish-1", "domain_suffixes": ["a.com"]}],
          "geoip": {"countries": ["jp"], "outbound": "mudfish-1"},
          "final_outbound": "reject",
          "global_outbound": "mudfish-1",
          "mode": "Global",
          "selected": "direct",
          "final_target": "proxy",
          "rules": [{"id": "r", "name": "r", "enabled": true, "target": "proxy", "kind": "domain", "suffixes": ["r.com"], "keywords": []}]
        }"#;
        let mut p: Profile = serde_json::from_str(v3).unwrap();
        assert!(!p.migrate(), "nothing to convert");
        // the stray `target`, `selected`, `final_target` and `rules` changed nothing
        assert_eq!(outbounds(&p), ["mudfish-1"], "not turned into a blocked group by its stray `target`");
        assert_eq!(p.geoip, GeoIpGroup { countries: vec!["jp".into()], outbound: "mudfish-1".into() });
        assert_eq!((p.final_outbound.as_str(), p.global_outbound.as_str(), p.mode), (TAG_REJECT, "mudfish-1", Mode::Global));
        assert_eq!(p.groups.len(), 1, "the stray v1 rule did not become a group");

        // saving drops the stray keys
        let saved = serde_json::to_value(&p).unwrap();
        for stray in ["rules", "selected", "final_target"] {
            assert!(saved.get(stray).is_none(), "{stray} is dropped on save");
        }
        assert!(saved["groups"][0].get("target").is_none());
        assert_eq!((saved["final_outbound"].as_str(), saved["global_outbound"].as_str()), (Some("reject"), Some("mudfish-1")));
    }

    /// Default node = a node, `final` = proxy: both now name that node, as does GeoIP.
    #[test]
    fn migrates_v2_with_node_default_and_proxied_final() {
        let v2 = r#"{
          "schema_version": 2,
          "nodes": [
            {"tag": "mudfish-1", "sid": 1, "name": "JP", "server": "1.1.1.1", "port": 18081, "country": "JP"},
            {"tag": "mudfish-2", "sid": 2, "name": "US", "server": "2.2.2.2", "port": 18081, "country": "US"}
          ],
          "selected": "mudfish-1",
          "groups": [
            {"id": "a", "name": "a", "enabled": true, "target": "proxy", "outbound": "proxy", "domain_suffixes": ["a.com"]},
            {"id": "b", "name": "b", "enabled": true, "target": "proxy", "outbound": "mudfish-2", "domain_suffixes": ["b.com"]},
            {"id": "c", "name": "c", "enabled": true, "target": "proxy", "outbound": "auto", "domain_suffixes": ["c.com"]},
            {"id": "d", "name": "d", "enabled": true, "target": "proxy", "outbound": "mudfish-9", "domain_suffixes": ["d.com"]},
            {"id": "e", "name": "e", "enabled": true, "target": "proxy", "outbound": "direct", "domain_suffixes": ["e.com"]}
          ],
          "final_target": "proxy"
        }"#;
        let mut p: Profile = serde_json::from_str(v2).unwrap();
        assert!(p.migrate());
        assert_eq!(
            outbounds(&p),
            ["mudfish-1", "mudfish-2", TAG_AUTO, "mudfish-1", "mudfish-1"],
            "follow-default, a removed node and v2's invalid `direct` all became the default node"
        );
        assert_eq!(p.final_outbound, "mudfish-1");
        assert_eq!(p.global_outbound, "mudfish-1");
        assert_eq!(p.geoip.outbound, "mudfish-1");
        assert_eq!(p.geoip.countries, ["tw"]);
    }

    #[test]
    fn migration_resolves_a_removed_default_node_to_auto() {
        let v2 = r#"{
          "schema_version": 2,
          "selected": "mudfish-9",
          "groups": [{"id": "a", "name": "a", "enabled": true, "target": "proxy", "outbound": "proxy", "domain_suffixes": ["a.com"]}],
          "final_target": "reject"
        }"#;
        let mut p: Profile = serde_json::from_str(v2).unwrap();
        assert!(p.migrate());
        assert_eq!(outbounds(&p), [TAG_AUTO]);
        assert_eq!(p.global_outbound, TAG_AUTO);
        assert_eq!((p.final_outbound.as_str(), p.geoip.outbound.as_str()), (TAG_REJECT, TAG_REJECT));
    }

    #[test]
    fn missing_dns_fields_take_defaults() {
        let p: Profile = serde_json::from_str(r#"{"dns": {"fakeip": true, "block_quic_for_proxied": false}}"#).unwrap();
        assert!(p.dns.ipv4_only);
        assert!(!p.dns.block_quic_for_proxied);
    }

    #[test]
    fn fresh_profile_needs_no_migration() {
        let mut p = Profile::default();
        assert!(!p.migrate());
        assert_eq!(p.groups.len(), 1);
        assert_eq!(p.groups[0].outbound, TAG_REJECT);
        assert_eq!(p.geoip, GeoIpGroup { countries: vec!["tw".into()], outbound: TAG_DIRECT.into() });
        assert_eq!((p.final_outbound.as_str(), p.global_outbound.as_str()), (TAG_DIRECT, TAG_AUTO));
    }

    #[test]
    fn v3_profile_round_trips() {
        let mut p = Profile { final_outbound: "mudfish-1".into(), ..Profile::default() };
        p.nodes.push(node("mudfish-1"));
        p.groups.push(RuleGroup::new("g", "g", "mudfish-1"));
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["schema_version"], 3);
        for legacy_key in ["rules", "selected", "final_target"] {
            assert!(json.get(legacy_key).is_none());
        }
        assert!(json["groups"][1].get("target").is_none());
        let mut back: Profile = serde_json::from_value(json).unwrap();
        assert_eq!(back, p);
        assert!(!back.migrate());
    }

    #[test]
    fn selections_have_a_live_choice_per_enabled_group() {
        let mut p = Profile { mode: Mode::Global, global_outbound: "gone".into(), final_outbound: "mudfish-9".into(), ..Profile::default() };
        let mut off = RuleGroup::new("off", "off", TAG_AUTO);
        off.enabled = false;
        p.groups = vec![
            RuleGroup::new("a", "a", TAG_AUTO),
            off,
            RuleGroup::new("d", "d", TAG_DIRECT),
            RuleGroup::new("r", "r", TAG_REJECT),
            RuleGroup::new("stale", "stale", "mudfish-9"),
        ];
        let s = p.selections();
        assert_eq!(s.mode, Mode::Global);
        assert_eq!(
            s.selectors,
            map(&[
                ("final", TAG_AUTO), // a removed node falls back to auto
                ("geoip", TAG_DIRECT),
                ("global", TAG_AUTO),
                ("group-a", TAG_AUTO),
                ("group-d", TAG_DIRECT),
                ("group-stale", TAG_AUTO),
            ]),
            "disabled and blocked groups have no selector"
        );

        p.nodes.push(node("mudfish-1"));
        p.global_outbound = "mudfish-1".into();
        p.final_outbound = TAG_DIRECT.into();
        p.geoip.outbound = "mudfish-1".into();
        let s = p.selections();
        assert_eq!((s.selectors["global"].as_str(), s.selectors["final"].as_str(), s.selectors["geoip"].as_str()), ("mudfish-1", TAG_DIRECT, "mudfish-1"));
    }

    #[test]
    fn selections_skip_blocked_final_and_geoip_without_countries() {
        let mut p = Profile { final_outbound: TAG_REJECT.into(), ..Profile::default() };
        assert_eq!(p.selections().selectors, map(&[("geoip", TAG_DIRECT), ("global", TAG_AUTO)]));

        p.geoip.outbound = TAG_REJECT.into();
        assert_eq!(p.selections().selectors, map(&[("global", TAG_AUTO)]), "blocked fixed groups have no selector");

        p.final_outbound = TAG_DIRECT.into();
        p.geoip = GeoIpGroup { countries: vec![" ".into(), String::new()], outbound: TAG_DIRECT.into() };
        assert_eq!(p.selections().selectors, map(&[("final", TAG_DIRECT), ("global", TAG_AUTO)]), "no countries: no GeoIP rule, so no selector");
    }

    #[test]
    fn geoip_codes_are_trimmed_and_unique() {
        let g = GeoIpGroup { countries: vec![" tw".into(), "jp".into(), String::new(), "tw".into(), "  ".into()], outbound: TAG_AUTO.into() };
        assert_eq!(g.codes(), ["tw", "jp"]);
    }

    #[test]
    fn log_level_defaults_to_warn_for_old_profiles() {
        let p: Profile = serde_json::from_str("{}").unwrap();
        assert_eq!(p.log_level, LogLevel::Warn);
    }

    /// A group saved before match modes existed keeps matching with OR, and no schema bump is needed.
    #[test]
    fn match_mode_defaults_to_any_for_old_groups_and_is_snake_case() {
        let old = r#"{"schema_version": 3, "groups": [
          {"id": "a", "name": "a", "enabled": true, "outbound": "auto", "process_names": ["a.exe"], "ip_cidrs": ["1.2.3.0/24"]}]}"#;
        let mut p: Profile = serde_json::from_str(old).unwrap();
        assert!(!p.migrate(), "a current-schema file needs no conversion for the new field");
        assert_eq!(p.groups[0].match_mode, MatchMode::Any);
        assert_eq!(RuleGroup::new("n", "n", TAG_AUTO).match_mode, MatchMode::Any);

        p.groups[0].match_mode = MatchMode::All;
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["groups"][0]["match_mode"], "all");
        assert_eq!(serde_json::from_value::<Profile>(json).unwrap(), p, "AND survives a save and load");
        assert_eq!(serde_json::to_value(MatchMode::Any).unwrap(), "any");
    }

    #[test]
    fn outbounds_fall_back_to_auto_when_a_node_is_removed() {
        let mut p = Profile::default();
        for tag in [TAG_DIRECT, TAG_REJECT, TAG_AUTO] {
            assert_eq!(p.effective_outbound(tag), tag);
        }
        assert_eq!(p.effective_outbound("mudfish-1"), TAG_AUTO);
        assert_eq!(p.effective_outbound("proxy"), TAG_AUTO, "v2's follow-the-default value means nothing any more");
        p.nodes.push(node("mudfish-1"));
        assert_eq!(p.effective_outbound("mudfish-1"), "mudfish-1");

        p.global_outbound = TAG_DIRECT.into();
        assert_eq!(p.effective_global(), TAG_AUTO, "Global mode takes no direct");
        p.global_outbound = "mudfish-1".into();
        assert_eq!(p.effective_global(), "mudfish-1");
        p.nodes.clear();
        assert_eq!(p.effective_global(), TAG_AUTO);
    }

    #[test]
    fn proxied_means_neither_direct_nor_reject() {
        let mut p = Profile::default();
        p.nodes.push(node("mudfish-1"));
        assert!(p.is_proxied("mudfish-1") && p.is_proxied(TAG_AUTO));
        assert!(p.is_proxied("mudfish-9"), "a removed node behaves like auto");
        assert!(!p.is_proxied(TAG_DIRECT) && !p.is_proxied(TAG_REJECT));
    }
}

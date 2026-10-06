use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// v2: rules became groups (several matcher kinds per group, own outbound each).
pub const PROFILE_SCHEMA_VERSION: u32 = 2;
pub const MUDFISH_SOCKS_PORT: u16 = 18081;

/// Outbound tag of the default-node selector (Global mode, proxied other traffic, groups that use the default).
pub const TAG_PROXY: &str = "proxy";
/// Outbound tag of the lowest-latency urltest group.
pub const TAG_AUTO: &str = "auto";
pub const TAG_DIRECT: &str = "direct";

/// Everything the user configures. Persisted as JSON; credentials are never stored here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(default)]
#[ts(export)]
pub struct Profile {
    pub schema_version: u32,
    /// Nodes the user picked from the Mudfish list; order is display order.
    pub nodes: Vec<ProxyNode>,
    /// Default node: `TAG_AUTO`, `TAG_DIRECT` or a node tag; applied to the `proxy` selector.
    pub selected: String,
    /// Routing groups in priority order; the first group that matches decides.
    /// Field-level default: a v1 file without `groups` must not pick up the preset group,
    /// because `migrate` converts its `rules` instead.
    #[serde(default)]
    pub groups: Vec<RuleGroup>,
    pub final_target: Target,
    pub mode: Mode,
    pub dns: DnsSettings,
    pub tun: TunSettings,
    /// sing-box log level; `info` logs every connection and DNS query.
    pub log_level: LogLevel,
    /// v1 `rules`, read only to migrate them into `groups`.
    #[serde(rename = "rules", default, skip_serializing)]
    #[ts(skip)]
    pub(crate) legacy_rules: Vec<legacy::Rule>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            nodes: Vec::new(),
            selected: TAG_AUTO.to_string(),
            groups: default_groups(),
            final_target: Target::Direct,
            mode: Mode::Rule,
            dns: DnsSettings::default(),
            tun: TunSettings::default(),
            log_level: LogLevel::default(),
            legacy_rules: Vec::new(),
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
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Target {
    Proxy,
    #[default]
    Direct,
    Reject,
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
    /// Choice of the default-node (`proxy`) selector.
    pub default_node: String,
    /// Selector tag of each enabled proxied group → its outbound.
    pub groups: BTreeMap<String, String>,
}

/// What to do with the UDP traffic of a group routed to the proxy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum UdpPolicy {
    /// Same target as the group.
    #[default]
    Follow,
    Direct,
    Reject,
}

/// A routing group: traffic matching *any* of its matchers (apps, domains, rule sets,
/// IP ranges) goes to the group's target. Groups are tried in priority order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[ts(export)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub target: Target,
    /// For `Target::Proxy`: `TAG_PROXY` (follow the main choice), `TAG_AUTO`, or a node tag.
    /// Each proxied group gets its own selector, so this can change live via the Clash API.
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
    #[serde(default)]
    pub udp: UdpPolicy,
}

impl RuleGroup {
    pub fn new(id: impl Into<String>, name: impl Into<String>, target: Target) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            enabled: true,
            target,
            outbound: default_group_outbound(),
            process_names: Vec::new(),
            process_paths: Vec::new(),
            directories: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_keywords: Vec::new(),
            rule_sets: Vec::new(),
            ip_cidrs: Vec::new(),
            udp: UdpPolicy::Follow,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, TS)]
#[serde(default)]
#[ts(export)]
pub struct DnsSettings {
    /// Proxied domains resolve to fake IPs so the node resolves them remotely.
    /// Required for remote resolution: sing-box hands SOCKS5 the IP otherwise (verified in M0).
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
    TAG_PROXY.to_string()
}

fn default_groups() -> Vec<RuleGroup> {
    let mut ads = RuleGroup::new("preset-ads", "廣告阻擋", Target::Reject);
    ads.enabled = false;
    ads.rule_sets = vec!["geosite:category-ads-all".into()];
    vec![ads]
}

impl Profile {
    pub fn node(&self, tag: &str) -> Option<&ProxyNode> {
        self.nodes.iter().find(|n| n.tag == tag)
    }

    fn outbound_exists(&self, tag: &str) -> bool {
        tag == TAG_AUTO || self.node(tag).is_some()
    }

    /// Returns `selected` if it still refers to something that exists, otherwise `auto`.
    /// Only the default node may be `direct`; groups that want direct use `Target::Direct`.
    pub fn effective_selected(&self) -> &str {
        if self.selected == TAG_DIRECT || self.outbound_exists(&self.selected) {
            &self.selected
        } else {
            TAG_AUTO
        }
    }

    /// A group's outbound, falling back to the default node if its node was removed.
    pub fn effective_group_outbound<'a>(&self, g: &'a RuleGroup) -> &'a str {
        if g.outbound == TAG_PROXY || self.outbound_exists(&g.outbound) {
            &g.outbound
        } else {
            TAG_PROXY
        }
    }

    /// Effective live choices (stale references already resolved to their fallbacks).
    pub fn selections(&self) -> Selections {
        Selections {
            mode: self.mode,
            default_node: self.effective_selected().to_string(),
            groups: self
                .groups
                .iter()
                .filter(|g| g.enabled && g.target == Target::Proxy)
                .map(|g| (g.selector_tag(), self.effective_group_outbound(g).to_string()))
                .collect(),
        }
    }

    /// Upgrades older files in place. Returns whether anything changed (caller should save).
    pub fn migrate(&mut self) -> bool {
        if self.schema_version >= PROFILE_SCHEMA_VERSION && self.legacy_rules.is_empty() {
            return false;
        }
        if self.groups.is_empty() {
            self.groups = self.legacy_rules.drain(..).map(legacy::Rule::into_group).collect();
        }
        self.legacy_rules.clear();
        self.schema_version = PROFILE_SCHEMA_VERSION;
        true
    }
}

/// Schema v1 rule shape (one matcher kind per rule), kept only for migration.
mod legacy {
    use super::*;

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
        pub fn into_group(self) -> RuleGroup {
            let mut g = RuleGroup::new(self.id, self.name, self.target);
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
        assert_eq!(p.schema_version, 2);
        assert_eq!(p.groups.len(), 3);
        assert_eq!(p.groups[0].process_names, ["game.exe"]);
        assert_eq!(p.groups[0].directories, ["C:\\Games"]);
        assert_eq!(p.groups[0].udp, UdpPolicy::Direct);
        assert_eq!(p.groups[0].outbound, TAG_PROXY);
        assert!(!p.groups[1].enabled);
        assert_eq!(p.groups[1].domain_keywords, ["foo"]);
        assert_eq!(p.groups[2].rule_sets, ["geosite:category-ads-all"]);

        let saved = serde_json::to_value(&p).unwrap();
        assert!(saved.get("rules").is_none());
        assert!(!p.migrate(), "second migrate is a no-op");
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
    }

    #[test]
    fn selections_cover_enabled_proxied_groups_only() {
        let mut p = Profile { selected: "gone".into(), mode: Mode::Global, ..Profile::default() };
        let mut a = RuleGroup::new("a", "a", Target::Proxy);
        a.outbound = TAG_AUTO.into();
        let mut off = RuleGroup::new("off", "off", Target::Proxy);
        off.enabled = false;
        p.groups = vec![a, off, RuleGroup::new("d", "d", Target::Direct)];
        let s = p.selections();
        assert_eq!(s.mode, Mode::Global);
        assert_eq!(s.default_node, TAG_AUTO, "stale default falls back to auto");
        assert_eq!(s.groups, BTreeMap::from([("group-a".to_string(), TAG_AUTO.to_string())]));
    }

    #[test]
    fn log_level_defaults_to_warn_for_old_profiles() {
        let p: Profile = serde_json::from_str("{}").unwrap();
        assert_eq!(p.log_level, LogLevel::Warn);
    }

    #[test]
    fn group_outbound_falls_back_when_node_removed() {
        let mut p = Profile::default();
        let mut g = RuleGroup::new("x", "x", Target::Proxy);
        g.outbound = "mudfish-1".into();
        assert_eq!(p.effective_group_outbound(&g), TAG_PROXY);
        p.nodes.push(ProxyNode {
            tag: "mudfish-1".into(),
            sid: 1,
            name: "n".into(),
            server: "1.1.1.1".into(),
            port: MUDFISH_SOCKS_PORT,
            country: "TW".into(),
            udp: true,
            wireguard: None,
        });
        assert_eq!(p.effective_group_outbound(&g), "mudfish-1");
    }
}

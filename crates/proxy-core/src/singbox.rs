//! Profile → sing-box 1.14 configuration (JSON).
//!
//! Field choices follow the M0 findings recorded in docs/PLAN.md: rule actions instead of
//! special outbounds, type-based DNS servers, and FakeIP for proxied domains (sing-box hands
//! SOCKS5 the sniffed-from IP otherwise, so the node could not resolve remotely).
//!
//! Matching semantics (sing-box route/rule/rule_abstract.go): inside one default rule,
//! `process_name`, `process_path`, `process_path_regex`, `network`, `port` and `rule_set`
//! are ANDed, while domain fields OR among themselves. A group means "any of its matchers",
//! so each matcher kind is emitted as its own sub-rule under a logical OR.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::model::*;

/// Runtime inputs that are not part of the persisted profile.
pub struct GenerateOptions<'a> {
    /// Mudfish account; only required when the profile has SOCKS (Mudfish) nodes.
    pub username: &'a str,
    pub password: &'a str,
    /// WireGuard private keys by node tag (kept in the OS credential store, not the profile).
    pub wireguard_keys: &'a BTreeMap<String, String>,
    /// Directory containing `geosite/`, `geoip/` and `acl/` `.srs` files.
    pub ruleset_dir: &'a Path,
    /// `127.0.0.1:<port>`
    pub clash_listen: &'a str,
    pub clash_secret: &'a str,
    pub log_level: &'a str,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum GenerateError {
    #[error("尚未加入任何節點")]
    NoNodes,
    #[error("尚未設定 Mudfish 帳號")]
    NoCredentials,
    #[error("找不到節點「{0}」的 WireGuard 金鑰，請刪除後重新產生")]
    MissingWireguardKey(String),
    #[error("群組「{0}」沒有任何比對條件")]
    EmptyGroup(String),
    #[error("規則集代碼格式錯誤：{0}（應為 geosite:xxx、geoip:xx 或 acl:xxx）")]
    BadRuleSetCode(String),
    #[error("找不到規則集檔案：{0}")]
    MissingRuleSet(String),
}

const DNS_LOCAL: &str = "dns-local";
const DNS_REMOTE: &str = "dns-remote";
const DNS_FAKEIP: &str = "dns-fakeip";

pub fn generate(profile: &Profile, opts: &GenerateOptions) -> Result<Value, GenerateError> {
    if profile.nodes.is_empty() {
        return Err(GenerateError::NoNodes);
    }
    if profile.nodes.iter().any(|n| !n.is_wireguard()) && (opts.username.is_empty() || opts.password.is_empty()) {
        return Err(GenerateError::NoCredentials);
    }
    if let Some(n) = profile.nodes.iter().find(|n| n.is_wireguard() && !opts.wireguard_keys.contains_key(&n.tag)) {
        return Err(GenerateError::MissingWireguardKey(n.name.clone()));
    }

    let groups: Vec<&RuleGroup> = profile.groups.iter().filter(|g| g.enabled).collect();
    if let Some(g) = groups.iter().find(|g| g.is_empty()) {
        return Err(GenerateError::EmptyGroup(g.name.clone()));
    }
    let rule_sets = collect_rule_sets(&groups, opts.ruleset_dir)?;

    Ok(json!({
        "log": { "level": opts.log_level, "timestamp": true },
        "dns": dns(profile, &groups),
        "inbounds": [tun(&profile.tun)],
        "outbounds": outbounds(profile, &groups, opts),
        "endpoints": endpoints(profile, opts),
        "route": route(profile, &groups, rule_sets),
        "experimental": {
            "clash_api": {
                "external_controller": opts.clash_listen,
                "secret": opts.clash_secret,
                "default_mode": profile.mode.as_clash(),
            },
            "cache_file": { "enabled": true, "path": "cache.db", "store_fakeip": profile.dns.fakeip },
        },
    }))
}

/// A referenced built-in rule set: `geosite:netflix` → tag `geosite-netflix`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuleSetRef {
    catalog: String,
    code: String,
    path: PathBuf,
}

impl RuleSetRef {
    fn parse(code: &str, dir: &Path) -> Result<Self, GenerateError> {
        let (catalog, name) = code
            .split_once(':')
            .filter(|(c, n)| matches!(*c, "geosite" | "geoip" | "acl") && !n.is_empty() && !n.contains(['/', '\\']))
            .ok_or_else(|| GenerateError::BadRuleSetCode(code.to_string()))?;
        let path = dir.join(catalog).join(format!("{name}.srs"));
        if !path.is_file() {
            return Err(GenerateError::MissingRuleSet(code.to_string()));
        }
        Ok(Self { catalog: catalog.to_string(), code: name.to_string(), path })
    }

    fn tag(&self) -> String {
        format!("{}-{}", self.catalog, self.code.replace('@', "-at-"))
    }
}

fn collect_rule_sets(groups: &[&RuleGroup], dir: &Path) -> Result<BTreeSet<RuleSetRef>, GenerateError> {
    let mut set = BTreeSet::new();
    for g in groups {
        for c in g.rule_sets.iter().filter(|c| !c.trim().is_empty()) {
            set.insert(RuleSetRef::parse(c.trim(), dir)?);
        }
    }
    Ok(set)
}

fn rule_set_tags(codes: &[String], only_geosite: bool) -> Vec<String> {
    codes
        .iter()
        .filter_map(|c| c.trim().split_once(':'))
        .filter(|(cat, _)| !only_geosite || *cat == "geosite")
        .map(|(cat, name)| format!("{cat}-{}", name.replace('@', "-at-")))
        .collect()
}

/// Domain part of a group (suffixes + keywords OR together), if any.
fn domain_rule(g: &RuleGroup) -> Option<Map<String, Value>> {
    let mut m = Map::new();
    put_list(&mut m, "domain_suffix", &g.domain_suffixes);
    put_list(&mut m, "domain_keyword", &g.domain_keywords);
    (!m.is_empty()).then_some(m)
}

/// One sub-rule per matcher kind; the group matches if any of them does.
fn group_matchers(g: &RuleGroup) -> Vec<Value> {
    let mut out = Vec::new();
    let mut single = |key: &str, items: &[String]| {
        let mut m = Map::new();
        put_list(&mut m, key, items);
        if !m.is_empty() {
            out.push(Value::Object(m));
        }
    };
    single("process_name", &g.process_names);
    single("process_path", &g.process_paths);
    let regexes: Vec<String> = g.directories.iter().filter(|d| !d.trim().is_empty()).map(|d| directory_regex(d)).collect();
    single("process_path_regex", &regexes);
    single("ip_cidr", &g.ip_cidrs);
    single("rule_set", &rule_set_tags(&g.rule_sets, false));
    if let Some(d) = domain_rule(g) {
        out.push(Value::Object(d));
    }
    out
}

/// Collapses sub-rules into one matcher: the rule itself if there is one, else logical OR.
fn any_of(mut subs: Vec<Value>) -> Value {
    if subs.len() == 1 {
        subs.pop().unwrap()
    } else {
        json!({ "type": "logical", "mode": "or", "rules": subs })
    }
}

fn dns(profile: &Profile, groups: &[&RuleGroup]) -> Value {
    let fake = profile.dns.fakeip;
    let proxied_server = if fake { DNS_FAKEIP } else { DNS_REMOTE };
    let mut servers = vec![
        json!({ "type": "local", "tag": DNS_LOCAL }),
        json!({
            "type": "https", "tag": DNS_REMOTE,
            "server": "1.1.1.1", "server_port": 443, "path": "/dns-query",
            "detour": TAG_PROXY,
        }),
    ];
    if fake {
        servers.push(json!({
            "type": "fakeip", "tag": DNS_FAKEIP,
            "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18",
        }));
    }

    let mut dns_rules = Vec::new();
    if fake {
        dns_rules.push(json!({ "clash_mode": "Global", "query_type": ["A", "AAAA"], "action": "route", "server": DNS_FAKEIP }));
    }
    for g in groups.iter().filter(|g| g.target == Target::Proxy) {
        if let Some(mut m) = domain_rule(g) {
            m.insert("query_type".into(), json!(["A", "AAAA"]));
            m.insert("action".into(), json!("route"));
            m.insert("server".into(), json!(proxied_server));
            dns_rules.push(Value::Object(m));
        }
        // Only geosite sets are pure domain lists; geoip/acl sets carry IP CIDRs, which
        // in DNS rules are legacy address filters that 1.14 rejects alongside query_type.
        let tags = rule_set_tags(&g.rule_sets, true);
        if !tags.is_empty() {
            dns_rules.push(json!({ "query_type": ["A", "AAAA"], "rule_set": tags, "action": "route", "server": proxied_server }));
        }
    }

    let mut dns = json!({ "servers": servers, "rules": dns_rules, "final": DNS_LOCAL });
    if profile.dns.ipv4_only {
        dns["strategy"] = json!("ipv4_only");
    }
    dns
}

fn tun(t: &TunSettings) -> Value {
    json!({
        "type": "tun", "tag": "tun-in",
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "mtu": t.mtu,
        "auto_route": true,
        "strict_route": t.strict_route,
    })
}

fn outbounds(profile: &Profile, groups: &[&RuleGroup], opts: &GenerateOptions) -> Value {
    let node_tags: Vec<&str> = profile.nodes.iter().map(|n| n.tag.as_str()).collect();
    // The default node may also be `direct`: groups that use it, Global mode and proxied
    // other traffic then go out directly without editing each group.
    let mut main_members = vec![TAG_AUTO, TAG_DIRECT];
    main_members.extend(&node_tags);
    // WARP lands on a nearby Cloudflare edge, so its latency nearly always wins; letting
    // `auto` pick it would silently pull region-targeted traffic off Mudfish. WARP joins
    // `auto` only when there are no Mudfish nodes, and is otherwise chosen explicitly.
    let mudfish: Vec<&str> = profile.nodes.iter().filter(|n| !n.is_wireguard()).map(|n| n.tag.as_str()).collect();
    let auto_members = if mudfish.is_empty() { node_tags.clone() } else { mudfish };

    let mut out = vec![
        json!({
            "type": "selector", "tag": TAG_PROXY,
            "outbounds": main_members,
            "default": profile.effective_selected(),
            "interrupt_exist_connections": true,
        }),
        json!({
            "type": "urltest", "tag": TAG_AUTO,
            "outbounds": auto_members,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "5m", "tolerance": 50, "idle_timeout": "30m",
        }),
    ];

    // Each proxied group has its own selector, so its node can be switched live.
    let mut group_members = vec![TAG_PROXY, TAG_AUTO];
    group_members.extend(&node_tags);
    for g in groups.iter().filter(|g| g.target == Target::Proxy) {
        out.push(json!({
            "type": "selector", "tag": g.selector_tag(),
            "outbounds": group_members,
            "default": profile.effective_group_outbound(g),
            "interrupt_exist_connections": true,
        }));
    }

    for n in profile.nodes.iter().filter(|n| !n.is_wireguard()) {
        let mut o = json!({
            "type": "socks", "tag": n.tag,
            "server": n.server, "server_port": n.port, "version": "5",
            "username": opts.username, "password": opts.password,
        });
        if !n.udp {
            o["network"] = json!("tcp");
        }
        out.push(o);
    }
    out.push(json!({ "type": "direct", "tag": TAG_DIRECT }));
    Value::Array(out)
}

/// WARP nodes as WireGuard endpoints (1.11+ replaced the WireGuard outbound). Endpoints are
/// addressed by tag exactly like outbounds, so selectors and urltest can include them.
fn endpoints(profile: &Profile, opts: &GenerateOptions) -> Value {
    let eps: Vec<Value> = profile
        .nodes
        .iter()
        .filter_map(|n| Some((n, n.wireguard.as_ref()?)))
        .map(|(n, wg)| {
            let mut address = vec![format!("{}/32", wg.address_v4)];
            if !wg.address_v6.is_empty() {
                address.push(format!("{}/128", wg.address_v6));
            }
            let mut peer = json!({
                "address": n.server,
                "port": n.port,
                "public_key": wg.peer_public_key,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25,
            });
            if wg.reserved.len() == 3 {
                peer["reserved"] = json!(wg.reserved);
            }
            json!({
                "type": "wireguard",
                "tag": n.tag,
                "mtu": wg.mtu,
                "address": address,
                "private_key": opts.wireguard_keys.get(&n.tag).map(String::as_str).unwrap_or_default(),
                "peers": [peer],
            })
        })
        .collect();
    Value::Array(eps)
}

fn route(profile: &Profile, groups: &[&RuleGroup], rule_sets: BTreeSet<RuleSetRef>) -> Value {
    let mut out = vec![
        json!({ "action": "sniff", "sniffer": ["http", "tls", "quic", "dns", "stun"], "timeout": "300ms" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "clash_mode": "Direct", "action": "route", "outbound": TAG_DIRECT }),
        json!({ "clash_mode": "Global", "action": "route", "outbound": TAG_PROXY }),
    ];
    if profile.tun.bypass_lan {
        out.push(json!({ "ip_is_private": true, "action": "route", "outbound": TAG_DIRECT }));
    }
    if profile.dns.block_quic_for_proxied {
        out.extend(quic_blocks(groups));
    }

    for g in groups {
        let matcher = any_of(group_matchers(g));
        if g.target == Target::Proxy && g.udp != UdpPolicy::Follow {
            let mut udp_rule = json!({ "type": "logical", "mode": "and", "rules": [{ "network": ["udp"] }, matcher.clone()] });
            with_action(&mut udp_rule, if g.udp == UdpPolicy::Direct { Action::Direct } else { Action::Reject });
            out.push(udp_rule);
        }
        let mut rule = matcher;
        with_action(
            &mut rule,
            match g.target {
                Target::Proxy => Action::Route(g.selector_tag()),
                Target::Direct => Action::Direct,
                Target::Reject => Action::Reject,
            },
        );
        out.push(rule);
    }

    let final_outbound = match profile.final_target {
        Target::Proxy => TAG_PROXY,
        Target::Direct | Target::Reject => TAG_DIRECT,
    };
    if profile.final_target == Target::Reject {
        out.push(json!({ "network": ["tcp", "udp"], "action": "reject" }));
    }

    let sets: Vec<Value> = rule_sets
        .iter()
        .map(|s| json!({ "type": "local", "tag": s.tag(), "format": "binary", "path": s.path.to_string_lossy() }))
        .collect();

    json!({
        "rules": out,
        "rule_set": sets,
        "final": final_outbound,
        "auto_detect_interface": true,
        "default_domain_resolver": DNS_LOCAL,
    })
}

/// Rejects UDP 443 to proxied domains, so browsers retry over TCP through the proxy. Must
/// precede the group rules (first match wins). Domains and rule sets get separate rules
/// because `rule_set` is ANDed with the domain fields inside a single rule.
fn quic_blocks(groups: &[&RuleGroup]) -> Vec<Value> {
    let proxied: Vec<&&RuleGroup> = groups.iter().filter(|g| g.target == Target::Proxy).collect();
    let suffixes: Vec<String> = proxied.iter().flat_map(|g| g.domain_suffixes.iter().cloned()).collect();
    let keywords: Vec<String> = proxied.iter().flat_map(|g| g.domain_keywords.iter().cloned()).collect();
    let sets: Vec<String> = proxied.iter().flat_map(|g| rule_set_tags(&g.rule_sets, true)).collect();

    let mut out = Vec::new();
    let mut base = Map::new();
    base.insert("network".into(), json!(["udp"]));
    base.insert("port".into(), json!([443]));

    let mut dom = base.clone();
    put_list(&mut dom, "domain_suffix", &suffixes);
    put_list(&mut dom, "domain_keyword", &keywords);
    if dom.len() > base.len() {
        dom.insert("action".into(), json!("reject"));
        out.push(Value::Object(dom));
    }
    let mut rs = base;
    put_list(&mut rs, "rule_set", &sets);
    if rs.contains_key("rule_set") {
        rs.insert("action".into(), json!("reject"));
        out.push(Value::Object(rs));
    }
    out
}

enum Action {
    Route(String),
    Direct,
    Reject,
}

fn with_action(v: &mut Value, a: Action) {
    match a {
        Action::Route(tag) => {
            v["action"] = json!("route");
            v["outbound"] = json!(tag);
        }
        Action::Direct => {
            v["action"] = json!("route");
            v["outbound"] = json!(TAG_DIRECT);
        }
        Action::Reject => v["action"] = json!("reject"),
    }
}

fn put_list(m: &mut Map<String, Value>, key: &str, items: &[String]) {
    let mut seen = BTreeSet::new();
    let items: Vec<&str> = items.iter().map(|s| s.trim()).filter(|s| !s.is_empty() && seen.insert(*s)).collect();
    if !items.is_empty() {
        m.insert(key.into(), json!(items));
    }
}

/// `C:\Games\LoL` → `(?i)^C:\\Games\\LoL\\.+$` (Windows paths are case-insensitive).
fn directory_regex(dir: &str) -> String {
    let dir = dir.trim().trim_end_matches(['\\', '/']);
    let mut escaped = String::with_capacity(dir.len() * 2);
    for c in dir.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    format!(r"(?i)^{escaped}\\.+$")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(sid: u32) -> ProxyNode {
        ProxyNode {
            tag: format!("mudfish-{sid}"),
            sid,
            name: format!("node {sid}"),
            server: "35.236.137.214".into(),
            port: MUDFISH_SOCKS_PORT,
            country: "TW".into(),
            udp: true,
            wireguard: None,
        }
    }

    fn warp_node() -> ProxyNode {
        ProxyNode {
            tag: "warp-test".into(),
            sid: 0,
            name: "Cloudflare WARP".into(),
            server: "engage.cloudflareclient.com".into(),
            port: 2408,
            country: "CF".into(),
            udp: true,
            wireguard: Some(WireguardPeer {
                peer_public_key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".into(),
                address_v4: "172.16.0.2".into(),
                address_v6: "2606:4700:110:8a36::1".into(),
                reserved: vec![1, 2, 3],
                mtu: 1280,
            }),
        }
    }

    static NO_KEYS: BTreeMap<String, String> = BTreeMap::new();

    fn warp_keys() -> BTreeMap<String, String> {
        // any valid base64 32-byte key works for `sing-box check`
        BTreeMap::from([("warp-test".to_string(), "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string())])
    }

    fn ruleset_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/src-tauri/resources/rulesets")
    }

    fn opts(dir: &Path) -> GenerateOptions<'_> {
        GenerateOptions {
            username: "user",
            password: "pass",
            wireguard_keys: &NO_KEYS,
            ruleset_dir: dir,
            clash_listen: "127.0.0.1:19090",
            clash_secret: "secret",
            log_level: "info",
        }
    }

    /// ads (reject) → game (mixed: app + domain + dir, own node, UDP direct) → site (domain only)
    /// → games (rule sets) → lan (IP, direct)
    fn sample_profile() -> Profile {
        let mut ads = RuleGroup::new("ads", "ads", Target::Reject);
        ads.rule_sets = vec!["geosite:category-ads-all".into()];

        let mut game = RuleGroup::new("game", "game", Target::Proxy);
        game.outbound = "mudfish-655".into();
        game.process_names = vec!["Game.exe".into()];
        game.process_paths = vec![r"C:\Program Files\Game\Game.exe".into()];
        game.directories = vec![r"C:\Riot Games\".into()];
        game.domain_suffixes = vec!["riotgames.com".into()];
        game.udp = UdpPolicy::Direct;

        let mut site = RuleGroup::new("site", "site", Target::Proxy);
        site.domain_suffixes = vec!["ifconfig.me".into()];

        let mut games = RuleGroup::new("games", "games", Target::Proxy);
        games.outbound = TAG_AUTO.into();
        games.rule_sets = vec!["geosite:category-games".into(), "geoip:jp".into()];

        let mut lan = RuleGroup::new("lan", "lan", Target::Direct);
        lan.ip_cidrs = vec!["100.64.0.0/10".into()];

        Profile {
            nodes: vec![node(591), node(655)],
            selected: "mudfish-591".into(),
            groups: vec![ads, game, site, games, lan],
            ..Profile::default()
        }
    }

    fn rules(c: &Value) -> &Vec<Value> {
        c["route"]["rules"].as_array().unwrap()
    }

    fn find_outbound<'a>(c: &'a Value, tag: &str) -> &'a Value {
        c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap()
    }

    #[test]
    fn rejects_profiles_that_cannot_run() {
        let dir = ruleset_dir();
        assert_eq!(generate(&Profile::default(), &opts(&dir)), Err(GenerateError::NoNodes));

        let mut p = sample_profile();
        let mut o = opts(&dir);
        o.password = "";
        assert_eq!(generate(&p, &o), Err(GenerateError::NoCredentials));

        p.groups.push(RuleGroup::new("empty", "empty", Target::Proxy));
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::EmptyGroup("empty".into())));
        p.groups.last_mut().unwrap().enabled = false;
        assert!(generate(&p, &opts(&dir)).is_ok(), "disabled empty groups are ignored");

        let mut bad = RuleGroup::new("bad", "bad", Target::Proxy);
        bad.rule_sets = vec!["geosite:../x".into()];
        p.groups.push(bad);
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::BadRuleSetCode("geosite:../x".into())));

        p.groups.last_mut().unwrap().rule_sets = vec!["geosite:no-such-set".into()];
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::MissingRuleSet("geosite:no-such-set".into())));
    }

    #[test]
    fn proxied_groups_get_their_own_selector() {
        let c = generate(&sample_profile(), &opts(&ruleset_dir())).unwrap();
        let main = find_outbound(&c, "proxy");
        assert_eq!(main["default"], "mudfish-591");
        assert_eq!(main["outbounds"], json!(["auto", "direct", "mudfish-591", "mudfish-655"]));

        let game = find_outbound(&c, "group-game");
        assert_eq!(game["type"], "selector");
        assert_eq!(game["outbounds"], json!(["proxy", "auto", "mudfish-591", "mudfish-655"]));
        assert_eq!(game["default"], "mudfish-655");
        assert_eq!(find_outbound(&c, "group-site")["default"], "proxy");
        assert_eq!(find_outbound(&c, "group-games")["default"], "auto");

        let tags: Vec<&str> = c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert!(!tags.contains(&"group-ads") && !tags.contains(&"group-lan"), "only proxied groups get selectors");
    }

    #[test]
    fn mixed_group_is_logical_or_of_separate_matchers() {
        let c = generate(&sample_profile(), &opts(&ruleset_dir())).unwrap();
        let r = rules(&c);
        // sniff, hijack-dns, 2× clash_mode, bypass LAN, 2× QUIC block
        assert_eq!(r[5]["domain_suffix"], json!(["riotgames.com", "ifconfig.me"]));
        assert_eq!(r[5]["port"], json!([443]));
        assert_eq!(r[6]["rule_set"], json!(["geosite-category-games"]));
        assert!(r[6].get("domain_suffix").is_none(), "rule_set and domains must not share a rule (AND)");

        assert_eq!(r[7]["rule_set"], json!(["geosite-category-ads-all"]));
        assert_eq!(r[7]["action"], "reject");

        // game: UDP-direct guard first, then the OR rule to its own selector
        assert_eq!(r[8]["mode"], "and");
        assert_eq!(r[8]["outbound"], "direct");
        assert_eq!(r[8]["rules"][1]["mode"], "or");
        let game = &r[9];
        assert_eq!(game["type"], "logical");
        assert_eq!(game["mode"], "or");
        assert_eq!(game["outbound"], "group-game");
        let subs = game["rules"].as_array().unwrap();
        assert_eq!(subs.len(), 4, "name, path, directory regex and domain are separate");
        assert_eq!(subs[0], json!({ "process_name": ["Game.exe"] }));
        assert_eq!(subs[1], json!({ "process_path": [r"C:\Program Files\Game\Game.exe"] }));
        assert_eq!(subs[2], json!({ "process_path_regex": [r"(?i)^C:\\Riot Games\\.+$"] }));
        assert_eq!(subs[3], json!({ "domain_suffix": ["riotgames.com"] }));

        // single-kind groups stay plain rules
        assert_eq!(r[10], json!({ "domain_suffix": ["ifconfig.me"], "action": "route", "outbound": "group-site" }));
        assert_eq!(r[11], json!({ "rule_set": ["geosite-category-games", "geoip-jp"], "action": "route", "outbound": "group-games" }));
        assert_eq!(r[12], json!({ "ip_cidr": ["100.64.0.0/10"], "action": "route", "outbound": "direct" }));
        assert_eq!(c["route"]["final"], "direct");
        assert_eq!(c["route"]["rule_set"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn priority_order_is_group_order() {
        let mut p = sample_profile();
        p.groups.swap(2, 4); // lan before site
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        let outs: Vec<&Value> = rules(&c)[10..].iter().map(|r| &r["outbound"]).collect();
        assert_eq!(outs, [&json!("direct"), &json!("group-games"), &json!("group-site")]);
    }

    #[test]
    fn dns_uses_fakeip_only_for_proxied_domains() {
        let c = generate(&sample_profile(), &opts(&ruleset_dir())).unwrap();
        let r = c["dns"]["rules"].as_array().unwrap();
        assert_eq!(r[0]["clash_mode"], "Global");
        assert_eq!(r[1]["domain_suffix"], json!(["riotgames.com"]));
        assert_eq!(r[2]["domain_suffix"], json!(["ifconfig.me"]));
        assert_eq!(r[3]["rule_set"], json!(["geosite-category-games"]));
        assert!(r[1..].iter().all(|x| x["server"] == "dns-fakeip"));
        assert_eq!(r.len(), 4, "reject/direct groups and geoip sets stay out of DNS rules");
        assert_eq!(c["dns"]["strategy"], "ipv4_only");

        let mut p = sample_profile();
        p.dns.fakeip = false;
        p.dns.ipv4_only = false;
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(c["dns"]["rules"][0]["server"], "dns-remote");
        assert!(c["dns"].get("strategy").is_none());
    }

    #[test]
    fn stale_outbounds_fall_back() {
        let mut p = sample_profile();
        p.selected = "mudfish-1".into();
        p.groups[1].outbound = "mudfish-2".into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(find_outbound(&c, "proxy")["default"], "auto");
        assert_eq!(find_outbound(&c, "group-game")["default"], "proxy");
    }

    #[test]
    fn default_node_can_be_direct() {
        let mut p = sample_profile();
        p.selected = TAG_DIRECT.into();
        p.groups[1].outbound = TAG_DIRECT.into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        let main = find_outbound(&c, "proxy");
        assert_eq!(main["outbounds"], json!(["auto", "direct", "mudfish-591", "mudfish-655"]));
        assert_eq!(main["default"], "direct");
        // groups pick direct via their target, not their outbound
        assert!(!find_outbound(&c, "group-game")["outbounds"].as_array().unwrap().contains(&json!("direct")));
        assert_eq!(find_outbound(&c, "group-game")["default"], "proxy");
    }

    #[test]
    fn warp_node_becomes_wireguard_endpoint() {
        let dir = ruleset_dir();
        let keys = warp_keys();
        let mut p = sample_profile();
        p.nodes.push(warp_node());
        p.groups[1].outbound = "warp-test".into();
        let mut o = opts(&dir);
        o.wireguard_keys = &keys;
        let c = generate(&p, &o).unwrap();

        let eps = c["endpoints"].as_array().unwrap();
        assert_eq!(eps.len(), 1);
        let ep = &eps[0];
        assert_eq!(ep["type"], "wireguard");
        assert_eq!(ep["tag"], "warp-test");
        assert_eq!(ep["mtu"], 1280);
        assert_eq!(ep["address"], json!(["172.16.0.2/32", "2606:4700:110:8a36::1/128"]));
        assert_eq!(ep["private_key"], keys["warp-test"]);
        assert_eq!(ep["peers"][0]["address"], "engage.cloudflareclient.com");
        assert_eq!(ep["peers"][0]["port"], 2408);
        assert_eq!(ep["peers"][0]["reserved"], json!([1, 2, 3]));
        assert_eq!(ep["peers"][0]["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));

        // selectable everywhere, but not duplicated as a socks outbound
        assert!(find_outbound(&c, "proxy")["outbounds"].as_array().unwrap().contains(&json!("warp-test")));
        assert_eq!(find_outbound(&c, "auto")["outbounds"], json!(["mudfish-591", "mudfish-655"]), "auto excludes WARP while Mudfish nodes exist");
        assert!(find_outbound(&c, "group-game")["outbounds"].as_array().unwrap().contains(&json!("warp-test")));
        assert_eq!(find_outbound(&c, "group-game")["default"], "warp-test");
        assert!(c["outbounds"].as_array().unwrap().iter().all(|o| o["tag"] != "warp-test"));
    }

    #[test]
    fn warp_only_profile_needs_no_mudfish_account() {
        let dir = ruleset_dir();
        let keys = warp_keys();
        let p = Profile { nodes: vec![warp_node()], ..Profile::default() };
        let mut o = opts(&dir);
        o.username = "";
        o.password = "";
        assert_eq!(generate(&p, &o), Err(GenerateError::MissingWireguardKey("Cloudflare WARP".into())));
        o.wireguard_keys = &keys;
        let c = generate(&p, &o).unwrap();
        assert_eq!(find_outbound(&c, "auto")["outbounds"], json!(["warp-test"]), "auto falls back to WARP when it is the only node");
    }

    #[test]
    fn final_reject_adds_catch_all() {
        let mut p = sample_profile();
        p.final_target = Target::Reject;
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(rules(&c).last().unwrap()["action"], "reject");
    }

    #[test]
    fn directory_regex_escapes() {
        assert_eq!(directory_regex(r"D:\Games (x86)\"), r"(?i)^D:\\Games \(x86\)\\.+$");
    }

    /// Validates generated configs with the real binary: SINGBOX_BIN=<path to sing-box.exe>.
    #[test]
    fn sing_box_check_accepts_generated_config() {
        let Ok(bin) = std::env::var("SINGBOX_BIN") else { return };
        let dir = ruleset_dir();
        let mut p = sample_profile();
        let mut acl = RuleGroup::new("acl", "acl", Target::Proxy);
        acl.rule_sets = vec!["acl:Steam".into()];
        acl.process_names = vec!["steam.exe".into()];
        acl.udp = UdpPolicy::Reject;
        acl.outbound = "warp-test".into();
        p.groups.push(acl);
        p.nodes.push(warp_node());
        let keys = warp_keys();
        let mut o = opts(&dir);
        o.wireguard_keys = &keys;
        for (fakeip, final_target, selected) in [(true, Target::Direct, "auto"), (false, Target::Proxy, "direct"), (true, Target::Reject, "mudfish-591")] {
            p.dns.fakeip = fakeip;
            p.final_target = final_target;
            p.selected = selected.into();
            let c = generate(&p, &o).unwrap();
            let path = std::env::temp_dir().join(format!("proxydesk-check-{fakeip}-{final_target:?}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&c).unwrap()).unwrap();
            let out = std::process::Command::new(&bin).args(["check", "-c"]).arg(&path).output().unwrap();
            let _ = std::fs::remove_file(&path);
            assert!(out.status.success(), "sing-box check failed: {}", String::from_utf8_lossy(&out.stderr));
        }
    }
}

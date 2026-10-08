//! Profile → sing-box 1.14 configuration (JSON).
//!
//! Field choices follow the M0 findings recorded in docs/PLAN.md: rule actions instead of
//! special outbounds, type-based DNS servers, and FakeIP for proxied domains (sing-box hands
//! SOCKS5 the sniffed-from IP otherwise, so the node could not resolve remotely).
//!
//! Matching semantics (sing-box route/rule/rule_abstract.go): inside one default rule,
//! `process_name`, `process_path`, `process_path_regex`, `network`, `port` and `rule_set`
//! are ANDed, while domain fields OR among themselves. A group combines its matcher kinds by
//! its match mode (any of them, or all of them), so each kind is emitted as its own sub-rule
//! under a logical OR or AND.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::custom::ProxyAuth;
use crate::model::*;

/// Runtime inputs that are not part of the persisted profile.
pub struct GenerateOptions<'a> {
    /// Mudfish account; only required when the profile has Mudfish nodes.
    pub username: &'a str,
    pub password: &'a str,
    /// WireGuard private keys by node tag (kept in the OS credential store, not the profile).
    pub wireguard_keys: &'a BTreeMap<String, String>,
    /// Accounts of the hand-added HTTP/SOCKS5 nodes by tag (kept in the OS credential store, not
    /// the profile). Every such node needs an entry; an empty username means no authentication.
    pub proxy_auth: &'a BTreeMap<String, ProxyAuth>,
    /// Directory containing `geosite/`, `geoip/` and `acl/` `.srs` files.
    pub ruleset_dir: &'a Path,
    /// `127.0.0.1:<port>`
    pub clash_listen: &'a str,
    pub clash_secret: &'a str,
    /// Fresh per start. sing-box's cache file restores each selector's last choice and the
    /// Clash mode under this id, overriding `default`/`default_mode`; a new id makes every
    /// start follow the profile. FakeIP mappings are not keyed by it and survive restarts.
    pub cache_id: &'a str,
    /// This app's executable: its own traffic (node list, WARP registration, TCP ping)
    /// always goes direct, also in Global mode.
    pub self_exe: Option<&'a str>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum GenerateError {
    #[error("尚未加入任何節點")]
    NoNodes,
    #[error("尚未設定 Mudfish 帳號")]
    NoCredentials,
    #[error("找不到節點「{0}」的 WireGuard 金鑰，請刪除後重新產生")]
    MissingWireguardKey(String),
    #[error("找不到節點「{0}」的帳號密碼，請在節點頁編輯這個節點並重新輸入")]
    MissingProxyAuth(String),
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
    if profile.nodes.iter().any(ProxyNode::is_mudfish) && (opts.username.is_empty() || opts.password.is_empty()) {
        return Err(GenerateError::NoCredentials);
    }
    if let Some(n) = profile.nodes.iter().find(|n| n.is_wireguard() && !opts.wireguard_keys.contains_key(&n.tag)) {
        return Err(GenerateError::MissingWireguardKey(n.name.clone()));
    }
    if let Some(n) = profile.nodes.iter().find(|n| n.is_custom() && !opts.proxy_auth.contains_key(&n.tag)) {
        return Err(GenerateError::MissingProxyAuth(n.name.clone()));
    }

    let groups: Vec<&RuleGroup> = profile.groups.iter().filter(|g| g.enabled).collect();
    if let Some(g) = groups.iter().find(|g| g.is_empty()) {
        return Err(GenerateError::EmptyGroup(g.name.clone()));
    }
    let geoip = geoip_rule_sets(profile);
    let rule_sets = collect_rule_sets(&groups, &geoip, opts.ruleset_dir)?;

    Ok(json!({
        "log": { "level": profile.log_level.as_str(), "timestamp": true },
        "dns": dns(profile, &groups),
        "inbounds": [tun(&profile.tun)],
        "outbounds": outbounds(profile, opts),
        "endpoints": endpoints(profile, opts),
        "route": route(profile, &groups, &geoip, rule_sets, opts.self_exe),
        "experimental": {
            "clash_api": {
                "external_controller": opts.clash_listen,
                "secret": opts.clash_secret,
                "default_mode": profile.mode.as_clash(),
            },
            "cache_file": { "enabled": true, "path": "cache.db", "cache_id": opts.cache_id, "store_fakeip": profile.dns.fakeip },
        },
    }))
}

/// Everything in the generated config that only takes effect when the core restarts. Two
/// profiles with the same fingerprint differ at most in their `Selections` (what each selector
/// is switched to, and the mode), which the running core applies live through the Clash API.
/// Secrets are placeholders here, so a changed account or key never shows up in it.
/// `Err` carries why the profile cannot become a config at all.
pub fn restart_fingerprint(profile: &Profile, ruleset_dir: &Path) -> Result<String, String> {
    let keys: BTreeMap<String, String> =
        profile.nodes.iter().filter(|n| n.is_wireguard()).map(|n| (n.tag.clone(), String::new())).collect();
    let auth: BTreeMap<String, ProxyAuth> =
        profile.nodes.iter().filter(|n| n.is_custom()).map(|n| (n.tag.clone(), ProxyAuth::default())).collect();
    let opts = GenerateOptions {
        username: "-",
        password: "-",
        wireguard_keys: &keys,
        proxy_auth: &auth,
        ruleset_dir,
        clash_listen: "",
        clash_secret: "",
        cache_id: "",
        self_exe: None,
    };
    match generate(profile, &opts) {
        Ok(mut c) => {
            for o in c["outbounds"].as_array_mut().into_iter().flatten() {
                if o["type"] == "selector" {
                    o.as_object_mut().map(|m| m.remove("default"));
                }
            }
            c["experimental"]["clash_api"]["default_mode"] = Value::Null;
            Ok(c.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Selector tag → member tags of a generated config (what the Clash API can switch to).
pub fn selector_members(config: &Value) -> BTreeMap<String, BTreeSet<String>> {
    config["outbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|o| o["type"] == "selector")
        .filter_map(|o| {
            let members = o["outbounds"].as_array()?.iter().filter_map(|m| m.as_str().map(String::from)).collect();
            Some((o["tag"].as_str()?.to_string(), members))
        })
        .collect()
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

/// The GeoIP group's countries as rule-set codes (`tw` → `geoip:tw`); empty means no GeoIP rule.
fn geoip_rule_sets(profile: &Profile) -> Vec<String> {
    profile.geoip.codes().into_iter().map(|c| format!("geoip:{c}")).collect()
}

fn collect_rule_sets(groups: &[&RuleGroup], geoip: &[String], dir: &Path) -> Result<BTreeSet<RuleSetRef>, GenerateError> {
    let mut set = BTreeSet::new();
    for c in groups.iter().flat_map(|g| &g.rule_sets).chain(geoip).filter(|c| !c.trim().is_empty()) {
        set.insert(RuleSetRef::parse(c.trim(), dir)?);
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

/// A `{ key: items }` matcher object, or `None` once empty values are trimmed away.
fn field_rule(key: &str, items: &[String]) -> Option<Value> {
    let mut m = Map::new();
    put_list(&mut m, key, items);
    (!m.is_empty()).then_some(Value::Object(m))
}

/// A group's `process_path_regex` values: exact paths and directories, both case-insensitive
/// (Windows paths are case-insensitive, and a hand-typed path may differ in case from sing-box's).
fn process_path_regexes(g: &RuleGroup) -> Vec<String> {
    g.process_paths
        .iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| path_regex(p))
        .chain(g.directories.iter().filter(|d| !d.trim().is_empty()).map(|d| directory_regex(d)))
        .collect()
}

/// The "app" matcher kind as separate sub-rules: a process-name rule and a path/dir-regex rule.
/// They are separate because sing-box ANDs `process_name` with `process_path_regex` inside one rule.
fn app_rules(g: &RuleGroup) -> Vec<Value> {
    [field_rule("process_name", &g.process_names), field_rule("process_path_regex", &process_path_regexes(g))]
        .into_iter()
        .flatten()
        .collect()
}

/// One sub-rule per sing-box field, fixed order (app name, app path, IP, rule set, domain). The OR
/// path ORs them all; kept byte-for-byte so existing profiles keep the same config and fingerprint.
fn group_matchers(g: &RuleGroup) -> Vec<Value> {
    let mut out = app_rules(g);
    out.extend(field_rule("ip_cidr", &g.ip_cidrs));
    out.extend(field_rule("rule_set", &rule_set_tags(&g.rule_sets, false)));
    if let Some(d) = domain_rule(g) {
        out.push(Value::Object(d));
    }
    out
}

/// One sub-rule per user-facing matcher kind (app, IP, rule set, domain), with the app kind's own
/// name/path/dir values OR-ed into a single sub-rule. The AND path ANDs these, so the kinds must
/// all match while a kind's own values still match any-of (e.g. "this app by name *or* folder").
fn group_kind_matchers(g: &RuleGroup) -> Vec<Value> {
    let mut out = Vec::new();
    let app = app_rules(g);
    if !app.is_empty() {
        out.push(any_of(app));
    }
    out.extend(field_rule("ip_cidr", &g.ip_cidrs));
    out.extend(field_rule("rule_set", &rule_set_tags(&g.rule_sets, false)));
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

/// Collapses sub-rules into one AND matcher: the rule itself if there is one, else logical AND.
fn all_of(mut subs: Vec<Value>) -> Value {
    if subs.len() == 1 {
        subs.pop().unwrap()
    } else {
        json!({ "type": "logical", "mode": "and", "rules": subs })
    }
}

/// A group's matcher. OR keeps the historical flat shape; AND combines one sub-rule per user-facing
/// kind, so the kinds AND while each kind's own values (the app names/paths especially) still OR.
fn group_matcher_expr(g: &RuleGroup) -> Value {
    match g.match_mode {
        MatchMode::Any => any_of(group_matchers(g)),
        MatchMode::All => all_of(group_kind_matchers(g)),
    }
}

/// A group is a true AND only when it has two or more populated matcher kinds; with one kind
/// `all` and `any` emit the identical rule, so FakeIP and the QUIC block still apply to it. The
/// gates below use this rather than `match_mode` alone so a pointless one-kind AND is not punished.
fn is_multi_kind_and(g: &RuleGroup) -> bool {
    g.match_mode == MatchMode::All && group_kind_matchers(g).len() >= 2
}

fn dns(profile: &Profile, groups: &[&RuleGroup]) -> Value {
    let fake = profile.dns.fakeip;
    let proxied_server = if fake { DNS_FAKEIP } else { DNS_REMOTE };
    let mut servers = vec![
        json!({ "type": "local", "tag": DNS_LOCAL }),
        json!({
            "type": "https", "tag": DNS_REMOTE,
            "server": "1.1.1.1", "server_port": 443, "path": "/dns-query",
            "detour": TAG_AUTO,
        }),
    ];
    if fake {
        servers.push(json!({
            "type": "fakeip", "tag": DNS_FAKEIP,
            "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18",
        }));
    }

    // Direct mode sends everything out directly, so resolve locally instead of faking.
    let mut dns_rules = vec![json!({ "clash_mode": "Direct", "action": "route", "server": DNS_LOCAL })];
    if fake {
        dns_rules.push(json!({ "clash_mode": "Global", "query_type": ["A", "AAAA"], "action": "route", "server": DNS_FAKEIP }));
    }
    // A multi-kind AND group gets no FakeIP rule. It claims a domain only together with its other
    // conditions (say, one app), but a DNS rule cannot see which app is asking: FakeIP keyed on
    // the domain alone would hand every app a fake IP for it. Other apps would then reach that
    // domain without the real IP GeoIP matches on, and miss the group's route rule as well. So an
    // AND group's domain resolves for real and is matched by the SNI/Host that sniffing finds.
    for g in groups.iter().filter(|g| profile.is_proxied(&g.outbound) && !is_multi_kind_and(g)) {
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

    // sing-box only accepts Clash modes that some rule mentions (plus `default_mode`). The
    // route rules name Direct and Global; without this no-op (same server as `final`), a core
    // started in Global or Direct mode could never be switched to Rule live.
    dns_rules.push(json!({ "clash_mode": "Rule", "action": "route", "server": DNS_LOCAL }));

    // `final` must stay real DNS: only the domains of proxied groups are faked, and GeoIP
    // needs the real IP of every other domain to match on.
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

/// The nodes `auto` picks from: the Mudfish nodes, or else the WARP nodes, or else the
/// hand-added ones. The other kinds are only ever chosen explicitly:
/// - WARP lands on a nearby Cloudflare edge, so its latency nearly always wins; letting `auto`
///   pick it would silently pull region-targeted traffic off Mudfish.
/// - A hand-added proxy is often TCP-only (HTTP, or a provider without UDP, like Webshare), so
///   `auto` landing on one would break the UDP of everything that follows `auto`.
fn auto_members(profile: &Profile) -> Vec<&str> {
    let tags = move |kind: fn(&ProxyNode) -> bool| profile.nodes.iter().filter(|n| kind(n)).map(|n| n.tag.as_str()).collect::<Vec<_>>();
    [tags(ProxyNode::is_mudfish), tags(ProxyNode::is_wireguard), tags(ProxyNode::is_custom)]
        .into_iter()
        .find(|members| !members.is_empty())
        .unwrap_or_default()
}

fn outbounds(profile: &Profile, opts: &GenerateOptions) -> Value {
    let node_tags: Vec<&str> = profile.nodes.iter().map(|n| n.tag.as_str()).collect();
    let mut out = vec![json!({
        "type": "urltest", "tag": TAG_AUTO,
        "outbounds": auto_members(profile),
        "url": "https://www.gstatic.com/generate_204",
        "interval": "5m", "tolerance": 50, "idle_timeout": "30m",
    })];

    // One selector per entry of `Profile::selections` — the very list the running core is
    // switched by, so config and live switches cannot drift apart: Global mode, `final`,
    // GeoIP and every group that is not blocked. Each can switch between direct and any node
    // live; Global has no `direct` (Direct mode covers it). `reject` is never a member: it
    // only exists as a rule action.
    for (tag, choice) in profile.selections().selectors {
        let mut members = if tag == TAG_GLOBAL { vec![TAG_AUTO] } else { vec![TAG_DIRECT, TAG_AUTO] };
        members.extend(&node_tags);
        out.push(json!({
            "type": "selector", "tag": tag,
            "outbounds": members,
            "default": choice,
            "interrupt_exist_connections": true,
        }));
    }

    out.extend(profile.nodes.iter().filter(|n| !n.is_wireguard()).map(|n| proxy_outbound(n, opts)));
    out.push(json!({ "type": "direct", "tag": TAG_DIRECT }));
    Value::Array(out)
}

/// A SOCKS5 or HTTP outbound. Mudfish nodes sign in with the Mudfish account, hand-added nodes
/// with their own (none when its username is empty).
fn proxy_outbound(n: &ProxyNode, opts: &GenerateOptions) -> Value {
    let (protocol, auth) = match &n.custom {
        Some(c) => (c.protocol, opts.proxy_auth.get(&n.tag).filter(|a| !a.username.is_empty()).map(|a| (a.username.as_str(), a.password.as_str()))),
        None => (ProxyProtocol::Socks5, Some((opts.username, opts.password))),
    };
    let mut o = match protocol {
        ProxyProtocol::Socks5 => json!({ "type": "socks", "tag": n.tag, "server": n.server, "server_port": n.port, "version": "5" }),
        ProxyProtocol::Http => json!({ "type": "http", "tag": n.tag, "server": n.server, "server_port": n.port }),
    };
    if let Some((username, password)) = auth {
        o["username"] = json!(username);
        o["password"] = json!(password);
    }
    // An HTTP proxy only tunnels TCP; sing-box's HTTP outbound has no `network` option at all.
    if protocol == ProxyProtocol::Socks5 && !n.udp {
        o["network"] = json!("tcp");
    }
    o
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

/// Route order: sniff, hijack-dns, exceptions, mode switches, the custom groups, GeoIP, and
/// `route.final` (the `final` group) at the very end.
fn route(profile: &Profile, groups: &[&RuleGroup], geoip: &[String], rule_sets: BTreeSet<RuleSetRef>, self_exe: Option<&str>) -> Value {
    let mut out = vec![
        json!({ "action": "sniff", "sniffer": ["http", "tls", "quic", "dns", "stun"], "timeout": "300ms" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
    ];
    // Exceptions that hold in every mode come before the mode switches.
    if let Some(exe) = self_exe {
        out.push(json!({ "process_path_regex": [path_regex(exe)], "action": "route", "outbound": TAG_DIRECT }));
    }
    if profile.tun.bypass_lan {
        out.push(json!({ "ip_is_private": true, "action": "route", "outbound": TAG_DIRECT }));
    }
    out.push(json!({ "clash_mode": "Direct", "action": "route", "outbound": TAG_DIRECT }));
    out.push(json!({ "clash_mode": "Global", "action": "route", "outbound": TAG_GLOBAL }));

    for g in groups {
        let proxied = profile.is_proxied(&g.outbound);
        // The QUIC block names the group's domains alone, which is only right while the domain
        // decides the group's traffic: not for a multi-kind AND group (it also needs its app/IP).
        if proxied && !is_multi_kind_and(g) && g.udp == UdpPolicy::Follow && profile.dns.block_quic_for_proxied {
            out.extend(quic_block(g));
        }
        let matcher = group_matcher_expr(g);
        if proxied && g.udp != UdpPolicy::Follow {
            let mut udp_rule = json!({ "type": "logical", "mode": "and", "rules": [{ "network": ["udp"] }, matcher.clone()] });
            with_action(&mut udp_rule, if g.udp == UdpPolicy::Direct { Action::Direct } else { Action::Reject });
            out.push(udp_rule);
        }
        let mut rule = matcher;
        with_action(&mut rule, selector_action(profile, &g.outbound, &g.selector_tag()));
        out.push(rule);
    }

    // GeoIP matches the destination IP only (no `resolve`): the default DNS is real, so every
    // domain no group claimed already arrives here as the IP it resolved to.
    if !geoip.is_empty() {
        let mut rule = json!({ "rule_set": rule_set_tags(geoip, false) });
        with_action(&mut rule, selector_action(profile, &profile.geoip.outbound, TAG_GEOIP));
        out.push(rule);
    }

    // A blocked `final` has no selector to point `route.final` at (`reject` is no outbound):
    // a catch-all reject rule does the blocking, and `final` is never reached.
    let final_blocked = profile.effective_outbound(&profile.final_outbound) == TAG_REJECT;
    if final_blocked {
        out.push(json!({ "network": ["tcp", "udp"], "action": "reject" }));
    }

    let sets: Vec<Value> = rule_sets
        .iter()
        .map(|s| json!({ "type": "local", "tag": s.tag(), "format": "binary", "path": s.path.to_string_lossy() }))
        .collect();

    json!({
        "rules": out,
        "rule_set": sets,
        "final": if final_blocked { TAG_DIRECT } else { TAG_FINAL },
        "auto_detect_interface": true,
        "default_domain_resolver": DNS_LOCAL,
    })
}

/// What a group, GeoIP or `final` rule does with its traffic: route it through the group's
/// `selector`, or reject it when the group's outbound is `reject`.
fn selector_action(profile: &Profile, outbound: &str, selector: &str) -> Action {
    if profile.effective_outbound(outbound) == TAG_REJECT {
        Action::Reject
    } else {
        Action::Route(selector.to_string())
    }
}

/// Rejects UDP 443 to a proxied group's domains, so browsers retry over TCP through the
/// proxy. Emitted right before the group's own rule, so a higher-priority group that sends the
/// same domain direct still wins. Domains and rule sets are separate sub-rules because
/// `rule_set` is ANDed with the domain fields inside a single rule. The caller emits it only
/// for proxied OR groups whose UDP follows the group: with their own UDP policy they keep it
/// (UDP direct lets QUIC work directly; UDP reject already covers it), and an AND group's
/// domain alone does not decide its traffic.
fn quic_block(g: &RuleGroup) -> Option<Value> {
    let mut subs = Vec::new();
    if let Some(d) = domain_rule(g) {
        subs.push(Value::Object(d));
    }
    let sets = rule_set_tags(&g.rule_sets, true);
    if !sets.is_empty() {
        subs.push(json!({ "rule_set": sets }));
    }
    (!subs.is_empty()).then(|| {
        json!({
            "type": "logical", "mode": "and",
            "rules": [{ "network": ["udp"], "port": [443] }, any_of(subs)],
            "action": "reject",
        })
    })
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

/// Regex-escapes a Windows path, accepting `/` as a separator (sing-box reports `\`).
fn escape_path(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len() * 2);
    for c in path.trim().chars().map(|c| if c == '/' { '\\' } else { c }) {
        if "\\.+*?()|[]{}^$".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// `C:\Games\game.exe` → `(?i)^C:\\Games\\game\.exe$`.
fn path_regex(path: &str) -> String {
    format!("(?i)^{}$", escape_path(path))
}

/// `C:\Games\LoL` → `(?i)^C:\\Games\\LoL\\.+$` (any executable below it).
fn directory_regex(dir: &str) -> String {
    format!(r"(?i)^{}\\.+$", escape_path(dir.trim().trim_end_matches(['\\', '/'])))
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
            custom: None,
        }
    }

    /// A hand-added node; its account goes into `GenerateOptions::proxy_auth` separately.
    fn custom_node(tag: &str, protocol: ProxyProtocol, udp: bool) -> ProxyNode {
        ProxyNode {
            tag: tag.into(),
            sid: 0,
            name: format!("custom {tag}"),
            server: "198.51.100.7".into(),
            port: 5092,
            country: String::new(),
            udp,
            wireguard: None,
            custom: Some(CustomProxy { protocol }),
        }
    }

    fn auth(entries: &[(&str, &str, &str)]) -> BTreeMap<String, ProxyAuth> {
        entries
            .iter()
            .map(|(tag, username, password)| (tag.to_string(), ProxyAuth { username: username.to_string(), password: password.to_string() }))
            .collect()
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
            custom: None,
        }
    }

    static NO_KEYS: BTreeMap<String, String> = BTreeMap::new();
    static NO_AUTH: BTreeMap<String, ProxyAuth> = BTreeMap::new();

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
            proxy_auth: &NO_AUTH,
            ruleset_dir: dir,
            clash_listen: "127.0.0.1:19090",
            clash_secret: "secret",
            cache_id: "run-1",
            self_exe: None,
        }
    }

    /// ads (blocked) → game (mixed: app + domain + dir, own node, UDP direct) → site (domain only)
    /// → games (rule sets) → lan (IP, direct); then GeoIP and final, both `direct` (the defaults).
    fn sample_profile() -> Profile {
        let mut ads = RuleGroup::new("ads", "ads", TAG_REJECT);
        ads.rule_sets = vec!["geosite:category-ads-all".into()];

        let mut game = RuleGroup::new("game", "game", "mudfish-655");
        game.process_names = vec!["Game.exe".into()];
        game.process_paths = vec![r"C:\Program Files\Game\Game.exe".into()];
        game.directories = vec![r"C:\Riot Games\".into()];
        game.domain_suffixes = vec!["riotgames.com".into()];
        game.udp = UdpPolicy::Direct;

        let mut site = RuleGroup::new("site", "site", "mudfish-591");
        site.domain_suffixes = vec!["ifconfig.me".into()];

        let mut games = RuleGroup::new("games", "games", TAG_AUTO);
        games.rule_sets = vec!["geosite:category-games".into(), "geoip:jp".into()];

        let mut lan = RuleGroup::new("lan", "lan", TAG_DIRECT);
        lan.ip_cidrs = vec!["100.64.0.0/10".into()];

        Profile {
            nodes: vec![node(591), node(655)],
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

    fn has_outbound(c: &Value, tag: &str) -> bool {
        c["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == tag)
    }

    #[test]
    fn rejects_profiles_that_cannot_run() {
        let dir = ruleset_dir();
        assert_eq!(generate(&Profile::default(), &opts(&dir)), Err(GenerateError::NoNodes));

        let mut p = sample_profile();
        let mut o = opts(&dir);
        o.password = "";
        assert_eq!(generate(&p, &o), Err(GenerateError::NoCredentials));

        p.groups.push(RuleGroup::new("empty", "empty", TAG_AUTO));
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::EmptyGroup("empty".into())));
        p.groups.last_mut().unwrap().enabled = false;
        assert!(generate(&p, &opts(&dir)).is_ok(), "disabled empty groups are ignored");

        let mut bad = RuleGroup::new("bad", "bad", TAG_AUTO);
        bad.rule_sets = vec!["geosite:../x".into()];
        p.groups.push(bad);
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::BadRuleSetCode("geosite:../x".into())));

        p.groups.last_mut().unwrap().rule_sets = vec!["geosite:no-such-set".into()];
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::MissingRuleSet("geosite:no-such-set".into())));
    }

    #[test]
    fn geoip_countries_need_their_rule_sets() {
        let dir = ruleset_dir();
        let mut p = sample_profile();
        p.geoip.countries = vec!["tw".into(), "../x".into()];
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::BadRuleSetCode("geoip:../x".into())));

        p.geoip.countries = vec!["tw".into(), "no-such-country".into()];
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::MissingRuleSet("geoip:no-such-country".into())));

        p.geoip.countries = vec!["blocked@ru".into()];
        let c = generate(&p, &opts(&dir)).unwrap();
        assert!(rules(&c).iter().any(|r| r["rule_set"] == json!(["geoip-blocked-at-ru"])), "codes with @ become valid tags");

        // a blocked GeoIP group still needs its sets
        p.geoip = GeoIpGroup { countries: vec!["no-such-country".into()], outbound: TAG_REJECT.into() };
        assert_eq!(generate(&p, &opts(&dir)), Err(GenerateError::MissingRuleSet("geoip:no-such-country".into())));
    }

    #[test]
    fn every_selector_comes_from_the_selections() {
        let p = sample_profile();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();

        // global, final, GeoIP and every enabled group that is not blocked (direct ones too)
        let members = selector_members(&c);
        let selections = p.selections();
        assert_eq!(members.keys().collect::<Vec<_>>(), selections.selectors.keys().collect::<Vec<_>>());
        assert_eq!(
            members.keys().map(String::as_str).collect::<Vec<_>>(),
            ["final", "geoip", "global", "group-game", "group-games", "group-lan", "group-site"]
        );
        for (tag, choice) in &selections.selectors {
            let s = find_outbound(&c, tag);
            assert_eq!(s["type"], "selector");
            assert_eq!(s["default"], choice.as_str(), "{tag}");
            assert_eq!(s["interrupt_exist_connections"], true, "{tag}");
        }

        assert_eq!(find_outbound(&c, "global")["outbounds"], json!(["auto", "mudfish-591", "mudfish-655"]), "Global has no direct");
        for tag in ["final", "geoip", "group-game", "group-games", "group-lan", "group-site"] {
            assert_eq!(find_outbound(&c, tag)["outbounds"], json!(["direct", "auto", "mudfish-591", "mudfish-655"]), "{tag}");
        }
        assert_eq!(find_outbound(&c, "group-game")["default"], "mudfish-655");
        assert_eq!(find_outbound(&c, "group-site")["default"], "mudfish-591");
        assert_eq!(find_outbound(&c, "group-games")["default"], "auto");
        assert_eq!(find_outbound(&c, "group-lan")["default"], "direct");
        assert_eq!(find_outbound(&c, "final")["default"], "direct");
        assert_eq!(find_outbound(&c, "geoip")["default"], "direct");
        assert_eq!(find_outbound(&c, "global")["default"], "auto");
        assert_eq!(find_outbound(&c, "auto")["type"], "urltest");
        assert!(!has_outbound(&c, "group-ads"), "a blocked group has no selector");
        assert!(!has_outbound(&c, "proxy"), "the default-node selector is gone");
    }

    #[test]
    fn reject_is_only_ever_a_rule_action() {
        let mut p = sample_profile();
        p.final_outbound = TAG_REJECT.into();
        p.geoip.outbound = TAG_REJECT.into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();

        for o in c["outbounds"].as_array().unwrap() {
            assert_ne!(o["tag"], "reject");
            assert!(o["outbounds"].as_array().into_iter().flatten().all(|m| m != "reject"), "{o}");
        }
        assert!(rules(&c).iter().all(|r| r["outbound"] != "reject"));
        assert_ne!(c["route"]["final"], "reject");
        for blocked in ["final", "geoip", "group-ads"] {
            assert!(!has_outbound(&c, blocked), "{blocked} is blocked, so it needs no selector");
        }
        assert_eq!(rules(&c)[5], json!({ "rule_set": ["geosite-category-ads-all"], "action": "reject" }));
    }

    #[test]
    fn mixed_group_is_logical_or_of_separate_matchers() {
        let c = generate(&sample_profile(), &opts(&ruleset_dir())).unwrap();
        let r = rules(&c);
        // sniff, hijack-dns, bypass LAN, then the two mode switches
        assert_eq!(r[2], json!({ "ip_is_private": true, "action": "route", "outbound": "direct" }));
        assert_eq!(r[3]["clash_mode"], "Direct");
        assert_eq!(r[4], json!({ "clash_mode": "Global", "action": "route", "outbound": "global" }));

        assert_eq!(r[5], json!({ "rule_set": ["geosite-category-ads-all"], "action": "reject" }));

        // game: UDP-direct guard first (no QUIC block: its UDP already goes direct), then the OR rule
        assert_eq!(r[6]["mode"], "and");
        assert_eq!(r[6]["outbound"], "direct");
        assert_eq!(r[6]["rules"][1]["mode"], "or");
        let game = &r[7];
        assert_eq!(game["type"], "logical");
        assert_eq!(game["mode"], "or");
        assert_eq!(game["outbound"], "group-game");
        let subs = game["rules"].as_array().unwrap();
        assert_eq!(subs.len(), 3, "name, path regexes and domain are separate sub-rules");
        assert_eq!(subs[0], json!({ "process_name": ["Game.exe"] }));
        assert_eq!(
            subs[1],
            json!({ "process_path_regex": [r"(?i)^C:\\Program Files\\Game\\Game\.exe$", r"(?i)^C:\\Riot Games\\.+$"] })
        );
        assert_eq!(subs[2], json!({ "domain_suffix": ["riotgames.com"] }));

        // site: its own QUIC block right before its rule
        assert_eq!(
            r[8],
            json!({ "type": "logical", "mode": "and", "action": "reject",
                    "rules": [{ "network": ["udp"], "port": [443] }, { "domain_suffix": ["ifconfig.me"] }] })
        );
        assert_eq!(r[9], json!({ "domain_suffix": ["ifconfig.me"], "action": "route", "outbound": "group-site" }));
        // games: only the geosite set takes part in QUIC blocking (geoip sets are IP lists)
        assert_eq!(r[10]["rules"][1], json!({ "rule_set": ["geosite-category-games"] }));
        assert_eq!(r[11], json!({ "rule_set": ["geosite-category-games", "geoip-jp"], "action": "route", "outbound": "group-games" }));
        // a direct group is routed through its own selector too, so it can switch to a node live
        assert_eq!(r[12], json!({ "ip_cidr": ["100.64.0.0/10"], "action": "route", "outbound": "group-lan" }));
        // GeoIP right behind the groups; final is `route.final`, not a rule
        assert_eq!(r[13], json!({ "rule_set": ["geoip-tw"], "action": "route", "outbound": "geoip" }));
        assert_eq!(r.len(), 14);
        assert_eq!(c["route"]["final"], "final");
        assert_eq!(c["route"]["rule_set"].as_array().unwrap().len(), 4, "ads, games, geoip-jp and geoip-tw");
    }

    /// Outbounds of the rules in order (skips QUIC blocks and the fixed prefix).
    fn rule_outbounds(c: &Value) -> Vec<String> {
        rules(c)[5..].iter().filter_map(|r| r["outbound"].as_str().map(String::from)).collect()
    }

    #[test]
    fn priority_order_is_group_order() {
        let mut p = sample_profile();
        p.groups.swap(2, 4); // lan before site
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(rule_outbounds(&c), ["direct", "group-game", "group-lan", "group-games", "group-site", "geoip"]);
    }

    #[test]
    fn geoip_follows_the_groups_and_precedes_the_final_catch_all() {
        let dir = ruleset_dir();
        let mut p = sample_profile();
        p.geoip = GeoIpGroup { countries: vec!["tw".into(), "jp".into(), " tw".into()], outbound: "mudfish-591".into() };
        let c = generate(&p, &opts(&dir)).unwrap();
        let r = rules(&c);
        let geoip = r.iter().position(|x| x["outbound"] == "geoip").unwrap();
        assert_eq!(r[geoip - 1]["outbound"], "group-lan", "right behind the last group");
        assert_eq!(r[geoip], json!({ "rule_set": ["geoip-tw", "geoip-jp"], "action": "route", "outbound": "geoip" }));
        assert_eq!(r.len(), geoip + 1, "nothing follows while final is not blocked");
        assert_eq!(find_outbound(&c, "geoip")["default"], "mudfish-591");
        let tags: Vec<&str> = c["route"]["rule_set"].as_array().unwrap().iter().map(|s| s["tag"].as_str().unwrap()).collect();
        assert_eq!(tags.iter().filter(|t| **t == "geoip-tw").count(), 1, "repeated countries share one rule set");

        // A blocked GeoIP is a reject action; a blocked final's catch-all comes after it.
        p.geoip.outbound = TAG_REJECT.into();
        p.final_outbound = TAG_REJECT.into();
        let c = generate(&p, &opts(&dir)).unwrap();
        let r = rules(&c);
        assert_eq!(r[r.len() - 2], json!({ "rule_set": ["geoip-tw", "geoip-jp"], "action": "reject" }));
        assert_eq!(r[r.len() - 1], json!({ "network": ["tcp", "udp"], "action": "reject" }));
        assert_eq!(c["route"]["final"], "direct", "the catch-all blocks; `final` has no selector then");

        // Without countries the rule, its selector and its rule sets are skipped, without an error.
        p.geoip = GeoIpGroup { countries: vec![" ".into(), String::new()], outbound: TAG_DIRECT.into() };
        p.final_outbound = TAG_DIRECT.into();
        let c = generate(&p, &opts(&dir)).unwrap();
        assert_eq!(rules(&c).last().unwrap()["outbound"], "group-lan", "the groups are the last rules");
        assert!(!has_outbound(&c, "geoip"));
        let tags: Vec<&str> = c["route"]["rule_set"].as_array().unwrap().iter().map(|s| s["tag"].as_str().unwrap()).collect();
        assert!(!tags.contains(&"geoip-tw"));
    }

    #[test]
    fn final_and_global_mode_route_through_their_selectors() {
        let mut p = sample_profile();
        p.final_outbound = "mudfish-591".into();
        p.global_outbound = "mudfish-655".into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(c["route"]["final"], "final");
        assert_eq!(rules(&c)[4], json!({ "clash_mode": "Global", "action": "route", "outbound": "global" }));
        assert_eq!(find_outbound(&c, "final")["default"], "mudfish-591");
        assert_eq!(find_outbound(&c, "global")["default"], "mudfish-655");
        assert_eq!(rules(&c).len(), 14, "no catch-all while final is not blocked");
    }

    #[test]
    fn quic_block_respects_group_priority() {
        // A higher-priority direct group for youtube.com must not lose QUIC to a lower proxied one.
        let mut yt = RuleGroup::new("yt", "yt", TAG_DIRECT);
        yt.domain_suffixes = vec!["youtube.com".into()];
        let mut google = RuleGroup::new("google", "google", TAG_AUTO);
        google.domain_suffixes = vec!["youtube.com".into(), "google.com".into()];
        let p = Profile { nodes: vec![node(591)], groups: vec![yt, google], ..Profile::default() };
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        let r = rules(&c);
        let yt_rule = r.iter().position(|x| x["domain_suffix"] == json!(["youtube.com"])).unwrap();
        let quic = r.iter().position(|x| x["action"] == "reject" && x["type"] == "logical").unwrap();
        assert!(yt_rule < quic, "direct group decides before the proxied group's QUIC block");

        let mut p = p;
        p.dns.block_quic_for_proxied = false;
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert!(rules(&c).iter().all(|x| x["action"] != "reject"));
    }

    #[test]
    fn direct_groups_get_no_fakeip_rule_and_no_quic_block() {
        let dir = ruleset_dir();
        let mut g = RuleGroup::new("d", "d", TAG_DIRECT);
        g.domain_suffixes = vec!["example.com".into()];
        g.rule_sets = vec!["geosite:category-games".into()];
        let mut p = Profile { nodes: vec![node(591)], groups: vec![g], ..Profile::default() };

        let c = generate(&p, &opts(&dir)).unwrap();
        assert_eq!(c["dns"]["rules"].as_array().unwrap().len(), 3, "only the Direct, Global and Rule mode rules");
        assert!(rules(&c).iter().all(|r| r["action"] != "reject"), "no QUIC block for a direct group");

        // the same group through a node gets both its FakeIP rules and its QUIC block
        p.groups[0].outbound = TAG_AUTO.into();
        let c = generate(&p, &opts(&dir)).unwrap();
        let dns = c["dns"]["rules"].as_array().unwrap();
        assert_eq!(dns.len(), 5);
        assert_eq!(dns[2]["domain_suffix"], json!(["example.com"]));
        assert_eq!(dns[3]["rule_set"], json!(["geosite-category-games"]));
        assert!(dns[2..4].iter().all(|r| r["server"] == "dns-fakeip"));
        assert!(rules(&c).iter().any(|r| r["action"] == "reject" && r["type"] == "logical"));
    }

    /// An AND group needs every populated matcher kind: one logical AND of the per-kind sub-rules.
    /// Its domain cannot decide on its own, so the group gets neither a FakeIP rule nor a QUIC block.
    #[test]
    fn and_group_matches_every_kind() {
        let dir = ruleset_dir();
        let mut g = RuleGroup::new("both", "both", "mudfish-591");
        g.match_mode = MatchMode::All;
        g.process_names = vec!["game.exe".into()];
        g.domain_suffixes = vec!["example.com".into()];
        g.ip_cidrs = vec!["1.2.3.0/24".into()];
        let and = Profile { nodes: vec![node(591)], groups: vec![g], ..Profile::default() };

        let c = generate(&and, &opts(&dir)).unwrap();
        let r = rules(&c);
        // sniff, hijack-dns, bypass LAN and the two mode switches, then the group, then GeoIP
        let rule = &r[5];
        assert_eq!(rule["type"], "logical");
        assert_eq!(rule["mode"], "and");
        assert_eq!((rule["action"].as_str(), rule["outbound"].as_str()), (Some("route"), Some("group-both")));
        let subs = rule["rules"].as_array().unwrap();
        assert_eq!(subs.len(), 3, "one sub-rule per kind: app, IP and domain");
        assert!(subs.contains(&json!({ "process_name": ["game.exe"] })));
        assert!(subs.contains(&json!({ "ip_cidr": ["1.2.3.0/24"] })));
        assert!(subs.contains(&json!({ "domain_suffix": ["example.com"] })));
        assert_eq!(r.len(), 7, "no QUIC block rule in front of it");
        assert!(r.iter().all(|x| x["action"] != "reject"));
        let dns = c["dns"]["rules"].as_array().unwrap();
        assert_eq!(dns.len(), 3, "only the Direct, Global and Rule mode rules: no FakeIP for its domain");
        assert!(dns.iter().all(|d| d.get("domain_suffix").is_none()));

        // The same conditions as OR get both, so the checks above are not vacuous.
        let mut or = and.clone();
        or.groups[0].match_mode = MatchMode::Any;
        let c = generate(&or, &opts(&dir)).unwrap();
        assert_eq!(c["dns"]["rules"].as_array().unwrap().len(), 4, "FakeIP rule for the domain");
        assert!(rules(&c).iter().any(|x| x["action"] == "reject" && x["type"] == "logical"), "QUIC block");
        assert_eq!(rules(&c)[6]["mode"], "or");
        assert_ne!(restart_fingerprint(&and, &dir), restart_fingerprint(&or, &dir), "switching the mode needs a reconnect");

        // With a UDP policy of its own, the UDP guard wraps the AND matcher (and still no QUIC block).
        let mut guarded = and.clone();
        guarded.groups[0].udp = UdpPolicy::Direct;
        let c = generate(&guarded, &opts(&dir)).unwrap();
        let (guard, rule) = (&rules(&c)[5], &rules(&c)[6]);
        assert_eq!((guard["mode"].as_str(), guard["outbound"].as_str()), (Some("and"), Some("direct")));
        assert_eq!(guard["rules"][0], json!({ "network": ["udp"] }));
        assert_eq!((guard["rules"][1]["type"].as_str(), guard["rules"][1]["mode"].as_str()), (Some("logical"), Some("and")));
        assert_eq!(rule["outbound"], "group-both");
        assert_eq!(rules(&c).len(), 8);
    }

    /// With one populated kind there is nothing to AND: the rule is the same in either mode.
    #[test]
    fn a_single_kind_is_the_same_rule_in_either_mode() {
        let mut g = RuleGroup::new("one", "one", TAG_AUTO);
        g.process_names = vec!["a.exe".into()];
        let any = group_matcher_expr(&g);
        g.match_mode = MatchMode::All;
        assert_eq!(group_matcher_expr(&g), any);
        assert_eq!(any, json!({ "process_name": ["a.exe"] }));
    }

    /// A one-kind AND group is identical to the OR version, so it must keep FakeIP and the QUIC
    /// block (only a genuine multi-kind AND loses them).
    #[test]
    fn single_kind_and_group_keeps_fakeip_and_quic_block() {
        let dir = ruleset_dir();
        let mut g = RuleGroup::new("d", "d", "mudfish-591");
        g.match_mode = MatchMode::All;
        g.domain_suffixes = vec!["example.com".into()];
        let p = Profile { nodes: vec![node(591)], groups: vec![g], ..Profile::default() };
        let c = generate(&p, &opts(&dir)).unwrap();
        assert!(
            c["dns"]["rules"].as_array().unwrap().iter().any(|d| d.get("domain_suffix").is_some()),
            "FakeIP for the lone domain, same as OR"
        );
        assert!(rules(&c).iter().any(|x| x["action"] == "reject" && x["type"] == "logical"), "QUIC block, same as OR");
        assert!(!is_multi_kind_and(&p.groups[0]));
    }

    /// In AND mode the "app" kind (names, paths, folders) still ORs internally: only the kinds AND,
    /// so "this app by name or folder, AND this IP" matches the app either way it is named.
    #[test]
    fn and_mode_ors_within_the_app_kind() {
        let dir = ruleset_dir();
        let mut g = RuleGroup::new("app-ip", "app-ip", "mudfish-591");
        g.match_mode = MatchMode::All;
        g.process_names = vec!["game.exe".into()];
        g.directories = vec![r"C:\Riot Games".into()];
        g.ip_cidrs = vec!["1.2.3.0/24".into()];
        let p = Profile { nodes: vec![node(591)], groups: vec![g], ..Profile::default() };
        let c = generate(&p, &opts(&dir)).unwrap();
        // sniff, hijack-dns, bypass LAN, the two mode switches, then the group
        let rule = &rules(&c)[5];
        assert_eq!((rule["type"].as_str(), rule["mode"].as_str()), (Some("logical"), Some("and")));
        let subs = rule["rules"].as_array().unwrap();
        assert_eq!(subs.len(), 2, "two kinds: app and IP");
        let app = subs.iter().find(|s| s["mode"] == "or").expect("the app kind is an inner OR of name and path");
        let app_subs = app["rules"].as_array().unwrap();
        assert!(app_subs.iter().any(|s| s.get("process_name").is_some()), "app matches by name");
        assert!(app_subs.iter().any(|s| s.get("process_path_regex").is_some()), "...or by folder");
        assert!(subs.iter().any(|s| s.get("ip_cidr").is_some()), "ANDed with the IP kind");
        assert!(is_multi_kind_and(&p.groups[0]));
    }

    /// A v0.4 file with one group that followed the default node and blocked its UDP.
    fn v2_group_with_udp_policy(selected: &str) -> String {
        format!(
            r#"{{"schema_version": 2, "selected": "{selected}", "final_target": "direct",
                "nodes": [{{"tag": "mudfish-591", "sid": 591, "name": "node 591", "server": "35.236.137.214", "port": 18081, "country": "TW"}}],
                "groups": [{{"id": "g", "name": "g", "enabled": true, "target": "proxy", "outbound": "proxy", "udp": "reject", "domain_suffixes": ["example.com"]}}]}}"#
        )
    }

    /// v3 cannot say "direct, but block its UDP": a group that followed a direct default node is a
    /// plain direct group after the migration. Its UDP policy stays in the profile, but no UDP
    /// guard, QUIC block or FakeIP rule is generated for it (an accepted loss).
    #[test]
    fn migrated_group_that_followed_a_direct_default_node_loses_its_udp_policy() {
        let dir = ruleset_dir();
        let mut p: Profile = serde_json::from_str(&v2_group_with_udp_policy("direct")).unwrap();
        assert!(p.migrate());
        assert_eq!(p.groups[0].outbound, TAG_DIRECT);
        assert_eq!(p.groups[0].udp, UdpPolicy::Reject, "kept as it was, but inert");

        let c = generate(&p, &opts(&dir)).unwrap();
        let r = rules(&c);
        assert!(r.iter().all(|x| x["type"] != "logical"), "no UDP guard or QUIC block for a direct group: {r:?}");
        assert_eq!(r[5], json!({ "domain_suffix": ["example.com"], "action": "route", "outbound": "group-g" }), "its own rule comes first after the mode switches");
        assert_eq!(c["dns"]["rules"].as_array().unwrap().len(), 3, "no FakeIP rule for its domain");
        assert_eq!(find_outbound(&c, "group-g")["default"], "direct");

        // the same file behind a node default node keeps the guard: that is what the direct case loses
        let mut proxied: Profile = serde_json::from_str(&v2_group_with_udp_policy("mudfish-591")).unwrap();
        assert!(proxied.migrate());
        assert_eq!(proxied.groups[0].outbound, "mudfish-591");
        let c = generate(&proxied, &opts(&dir)).unwrap();
        let r = rules(&c);
        assert_eq!(r[5]["type"], "logical", "UDP guard first");
        assert_eq!(r[5]["action"], "reject");
        assert_eq!(r[6]["outbound"], "group-g");
        assert_eq!(c["dns"]["rules"].as_array().unwrap().len(), 4, "and its FakeIP rule");

        // pointing the migrated direct group at the node brings the policy back
        p.groups[0].outbound = "mudfish-591".into();
        let c = generate(&p, &opts(&dir)).unwrap();
        assert_eq!(rules(&c)[5]["action"], "reject");
    }

    #[test]
    fn exceptions_precede_mode_switches() {
        let dir = ruleset_dir();
        let mut o = opts(&dir);
        o.self_exe = Some(r"C:\Program Files\ProxyDesk\proxydesk.exe");
        let c = generate(&sample_profile(), &o).unwrap();
        let r = rules(&c);
        assert_eq!(r[2], json!({ "process_path_regex": [r"(?i)^C:\\Program Files\\ProxyDesk\\proxydesk\.exe$"], "action": "route", "outbound": "direct" }));
        assert_eq!(r[3]["ip_is_private"], true, "LAN stays direct in Global mode too");
        assert_eq!(r[4]["clash_mode"], "Direct");
        assert_eq!(r[5]["clash_mode"], "Global");
    }

    #[test]
    fn path_regexes_accept_forward_slashes() {
        assert_eq!(path_regex("C:/Games/a+b.exe"), r"(?i)^C:\\Games\\a\+b\.exe$");
        assert_eq!(directory_regex("C:/Games/"), r"(?i)^C:\\Games\\.+$");
    }

    #[test]
    fn dns_uses_fakeip_only_for_proxied_domains() {
        let c = generate(&sample_profile(), &opts(&ruleset_dir())).unwrap();
        let r = c["dns"]["rules"].as_array().unwrap();
        assert_eq!(r[0], json!({ "clash_mode": "Direct", "action": "route", "server": "dns-local" }));
        assert_eq!(r[1]["clash_mode"], "Global");
        assert_eq!(r[2]["domain_suffix"], json!(["riotgames.com"]));
        assert_eq!(r[3]["domain_suffix"], json!(["ifconfig.me"]));
        assert_eq!(r[4]["rule_set"], json!(["geosite-category-games"]));
        assert!(r[1..5].iter().all(|x| x["server"] == "dns-fakeip"));
        assert_eq!(r[5], json!({ "clash_mode": "Rule", "action": "route", "server": "dns-local" }));
        assert_eq!(r.len(), 6, "blocked/direct groups and geoip sets stay out of DNS rules");
        assert_eq!(c["dns"]["strategy"], "ipv4_only");
        // GeoIP needs real IPs for every domain no group claimed
        assert_eq!(c["dns"]["final"], "dns-local");

        let remote = c["dns"]["servers"].as_array().unwrap().iter().find(|s| s["tag"] == "dns-remote").unwrap();
        assert_eq!(remote["detour"], "auto");

        let mut p = sample_profile();
        p.dns.fakeip = false;
        p.dns.ipv4_only = false;
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(c["dns"]["rules"][1]["server"], "dns-remote");
        assert!(c["dns"].get("strategy").is_none());
        assert_eq!(c["dns"]["final"], "dns-local");
        let remote = c["dns"]["servers"].as_array().unwrap().iter().find(|s| s["tag"] == "dns-remote").unwrap();
        assert_eq!(remote["detour"], "auto", "the proxy selector is gone; DNS goes through auto");
    }

    /// sing-box builds its switchable mode list from the `clash_mode` values in the rules.
    #[test]
    fn every_mode_is_switchable_whatever_the_start_mode() {
        for start in [Mode::Rule, Mode::Global, Mode::Direct] {
            let p = Profile { mode: start, ..sample_profile() };
            let c = generate(&p, &opts(&ruleset_dir())).unwrap();
            let text = c.to_string();
            for m in ["Rule", "Global", "Direct"] {
                assert!(text.contains(&format!(r#""clash_mode":"{m}""#)), "{m} missing when starting in {start:?}");
            }
        }
    }

    #[test]
    fn cache_id_and_log_level_come_from_options_and_profile() {
        let mut p = sample_profile();
        p.log_level = LogLevel::Info;
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(c["experimental"]["cache_file"]["cache_id"], "run-1");
        assert_eq!(c["log"]["level"], "info");
    }

    #[test]
    fn fingerprint_ignores_live_selections_only() {
        let dir = ruleset_dir();
        let base = sample_profile();
        let fp = restart_fingerprint(&base, &dir);

        // Everything a selector can be switched to without a restart.
        for live in [
            |p: &mut Profile| p.geoip.outbound = "mudfish-591".into(), // GeoIP: direct → node
            |p: &mut Profile| p.final_outbound = "mudfish-655".into(), // final: direct → node
            |p: &mut Profile| p.global_outbound = "mudfish-655".into(),
            |p: &mut Profile| p.groups[1].outbound = TAG_AUTO.into(), // between nodes
            |p: &mut Profile| p.groups[2].outbound = "mudfish-655".into(),
            |p: &mut Profile| p.groups[4].outbound = TAG_AUTO.into(), // an IP-only group: nothing but its selector depends on direct vs proxy
            |p: &mut Profile| p.mode = Mode::Global,
            |p: &mut Profile| p.groups[1].name = "renamed".into(),
        ] {
            let mut p = base.clone();
            live(&mut p);
            assert_eq!(restart_fingerprint(&p, &dir), fp, "applies without a restart");
        }

        let mut off = base.clone();
        off.groups.push(RuleGroup::new("idle", "idle", TAG_AUTO));
        off.groups.last_mut().unwrap().enabled = false;
        assert_eq!(restart_fingerprint(&off, &dir), fp, "editing a disabled group needs no restart");

        // Everything else changes the config itself.
        for change in [
            |p: &mut Profile| p.groups[2].domain_suffixes.push("example.com".into()),
            |p: &mut Profile| p.groups.swap(2, 3),
            // a domain group between direct and proxied: its FakeIP DNS rule and QUIC block come or go
            |p: &mut Profile| p.groups[2].outbound = TAG_DIRECT.into(),
            |p: &mut Profile| p.groups[4].outbound = TAG_REJECT.into(),
            |p: &mut Profile| p.groups[1].outbound = TAG_REJECT.into(),
            |p: &mut Profile| p.final_outbound = TAG_REJECT.into(),
            |p: &mut Profile| p.geoip.outbound = TAG_REJECT.into(),
            |p: &mut Profile| p.geoip.countries.push("jp".into()),
            |p: &mut Profile| p.geoip.countries.clear(),
            |p: &mut Profile| p.log_level = LogLevel::Debug,
            |p: &mut Profile| p.nodes.pop().map(|_| ()).unwrap(),
        ] {
            let mut p = base.clone();
            change(&mut p);
            assert_ne!(restart_fingerprint(&p, &dir), fp);
        }

        // Unblocking a blocked group brings its selector back: a restart as well.
        let mut blocked = base.clone();
        blocked.groups[1].outbound = TAG_REJECT.into();
        let mut unblocked = blocked.clone();
        unblocked.groups[1].outbound = "mudfish-655".into();
        assert_ne!(restart_fingerprint(&blocked, &dir), restart_fingerprint(&unblocked, &dir));

        let mut bad = base.clone();
        bad.groups.push(RuleGroup::new("empty", "empty", TAG_AUTO));
        assert_eq!(restart_fingerprint(&bad, &dir), Err("群組「empty」沒有任何比對條件".to_string()));
    }

    #[test]
    fn selector_members_list_what_can_be_switched() {
        let c = generate(&sample_profile(), &opts(&ruleset_dir())).unwrap();
        let m = selector_members(&c);
        assert_eq!(
            m.keys().map(String::as_str).collect::<Vec<_>>(),
            ["final", "geoip", "global", "group-game", "group-games", "group-lan", "group-site"]
        );
        assert!(m["final"].contains("direct") && m["group-game"].contains("direct"));
        assert!(!m["global"].contains("direct") && m["global"].contains("auto"));
        assert!(m.values().all(|members| !members.contains("reject")));
    }

    #[test]
    fn stale_outbounds_fall_back() {
        let mut p = sample_profile();
        p.final_outbound = "mudfish-1".into();
        p.geoip.outbound = "mudfish-1".into();
        p.global_outbound = "mudfish-1".into();
        p.groups[1].outbound = "mudfish-2".into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        for tag in ["final", "geoip", "global", "group-game"] {
            assert_eq!(find_outbound(&c, tag)["default"], "auto", "{tag}");
        }
    }

    #[test]
    fn fixed_groups_can_be_direct_a_node_or_auto() {
        let mut p = sample_profile();
        p.final_outbound = "mudfish-591".into();
        p.geoip.outbound = TAG_AUTO.into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        assert_eq!(find_outbound(&c, "final")["default"], "mudfish-591");
        assert_eq!(find_outbound(&c, "geoip")["default"], "auto");
        // either can still go direct live
        for tag in ["final", "geoip"] {
            assert!(find_outbound(&c, tag)["outbounds"].as_array().unwrap().contains(&json!("direct")));
        }
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
        for tag in ["final", "geoip", "global", "group-game"] {
            assert!(find_outbound(&c, tag)["outbounds"].as_array().unwrap().contains(&json!("warp-test")), "{tag}");
        }
        assert_eq!(find_outbound(&c, "auto")["outbounds"], json!(["mudfish-591", "mudfish-655"]), "auto excludes WARP while Mudfish nodes exist");
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
    fn hand_added_nodes_become_http_and_socks_outbounds_with_their_own_accounts() {
        let dir = ruleset_dir();
        let mut p = sample_profile();
        p.nodes.extend([
            custom_node("custom-http", ProxyProtocol::Http, true), // `udp` on an HTTP node (a hand edit) changes nothing
            custom_node("custom-socks", ProxyProtocol::Socks5, false),
            custom_node("custom-udp", ProxyProtocol::Socks5, true),
            custom_node("custom-open", ProxyProtocol::Http, false),
        ]);
        p.groups[2].outbound = "custom-http".into();
        let accounts = auth(&[("custom-http", "tslv", "secret"), ("custom-socks", "u", "p"), ("custom-udp", "u2", "p2"), ("custom-open", "", "")]);
        let mut o = opts(&dir);
        o.proxy_auth = &accounts;
        let c = generate(&p, &o).unwrap();

        assert_eq!(
            find_outbound(&c, "custom-http"),
            &json!({ "type": "http", "tag": "custom-http", "server": "198.51.100.7", "server_port": 5092, "username": "tslv", "password": "secret" }),
            "no `version`, and no `network`: the HTTP outbound has neither"
        );
        assert_eq!(
            find_outbound(&c, "custom-socks"),
            &json!({ "type": "socks", "tag": "custom-socks", "server": "198.51.100.7", "server_port": 5092, "version": "5",
                     "username": "u", "password": "p", "network": "tcp" })
        );
        assert!(find_outbound(&c, "custom-udp").get("network").is_none(), "UDP allowed");
        assert_eq!(
            find_outbound(&c, "custom-open"),
            &json!({ "type": "http", "tag": "custom-open", "server": "198.51.100.7", "server_port": 5092 }),
            "no username: no authentication"
        );
        let mudfish = find_outbound(&c, "mudfish-591");
        assert_eq!((mudfish["username"].as_str(), mudfish["password"].as_str()), (Some("user"), Some("pass")), "Mudfish nodes keep the Mudfish account");

        // Selectable everywhere, but `auto` keeps to the Mudfish nodes.
        for tag in ["final", "geoip", "global", "group-game"] {
            let members = find_outbound(&c, tag)["outbounds"].as_array().unwrap();
            assert!(["custom-http", "custom-socks", "custom-udp", "custom-open"].iter().all(|t| members.contains(&json!(t))), "{tag}");
        }
        assert_eq!(find_outbound(&c, "group-site")["default"], "custom-http");
        assert_eq!(find_outbound(&c, "auto")["outbounds"], json!(["mudfish-591", "mudfish-655"]));
    }

    /// `auto` takes the hand-added nodes only when there is nothing else, rather than having no member.
    #[test]
    fn auto_picks_hand_added_nodes_only_without_other_nodes() {
        let dir = ruleset_dir();
        let keys = warp_keys();
        let accounts = auth(&[("custom-1", "u", "p"), ("custom-2", "u", "p")]);
        let mut o = opts(&dir);
        o.wireguard_keys = &keys;
        o.proxy_auth = &accounts;
        let auto = |extra: Option<ProxyNode>| {
            let mut nodes = vec![custom_node("custom-1", ProxyProtocol::Http, false), custom_node("custom-2", ProxyProtocol::Socks5, false)];
            nodes.extend(extra);
            let c = generate(&Profile { nodes, ..Profile::default() }, &o).unwrap();
            find_outbound(&c, "auto")["outbounds"].clone()
        };
        assert_eq!(auto(Some(node(591))), json!(["mudfish-591"]));
        assert_eq!(auto(Some(warp_node())), json!(["warp-test"]), "WARP comes before hand-added nodes");
        assert_eq!(auto(None), json!(["custom-1", "custom-2"]));
    }

    #[test]
    fn hand_added_nodes_need_their_own_account_entry_not_the_mudfish_account() {
        let dir = ruleset_dir();
        let p = Profile { nodes: vec![custom_node("custom-1", ProxyProtocol::Http, false)], ..Profile::default() };
        let mut o = opts(&dir);
        o.username = "";
        o.password = "";
        assert_eq!(generate(&p, &o), Err(GenerateError::MissingProxyAuth("custom custom-1".into())));

        let accounts = auth(&[("custom-1", "u", "p")]);
        o.proxy_auth = &accounts;
        assert!(generate(&p, &o).is_ok(), "no Mudfish account needed");

        let mut mixed = p.clone();
        mixed.nodes.push(node(591));
        assert_eq!(generate(&mixed, &o), Err(GenerateError::NoCredentials), "a Mudfish node next to it still needs one");
    }

    /// The server of a hand-added node is part of the config, its account is not (placeholders,
    /// like every other secret): a changed password applies on the next connect without a prompt.
    #[test]
    fn fingerprint_sees_hand_added_servers_but_not_their_accounts() {
        let dir = ruleset_dir();
        let mut p = sample_profile();
        let base = restart_fingerprint(&p, &dir);
        p.nodes.push(custom_node("custom-1", ProxyProtocol::Http, false));
        let with_node = restart_fingerprint(&p, &dir);
        assert!(with_node.is_ok(), "no account is needed for the fingerprint");
        assert_ne!(with_node, base, "a new node is a new outbound");

        for change in [
            |n: &mut ProxyNode| n.port = 8080,
            |n: &mut ProxyNode| n.server = "203.0.113.9".into(),
            |n: &mut ProxyNode| n.custom = Some(CustomProxy { protocol: ProxyProtocol::Socks5 }),
        ] {
            let mut changed = p.clone();
            change(changed.nodes.last_mut().unwrap());
            assert_ne!(restart_fingerprint(&changed, &dir), with_node);
        }
        let mut renamed = p.clone();
        renamed.nodes.last_mut().unwrap().name = "renamed".into();
        assert_eq!(restart_fingerprint(&renamed, &dir), with_node, "the name is not in the config");
    }

    #[test]
    fn blocked_final_adds_a_catch_all_instead_of_a_selector() {
        let mut p = sample_profile();
        p.final_outbound = TAG_REJECT.into();
        let c = generate(&p, &opts(&ruleset_dir())).unwrap();
        let r = rules(&c);
        assert_eq!(r[r.len() - 1], json!({ "network": ["tcp", "udp"], "action": "reject" }));
        assert_eq!(r[r.len() - 2]["outbound"], "geoip", "GeoIP is decided before the catch-all");
        assert_eq!(c["route"]["final"], "direct");
        assert!(!has_outbound(&c, "final"));
        assert!(!p.selections().selectors.contains_key("final"));
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
        let mut acl = RuleGroup::new("acl", "acl", "warp-test");
        acl.rule_sets = vec!["acl:Steam".into()];
        acl.process_names = vec!["steam.exe".into()];
        acl.udp = UdpPolicy::Reject;
        p.groups.push(acl);
        // Hand-added nodes of both protocols, with and without an account, one of them a group's outbound.
        let mut web = RuleGroup::new("web", "web", "custom-http");
        web.domain_suffixes = vec!["example.org".into()];
        p.groups.push(web);
        p.nodes.push(warp_node());
        p.nodes.extend([
            custom_node("custom-http", ProxyProtocol::Http, false),
            custom_node("custom-socks", ProxyProtocol::Socks5, false),
            custom_node("custom-udp", ProxyProtocol::Socks5, true),
            custom_node("custom-open", ProxyProtocol::Http, false),
        ]);
        let keys = warp_keys();
        let accounts = auth(&[("custom-http", "tslv", "secret"), ("custom-socks", "u", "p"), ("custom-udp", "u2", "p2"), ("custom-open", "", "")]);
        let mut o = opts(&dir);
        o.wireguard_keys = &keys;
        o.proxy_auth = &accounts;
        o.self_exe = Some(r"C:\Program Files\ProxyDesk\proxydesk.exe");
        // AND groups with app + domain + IP, one of them with a UDP policy of its own: the logical
        // `and`, and the UDP guard wrapped around it, must pass the real validator too.
        let and_group = |id: &str, udp: UdpPolicy| {
            let mut g = RuleGroup::new(id, id, "mudfish-655");
            g.match_mode = MatchMode::All;
            g.process_names = vec!["game.exe".into()];
            g.domain_suffixes = vec!["example.com".into()];
            g.ip_cidrs = vec!["1.2.3.0/24".into()];
            g.udp = udp;
            g
        };
        let or_groups = p.groups.clone();
        // (FakeIP, final, GeoIP outbound, GeoIP countries, with the AND groups)
        let cases = [
            (true, TAG_DIRECT, "warp-test", vec!["tw"], false),
            (false, "mudfish-591", TAG_AUTO, vec!["tw", "jp"], false),
            (true, TAG_REJECT, TAG_DIRECT, vec!["tw"], false),
            (true, TAG_AUTO, TAG_REJECT, vec!["tw"], false),
            (true, TAG_DIRECT, TAG_DIRECT, vec![], false),
            (true, TAG_DIRECT, TAG_AUTO, vec!["tw"], true),
            (false, "custom-socks", "custom-open", vec!["tw"], false),
        ];
        for (i, (fakeip, final_outbound, geoip_outbound, countries, with_and)) in cases.into_iter().enumerate() {
            p.dns.fakeip = fakeip;
            p.final_outbound = final_outbound.into();
            p.geoip = GeoIpGroup { countries: countries.into_iter().map(String::from).collect(), outbound: geoip_outbound.into() };
            p.groups = or_groups.clone();
            if with_and {
                p.groups.extend([and_group("both", UdpPolicy::Follow), and_group("both-udp", UdpPolicy::Direct)]);
            }
            let c = generate(&p, &o).unwrap();
            let path = std::env::temp_dir().join(format!("proxydesk-check-{i}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&c).unwrap()).unwrap();
            let out = std::process::Command::new(&bin).args(["check", "-c"]).arg(&path).output().unwrap();
            let _ = std::fs::remove_file(&path);
            assert!(
                out.status.success(),
                "sing-box check failed for case {i} ({final_outbound}, GeoIP {geoip_outbound}, FakeIP {fakeip}, AND groups {with_and}): {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

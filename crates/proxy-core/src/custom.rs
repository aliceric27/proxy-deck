//! Proxies added by hand: an HTTP or SOCKS5 server with an account of its own (Webshare and the
//! like). The profile keeps only the server; the account lives in the OS credential store and
//! reaches the generator through `GenerateOptions::proxy_auth`.

use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::model::{CustomProxy, ProxyNode, ProxyProtocol};

/// Ports assumed when a link names none.
const DEFAULT_HTTP_PORT: u16 = 80;
const DEFAULT_SOCKS_PORT: u16 = 1080;
/// RFC 1929 caps the SOCKS5 username and password at 255 bytes; HTTP gets the same limit.
const MAX_AUTH_LEN: usize = 255;

/// Username and password of a hand-added node. An empty username means the proxy takes no
/// authentication (say, one that allows the user's IP).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// A pasted proxy link split into its parts, for the add dialog to fill in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct ProxyLink {
    pub protocol: ProxyProtocol,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// What the add/edit dialog sends for a hand-added node.
#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
pub struct CustomNodeInput {
    /// Empty: `server:port`.
    pub name: String,
    pub protocol: ProxyProtocol,
    pub server: String,
    pub port: u16,
    /// Ignored for HTTP, which only tunnels TCP.
    pub udp: bool,
    /// Empty: the proxy takes no authentication.
    pub username: String,
    /// `None` keeps the stored password (editing a node); a new node has none stored.
    #[serde(default)]
    pub password: Option<String>,
}

impl CustomNodeInput {
    /// The node under `tag` and the account to store for it, or why the input is unusable.
    /// `stored` is the account saved for the node so far (editing): a `None` password keeps it.
    pub fn into_node(self, tag: String, stored: Option<ProxyAuth>) -> Result<(ProxyNode, ProxyAuth), String> {
        let server = normalize_server(&self.server)?;
        if self.port == 0 {
            return Err("請輸入連接埠（1–65535）".into());
        }
        let username = self.username.trim().to_string();
        let password = match (username.is_empty(), self.password) {
            (true, Some(p)) if !p.is_empty() => return Err("有密碼時也要填使用者名稱".into()),
            // No username: the proxy takes no authentication, so a stored password goes too.
            (true, _) => String::new(),
            (false, Some(p)) => p,
            (false, None) => stored.map(|a| a.password).unwrap_or_default(),
        };
        if username.len() > MAX_AUTH_LEN || password.len() > MAX_AUTH_LEN {
            return Err("使用者名稱或密碼太長（最多 255 個位元組）".into());
        }
        if self.protocol == ProxyProtocol::Http && username.contains(':') {
            return Err("HTTP 代理的使用者名稱不能包含冒號".into());
        }
        let name = match self.name.trim() {
            "" => host_port(&server, self.port),
            name => name.to_string(),
        };
        let node = ProxyNode {
            tag,
            sid: 0,
            name,
            server,
            port: self.port,
            country: String::new(),
            udp: self.protocol == ProxyProtocol::Socks5 && self.udp,
            wireguard: None,
            custom: Some(CustomProxy { protocol: self.protocol }),
        };
        Ok((node, ProxyAuth { username, password }))
    }

    /// The account to store for the node under `tag`, only once `saved` (that node as the profile
    /// holds it now) is exactly the node this input builds. After a profile save that failed, the
    /// profile still has the old node or none, and the stored account must keep matching it.
    pub fn account_for_saved(self, tag: String, saved: Option<&ProxyNode>, stored: Option<ProxyAuth>) -> Result<ProxyAuth, String> {
        let (node, auth) = self.into_node(tag, stored)?;
        if saved == Some(&node) {
            Ok(auth)
        } else {
            Err("節點設定尚未儲存，帳號密碼沒有更新".into())
        }
    }
}

/// Splits a pasted proxy into its parts. Accepts `http://user:pass@host:port`, `socks5://…`
/// (also `socks5h://` and `socks://`; the username and password percent-decoded), and the
/// scheme-less forms, all HTTP (the dialog can switch to SOCKS5): the `host:port:user:pass`
/// lines of a Webshare proxy list, `user:pass@host:port` and `host:port`. Only the first
/// non-empty line is read.
pub fn parse_proxy_link(text: &str) -> Result<ProxyLink, String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty()).ok_or("請貼上代理連結")?;
    let Some((scheme, rest)) = line.split_once("://") else { return parse_bare(line) };
    let (protocol, default_port) = match scheme.to_ascii_lowercase().as_str() {
        "http" => (ProxyProtocol::Http, DEFAULT_HTTP_PORT),
        "socks5" | "socks5h" | "socks" => (ProxyProtocol::Socks5, DEFAULT_SOCKS_PORT),
        "https" => return Err("不支援 HTTPS（TLS）代理，請改用 http:// 或 socks5://".into()),
        other => return Err(format!("不支援 {other}:// 連結，只接受 http:// 與 socks5://")),
    };
    // As in a URL, the authority ends at the path, query or fragment (a proxy has no use for
    // them), and its last `@` ends the username and password.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (username, password, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => {
            let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
            (percent_decode(user)?, percent_decode(pass)?, host_port)
        }
        None => (String::new(), String::new(), authority),
    };
    let (server, port) = split_host_port(host_port, Some(default_port))?;
    Ok(ProxyLink { protocol, server, port, username, password })
}

/// The scheme-less forms. `host:port[:user[:pass]]` wins when its second part is a port, so a
/// Webshare line keeps an `@` or `:` in its password; otherwise `user:pass@host:port`.
fn parse_bare(line: &str) -> Result<ProxyLink, String> {
    let protocol = ProxyProtocol::Http;
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() >= 2 && !parts[0].contains('@') && !parts[1].is_empty() && parts[1].bytes().all(|b| b.is_ascii_digit()) {
        return Ok(ProxyLink {
            protocol,
            server: normalize_server(parts[0])?,
            port: parse_port(parts[1])?,
            username: parts.get(2).copied().unwrap_or_default().to_string(),
            password: parts.get(3).copied().unwrap_or_default().to_string(),
        });
    }
    let (userinfo, host_port) = line.rsplit_once('@').ok_or("無法辨識：請貼上 http://…、socks5://…，或「主機:連接埠:帳號:密碼」")?;
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (server, port) = split_host_port(host_port, None)?;
    Ok(ProxyLink { protocol, server, port, username: user.to_string(), password: pass.to_string() })
}

/// `host:port` or `[v6]:port`; without a port, `default_port` if there is one.
fn split_host_port(s: &str, default_port: Option<u16>) -> Result<(String, u16), String> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (v6, after) = rest.split_once(']').ok_or("IPv6 位址少了「]」")?;
            match after {
                "" => (v6, None),
                _ => (v6, Some(after.strip_prefix(':').ok_or_else(|| format!("位址「{s}」格式不正確"))?)),
            }
        }
        None => match s.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (s, None),
        },
    };
    let port = match port.filter(|p| !p.is_empty()) {
        Some(p) => parse_port(p)?,
        None => default_port.ok_or("缺少連接埠")?,
    };
    Ok((normalize_server(host)?, port))
}

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>().ok().filter(|&port| port != 0).ok_or_else(|| format!("連接埠「{p}」不正確，應為 1–65535"))
}

/// A host name, an IPv4 address or an IPv6 address (brackets dropped), or why it is none.
fn normalize_server(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let host = trimmed.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(trimmed);
    if host.is_empty() {
        return Err("請輸入伺服器位址".into());
    }
    let valid = if host.contains(':') {
        host.parse::<Ipv6Addr>().is_ok()
    } else {
        host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    };
    if valid {
        Ok(host.to_string())
    } else {
        Err(format!("伺服器位址「{host}」格式不正確：只填主機名稱或 IP，不含 http:// 與連接埠"))
    }
}

/// `host:port`, with an IPv6 address in brackets.
fn host_port(server: &str, port: u16) -> String {
    if server.contains(':') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

/// `%40` → `@` (RFC 3986, UTF-8). A `%` that starts no escape stays as it is.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let hex = |i: usize| bytes.get(i).and_then(|&b| (b as char).to_digit(16));
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if let (b'%', Some(high), Some(low)) = (bytes[i], hex(i + 1), hex(i + 2)) {
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "連結裡的帳號或密碼不是有效的 UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(protocol: ProxyProtocol, server: &str, port: u16, username: &str, password: &str) -> ProxyLink {
        ProxyLink { protocol, server: server.into(), port, username: username.into(), password: password.into() }
    }

    fn input(protocol: ProxyProtocol, username: &str, password: Option<&str>) -> CustomNodeInput {
        CustomNodeInput {
            name: String::new(),
            protocol,
            server: " 198.51.100.7 ".into(),
            port: 5092,
            udp: true,
            username: username.into(),
            password: password.map(String::from),
        }
    }

    #[test]
    fn parses_scheme_links() {
        use ProxyProtocol::*;
        // the shape curl takes and Webshare shows
        assert_eq!(parse_proxy_link("http://tslv:secret@198.51.100.7:5092/").unwrap(), link(Http, "198.51.100.7", 5092, "tslv", "secret"));
        assert_eq!(parse_proxy_link("  socks5://u:p@proxy.example.com:1080\n").unwrap(), link(Socks5, "proxy.example.com", 1080, "u", "p"));
        for scheme in ["socks5h", "socks", "SOCKS5"] {
            assert_eq!(parse_proxy_link(&format!("{scheme}://u:p@h:1")).unwrap().protocol, Socks5, "{scheme}");
        }
        assert_eq!(parse_proxy_link("HTTP://h:8080").unwrap(), link(Http, "h", 8080, "", ""), "no account");
        // default ports, and an empty port is no port
        assert_eq!(parse_proxy_link("http://u:p@h").unwrap().port, 80);
        assert_eq!(parse_proxy_link("http://h:/").unwrap().port, 80);
        assert_eq!(parse_proxy_link("socks5://h").unwrap().port, 1080);
        // percent-encoding; the last `@` of the authority ends the account; a path or query is ignored
        assert_eq!(parse_proxy_link("http://me%40mail.com:p%3Ass%25@h:3128").unwrap(), link(Http, "h", 3128, "me@mail.com", "p:ss%"));
        assert_eq!(parse_proxy_link("http://u:p@ss@h:3128/x?y#z").unwrap(), link(Http, "h", 3128, "u", "p@ss"));
        assert_eq!(parse_proxy_link("http://u:50%off@h:1").unwrap().password, "50%off", "a stray % stays");
        assert_eq!(parse_proxy_link("http://u@h:1").unwrap(), link(Http, "h", 1, "u", ""), "username only");
        // IPv6 needs brackets, which the server drops
        assert_eq!(parse_proxy_link("socks5://[2001:db8::1]:1080").unwrap(), link(Socks5, "2001:db8::1", 1080, "", ""));
        assert_eq!(parse_proxy_link("socks5://[2001:db8::1]").unwrap().port, 1080);
        // only the first non-empty line
        assert_eq!(parse_proxy_link("\n\nhttp://a:b@h1:1\nhttp://c:d@h2:2").unwrap().server, "h1");
    }

    #[test]
    fn parses_scheme_less_lines_as_http() {
        use ProxyProtocol::*;
        // a line of a Webshare proxy list download; the password may contain `:` or `@`
        assert_eq!(parse_proxy_link("198.51.100.7:5092:tslv:secret").unwrap(), link(Http, "198.51.100.7", 5092, "tslv", "secret"));
        assert_eq!(parse_proxy_link("198.51.100.7:5092:tslv:se:cr@t").unwrap().password, "se:cr@t");
        assert_eq!(parse_proxy_link("h:8080").unwrap(), link(Http, "h", 8080, "", ""));
        assert_eq!(parse_proxy_link("h:8080:user").unwrap(), link(Http, "h", 8080, "user", ""));
        assert_eq!(parse_proxy_link("user:pass@h:8080").unwrap(), link(Http, "h", 8080, "user", "pass"));
        assert_eq!(parse_proxy_link("12345:678@h:80").unwrap(), link(Http, "h", 80, "12345", "678"), "a numeric account is no port");
    }

    #[test]
    fn rejects_what_is_no_usable_proxy() {
        for bad in [
            "",
            " \n ",
            "https://u:p@h:443",
            "vmess://abc",
            "socks4://h:1080",
            "http://h:0",
            "http://h:65536",
            "http://h:port",
            "http://:8080",
            "http://u:p@:8080",
            "http://[2001:db8::1",
            "http://2001:db8::1",
            "http://bad host:80",
            "just-a-host",
            "user:pass@h",
            "h:0:u:p",
        ] {
            assert!(parse_proxy_link(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(parse_proxy_link("https://h").unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn builds_an_http_node_that_is_tcp_only() {
        let (node, auth) = input(ProxyProtocol::Http, " tslv ", Some("secret")).into_node("custom-1".into(), None).unwrap();
        assert_eq!(node.tag, "custom-1");
        assert_eq!((node.server.as_str(), node.port, node.sid), ("198.51.100.7", 5092, 0));
        assert_eq!(node.name, "198.51.100.7:5092", "an empty name becomes server:port");
        assert!(!node.udp, "HTTP only tunnels TCP, whatever the dialog said");
        assert!(node.is_custom() && !node.is_mudfish());
        assert_eq!(node.custom, Some(CustomProxy { protocol: ProxyProtocol::Http }));
        assert_eq!(node.country, "");
        assert_eq!(auth, ProxyAuth { username: "tslv".into(), password: "secret".into() });

        let (socks, _) = input(ProxyProtocol::Socks5, "u", Some("p")).into_node("custom-2".into(), None).unwrap();
        assert!(socks.udp, "SOCKS5 keeps the choice");
        let mut named = input(ProxyProtocol::Socks5, "", None);
        named.name = "  Webshare US ".into();
        named.server = "[2001:db8::1]".into();
        let (node, auth) = named.into_node("custom-3".into(), None).unwrap();
        assert_eq!((node.name.as_str(), node.server.as_str()), ("Webshare US", "2001:db8::1"));
        assert_eq!(auth, ProxyAuth::default(), "no username: no authentication");

        let mut unnamed_v6 = input(ProxyProtocol::Socks5, "", None);
        unnamed_v6.server = "2001:db8::1".into();
        assert_eq!(unnamed_v6.into_node("custom-4".into(), None).unwrap().0.name, "[2001:db8::1]:5092");
    }

    #[test]
    fn editing_keeps_or_replaces_the_stored_password() {
        let stored = || Some(ProxyAuth { username: "old".into(), password: "kept".into() });
        let auth = |i: CustomNodeInput| i.into_node("custom-1".into(), stored()).unwrap().1;
        assert_eq!(auth(input(ProxyProtocol::Http, "new", None)), ProxyAuth { username: "new".into(), password: "kept".into() }, "None keeps it");
        assert_eq!(auth(input(ProxyProtocol::Http, "new", Some("fresh"))).password, "fresh");
        assert_eq!(auth(input(ProxyProtocol::Http, "new", Some(""))).password, "", "an explicit empty password (an API key as username)");
        assert_eq!(auth(input(ProxyProtocol::Http, " ", None)), ProxyAuth::default(), "clearing the username drops the account");
        assert_eq!(input(ProxyProtocol::Http, "new", None).into_node("custom-1".into(), None).unwrap().1.password, "", "nothing stored");
    }

    /// The account follows the profile: written for the node the profile holds, never for one
    /// whose save did not happen (a new node, or an edit whose profile write failed).
    #[test]
    fn an_account_is_only_stored_for_the_node_the_profile_holds() {
        let (node, _) = input(ProxyProtocol::Http, "u", Some("p")).into_node("custom-1".into(), None).unwrap();
        let account = |i: CustomNodeInput, saved: Option<&ProxyNode>, stored| i.account_for_saved("custom-1".into(), saved, stored);
        assert_eq!(
            account(input(ProxyProtocol::Http, "u", Some("p")), Some(&node), None).unwrap(),
            ProxyAuth { username: "u".into(), password: "p".into() }
        );
        assert!(account(input(ProxyProtocol::Http, "u", Some("p")), None, None).is_err(), "a new node that was never saved");
        let mut before_edit = node.clone();
        before_edit.port = 8080;
        assert!(account(input(ProxyProtocol::Http, "u", Some("p")), Some(&before_edit), None).is_err(), "the profile still has the old server");
        // A password-only edit leaves the node as it was, so its account goes through (or is kept).
        let stored = || Some(ProxyAuth { username: "u".into(), password: "old".into() });
        assert_eq!(account(input(ProxyProtocol::Http, "u", Some("new")), Some(&node), stored()).unwrap().password, "new");
        assert_eq!(account(input(ProxyProtocol::Http, "u", None), Some(&node), stored()).unwrap().password, "old");
        assert!(account(input(ProxyProtocol::Http, "", Some("p")), Some(&node), None).is_err(), "still validated");
    }

    #[test]
    fn rejects_unusable_input() {
        let err = |i: CustomNodeInput| i.into_node("custom-1".into(), None).unwrap_err();
        assert!(err(input(ProxyProtocol::Http, "", Some("p"))).contains("使用者名稱"), "a password needs a username");
        assert!(err(input(ProxyProtocol::Http, "a:b", Some("p"))).contains("冒號"), "Basic auth cannot carry a colon in the username");
        assert!(input(ProxyProtocol::Socks5, "a:b", Some("p")).into_node("custom-1".into(), None).is_ok(), "SOCKS5 can");
        assert!(err(input(ProxyProtocol::Socks5, &"u".repeat(256), Some("p"))).contains("太長"));
        assert!(err(input(ProxyProtocol::Socks5, "u", Some(&"p".repeat(256)))).contains("太長"));
        let mut no_port = input(ProxyProtocol::Http, "u", Some("p"));
        no_port.port = 0;
        assert!(err(no_port).contains("連接埠"));
        for server in ["", "  ", "http://h", "h:8080", "a b", "h/x", "u@h", "2001:db8::zz", "例子.tw"] {
            let mut i = input(ProxyProtocol::Http, "u", Some("p"));
            i.server = server.into();
            assert!(i.into_node("custom-1".into(), None).is_err(), "{server:?} is no server");
        }
    }
}

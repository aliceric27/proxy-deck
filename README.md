<div align="center">

<img src="assets/hero.svg" width="100%" alt="ProxyDesk — a Windows split-tunnel client that sends only the apps and domains you pick through a proxy" />

English | [繁體中文](README.zh-TW.md)

[![Release](https://img.shields.io/github/v/release/aliceric27/proxy-deck?sort=semver)](https://github.com/aliceric27/proxy-deck/releases)
[![CI](https://github.com/aliceric27/proxy-deck/actions/workflows/ci.yml/badge.svg)](https://github.com/aliceric27/proxy-deck/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/github/downloads/aliceric27/proxy-deck/total)](https://github.com/aliceric27/proxy-deck/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
<br />
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-0078D6?logo=windows&logoColor=white)](#install)
[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![sing-box](https://img.shields.io/badge/sing--box-1.14.2-4B5563)](https://github.com/SagerNet/sing-box)
[![Rust](https://img.shields.io/badge/Rust-stable-B7410E?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)

</div>

---

ProxyDesk is a Windows desktop proxy client. It pulls SOCKS5 nodes from Mudfish and runs sing-box in TUN mode so that **only the apps or domains you choose** go through a proxy; everything else is handled by GeoIP and a final rule (direct by default).

## Features

- **Per-app and per-domain routing**: a group can mix programs, domains, rule sets and IP ranges, each group with its own outbound (direct, block, auto-select or a specific node), matched in priority order. A group's conditions can match on *any* or *all*.
- **Three node sources**: Mudfish nodes, generated Cloudflare WARP nodes, and hand-added HTTP / SOCKS5 proxies (e.g. Webshare — paste `http://user:pass@host:port`).
- **Auto-select**: with several Mudfish nodes added, picks the one with the lowest latency.
- **Import**: paste or pick a JSON file under *New group → Import* to add many groups at once (ProxyDesk groups, Karing diversion rules, sing-box rule sets or a config's route rules).
- **Traffic history**: upload / download per connection session, split by exit and by program.
- **Live switching**: most outbound changes take effect without reconnecting.
- **Secrets stay off disk**: the Mudfish account, WARP private keys and hand-added proxy credentials live only in Windows Credential Manager — never in the profile or logs. The generated sing-box config is passed over stdin and never written to disk.

> The UI is currently in Traditional Chinese only.

## Install

1. Download `ProxyDesk_<version>_x64-setup.exe` from [Releases](https://github.com/aliceric27/proxy-deck/releases).
2. Run the installer. It is not code-signed, so Windows SmartScreen may block it; once you trust the source, click *More info → Run anyway*.
3. ProxyDesk asks for UAC elevation every time it starts: TUN mode needs administrator rights.

Requirements: Windows 10 / 11 x64 and WebView2 (built into Windows 11; the installer fetches it on Windows 10). Mudfish nodes need a [Mudfish](https://mudfish.net) account with credit.

## Quick start

1. **設定 (Settings) → Mudfish 帳號**: enter your Mudfish ID and password and click 測試帳號 (Test). The test is a SOCKS5 authentication only and uses no traffic.
2. **節點 (Nodes)**: tick the Mudfish nodes you want in the list on the left, or generate a WARP node / add your own proxy.
3. **分流群組 (Groups)**: create a group, add the programs (e.g. `game.exe`; `.exe` is appended for you) or domains that should be proxied, and pick a node or 自動選擇 (auto-select) as its outbound.
4. Click **連線 (Connect)** at the bottom left.

## Routing

Rules are matched top to bottom: custom groups → GeoIP → final.

- **Custom groups**: see *Features* above.
- **GeoIP**: traffic whose destination IP is in the chosen countries or regions (Taiwan by default) gets one outbound.
- **final**: everything that matched nothing above gets one outbound (direct by default).

GeoIP and final are fixed groups that cannot be removed or disabled. Switching them between direct and a node takes full effect immediately, without reconnecting. Custom groups also switch between nodes live, but switching a group between direct and proxied needs a reconnect for its DNS, QUIC and UDP rules to take full effect. Switching to or from *block* always needs a reconnect. Global mode has its own outbound.

Hand-added nodes never take part in auto-select; pick them explicitly in a group or outbound.

The Mudfish node list is fetched again every time the app starts, and added Mudfish nodes follow it (address and name). When Mudfish cannot be reached, the last saved list is used and the Nodes page says so.

## Traffic history

The 流量統計 (Traffic) page records each connection session — from clicking Connect until disconnecting or reconnecting — with its upload and download, and charts per-session usage, proxied vs. direct, usage over time, and the split by exit (node) and by program. It keeps recording while the window is hidden in the tray. Sessions are saved to `traffic-history.json` in the data folder, newest 200 kept; only byte counts, times, node names and program file names are stored — no URLs or IPs.

## Where data lives

| What | Where |
|---|---|
| Mudfish account | Windows Credential Manager (`ProxyDesk` / `mudfish-account`) |
| Profile (no passwords), node list cache, traffic history | `%APPDATA%\tw.proxydesk.desktop\` |
| WARP private keys and device tokens | Windows Credential Manager (`ProxyDesk` / `node-<tag>`) |
| Hand-added proxy credentials | Windows Credential Manager (`ProxyDesk` / `node-<tag>`); deleted with the node |
| sing-box working dir (cache.db), writable by administrators only. The generated config (with credentials) reaches sing-box over stdin and is never written to disk | `%ProgramData%\ProxyDesk\run\` |

When the profile format is upgraded, the original file is first copied to `profile.v<old version>-backup.json` in the same folder (never overwritten). Routing stays the same after an upgrade, with two small differences:

- If the old default node was *direct*, Global mode becomes Direct mode (which also sends everything direct).
- A group that followed a *direct* default node is now a plain direct group, so its UDP policy no longer applies (direct groups have no UDP or QUIC rules).

If the profile cannot be read (corrupted, or locked by another program), one of two things happens:

- If it can be moved aside, it is renamed to `profile.json.bad` (or `.bad-2`, `.bad-3`, … — never overwriting), the defaults are used, and a warning is shown at the top of the window.
- If it cannot even be renamed (usually another program such as antivirus holds it for a moment), ProxyDesk shows an error and does not start, leaving the original untouched so the first save cannot overwrite it. Close the other program and start again.

## Building from source

- UI: Tauri v2 (Rust) + React + Tailwind, desktop-first layout
- Core: unmodified sing-box 1.14.2, run as a separate child process (GPL-3.0, not linked)

Requirements: Rust (stable, MSVC), Visual Studio Build Tools (C++ workload), Node.js 22+, WebView2.

```powershell
pwsh -File scripts/fetch-singbox.ps1   # downloads sing-box, checks its SHA-256, puts it in src-tauri/binaries/
pwsh -File scripts/fetch-rulesets.ps1  # downloads the pinned rule-set snapshot, checks its SHA-256, puts it in src-tauri/resources/rulesets/
cd apps/desktop
npm install
npm run tauri dev                       # dev mode; TUN needs an elevated terminal
npm run tauri build                     # builds target/release/bundle/nsis/ProxyDesk_<ver>_x64-setup.exe
```

The app manifest requires administrator rights (that is how v1 gets TUN access). Started from a non-elevated terminal, it shows a UAC prompt.

### Tests

```powershell
cargo test -p proxy-core                # config generator and Mudfish list parsing
$env:SINGBOX_BIN = "apps\desktop\src-tauri\binaries\sing-box-x86_64-pc-windows-msvc.exe"
cargo test -p proxy-core                # also validates generated configs with a real `sing-box check`
cargo test --workspace                  # adds the core state machine (fake launcher) and secured-directory tests (elevated terminal), and regenerates the frontend types
cd apps/desktop; npx tsc --noEmit       # frontend type check
```

M0 verification setup: `docker/m0/` (Linux container, see its README). It reads credentials from `.env.local` in the repo root (`MUDFISH_USER=` / `MUDFISH_PASS=`, never commit it).

### Releasing

Pushing a `v*` tag (e.g. `v0.9.0`) makes GitHub Actions build the NSIS installer on Windows and create a **draft** release with it attached; review it and publish it by hand.

```powershell
git tag v0.9.0
git push origin v0.9.0
```

### Project layout

```
crates/proxy-core/        profile model, Mudfish list parsing, hand-added nodes (link parsing), group import (JSON), Profile → sing-box JSON (pure logic, unit-tested)
apps/desktop/src-tauri/   Tauri backend: sing-box child process, Clash API client, Credential Manager, traffic history, tray
apps/desktop/src/         React frontend: dashboard, nodes, groups, connections, traffic, logs, settings
docker/m0/                M0 Docker verification setup
scripts/                  fetch-singbox.ps1 and fetch-rulesets.ps1
assets/                   logo, README artwork and social preview (editable text masters in assets/src/)
```

## Credits

ProxyDesk would not exist without these projects. The installer bundles them unmodified; see also [`THIRD_PARTY_NOTICES.txt`](apps/desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt).

- [sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0-or-later) — the proxy core, run as a separate process that ProxyDesk does not link against.
- [Karing rule sets](https://github.com/KaringX/karing-ruleset) — the built-in geosite, geoip and acl rule sets are a snapshot (2026-10-06) of its `sing` branch, which compiles:
  - [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) (GPL-3.0) for geosite and geoip, built on [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) (MIT) and public GeoIP data;
  - [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR) (CC BY-SA 4.0) for the acl sets.
- [Karing](https://github.com/KaringX/karing) — the diversion-rule format the group import understands.
- [Tauri](https://tauri.app), [React](https://react.dev), [Tailwind CSS](https://tailwindcss.com) and [Lucide](https://lucide.dev) for the app itself.

## License

ProxyDesk is released under the [MIT License](LICENSE), including the logo and artwork in [`assets/`](assets). The bundled components above keep their own licenses.

ProxyDesk is not affiliated with Mudfish or Cloudflare.

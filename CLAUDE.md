# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

ProxyDesk is a Windows desktop proxy client: it pulls SOCKS5 nodes from Mudfish and runs sing-box in TUN mode so only chosen apps/domains go through the proxy. Design decisions and verified findings live in `docs/PLAN.md` — read the relevant section before changing routing, DNS, or privilege behavior.

## Commands

```powershell
pwsh -File scripts/fetch-singbox.ps1          # required once: sidecar binary is not in git
cd apps/desktop; npm install; npm run tauri dev
npm run tauri build                           # NSIS installer in target/release/bundle/nsis/
cargo test -p proxy-core                      # set SINGBOX_BIN=<sidecar exe> to also run `sing-box check` on generated configs
cargo test -p proxy-core singbox::tests::mixed_group_is_logical_or_of_separate_matchers   # single test
cargo test --workspace                        # also regenerates apps/desktop/src/lib/bindings/*.ts (ts-rs)
cd apps/desktop; npx tsc --noEmit
```

The app manifest is `requireAdministrator` (TUN), so `tauri dev` and `cargo test -p proxydesk` need an elevated shell. Debug builds expose WebView2 DevTools on `PROXYDESK_CDP_PORT` (e.g. 9222) for Playwright `connectOverCDP` UI automation; release builds never do. While that port is open any local process can drive the elevated webview — set it only for automation runs.

## Architecture

- `crates/proxy-core` — no Tauri dependency. `model.rs` is the persisted `Profile` (serde, `#[serde(default)]` so old profiles keep loading — add new fields with defaults; bump `PROFILE_SCHEMA_VERSION` and extend `Profile::migrate` for shape changes). Routing is an ordered list of `RuleGroup`s: each mixes app/domain/rule-set/IP matchers (any-of) and, when proxied, gets its own selector `group-<id>` so its node can switch live. `singbox.rs::generate` turns a Profile into sing-box 1.14 JSON; `restart_fingerprint` is that config minus the live-switchable parts; `mudfish.rs` parses `https://mudfish.net/api/staticnodes`.
- `apps/desktop/src-tauri/src/core.rs` — `CoreManager` is the sing-box state machine: start → check → spawn → health → apply selections → supervise, with a bounded auto-restart (backoff) after crashes and a generation counter so intentional stops never look like crashes. It has no Tauri dependency: process work goes through the `Launcher` trait (`SingBox` in production, a scripted fake in tests) and notifications through `CoreEvents` (`lib.rs` forwards them as `core-status` / batched `core-log` events and to the tray). The config reaches sing-box over stdin (`-c stdin`) and never touches the disk; the working dir `%ProgramData%\ProxyDesk\run` is created admin-only by `paths::secure`. The child sits in a Job Object (KILL_ON_JOB_CLOSE); an orphan sweep runs in the background at startup.
- **Single write path**: the frontend changes the profile only through `updateProfile` → `save_profile` (queued, in order). The backend persists, applies `Profile::selections()` (default node, group outbounds, mode) to a running core through the Clash API, and returns whether a reconnect is still needed (`stale`, from `restart_fingerprint`). Selector switches rely on `interrupt_exist_connections`; only a mode switch closes all connections. Switches to a selector or member the running config lacks (group/node added after the start) are skipped — `stale` already asks for a reconnect. `start` runs `sing-box check` before stopping the running core, and `CoreManager::fail` never stops a running core, so an invalid profile or rejected config costs no connection.
- Types shared with the frontend derive `ts_rs::TS` + `#[ts(export)]`; `cargo test` writes them to `apps/desktop/src/lib/bindings/` (generated and committed — never edit by hand). `src/lib/ipc.ts` only wraps commands and events.
- Live traffic: `traffic.rs` polls the Clash API once per second, only while connected and the window is visible, and pushes a `traffic` event.

## Constraints verified on Windows (don't regress)

- sing-box hands SOCKS5 the IP, not the sniffed domain → proxied domains need FakeIP for remote resolution. A FakeIP destination routed to `direct` still works (the domain is restored and resolved locally).
- Mudfish nodes are IPv4-only: an app choosing an AAAA answer gets EOF on proxied connections → `dns.ipv4_only` defaults on.
- Inside one sing-box rule, `process_name`/`process_path`/`process_path_regex`/`rule_set`/`network`/`port` are ANDed (only domain fields OR). A group's matchers must therefore be separate sub-rules under a logical `or` — never merge different matcher kinds into one rule object.
- Route order: sniff → hijack-dns → ProxyDesk's own exe direct → private IPs direct → `clash_mode` Direct/Global → per group (its QUIC block, its UDP guard, its rule). Exceptions that must hold in every mode go before the mode switches; a group's QUIC block sits right before its rule so a higher-priority direct group still wins.
- In DNS rules only `geosite:` sets are used; geoip/acl sets contain IP CIDRs, which 1.14 rejects next to `query_type`.
- Windows `process_name` matches the full file name (`curl.exe`); the UI auto-appends `.exe`. Paths and directories become case-insensitive `process_path_regex` (`/` accepted as separator).
- sing-box's `cache_file` restores selectors and the Clash mode under its `cache_id`, overriding `default`/`default_mode`; a fresh `cache_id` per start makes the profile win (FakeIP mappings are not keyed by it and survive). Selections are applied again after every health check (auto-restarts reuse the same plan).
- sing-box only switches to Clash modes that some rule mentions (plus `default_mode`), and answers 204 even when it ignores the request. The generator keeps all three modes mentioned (a no-op DNS rule names `Rule`); `ClashClient::set_mode` reads the mode back.
- WARP nodes (`ProxyNode.wireguard`) are WireGuard **endpoints** in sing-box, not outbounds; their private keys live in Credential Manager under `node-<tag>` and are passed to `generate` via `GenerateOptions.wireguard_keys`. `auto` excludes WARP while any Mudfish node exists (WARP's local edge would always win on latency). Removing a WARP node deregisters the device with Cloudflare and deletes its secret.
- Mudfish SOCKS credentials are the account ID/password: keep them in Windows Credential Manager only, never in `profile.json`, on disk or in logs. `.env.local` (gitignored) is for local scripts.

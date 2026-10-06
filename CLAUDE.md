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
cd apps/desktop; npx tsc --noEmit
```

The app manifest is `requireAdministrator` (TUN), so `tauri dev` and `cargo test -p proxydesk` need an elevated shell. Debug builds expose WebView2 DevTools on `PROXYDESK_CDP_PORT` (e.g. 9222) for Playwright `connectOverCDP` UI automation; release builds never do.

## Architecture

- `crates/proxy-core` — no Tauri dependency. `model.rs` is the persisted `Profile` (serde, `#[serde(default)]` so old profiles keep loading — add new fields with defaults; bump `PROFILE_SCHEMA_VERSION` and extend `Profile::migrate` for shape changes). Routing is an ordered list of `RuleGroup`s: each mixes app/domain/rule-set/IP matchers (any-of) and, when proxied, gets its own selector `group-<id>` so its node can switch live. `singbox.rs::generate` turns a Profile into sing-box 1.14 JSON; `mudfish.rs` parses `https://mudfish.net/api/staticnodes`.
- `apps/desktop/src-tauri` — `core.rs` owns the sing-box child: generate → write `run/config.json` → `sing-box check` → spawn with `CREATE_NO_WINDOW` → poll Clash API `/version` → supervise. The child is placed in a Job Object with KILL_ON_JOB_CLOSE so it dies with the app; `kill_orphans` is a second safety net at startup. Clash API port and secret are random per start. `commands.rs` is the frontend surface; `src/lib/ipc.ts` mirrors its types by hand — keep both in sync.
- Group/matcher changes require a core restart (sing-box has no hot reload); default-node selection (`proxy` selector: `auto`, `direct` or a node; used by groups set to "使用預設節點", Global mode and proxied final traffic), per-group node selection (`select_group_outbound`) and mode switch go live through the Clash API and also close existing connections so traffic moves immediately.
- Frontend state: `src/lib/store.tsx` (`updateProfile` persists via `save_profile`; `patchLocal` only for values the backend already saved).

## Constraints verified in M0 (don't regress)

- sing-box hands SOCKS5 the IP, not the sniffed domain → proxied domains need FakeIP for remote resolution.
- Mudfish nodes are IPv4-only: an app choosing an AAAA answer gets EOF on proxied connections → `dns.ipv4_only` defaults on.
- Inside one sing-box rule, `process_name`/`process_path`/`process_path_regex`/`rule_set`/`network`/`port` are ANDed (only domain fields OR). A group's matchers must therefore be separate sub-rules under a logical `or` — never merge different matcher kinds into one rule object.
- In DNS rules only `geosite:` sets are used; geoip/acl sets contain IP CIDRs, which 1.14 rejects next to `query_type`.
- Windows `process_name` matches the full file name (`curl.exe`); the UI auto-appends `.exe`.
- WARP nodes (`ProxyNode.wireguard`) are WireGuard **endpoints** in sing-box, not outbounds; their private keys live in Credential Manager under `node-<tag>` and are passed to `generate` via `GenerateOptions.wireguard_keys`. `auto` excludes WARP while any Mudfish node exists (WARP's local edge would always win on latency).
- With `cache_file` enabled, sing-box restores each selector's last live choice and ignores `default`. `core.rs` therefore re-applies the profile's default node and group outbounds via the Clash API right after the health check; the profile is the source of truth. Keep `cache_file` for the FakeIP store.
- Mudfish SOCKS credentials are the account ID/password: keep them in Windows Credential Manager only, never in `profile.json` or logs. `.env.local` (gitignored) is for local scripts.

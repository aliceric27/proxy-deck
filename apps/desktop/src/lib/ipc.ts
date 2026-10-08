// Typed wrappers around the Rust commands in src-tauri/src/commands.rs. Data types are
// generated from the Rust structs into ./bindings by `cargo test` (ts-rs); never hand-edit them.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AccountCheck } from "./bindings/AccountCheck";
import type { ClashProxy } from "./bindings/ClashProxy";
import type { CoreStatus } from "./bindings/CoreStatus";
import type { CustomNodeInput } from "./bindings/CustomNodeInput";
import type { LogBatch } from "./bindings/LogBatch";
import type { NodeList } from "./bindings/NodeList";
import type { PingResult } from "./bindings/PingResult";
import type { ProcessInfo } from "./bindings/ProcessInfo";
import type { Profile } from "./bindings/Profile";
import type { ProfileState } from "./bindings/ProfileState";
import type { ProxyLink } from "./bindings/ProxyLink";
import type { ProxyNode } from "./bindings/ProxyNode";
import type { RuleGroup } from "./bindings/RuleGroup";
import type { RuleSetCatalog } from "./bindings/RuleSetCatalog";
import type { Snapshot } from "./bindings/Snapshot";
import type { Traffic } from "./bindings/Traffic";

export type { AccountCheck } from "./bindings/AccountCheck";
export type { ClashProxy } from "./bindings/ClashProxy";
export type { Connection } from "./bindings/Connection";
export type { CoreStatus } from "./bindings/CoreStatus";
export type { CustomNodeInput } from "./bindings/CustomNodeInput";
export type { CustomProxy } from "./bindings/CustomProxy";
export type { GeoIpGroup } from "./bindings/GeoIpGroup";
export type { LogBatch } from "./bindings/LogBatch";
export type { LogLevel } from "./bindings/LogLevel";
export type { MatchMode } from "./bindings/MatchMode";
export type { Mode } from "./bindings/Mode";
export type { NodeEntry } from "./bindings/NodeEntry";
export type { ProcessInfo } from "./bindings/ProcessInfo";
export type { Profile } from "./bindings/Profile";
export type { ProfileState } from "./bindings/ProfileState";
export type { ProxyLink } from "./bindings/ProxyLink";
export type { ProxyNode } from "./bindings/ProxyNode";
export type { ProxyProtocol } from "./bindings/ProxyProtocol";
export type { RuleGroup } from "./bindings/RuleGroup";
export type { RuleSetCatalog } from "./bindings/RuleSetCatalog";
export type { Snapshot } from "./bindings/Snapshot";
export type { Traffic } from "./bindings/Traffic";
export type { UdpPolicy } from "./bindings/UdpPolicy";

/** Mirrors `RuleGroup::selector_tag` in proxy-core. */
export const groupSelectorTag = (g: RuleGroup) => `group-${g.id}`;
/** Selector tags of the GeoIP group, the final group and Global mode; mirror `TAG_GEOIP`, `TAG_FINAL`, `TAG_GLOBAL`. */
export const TAG_GEOIP = "geoip";
export const TAG_FINAL = "final";
export const TAG_GLOBAL = "global";

export const api = {
  snapshot: () => invoke<Snapshot>("get_snapshot"),
  /** The only way to change the profile. Resolves to what still needs a reconnect. */
  saveProfile: (profile: Profile) => invoke<ProfileState>("save_profile", { profile }),
  setCredentials: (username: string, password: string) => invoke<void>("set_credentials", { username, password }),
  clearCredentials: () => invoke<void>("clear_credentials"),
  /** Auth-only check of the stored Mudfish account against live nodes; costs no traffic. */
  verifyAccount: () => invoke<AccountCheck>("verify_account"),
  nodes: (force: boolean) => invoke<NodeList>("get_nodes", { force }),
  warpCreate: () => invoke<ProxyNode>("warp_create"),
  /** Unregisters a just-created WARP device whose node could not be saved. */
  warpDiscard: (tag: string) => invoke<void>("warp_discard", { tag }),
  /** Splits a pasted proxy link into its parts; nothing is stored. */
  parseProxyLink: (text: string) => invoke<ProxyLink>("parse_proxy_link", { text }),
  /** Validates a hand-added HTTP/SOCKS5 node (`tag` null: a new one) and returns it to save through `saveProfile`; stores nothing. */
  customNodeBuild: (tag: string | null, input: CustomNodeInput) => invoke<ProxyNode>("custom_node_build", { tag, input }),
  /** After the save: stores the node's account, only if the profile now holds exactly the node built from `input`. */
  customNodeStoreAuth: (tag: string, input: CustomNodeInput) => invoke<void>("custom_node_store_auth", { tag, input }),
  /** The stored username of a hand-added node (`null`: no readable account); the password never leaves the backend. */
  customNodeUsername: (tag: string) => invoke<string | null>("custom_node_username", { tag }),
  ping: (ips: string[]) => invoke<PingResult[]>("ping_nodes", { ips }),
  start: () => invoke<void>("core_start"),
  stop: () => invoke<void>("core_stop"),
  logs: () => invoke<LogBatch>("core_logs"),
  proxies: () => invoke<Record<string, ClashProxy>>("clash_proxies"),
  delay: (tag: string) => invoke<number>("clash_delay", { tag }),
  closeConnection: (id: string) => invoke<void>("clash_close_connection", { id }),
  closeAll: () => invoke<void>("clash_close_all"),
  processes: () => invoke<ProcessInfo[]>("list_processes"),
  ruleSetCatalog: () => invoke<RuleSetCatalog>("rule_set_catalog"),
  openDataDir: () => invoke<void>("open_data_dir"),
};

export const events = {
  coreStatus: (cb: (s: CoreStatus) => void): Promise<UnlistenFn> => listen<CoreStatus>("core-status", (e) => cb(e.payload)),
  /** Batched: one event per ~250 ms of core output, numbered to join `api.logs()`. */
  coreLog: (cb: (batch: LogBatch) => void): Promise<UnlistenFn> => listen<LogBatch>("core-log", (e) => cb(e.payload)),
  coreError: (cb: (msg: string) => void): Promise<UnlistenFn> => listen<string>("core-error", (e) => cb(e.payload)),
  /** Once a second while connected and the window is visible. */
  traffic: (cb: (t: Traffic) => void): Promise<UnlistenFn> => listen<Traffic>("traffic", (e) => cb(e.payload)),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

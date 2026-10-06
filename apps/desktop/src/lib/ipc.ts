// Typed wrappers around the Rust commands in src-tauri/src/commands.rs. Data types are
// generated from the Rust structs into ./bindings by `cargo test` (ts-rs); never hand-edit them.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ClashProxy } from "./bindings/ClashProxy";
import type { CoreStatus } from "./bindings/CoreStatus";
import type { LogBatch } from "./bindings/LogBatch";
import type { NodeList } from "./bindings/NodeList";
import type { PingResult } from "./bindings/PingResult";
import type { ProcessInfo } from "./bindings/ProcessInfo";
import type { Profile } from "./bindings/Profile";
import type { ProfileState } from "./bindings/ProfileState";
import type { ProxyNode } from "./bindings/ProxyNode";
import type { RuleGroup } from "./bindings/RuleGroup";
import type { RuleSetCatalog } from "./bindings/RuleSetCatalog";
import type { Snapshot } from "./bindings/Snapshot";
import type { Traffic } from "./bindings/Traffic";

export type { ClashProxy } from "./bindings/ClashProxy";
export type { Connection } from "./bindings/Connection";
export type { CoreStatus } from "./bindings/CoreStatus";
export type { LogBatch } from "./bindings/LogBatch";
export type { LogLevel } from "./bindings/LogLevel";
export type { Mode } from "./bindings/Mode";
export type { NodeEntry } from "./bindings/NodeEntry";
export type { ProcessInfo } from "./bindings/ProcessInfo";
export type { Profile } from "./bindings/Profile";
export type { ProfileState } from "./bindings/ProfileState";
export type { ProxyNode } from "./bindings/ProxyNode";
export type { RuleGroup } from "./bindings/RuleGroup";
export type { RuleSetCatalog } from "./bindings/RuleSetCatalog";
export type { Snapshot } from "./bindings/Snapshot";
export type { Target } from "./bindings/Target";
export type { Traffic } from "./bindings/Traffic";
export type { UdpPolicy } from "./bindings/UdpPolicy";

/** Mirrors `RuleGroup::selector_tag` in proxy-core. */
export const groupSelectorTag = (g: RuleGroup) => `group-${g.id}`;

export const api = {
  snapshot: () => invoke<Snapshot>("get_snapshot"),
  /** The only way to change the profile. Resolves to what still needs a reconnect. */
  saveProfile: (profile: Profile) => invoke<ProfileState>("save_profile", { profile }),
  setCredentials: (username: string, password: string) => invoke<void>("set_credentials", { username, password }),
  clearCredentials: () => invoke<void>("clear_credentials"),
  nodes: (force: boolean) => invoke<NodeList>("get_nodes", { force }),
  warpCreate: () => invoke<ProxyNode>("warp_create"),
  /** Unregisters a just-created WARP device whose node could not be saved. */
  warpDiscard: (tag: string) => invoke<void>("warp_discard", { tag }),
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

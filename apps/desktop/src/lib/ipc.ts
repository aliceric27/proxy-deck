// Typed wrappers around the Rust commands in src-tauri/src/commands.rs.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Target = "proxy" | "direct" | "reject";
export type Mode = "Rule" | "Global" | "Direct";
export type UdpPolicy = "follow" | "direct" | "reject";

export interface ProxyNode {
  tag: string;
  sid: number;
  name: string;
  server: string;
  port: number;
  country: string;
  udp: boolean;
  /** Cloudflare WARP (WireGuard) node; absent for Mudfish SOCKS5. */
  wireguard?: { peer_public_key: string; address_v4: string; address_v6: string; reserved: number[]; mtu: number } | null;
}

/** Mirrors `RuleGroup` in proxy-core: matches if ANY matcher matches; groups are tried in order. */
export interface RuleGroup {
  id: string;
  name: string;
  enabled: boolean;
  target: Target;
  /** For target "proxy": "proxy" (follow main), "auto", or a node tag. */
  outbound: string;
  process_names: string[];
  process_paths: string[];
  directories: string[];
  domain_suffixes: string[];
  domain_keywords: string[];
  rule_sets: string[];
  ip_cidrs: string[];
  udp: UdpPolicy;
}

export const groupSelectorTag = (g: RuleGroup) => `group-${g.id}`;

export interface Profile {
  schema_version: number;
  nodes: ProxyNode[];
  selected: string;
  groups: RuleGroup[];
  final_target: Target;
  mode: Mode;
  dns: { fakeip: boolean; block_quic_for_proxied: boolean; ipv4_only: boolean };
  tun: { mtu: number; strict_route: boolean; bypass_lan: boolean };
}

export type CoreStatus =
  | { state: "stopped" }
  | { state: "starting" }
  | { state: "running"; started_at: number }
  | { state: "error"; message: string };

export interface Snapshot {
  profile: Profile;
  username: string | null;
  core: CoreStatus;
  elevated: boolean;
  version: string;
  sing_box_found: boolean;
}

export interface MudfishNode {
  sid: number;
  hostname: string;
  ip: string;
  location: string;
  country: string;
  region: string;
  city: string;
  provider: string;
  commercial: boolean;
  premium: boolean;
}

export interface ProcessInfo {
  name: string;
  path: string;
}

export interface RuleSetCatalog {
  geosite: string[];
  geoip: string[];
  acl: string[];
}

/** Subset of a Clash API `/connections` entry that the UI uses. */
export interface Connection {
  id: string;
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  rulePayload: string;
  metadata: {
    network: string;
    host: string;
    destinationIP: string;
    destinationPort: string;
    processPath?: string;
    process?: string;
  };
}

export interface ConnectionsSnapshot {
  downloadTotal: number;
  uploadTotal: number;
  connections: Connection[] | null;
}

export interface ClashProxy {
  type: string;
  now?: string;
  all?: string[];
  history?: { time: string; delay: number }[];
}

export const api = {
  snapshot: () => invoke<Snapshot>("get_snapshot"),
  saveProfile: (profile: Profile) => invoke<boolean>("save_profile", { profile }),
  setCredentials: (username: string, password: string) => invoke<void>("set_credentials", { username, password }),
  clearCredentials: () => invoke<void>("clear_credentials"),
  nodes: (force: boolean) => invoke<{ fetched_at: number; nodes: MudfishNode[] }>("get_nodes", { force }),
  warpCreate: () => invoke<Profile>("warp_create"),
  ping: (ips: string[]) => invoke<{ ip: string; ms: number | null }[]>("ping_nodes", { ips }),
  start: () => invoke<void>("core_start"),
  stop: () => invoke<void>("core_stop"),
  logs: () => invoke<string[]>("core_logs"),
  select: (tag: string) => invoke<void>("select_outbound", { tag }),
  selectGroup: (groupId: string, outbound: string) => invoke<void>("select_group_outbound", { groupId, outbound }),
  setMode: (mode: Mode) => invoke<void>("set_mode", { mode }),
  proxies: () => invoke<{ proxies: Record<string, ClashProxy> }>("clash_proxies"),
  delay: (tag: string) => invoke<number>("clash_delay", { tag }),
  connections: () => invoke<ConnectionsSnapshot>("clash_connections"),
  closeConnection: (id: string) => invoke<void>("clash_close_connection", { id }),
  closeAll: () => invoke<void>("clash_close_all"),
  processes: () => invoke<ProcessInfo[]>("list_processes"),
  ruleSetCatalog: () => invoke<RuleSetCatalog>("rule_set_catalog"),
  openDataDir: () => invoke<void>("open_data_dir"),
};

export const events = {
  coreStatus: (cb: (s: CoreStatus) => void): Promise<UnlistenFn> => listen<CoreStatus>("core-status", (e) => cb(e.payload)),
  coreLog: (cb: (line: string) => void): Promise<UnlistenFn> => listen<string>("core-log", (e) => cb(e.payload)),
  coreError: (cb: (msg: string) => void): Promise<UnlistenFn> => listen<string>("core-error", (e) => cb(e.payload)),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}

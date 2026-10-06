import type { ReactNode } from "react";
import { AppWindow, Globe, Layers, Network } from "lucide-react";
import { api, errorText, type ClashProxy, type Profile, type RuleGroup, type Target } from "../lib/ipc";
import { useApp } from "../lib/store";
import { newId } from "../lib/format";
import { Badge, Select } from "./ui";

export function newGroup(partial: Partial<RuleGroup> = {}): RuleGroup {
  return {
    id: newId(),
    name: "新的群組",
    enabled: true,
    target: "proxy",
    outbound: "proxy",
    process_names: [],
    process_paths: [],
    directories: [],
    domain_suffixes: [],
    domain_keywords: [],
    rule_sets: [],
    ip_cidrs: [],
    udp: "follow",
    ...partial,
  };
}

export type MatcherKind = "app" | "domain" | "rule_set" | "ip";

export const MATCHER_META: Record<MatcherKind, { label: string; icon: ReactNode }> = {
  app: { label: "應用程式", icon: <AppWindow size={13} /> },
  domain: { label: "網域", icon: <Globe size={13} /> },
  rule_set: { label: "規則集", icon: <Layers size={13} /> },
  ip: { label: "IP 範圍", icon: <Network size={13} /> },
};

export function matcherCounts(g: RuleGroup): Record<MatcherKind, number> {
  return {
    app: g.process_names.length + g.process_paths.length + g.directories.length,
    domain: g.domain_suffixes.length + g.domain_keywords.length,
    rule_set: g.rule_sets.length,
    ip: g.ip_cidrs.length,
  };
}

export const isGroupEmpty = (g: RuleGroup) => Object.values(matcherCounts(g)).every((n) => n === 0);

/** Compact "icon + count" chips for each matcher kind present in the group. */
export function MatcherSummary({ group }: { group: RuleGroup }) {
  const counts = matcherCounts(group);
  const kinds = (Object.keys(counts) as MatcherKind[]).filter((k) => counts[k] > 0);
  if (!kinds.length) return <span className="text-[11px] text-warn">尚未設定條件</span>;
  return (
    <span className="flex items-center gap-2.5 text-[11px] text-muted">
      {kinds.map((k) => (
        <span key={k} className="inline-flex items-center gap-1" title={MATCHER_META[k].label}>
          {MATCHER_META[k].icon}
          {counts[k]}
        </span>
      ))}
    </span>
  );
}

/** First few concrete matcher values, for the row subtitle. */
export function matcherPreview(g: RuleGroup, max = 5): string {
  const items = [
    ...g.process_names,
    ...g.process_paths,
    ...g.directories.map((d) => `${d}\\*`),
    ...g.domain_suffixes,
    ...g.domain_keywords.map((k) => `*${k}*`),
    ...g.rule_sets,
    ...g.ip_cidrs,
  ];
  return items.slice(0, max).join("  ·  ") + (items.length > max ? `  …（共 ${items.length} 項）` : "");
}

const AUTO_LABEL = "自動選擇（Mudfish 最低延遲）";

/** Choices for a proxied group's own selector. Direct is not offered: a group goes direct via its target. */
export function outboundOptions(profile: Profile) {
  return [{ value: "proxy", label: "使用預設節點" }, { value: "auto", label: AUTO_LABEL }, ...profile.nodes.map((n) => ({ value: n.tag, label: n.name }))];
}

/** Choices for the default node (the `proxy` selector). */
export function defaultNodeOptions(profile: Profile) {
  return [{ value: "direct", label: "直接連線" }, { value: "auto", label: AUTO_LABEL }, ...profile.nodes.map((n) => ({ value: n.tag, label: n.name }))];
}

export function outboundLabel(profile: Profile, tag: string): string {
  if (tag === "auto") return "自動選擇";
  return profile.nodes.find((n) => n.tag === tag)?.name ?? "預設節點";
}

/** Display name for a resolved outbound tag (a node, `direct`, …). */
export function nodeDisplayName(profile: Profile, tag: string | undefined): string | undefined {
  if (!tag) return undefined;
  if (tag === "direct") return "直接連線";
  if (tag === "auto") return "自動選擇";
  return profile.nodes.find((n) => n.tag === tag)?.name ?? tag;
}

/** Follows selector → selector → urltest → node, e.g. group → proxy → auto → mudfish-591. */
export function resolveNode(proxies: Record<string, ClashProxy>, tag: string): string | undefined {
  let cur: string | undefined = tag;
  for (let i = 0; i < 5 && cur && proxies[cur]?.now; i++) cur = proxies[cur].now;
  return cur && !proxies[cur]?.now ? cur : undefined;
}

export function OutboundSelect({ profile, value, onChange, className }: { profile: Profile; value: string; onChange: (v: string) => void; className?: string }) {
  const options = outboundOptions(profile);
  const known = options.some((o) => o.value === value);
  return <Select label="出口節點" value={known ? value : "proxy"} onChange={onChange} options={options} className={className} />;
}

/** Default-node dropdown; switches live when connected and persists either way. */
export function DefaultNodeSelect({ className, onChanged }: { className?: string; onChanged?: () => void }) {
  const { profile, patchLocal, toast } = useApp();
  if (!profile) return null;
  const options = defaultNodeOptions(profile);
  const value = options.some((o) => o.value === profile.selected) ? profile.selected : "auto";
  const select = async (tag: string) => {
    try {
      await api.select(tag);
      patchLocal((p) => ({ ...p, selected: tag }));
      onChanged?.();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };
  return <Select label="預設節點" value={value} onChange={select} options={options} className={className} />;
}

export function TargetBadge({ target, detail }: { target: Target; detail?: string }) {
  if (target === "proxy") return <Badge tone="accent">代理{detail ? ` · ${detail}` : ""}</Badge>;
  if (target === "direct") return <Badge tone="muted">直連</Badge>;
  return <Badge tone="danger">阻擋</Badge>;
}

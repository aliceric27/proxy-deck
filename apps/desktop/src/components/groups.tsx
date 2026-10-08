import type { ReactNode } from "react";
import { AppWindow, Globe, Layers, Network } from "lucide-react";
import type { ClashProxy, Profile, RuleGroup } from "../lib/ipc";
import { countryName, newId } from "../lib/format";
import { Badge, Select } from "./ui";

export function newGroup(partial: Partial<RuleGroup> = {}): RuleGroup {
  return {
    id: newId(),
    name: "新的群組",
    enabled: true,
    outbound: "auto",
    process_names: [],
    process_paths: [],
    directories: [],
    domain_suffixes: [],
    domain_keywords: [],
    rule_sets: [],
    ip_cidrs: [],
    udp: "follow",
    match_mode: "any",
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

/** Compact "icon + count" chips for each matcher kind present in the group; an AND group is tagged first. */
export function MatcherSummary({ group }: { group: RuleGroup }) {
  const counts = matcherCounts(group);
  const kinds = (Object.keys(counts) as MatcherKind[]).filter((k) => counts[k] > 0);
  if (!kinds.length) return <span className="text-[11px] text-warn">尚未設定條件</span>;
  return (
    <span className="flex items-center gap-2.5 text-[11px] text-muted">
      {group.match_mode === "all" && (
        <span className="rounded bg-surface-2 px-1 text-[10px] font-medium text-muted" title="需符合全部條件">
          AND
        </span>
      )}
      {kinds.map((k) => (
        <span key={k} className="inline-flex items-center gap-1" title={MATCHER_META[k].label}>
          {MATCHER_META[k].icon}
          {counts[k]}
        </span>
      ))}
    </span>
  );
}

/** First few concrete matcher values, for the row subtitle. The AND/OR signal is the `MatcherSummary`
 * tag, not this list, because the flattened values cross kinds (which AND) and same-kind values (which OR). */
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

/** `tw` → 「台灣（tw）」. Anything but a two-letter region code (`amazon`, `blocked@ru`), or a code the browser cannot name, stays as it is. */
export function geoipLabel(code: string): string {
  if (!/^[a-z]{2}$/i.test(code)) return code;
  const name = countryName(code);
  return name.toUpperCase() === code.toUpperCase() ? code : `${name}（${code}）`;
}

/** Mirrors `GeoIpGroup::codes`: the countries as the generator reads them, trimmed and without blanks or repeats. */
export function uniqueCodes(countries: string[]): string[] {
  return [...new Set(countries.map((c) => c.trim()).filter(Boolean))];
}

/** Subtitle of the GeoIP row: the first few countries by name. */
export function geoipSummary(countries: string[], max = 4): string {
  const codes = uniqueCodes(countries);
  if (!codes.length) return "尚未選擇國家或地區，這條規則不生效";
  return codes.slice(0, max).map(geoipLabel).join("、") + (codes.length > max ? `…（共 ${codes.length} 個）` : "");
}

const AUTO_LABEL = "自動選擇（Mudfish 最低延遲）";

/** Choices of a group's, GeoIP's or final's selector: direct, auto, each node, or block. */
export function outboundOptions(profile: Profile) {
  return [
    { value: "direct", label: "直接連線" },
    { value: "auto", label: AUTO_LABEL },
    ...profile.nodes.map((n) => ({ value: n.tag, label: n.name })),
    { value: "reject", label: "阻擋" },
  ];
}

/** Choices of Global mode's selector: no direct (Direct mode covers it) and no blocking. */
export function globalOptions(profile: Profile) {
  return [{ value: "auto", label: AUTO_LABEL }, ...profile.nodes.map((n) => ({ value: n.tag, label: n.name }))];
}

/** Mirrors `Profile::effective_outbound`: a node that was removed counts as `auto`. */
export function effectiveOutbound(profile: Profile, outbound: string): string {
  const known = outbound === "direct" || outbound === "reject" || outbound === "auto" || profile.nodes.some((n) => n.tag === outbound);
  return known ? outbound : "auto";
}

/** Mirrors `Profile::effective_global`: `auto` or an existing node. */
export function effectiveGlobal(profile: Profile): string {
  const o = profile.global_outbound;
  return o === "auto" || profile.nodes.some((n) => n.tag === o) ? o : "auto";
}

/** Mirrors `Profile::is_proxied`: traffic leaves through a node, i.e. it is neither direct nor blocked. */
export const isProxied = (profile: Profile, outbound: string) => !["direct", "reject"].includes(effectiveOutbound(profile, outbound));

/** The outbound is a node that forwards TCP only (an HTTP proxy, or UDP turned off); `auto` counts as no. */
export const isTcpOnlyNode = (profile: Profile, outbound: string) => profile.nodes.find((n) => n.tag === effectiveOutbound(profile, outbound))?.udp === false;

/** Display name for a resolved outbound tag (a node, `direct`, …). */
export function nodeDisplayName(profile: Profile, tag: string | undefined): string | undefined {
  if (!tag) return undefined;
  if (tag === "direct") return "直接連線";
  if (tag === "reject") return "阻擋";
  if (tag === "auto") return "自動選擇";
  return profile.nodes.find((n) => n.tag === tag)?.name ?? tag;
}

/** Follows selector → selector → urltest → node, e.g. final → auto → mudfish-591. Undefined while `tag` is not in `proxies`. */
export function resolveNode(proxies: Record<string, ClashProxy>, tag: string): string | undefined {
  let cur: string | undefined = tag;
  for (let i = 0; i < 5 && cur && proxies[cur]?.now; i++) cur = proxies[cur].now;
  return cur && cur !== tag && !proxies[cur]?.now ? cur : undefined;
}

/**
 * Dropdown for an outbound. It shows the effective value: one that points at a removed node
 * (or, for Global, at `direct`) is displayed as `auto`, which is what the backend uses then.
 */
export function OutboundSelect({
  profile,
  value,
  onChange,
  kind = "route",
  label = "出口",
  className,
}: {
  profile: Profile;
  value: string;
  onChange: (v: string) => void;
  kind?: "route" | "global";
  label?: string;
  className?: string;
}) {
  const options = kind === "global" ? globalOptions(profile) : outboundOptions(profile);
  const known = options.some((o) => o.value === value);
  return <Select label={label} value={known ? value : "auto"} onChange={onChange} options={options} className={className} />;
}

export function OutboundBadge({ profile, outbound }: { profile: Profile; outbound: string }) {
  const o = effectiveOutbound(profile, outbound);
  if (o === "direct") return <Badge tone="muted">直連</Badge>;
  if (o === "reject") return <Badge tone="danger">阻擋</Badge>;
  return <Badge tone="accent">{nodeDisplayName(profile, o)}</Badge>;
}

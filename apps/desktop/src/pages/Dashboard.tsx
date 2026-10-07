import { useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ListFilter, Lock } from "lucide-react";
import type { PageId } from "../App";
import { api, groupSelectorTag, TAG_FINAL, TAG_GEOIP, TAG_GLOBAL, type ClashProxy, type Mode } from "../lib/ipc";
import { useApp, useInterval, useTraffic } from "../lib/store";
import { formatBytes, formatElapsed, formatRate } from "../lib/format";
import { Badge, Button, Card, cx, PageHeader, Segmented } from "../components/ui";
import { effectiveGlobal, effectiveOutbound, geoipSummary, MatcherSummary, nodeDisplayName, OutboundSelect, resolveNode } from "../components/groups";

const MODES: { value: Mode; label: string; hint: string }[] = [
  { value: "Rule", label: "規則", hint: "依分流群組、GeoIP 與 final 決定出口" },
  { value: "Global", label: "全域", hint: "所有流量都走全域出口" },
  { value: "Direct", label: "直連", hint: "所有流量直連，不經過代理" },
];

export default function Dashboard({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const { profile, core, updateProfile } = useApp();
  const running = core.state === "running";
  const traffic = useTraffic();
  const conns = traffic?.connections ?? [];
  const [proxies, setProxies] = useState<Record<string, ClashProxy>>({});

  const refreshProxies = async () => {
    try {
      setProxies(await api.proxies());
    } catch {
      /* core stopping */
    }
  };
  useInterval(refreshProxies, 5000, running);

  if (!profile) return null;

  const nodeName = (tag?: string) => nodeDisplayName(profile, tag);
  /** The member the running core really uses behind a selector (`auto` resolved to its node). */
  const actualOf = (selector: string) => (running ? resolveNode(proxies, selector) : undefined);
  const activeGroups = profile.groups.filter((g) => g.enabled);
  const modeLabel = MODES.find((m) => m.value === profile.mode)?.label;

  // All of these apply live: the backend switches the running core's selector / mode.
  const refreshLive = () => {
    if (running) refreshProxies();
  };
  const selectGroup = (id: string, outbound: string) =>
    updateProfile((p) => ({ ...p, groups: p.groups.map((x) => (x.id === id ? { ...x, outbound } : x)) })).then(refreshLive);
  const selectGeoip = (outbound: string) => updateProfile((p) => ({ ...p, geoip: { ...p.geoip, outbound } })).then(refreshLive);
  const selectFinal = (outbound: string) => updateProfile((p) => ({ ...p, final_outbound: outbound })).then(refreshLive);
  const selectGlobal = (outbound: string) => updateProfile((p) => ({ ...p, global_outbound: outbound })).then(refreshLive);
  const setMode = (mode: Mode) => updateProfile((p) => ({ ...p, mode }));

  /** The outbound a selector really uses; the profile's choice while not connected or when the running config has no such selector (it was blocked or empty at the start). */
  const outboundValue = (outbound: string, selector: string) => (outbound === "reject" ? "阻擋" : (nodeName(actualOf(selector) ?? outbound) ?? "—"));
  /** The 「目前使用」 line is worth showing only when the dropdown does not already tell: `auto`, or the core is elsewhere. */
  const showActual = (selected: string, actual: string | undefined) => actual !== undefined && (selected === "auto" || actual !== selected);
  const finalOutbound = effectiveOutbound(profile, profile.final_outbound);
  const globalOutbound = effectiveGlobal(profile);
  const globalNow = actualOf(TAG_GLOBAL);

  /** One row of the routing card: a custom group, or the fixed GeoIP / final row. */
  const routeRow = (r: { key: string; index?: number; title: string; subtitle: ReactNode; outbound: string; selector: string; onChange: (outbound: string) => void }) => {
    const selected = effectiveOutbound(profile, r.outbound);
    const blocked = selected === "reject";
    const actual = blocked ? undefined : actualOf(r.selector);
    const count = running && !blocked ? conns.filter((c) => c.chains.includes(r.selector)).length : undefined;
    return (
      <li key={r.key} className={cx("flex items-center gap-3 px-4 py-2.5", r.index === undefined && "bg-surface-2/50", profile.mode !== "Rule" && "opacity-55")}>
        <span className="tabular flex w-5 justify-end text-xs text-muted" title={r.index === undefined ? "固定的群組" : "優先順序"}>
          {r.index ?? <Lock size={12} aria-label="固定的群組" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium">{r.title}</div>
          {r.subtitle}
        </div>
        {count !== undefined && <Badge tone={count ? "accent" : "muted"}>{count} 條連線</Badge>}
        <div className="flex w-72 shrink-0 flex-col items-end gap-0.5">
          <OutboundSelect profile={profile} value={r.outbound} onChange={r.onChange} label={`${r.title} 的出口`} className="w-full" />
          {showActual(selected, actual) && <span className="text-[11px] text-muted">目前使用：{nodeName(actual)}</span>}
        </div>
      </li>
    );
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="總覽"
        subtitle={
          core.state === "running"
            ? `已連線 ${formatElapsed(core.started_at * 1000)}`
            : core.state === "error"
              ? "連線發生錯誤"
              : core.state === "reconnecting"
                ? `核心意外結束，正在自動重新連線（第 ${core.attempt} 次）`
                : core.state === "starting"
                  ? "連線中…"
                  : "未連線"
        }
      />
      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-6">
        {(core.state === "error" || core.state === "reconnecting") && (
          <div className="selectable rounded-lg border border-danger/40 bg-danger-soft px-4 py-3 text-[13px] whitespace-pre-wrap text-danger">{core.message}</div>
        )}

        <div className="grid grid-cols-4 gap-4">
          {profile.mode === "Rule" ? (
            <Stat label="final" value={outboundValue(finalOutbound, TAG_FINAL)} hint="不符合任何規則的流量" />
          ) : profile.mode === "Global" ? (
            <Stat label="全域出口" value={outboundValue(globalOutbound, TAG_GLOBAL)} hint="所有流量都走這個出口" />
          ) : (
            <Stat label="出口" value="直接連線" hint="所有流量直連，不經過代理" />
          )}
          <Stat label="上傳" value={traffic ? formatRate(traffic.up_rate) : "—"} hint={traffic ? `累計 ${formatBytes(traffic.upload_total)}` : undefined} icon={<ArrowUp size={14} />} />
          <Stat label="下載" value={traffic ? formatRate(traffic.down_rate) : "—"} hint={traffic ? `累計 ${formatBytes(traffic.download_total)}` : undefined} icon={<ArrowDown size={14} />} />
          <Stat label="連線數" value={running ? String(conns.length) : "—"} hint="目前開啟中的連線" />
        </div>

        <Card title="模式">
          <div className="flex items-center gap-4 px-4 py-3">
            <Segmented value={profile.mode} onChange={setMode} options={MODES} />
            <span className="text-xs text-muted">{MODES.find((m) => m.value === profile.mode)?.hint}</span>
            {profile.mode === "Global" && (
              <div className="ml-auto flex items-center gap-3">
                <span className="text-xs font-medium">全域出口</span>
                <div className="flex w-64 flex-col items-end gap-0.5">
                  <OutboundSelect kind="global" label="全域出口" profile={profile} value={profile.global_outbound} onChange={selectGlobal} className="w-full" />
                  {showActual(globalOutbound, globalNow) && <span className="text-[11px] text-muted">目前使用：{nodeName(globalNow)}</span>}
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card
          title={`生效中的群組（${activeGroups.length}）`}
          actions={
            <Button size="sm" variant="ghost" onClick={() => onNavigate("groups")}>
              管理群組
            </Button>
          }
        >
          {profile.mode !== "Rule" && (
            <div className="border-b border-border bg-warn-soft px-4 py-2 text-xs text-warn">目前為「{modeLabel}」模式，分流暫不生效；切回「規則」即恢復。</div>
          )}
          {activeGroups.length === 0 && (
            <div className="flex items-center gap-2 border-b border-border px-4 py-3 text-xs text-muted">
              <ListFilter size={16} className="shrink-0 opacity-50" />
              沒有啟用的自訂群組，流量依下方的 GeoIP 與 final 處理。
            </div>
          )}
          <ol className="divide-y divide-border">
            {activeGroups.map((g, i) =>
              routeRow({
                key: g.id,
                index: i + 1,
                title: g.name,
                subtitle: <MatcherSummary group={g} />,
                outbound: g.outbound,
                selector: groupSelectorTag(g),
                onChange: (outbound) => selectGroup(g.id, outbound),
              }),
            )}
            {routeRow({
              key: "geoip",
              title: "GeoIP",
              subtitle: <div className="truncate text-[11px] text-muted">{geoipSummary(profile.geoip.countries)}</div>,
              outbound: profile.geoip.outbound,
              selector: TAG_GEOIP,
              onChange: selectGeoip,
            })}
            {routeRow({
              key: "final",
              title: "final",
              subtitle: <div className="truncate text-[11px] text-muted">不符合以上任何規則的流量</div>,
              outbound: profile.final_outbound,
              selector: TAG_FINAL,
              onChange: selectFinal,
            })}
          </ol>
        </Card>
      </div>
    </div>
  );
}

function Stat({ label, value, hint, icon }: { label: string; value: string; hint?: string; icon?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <div className="flex items-center gap-1 text-xs text-muted">
        {icon}
        {label}
      </div>
      <div className="tabular mt-1 truncate text-lg font-semibold" title={value}>
        {value}
      </div>
      {hint && <div className="mt-0.5 truncate text-[11px] text-muted">{hint}</div>}
    </div>
  );
}

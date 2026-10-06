import { useState } from "react";
import { ArrowDown, ArrowUp, ListFilter } from "lucide-react";
import type { PageId } from "../App";
import { api, groupSelectorTag, type ClashProxy, type Mode, type RuleGroup } from "../lib/ipc";
import { useApp, useInterval, useTraffic } from "../lib/store";
import { formatBytes, formatElapsed, formatRate } from "../lib/format";
import { Badge, Button, Card, cx, PageHeader, Segmented } from "../components/ui";
import { DefaultNodeSelect, MatcherSummary, nodeDisplayName, OutboundSelect, resolveNode, TargetBadge } from "../components/groups";

const MODES: { value: Mode; label: string; hint: string }[] = [
  { value: "Rule", label: "規則", hint: "依分流群組決定走代理或直連" },
  { value: "Global", label: "全域", hint: "所有流量都走預設節點" },
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
  const defaultNow = running ? nodeName(resolveNode(proxies, "proxy")) : undefined;
  const activeGroups = profile.groups.filter((g) => g.enabled);

  // Both apply live: the backend switches the running core's selector / mode.
  const selectGroup = (g: RuleGroup, outbound: string) =>
    updateProfile((p) => ({ ...p, groups: p.groups.map((x) => (x.id === g.id ? { ...x, outbound } : x)) })).then(() => {
      if (running) refreshProxies();
    });
  const setMode = (mode: Mode) => updateProfile((p) => ({ ...p, mode }));

  const connCount = (g: RuleGroup) => conns.filter((c) => c.chains.includes(groupSelectorTag(g))).length;

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
          <Stat
            label="預設節點"
            value={defaultNow ?? (running ? "測試中…" : (nodeName(profile.selected) ?? "—"))}
            hint={profile.selected === "auto" ? "自動選擇最低延遲" : profile.selected === "direct" ? "不經過代理" : "手動指定"}
          />
          <Stat label="上傳" value={traffic ? formatRate(traffic.up_rate) : "—"} hint={traffic ? `累計 ${formatBytes(traffic.upload_total)}` : undefined} icon={<ArrowUp size={14} />} />
          <Stat label="下載" value={traffic ? formatRate(traffic.down_rate) : "—"} hint={traffic ? `累計 ${formatBytes(traffic.download_total)}` : undefined} icon={<ArrowDown size={14} />} />
          <Stat label="連線數" value={running ? String(conns.length) : "—"} hint="目前開啟中的連線" />
        </div>

        <Card title="模式">
          <div className="flex items-center gap-4 px-4 py-3">
            <Segmented value={profile.mode} onChange={setMode} options={MODES} />
            <span className="text-xs text-muted">{MODES.find((m) => m.value === profile.mode)?.hint}</span>
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
            <div className="border-b border-border bg-warn-soft px-4 py-2 text-xs text-warn">目前為「{MODES.find((m) => m.value === profile.mode)?.label}」模式，群組暫不生效；切回「規則」即恢復。</div>
          )}
          {activeGroups.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-muted">
              <ListFilter size={22} className="mx-auto mb-2 opacity-50" />
              沒有啟用的群組，所有流量依「其他流量」設定處理。
            </div>
          ) : (
            <ol className="divide-y divide-border">
              {activeGroups.map((g, i) => {
                const actual = running && g.target === "proxy" ? nodeName(resolveNode(proxies, groupSelectorTag(g))) : undefined;
                const count = running && g.target === "proxy" ? connCount(g) : undefined;
                return (
                  <li key={g.id} className={cx("flex items-center gap-3 px-4 py-2.5", profile.mode !== "Rule" && "opacity-55")}>
                    <span className="tabular w-5 text-right text-xs text-muted" title="優先順序">
                      {i + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-medium">{g.name}</div>
                      <MatcherSummary group={g} />
                    </div>
                    {count !== undefined && <Badge tone={count ? "accent" : "muted"}>{count} 條連線</Badge>}
                    {g.target === "proxy" ? (
                      <div className="flex w-72 shrink-0 flex-col items-end gap-0.5">
                        <OutboundSelect profile={profile} value={g.outbound} onChange={(v) => selectGroup(g, v)} className="w-full" />
                        {actual && <span className="text-[11px] text-muted">目前使用：{actual}</span>}
                      </div>
                    ) : (
                      <div className="flex w-72 shrink-0 justify-end">
                        <TargetBadge target={g.target} />
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
          <div className={cx("flex items-center gap-3 border-t border-border bg-surface-2/50 px-4 py-2.5", profile.mode === "Direct" && "opacity-55")}>
            <span className="w-5" />
            <div className="min-w-0 flex-1">
              <div className="font-medium">預設節點</div>
              <div className="truncate text-[11px] text-muted">「使用預設節點」的群組、全域模式與走代理的其他流量</div>
            </div>
            <div className="flex w-72 shrink-0 flex-col items-end gap-0.5">
              <DefaultNodeSelect className="w-full" onChanged={running ? refreshProxies : undefined} />
              {defaultNow && <span className="text-[11px] text-muted">目前使用：{defaultNow}</span>}
            </div>
          </div>
          <div className={cx("flex items-center gap-3 border-t border-border px-4 py-2.5", profile.mode !== "Rule" && "opacity-55")}>
            <span className="w-5" />
            <div className="min-w-0 flex-1">
              <div className="font-medium">其他流量</div>
              <div className="truncate text-[11px] text-muted">不符合任何群組的流量，可在「分流群組」頁更改</div>
            </div>
            <div className="flex w-72 shrink-0 justify-end">
              <TargetBadge target={profile.final_target} detail={profile.final_target === "proxy" ? "預設節點" : undefined} />
            </div>
          </div>
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

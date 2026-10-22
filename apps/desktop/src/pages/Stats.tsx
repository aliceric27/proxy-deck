import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, ChartColumn, Trash2 } from "lucide-react";
import { api, errorText, type ExitKind, type SessionEnd, type TrafficSession, type Usage } from "../lib/ipc";
import { useApp, useInterval } from "../lib/store";
import { formatBytes, formatDate, formatDateTime, formatDuration, formatRate, formatTime } from "../lib/format";
import { Badge, Button, Card, cx, EmptyState, Modal, PageHeader, Segmented, type Tone } from "../components/ui";
import { Legend, SERIES, SplitBar, SplitRows, StackedColumns, splitTotal, UsageBars, type Column, type Split, type UsageRow } from "../components/charts";

type Range = "7" | "30" | "all";
const RANGES: { value: Range; label: string }[] = [
  { value: "7", label: "近 7 天" },
  { value: "30", label: "近 30 天" },
  { value: "all", label: "全部" },
];

/** Timeline buckets are merged until a session's chart has at most this many columns. */
const MAX_TIMELINE_COLUMNS = 72;

const nowSecs = () => Math.floor(Date.now() / 1000);
const endOf = (s: TrafficSession) => s.ended_at ?? Math.max(s.last_seen, nowSecs());
const durationOf = (s: TrafficSession) => endOf(s) - s.started_at;

/** Through a node / direct / not attributed. The totals are sing-box's counters; the split adds up connections. */
function sessionSplit(s: TrafficSession): Split {
  let proxied = 0;
  let direct = 0;
  for (const e of s.exits) {
    proxied += e.proxied;
    if (e.kind === "direct") direct += e.upload + e.download;
  }
  return { proxied, direct, other: Math.max(0, s.upload + s.download - proxied - direct) };
}

const sumSplits = (list: Split[]): Split =>
  list.reduce((a, b) => ({ proxied: a.proxied + b.proxied, direct: a.direct + b.direct, other: a.other + b.other }), { proxied: 0, direct: 0, other: 0 });

const END: Record<SessionEnd, { label: string; tone: Tone; hint: string }> = {
  stopped: { label: "已中斷", tone: "muted", hint: "手動中斷連線或結束程式" },
  reconnected: { label: "重新連線", tone: "muted", hint: "重新連線（例如套用變更的設定），之後的用量記在下一筆" },
  error: { label: "錯誤", tone: "danger", hint: "核心發生錯誤，自動重試後仍無法恢復" },
  interrupted: { label: "未正常結束", tone: "warn", hint: "程式沒有正常結束（例如被強制關閉），用量以最後一次存檔為準，最多少記 1 分鐘" },
};

function EndBadge({ s }: { s: TrafficSession }) {
  if (!s.end) return <Badge tone="accent">進行中</Badge>;
  const e = END[s.end];
  return (
    <span title={e.hint}>
      <Badge tone={e.tone}>{e.label}</Badge>
    </span>
  );
}

const KIND_LABEL: Record<ExitKind, string> = { direct: "直連", mudfish: "Mudfish", warp: "WARP", custom: "自訂", other: "其他" };

function exitRow(u: Usage): UsageRow {
  const total = u.upload + u.download;
  const kind = u.kind ?? "other";
  const split: Split = kind === "direct" ? { proxied: 0, direct: total, other: 0 } : kind === "other" ? { proxied: 0, direct: 0, other: total } : { proxied: total, direct: 0, other: 0 };
  return { key: u.key, label: u.label, badge: kind !== "direct" && <Badge>{KIND_LABEL[kind]}</Badge>, split, upload: u.upload, download: u.download };
}

function appRow(u: Usage): UsageRow {
  const total = u.upload + u.download;
  return { key: u.key, label: u.label, split: { proxied: u.proxied, direct: total - u.proxied, other: 0 }, upload: u.upload, download: u.download };
}

export default function Stats() {
  const { core, toast } = useApp();
  const live = core.state === "running" || core.state === "reconnecting";
  const [sessions, setSessions] = useState<TrafficSession[] | null>(null);
  const [range, setRange] = useState<Range>("30");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const detailRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      setSessions((await api.trafficHistory()).sessions);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [toast]);
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;
  /** Only the running session changes between status changes: fetch it alone and swap it in. */
  const refreshLive = useCallback(async () => {
    try {
      const current = await api.trafficCurrent();
      const list = sessionsRef.current;
      if (!current || !list) return;
      if (list.some((s) => s.id === current.id)) setSessions(list.map((s) => (s.id === current.id ? current : s)));
      else await load(); // a session this list has not seen yet
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [load, toast]);
  // The whole history again on every status change (a session opens or closes); the running one every 5 s.
  useEffect(() => {
    load();
  }, [load, core.state]);
  useInterval(refreshLive, 5000, live);

  const shown = useMemo(() => {
    const all = sessions ?? [];
    if (range === "all") return all;
    const since = nowSecs() - Number(range) * 86400;
    return all.filter((s) => endOf(s) >= since);
  }, [sessions, range]);
  const splits = useMemo(() => new Map(shown.map((s) => [s.id, sessionSplit(s)])), [shown]);
  const selected = shown.find((s) => s.id === selectedId) ?? shown[shown.length - 1];

  const select = (id: string, scroll = false) => {
    setSelectedId(id);
    if (scroll) requestAnimationFrame(() => detailRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" }));
  };

  const clear = async () => {
    setConfirmClear(false);
    try {
      await api.clearTrafficHistory();
      await load();
      toast("已清除流量紀錄。", "success");
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const hasClosed = (sessions ?? []).some((s) => s.ended_at !== null);
  const header = (
    <PageHeader
      title="流量統計"
      subtitle="每次連線的上傳與下載用量；連線中每秒記錄，縮到系統匣時也會記錄"
      actions={
        <>
          <Segmented value={range} onChange={setRange} options={RANGES} />
          <Button icon={<Trash2 size={14} />} variant="danger" disabled={!hasClosed} onClick={() => setConfirmClear(true)}>
            清除紀錄
          </Button>
        </>
      }
    />
  );

  if (sessions === null) return <div className="flex h-full flex-col">{header}</div>;

  const totals = sumSplits(shown.map((s) => splits.get(s.id)!));
  const upload = shown.reduce((a, s) => a + s.upload, 0);
  const download = shown.reduce((a, s) => a + s.download, 0);
  const total = upload + download;
  const share = (v: number) => (total > 0 ? `佔 ${Math.round((v / total) * 100)}%` : "—");
  const time = shown.reduce((a, s) => a + durationOf(s), 0);

  const columns: Column[] = shown.map((s) => {
    const split = splits.get(s.id)!;
    return {
      key: s.id,
      split,
      xLabel: s.ended_at === null ? "進行中" : formatDate(s.started_at),
      ariaLabel: `${formatDateTime(s.started_at)} 起 ${formatDuration(durationOf(s))}，共 ${formatBytes(s.upload + s.download)}，經代理 ${formatBytes(split.proxied)}`,
      tooltip: (
        <div className="space-y-1">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium">{formatDateTime(s.started_at)}</span>
            <EndBadge s={s} />
          </div>
          <div className="text-muted">
            {formatDuration(durationOf(s))} · 共 <span className="tabular font-semibold text-text">{formatBytes(s.upload + s.download)}</span>
          </div>
          <SplitRows split={split} />
          <div className="tabular text-muted">
            ↑ {formatBytes(s.upload)} · ↓ {formatBytes(s.download)}
          </div>
        </div>
      ),
    };
  });

  return (
    <div className="flex h-full flex-col">
      {header}
      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-6">
        {sessions.length === 0 ? (
          <EmptyState icon={<ChartColumn size={28} />} title="還沒有流量紀錄">
            連線後，每一次連線的上傳、下載用量，以及經代理與直連的比例都會記錄在這裡。
          </EmptyState>
        ) : (
          <>
            <div className="grid grid-cols-4 gap-4">
              <Tile label="總用量" value={formatBytes(total)} hint={`↑ ${formatBytes(upload)} · ↓ ${formatBytes(download)}`} />
              <Tile label="經代理" value={formatBytes(totals.proxied)} hint={share(totals.proxied)} swatch={SERIES[0].color} />
              <Tile label="直連" value={formatBytes(totals.direct)} hint={share(totals.direct)} swatch={SERIES[1].color} />
              <Tile
                label="連線次數"
                value={String(shown.length)}
                hint={shown.length ? `平均每次 ${formatBytes(total / shown.length)} · 共 ${formatDuration(time)}` : "—"}
              />
            </div>

            <Card title="每次連線的用量" actions={<Legend />}>
              {shown.length === 0 ? (
                <p className="px-4 py-10 text-center text-xs text-muted">這段期間沒有連線紀錄。</p>
              ) : (
                <div className="px-4 pt-4 pb-2">
                  <StackedColumns label="每次連線的用量" columns={columns} selected={selected?.id} onSelect={(id) => select(id, true)} />
                </div>
              )}
            </Card>

            {selected && (
              <div ref={detailRef}>
                <SessionDetail s={selected} split={splits.get(selected.id)!} />
              </div>
            )}

            {shown.length > 0 && (
              <Card title={`連線紀錄（${shown.length}）`}>
                <div className="max-h-96 overflow-auto">
                  <table className="w-full text-[13px]">
                    <thead className="sticky top-0 bg-surface text-left text-xs text-muted">
                      <tr className="border-b border-border">
                        <th className="px-4 py-2 font-medium">開始</th>
                        <th className="px-2 py-2 font-medium">時長</th>
                        <th className="px-2 py-2 text-right font-medium">上傳</th>
                        <th className="px-2 py-2 text-right font-medium">下載</th>
                        <th className="px-2 py-2 text-right font-medium">合計</th>
                        <th className="px-2 py-2 font-medium">經代理</th>
                        <th className="px-4 py-2 font-medium">狀態</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...shown].reverse().map((s) => {
                        const split = splits.get(s.id)!;
                        const all = splitTotal(split);
                        return (
                          <tr
                            key={s.id}
                            onClick={() => select(s.id, true)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                select(s.id, true);
                              }
                            }}
                            tabIndex={0}
                            aria-current={s.id === selected?.id ? "true" : undefined}
                            className={cx("cursor-pointer border-b border-border last:border-0", s.id === selected?.id ? "bg-accent-soft" : "hover:bg-surface-2")}
                          >
                            <td className="tabular px-4 py-2">{formatDateTime(s.started_at)}</td>
                            <td className="px-2 py-2 text-muted">{formatDuration(durationOf(s))}</td>
                            <td className="tabular px-2 py-2 text-right">{formatBytes(s.upload)}</td>
                            <td className="tabular px-2 py-2 text-right">{formatBytes(s.download)}</td>
                            <td className="tabular px-2 py-2 text-right font-medium">{formatBytes(s.upload + s.download)}</td>
                            <td className="px-2 py-2">
                              <div className="flex items-center gap-2">
                                <SplitBar split={split} className="w-16" />
                                <span className="tabular w-9 text-right text-xs text-muted">{all > 0 ? `${Math.round((split.proxied / all) * 100)}%` : "—"}</span>
                              </div>
                            </td>
                            <td className="px-4 py-2">
                              <EndBadge s={s} />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}
          </>
        )}
      </div>

      {confirmClear && (
        <Modal
          title="清除流量紀錄"
          width={420}
          onClose={() => setConfirmClear(false)}
          footer={
            <>
              <Button onClick={() => setConfirmClear(false)}>取消</Button>
              <Button variant="danger" onClick={clear}>
                清除
              </Button>
            </>
          }
        >
          <p className="px-4 py-4 text-[13px] leading-relaxed">
            所有已結束的連線紀錄都會刪除，無法復原。{live && "目前的連線會繼續記錄。"}
          </p>
        </Modal>
      )}
    </div>
  );
}

function SessionDetail({ s, split }: { s: TrafficSession; split: Split }) {
  const t = s.timeline;
  const columns = useMemo<Column[]>(() => {
    const n = t.upload.length;
    const group = Math.max(1, Math.ceil(n / MAX_TIMELINE_COLUMNS));
    const span = t.bucket_secs * group;
    const sum = (v: number[], from: number) => v.slice(from, from + group).reduce((a, b) => a + b, 0);
    return Array.from({ length: Math.ceil(n / group) }, (_, i) => {
      const from = i * group;
      const [up, down, proxied, direct] = [sum(t.upload, from), sum(t.download, from), sum(t.proxied, from), sum(t.direct, from)];
      const c: Split = { proxied, direct, other: Math.max(0, up + down - proxied - direct) };
      const start = s.started_at + from * t.bucket_secs;
      return {
        key: String(i),
        split: c,
        xLabel: formatTime(start),
        ariaLabel: `${formatTime(start)} 起 ${formatDuration(span)}：${formatBytes(up + down)}`,
        tooltip: (
          <div className="space-y-1">
            <div className="font-medium">
              {formatTime(start)} – {formatTime(start + span)}
            </div>
            <div className="text-muted">
              共 <span className="tabular font-semibold text-text">{formatBytes(up + down)}</span> · 平均 {formatRate((up + down) / span)}
            </div>
            <SplitRows split={c} />
            <div className="tabular text-muted">
              ↑ {formatBytes(up)} · ↓ {formatBytes(down)}
            </div>
          </div>
        ),
      };
    });
  }, [s.started_at, t]);

  const end = s.ended_at === null ? "進行中" : new Date(s.ended_at * 1000).toDateString() === new Date(s.started_at * 1000).toDateString() ? formatTime(s.ended_at) : formatDateTime(s.ended_at);
  const proxiedShare = s.upload + s.download > 0 ? Math.round((split.proxied / (s.upload + s.download)) * 100) : 0;

  return (
    <Card title={`連線詳情 · ${formatDateTime(s.started_at)} – ${end}`} actions={<EndBadge s={s} />}>
      <dl className="grid grid-cols-5 divide-x divide-border border-b border-border">
        <Fact label="時長" value={formatDuration(durationOf(s))} hint={s.restarts > 0 ? `其間自動重連 ${s.restarts} 次` : undefined} />
        <Fact label="上傳" value={formatBytes(s.upload)} icon={<ArrowUp size={12} />} />
        <Fact label="下載" value={formatBytes(s.download)} icon={<ArrowDown size={12} />} />
        <Fact label="經代理" value={formatBytes(split.proxied)} hint={`佔 ${proxiedShare}%`} />
        <Fact label="最高速度" value={formatRate(s.peak_down_rate)} hint={`上傳最高 ${formatRate(s.peak_up_rate)}`} icon={<ArrowDown size={12} />} />
      </dl>
      <div className="px-4 pt-3 pb-2">
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-xs font-medium text-muted">用量隨時間（每欄 {formatDuration(t.bucket_secs * Math.max(1, Math.ceil(t.upload.length / MAX_TIMELINE_COLUMNS)))}）</h3>
          <Legend />
        </div>
        {columns.length ? (
          <StackedColumns label="這次連線的用量隨時間變化" columns={columns} height={150} minSlot={6} labelWidth={40} />
        ) : (
          <p className="py-6 text-center text-xs text-muted">尚無資料</p>
        )}
      </div>
      <div className="grid grid-cols-2 divide-x divide-border border-t border-border">
        <section>
          <h3 className="px-4 pt-3 text-xs font-medium text-muted">依出口</h3>
          <UsageBars rows={s.exits.map(exitRow)} empty="沒有可歸類的連線" />
        </section>
        <section>
          <h3 className="px-4 pt-3 text-xs font-medium text-muted">依程式</h3>
          <UsageBars rows={s.apps.map(appRow)} empty="沒有可歸類的連線" />
        </section>
      </div>
    </Card>
  );
}

function Tile({ label, value, hint, swatch }: { label: string; value: string; hint?: string; swatch?: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <div className="flex items-center gap-1.5 text-xs text-muted">
        {swatch && <span className="h-2.5 w-2.5 rounded-sm" style={{ background: swatch }} />}
        {label}
      </div>
      <div className="mt-1 truncate text-lg font-semibold" title={value}>
        {value}
      </div>
      {hint && (
        <div className="mt-0.5 truncate text-[11px] text-muted" title={hint}>
          {hint}
        </div>
      )}
    </div>
  );
}

function Fact({ label, value, hint, icon }: { label: string; value: string; hint?: string; icon?: React.ReactNode }) {
  return (
    <div className="min-w-0 px-4 py-2.5">
      <dt className="flex items-center gap-1 text-[11px] text-muted">
        {icon}
        {label}
      </dt>
      <dd className="mt-0.5 truncate text-[13px] font-semibold">{value}</dd>
      {hint && <dd className="truncate text-[11px] text-muted">{hint}</dd>}
    </div>
  );
}

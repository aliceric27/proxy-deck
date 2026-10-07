import { useMemo, useState } from "react";
import { Activity, Pause, Play, Search, XCircle } from "lucide-react";
import { api, errorText, groupSelectorTag, TAG_FINAL, TAG_GEOIP, TAG_GLOBAL, type Connection, type RuleGroup } from "../lib/ipc";
import { useApp, useInterval, useTraffic } from "../lib/store";
import { basename, formatBytes, formatElapsed } from "../lib/format";
import { Badge, Button, ContextMenu, cx, EmptyState, Input, PageHeader, Segmented, type MenuItem } from "../components/ui";
import { newGroup } from "../components/groups";

type Filter = "all" | "proxy" | "direct";
type SortKey = "start" | "download" | "upload";

/** `chains` runs from the actual outbound back to the selector that picked it: [node, …, group-x]. */
const isProxied = (c: Connection) => c.chains.length > 0 && c.chains[0] !== "direct";

export default function Connections() {
  const { profile, core, updateProfile, toast } = useApp();
  const running = core.state === "running";
  const [paused, setPaused] = useState(false);
  const conns = useTraffic(paused)?.connections ?? [];
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [sort, setSort] = useState<SortKey>("start");
  const [menu, setMenu] = useState<{ x: number; y: number; c: Connection } | null>(null);
  const [now, setNow] = useState(Date.now());

  useInterval(() => setNow(Date.now()), 1000, running && !paused);

  const visible = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const list = (running ? conns : []).filter((c) => {
      if (filter === "proxy" && !isProxied(c)) return false;
      if (filter === "direct" && isProxied(c)) return false;
      if (!ql) return true;
      const m = c.metadata;
      return [m.host, m.destinationIP, m.processPath ?? "", c.rule, c.rulePayload].some((s) => s?.toLowerCase().includes(ql));
    });
    list.sort((a, b) => (sort === "start" ? b.start.localeCompare(a.start) : sort === "download" ? b.download - a.download : b.upload - a.upload));
    return list;
  }, [conns, q, filter, sort, running]);

  /** What the group column calls a selector: a custom group by name, the fixed ones and Global mode by role. */
  const selectorLabels = new Map<string, string>([
    [TAG_GLOBAL, "全域"],
    [TAG_GEOIP, "GeoIP"],
    [TAG_FINAL, "final"],
    ...(profile?.groups ?? []).map((g): [string, string] => [groupSelectorTag(g), g.name]),
  ]);
  const nodeName = (tag: string) => profile?.nodes.find((n) => n.tag === tag)?.name ?? tag;

  /** New top-priority group for this program or domain, sent through `auto` or direct. */
  const createGroup = (kind: "app" | "domain", outbound: "auto" | "direct", value: string) => {
    const g = newGroup(kind === "app" ? { name: value, outbound, process_names: [value] } : { name: value, outbound, domain_suffixes: [value] });
    updateProfile((p) => ({ ...p, groups: [g, ...p.groups] }));
    toast(`已新增最優先的群組「${g.name}」${running ? "，重新連線後生效" : ""}。`, "success");
  };

  const addToGroup = (g: RuleGroup, kind: "app" | "domain", value: string) => {
    updateProfile((p) => ({
      ...p,
      groups: p.groups.map((x) =>
        x.id !== g.id
          ? x
          : kind === "app"
            ? { ...x, process_names: [...new Set([...x.process_names, value])] }
            : { ...x, domain_suffixes: [...new Set([...x.domain_suffixes, value])] },
      ),
    }));
    toast(`已把 ${value} 加入群組「${g.name}」${running ? "，重新連線後生效" : ""}。`, "success");
  };

  const menuItems = (c: Connection): MenuItem[] => {
    const proc = c.metadata.processPath ? basename(c.metadata.processPath) : "";
    const host = c.metadata.host;
    const groups = (profile?.groups ?? []).slice(0, 8);
    const items: MenuItem[] = [{ label: "關閉連線", onSelect: () => api.closeConnection(c.id).catch((e) => toast(errorText(e), "error")) }];
    if (proc) {
      items.push(
        { label: `為「${proc}」建立走代理的群組`, separatorBefore: true, onSelect: () => createGroup("app", "auto", proc) },
        { label: `為「${proc}」建立直連的群組`, onSelect: () => createGroup("app", "direct", proc) },
        ...groups.map((g) => ({ label: `把「${proc}」加入「${g.name}」`, onSelect: () => addToGroup(g, "app", proc) })),
      );
    }
    if (host) {
      items.push(
        { label: `為「${host}」建立走代理的群組`, separatorBefore: true, onSelect: () => createGroup("domain", "auto", host) },
        { label: `為「${host}」建立直連的群組`, onSelect: () => createGroup("domain", "direct", host) },
        ...groups.map((g) => ({ label: `把「${host}」加入「${g.name}」`, onSelect: () => addToGroup(g, "domain", host) })),
      );
    }
    items.push({
      label: "複製目的地",
      separatorBefore: true,
      onSelect: () => navigator.clipboard.writeText(`${host || c.metadata.destinationIP}:${c.metadata.destinationPort}`),
    });
    return items;
  };

  const totalDown = visible.reduce((s, c) => s + c.download, 0);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="連線"
        subtitle={running ? `${visible.length} 條連線 · 下載合計 ${formatBytes(totalDown)}` : "連線後會即時顯示每個程式的連線與走向"}
        actions={
          <>
            <Button disabled={!running} onClick={() => setPaused((p) => !p)} icon={paused ? <Play size={14} /> : <Pause size={14} />}>
              {paused ? "繼續更新" : "暫停更新"}
            </Button>
            <Button variant="danger" disabled={!running || !conns.length} onClick={() => api.closeAll().catch((e) => toast(errorText(e), "error"))} icon={<XCircle size={14} />}>
              關閉全部
            </Button>
          </>
        }
      />
      <div className="flex items-center gap-2 border-b border-border px-6 py-2.5">
        <div className="relative flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-muted" />
          <Input className="w-full pl-8" placeholder="搜尋程式、網域、IP、規則…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Segmented
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "全部" },
            { value: "proxy", label: "走代理" },
            { value: "direct", label: "直連" },
          ]}
        />
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {!running ? (
          <EmptyState icon={<Activity size={28} />} title="尚未連線" />
        ) : visible.length === 0 ? (
          <EmptyState icon={<Activity size={28} />} title="目前沒有連線" />
        ) : (
          <table className="w-full table-fixed border-collapse text-[13px]">
            <thead className="sticky top-0 z-10 bg-surface text-left text-xs text-muted shadow-[0_1px_0_var(--border)]">
              <tr>
                <th className="w-[18%] py-2 pl-6 font-medium">程式</th>
                <th className="py-2 font-medium">目的地</th>
                <th className="w-14 py-2 font-medium">協定</th>
                <th className="w-[16%] py-2 font-medium">規則</th>
                <th className="w-[20%] py-2 font-medium">群組 → 出口</th>
                <SortTh label="上傳" k="upload" sort={sort} setSort={setSort} />
                <SortTh label="下載" k="download" sort={sort} setSort={setSort} />
                <SortTh label="時間" k="start" sort={sort} setSort={setSort} className="pr-6" />
              </tr>
            </thead>
            <tbody>
              {visible.map((c) => {
                const m = c.metadata;
                const proxied = isProxied(c);
                return (
                  <tr
                    key={c.id}
                    className="border-b border-border/60 hover:bg-surface-2"
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setMenu({ x: e.clientX, y: e.clientY, c });
                    }}
                  >
                    <td className="truncate py-1.5 pl-6" title={m.processPath}>
                      {m.processPath ? basename(m.processPath) : <span className="text-muted">—</span>}
                    </td>
                    <td className="selectable truncate py-1.5 font-mono text-xs" title={`${m.host || m.destinationIP}:${m.destinationPort}`}>
                      {m.host || m.destinationIP}:{m.destinationPort}
                    </td>
                    <td className="py-1.5 text-xs text-muted uppercase">{m.network}</td>
                    <td className="truncate py-1.5 text-xs text-muted" title={`${c.rule} ${c.rulePayload}`}>
                      {c.rule || "final"}
                    </td>
                    <td className="truncate py-1.5">
                      {(() => {
                        const label = c.chains.map((t) => selectorLabels.get(t)).find(Boolean);
                        return (
                          <span className="flex items-center gap-1.5" title={c.chains.slice().reverse().join(" → ")}>
                            {label && <span className="truncate text-xs">{label}</span>}
                            {label && <span className="text-muted">→</span>}
                            <Badge tone={proxied ? "accent" : "muted"}>{proxied ? nodeName(c.chains[0]) : "直連"}</Badge>
                          </span>
                        );
                      })()}
                    </td>
                    <td className="tabular py-1.5 text-right text-xs">{formatBytes(c.upload)}</td>
                    <td className="tabular py-1.5 text-right text-xs">{formatBytes(c.download)}</td>
                    <td className="tabular py-1.5 pr-6 text-right text-xs text-muted">{formatElapsed(Date.parse(c.start), now)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <p className="border-t border-border px-6 py-2 text-[11px] text-muted">在連線上按右鍵，可以為該程式或網域建立群組，或加入既有的群組。</p>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menuItems(menu.c)} onClose={() => setMenu(null)} />}
    </div>
  );
}

function SortTh({ label, k, sort, setSort, className }: { label: string; k: SortKey; sort: SortKey; setSort: (k: SortKey) => void; className?: string }) {
  return (
    <th className={cx("w-20 py-2 text-right font-medium", className)}>
      <button onClick={() => setSort(k)} className={cx("hover:text-text", sort === k && "text-accent")}>
        {label}
        {sort === k ? " ↓" : ""}
      </button>
    </th>
  );
}

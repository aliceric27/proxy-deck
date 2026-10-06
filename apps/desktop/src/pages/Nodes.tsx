import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Cloud, Gauge, Loader2, Plus, RefreshCw, Search, Server, Trash2 } from "lucide-react";
import { api, errorText, type NodeEntry } from "../lib/ipc";
import { useApp } from "../lib/store";
import { countryName, latencyTone } from "../lib/format";
import { Badge, Button, cx, EmptyState, IconButton, Input, Modal, PageHeader, Select } from "../components/ui";

type SortKey = "location" | "latency";

export default function Nodes() {
  const { profile, core, updateProfile, toast } = useApp();
  const running = core.state === "running";
  const [creatingWarp, setCreatingWarp] = useState(false);
  const [confirmWarp, setConfirmWarp] = useState(false);
  const [nodes, setNodes] = useState<NodeEntry[]>([]);
  const [fetchedAt, setFetchedAt] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [country, setCountry] = useState("all");
  const [sort, setSort] = useState<SortKey>("location");
  const [latency, setLatency] = useState<Record<string, number | null>>({});
  const [pinging, setPinging] = useState(false);
  const [proxyDelay, setProxyDelay] = useState<Record<string, number | null>>({});
  const [testing, setTesting] = useState(false);

  const load = useCallback(
    async (force: boolean) => {
      setLoading(true);
      try {
        const r = await api.nodes(force);
        setNodes(r.nodes);
        setFetchedAt(r.fetched_at);
      } catch (e) {
        toast(errorText(e), "error");
      } finally {
        setLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    load(false);
  }, [load]);

  const countries = useMemo(() => {
    const counts = new Map<string, number>();
    nodes.forEach((n) => counts.set(n.country, (counts.get(n.country) ?? 0) + 1));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [nodes]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = nodes.filter(
      (n) =>
        (country === "all" || n.country === country) &&
        (!q || [n.location, n.ip, n.hostname, countryName(n.country)].some((s) => s.toLowerCase().includes(q))),
    );
    if (sort === "latency") {
      const v = (n: NodeEntry) => (n.ip in latency ? (latency[n.ip] ?? 99999) : 100000);
      list.sort((a, b) => v(a) - v(b));
    }
    return list;
  }, [nodes, query, country, sort, latency]);

  if (!profile) return null;
  const selectedTags = new Set(profile.nodes.map((n) => n.tag));

  // Decided against the latest profile inside the update, so fast double clicks cannot add twice.
  const toggle = (n: NodeEntry) =>
    updateProfile((p) => ({
      ...p,
      nodes: p.nodes.some((x) => x.tag === n.proxy.tag) ? p.nodes.filter((x) => x.tag !== n.proxy.tag) : [...p.nodes, n.proxy],
    }));

  const ping = async () => {
    const targets = visible.slice(0, 300).map((n) => n.ip);
    if (!targets.length) return;
    setPinging(true);
    try {
      const res = await api.ping(targets);
      setLatency((prev) => ({ ...prev, ...Object.fromEntries(res.map((r) => [r.ip, r.ms])) }));
      setSort("latency");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setPinging(false);
    }
  };

  const createWarp = async () => {
    setConfirmWarp(false);
    setCreatingWarp(true);
    try {
      const n = await api.warpCreate();
      if (!(await updateProfile((p) => ({ ...p, nodes: [...p.nodes, n] })))) {
        await api.warpDiscard(n.tag).catch(() => {}); // best effort: never saved, do not leave the device registered
        return;
      }
      toast(`已產生「${n.name}」（${n.wireguard?.address_v4}），可設為預設節點或在群組中選用。`, "success");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setCreatingWarp(false);
    }
  };

  /** Real round trip through each added node (Clash API delay test); needs a running core. */
  const testProxies = async () => {
    setTesting(true);
    const results = await Promise.all(profile.nodes.map(async (n) => [n.tag, await api.delay(n.tag).catch(() => null)] as const));
    setProxyDelay(Object.fromEntries(results));
    setTesting(false);
  };

  const move = (tag: string, dir: -1 | 1) =>
    updateProfile((p) => {
      const i = p.nodes.findIndex((n) => n.tag === tag);
      const j = i + dir;
      if (i < 0 || j < 0 || j >= p.nodes.length) return p;
      const nodes = [...p.nodes];
      [nodes[i], nodes[j]] = [nodes[j], nodes[i]];
      return { ...p, nodes };
    });

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="節點"
        subtitle={fetchedAt ? `Mudfish 共 ${nodes.length} 個節點 · 清單更新於 ${new Date(fetchedAt * 1000).toLocaleString("zh-TW")}` : "載入 Mudfish 節點清單…"}
        actions={
          <>
            <Button onClick={ping} disabled={pinging || !visible.length} icon={pinging ? <Loader2 size={14} className="animate-spin" /> : <Gauge size={14} />}>
              測速{visible.length > 300 ? "（前 300 個）" : ""}
            </Button>
            <Button onClick={() => load(true)} disabled={loading} icon={<RefreshCw size={14} className={cx(loading && "animate-spin")} />}>
              更新清單
            </Button>
          </>
        }
      />
      <div className="flex min-h-0 flex-1">
        <section className="flex min-w-0 flex-1 flex-col" aria-label="Mudfish 節點清單">
          <div className="flex items-center gap-2 border-b border-border px-6 py-2.5">
            <div className="relative flex-1">
              <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-muted" />
              <Input className="w-full pl-8" placeholder="搜尋城市、供應商、IP…" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <Select
              label="國家"
              value={country}
              onChange={setCountry}
              className="w-44"
              options={[{ value: "all", label: `全部國家（${nodes.length}）` }, ...countries.map(([cc, n]) => ({ value: cc, label: `${countryName(cc)} ${cc}（${n}）` }))]}
            />
            <Select
              label="排序"
              value={sort}
              onChange={setSort}
              className="w-32"
              options={[
                { value: "location", label: "依地區" },
                { value: "latency", label: "依延遲" },
              ]}
            />
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
            {loading && !nodes.length ? (
              <div className="flex h-full items-center justify-center text-muted">
                <Loader2 className="animate-spin" />
              </div>
            ) : visible.length === 0 ? (
              <EmptyState icon={<Server size={28} />} title="沒有符合條件的節點" />
            ) : (
              <table className="w-full border-collapse text-[13px]">
                <thead className="sticky top-0 z-10 bg-surface text-left text-xs text-muted shadow-[0_1px_0_var(--border)]">
                  <tr>
                    <th className="w-12 py-2 pl-6 font-medium" />
                    <th className="py-2 font-medium">地區</th>
                    <th className="py-2 font-medium">供應商</th>
                    <th className="py-2 font-medium">IP</th>
                    <th className="w-24 py-2 pr-6 text-right font-medium">TCP 延遲</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((n) => {
                    const added = selectedTags.has(`mudfish-${n.sid}`);
                    const ms = latency[n.ip];
                    return (
                      <tr key={n.sid} onDoubleClick={() => toggle(n)} className={cx("border-b border-border/60 hover:bg-surface-2", added && "bg-accent-soft/40")}>
                        <td className="py-1.5 pl-6">
                          <input type="checkbox" checked={added} onChange={() => toggle(n)} aria-label={`加入 ${n.location}`} className="h-3.5 w-3.5 accent-[var(--accent)]" />
                        </td>
                        <td className="py-1.5">
                          <div className="flex items-center gap-2">
                            <Badge>{n.country}</Badge>
                            <span>{n.city || n.location}</span>
                            <span className="text-xs text-muted">{countryName(n.country)}</span>
                          </div>
                        </td>
                        <td className="py-1.5">
                          <span className="mr-1.5">{n.provider}</span>
                          {n.premium && (
                            <span title="Premium 是部分訂閱方案的存取限制標記。使用流量計費（PPT）且有餘額時可直接使用，不需另購 Premium 訂閱。">
                              <Badge tone="accent">Premium</Badge>
                            </span>
                          )}
                          {!n.commercial && (
                            <span title="Mudfish 標示的免費節點。">
                              <Badge tone="ok">免費</Badge>
                            </span>
                          )}
                        </td>
                        <td className="selectable py-1.5 font-mono text-xs text-muted">{n.ip}</td>
                        <td className="tabular py-1.5 pr-6 text-right">
                          {n.ip in latency ? <Badge tone={latencyTone(ms)}>{ms == null ? "逾時" : `${ms} ms`}</Badge> : <span className="text-muted">—</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
          <p className="border-t border-border px-6 py-2 text-[11px] text-muted">
            勾選或雙擊加入節點。TCP 延遲是到節點 SOCKS 連接埠（18081）的握手時間，不消耗 Mudfish 流量；連線後可在右側測試經過代理的實際延遲。
          </p>
        </section>

        <aside className="flex w-80 shrink-0 flex-col border-l border-border bg-surface" aria-label="已選節點">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-[13px] font-semibold">已選節點（{profile.nodes.length}）</h2>
            <Button
              size="sm"
              variant="ghost"
              disabled={!running || testing || !profile.nodes.length}
              onClick={testProxies}
              icon={testing ? <Loader2 size={12} className="animate-spin" /> : <Gauge size={12} />}
              title={running ? "經過各節點實際連線測試延遲" : "連線後才能測試代理延遲"}
            >
              測試延遲
            </Button>
          </div>
          <div className="border-b border-border px-4 py-3">
            <Button
              className="w-full"
              onClick={() => setConfirmWarp(true)}
              disabled={creatingWarp}
              icon={creatingWarp ? <Loader2 size={14} className="animate-spin" /> : <Cloud size={14} />}
              title="向 Cloudflare 註冊一個新的免費 WARP 裝置，產生 WireGuard 節點"
            >
              產生 WARP 節點
            </Button>
            <p className="mt-1.5 text-[11px] leading-relaxed text-muted">每次產生都會註冊一個新的 Cloudflare WARP 免費裝置。金鑰存在 Windows 認證管理員；移除節點時會向 Cloudflare 註銷該裝置並刪除金鑰。</p>
          </div>
          {profile.nodes.length === 0 ? (
            <EmptyState icon={<Plus size={24} />} title="尚未加入節點">
              從左側清單勾選 Mudfish 節點，或產生 WARP 節點。加入多個節點時，「自動選擇」會挑延遲最低的一個。
            </EmptyState>
          ) : (
            <ul className="min-h-0 flex-1 divide-y divide-border overflow-auto">
              {profile.nodes.map((n, i) => (
                <li key={n.tag} className="group flex items-center gap-2 px-4 py-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate" title={n.name}>{n.name}</span>
                      {n.wireguard ? <Badge tone="warn">WARP</Badge> : <Badge>Mudfish</Badge>}
                      {n.tag in proxyDelay && (
                        <Badge tone={latencyTone(proxyDelay[n.tag])}>{proxyDelay[n.tag] == null ? "逾時" : `${proxyDelay[n.tag]} ms`}</Badge>
                      )}
                    </div>
                    <div className="truncate font-mono text-[11px] text-muted" title={n.wireguard ? `${n.wireguard.address_v4} ${n.wireguard.address_v6}` : undefined}>
                      {n.server}
                      {n.wireguard ? `:${n.port} · ${n.wireguard.address_v4}` : ""}
                    </div>
                  </div>
                  <div className="flex opacity-0 group-hover:opacity-100 focus-within:opacity-100">
                    <IconButton label="上移" disabled={i === 0} onClick={() => move(n.tag, -1)}>
                      <ArrowUp size={14} />
                    </IconButton>
                    <IconButton label="下移" disabled={i === profile.nodes.length - 1} onClick={() => move(n.tag, 1)}>
                      <ArrowDown size={14} />
                    </IconButton>
                    <IconButton label="移除" onClick={() => updateProfile((p) => ({ ...p, nodes: p.nodes.filter((x) => x.tag !== n.tag) }))}>
                      <Trash2 size={14} />
                    </IconButton>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </aside>
      </div>
      {confirmWarp && (
        <Modal
          title="產生 WARP 節點"
          width={460}
          onClose={() => setConfirmWarp(false)}
          footer={
            <>
              <Button onClick={() => setConfirmWarp(false)}>取消</Button>
              <Button variant="primary" onClick={createWarp}>
                註冊並產生
              </Button>
            </>
          }
        >
          <p className="px-4 py-3 text-[13px] leading-relaxed">
            會向 Cloudflare 註冊一個新的免費 WARP 裝置（每按一次一個），使用時需遵守 Cloudflare 的服務條款。之後移除這個節點時，ProxyDesk 會一併註銷該裝置。
          </p>
        </Modal>
      )}
    </div>
  );
}

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { ArrowDown, ArrowUp, ChevronRight, Copy, FolderOpen, GripVertical, ListFilter, Lock, Plus, Search, Trash2 } from "lucide-react";
import { api, errorText, type GeoIpGroup, type Profile, type ProcessInfo, type RuleGroup, type RuleSetCatalog, type UdpPolicy } from "../lib/ipc";
import { useApp } from "../lib/store";
import { newId } from "../lib/format";
import { Button, ChipInput, ContextMenu, cx, EmptyState, IconButton, Input, Modal, PageHeader, Segmented, Select, Toggle, type MenuItem } from "../components/ui";
import {
  geoipLabel,
  geoipSummary,
  isProxied,
  MATCHER_META,
  MatcherSummary,
  matcherCounts,
  matcherPreview,
  newGroup,
  OutboundBadge,
  OutboundSelect,
  uniqueCodes,
  type MatcherKind,
} from "../components/groups";

/** `selectedId` of the fixed rows; custom groups use their own id. */
const GEOIP_ID = "@geoip";
const FINAL_ID = "@final";

/** Windows `process_name` matches the full file name, so `steam` must become `steam.exe`. */
function normalizeExe(name: string): string {
  const n = name.trim();
  return n && !/\.[a-z0-9]+$/i.test(n) ? `${n}.exe` : n;
}

export default function Groups() {
  const { profile, updateProfile } = useApp();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [freshId, setFreshId] = useState<string | null>(null);
  const [menu, setMenu] = useState<{ x: number; y: number; group: RuleGroup } | null>(null);
  const [dragId, setDragId] = useState<string | null>(null);
  const [dropIndex, setDropIndex] = useState<number | null>(null);

  if (!profile) return null;
  const groups = profile.groups;
  const selected = groups.find((g) => g.id === selectedId) ?? null;

  const patch = (id: string, p: Partial<RuleGroup>) => updateProfile((pr) => ({ ...pr, groups: pr.groups.map((g) => (g.id === id ? { ...g, ...p } : g)) }));

  /** Moves group `id` so it ends up at index `to` (0 = highest priority). */
  const moveTo = (id: string, to: number) =>
    updateProfile((pr) => {
      const from = pr.groups.findIndex((g) => g.id === id);
      if (from < 0) return pr;
      const next = [...pr.groups];
      const [g] = next.splice(from, 1);
      next.splice(Math.max(0, Math.min(to, next.length)), 0, g);
      return { ...pr, groups: next };
    });

  const remove = (id: string) => {
    updateProfile((pr) => ({ ...pr, groups: pr.groups.filter((g) => g.id !== id) }));
    if (selectedId === id) setSelectedId(null);
  };

  const add = () => {
    const g = newGroup();
    updateProfile((pr) => ({ ...pr, groups: [g, ...pr.groups] }));
    setSelectedId(g.id);
    setFreshId(g.id);
  };

  const duplicate = (g: RuleGroup) => {
    const copy = { ...g, id: newId(), name: `${g.name}（副本）` };
    updateProfile((pr) => {
      const i = pr.groups.findIndex((x) => x.id === g.id);
      const next = [...pr.groups];
      next.splice(i + 1, 0, copy);
      return { ...pr, groups: next };
    });
    setSelectedId(copy.id);
  };

  const rowMenu = (g: RuleGroup): MenuItem[] => {
    const i = groups.findIndex((x) => x.id === g.id);
    return [
      { label: "編輯", onSelect: () => setSelectedId(g.id) },
      { label: g.enabled ? "停用" : "啟用", onSelect: () => patch(g.id, { enabled: !g.enabled }) },
      { label: "建立副本", onSelect: () => duplicate(g) },
      { label: "移到最上面（最優先）", disabled: i === 0, separatorBefore: true, onSelect: () => moveTo(g.id, 0) },
      { label: "上移", disabled: i === 0, onSelect: () => moveTo(g.id, i - 1) },
      { label: "下移", disabled: i === groups.length - 1, onSelect: () => moveTo(g.id, i + 1) },
      { label: "移到最下面", disabled: i === groups.length - 1, onSelect: () => moveTo(g.id, groups.length - 1) },
      { label: "刪除", danger: true, separatorBefore: true, onSelect: () => remove(g.id) },
    ];
  };

  const enabledCount = groups.filter((g) => g.enabled).length;

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="分流群組"
        subtitle={`由上而下比對；都不符合時依序比對 GeoIP 與 final。拖曳列表可調整順序，已啟用 ${enabledCount} / ${groups.length} 個群組。`}
        actions={
          <Button variant="primary" icon={<Plus size={14} />} onClick={add}>
            新增群組
          </Button>
        }
      />
      <div className="flex min-h-0 flex-1">
        <section className="flex min-w-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-auto">
            {groups.length === 0 ? (
              <EmptyState icon={<ListFilter size={28} />} title="沒有自訂群組">
                一個群組可以同時包含應用程式、網域、規則集與 IP 範圍，符合任一條件的流量就會走這個群組指定的出口，例如「遊戲」群組走日本節點、「影音」群組走台灣節點。沒有群組可以套用的流量，會依序交給下方的 GeoIP 與 final。
              </EmptyState>
            ) : (
              <ol onDragLeave={() => setDropIndex(null)}>
                {groups.map((g, i) => (
                  <li
                    key={g.id}
                    draggable
                    onDragStart={(e) => {
                      setDragId(g.id);
                      e.dataTransfer.effectAllowed = "move";
                    }}
                    onDragEnd={() => {
                      setDragId(null);
                      setDropIndex(null);
                    }}
                    onDragOver={(e) => {
                      if (!dragId) return;
                      e.preventDefault();
                      const r = e.currentTarget.getBoundingClientRect();
                      setDropIndex(e.clientY < r.top + r.height / 2 ? i : i + 1);
                    }}
                    onDrop={(e) => {
                      e.preventDefault();
                      if (dragId && dropIndex != null) {
                        const from = groups.findIndex((x) => x.id === dragId);
                        moveTo(dragId, from < dropIndex ? dropIndex - 1 : dropIndex);
                      }
                      setDragId(null);
                      setDropIndex(null);
                    }}
                    onClick={() => setSelectedId(g.id)}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setMenu({ x: e.clientX, y: e.clientY, group: g });
                    }}
                    className={cx(
                      "group relative flex cursor-default items-center gap-3 border-b border-border px-4 py-2.5 hover:bg-surface-2",
                      selectedId === g.id && "bg-accent-soft/60",
                      !g.enabled && "opacity-55",
                      dragId === g.id && "opacity-40",
                    )}
                  >
                    {dropIndex === i && <span className="absolute inset-x-0 -top-px h-0.5 bg-accent" />}
                    {dropIndex === i + 1 && i === groups.length - 1 && <span className="absolute inset-x-0 -bottom-px h-0.5 bg-accent" />}
                    <GripVertical size={14} className="shrink-0 cursor-grab text-muted opacity-40 group-hover:opacity-100" aria-hidden />
                    <span className="tabular w-5 text-right text-xs text-muted" title="優先順序">
                      {i + 1}
                    </span>
                    <Toggle checked={g.enabled} onChange={(v) => patch(g.id, { enabled: v })} label={`啟用 ${g.name}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <span className="truncate font-medium">{g.name}</span>
                        <MatcherSummary group={g} />
                      </div>
                      <div className="truncate font-mono text-[11px] text-muted">{matcherPreview(g) || "—"}</div>
                    </div>
                    <OutboundBadge profile={profile} outbound={g.outbound} />
                    <div className="flex opacity-0 group-hover:opacity-100">
                      <IconButton label="上移" disabled={i === 0} onClick={(e) => (e.stopPropagation(), moveTo(g.id, i - 1))}>
                        <ArrowUp size={14} />
                      </IconButton>
                      <IconButton label="下移" disabled={i === groups.length - 1} onClick={(e) => (e.stopPropagation(), moveTo(g.id, i + 1))}>
                        <ArrowDown size={14} />
                      </IconButton>
                    </div>
                  </li>
                ))}
              </ol>
            )}
            {/* The last two rules of the list. A group dropped here lands after the last custom group: nothing can follow GeoIP and final. */}
            <div
              className={cx("bg-surface-2/40", groups.length === 0 && "border-t border-border")}
              onDragOver={(e) => {
                if (!dragId) return;
                e.preventDefault();
                setDropIndex(groups.length);
              }}
              onDragLeave={(e) => {
                if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropIndex(null);
              }}
              onDrop={(e) => {
                e.preventDefault();
                const last = groups.length - 1;
                if (dragId && groups[last]?.id !== dragId) moveTo(dragId, last);
                setDragId(null);
                setDropIndex(null);
              }}
            >
              <p className="px-6 pt-2 pb-1 text-[11px] text-muted">{groups.length ? "以上群組都不符合時，依序比對：" : "流量依序比對："}</p>
              <FixedRow
                title="GeoIP"
                subtitle={geoipSummary(profile.geoip.countries)}
                profile={profile}
                outbound={profile.geoip.outbound}
                selected={selectedId === GEOIP_ID}
                onSelect={() => setSelectedId(GEOIP_ID)}
              />
              <FixedRow
                title="final"
                subtitle="不符合以上任何規則的流量"
                profile={profile}
                outbound={profile.final_outbound}
                selected={selectedId === FINAL_ID}
                onSelect={() => setSelectedId(FINAL_ID)}
              />
            </div>
          </div>
        </section>

        {selected && (
          <GroupEditor
            key={selected.id}
            group={selected}
            fresh={freshId === selected.id}
            onChange={(p) => patch(selected.id, p)}
            onDelete={() => remove(selected.id)}
            onClose={() => setSelectedId(null)}
          />
        )}
        {selectedId === GEOIP_ID && <GeoIpEditor onClose={() => setSelectedId(null)} />}
        {selectedId === FINAL_ID && <FinalEditor onClose={() => setSelectedId(null)} />}
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={rowMenu(menu.group)} onClose={() => setMenu(null)} />}
    </div>
  );
}

/** A fixed row after the custom groups: it cannot be dragged, toggled or deleted, only edited. */
function FixedRow({ title, subtitle, profile, outbound, selected, onSelect }: { title: string; subtitle: string; profile: Profile; outbound: string; selected: boolean; onSelect: () => void }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={selected ? "true" : undefined}
      className={cx("flex w-full cursor-default items-center gap-3 border-b border-border px-4 py-2.5 text-left hover:bg-surface-2", selected && "bg-accent-soft/60")}
    >
      {/* Same columns as a custom row (grip, priority, toggle), so the names line up. */}
      <Lock size={14} className="shrink-0 text-muted" aria-label="固定的群組" />
      <span className="w-5" />
      <span className="w-9 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium">{title}</div>
        <div className="truncate text-[11px] text-muted">{subtitle}</div>
      </div>
      <OutboundBadge profile={profile} outbound={outbound} />
      <span className="w-14 shrink-0" />
    </button>
  );
}

function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="text-xs font-medium">{label}</div>
      {children}
      {hint && <div className="text-[11px] leading-relaxed text-muted">{hint}</div>}
    </div>
  );
}

function Section({ kind, count, defaultOpen, children }: { kind: MatcherKind; count: number; defaultOpen: boolean; children: ReactNode }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="rounded-md border border-border">
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] font-medium hover:bg-surface-2">
        <ChevronRight size={14} className={cx("text-muted transition-transform", open && "rotate-90")} />
        {MATCHER_META[kind].icon}
        <span className="flex-1">{MATCHER_META[kind].label}</span>
        {count > 0 && <span className="rounded bg-accent-soft px-1.5 text-[11px] text-accent">{count}</span>}
      </button>
      {open && <div className="space-y-4 border-t border-border p-3">{children}</div>}
    </section>
  );
}

/** Right-hand panel shell shared by the editors. */
function EditorFrame({ title, onClose, footer, children }: { title: string; onClose: () => void; footer?: ReactNode; children: ReactNode }) {
  return (
    <aside className="flex w-[460px] shrink-0 flex-col border-l border-border bg-surface" aria-label={title}>
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-[13px] font-semibold">{title}</h2>
        <Button size="sm" variant="ghost" onClick={onClose}>
          完成
        </Button>
      </div>
      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">{children}</div>
      {footer}
    </aside>
  );
}

function GroupEditor({ group: g, fresh, onChange, onDelete, onClose }: { group: RuleGroup; fresh: boolean; onChange: (p: Partial<RuleGroup>) => void; onDelete: () => void; onClose: () => void }) {
  const { profile, toast } = useApp();
  const [name, setName] = useState(g.name);
  const [picker, setPicker] = useState(false);
  const counts = matcherCounts(g);
  if (!profile) return null;

  const browseExe = async () => {
    const path = await open({ multiple: false, directory: false, filters: [{ name: "程式", extensions: ["exe"] }] });
    if (typeof path === "string" && !g.process_paths.includes(path)) onChange({ process_paths: [...g.process_paths, path] });
  };
  const browseDir = async () => {
    const path = await open({ multiple: false, directory: true });
    if (typeof path === "string" && !g.directories.includes(path)) onChange({ directories: [...g.directories, path] });
  };

  return (
    <>
      <EditorFrame
        title="編輯群組"
        onClose={onClose}
        footer={
          <div className="flex justify-between border-t border-border p-4">
            <Button variant="danger" icon={<Trash2 size={14} />} onClick={onDelete}>
              刪除群組
            </Button>
            <Button variant="ghost" icon={<Copy size={14} />} onClick={() => navigator.clipboard.writeText(JSON.stringify(g, null, 2))}>
              複製 JSON
            </Button>
          </div>
        }
      >
        <Field label="名稱">
          <Input
            className="w-full"
            value={name}
            autoFocus={fresh}
            onFocus={(e) => fresh && e.target.select()}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => name.trim() && name !== g.name && onChange({ name: name.trim() })}
            onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
          />
        </Field>
        <Field label="出口" hint="連線中可在總覽頁即時切換；直連與代理互換時，部分規則要重新連線才完整生效，改成或離開「阻擋」也需要重新連線。">
          <OutboundSelect profile={profile} value={g.outbound} onChange={(outbound) => onChange({ outbound })} className="w-full" />
        </Field>
        {isProxied(profile, g.outbound) && (
          <Field label="UDP 流量" hint="遊戲通常使用 UDP。">
            <Select<UdpPolicy>
              label="UDP 流量"
              value={g.udp}
              onChange={(udp) => onChange({ udp })}
              className="w-full"
              options={[
                { value: "follow", label: "一起走代理" },
                { value: "direct", label: "UDP 直連" },
                { value: "reject", label: "阻擋 UDP" },
              ]}
            />
          </Field>
        )}

        <div className="space-y-2">
          <div className="text-xs font-medium">比對條件</div>
          <Segmented
            value={g.match_mode}
            onChange={(match_mode: "any" | "all") => onChange({ match_mode })}
            options={[
              { value: "any", label: "符合任一條件 (OR)", hint: "任一類條件符合就套用" },
              { value: "all", label: "符合全部條件 (AND)", hint: "每一類條件都要符合才套用，例如某程式且某 IP" },
            ]}
          />
          <p className="text-[11px] leading-relaxed text-muted">
            {g.match_mode === "all"
              ? "需同時符合下列所有已設定的條件才套用（例如：特定程式 ＋ 特定 IP）。同一類中有多個值時仍是任一符合。若含網域條件，網域不使用 FakeIP，改以連線的 SNI／主機名稱比對（適用多數 TLS／HTTP 連線）。"
              : "符合下列任一條件即套用這個群組。"}
          </p>
        </div>

        <Section kind="app" count={counts.app} defaultOpen={fresh || counts.app > 0}>
          <Field label="程式名稱" hint="例如 LeagueClient.exe；未加副檔名時自動補上 .exe。">
            <ChipInput mono values={g.process_names} onChange={(v) => onChange({ process_names: [...new Set(v.map(normalizeExe))] })} placeholder="game.exe" />
            <Button size="sm" icon={<Search size={12} />} onClick={() => setPicker(true)}>
              從執行中的程式選擇…
            </Button>
          </Field>
          <Field label="完整路徑" hint="只比對這個位置的執行檔。">
            <ChipInput mono values={g.process_paths} onChange={(process_paths) => onChange({ process_paths })} placeholder="C:\Program Files\Game\game.exe" />
            <Button size="sm" icon={<FolderOpen size={12} />} onClick={() => browseExe().catch((e) => toast(errorText(e), "error"))}>
              瀏覽 .exe…
            </Button>
          </Field>
          <Field label="安裝資料夾" hint="資料夾內（含子資料夾）所有程式都符合。">
            <ChipInput mono values={g.directories} onChange={(directories) => onChange({ directories })} placeholder="C:\Riot Games" />
            <Button size="sm" icon={<FolderOpen size={12} />} onClick={() => browseDir().catch((e) => toast(errorText(e), "error"))}>
              選擇資料夾…
            </Button>
          </Field>
        </Section>

        <Section kind="domain" count={counts.domain} defaultOpen={fresh || counts.domain > 0}>
          <Field label="網域" hint="example.com 會同時比對所有子網域。">
            <ChipInput mono values={g.domain_suffixes} onChange={(domain_suffixes) => onChange({ domain_suffixes })} placeholder="example.com" />
          </Field>
          <Field label="關鍵字" hint="網域中包含此字串即符合。">
            <ChipInput mono values={g.domain_keywords} onChange={(domain_keywords) => onChange({ domain_keywords })} placeholder="google" />
          </Field>
        </Section>

        <Section kind="rule_set" count={counts.rule_set} defaultOpen={counts.rule_set > 0}>
          <RuleSetFields codes={g.rule_sets} onChange={(rule_sets) => onChange({ rule_sets })} />
        </Section>

        <Section kind="ip" count={counts.ip} defaultOpen={counts.ip > 0}>
          <Field label="IP 範圍（CIDR）" hint="例如 100.64.0.0/10 或 203.0.113.5/32。">
            <ChipInput mono values={g.ip_cidrs} onChange={(ip_cidrs) => onChange({ ip_cidrs })} placeholder="203.0.113.0/24" />
          </Field>
        </Section>
      </EditorFrame>
      {picker && (
        <ProcessPicker
          onClose={() => setPicker(false)}
          onPick={(p, by) =>
            by === "name"
              ? onChange({ process_names: [...new Set([...g.process_names, p.name])] })
              : onChange({ process_paths: [...new Set([...g.process_paths, p.path])] })
          }
        />
      )}
    </>
  );
}

/** Traffic whose destination IP belongs to the chosen countries or regions: right after the custom groups. */
function GeoIpEditor({ onClose }: { onClose: () => void }) {
  const { profile, updateProfile, toast } = useApp();
  const [catalog, setCatalog] = useState<RuleSetCatalog | null>(null);
  const [q, setQ] = useState("");
  useEffect(() => {
    api.ruleSetCatalog().then(setCatalog).catch((e) => toast(errorText(e), "error"));
  }, [toast]);
  const visible = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return (catalog?.geoip ?? []).filter((c) => !ql || c.toLowerCase().includes(ql) || geoipLabel(c).toLowerCase().includes(ql));
  }, [catalog, q]);
  if (!profile) return null;

  // The countries as the generator reads them: trimmed, unique, no blanks.
  const codes = uniqueCodes(profile.geoip.countries);
  const lastOne = codes.length <= 1;
  const setGeoip = (p: Partial<GeoIpGroup>) => updateProfile((pr) => ({ ...pr, geoip: { ...pr.geoip, ...p } }));
  /** Adds or removes `code`. Decided against the latest profile, and the list never ends up empty. */
  const toggle = (code: string) => {
    if (lastOne && codes.includes(code)) return void toast("至少要保留一個國家或地區。");
    updateProfile((pr) => {
      const current = uniqueCodes(pr.geoip.countries);
      if (!current.includes(code)) return { ...pr, geoip: { ...pr.geoip, countries: [...current, code] } };
      if (current.length <= 1) return pr;
      return { ...pr, geoip: { ...pr.geoip, countries: current.filter((c) => c !== code) } };
    });
  };

  return (
    <EditorFrame title="編輯 GeoIP" onClose={onClose}>
      <p className="text-[11px] leading-relaxed text-muted">目的地 IP 屬於下列國家或地區、又不符合任何自訂群組的流量，會走這個出口。這是固定的群組，無法刪除或停用。</p>
      <Field label="出口" hint="連線中也可以在總覽頁即時切換；改成或離開「阻擋」需要重新連線。">
        <OutboundSelect profile={profile} value={profile.geoip.outbound} onChange={(outbound) => setGeoip({ outbound })} className="w-full" />
      </Field>
      <Field
        label={`國家與地區（${codes.length}）`}
        hint={
          codes.length === 1 ? (
            <span className="text-warn">至少要保留一個國家或地區，無法再移除。</span>
          ) : codes.length > 1 ? (
            "點擊標籤即可移除，也可以在下方搜尋後勾選新增。"
          ) : (
            "在下方搜尋後勾選新增。"
          )
        }
      >
        {codes.length === 0 ? (
          <p className="text-[11px] text-warn">尚未選擇國家或地區，GeoIP 規則不會生效。</p>
        ) : (
          <div className="flex flex-wrap gap-1">
            {codes.map((c) => (
              <button
                key={c}
                onClick={() => toggle(c)}
                disabled={lastOne}
                title={lastOne ? "至少要保留一個國家或地區" : "點擊移除"}
                className="rounded bg-accent-soft px-1.5 py-0.5 text-xs text-accent hover:bg-danger-soft hover:text-danger disabled:pointer-events-none"
              >
                {geoipLabel(c)}
                {!lastOne && " ×"}
              </button>
            ))}
          </div>
        )}
      </Field>
      <Field label="新增國家或地區" hint="可以用國家名稱或代碼搜尋。">
        <Input className="w-full" placeholder="搜尋，例如 日本 或 jp…" value={q} onChange={(e) => setQ(e.target.value)} />
        <ul className="h-64 overflow-auto rounded-md border border-border">
          {catalog === null && <li className="px-2.5 py-3 text-center text-xs text-muted">讀取中…</li>}
          {catalog !== null && visible.length === 0 && <li className="px-2.5 py-3 text-center text-xs text-muted">沒有符合的項目</li>}
          {visible.map((c) => {
            const on = codes.includes(c);
            const locked = on && lastOne;
            return (
              <li key={c}>
                <button
                  onClick={() => toggle(c)}
                  disabled={locked}
                  title={locked ? "至少要保留一個國家或地區" : undefined}
                  className={cx("flex w-full items-center gap-2 px-2.5 py-1 text-left text-xs hover:bg-surface-2 disabled:pointer-events-none disabled:opacity-60", on && "text-accent")}
                >
                  <input type="checkbox" readOnly checked={on} tabIndex={-1} className="h-3 w-3 accent-[var(--accent)]" />
                  {geoipLabel(c)}
                </button>
              </li>
            );
          })}
        </ul>
      </Field>
    </EditorFrame>
  );
}

/** Everything no custom group and no GeoIP country claimed: the last row. */
function FinalEditor({ onClose }: { onClose: () => void }) {
  const { profile, updateProfile } = useApp();
  if (!profile) return null;
  return (
    <EditorFrame title="編輯 final" onClose={onClose}>
      <p className="text-[11px] leading-relaxed text-muted">所有自訂群組與 GeoIP 都不符合的流量，會走這個出口。這是最後一條規則，無法刪除或停用。</p>
      <Field label="出口" hint="連線中也可以在總覽頁即時切換；改成或離開「阻擋」需要重新連線。">
        <OutboundSelect profile={profile} value={profile.final_outbound} onChange={(final_outbound) => updateProfile((p) => ({ ...p, final_outbound }))} className="w-full" />
      </Field>
      {isProxied(profile, profile.final_outbound) && (
        <p className="rounded-md bg-surface-2 px-3 py-2 text-[11px] leading-relaxed text-muted">
          走代理時，不屬於任何自訂群組的網域會先在本機解析，再把 IP 交給節點。要讓節點負責解析網域，請把該網域加進自訂群組。
        </p>
      )}
    </EditorFrame>
  );
}

function ProcessPicker({ onClose, onPick }: { onClose: () => void; onPick: (p: ProcessInfo, by: "name" | "path") => void }) {
  const { toast } = useApp();
  const [list, setList] = useState<ProcessInfo[] | null>(null);
  const [q, setQ] = useState("");
  const [added, setAdded] = useState<Set<string>>(new Set());
  useEffect(() => {
    api.processes().then(setList).catch((e) => toast(errorText(e), "error"));
  }, [toast]);
  const visible = useMemo(() => (list ?? []).filter((p) => !q || p.path.toLowerCase().includes(q.toLowerCase())), [list, q]);
  const pick = (p: ProcessInfo, by: "name" | "path") => {
    onPick(p, by);
    setAdded((s) => new Set(s).add(p.path + by));
  };
  return (
    <Modal title="從執行中的程式選擇" onClose={onClose} width={640} footer={<Button onClick={onClose}>完成</Button>}>
      <div className="border-b border-border p-3">
        <Input autoFocus className="w-full" placeholder="搜尋程式名稱或路徑…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {list === null ? (
        <p className="p-6 text-center text-muted">讀取中…</p>
      ) : (
        <ul className="max-h-[420px] divide-y divide-border overflow-auto">
          {visible.map((p) => (
            <li key={p.path} className="flex items-center gap-3 px-4 py-2">
              <div className="min-w-0 flex-1">
                <div className="truncate font-medium">{p.name}</div>
                <div className="truncate font-mono text-[11px] text-muted" title={p.path}>
                  {p.path}
                </div>
              </div>
              <Button size="sm" disabled={added.has(p.path + "name")} onClick={() => pick(p, "name")}>
                {added.has(p.path + "name") ? "已加入" : "依名稱"}
              </Button>
              <Button size="sm" variant="ghost" disabled={added.has(p.path + "path")} onClick={() => pick(p, "path")}>
                {added.has(p.path + "path") ? "已加入" : "依路徑"}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Modal>
  );
}

function RuleSetFields({ codes, onChange }: { codes: string[]; onChange: (codes: string[]) => void }) {
  const { toast } = useApp();
  const [catalog, setCatalog] = useState<RuleSetCatalog | null>(null);
  const [tab, setTab] = useState<keyof RuleSetCatalog>("geosite");
  const [q, setQ] = useState("");
  useEffect(() => {
    api.ruleSetCatalog().then(setCatalog).catch((e) => toast(errorText(e), "error"));
  }, [toast]);
  const visible = useMemo(() => (catalog?.[tab] ?? []).filter((c) => !q || c.toLowerCase().includes(q.toLowerCase())).slice(0, 300), [catalog, tab, q]);
  const toggle = (code: string) => onChange(codes.includes(code) ? codes.filter((c) => c !== code) : [...codes, code]);

  return (
    <>
      {codes.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {codes.map((c) => (
            <button key={c} onClick={() => toggle(c)} className="rounded bg-accent-soft px-1.5 py-0.5 font-mono text-xs text-accent hover:bg-danger-soft hover:text-danger" title="點擊移除">
              {c} ×
            </button>
          ))}
        </div>
      )}
      <Field label="內建規則集" hint="geosite：網站分類（netflix、category-games）；geoip：國家或服務 IP（tw、jp）；acl：ACL4SSR 規則（Steam、BanAD）。">
        <div className="flex gap-2">
          <Segmented
            value={tab}
            onChange={setTab}
            options={[
              { value: "geosite", label: "geosite" },
              { value: "geoip", label: "geoip" },
              { value: "acl", label: "acl" },
            ]}
          />
          <Input className="min-w-0 flex-1" placeholder="搜尋…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <ul className="h-56 overflow-auto rounded-md border border-border">
          {visible.map((c) => {
            const code = `${tab}:${c}`;
            const on = codes.includes(code);
            return (
              <li key={c}>
                <button onClick={() => toggle(code)} className={cx("flex w-full items-center gap-2 px-2.5 py-1 text-left font-mono text-xs hover:bg-surface-2", on && "text-accent")}>
                  <input type="checkbox" readOnly checked={on} tabIndex={-1} className="h-3 w-3 accent-[var(--accent)]" />
                  {c}
                </button>
              </li>
            );
          })}
        </ul>
      </Field>
    </>
  );
}

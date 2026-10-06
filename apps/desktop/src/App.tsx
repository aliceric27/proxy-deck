import { useEffect, useState, type ReactNode } from "react";
import { Activity, AlertTriangle, LayoutDashboard, ListFilter, Loader2, Power, ScrollText, Server, Settings as SettingsIcon, X } from "lucide-react";
import { useApp } from "./lib/store";
import { Button, cx, Kbd } from "./components/ui";
import Dashboard from "./pages/Dashboard";
import Nodes from "./pages/Nodes";
import Groups from "./pages/Groups";
import Connections from "./pages/Connections";
import Logs from "./pages/Logs";
import Settings from "./pages/Settings";

export type PageId = "dashboard" | "nodes" | "groups" | "connections" | "logs" | "settings";

const PAGES: { id: PageId; label: string; icon: ReactNode }[] = [
  { id: "dashboard", label: "總覽", icon: <LayoutDashboard size={16} /> },
  { id: "nodes", label: "節點", icon: <Server size={16} /> },
  { id: "groups", label: "分流群組", icon: <ListFilter size={16} /> },
  { id: "connections", label: "連線", icon: <Activity size={16} /> },
  { id: "logs", label: "日誌", icon: <ScrollText size={16} /> },
  { id: "settings", label: "設定", icon: <SettingsIcon size={16} /> },
];

export default function App() {
  const { snapshot, core, needsApply, busy, connect, disconnect, toasts, dismissToast } = useApp();
  const [page, setPage] = useState<PageId>("dashboard");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey || e.shiftKey) return;
      const n = Number(e.key);
      if (n >= 1 && n <= PAGES.length) {
        e.preventDefault();
        setPage(PAGES[n - 1].id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!snapshot) {
    return (
      <div className="flex h-full items-center justify-center text-muted">
        <Loader2 className="animate-spin" size={20} />
      </div>
    );
  }

  const running = core.state === "running";
  const starting = core.state === "starting";

  return (
    <div className="flex h-full">
      <nav className="flex w-52 shrink-0 flex-col border-r border-border bg-surface" aria-label="主選單">
        <div className="flex h-14 items-center gap-2 px-4">
          <div className="flex h-7 w-7 items-center justify-center rounded-md bg-accent text-accent-text">
            <Power size={15} strokeWidth={2.5} />
          </div>
          <span className="text-sm font-semibold">ProxyDesk</span>
        </div>
        <ul className="flex-1 space-y-0.5 px-2 py-1">
          {PAGES.map((p, i) => (
            <li key={p.id}>
              <button
                onClick={() => setPage(p.id)}
                aria-current={page === p.id ? "page" : undefined}
                className={cx(
                  "group flex h-8 w-full items-center gap-2.5 rounded-md px-2.5 text-[13px]",
                  page === p.id ? "bg-accent-soft font-medium text-accent" : "text-muted hover:bg-surface-2 hover:text-text",
                )}
              >
                {p.icon}
                <span className="flex-1 text-left">{p.label}</span>
                <span className="opacity-0 group-hover:opacity-100">
                  <Kbd>Ctrl {i + 1}</Kbd>
                </span>
              </button>
            </li>
          ))}
        </ul>
        <div className="border-t border-border p-3">
          <div className="mb-2 flex items-center gap-2 text-xs">
            <span className={cx("h-2 w-2 rounded-full", running ? "bg-ok" : starting ? "bg-warn animate-pulse" : core.state === "error" ? "bg-danger" : "bg-border")} />
            <span className="text-muted">{running ? "已連線" : starting ? "連線中…" : core.state === "error" ? "發生錯誤" : "未連線"}</span>
          </div>
          <Button
            variant={running || starting ? "secondary" : "primary"}
            className="w-full"
            disabled={busy}
            onClick={() => (running || starting ? disconnect() : connect())}
            icon={busy ? <Loader2 size={14} className="animate-spin" /> : <Power size={14} />}
          >
            {running || starting ? "中斷連線" : "連線"}
          </Button>
        </div>
      </nav>

      <main className="flex min-w-0 flex-1 flex-col">
        <Banners onNavigate={setPage} />
        {needsApply && running && (
          <div className="flex items-center justify-between gap-3 border-b border-border bg-accent-soft px-6 py-2 text-[13px]">
            <span>設定已變更，重新連線後才會生效。</span>
            <Button size="sm" variant="primary" disabled={busy} onClick={connect}>
              立即套用
            </Button>
          </div>
        )}
        <div className="min-h-0 flex-1">
          {page === "dashboard" && <Dashboard onNavigate={setPage} />}
          {page === "nodes" && <Nodes />}
          {page === "groups" && <Groups />}
          {page === "connections" && <Connections />}
          {page === "logs" && <Logs />}
          {page === "settings" && <Settings />}
        </div>
      </main>

      <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-96 flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={cx(
              "pointer-events-auto flex items-start gap-2 rounded-md border px-3 py-2.5 text-[13px] shadow-lg",
              t.kind === "error" ? "border-danger/40 bg-danger-soft text-danger" : t.kind === "success" ? "border-ok/40 bg-ok-soft text-ok" : "border-border bg-surface",
            )}
          >
            <span className="selectable flex-1 break-words whitespace-pre-wrap">{t.text}</span>
            <button aria-label="關閉通知" onClick={() => dismissToast(t.id)} className="opacity-60 hover:opacity-100">
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function Banners({ onNavigate }: { onNavigate: (p: PageId) => void }) {
  const { snapshot } = useApp();
  if (!snapshot) return null;
  const items: { text: string; action?: { label: string; page: PageId } }[] = [];
  if (!snapshot.elevated) items.push({ text: "ProxyDesk 未以系統管理員身分執行，無法建立 TUN 介面卡。請關閉後以系統管理員身分重新開啟。" });
  if (!snapshot.sing_box_found) items.push({ text: "找不到 sing-box.exe，請重新安裝 ProxyDesk。" });
  const nodes = snapshot.profile.nodes;
  if (nodes.length === 0) items.push({ text: "尚未加入任何節點。", action: { label: "選擇節點", page: "nodes" } });
  else if (!snapshot.username && nodes.some((n) => !n.wireguard)) items.push({ text: "已加入 Mudfish 節點，但尚未設定 Mudfish 帳號。", action: { label: "前往設定", page: "settings" } });
  if (!items.length) return null;
  return (
    <div className="border-b border-border bg-warn-soft">
      {items.map((it) => (
        <div key={it.text} className="flex items-center gap-2 px-6 py-2 text-[13px] text-warn">
          <AlertTriangle size={14} className="shrink-0" />
          <span className="flex-1">{it.text}</span>
          {it.action && (
            <Button size="sm" onClick={() => onNavigate(it.action!.page)}>
              {it.action.label}
            </Button>
          )}
        </div>
      ))}
    </div>
  );
}

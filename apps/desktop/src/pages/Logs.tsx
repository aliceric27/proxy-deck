import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDownToLine, Copy, Search } from "lucide-react";
import { api, errorText, events, type LogBatch } from "../lib/ipc";
import { useApp } from "../lib/store";
import { Button, cx, Input, PageHeader, Segmented } from "../components/ui";

type Level = "all" | "warn" | "error";
const MAX_LINES = 3000;

function levelOf(line: string): "error" | "warn" | "info" | "debug" | "other" {
  if (/\b(ERROR|FATAL|PANIC)\b/.test(line)) return "error";
  if (/\bWARN\b/.test(line)) return "warn";
  if (/\bINFO\b/.test(line)) return "info";
  if (/\b(DEBUG|TRACE)\b/.test(line)) return "debug";
  return "other";
}

type Line = { text: string; level: ReturnType<typeof levelOf> };
const toLines = (texts: string[]): Line[] => texts.map((text) => ({ text, level: levelOf(text) }));

export default function Logs() {
  const { toast } = useApp();
  const toastRef = useRef(toast);
  toastRef.current = toast;
  const [lines, setLines] = useState<Line[]>([]);
  const [q, setQ] = useState("");
  const [level, setLevel] = useState<Level>("all");
  const [follow, setFollow] = useState(true);
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    // Subscribe before taking the snapshot; batches carry sequence numbers, so lines already
    // in the snapshot are skipped and none fall in between.
    let nextSeq: number | null = null;
    const early: LogBatch[] = [];
    const append = (b: LogBatch) => {
      if (nextSeq === null) return void early.push(b);
      const fresh = b.lines.slice(Math.max(0, nextSeq - b.first));
      nextSeq = Math.max(nextSeq, b.first + b.lines.length);
      if (fresh.length)
        setLines((prev) => {
          const next = prev.concat(toLines(fresh));
          return next.length > MAX_LINES ? next.slice(-MAX_LINES) : next;
        });
    };
    const un = events.coreLog(append);
    un.then(() => api.logs()).then((snap) => {
      if (!alive) return;
      setLines(toLines(snap.lines.slice(-MAX_LINES)));
      nextSeq = snap.first + snap.lines.length;
      early.splice(0).forEach(append);
    }, (e) => toastRef.current(errorText(e), "error"));
    return () => {
      alive = false;
      un.then((f) => f());
    };
  }, []);

  const visible = useMemo(() => {
    const ql = q.toLowerCase();
    return lines.filter(({ text, level: lv }) => {
      if (level === "error" && lv !== "error") return false;
      if (level === "warn" && lv !== "error" && lv !== "warn") return false;
      return !ql || text.toLowerCase().includes(ql);
    });
  }, [lines, q, level]);

  useEffect(() => {
    if (follow) bottom.current?.scrollIntoView({ block: "end" });
  }, [visible, follow]);

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="日誌"
        subtitle="sing-box 核心輸出（保留最近 3000 行）"
        actions={
          <Button
            icon={<Copy size={14} />}
            onClick={() => {
              navigator.clipboard.writeText(visible.map((l) => l.text).join("\n"));
              toast(`已複製 ${visible.length} 行`, "success");
            }}
          >
            複製
          </Button>
        }
      />
      <div className="flex items-center gap-2 border-b border-border px-6 py-2.5">
        <div className="relative flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-muted" />
          <Input className="w-full pl-8" placeholder="搜尋日誌…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Segmented
          value={level}
          onChange={setLevel}
          options={[
            { value: "all", label: "全部" },
            { value: "warn", label: "警告以上" },
            { value: "error", label: "錯誤" },
          ]}
        />
        <Button variant={follow ? "primary" : "secondary"} onClick={() => setFollow((f) => !f)} icon={<ArrowDownToLine size={14} />}>
          自動捲動
        </Button>
      </div>
      <div
        className="selectable min-h-0 flex-1 overflow-auto bg-surface px-6 py-2 font-mono text-xs leading-5"
        onWheel={(e) => e.deltaY < 0 && follow && setFollow(false)}
      >
        {visible.length === 0 ? (
          <p className="py-8 text-center font-sans text-muted">尚無日誌。連線後 sing-box 的輸出會顯示在這裡。</p>
        ) : (
          visible.map(({ text, level: lv }, i) => (
            <div key={i} className={cx("break-all whitespace-pre-wrap", lv === "error" && "text-danger", lv === "warn" && "text-warn", lv === "debug" && "text-muted", text.startsWith("----") && "font-semibold text-accent")}>
              {text}
            </div>
          ))
        )}
        <div ref={bottom} />
      </div>
    </div>
  );
}

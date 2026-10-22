// Hand-drawn SVG charts for the traffic statistics. One encoding across the page: blue = through a
// node, green = direct, gray = bytes the history could not attribute (see `stats.rs`). The colors
// are the `--viz-*` tokens in index.css, validated for colour-blind separation on both surfaces.
import { useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { formatBytes } from "../lib/format";
import { cx } from "./ui";

export interface Split {
  proxied: number;
  direct: number;
  other: number;
}

export const SERIES: { key: keyof Split; label: string; color: string; hint: string }[] = [
  { key: "proxied", label: "經代理", color: "var(--viz-proxy)", hint: "經過節點（Mudfish、WARP、自訂）" },
  { key: "direct", label: "直連", color: "var(--viz-direct)", hint: "不經代理，直接連線" },
  { key: "other", label: "其他", color: "var(--viz-other)", hint: "無法歸類出口的流量：取樣前就結束的短暫連線、已移除的節點等" },
];

export const splitTotal = (s: Split) => s.proxied + s.direct + s.other;

export function Legend({ className }: { className?: string }) {
  return (
    <ul className={cx("flex items-center gap-3 text-[11px] text-muted", className)} aria-label="圖例">
      {SERIES.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5" title={s.hint}>
          <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
          {s.label}
        </li>
      ))}
    </ul>
  );
}

/** One row per series with a line key, value first: the tooltip body for a split. */
export function SplitRows({ split }: { split: Split }) {
  return (
    <>
      {SERIES.filter((s) => s.key !== "other" || split.other > 0).map((s) => (
        <div key={s.key} className="flex items-center gap-2">
          <span className="h-0.5 w-3 rounded-full" style={{ background: s.color }} />
          <span className="tabular font-semibold">{formatBytes(split[s.key])}</span>
          <span className="text-muted">{s.label}</span>
        </div>
      ))}
    </>
  );
}

/** Round byte steps in the unit of the largest value (…, 200 MB, 500 MB, 1 GB, …); the last tick is ≥ `max`. */
export function byteTicks(max: number, count = 4): number[] {
  if (!(max > 0)) return [0, 1];
  let unit = 1;
  while (max / unit >= 1024 && unit < 1024 ** 4) unit *= 1024;
  const raw = max / unit / count;
  const step = ([1, 2, 5, 10, 20, 50, 100, 200, 500, 1000].find((s) => s >= raw) ?? 1000) * unit;
  return Array.from({ length: Math.ceil(max / step) + 1 }, (_, i) => i * step);
}

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth);
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, width];
}

/** A column's outline with 4px rounded corners on top and a square foot. */
function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  r = Math.max(0, Math.min(r, h, w / 2));
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

export interface Column {
  key: string;
  split: Split;
  /** Under the column; shown for as many columns as fit. */
  xLabel: string;
  tooltip: ReactNode;
  ariaLabel: string;
}

const AXIS_W = 56;
const PAD_TOP = 10;
const X_AXIS_H = 20;
const TIP_W = 228;

/**
 * Stacked columns on a byte axis, oldest left. Each column shows a tooltip on hover. The chart is
 * one tab stop: the arrow keys (Home / End) walk the columns with the same tooltip, and with
 * `onSelect` Enter or Space picks one (a listbox). Too many columns to fit scroll sideways,
 * starting at the newest end.
 */
export function StackedColumns({
  columns,
  height = 190,
  selected,
  onSelect,
  minSlot = 12,
  labelWidth = 44,
  label,
}: {
  columns: Column[];
  height?: number;
  selected?: string | null;
  onSelect?: (key: string) => void;
  minSlot?: number;
  labelWidth?: number;
  label: string;
}) {
  const [wrapRef, width] = useWidth<HTMLDivElement>();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollLeft, setScrollLeft] = useState(0);
  const [hover, setHover] = useState<number | null>(null);
  const id = useId();

  const n = columns.length;
  const plotW = Math.max(0, width - AXIS_W);
  const slot = n ? Math.max(minSlot, plotW / n) : 0;
  const innerW = Math.max(plotW, slot * n);
  const overflows = innerW > plotW + 0.5;
  const barW = Math.min(24, Math.max(2, slot * 0.6));
  const ticks = byteTicks(Math.max(0, ...columns.map((c) => splitTotal(c.split))));
  const top = ticks[ticks.length - 1];
  const plotH = height - PAD_TOP - X_AXIS_H;
  const y = (v: number) => PAD_TOP + plotH - (v / top) * plotH;
  const labelEvery = Math.max(1, Math.ceil(labelWidth / Math.max(slot, 1)));

  // Start at the newest columns; keep the user's scroll position otherwise.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollLeft = el.scrollWidth;
  }, [n, width]);

  const selectedIndex = columns.findIndex((c) => c.key === selected);
  /** Keyboard focus moved to column `i`: show it, scrolled into view. */
  const focusColumn = (i: number) => {
    const el = scrollRef.current;
    const at = Math.min(Math.max(0, i), n - 1);
    if (el) {
      if (at * slot < el.scrollLeft) el.scrollLeft = at * slot;
      else if ((at + 1) * slot > el.scrollLeft + el.clientWidth) el.scrollLeft = (at + 1) * slot - el.clientWidth;
    }
    setHover(at);
  };
  const onKeyDown = (e: KeyboardEvent) => {
    const at = hover ?? (selectedIndex >= 0 ? selectedIndex : n - 1);
    const to = { ArrowLeft: at - 1, ArrowRight: at + 1, Home: 0, End: n - 1 }[e.key];
    if (to !== undefined) {
      e.preventDefault();
      focusColumn(to);
    } else if (onSelect && hover !== null && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      onSelect(columns[hover].key);
    }
  };

  // Beside the column (right of it, or left near the right edge), inside the plot's height.
  const tipLeft = (i: number) => {
    const right = AXIS_W + (i + 1) * slot - scrollLeft + 6;
    return right + TIP_W <= width ? right : Math.max(0, AXIS_W + i * slot - scrollLeft - TIP_W - 6);
  };
  const tip = hover !== null && columns[hover] && (
    <div
      role="tooltip"
      className="pointer-events-none absolute top-0 z-10 rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-lg"
      style={{ width: TIP_W, left: tipLeft(hover) }}
    >
      {columns[hover].tooltip}
    </div>
  );

  return (
    <div ref={wrapRef} className="relative" style={{ height: height + (overflows ? 12 : 0) }}>
      {width > 0 && (
        <>
          <div className="pointer-events-none absolute top-0 left-0" style={{ width: AXIS_W, height }} aria-hidden>
            {ticks.map((t) => (
              <span key={t} className="tabular absolute right-2 -translate-y-1/2 text-[10px] text-muted" style={{ top: y(t) }}>
                {formatBytes(t)}
              </span>
            ))}
          </div>
          <div
            ref={scrollRef}
            onScroll={(e) => setScrollLeft(e.currentTarget.scrollLeft)}
            tabIndex={n ? 0 : -1}
            role={onSelect ? "listbox" : "group"}
            aria-label={label}
            aria-activedescendant={hover !== null ? `${id}-${hover}` : undefined}
            onKeyDown={onKeyDown}
            onFocus={() => hover === null && n && focusColumn(selectedIndex >= 0 ? selectedIndex : n - 1)}
            onBlur={() => setHover(null)}
            className="absolute inset-y-0 right-0 overflow-x-auto overflow-y-hidden rounded"
            style={{ left: AXIS_W }}
          >
            <svg width={innerW} height={height} className="block">
              {ticks.map((t) => (
                <line key={t} x1={0} x2={innerW} y1={Math.round(y(t)) + 0.5} y2={Math.round(y(t)) + 0.5} stroke="var(--border)" strokeWidth={1} />
              ))}
              {columns.map((c, i) => {
                const x0 = i * slot;
                const bx = x0 + (slot - barW) / 2;
                const isSel = selected === c.key;
                // Bottom to top; every segment after the first starts 2px higher (the surface gap).
                const visible = SERIES.map((s) => ({ color: s.color, h: (c.split[s.key] / top) * plotH })).filter((s) => s.h > 0);
                let base = PAD_TOP + plotH;
                const parts = visible
                  .map((s, k) => {
                    const gap = k > 0 ? 2 : 0;
                    const h = Math.max(0, s.h - gap);
                    const part = { color: s.color, y: base - gap - h, h, last: k === visible.length - 1 };
                    base -= s.h;
                    return part;
                  })
                  .filter((p) => p.h >= 0.5);
                const showLabel = (n - 1 - i) % labelEvery === 0;
                return (
                  <g
                    key={c.key}
                    id={`${id}-${i}`}
                    role={onSelect ? "option" : "img"}
                    aria-label={c.ariaLabel}
                    aria-selected={onSelect ? isSel : undefined}
                    className={cx(onSelect && "cursor-pointer")}
                    onPointerEnter={() => setHover(i)}
                    onPointerLeave={() => setHover((h) => (h === i ? null : h))}
                    onClick={() => onSelect?.(c.key)}
                  >
                    <rect
                      x={x0 + 1}
                      y={PAD_TOP - 6}
                      width={Math.max(0, slot - 2)}
                      height={plotH + 6}
                      rx={4}
                      fill={isSel ? "var(--accent-soft)" : hover === i ? "var(--surface-2)" : "transparent"}
                    />
                    {parts.map((p, k) =>
                      p.last ? (
                        <path key={k} d={topRounded(bx, p.y, barW, p.h, 4)} fill={p.color} />
                      ) : (
                        <rect key={k} x={bx} y={p.y} width={barW} height={p.h} fill={p.color} />
                      ),
                    )}
                    {showLabel && (
                      <text
                        // Labels at the ends hug the plot edge instead of being cut off by it.
                        x={x0 + slot / 2 < labelWidth / 2 ? 0 : x0 + slot / 2 > innerW - labelWidth / 2 ? innerW : x0 + slot / 2}
                        y={height - 6}
                        textAnchor={x0 + slot / 2 < labelWidth / 2 ? "start" : x0 + slot / 2 > innerW - labelWidth / 2 ? "end" : "middle"}
                        fontSize={10}
                        fill={isSel ? "var(--text)" : "var(--muted)"}
                        fontWeight={isSel ? 600 : 400}
                      >
                        {c.xLabel}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
          {tip}
        </>
      )}
    </div>
  );
}

export interface UsageRow {
  key: string;
  label: string;
  badge?: ReactNode;
  split: Split;
  upload: number;
  download: number;
}

/** Horizontal stacked bars, all on one scale (the largest row fills the track), value at the end. */
export function UsageBars({ rows, empty }: { rows: UsageRow[]; empty: string }) {
  if (!rows.length) return <p className="px-4 py-6 text-center text-xs text-muted">{empty}</p>;
  const max = Math.max(...rows.map((r) => splitTotal(r.split)), 1);
  return (
    <ul className="space-y-2.5 px-4 py-3">
      {rows.map((r) => {
        const total = splitTotal(r.split);
        const parts = SERIES.filter((s) => r.split[s.key] > 0);
        const detail = [
          ...parts.map((s) => `${s.label} ${formatBytes(r.split[s.key])}`),
          `上傳 ${formatBytes(r.upload)}`,
          `下載 ${formatBytes(r.download)}`,
        ].join(" · ");
        return (
          <li key={r.key} className="grid grid-cols-[minmax(0,38%)_1fr_auto] items-center gap-3" title={detail}>
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="truncate text-[13px]">{r.label}</span>
              {r.badge}
            </div>
            <div className="flex h-2 min-w-0 gap-[2px]" style={{ width: `${Math.max(1, (total / max) * 100)}%` }} aria-hidden>
              {parts.map((s, k) => (
                <span
                  key={s.key}
                  className={cx("h-full min-w-[2px]", k === parts.length - 1 && "rounded-r-[4px]")}
                  style={{ flexGrow: r.split[s.key], flexBasis: 0, background: s.color }}
                />
              ))}
            </div>
            <span className="tabular w-16 text-right text-xs font-medium">{formatBytes(total)}</span>
          </li>
        );
      })}
    </ul>
  );
}

/** A thin stacked bar for table cells, scaled to its own total. */
export function SplitBar({ split, className }: { split: Split; className?: string }) {
  const parts = SERIES.filter((s) => split[s.key] > 0);
  return (
    <div className={cx("flex h-1.5 gap-[2px] overflow-hidden rounded-full bg-surface-2", className)} aria-hidden>
      {parts.map((s) => (
        <span key={s.key} className="h-full min-w-[2px]" style={{ flexGrow: split[s.key], flexBasis: 0, background: s.color }} />
      ))}
    </div>
  );
}

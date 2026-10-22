const regionNames = new Intl.DisplayNames(["zh-TW"], { type: "region" });

export function countryName(cc: string): string {
  try {
    return regionNames.of(cc.toUpperCase()) ?? cc;
  } catch {
    return cc;
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(Math.max(0, Math.round(bytesPerSec)))}/s`;
}

export function formatElapsed(fromMs: number, nowMs = Date.now()): string {
  const s = Math.max(0, Math.floor((nowMs - fromMs) / 1000));
  if (s < 60) return `${s} 秒`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分 ${s % 60} 秒`;
  const h = Math.floor(m / 60);
  return `${h} 小時 ${m % 60} 分`;
}

/** Seconds as 「2 小時 5 分」, 「3 分 20 秒」, 「45 秒」. */
export function formatDuration(secs: number): string {
  return formatElapsed(0, Math.max(0, secs) * 1000);
}

const dateTime = new Intl.DateTimeFormat("zh-TW", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
const timeOnly = new Intl.DateTimeFormat("zh-TW", { hour: "2-digit", minute: "2-digit", hour12: false });
const dateOnly = new Intl.DateTimeFormat("zh-TW", { month: "numeric", day: "numeric" });

/** Unix seconds as 「10/10 14:03」. */
export const formatDateTime = (secs: number) => dateTime.format(secs * 1000);
/** Unix seconds as 「14:03」. */
export const formatTime = (secs: number) => timeOnly.format(secs * 1000);
/** Unix seconds as 「10/10」. */
export const formatDate = (secs: number) => dateOnly.format(secs * 1000);

export function latencyTone(ms: number | null | undefined): "ok" | "warn" | "danger" | "muted" {
  if (ms == null) return "muted";
  if (ms < 150) return "ok";
  if (ms < 400) return "warn";
  return "danger";
}

export function basename(path: string): string {
  return path.split(/[\\/]/).pop() ?? path;
}

export function newId(): string {
  return crypto.randomUUID();
}

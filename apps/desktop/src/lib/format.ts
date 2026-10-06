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

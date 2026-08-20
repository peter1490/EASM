/** Formatting helpers shared by every screen. */

/** "1 asset" / "2 assets" — the count is formatted, the noun agrees with it. */
export function plural(count: number | null | undefined, one: string, many?: string): string {
  const value = count ?? 0;
  return `${value.toLocaleString()} ${value === 1 ? one : (many ?? `${one}s`)}`;
}

export function num(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "—";
  return value.toLocaleString();
}

export function score(value: number | null | undefined, digits = 1): string {
  if (value == null || Number.isNaN(value)) return "—";
  return value.toFixed(digits);
}

export function pct(value: number | null | undefined, digits = 0): string {
  if (value == null || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

/**
 * Divisor paired with the unit the division produces — dividing seconds by 60
 * yields minutes, so the first entry is "m". Pairing each divisor with the unit
 * it starts from renders 5 minutes as "5s ago".
 */
const UNITS: Array<[number, string]> = [
  [60, "m"],
  [60, "h"],
  [24, "d"],
  [7, "w"],
];

/** "2h ago", "3d ago", "just now". Returns "never" for null. */
export function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  let delta = Math.max(0, (Date.now() - then) / 1000);
  if (delta < 45) return "just now";
  let unit = "s";
  for (const [step, next] of UNITS) {
    if (delta < step) break;
    delta /= step;
    unit = next;
  }
  if (unit === "d" && delta >= 4) return absolute(iso);
  return `${Math.round(delta)}${unit} ago`;
}

export function absolute(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Elapsed time between two instants, as "2m 14s". */
export function duration(from: string | null | undefined, to: string | null | undefined): string {
  if (!from) return "—";
  const start = new Date(from).getTime();
  const end = to ? new Date(to).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end)) return "—";
  const secs = Math.max(0, Math.round((end - start) / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

/** A span given directly in seconds, e.g. process uptime. */
export function elapsed(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds)) return "—";
  const total = Math.max(0, Math.floor(seconds));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function bytes(value: number | null | undefined): string {
  if (value == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = value;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Humanise a snake_case backend token for display. */
export function humanise(value: string | null | undefined): string {
  if (!value) return "—";
  return value.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

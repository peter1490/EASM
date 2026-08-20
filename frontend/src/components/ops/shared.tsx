"use client";

/**
 * Small pieces shared by the five Ops segments.
 *
 * Anything here is either (a) a vocabulary Ops owns and no other destination
 * needs — run/scan status tone, trigger labels, cron glosses — or (b) a control
 * the kit does not carry, like a range slider. Nothing here duplicates the
 * severity/risk tables in `@/lib/severity`; a scan being "failed" is not a
 * severity.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/cn";
import { humanise, dateTime } from "@/lib/format";
import { Button, Chip } from "@/components/kit";

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/**
 * `global_admin` satisfies every gate, and the role a user holds on the active
 * company counts the same as a global one.
 *
 * That is what the server does too: the auth middleware folds the active
 * company's `user_companies.role` into `UserContext.roles`, so `/api/auth/me`
 * already reports it. The company role is OR-ed in here as well because the
 * companies list and `/api/auth/me` are fetched separately, and this way the
 * two can never disagree about what the user may do.
 */
export function useOpsRoles() {
  const { user, companies, companyId } = useAuth();
  return useMemo(() => {
    const roles = user?.roles ?? [];
    const companyRole = companies.find((company) => company.id === companyId)?.role ?? null;
    const isGlobalAdmin = roles.includes("global_admin");
    const isAdmin = isGlobalAdmin || roles.includes("admin") || companyRole === "admin";
    const isOperator = isAdmin || roles.includes("operator") || companyRole === "operator";
    const isAnalyst = isOperator || roles.includes("analyst") || companyRole === "analyst";
    return { isGlobalAdmin, isAdmin, isOperator, isAnalyst };
  }, [user, companies, companyId]);
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/**
 * Repeat `run` every `ms`, but only while the tab is visible, and catch up the
 * moment it becomes visible again. Discovery *status* is not polled here — the
 * shell owns that one timer; this is for the tables each segment draws.
 */
export function usePoll(run: () => void, ms: number, enabled = true) {
  const saved = useRef(run);
  saved.current = run;

  useEffect(() => {
    if (!enabled || ms <= 0) return;
    let timer: ReturnType<typeof setTimeout>;

    const visible = () => typeof document === "undefined" || document.visibilityState === "visible";
    const tick = () => {
      if (visible()) saved.current();
      timer = setTimeout(tick, ms);
    };
    timer = setTimeout(tick, ms);

    const onVisibility = () => {
      if (visible()) saved.current();
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [ms, enabled]);
}

/**
 * A once-a-second re-render so an elapsed clock advances smoothly. It touches
 * no endpoint — the counters around it still come from the shell's poller.
 */
export function useSecondsTick(active: boolean) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => {
      if (typeof document === "undefined" || document.visibilityState === "visible") {
        setTick((value) => value + 1);
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [active]);
}

/**
 * The silent-refresh contract: the first load may show a spinner, every later
 * one must not. Returns `loading` (first load only) and a `begin` to call.
 */
export function useSilentLoad() {
  const hasLoaded = useRef(false);
  const [loading, setLoading] = useState(true);

  const begin = useCallback(() => {
    if (!hasLoaded.current) setLoading(true);
  }, []);

  const done = useCallback(() => {
    hasLoaded.current = true;
    setLoading(false);
  }, []);

  return { loading, begin, done, hasLoaded };
}

// ---------------------------------------------------------------------------
// Run / scan vocabulary
// ---------------------------------------------------------------------------

const STATUS_TONE: Record<string, { text: string; wash: string }> = {
  pending: { text: "text-ink-2", wash: "bg-nil-wash" },
  queued: { text: "text-ink-2", wash: "bg-nil-wash" },
  running: { text: "text-accent-ink", wash: "bg-accent-wash" },
  completed: { text: "text-ok", wash: "bg-ok-wash" },
  failed: { text: "text-crit", wash: "bg-crit-wash" },
  cancelled: { text: "text-ink-3", wash: "bg-nil-wash" },
};

export function StatusChip({ status }: { status: string | null | undefined }) {
  const key = (status ?? "").toLowerCase();
  return (
    <Chip tone={STATUS_TONE[key]}>
      {key === "running" && <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" aria-hidden="true" />}
      {humanise(status)}
    </Chip>
  );
}

/**
 * `trigger_type` is stored as the lowercased debug name of the enum variant —
 * `TriggerType` for a discovery run, `ScanTriggerType` for a scan — so it has
 * no underscores. In practice the backend writes `manual` or `scheduled` for a
 * run and `manual` or `discovery` for a scan; the other two variants are
 * declared but never constructed. `seed_added` / `auto` / `auto_discovery` are
 * not values this API produces.
 */
const TRIGGER_LABELS: Record<string, string> = {
  manual: "Manual",
  scheduled: "Scheduled",
  discovery: "Discovery",
  seedadded: "Seed added",
  onchange: "On change",
};

export function triggerLabel(trigger: string | null | undefined): string {
  if (!trigger) return "—";
  return TRIGGER_LABELS[trigger] ?? humanise(trigger);
}

// ---------------------------------------------------------------------------
// Time zones
// ---------------------------------------------------------------------------

/** Used when the runtime has no `Intl.supportedValuesOf`. */
const FALLBACK_TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Singapore",
  "Australia/Sydney",
];

export function browserTimeZone(): string {
  if (typeof Intl === "undefined") return "UTC";
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

export function useTimeZones() {
  const local = useMemo(() => browserTimeZone(), []);
  return useMemo(() => {
    const supported = (Intl as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone");
    const base = Array.isArray(supported) && supported.length > 0 ? supported : FALLBACK_TIMEZONES;
    const zones = base.includes(local) ? base : [local, ...base];
    return { zones, local };
  }, [local]);
}

/** A timestamp rendered in a specific zone — a schedule reads in its own time. */
export function formatInZone(iso: string | null | undefined, timeZone?: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  try {
    return date.toLocaleString(undefined, {
      timeZone,
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return dateTime(iso);
  }
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

const DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/**
 * Plain English for the handful of shapes people actually type. Anything else —
 * lists, ranges, month restrictions, the 6- and 7-field forms the backend also
 * accepts — returns null and the caller shows the raw expression. Guessing at a
 * cron expression is worse than not glossing it.
 */
export function cronGloss(cron: string): string | null {
  const fields = cron.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields;
  if (month !== "*") return null;

  const isNumber = (value: string) => /^\d{1,2}$/.test(value);
  const clock = (h: string, m: string) => `${h.padStart(2, "0")}:${m.padStart(2, "0")}`;
  const everyMinute = /^\*\/(\d{1,2})$/.exec(minute);
  const everyHour = /^\*\/(\d{1,2})$/.exec(hour);
  const anyDay = dayOfMonth === "*" && dayOfWeek === "*";

  if (minute === "*" && hour === "*" && anyDay) return "Every minute";
  if (everyMinute && hour === "*" && anyDay) return `Every ${everyMinute[1]} minutes`;
  if (isNumber(minute) && hour === "*" && anyDay) {
    return minute === "0" ? "Hourly, on the hour" : `Hourly, at ${minute} past`;
  }
  if (isNumber(minute) && everyHour && anyDay) {
    return `Every ${everyHour[1]} hours, at ${minute} past`;
  }
  if (isNumber(minute) && isNumber(hour) && anyDay) return `Daily at ${clock(hour, minute)}`;
  if (isNumber(minute) && isNumber(hour) && dayOfMonth === "*" && isNumber(dayOfWeek) && Number(dayOfWeek) <= 6) {
    return `Weekly on ${DAY_NAMES[Number(dayOfWeek)]} at ${clock(hour, minute)}`;
  }
  if (isNumber(minute) && isNumber(hour) && isNumber(dayOfMonth) && dayOfWeek === "*") {
    return `Monthly on day ${Number(dayOfMonth)} at ${clock(hour, minute)}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Controls the kit does not carry
// ---------------------------------------------------------------------------

export function Slider({
  label,
  value,
  min,
  max,
  step = 1,
  onChange,
  display,
  minHint,
  maxHint,
  disabled,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (next: number) => void;
  display?: ReactNode;
  minHint?: string;
  maxHint?: string;
  disabled?: boolean;
}) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3">
        <span className="lbl">{label}</span>
        <span className="mono text-[12px] text-ink">{display ?? value}</span>
      </div>
      <input
        type="range"
        aria-label={label}
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(Number(event.target.value))}
        className="w-full mt-2 h-1.5 rounded-full appearance-none bg-surface-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        style={{ accentColor: "var(--accent)" }}
      />
      {(minHint || maxHint) && (
        <div className="flex justify-between text-[11px] text-ink-3 mt-1">
          <span>{minHint}</span>
          <span>{maxHint}</span>
        </div>
      )}
    </div>
  );
}

export function Pagination({
  offset,
  limit,
  count,
  total,
  hasMore,
  onOffset,
}: {
  offset: number;
  limit: number;
  /** Rows on the current page. */
  count: number;
  /** Server total, when the endpoint reports one. */
  total?: number;
  hasMore: boolean;
  onOffset: (next: number) => void;
}) {
  if (offset === 0 && !hasMore) return null;
  const first = count === 0 ? 0 : offset + 1;
  const last = offset + count;
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-2.5 border-t border-rule">
      <span className="text-[11.5px] text-ink-3">
        <span className="mono">
          {first}–{last}
        </span>
        {total != null && (
          <>
            {" of "}
            <span className="mono">{total.toLocaleString()}</span>
          </>
        )}
      </span>
      <div className="flex items-center gap-2">
        <Button size="sm" disabled={offset === 0} onClick={() => onOffset(Math.max(0, offset - limit))}>
          Previous
        </Button>
        <Button size="sm" disabled={!hasMore} onClick={() => onOffset(offset + limit)}>
          Next
        </Button>
      </div>
    </div>
  );
}

/** Label/value row used inside the Ops drawers. */
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 py-1.5">
      <span className="lbl w-[112px] shrink-0">{label}</span>
      <span className="text-[12.5px] text-ink min-w-0 break-words">{children}</span>
    </div>
  );
}

/** A row of figures behind one border — the strip at the top of a segment. */
export function StatStrip({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn("grid bg-surface border border-rule rounded-lg divide-x divide-rule", className)}>{children}</div>
  );
}

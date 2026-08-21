"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Bar,
  Button,
  Card,
  CardHeader,
  Dot,
  ErrorState,
  Icon,
  LoadingBlock,
  Stat,
} from "@/components/kit";
import { getHealth, getMetrics, type SystemMetrics } from "@/app/api";
import { bytes, num, score } from "@/lib/format";
import { cn } from "@/lib/cn";
import { Note, errorMessage } from "./shared";

const POLL_MS = 10_000;

/** `/api/health` also reports per-dependency checks; the typed client only names three fields. */
type HealthCheck = { healthy?: boolean; message?: string; latency_ms?: number };
type HealthView = {
  status: string;
  version: string;
  timestamp?: string;
  checks?: Record<string, HealthCheck>;
};

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / (3600 * 24));
  const hours = Math.floor((seconds % (3600 * 24)) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

/** Load colour: green under half, amber to 80, red above. */
function loadTone(percent: number): string {
  if (percent >= 80) return "var(--crit)";
  if (percent >= 50) return "var(--med)";
  return "var(--ok)";
}

export function StatusPane() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<HealthView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [metricsError, setMetricsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const hasLoadedRef = useRef(false);

  const load = useCallback(async (silent: boolean) => {
    if (silent) setRefreshing(true);
    else if (!hasLoadedRef.current) setLoading(true);

    // Metrics are company-scoped and 403 for a user with no company yet; health
    // is not. Settle them independently so one failure never blanks the page.
    const [healthResult, metricsResult] = await Promise.allSettled([getHealth(), getMetrics()]);

    if (healthResult.status === "fulfilled") {
      setHealth(healthResult.value as HealthView);
      setError(null);
    } else {
      setHealth(null);
      setError(errorMessage(healthResult.reason));
    }

    if (metricsResult.status === "fulfilled") {
      setMetrics(metricsResult.value);
      setMetricsError(null);
    } else {
      setMetricsError(errorMessage(metricsResult.reason));
    }

    hasLoadedRef.current = true;
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    // The first load. It sets state synchronously only on the silent path,
    // which the interval below takes, not this call.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load(false);
    const iv = setInterval(() => load(true), POLL_MS);
    return () => clearInterval(iv);
  }, [load]);

  if (loading && !health && !metrics) return <LoadingBlock label="Reading system status" />;

  const memoryPercent =
    metrics && metrics.memory_usage.total_bytes > 0
      ? (metrics.memory_usage.used_bytes / metrics.memory_usage.total_bytes) * 100
      : 0;
  const cpuPercent = metrics?.cpu_usage_percent ?? 0;
  const healthy = health ? health.status === "healthy" || health.status === "ok" : false;
  const checks = Object.entries(health?.checks ?? {});

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} onRetry={() => load(false)} />}

      <Card>
        <CardHeader
          title="Service"
          hint={health ? `version ${health.version}` : undefined}
          actions={
            <Button size="sm" icon="refresh" onClick={() => load(true)} loading={refreshing}>
              Refresh
            </Button>
          }
        />
        <div className="grid grid-cols-2 sm:grid-cols-4">
          <Stat
            label="API"
            value={
              <span className="inline-flex items-center gap-2">
                <Dot color={healthy ? "var(--ok)" : "var(--crit)"} className="w-2 h-2" />
                <span className="text-[20px]">{health ? health.status.toUpperCase() : "UNREACHABLE"}</span>
              </span>
            }
            footnote={<span className="text-ink-3">Backend health endpoint</span>}
          />
          <Stat
            className="border-l border-rule"
            label="Uptime"
            value={<span className="text-[20px]">{metrics ? formatUptime(metrics.uptime_seconds) : "—"}</span>}
            footnote={<span className="text-ink-3">Since last restart</span>}
          />
          <Stat
            className="border-l border-rule"
            label="CPU"
            value={<span className="text-[20px]">{metrics ? `${score(cpuPercent)}%` : "—"}</span>}
            footnote={<Bar value={cpuPercent / 100} color={loadTone(cpuPercent)} className="mt-1.5" />}
          />
          <Stat
            className="border-l border-rule"
            label="Memory"
            value={<span className="text-[20px]">{metrics ? `${score(memoryPercent)}%` : "—"}</span>}
            footnote={
              <>
                <Bar value={memoryPercent / 100} color={loadTone(memoryPercent)} className="mt-1.5" />
                <span className="text-ink-3 block mt-1">
                  {metrics
                    ? `${bytes(metrics.memory_usage.used_bytes)} of ${bytes(metrics.memory_usage.total_bytes)}`
                    : "—"}
                </span>
              </>
            }
          />
        </div>
      </Card>

      {metricsError && (
        <Note>
          Runtime metrics are unavailable: {metricsError}. They are scoped to a company, so they stay empty until you
          belong to one.
        </Note>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Application" hint="This company's totals" />
          <div className="p-1.5">
            {[
              { label: "Assets", value: num(metrics?.total_assets), icon: "globe" as const },
              { label: "Findings", value: num(metrics?.total_findings), icon: "alert" as const },
              { label: "Active scans", value: num(metrics?.active_scans), icon: "activity" as const },
              {
                label: "Requests / sec",
                value: metrics ? score(metrics.requests_per_second, 2) : "—",
                icon: "arrowUp" as const,
              },
            ].map((row) => (
              <div
                key={row.label}
                className="flex items-center justify-between gap-3 px-2.5 py-2 rounded-md hover:bg-surface-2"
              >
                <span className="flex items-center gap-2.5 text-[12.5px] text-ink-2">
                  <Icon name={row.icon} size={13} className="text-ink-3" />
                  {row.label}
                </span>
                <span className="fig text-[15px]">{row.value}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader title="Dependency checks" hint="Reported by /api/health" />
          <div className="p-1.5">
            {checks.length === 0 ? (
              <div className="px-2.5 py-2 text-[12px] text-ink-3">
                {health
                  ? "The API reports no individual dependency checks."
                  : "No checks — the API did not answer."}
              </div>
            ) : (
              checks.map(([name, check]) => {
                const ok = check?.healthy !== false;
                return (
                  <div
                    key={name}
                    className="flex items-center justify-between gap-3 px-2.5 py-2 rounded-md hover:bg-surface-2"
                  >
                    <span className="flex items-center gap-2.5 min-w-0">
                      <Dot color={ok ? "var(--ok)" : "var(--crit)"} />
                      <span className="text-[12.5px] capitalize truncate">{name.replace(/_/g, " ")}</span>
                    </span>
                    <span className="flex items-center gap-2 shrink-0">
                      {typeof check?.latency_ms === "number" && (
                        <span className="mono text-[11px] text-ink-3">{score(check.latency_ms)} ms</span>
                      )}
                      <span
                        className={cn(
                          "text-[10px] font-semibold uppercase tracking-[0.06em] px-1.5 h-[19px] inline-flex items-center rounded",
                          ok ? "bg-ok-wash text-ok" : "bg-crit-wash text-crit",
                        )}
                      >
                        {ok ? "healthy" : "down"}
                      </span>
                    </span>
                  </div>
                );
              })
            )}
            {health?.timestamp && (
              <div className="px-2.5 pt-2 pb-1 text-[11px] text-ink-3">
                Checked {new Date(health.timestamp).toLocaleTimeString()} · refreshes every 10s
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

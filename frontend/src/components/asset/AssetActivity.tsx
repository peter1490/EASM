"use client";

import Link from "next/link";
import { useMemo } from "react";
import { Chip, EmptyState, Icon, RiskChip, SeverityChip, type IconName } from "@/components/kit";
import { TrendChart, TrendLegend, type TrendPoint } from "@/components/charts/TrendChart";
import { cn } from "@/lib/cn";
import { ago, dateTime, duration, humanise, score as fmtScore } from "@/lib/format";
import { SEVERITY_ORDER, riskTone } from "@/lib/severity";
import type {
  AssetRiskHistoryEntry,
  AssetScanHistoryEntry,
  ScanListItem,
  SecurityFinding,
} from "@/app/api";
import { Section } from "./shared";

/**
 * Everything that has happened to this asset, on one timeline.
 *
 * Scans and risk recalculations used to live on two separate tabs, which made
 * the obvious question — "the score jumped, what ran just before it?" — a
 * matter of comparing two tables by timestamp. They are the same story, so they
 * are now one list, newest first.
 */

type ScanEvent = {
  kind: "scan";
  key: string;
  at: string;
  id: string;
  scanType: string;
  status: string;
  startedAt: string | null;
  completedAt: string | null;
  note: string | null;
  bySeverity: Record<string, number>;
  total: number;
};

type RiskEvent = {
  kind: "risk";
  key: string;
  at: string;
  scoreValue: number;
  level: string;
  delta: number | null;
};

type TimelineEvent = ScanEvent | RiskEvent;

const SCAN_STATUS_TONE: Record<string, { text: string; wash: string }> = {
  completed: { text: "text-ok", wash: "bg-ok-wash" },
  running: { text: "text-accent-ink", wash: "bg-accent-wash" },
  pending: { text: "text-ink-2", wash: "bg-nil-wash" },
  failed: { text: "text-crit", wash: "bg-crit-wash" },
  cancelled: { text: "text-ink-3", wash: "bg-nil-wash" },
};

const SCAN_STATUS_ICON: Record<string, IconName> = {
  completed: "check",
  running: "refresh",
  pending: "clock",
  failed: "alert",
  cancelled: "ban",
};

function severityCounts(summary: Record<string, unknown> | null | undefined): Record<string, number> {
  const raw = summary?.["findings_by_severity"];
  if (!raw || typeof raw !== "object") return {};
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const count = Number(value);
    if (Number.isFinite(count) && count > 0) out[key.toLowerCase()] = count;
  }
  return out;
}

export function AssetActivity({
  scans,
  scanHistory,
  riskHistory,
  findings,
}: {
  scans: ScanListItem[];
  scanHistory: AssetScanHistoryEntry[];
  riskHistory: AssetRiskHistoryEntry[];
  findings: SecurityFinding[];
}) {
  /** Risk history newest first, so a row's delta is against the row below it. */
  const orderedRisk = useMemo(
    () =>
      [...riskHistory].sort(
        (a, b) => new Date(b.calculated_at).getTime() - new Date(a.calculated_at).getTime(),
      ),
    [riskHistory],
  );

  /**
   * Active findings at each recalculation, so the trend line has a second
   * series: a finding counts if it had been seen and had not yet been closed.
   */
  const series = useMemo<TrendPoint[]>(() => {
    if (orderedRisk.length === 0) return [];
    const windows = findings.map((finding) => ({
      firstSeen: new Date(finding.first_seen_at).getTime(),
      resolvedAt: finding.resolved_at ? new Date(finding.resolved_at).getTime() : null,
      status: finding.status,
    }));

    return [...orderedRisk]
      .reverse()
      .map((entry) => {
        const at = new Date(entry.calculated_at).getTime();
        const active = windows.reduce((count, finding) => {
          if (finding.firstSeen > at) return count;
          if (finding.resolvedAt && finding.resolvedAt <= at) return count;
          if (finding.status === "resolved" || finding.status === "false_positive") return count;
          return count + 1;
        }, 0);
        return { timestamp: entry.calculated_at, risk_score: entry.risk_score, active_findings: active };
      });
  }, [orderedRisk, findings]);

  const events = useMemo<TimelineEvent[]>(() => {
    // The scan queue and the evolution endpoint both describe scans; merge them
    // by id so a scan appears once, with whichever summary is richer.
    const merged = new Map<string, ScanEvent>();

    const put = (
      id: string,
      at: string,
      scanType: string,
      status: string,
      startedAt: string | null,
      completedAt: string | null,
      note: string | null,
      summary: Record<string, unknown> | null | undefined,
    ) => {
      const bySeverity = severityCounts(summary);
      const total = Object.values(bySeverity).reduce((sum, value) => sum + value, 0);
      const existing = merged.get(id);
      if (existing && existing.total >= total) return;
      merged.set(id, {
        kind: "scan",
        key: `scan:${id}`,
        at,
        id,
        scanType,
        status,
        startedAt,
        completedAt,
        note,
        bySeverity,
        total,
      });
    };

    scans.forEach((scan) =>
      put(
        scan.id,
        scan.completed_at ?? scan.started_at ?? scan.created_at,
        scan.scan_type,
        scan.status,
        scan.started_at,
        scan.completed_at,
        scan.note,
        scan.result_summary,
      ),
    );
    scanHistory.forEach((scan) =>
      put(
        scan.id,
        scan.completed_at ?? scan.started_at ?? scan.created_at,
        scan.scan_type,
        scan.status,
        scan.started_at,
        scan.completed_at,
        null,
        scan.result_summary,
      ),
    );

    const riskEvents: RiskEvent[] = orderedRisk.map((entry, index) => {
      const previous = orderedRisk[index + 1];
      return {
        kind: "risk",
        key: `risk:${entry.calculated_at}:${index}`,
        at: entry.calculated_at,
        scoreValue: entry.risk_score,
        level: entry.risk_level,
        delta: previous ? entry.risk_score - previous.risk_score : null,
      };
    });

    return [...merged.values(), ...riskEvents].sort(
      (a, b) => new Date(b.at).getTime() - new Date(a.at).getTime(),
    );
  }, [scans, scanHistory, orderedRisk]);

  return (
    <div className="flex flex-col gap-4">
      <Section title="Risk trend" hint="Score and active findings over time" actions={<TrendLegend />}>
        <TrendChart data={series} height={168} />
      </Section>

      <Section title="Activity" hint={events.length > 0 ? `${events.length} events` : undefined}>
        {events.length === 0 ? (
          <EmptyState
            icon="activity"
            title="Nothing has happened yet"
            description="Scans and risk recalculations for this asset appear here, newest first."
          />
        ) : (
          <ol className="flex flex-col">
            {events.map((event, index) => (
              <li key={event.key} className="flex gap-3">
                {/* Rail: dot plus the connector down to the next event. */}
                <div className="flex flex-col items-center shrink-0 w-4">
                  <span
                    className={cn(
                      "grid place-items-center w-4 h-4 rounded-full mt-[7px] shrink-0",
                      event.kind === "risk" ? "bg-accent-wash text-accent-ink" : "bg-surface-2 text-ink-2",
                    )}
                  >
                    <Icon
                      name={event.kind === "risk" ? "chart" : (SCAN_STATUS_ICON[event.status] ?? "play")}
                      size={9}
                      strokeWidth={1.8}
                    />
                  </span>
                  {index < events.length - 1 && <span className="flex-1 w-px bg-rule my-1" aria-hidden="true" />}
                </div>

                <div className="flex-1 min-w-0 pb-4">
                  {event.kind === "scan" ? (
                    <ScanRow event={event} />
                  ) : (
                    <RiskRow event={event} />
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
      </Section>
    </div>
  );
}

function EventTime({ at }: { at: string }) {
  return (
    <time className="text-[11.5px] text-ink-3 shrink-0" dateTime={at} title={dateTime(at)}>
      {ago(at)}
    </time>
  );
}

function ScanRow({ event }: { event: ScanEvent }) {
  const tone = SCAN_STATUS_TONE[event.status] ?? SCAN_STATUS_TONE.pending;
  const severities = SEVERITY_ORDER.filter((severity) => (event.bySeverity[severity] ?? 0) > 0);

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-baseline gap-2 flex-wrap">
        <span className="text-[12.5px] font-medium text-ink">{humanise(event.scanType)} scan</span>
        <Chip tone={tone} className="h-[19px] text-[10px] uppercase tracking-[0.06em] font-semibold">
          {humanise(event.status)}
        </Chip>
        <EventTime at={event.at} />
        {event.startedAt && event.completedAt && (
          <span className="mono text-[11px] text-ink-3">{duration(event.startedAt, event.completedAt)}</span>
        )}
      </div>

      <div className="flex items-center gap-1.5 flex-wrap">
        {severities.length > 0 ? (
          severities.map((severity) => (
            <SeverityChip key={severity} severity={severity} short count={event.bySeverity[severity]} />
          ))
        ) : event.status === "completed" ? (
          <span className="text-[12px] text-ink-3">No findings</span>
        ) : null}
        <Link
          href={`/findings?scan=${event.id}`}
          className="inline-flex items-center gap-1 text-[12px] font-medium text-accent-ink hover:underline"
        >
          Findings from this scan
          <Icon name="arrowRight" size={11} />
        </Link>
      </div>

      {event.note && <p className="text-[12px] text-ink-3 truncate">{event.note}</p>}
    </div>
  );
}

function RiskRow({ event }: { event: RiskEvent }) {
  const tone = riskTone(event.level);
  return (
    <div className="flex items-baseline gap-2 flex-wrap">
      <span className="text-[12.5px] font-medium text-ink">Risk recalculated</span>
      <span className="mono text-[12.5px] font-medium" style={{ color: tone.dot }}>
        {fmtScore(event.scoreValue)}
      </span>
      <RiskChip level={event.level} />
      {event.delta != null && event.delta !== 0 && (
        <span className={cn("mono text-[11.5px] font-medium", event.delta > 0 ? "text-crit" : "text-ok")}>
          {event.delta > 0 ? "+" : ""}
          {fmtScore(event.delta)}
        </span>
      )}
      <EventTime at={event.at} />
    </div>
  );
}

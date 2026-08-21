"use client";

import { useId, useMemo, useState } from "react";
import { cn } from "@/lib/cn";
import { score as fmtScore } from "@/lib/format";
import { RISK_SCORE_MAX } from "@/lib/severity";

export interface TrendPoint {
  timestamp: string;
  risk_score: number | null;
  active_findings: number;
}

/**
 * Portfolio risk and open findings on one dual-axis chart.
 *
 * Replaces RiskFindingsEvolutionChart, which drew the same series but lived on
 * its own route (/company-overview) that nothing linked to except the sidebar.
 */
export function TrendChart({
  data,
  height = 176,
  className,
}: {
  data: TrendPoint[];
  height?: number;
  className?: string;
}) {
  const gradientId = useId();
  const [hover, setHover] = useState<number | null>(null);

  const geometry = useMemo(() => {
    const points = data.filter((d) => d.risk_score != null || d.active_findings != null);
    if (points.length < 2) return null;

    const pad = { left: 36, right: 36, top: 10, bottom: 26 };
    const width = 1000; // viewBox units; the svg scales to its container
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const risks = points.map((p) => p.risk_score).filter((v): v is number => v != null);
    const finds = points.map((p) => p.active_findings ?? 0);

    // Pad the domains so the lines never touch the frame. Risk runs 0–1000, so the
    // axis steps in fifties rather than tens.
    const riskMin = Math.max(0, Math.floor((Math.min(...risks, 0) - 25) / 50) * 50);
    const riskMax = Math.min(
      RISK_SCORE_MAX,
      Math.ceil((Math.max(...risks, 100) + 25) / 50) * 50,
    );
    const findMin = Math.max(0, Math.floor((Math.min(...finds) - 2) / 5) * 5);
    const findMax = Math.max(findMin + 5, Math.ceil((Math.max(...finds) + 2) / 5) * 5);

    const x = (i: number) => pad.left + (i / (points.length - 1)) * plotW;
    const yRisk = (v: number) => pad.top + plotH - ((v - riskMin) / (riskMax - riskMin || 1)) * plotH;
    const yFind = (v: number) => pad.top + plotH - ((v - findMin) / (findMax - findMin || 1)) * plotH;

    let riskPath = "";
    let started = false;
    points.forEach((p, i) => {
      if (p.risk_score == null) return;
      riskPath += `${started ? "L" : "M"}${x(i).toFixed(1)} ${yRisk(p.risk_score).toFixed(1)}`;
      started = true;
    });

    const findPath = points
      .map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${yFind(p.active_findings ?? 0).toFixed(1)}`)
      .join("");

    const firstRiskIndex = points.findIndex((p) => p.risk_score != null);
    const areaPath =
      riskPath && firstRiskIndex >= 0
        ? `${riskPath}L${x(points.length - 1).toFixed(1)} ${(pad.top + plotH).toFixed(1)}L${x(firstRiskIndex).toFixed(1)} ${(pad.top + plotH).toFixed(1)}Z`
        : "";

    const ticks = [0, Math.floor((points.length - 1) / 2), points.length - 1].map((i) => ({
      x: x(i),
      label: new Date(points[i].timestamp).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    }));

    return {
      points, width, pad, plotH, x, yRisk, yFind,
      riskPath, findPath, areaPath,
      riskMin, riskMax, findMin, findMax, ticks,
    };
  }, [data, height]);

  if (!geometry) {
    return (
      <div className={cn("grid place-items-center text-[12.5px] text-ink-3", className)} style={{ height }}>
        Not enough history yet — trends appear once two days of scans have run.
      </div>
    );
  }

  const { points, width, pad, plotH, x, yRisk, yFind, riskPath, findPath, areaPath, riskMin, riskMax, findMin, findMax, ticks } =
    geometry;
  const active = hover != null ? points[hover] : null;

  return (
    <div className={cn("relative", className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        role="img"
        aria-label="Risk score and active findings over time"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const ratio = (event.clientX - rect.left) / rect.width;
          const svgX = ratio * width;
          const index = Math.round(((svgX - pad.left) / (width - pad.left - pad.right)) * (points.length - 1));
          setHover(Math.max(0, Math.min(points.length - 1, index)));
        }}
      >
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.16" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0, 0.5, 1].map((f) => {
          const y = pad.top + f * plotH;
          return <line key={f} x1={pad.left} y1={y} x2={width - pad.right} y2={y} stroke="var(--rule)" strokeWidth={1} vectorEffect="non-scaling-stroke" />;
        })}

        {areaPath && <path d={areaPath} fill={`url(#${gradientId})`} />}
        <path d={findPath} stroke="var(--ink-3)" strokeWidth={1.5} strokeDasharray="4 3" fill="none" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        {riskPath && <path d={riskPath} stroke="var(--accent)" strokeWidth={2} fill="none" vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />}

        {hover != null && (
          <line x1={x(hover)} y1={pad.top} x2={x(hover)} y2={pad.top + plotH} stroke="var(--rule-2)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
        )}
        {active?.risk_score != null && (
          <circle cx={x(hover!)} cy={yRisk(active.risk_score)} r={3.5} fill="var(--accent)" stroke="var(--surface)" strokeWidth={2} />
        )}
        {active && (
          <circle cx={x(hover!)} cy={yFind(active.active_findings ?? 0)} r={3} fill="var(--ink-3)" stroke="var(--surface)" strokeWidth={2} />
        )}
      </svg>

      {/* Axis labels sit outside the SVG so they never stretch with preserveAspectRatio="none". */}
      <div className="absolute inset-0 pointer-events-none">
        <span className="mono absolute text-[9.5px] text-ink-3" style={{ left: 0, top: 4 }}>{riskMax}</span>
        <span className="mono absolute text-[9.5px] text-ink-3" style={{ left: 0, top: height - 36 }}>{riskMin}</span>
        <span className="mono absolute text-[9.5px] text-ink-3" style={{ right: 0, top: 4 }}>{findMax}</span>
        <span className="mono absolute text-[9.5px] text-ink-3" style={{ right: 0, top: height - 36 }}>{findMin}</span>
      </div>

      <div className="flex justify-between text-[10.5px] text-ink-3 mt-1" style={{ paddingLeft: 36, paddingRight: 36 }}>
        {ticks.map((tick, i) => (
          <span key={i}>{tick.label}</span>
        ))}
      </div>

      {active && (
        <div className="absolute top-0 left-1/2 -translate-x-1/2 flex items-center gap-3 px-2.5 py-1 rounded-md border border-rule bg-surface text-[11.5px] shadow-sm pointer-events-none">
          <span className="text-ink-3">
            {new Date(active.timestamp).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-0.5 bg-accent rounded-sm" />
            risk <span className="mono font-medium">{fmtScore(active.risk_score)}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 border-t-2 border-dashed border-ink-3" />
            findings <span className="mono font-medium">{active.active_findings}</span>
          </span>
        </div>
      )}
    </div>
  );
}

export function TrendLegend() {
  return (
    <div className="flex items-center gap-3.5 text-[11.5px] text-ink-2">
      <span className="flex items-center gap-1.5">
        <span className="w-3.5 h-0.5 bg-accent rounded-sm" />
        Risk score
      </span>
      <span className="flex items-center gap-1.5">
        <span className="w-3.5 border-t-2 border-dashed border-ink-3" />
        Active findings
      </span>
    </div>
  );
}

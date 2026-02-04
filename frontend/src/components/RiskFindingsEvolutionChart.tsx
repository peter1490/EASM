"use client";

import { useId, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import EmptyState from "@/components/ui/EmptyState";

export type EvolutionPoint = {
  timestamp: string;
  risk_score: number | null;
  active_findings: number | null;
};

interface RiskFindingsEvolutionChartProps {
  title: string;
  description?: string;
  data: EvolutionPoint[];
  emptyState?: {
    title: string;
    description?: string;
    icon?: string;
  };
}

const DEFAULT_EMPTY_STATE = {
  title: "No evolution data",
  description: "Run scans and risk calculations to populate the timeline.",
  icon: "chart",
};

const getRiskLevelFromScore = (score: number | null) => {
  if (score === null || Number.isNaN(score)) return "unknown";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "info";
};

const getRiskBadgeClasses = (score: number | null) => {
  const level = getRiskLevelFromScore(score);
  switch (level) {
    case "critical":
      return "border-rose-500/30 bg-rose-500/15 text-rose-500";
    case "high":
      return "border-orange-500/30 bg-orange-500/15 text-orange-500";
    case "medium":
      return "border-amber-500/30 bg-amber-500/15 text-amber-500";
    case "low":
      return "border-emerald-500/30 bg-emerald-500/15 text-emerald-600";
    case "info":
      return "border-teal-500/30 bg-teal-500/15 text-teal-600";
    default:
      return "border-muted bg-muted text-muted-foreground";
  }
};

const getRiskStrokeColor = (score: number | null) => {
  const level = getRiskLevelFromScore(score);
  switch (level) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#f59e0b";
    case "low":
      return "#10b981";
    case "info":
      return "#14b8a6";
    default:
      return "#94a3b8";
  }
};

const formatDateLabel = (value: number) => {
  const date = new Date(value);
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
};

export default function RiskFindingsEvolutionChart({
  title,
  description,
  data,
  emptyState = DEFAULT_EMPTY_STATE,
}: RiskFindingsEvolutionChartProps) {
  const chartId = useId();

  const {
    points,
    minTime,
    maxTime,
    maxRisk,
    maxFindings,
    latestRisk,
    latestFindings,
  } = useMemo(() => {
    const sorted = [...data]
      .filter((entry) => entry.timestamp)
      .sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      );

    if (sorted.length === 0) {
      return {
        points: [] as Array<{ time: number; risk: number | null; findings: number | null }>,
        minTime: 0,
        maxTime: 0,
        maxRisk: 100,
        maxFindings: 1,
        latestRisk: null as number | null,
        latestFindings: null as number | null,
      };
    }

    const mapped = sorted.map((entry) => ({
      time: new Date(entry.timestamp).getTime(),
      risk: typeof entry.risk_score === "number" ? entry.risk_score : null,
      findings: typeof entry.active_findings === "number" ? entry.active_findings : null,
    }));

    const times = mapped.map((entry) => entry.time);
    const riskValues = mapped
      .map((entry) => entry.risk)
      .filter((value): value is number => typeof value === "number");
    const findingsValues = mapped
      .map((entry) => entry.findings)
      .filter((value): value is number => typeof value === "number");

    const last = mapped[mapped.length - 1];

    return {
      points: mapped,
      minTime: Math.min(...times),
      maxTime: Math.max(...times),
      maxRisk: Math.max(100, ...(riskValues.length > 0 ? riskValues : [0])),
      maxFindings: Math.max(1, ...(findingsValues.length > 0 ? findingsValues : [0])),
      latestRisk: last?.risk ?? null,
      latestFindings: last?.findings ?? null,
    };
  }, [data]);

  const hasData = points.length > 0;

  const width = 1000;
  const height = 320;
  const padding = {
    left: 70,
    right: 70,
    top: 30,
    bottom: 50,
  };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const buildPath = (
    series: Array<number | null>,
    scaleY: (value: number) => number,
  ) => {
    let path = "";
    let started = false;

    series.forEach((value, index) => {
      if (value === null || Number.isNaN(value)) {
        started = false;
        return;
      }
      const time = points[index]?.time ?? 0;
      const x = padding.left + ((time - minTime) / (maxTime - minTime || 1)) * plotWidth;
      const y = scaleY(value);

      if (!started) {
        path += `M${x},${y}`;
        started = true;
      } else {
        path += ` L${x},${y}`;
      }
    });

    return path;
  };

  const riskSeries = points.map((point) => point.risk);
  const findingsSeries = points.map((point) => point.findings ?? 0);

  const riskScale = (value: number) =>
    padding.top + (1 - value / (maxRisk || 1)) * plotHeight;

  const findingsScale = (value: number) =>
    padding.top + (1 - value / (maxFindings || 1)) * plotHeight;

  const riskPath = buildPath(riskSeries, riskScale);
  const findingsPath = buildPath(findingsSeries, findingsScale);
  const hasRiskSeries = riskSeries.filter((value) => value !== null).length > 1;

  const tickCount = 4;
  const xTicks = Array.from({ length: tickCount }, (_, index) => {
    const ratio = index / (tickCount - 1);
    return minTime + ratio * (maxTime - minTime || 1);
  });

  const yTicks = [0, Math.round(maxRisk / 2), Math.round(maxRisk)];
  const findingsTicks = [0, Math.round(maxFindings / 2), Math.round(maxFindings)];

  return (
    <Card className="overflow-hidden border-border/60 bg-gradient-to-br from-card via-card to-primary/5 shadow-[0_24px_60px_-40px_rgba(14,165,233,0.6)]">
      <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <CardTitle>{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1 ${getRiskBadgeClasses(latestRisk)}`}>
            <span className="h-2 w-2 rounded-full bg-current shadow-[0_0_10px_rgba(244,63,94,0.6)]" />
            <span className="font-semibold">Risk</span>
            <span className="font-mono">{latestRisk !== null ? latestRisk.toFixed(1) : "NA"}</span>
            {latestRisk !== null && (
              <span className="uppercase tracking-wide text-[10px]">{getRiskLevelFromScore(latestRisk)}</span>
            )}
          </div>
          <div className="flex items-center gap-2 rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1 text-amber-500">
            <span className="h-2 w-2 rounded-full bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.7)]" />
            <span className="font-semibold">Active Findings</span>
            <span className="font-mono">{latestFindings !== null ? latestFindings : "NA"}</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {!hasData ? (
          <EmptyState
            icon={emptyState.icon}
            title={emptyState.title}
            description={emptyState.description}
          />
        ) : (
          <div className="relative h-80 w-full overflow-hidden rounded-2xl border border-border/60 bg-gradient-to-br from-background/80 via-background to-primary/10">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.18),_transparent_60%)]" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_bottom,_rgba(99,102,241,0.18),_transparent_55%)]" />
            <svg viewBox={`0 0 ${width} ${height}`} className="relative h-full w-full">
              <defs>
                <linearGradient id={`${chartId}-risk`} x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor={getRiskStrokeColor(latestRisk)} stopOpacity="0.95" />
                  <stop offset="100%" stopColor={getRiskStrokeColor(latestRisk)} stopOpacity="0.75" />
                </linearGradient>
                <linearGradient id={`${chartId}-risk-fill`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={getRiskStrokeColor(latestRisk)} stopOpacity="0.2" />
                  <stop offset="100%" stopColor={getRiskStrokeColor(latestRisk)} stopOpacity="0" />
                </linearGradient>
                <linearGradient id={`${chartId}-findings`} x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#f97316" stopOpacity="0.75" />
                </linearGradient>
                <filter id={`${chartId}-glow`} x="-30%" y="-30%" width="160%" height="160%">
                  <feGaussianBlur stdDeviation="6" result="coloredBlur" />
                  <feMerge>
                    <feMergeNode in="coloredBlur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Grid */}
              <g opacity="0.25">
                {yTicks.map((tick) => {
                  const y = riskScale(tick);
                  return (
                    <line
                      key={`grid-risk-${tick}`}
                      x1={padding.left}
                      x2={width - padding.right}
                      y1={y}
                      y2={y}
                      stroke="#cbd5f5"
                      strokeDasharray="4 6"
                    />
                  );
                })}
              </g>

              {/* Axes */}
              <line
                x1={padding.left}
                x2={padding.left}
                y1={padding.top}
                y2={height - padding.bottom}
                stroke="#94a3b8"
                strokeOpacity="0.5"
              />
              <line
                x1={width - padding.right}
                x2={width - padding.right}
                y1={padding.top}
                y2={height - padding.bottom}
                stroke="#94a3b8"
                strokeOpacity="0.5"
              />
              <line
                x1={padding.left}
                x2={width - padding.right}
                y1={height - padding.bottom}
                y2={height - padding.bottom}
                stroke="#94a3b8"
                strokeOpacity="0.5"
              />

              <text
                x={padding.left - 50}
                y={padding.top + plotHeight / 2}
                transform={`rotate(-90 ${padding.left - 50} ${padding.top + plotHeight / 2})`}
                fontSize="11"
                fill="#64748b"
                textAnchor="middle"
              >
                Risk Score
              </text>
              <text
                x={width - padding.right + 50}
                y={padding.top + plotHeight / 2}
                transform={`rotate(90 ${width - padding.right + 50} ${padding.top + plotHeight / 2})`}
                fontSize="11"
                fill="#64748b"
                textAnchor="middle"
              >
                Active Findings
              </text>

              {/* Risk area */}
              {riskPath && hasRiskSeries && (
                <path
                  d={`${riskPath} L${width - padding.right},${height - padding.bottom} L${padding.left},${height - padding.bottom} Z`}
                  fill={`url(#${chartId}-risk-fill)`}
                />
              )}

              {/* Lines */}
              {riskPath && (
                <path
                  d={riskPath}
                  fill="none"
                  stroke={`url(#${chartId}-risk)`}
                  strokeWidth="3"
                  filter={`url(#${chartId}-glow)`}
                />
              )}
              {findingsPath && (
                <path
                  d={findingsPath}
                  fill="none"
                  stroke={`url(#${chartId}-findings)`}
                  strokeWidth="2.5"
                  strokeDasharray="6 6"
                />
              )}

              {/* Axis labels */}
              {yTicks.map((tick) => (
                <text
                  key={`risk-label-${tick}`}
                  x={padding.left - 12}
                  y={riskScale(tick) + 4}
                  textAnchor="end"
                  fontSize="11"
                  fill="#64748b"
                >
                  {tick}
                </text>
              ))}
              {findingsTicks.map((tick) => (
                <text
                  key={`findings-label-${tick}`}
                  x={width - padding.right + 12}
                  y={findingsScale(tick) + 4}
                  textAnchor="start"
                  fontSize="11"
                  fill="#64748b"
                >
                  {tick}
                </text>
              ))}

              {/* X axis labels */}
              {xTicks.map((tick, index) => {
                const x =
                  padding.left +
                  ((tick - minTime) / (maxTime - minTime || 1)) * plotWidth;
                return (
                  <text
                    key={`x-label-${index}`}
                    x={x}
                    y={height - padding.bottom + 28}
                    textAnchor="middle"
                    fontSize="11"
                    fill="#64748b"
                  >
                    {formatDateLabel(tick)}
                  </text>
                );
              })}
            </svg>
            <div className="pointer-events-none absolute inset-x-0 bottom-0 flex items-center justify-between px-8 py-4 text-xs text-muted-foreground">
              <span className="font-semibold text-emerald-600">Low = Good</span>
              <span className="font-semibold text-rose-500">High = Bad</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

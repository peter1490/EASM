"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  getCompanyEvolution,
  getHealth,
  getHighRiskAssets,
  getMetrics,
  getRiskOverview,
  listScans,
  listSecurityFindings,
  type Asset,
  type CompanyEvolutionResponse,
  type RiskOverview,
  type ScanListItem,
  type SecurityFinding,
  type SystemMetrics,
} from "@/app/api";
import {
  Card, CardHeader, Bar, StackedBar, Dot, Icon, PageHeader,
  RiskChip, SeverityChip, Segmented, Table, TBody, TD, TH, THead, TR,
  EmptyState, ErrorState, LoadingBlock, assetIcon,
} from "@/components/kit";
import { TrendChart, TrendLegend } from "@/components/charts/TrendChart";
import { useDiscovery, runProgress } from "@/hooks/useDiscovery";
import { OPEN_STATUSES, riskTone, severityTone, SEVERITY_ORDER, RISK_ORDER } from "@/lib/severity";
import { ago, elapsed, num, pct, plural, score } from "@/lib/format";
import { useAuth } from "@/context/AuthContext";

const RANGES = [
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
] as const;

const TYPE_ORDER = ["domain", "ip", "port", "certificate", "organization", "asn"] as const;
const TYPE_SHADES: Record<string, string> = {
  domain: "var(--accent)",
  ip: "oklch(0.62 0.10 264)",
  port: "oklch(0.70 0.07 264)",
  certificate: "oklch(0.78 0.05 264)",
  organization: "oklch(0.84 0.03 264)",
  asn: "oklch(0.88 0.02 264)",
};

export default function OverviewPage() {
  const { user } = useAuth();
  const { status: discovery } = useDiscovery();

  const [range, setRange] = useState<string>("30");
  const [tab, setTab] = useState<"findings" | "assets">("findings");

  const [overview, setOverview] = useState<RiskOverview | null>(null);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<{ status: string; version: string } | null>(null);
  const [evolution, setEvolution] = useState<CompanyEvolutionResponse | null>(null);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Background refreshes must not throw the screen back to a spinner.
  const hasLoaded = useRef(false);

  const load = useCallback(async () => {
    try {
      const [overviewData, metricsData, healthData, evolutionData, findingData, assetData, scanData] =
        await Promise.all([
          getRiskOverview(),
          getMetrics(),
          getHealth(),
          getCompanyEvolution(Number(range)),
          listSecurityFindings({
            severity: ["critical", "high"],
            status: OPEN_STATUSES,
            sort_by: "severity",
            sort_dir: "desc",
            limit: 8,
          }),
          getHighRiskAssets(8),
          listScans({ limit: 6 }),
        ]);
      setOverview(overviewData);
      setMetrics(metricsData);
      setHealth(healthData);
      setEvolution(evolutionData);
      setFindings(findingData.findings ?? []);
      setAssets(assetData ?? []);
      setScans(scanData.scans ?? []);
      setError(null);
    } catch (err) {
      // The old dashboard set this and never rendered it, so an API failure
      // showed a page of confident zeros.
      setError((err as Error).message);
    } finally {
      hasLoaded.current = true;
      setLoading(false);
    }
  }, [range]);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 30_000);
    return () => clearInterval(id);
  }, [load]);

  if (loading && !hasLoaded.current) {
    return (
      <div className="h-full grid place-items-center">
        <LoadingBlock label="Loading your attack surface" />
      </div>
    );
  }

  const severities = overview?.findings_by_severity ?? {};
  const openFindings = Object.values(severities).reduce((sum, n) => sum + n, 0);
  const criticalHigh = (severities.critical ?? 0) + (severities.high ?? 0);
  const byLevel = overview?.assets_by_level ?? {};
  const byType = overview?.assets_by_type ?? {};
  const totalAssets = overview?.total_assets ?? metrics?.total_assets ?? 0;
  const progress = runProgress(discovery);

  return (
    <div className="h-full overflow-y-auto">
      <div className="px-6 py-5 flex flex-col gap-4 max-w-[1680px] mx-auto">
        <PageHeader
          title="Overview"
          hint={
            discovery?.running
              ? `Discovery running · ${discovery.seeds_processed} of ${discovery.seeds_total ?? "?"} seeds · ${discovery.assets_discovered} new assets`
              : `${plural(totalAssets, "asset")} tracked${user?.email ? ` · signed in as ${user.email}` : ""}`
          }
          actions={
            <Segmented
              options={RANGES.map((r) => ({ value: r.value, label: r.label }))}
              value={range}
              onChange={setRange}
              ariaLabel="Time range"
            />
          }
        />

        {error && <ErrorState error={error} onRetry={() => void load()} />}

        {/* Exposure — four figures behind one border, not four cards. */}
        <Card className="flex items-stretch divide-x divide-rule">
          <ExposureStat label="Assets tracked" value={num(totalAssets)} note={
            <span className="text-ink-3">
  <span className="mono">{num(overview?.assets_never_scanned ?? 0)}</span> never scanned
            </span>
          } />
          <ExposureStat label="Open findings" value={num(openFindings)} note={
            <span className="text-ink-3">across every asset and scan</span>
          } />
          <ExposureStat
            label="Critical & high"
            value={num(criticalHigh)}
            tone={criticalHigh > 0 ? "var(--crit)" : undefined}
            note={
              <Link href="/findings?severity=critical,high" className="font-medium">
                Review now
              </Link>
            }
          />
          <ExposureStat
            label="Portfolio risk"
            value={score(overview?.average_risk_score)}
            tone={riskToneColour(overview?.average_risk_score)}
            note={
              <span className="text-ink-3">
                <span className="mono">{num(overview?.assets_pending_calculation ?? 0)}</span> awaiting calculation
              </span>
            }
          />
        </Card>

        <div className="flex gap-4 items-stretch max-xl:flex-col">
          <Card className="flex-1 min-w-0 flex flex-col">
            <CardHeader
              title="Risk and findings trend"
              hint={`last ${range} days`}
              actions={<TrendLegend />}
            />
            <div className="px-4 pt-3 pb-4">
              <TrendChart data={evolution?.series ?? []} />
            </div>
          </Card>

          <Card className="w-[400px] shrink-0 max-xl:w-full p-4 flex flex-col gap-3">
            <h2 className="text-sm font-semibold tracking-[-0.012em]">Composition</h2>

            <Breakdown
              label="By asset type"
              total={num(totalAssets)}
              segments={TYPE_ORDER.filter((t) => (byType[t] ?? 0) > 0).map((t) => ({
                value: byType[t] ?? 0,
                color: TYPE_SHADES[t],
                label: t,
              }))}
            />

            <div className="h-px bg-rule" />

            <Breakdown
              label="By risk level"
              total={`avg ${score(overview?.average_risk_score)}`}
              segments={RISK_ORDER.filter((l) => (byLevel[l] ?? 0) > 0).map((l) => ({
                value: byLevel[l] ?? 0,
                color: riskTone(l).dot,
                label: l,
              }))}
            />

            {/* `never` is the display token Surface prints, not the value it
                parses — as a query param it matched no filter at all. */}
            <Link
              href="/surface?scan=never_scanned"
              className="mt-auto flex items-center justify-between h-[30px] px-2.5 rounded-md bg-surface-2 text-[12.5px] font-medium no-underline hover:bg-accent-wash"
            >
              <span>{plural(overview?.assets_never_scanned, "asset has", "assets have")} never been scanned</span>
              <Icon name="arrowRight" size={13} />
            </Link>
          </Card>
        </div>

        <div className="flex gap-4 items-start max-xl:flex-col">
          <Card className="flex-1 min-w-0 overflow-hidden">
            <CardHeader
              title="Needs attention"
              actions={
                <div className="flex items-center gap-3">
                  <Segmented
                    options={[
                      { value: "findings", label: "Findings", badge: findings.length },
                      { value: "assets", label: "Assets", badge: assets.length },
                    ]}
                    value={tab}
                    onChange={(next) => setTab(next as "findings" | "assets")}
                  />
                  <Link
                    href={tab === "findings" ? "/findings" : "/surface"}
                    className="text-[12.5px] font-medium flex items-center gap-1.5"
                  >
                    View all <Icon name="arrowRight" size={12} />
                  </Link>
                </div>
              }
            />
            {tab === "findings" ? <FindingQueue findings={findings} /> : <AssetQueue assets={assets} />}
          </Card>

          <Card className="w-[400px] shrink-0 max-xl:w-full overflow-hidden">
            <div className="px-4 py-3.5 border-b border-rule">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Dot color={discovery?.running ? "var(--accent)" : "var(--ink-3)"} />
                  <h2 className="text-sm font-semibold tracking-[-0.012em]">
                    {discovery?.running ? "Discovery running" : "Discovery idle"}
                  </h2>
                </div>
                <Link href="/ops" className="text-[11.5px] font-medium">
                  Ops
                </Link>
              </div>
              {discovery?.running ? (
                <>
                  <p className="text-[12px] text-ink-2 mt-1.5">
                    {discovery.current_phase || "Starting"} · started {ago(discovery.started_at)}
                  </p>
                  <Bar value={progress ?? 0} className="mt-2.5" />
                  <div className="flex gap-5 mt-2.5">
                    <MiniStat value={`${discovery.seeds_processed}/${discovery.seeds_total ?? "?"}`} label="seeds" />
                    <MiniStat value={num(discovery.assets_discovered)} label="new" tone="var(--ok)" />
                    <MiniStat value={num(discovery.scans_queued ?? discovery.queue_pending ?? 0)} label="queued" />
                    <MiniStat
                      value={num(discovery.error_count)}
                      label="errors"
                      tone={discovery.error_count > 0 ? "var(--high)" : undefined}
                    />
                  </div>
                </>
              ) : (
                <p className="text-[12px] text-ink-2 mt-1.5">
                  Last completed run {ago(discovery?.completed_at)}.
                </p>
              )}
            </div>

            <div className="px-4 pt-3 pb-2 flex items-center justify-between">
              <span className="lbl">Recent scans</span>
              <Link href="/ops?tab=scans" className="text-[11.5px] font-medium">
                Scan queue
              </Link>
            </div>
            <div className="px-2 pb-2">
              {scans.length === 0 ? (
                <p className="px-2 py-6 text-center text-[12.5px] text-ink-3">No scans yet.</p>
              ) : (
                scans.map((scan) => (
                  <Link
                    key={scan.id}
                    href={`/findings?scan=${scan.id}`}
                    className="flex items-center gap-2.5 h-[38px] px-2 rounded-md no-underline text-ink hover:bg-surface-2"
                  >
                    <Dot color={scanTone(scan.status)} />
                    <span className="mono text-[12px] flex-1 truncate">{scan.asset_value ?? scan.asset_id.slice(0, 8)}</span>
                    <span className="text-[10.5px] text-ink-3">{scan.scan_type.replace(/_/g, " ")}</span>
                    <span className="text-[11.5px] text-ink-3 w-[52px] text-right">{ago(scan.created_at)}</span>
                  </Link>
                ))
              )}
            </div>
          </Card>
        </div>

        {/* System — one line, not a grid of cards. */}
        <div className="flex items-center gap-5 h-[34px] px-4 rounded-lg border border-rule bg-surface-2 text-[11.5px] flex-wrap">
          <span className="flex items-center gap-1.5 font-medium">
            <Dot color={health?.status === "healthy" ? "var(--ok)" : "var(--high)"} />
            {health?.status === "healthy" ? "All systems operational" : "System degraded"}
          </span>
          <span className="text-ink-2">
            CPU <span className="mono text-ink">{score(metrics?.cpu_usage_percent)}%</span>
          </span>
          <span className="text-ink-2">
            Memory{" "}
            <span className="mono text-ink">
              {metrics ? pct(metrics.memory_usage.used_bytes / metrics.memory_usage.total_bytes) : "—"}
            </span>
          </span>
          <span className="text-ink-2">
            Throughput <span className="mono text-ink">{score(metrics?.requests_per_second, 1)}/s</span>
          </span>
          <span className="text-ink-2">
            Uptime <span className="mono text-ink">{elapsed(metrics?.uptime_seconds)}</span>
          </span>
          <span className="text-ink-2">
            Active scans <span className="mono text-ink">{num(metrics?.active_scans)}</span>
          </span>
          <Link href="/settings?pane=system" className="ml-auto font-medium">
            System details
          </Link>
        </div>
      </div>
    </div>
  );
}

function riskToneColour(value: number | null | undefined): string | undefined {
  if (value == null) return undefined;
  if (value >= 85) return "var(--crit)";
  if (value >= 65) return "var(--high)";
  if (value >= 40) return "var(--med)";
  return undefined;
}

function scanTone(status: string): string {
  if (status === "failed") return "var(--crit)";
  if (status === "running") return "var(--accent)";
  if (status === "pending") return "var(--ink-3)";
  return "var(--ok)";
}

function ExposureStat({
  label,
  value,
  tone,
  note,
}: {
  label: string;
  value: string;
  tone?: string;
  note?: React.ReactNode;
}) {
  return (
    <div className="flex-1 px-[18px] py-3.5 min-w-0">
      <div className="lbl">{label}</div>
      <div className="fig text-[30px] mt-1 leading-none" style={tone ? { color: tone } : undefined}>
        {value}
      </div>
      <div className="text-[11.5px] mt-1.5 truncate">{note}</div>
    </div>
  );
}

function MiniStat({ value, label, tone }: { value: string; label: string; tone?: string }) {
  return (
    <div>
      <div className="fig text-[15px]" style={tone ? { color: tone } : undefined}>
        {value}
      </div>
      <div className="lbl text-[9px]">{label}</div>
    </div>
  );
}

function Breakdown({
  label,
  total,
  segments,
}: {
  label: string;
  total: string;
  segments: Array<{ value: number; color: string; label: string }>;
}) {
  return (
    <div>
      <div className="flex justify-between items-baseline mb-1.5">
        <span className="lbl">{label}</span>
        <span className="mono text-[10.5px] text-ink-3">{total}</span>
      </div>
      {segments.length === 0 ? (
        <p className="text-[12px] text-ink-3">Nothing recorded yet.</p>
      ) : (
        <>
          <StackedBar segments={segments} />
          <div className="flex flex-wrap gap-x-3.5 gap-y-1 mt-2 text-[11.5px] text-ink-2">
            {segments.map((segment) => (
              <span key={segment.label} className="flex items-center gap-1.5">
                <Dot color={segment.color} />
                <span className="capitalize">{segment.label}</span>
                <span className="mono text-ink">{num(segment.value)}</span>
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function FindingQueue({ findings }: { findings: SecurityFinding[] }) {
  if (findings.length === 0) {
    return (
      <EmptyState
        icon="shieldCheck"
        title="Nothing critical or high is open"
        description="New findings appear here as scans complete."
      />
    );
  }
  return (
    <Table>
      <THead>
        <TR>
          <TH className="w-[74px]">Severity</TH>
          <TH>Finding</TH>
          <TH className="w-[170px]">Asset</TH>
          <TH className="w-[62px]">CVSS</TH>
          <TH className="w-[66px]">Age</TH>
        </TR>
      </THead>
      <TBody>
        {findings.map((finding) => (
          <TR key={finding.id} interactive>
            <TD>
              <Link href={`/findings?finding=${finding.id}`} className="no-underline">
                <SeverityChip severity={finding.severity} short />
              </Link>
            </TD>
            <TD>
              <Link href={`/findings?finding=${finding.id}`} className="font-medium text-ink no-underline hover:text-accent">
                {finding.title}
              </Link>
            </TD>
            <TD className="mono text-[12px] text-ink-2">
              <Link href={`/surface/${finding.asset_id}`} className="no-underline text-inherit hover:text-accent">
                {finding.asset_value ?? finding.asset_id.slice(0, 8)}
              </Link>
            </TD>
            <TD className="mono font-medium" style={{ color: severityTone(finding.severity).dot }}>
              {score(finding.cvss_score)}
            </TD>
            <TD className="text-[12px] text-ink-3">{ago(finding.first_seen_at)}</TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

function AssetQueue({ assets }: { assets: Asset[] }) {
  if (assets.length === 0) {
    return (
      <EmptyState
        icon="globe"
        title="No risk scores yet"
        description="Run a discovery and a scan, then recalculate risk to populate this queue."
      />
    );
  }
  return (
    <Table>
      <THead>
        <TR>
          <TH>Asset</TH>
          <TH className="w-[96px]">Type</TH>
          <TH className="w-[160px]">Risk</TH>
          <TH className="w-[150px]">Open findings</TH>
          <TH className="w-[104px]">Confidence</TH>
          <TH className="w-[110px]">Last scan</TH>
        </TR>
      </THead>
      <TBody>
        {assets.map((asset) => {
          const tone = riskTone(asset.risk_level);
          return (
            <TR key={asset.id} interactive>
              <TD>
                <Link href={`/surface/${asset.id}`} className="flex items-center gap-2 no-underline text-ink hover:text-accent">
                  <Icon name={assetIcon(asset.asset_type)} size={14} className="text-ink-3" />
                  <span className="mono text-[12.5px] font-medium">{asset.value}</span>
                </Link>
              </TD>
              <TD className="text-[12px] text-ink-2 capitalize">{asset.asset_type}</TD>
              <TD>
                <div className="flex items-center gap-2">
                  <span className="mono font-medium w-[34px]" style={{ color: tone.dot }}>
                    {score(asset.risk_score)}
                  </span>
                  <Bar value={(asset.risk_score ?? 0) / 100} color={tone.dot} className="w-[56px]" />
                  <RiskChip level={asset.risk_level} />
                </div>
              </TD>
              <TD>
                <div className="flex items-center gap-1">
                  {asset.open_findings && asset.open_findings.total > 0 ? (
                    SEVERITY_ORDER.filter((s) => (asset.open_findings?.[s] ?? 0) > 0)
                      .slice(0, 2)
                      .map((s) => (
                        <SeverityChip key={s} severity={s} short count={asset.open_findings?.[s]} />
                      ))
                  ) : (
                    <span className="text-[12px] text-ink-3">none</span>
                  )}
                </div>
              </TD>
              <TD className="mono text-[12px] text-ink-2">{asset.ownership_confidence.toFixed(2)}</TD>
              <TD className="text-[12px] text-ink-3">{ago(asset.last_scanned_at)}</TD>
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}

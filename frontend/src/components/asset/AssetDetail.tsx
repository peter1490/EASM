"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  getAsset,
  getAssetEvolution,
  getAssetFindings,
  getAssetPdfReport,
  getAssetTags,
  listScans,
  listTags,
  recalculateAssetRisk,
  tagAsset,
  triggerAssetScan,
  untagAsset,
  updateAssetComment,
  updateAssetImportance,
  checkBlacklist,
  type Asset,
  type AssetEvolutionResponse,
  type AssetTagDetail,
  type BlacklistCheckResult,
  type ScanListItem,
  type SecurityFinding,
  type SecurityScanType,
  type TagWithCount,
} from "@/app/api";
import {
  Bar,
  Button,
  Chip,
  Dot,
  EmptyState,
  ErrorState,
  Icon,
  LoadingBlock,
  RiskChip,
  SeverityChip,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Tabs,
  assetIcon,
  type SegmentOption,
  type IconName,
} from "@/components/kit";
import { cn } from "@/lib/cn";
import { uniq } from "@/lib/list";
import { ago, dateTime, humanise, num, pct } from "@/lib/format";
import {
  SEVERITY_ORDER,
  findingStatus,
  isOpen,
  RISK_SCORE_MAX,
  formatRiskScore,
  riskFraction,
  riskLevelFromScore,
  riskTone,
  severityFromCvss,
  severityTone,
} from "@/lib/severity";
import { AssetActivity } from "./AssetActivity";
import { AssetDiscoveryGraph } from "./AssetDiscoveryGraph";
import { BlacklistPanel } from "./BlacklistPanel";
import { CommentEditor } from "./CommentEditor";
import { ImportancePicker } from "./ImportancePicker";
import { RawMetadata } from "./RawMetadata";
import { TagsPanel } from "./TagsPanel";
import { TechPortsPanel } from "./TechPortsPanel";
import {
  KV,
  Notice,
  Section,
  confidenceColor,
  toBlacklistObjectType,
  useCanWrite,
} from "./shared";

/**
 * THE asset detail. One component, two placements: inside the inventory's
 * drawer, and full width on `/surface/[id]`. `variant` moves blocks around; it
 * never changes which blocks exist, because the old split — a shallow modal
 * that could not edit anything and a five-tab page that could — is exactly the
 * thing this redesign removes.
 */

type TabKey = "overview" | "findings" | "activity";

const REFRESH_MS = 10_000;

/**
 * The scan types a user can start from an asset.
 *
 * A full scan is the default and does everything. The three focused options
 * exist because each is useful on its own cadence: a DNS audit touches only the
 * resolver and can run against every domain daily, while a full scan opens
 * hundreds of connections to the host.
 */
const SCAN_TYPES: { value: SecurityScanType; label: string; hint: string; icon: IconName }[] = [
  {
    value: "full",
    label: "Full scan",
    hint: "Ports, services, TLS, DNS, HTTP and threat intel",
    icon: "play",
  },
  {
    value: "tls_analysis",
    label: "SSL/TLS scan",
    hint: "Protocols, cipher suites, certificate chain and a graded result",
    icon: "certificate",
  },
  {
    value: "dns_audit",
    label: "DNS audit",
    hint: "Records, DNSSEC, SPF/DKIM/DMARC, zone transfer and takeover",
    icon: "globe",
  },
  {
    value: "http_probe",
    label: "HTTP scan",
    hint: "Security headers, cookies, CORS, methods and exposed files",
    icon: "link",
  },
  {
    value: "port_scan",
    label: "Port scan",
    hint: "Open ports and service detection only",
    icon: "port",
  },
];

/**
 * Run-scan control: the default action on click, with the focused scan types
 * behind a disclosure. A single "Run scan" button hid the fact that a targeted
 * scan is possible at all.
 */
function ScanMenu({
  onRun,
  running,
  disabled,
  size,
}: {
  onRun: (scanType: SecurityScanType) => void;
  running: SecurityScanType | null;
  disabled: boolean;
  size: "sm" | "md";
}) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);

  // Close on an outside click or Escape, so the menu never strands the page.
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div className="relative flex items-center" ref={container}>
      <Button
        variant="primary"
        icon="play"
        onClick={() => onRun("full")}
        loading={running === "full"}
        disabled={disabled}
        size={size}
        className="rounded-r-none"
      >
        Run scan
      </Button>
      <Button
        variant="primary"
        icon="chevronDown"
        onClick={() => setOpen((current) => !current)}
        disabled={disabled}
        size={size}
        aria-label="Choose a scan type"
        aria-expanded={open}
        className="rounded-l-none border-l border-black/15 px-2"
      />
      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 w-[286px] rounded-lg border border-rule bg-surface shadow-lg overflow-hidden">
          {SCAN_TYPES.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => {
                setOpen(false);
                onRun(option.value);
              }}
              disabled={running !== null}
              className="flex w-full items-start gap-2.5 px-3 py-2.5 text-left hover:bg-surface-2 disabled:opacity-50"
            >
              <Icon name={option.icon} size={13} className="text-ink-3 mt-0.5 shrink-0" />
              <span className="min-w-0">
                <span className="block text-[12.5px] font-medium">{option.label}</span>
                <span className="block text-[11.5px] text-ink-3">{option.hint}</span>
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** Provenance keys the discovery pipeline writes, in the order they read best. */
const PROVENANCE_KEYS: Array<{ key: string; label: string }> = [
  { key: "parent_domain", label: "Parent domain" },
  { key: "resolved_from", label: "Resolved from" },
  { key: "reverse_resolved_from", label: "Reverse resolved from" },
  { key: "seed_domain", label: "Seed domain" },
  { key: "pivot", label: "Pivot" },
  { key: "organization", label: "Organization" },
  { key: "asn", label: "ASN" },
  { key: "cidr", label: "CIDR" },
  { key: "issuer", label: "Certificate issuer" },
  { key: "common_name", label: "Common name" },
  { key: "certificate_subject", label: "Certificate subject" },
  { key: "not_after", label: "Certificate expires" },
  { key: "discovery_depth", label: "Discovery depth" },
];

export interface AssetDetailProps {
  assetId: string;
  variant?: "drawer" | "page";
  /** Row data from the list, so the drawer paints before the fetch lands. */
  initialAsset?: Asset | null;
  /** Fires whenever the asset changes, so a list can patch its row optimistically. */
  onAssetChange?: (asset: Asset) => void;
  /** Fires after a successful blacklist, so a list can drop deleted descendants. */
  onBlacklisted?: () => void;
  /** Extra buttons for the action bar — the drawer passes "Open full page". */
  extraActions?: ReactNode;
}

export function AssetDetail({
  assetId,
  variant = "page",
  initialAsset = null,
  onAssetChange,
  onBlacklisted,
  extraActions,
}: AssetDetailProps) {
  const router = useRouter();
  const canWrite = useCanWrite();

  const [asset, setAsset] = useState<Asset | null>(initialAsset);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [evolution, setEvolution] = useState<AssetEvolutionResponse | null>(null);
  const [tags, setTags] = useState<AssetTagDetail[]>([]);
  const [allTags, setAllTags] = useState<TagWithCount[]>([]);
  const [blacklist, setBlacklist] = useState<BlacklistCheckResult | null>(null);

  const [loading, setLoading] = useState(!initialAsset);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tab, setTab] = useState<TabKey>("overview");

  const [scanning, setScanning] = useState<SecurityScanType | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [recalculating, setRecalculating] = useState(false);
  const [savingImportance, setSavingImportance] = useState(false);
  const [taggingBusy, setTaggingBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const changeRef = useRef(onAssetChange);
  changeRef.current = onAssetChange;

  /** Adopt a server copy of the asset and let the list patch its row with it. */
  const applyAsset = useCallback((next: Asset) => {
    setAsset(next);
    changeRef.current?.(next);
  }, []);

  const load = useCallback(
    async (manual = false) => {
      if (manual) setRefreshing(true);
      try {
        const [assetData, findingsData, scansData, evolutionData, assetTags, tagCatalogue] = await Promise.all([
          getAsset(assetId),
          getAssetFindings(assetId).catch(() => [] as SecurityFinding[]),
          listScans({ asset_id: assetId, limit: 50 }).catch(() => null),
          getAssetEvolution(assetId, 50).catch(() => null),
          getAssetTags(assetId).catch(() => [] as AssetTagDetail[]),
          listTags(100, 0).catch(() => ({ tags: [] as TagWithCount[], total_count: 0, limit: 0, offset: 0 })),
        ]);

        const objectType = toBlacklistObjectType(assetData.asset_type);
        const blacklistState = objectType
          ? await checkBlacklist(objectType, assetData.value).catch(() => null)
          : null;

        applyAsset(assetData);
        setFindings(findingsData);
        setScans(scansData?.scans ?? []);
        setEvolution(evolutionData);
        setTags(assetTags);
        setAllTags(tagCatalogue.tags);
        setBlacklist(blacklistState);
        setLoadError(null);
      } catch (err) {
        setLoadError((err as Error).message);
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [assetId, applyAsset],
  );

  // Silent refresh: the first pass may show a spinner, every later pass simply
  // swaps the data underneath — no flash, no lost scroll position, and the
  // comment editor keeps whatever is being typed.
  useEffect(() => {
    setLoading(!initialAsset);
    void load();
    const timer = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(timer);
    // `initialAsset` intentionally excluded: it seeds first paint only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  const guard = async (run: () => Promise<void>) => {
    setActionError(null);
    try {
      await run();
    } catch (err) {
      setActionError((err as Error).message);
    }
  };

  const runScan = (scanType: SecurityScanType = "full") =>
    guard(async () => {
      if (!asset) return;
      setScanning(scanType);
      try {
        const scan = await triggerAssetScan(
          asset.id,
          scanType,
          `${SCAN_TYPES.find((option) => option.value === scanType)?.label ?? "Scan"} from asset ${asset.value}`,
        );
        setNotice(`${humanise(scan.scan_type)} scan queued. It runs in the background.`);
        void load();
      } finally {
        setScanning(null);
      }
    });

  const downloadReport = () =>
    guard(async () => {
      if (!asset) return;
      setDownloading(true);
      try {
        const { blob, filename } = await getAssetPdfReport(asset.id);
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        // Revoke on the next frame; revoking synchronously races the download
        // in Safari and lands as a silently empty file.
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setNotice(`Downloaded ${filename}`);
      } finally {
        setDownloading(false);
      }
    });

  const recalculate = () =>
    guard(async () => {
      if (!asset) return;
      setRecalculating(true);
      try {
        applyAsset(await recalculateAssetRisk(asset.id));
      } finally {
        setRecalculating(false);
      }
    });

  const setImportance = (level: number) =>
    guard(async () => {
      if (!asset || level === asset.importance) return;
      setSavingImportance(true);
      // Optimistic: the shields move now, the server copy lands a moment later.
      setAsset({ ...asset, importance: level });
      try {
        applyAsset(await updateAssetImportance(asset.id, level));
      } catch (err) {
        setAsset(asset);
        throw err;
      } finally {
        setSavingImportance(false);
      }
    });

  const saveComment = async (next: string | null) => {
    if (!asset) return;
    setActionError(null);
    try {
      applyAsset(await updateAssetComment(asset.id, next));
    } catch (err) {
      setActionError((err as Error).message);
      throw err;
    }
  };

  const applyTag = (tagId: string) =>
    guard(async () => {
      if (!asset) return;
      setTaggingBusy(true);
      try {
        await tagAsset(asset.id, tagId);
        setTags(await getAssetTags(asset.id));
      } finally {
        setTaggingBusy(false);
      }
    });

  const removeTag = (tagId: string) =>
    guard(async () => {
      if (!asset) return;
      setTaggingBusy(true);
      try {
        await untagAsset(asset.id, tagId);
        setTags(await getAssetTags(asset.id));
      } finally {
        setTaggingBusy(false);
      }
    });

  const openFindings = useMemo(() => findings.filter((finding) => isOpen(finding.status)), [findings]);

  const openBySeverity = useMemo(() => {
    const counts: Record<string, number> = {};
    openFindings.forEach((finding) => {
      const severity = finding.severity?.toLowerCase() ?? severityFromCvss(finding.cvss_score) ?? "info";
      counts[severity] = (counts[severity] ?? 0) + 1;
    });
    return counts;
  }, [openFindings]);

  /** Triage order: still-active first, then severity, then CVSS. */
  const triaged = useMemo(() => {
    const rank = (finding: SecurityFinding) => {
      const severity = finding.severity?.toLowerCase() ?? severityFromCvss(finding.cvss_score) ?? "info";
      const index = SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
      return index === -1 ? SEVERITY_ORDER.length : index;
    };
    return [...findings].sort((a, b) => {
      const activeDelta = Number(isOpen(b.status)) - Number(isOpen(a.status));
      if (activeDelta !== 0) return activeDelta;
      const severityDelta = rank(a) - rank(b);
      if (severityDelta !== 0) return severityDelta;
      return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
    });
  }, [findings]);

  if (loading && !asset) return <LoadingBlock label="Loading asset" />;

  if (!asset) {
    return (
      <div className="flex flex-col gap-3">
        <ErrorState error={loadError ?? "This asset could not be loaded."} onRetry={() => void load(true)} />
        <div>
          <Button icon="arrowRight" onClick={() => router.push("/surface")}>
            Back to Surface
          </Button>
        </div>
      </div>
    );
  }

  const level = asset.risk_level ?? riskLevelFromScore(asset.risk_score);
  const tone = riskTone(level);
  const page = variant === "page";

  const tabs: Array<SegmentOption<TabKey>> = [
    { value: "overview", label: "Overview" },
    { value: "findings", label: "Findings", badge: openFindings.length > 0 ? openFindings.length : undefined },
    { value: "activity", label: "Activity" },
  ];

  // ---------------------------------------------------------------- overview

  const headline = (
    <div className="grid grid-cols-1 sm:grid-cols-3 bg-surface border border-rule rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-rule">
      <div className="px-4 py-3.5">
        <div className="flex items-center justify-between gap-2">
          <span className="lbl">Risk score</span>
          <button
            type="button"
            onClick={recalculate}
            disabled={recalculating || !canWrite}
            className="inline-flex items-center gap-1 text-[11.5px] font-medium text-ink-3 hover:text-accent-ink disabled:opacity-50"
          >
            <Icon name="refresh" size={11} className={cn(recalculating && "animate-spin")} />
            {recalculating ? "Recalculating" : "Recalculate"}
          </button>
        </div>
        <div className="flex items-baseline gap-2 mt-1">
          <span className="fig text-[30px] leading-none" style={{ color: tone.dot }}>
            {formatRiskScore(asset.risk_score)}
          </span>
          <span className="mono text-[12px] text-ink-3">/ {RISK_SCORE_MAX}</span>
          {level && <RiskChip level={level} />}
        </div>
        <Bar value={riskFraction(asset.risk_score)} color={tone.dot} className="mt-2.5" />
        <div className="text-[11.5px] text-ink-3 mt-1.5">
          {asset.last_risk_run ? `Calculated ${ago(asset.last_risk_run)}` : "Never calculated"}
        </div>
      </div>

      <div className="px-4 py-3.5">
        <span className="lbl">Ownership confidence</span>
        <div className="fig text-[30px] leading-none mt-1" style={{ color: confidenceColor(asset.ownership_confidence) }}>
          {pct(asset.ownership_confidence)}
        </div>
        <Bar
          value={asset.ownership_confidence}
          color={confidenceColor(asset.ownership_confidence)}
          className="mt-2.5"
        />
        <div className="text-[11.5px] text-ink-3 mt-1.5">
          {asset.sources.length} {asset.sources.length === 1 ? "source" : "sources"} agree
        </div>
      </div>

      <div className="px-4 py-3.5">
        <span className="lbl">Open findings</span>
        <div
          className="fig text-[30px] leading-none mt-1"
          style={{ color: openFindings.length > 0 ? "var(--ink)" : "var(--ok)" }}
        >
          {num(openFindings.length)}
        </div>
        <div className="flex flex-wrap gap-1 mt-2.5 min-h-[19px]">
          {SEVERITY_ORDER.filter((severity) => (openBySeverity[severity] ?? 0) > 0).map((severity) => (
            <SeverityChip key={severity} severity={severity} short count={openBySeverity[severity]} />
          ))}
          {openFindings.length === 0 && <span className="text-[11.5px] text-ink-3">Nothing open</span>}
        </div>
        <button
          type="button"
          onClick={() => setTab("findings")}
          className="text-[11.5px] font-medium text-accent-ink hover:underline mt-1.5"
        >
          {findings.length} total for this asset
        </button>
      </div>
    </div>
  );

  const provenance = PROVENANCE_KEYS.filter((entry) => {
    const value = asset.metadata?.[entry.key];
    return value != null && value !== "";
  });

  const information = (
    <Section title="Asset information">
      <div className="grid grid-cols-2 gap-x-4 gap-y-3.5">
        <KV label="Type">
          <span className="inline-flex items-center gap-1.5">
            <Icon name={assetIcon(asset.asset_type)} size={12} className="text-ink-3" />
            {humanise(asset.asset_type)}
          </span>
        </KV>
        <KV label="Status">
          <span className="inline-flex items-center gap-1.5">
            <Dot color={asset.status === "active" ? "var(--ok)" : "var(--nil)"} />
            {humanise(asset.status)}
          </span>
        </KV>
        <KV label="First seen">{asset.first_seen_at ? dateTime(asset.first_seen_at) : "—"}</KV>
        <KV label="Last seen">{asset.last_seen_at ? dateTime(asset.last_seen_at) : "—"}</KV>
        <KV label="Discovered">{dateTime(asset.created_at)}</KV>
        <KV label="Last updated">{dateTime(asset.updated_at)}</KV>
        {provenance.map((entry) => (
          <KV key={entry.key} label={entry.label}>
            <span className="mono text-[11.5px]">{String(asset.metadata[entry.key])}</span>
          </KV>
        ))}
      </div>

      <div className="mt-4 pt-3.5 border-t border-rule">
        <div className="lbl mb-1.5">Discovery sources</div>
        <div className="flex flex-wrap gap-1.5">
          {asset.sources.length === 0 ? (
            <span className="text-[12.5px] text-ink-3">None recorded</span>
          ) : (
            uniq(asset.sources).map((source) => (
              <Chip key={source} wrap>
                {source}
              </Chip>
            ))
          )}
        </div>
      </div>
    </Section>
  );

  const analyst = (
    <Section title="Analyst" hint="Importance feeds the risk score">
      <div className="flex flex-col gap-4">
        <div>
          <div className="lbl mb-1.5">Business importance</div>
          <ImportancePicker value={asset.importance} onChange={setImportance} disabled={savingImportance || !canWrite} />
        </div>
        <div>
          <div className="lbl mb-1.5">Comment</div>
          <CommentEditor comment={asset.comment} onSave={saveComment} disabled={!canWrite} />
        </div>
      </div>
    </Section>
  );

  const tagsBlock = (
    <Section title="Tags" hint={tags.length > 0 ? `${tags.length} applied` : undefined}>
      <TagsPanel
        applied={tags}
        available={allTags}
        onTag={applyTag}
        onUntag={removeTag}
        busy={taggingBusy || !canWrite}
      />
    </Section>
  );

  const exclusion = (
    <BlacklistPanel
      asset={asset}
      status={blacklist}
      onBlacklisted={() => {
        onBlacklisted?.();
        void load();
      }}
    />
  );

  const path = (
    <Section title="Discovery path" hint="How this asset was reached">
      <AssetDiscoveryGraph assetId={asset.id} height={page ? 420 : 300} />
    </Section>
  );

  const tech = (
    <TechPortsPanel
      metadata={asset.metadata}
      findings={findings}
      scans={scans}
      scanHistory={evolution?.scan_history ?? []}
    />
  );

  const overview = page ? (
    <div className="flex flex-col gap-4">
      {headline}
      <div className="grid grid-cols-1 xl:grid-cols-[1.35fr_1fr] gap-4 items-start">
        <div className="flex flex-col gap-4 min-w-0">
          {information}
          {analyst}
          {path}
        </div>
        <div className="flex flex-col gap-4 min-w-0">
          {tagsBlock}
          {exclusion}
          {tech}
        </div>
      </div>
      <RawMetadata asset={asset} />
    </div>
  ) : (
    <div className="flex flex-col gap-4">
      {headline}
      {information}
      {analyst}
      {tagsBlock}
      {exclusion}
      {tech}
      {path}
      <RawMetadata asset={asset} />
    </div>
  );

  // ---------------------------------------------------------------- findings

  const findingsPane = (
    <Section
      title="Findings"
      hint={`${openFindings.length} open of ${findings.length}`}
      className="overflow-hidden"
    >
      {findings.length === 0 ? (
        <EmptyState
          icon="shieldCheck"
          title="No findings"
          description="Nothing has been detected on this asset. Run a scan to check again."
          action={
            <Button
              variant="primary"
              icon="play"
              onClick={() => void runScan("full")}
              loading={scanning !== null}
              disabled={!canWrite}
            >
              Run scan
            </Button>
          }
        />
      ) : (
        <div className="-mx-4 -mb-4">
          <Table>
            <THead>
              <TR>
                <TH className="w-[92px]">Severity</TH>
                <TH>Finding</TH>
                <TH className="w-[150px]">Status</TH>
                <TH className="w-[70px] text-right">CVSS</TH>
                <TH className="w-[110px]">Last seen</TH>
              </TR>
            </THead>
            <TBody>
              {triaged.map((finding) => {
                const status = findingStatus(finding.status);
                const severity = finding.severity ?? severityFromCvss(finding.cvss_score);
                const cvssTone = severityTone(severityFromCvss(finding.cvss_score));
                return (
                  <TR
                    key={finding.id}
                    interactive
                    // Carries the asset through, so Findings opens scoped to
                    // this asset rather than dropping the reader into the whole
                    // company's queue. The asset pill there clears the scope.
                    onClick={() => router.push(`/findings?asset=${asset.id}&finding=${finding.id}`)}
                  >
                    <TD>
                      <SeverityChip severity={severity} short />
                    </TD>
                    <TD className="w-full max-w-0">
                      <div className="truncate text-[12.5px] font-medium text-ink" title={finding.title}>
                        {finding.title}
                      </div>
                      <div className="mono text-[11px] text-ink-3 truncate">{finding.finding_type}</div>
                    </TD>
                    <TD>
                      <span className="inline-flex items-center gap-1.5 text-[12px] text-ink-2">
                        <Dot color={status.dot} />
                        {status.label}
                      </span>
                    </TD>
                    <TD className="text-right">
                      <span className={cn("mono text-[12px]", finding.cvss_score != null ? cvssTone.text : "text-ink-3")}>
                        {finding.cvss_score != null ? finding.cvss_score.toFixed(1) : "—"}
                      </span>
                    </TD>
                    <TD>
                      <span className="text-[12px] text-ink-3" title={dateTime(finding.last_seen_at)}>
                        {ago(finding.last_seen_at)}
                      </span>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        </div>
      )}
    </Section>
  );

  // ------------------------------------------------------------------ chrome

  const lastScanTone =
    asset.last_scan_status === "completed"
      ? "var(--ok)"
      : asset.last_scan_status === "failed"
        ? "var(--crit)"
        : asset.last_scan_status === "running"
          ? "var(--accent)"
          : "var(--nil)";

  const actions = (
    <div className="flex items-center gap-2 flex-wrap">
      {extraActions}
      <Button icon="refresh" onClick={() => void load(true)} loading={refreshing} size={page ? "md" : "sm"}>
        Refresh
      </Button>
      <Button icon="download" onClick={downloadReport} loading={downloading} size={page ? "md" : "sm"}>
        PDF report
      </Button>
      <ScanMenu
        onRun={runScan}
        running={scanning}
        disabled={!canWrite}
        size={page ? "md" : "sm"}
      />
    </div>
  );

  return (
    <div className={cn("flex flex-col gap-4", page && "mx-auto w-full max-w-[1240px]")}>
      {page && (
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <Link
              href="/surface"
              className="inline-flex items-center gap-1.5 text-[12px] font-medium text-ink-3 hover:text-ink"
            >
              <Icon name="chevronRight" size={11} className="rotate-180" />
              Surface
            </Link>
            <div className="flex items-center gap-2.5 mt-1.5 flex-wrap">
              <Icon name={assetIcon(asset.asset_type)} size={19} className="text-ink-2" />
              <h1 className="mono text-[23px] font-semibold tracking-[-0.025em] leading-tight break-all">
                {asset.value}
              </h1>
              <Chip>{humanise(asset.asset_type)}</Chip>
              {level && <RiskChip level={level} />}
            </div>
          </div>
          {actions}
        </div>
      )}

      {!page && <div className="flex items-center justify-end">{actions}</div>}

      <div className="flex items-center justify-between gap-3 border-b border-rule">
        <Tabs options={tabs} value={tab} onChange={setTab} />
        {asset.last_scan_status && (
          <span className="inline-flex items-center gap-1.5 text-[11.5px] text-ink-3 pb-1.5">
            <Dot color={lastScanTone} />
            {asset.last_scan_id ? (
              <Link href={`/findings?scan=${asset.last_scan_id}`} className="hover:text-ink hover:underline">
                Last scan {humanise(asset.last_scan_status).toLowerCase()} {ago(asset.last_scanned_at)}
              </Link>
            ) : (
              <>
                Last scan {humanise(asset.last_scan_status).toLowerCase()} {ago(asset.last_scanned_at)}
              </>
            )}
          </span>
        )}
      </div>

      {notice && (
        <Notice tone="info" icon="clock" onDismiss={() => setNotice(null)}>
          {notice}
        </Notice>
      )}
      {/* No retry: the action is not repeatable from here, and it clears itself
          the moment the next one runs. */}
      {actionError && <ErrorState error={actionError} />}
      {loadError && <ErrorState error={loadError} onRetry={() => void load(true)} />}

      {tab === "overview" && overview}
      {tab === "findings" && findingsPane}
      {tab === "activity" && (
        <AssetActivity
          scans={scans}
          scanHistory={evolution?.scan_history ?? []}
          riskHistory={evolution?.risk_history ?? []}
          findings={findings}
        />
      )}
    </div>
  );
}

export default AssetDetail;

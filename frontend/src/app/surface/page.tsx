"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import {
  searchAssetsAdvanced,
  triggerAssetScan,
  updateAssetImportance,
  type Asset,
  type AssetSearchParams,
  type AssetSearchResponse,
  type AssetType,
} from "@/app/api";
import {
  Bar,
  BulkAction,
  BulkBar,
  Button,
  Card,
  Checkbox,
  Chip,
  Drawer,
  Dot,
  EmptyState,
  ErrorState,
  FacetRail,
  Icon,
  IconButton,
  LoadingBlock,
  PageHeader,
  QueryBar,
  RiskChip,
  RowActions,
  Select,
  SeverityChip,
  SortableTH,
  Spinner,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  assetIcon,
  type FacetGroup,
} from "@/components/kit";
import { AssetDetail } from "@/components/asset/AssetDetail";
import { Notice, confidenceColor, useCanWrite } from "@/components/asset/shared";
import { ago, dateTime, humanise, num, pct, score as fmtScore } from "@/lib/format";
import { RISK_ORDER, SEVERITY_ORDER, riskLevelFromScore, riskTone } from "@/lib/severity";

/**
 * The asset inventory.
 *
 * Replaces `/assets` and the asset half of `/risk` and `/search`. Filters live
 * in the URL so a view is a link; a row opens the detail in a drawer so you
 * keep your place in the list, and ⌘-click still takes you to the full page.
 */

const ASSET_TYPES: AssetType[] = ["domain", "ip", "port", "certificate", "organization", "asn"];

type BandId = "high" | "mid" | "low";

/**
 * `min_confidence` is the only confidence filter the search endpoint has, so a
 * band's floor is applied by the server and its ceiling here. That is the whole
 * reason the row count and the total can disagree on a banded view.
 */
interface ConfidenceBand {
  id: BandId;
  label: string;
  token: string;
  min?: number;
  max?: number;
}

const CONFIDENCE_BANDS: ConfidenceBand[] = [
  { id: "high", label: "Above 0.70", token: "conf:>0.70", min: 0.7 },
  { id: "mid", label: "0.40 – 0.70", token: "conf:0.40–0.70", min: 0.4, max: 0.7 },
  { id: "low", label: "Below 0.40", token: "conf:<0.40", max: 0.4 },
];

const SCAN_STATES: Array<{ id: "never_scanned" | "scanned"; label: string }> = [
  { id: "never_scanned", label: "Never scanned" },
  { id: "scanned", label: "Scanned" },
];

type SortField = NonNullable<AssetSearchParams["sort_by"]>;

const SORTS: Array<{ value: string; label: string }> = [
  { value: "created_at:desc", label: "Newest first" },
  { value: "created_at:asc", label: "Oldest first" },
  { value: "risk_score:desc", label: "Risk: high to low" },
  { value: "risk_score:asc", label: "Risk: low to high" },
  { value: "confidence:desc", label: "Confidence: high to low" },
  { value: "confidence:asc", label: "Confidence: low to high" },
  { value: "importance:desc", label: "Importance: high to low" },
  { value: "importance:asc", label: "Importance: low to high" },
  { value: "value:asc", label: "Value: A to Z" },
  { value: "value:desc", label: "Value: Z to A" },
];

const PAGE_SIZES = [25, 50, 100];
const REFRESH_MS = 25_000;
const EXPORT_PAGE = 500;

interface Filters {
  q: string;
  /** Multi-select: the search endpoint takes these comma-separated. */
  type: AssetType[];
  risk: string[];
  scan: "scanned" | "never_scanned" | null;
  band: BandId | null;
  source: string[];
  sortBy: SortField;
  sortDir: "asc" | "desc";
  page: number;
  size: number;
}

/** Read a comma-separated filter, keeping only values the caller recognises. */
function parseList(raw: string | null, allowed?: readonly string[]): string[] {
  if (!raw) return [];
  const values = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return allowed ? values.filter((value) => allowed.includes(value)) : values;
}

function parseFilters(params: URLSearchParams): Filters {
  const scan = params.get("scan");
  const band = params.get("conf");
  const sort = (params.get("sort") ?? "created_at") as SortField;
  const size = Number(params.get("size"));
  const page = Number(params.get("page"));

  return {
    q: params.get("q") ?? "",
    type: parseList(params.get("type"), ASSET_TYPES) as AssetType[],
    risk: parseList(params.get("risk"), RISK_ORDER),
    scan: scan === "scanned" || scan === "never_scanned" ? scan : null,
    band: CONFIDENCE_BANDS.some((entry) => entry.id === band) ? (band as Filters["band"]) : null,
    source: parseList(params.get("source")),
    sortBy: (["created_at", "confidence", "value", "importance", "risk_score"] as SortField[]).includes(sort)
      ? sort
      : "created_at",
    sortDir: params.get("dir") === "asc" ? "asc" : "desc",
    page: Number.isFinite(page) && page > 0 ? page : 1,
    size: PAGE_SIZES.includes(size) ? size : 25,
  };
}

/** Facet keys are `group:value`, which is also what the query bar shows. */
function activeFacetKeys(filters: Filters): string[] {
  const keys: string[] = [];
  for (const value of filters.type) keys.push(`type:${value}`);
  for (const value of filters.risk) keys.push(`risk:${value}`);
  if (filters.scan) keys.push(`scan:${filters.scan}`);
  if (filters.band) keys.push(`conf:${filters.band}`);
  for (const value of filters.source) keys.push(`source:${value}`);
  return keys;
}

/** Facet keys are `group:value`; values may themselves contain a colon. */
function splitFacetKey(key: string): [string, string] {
  const at = key.indexOf(":");
  return at === -1 ? [key, ""] : [key.slice(0, at), key.slice(at + 1)];
}

function tokenFor(key: string): string {
  const [group, value] = splitFacetKey(key);
  if (group === "conf") return CONFIDENCE_BANDS.find((band) => band.id === value)?.token ?? key;
  if (group === "scan") return `scan:${value === "never_scanned" ? "never" : "done"}`;
  return `${group}:${value}`;
}

export default function SurfacePage() {
  return (
    <Suspense fallback={<LoadingBlock label="Loading inventory" />}>
      <Surface />
    </Suspense>
  );
}

function Surface() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const canWrite = useCanWrite();

  const query = searchParams.toString();
  const openId = searchParams.get("asset");

  // Which asset the drawer shows is not part of the question being asked of the
  // server, so it must not refetch the list or clear a selection.
  const dataQuery = useMemo(() => {
    const params = new URLSearchParams(query);
    params.delete("asset");
    return params.toString();
  }, [query]);
  const filters = useMemo(() => parseFilters(new URLSearchParams(dataQuery)), [dataQuery]);

  const [text, setText] = useState(filters.q);
  const [data, setData] = useState<AssetSearchResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [drawerAsset, setDrawerAsset] = useState<Asset | null>(null);
  const [notice, setNotice] = useState<{ tone: "ok" | "warn"; text: string } | null>(null);
  const [searching, setSearching] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set());
  const [importanceMode, setImportanceMode] = useState(false);

  const hasLoadedRef = useRef(false);
  const textRef = useRef(text);
  textRef.current = text;
  const openIdRef = useRef(openId);
  openIdRef.current = openId;

  const setParams = useCallback(
    (patch: Record<string, string | number | null>, resetPage = true) => {
      const next = new URLSearchParams(query);
      Object.entries(patch).forEach(([key, value]) => {
        if (value === null || value === "") next.delete(key);
        else next.set(key, String(value));
      });
      if (resetPage && !("page" in patch)) next.delete("page");
      router.replace(next.toString() ? `/surface?${next.toString()}` : "/surface", { scroll: false });
    },
    [query, router],
  );

  // The text field is local and lands in the URL 300ms after typing stops, so
  // the address bar stays shareable without a request per keystroke.
  useEffect(() => {
    if (text === filters.q) return;
    const timer = setTimeout(() => setParams({ q: textRef.current || null }), 300);
    return () => clearTimeout(timer);
  }, [text, filters.q, setParams]);

  // Adopt an externally-changed q (back button, reset) when nothing is being typed.
  useEffect(() => {
    setText((current) => (current === filters.q ? current : filters.q));
  }, [filters.q]);

  const searchParamsForApi = useCallback(
    (limit: number, offset: number): AssetSearchParams => {
      const band = CONFIDENCE_BANDS.find((entry) => entry.id === filters.band);
      return {
        q: filters.q || undefined,
        asset_type: filters.type.length > 0 ? filters.type : "all",
        risk_level: filters.risk.length > 0 ? filters.risk : undefined,
        scan_status: filters.scan ?? "all",
        source: filters.source.length > 0 ? filters.source : undefined,
        min_confidence: band?.min,
        sort_by: filters.sortBy,
        sort_dir: filters.sortDir,
        limit,
        offset,
      };
    },
    [filters],
  );

  /**
   * `silent` is what keeps the 25-second poll from being felt: the first load
   * gets the spinner, a filter change gets a small activity mark next to the
   * count, and a background refresh gets nothing at all.
   */
  const fetchPage = useCallback(
    async (silent = false) => {
      if (!hasLoadedRef.current) setLoading(true);
      else if (!silent) setSearching(true);
      try {
        const response = await searchAssetsAdvanced(
          searchParamsForApi(filters.size, (filters.page - 1) * filters.size),
        );
        setData(response);
        setError(null);
        hasLoadedRef.current = true;
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setLoading(false);
        setSearching(false);
      }
    },
    [searchParamsForApi, filters.size, filters.page],
  );

  useEffect(() => {
    void fetchPage();
    const timer = setInterval(() => void fetchPage(true), REFRESH_MS);
    return () => clearInterval(timer);
  }, [fetchPage]);

  // A different question means a different answer: drop a selection that no
  // longer refers to what is on screen.
  useEffect(() => {
    setSelected(new Set());
    setImportanceMode(false);
  }, [dataQuery]);

  const band = CONFIDENCE_BANDS.find((entry) => entry.id === filters.band);

  /**
   * The search endpoint takes a floor but no ceiling, so a banded filter is
   * finished off here. Only the upper bound is client-side; everything else the
   * server did.
   */
  const assets = useMemo(() => {
    const rows = data?.assets ?? [];
    const ceiling = band?.max;
    if (ceiling == null) return rows;
    return rows.filter((asset) => asset.ownership_confidence < ceiling);
  }, [data, band]);

  const totalCount = data?.total_count ?? 0;
  const capped = Boolean(band?.max);

  const patchAsset = useCallback((next: Asset) => {
    // Also adopt it when the drawer was deep-linked and has no row behind it,
    // which is the only way its header learns what it is showing.
    setDrawerAsset((current) =>
      current?.id === next.id || openIdRef.current === next.id ? next : current,
    );
    setData((current) =>
      current
        ? { ...current, assets: current.assets.map((asset) => (asset.id === next.id ? next : asset)) }
        : current,
    );
  }, []);

  // ------------------------------------------------------------------ facets

  const facets = useMemo<FacetGroup[]>(
    () => [
      {
        name: "Asset type",
        items: ASSET_TYPES.map((type) => ({ key: `type:${type}`, label: humanise(type) })),
      },
      {
        name: "Risk level",
        items: RISK_ORDER.map((level) => ({
          key: `risk:${level}`,
          label: riskTone(level).label,
          swatch: riskTone(level).dot,
        })),
      },
      {
        name: "Scan state",
        items: SCAN_STATES.map((state) => ({ key: `scan:${state.id}`, label: state.label })),
      },
      {
        name: "Confidence",
        items: CONFIDENCE_BANDS.map((entry) => ({
          key: `conf:${entry.id}`,
          label: entry.label,
          swatch: confidenceColor(entry.min ?? 0),
        })),
      },
      ...(data?.sources?.length
        ? [
            {
              name: "Source",
              items: data.sources.map((source) => ({ key: `source:${source}`, label: source })),
            },
          ]
        : []),
    ],
    [data?.sources],
  );

  const active = activeFacetKeys(filters);

  /**
   * Type, risk and source accumulate — the search endpoint takes each of them
   * comma-separated. Scan state and confidence band stay single-select because
   * they are genuinely exclusive.
   */
  const MULTI = new Set(["type", "risk", "source"]);
  const toggleFacet = (key: string) => {
    const [group, value] = splitFacetKey(key);
    const param = group === "conf" ? "conf" : group;
    const params = new URLSearchParams(query);

    if (!MULTI.has(param)) {
      setParams({ [param]: params.get(param) === value ? null : value, page: null });
      return;
    }

    const current = parseList(params.get(param));
    const next = current.includes(value)
      ? current.filter((entry) => entry !== value)
      : [...current, value];
    setParams({ [param]: next.length > 0 ? next.join(",") : null, page: null });
  };

  const tokens = active.map(tokenFor);
  const tokenToKey = new Map(active.map((key) => [tokenFor(key), key]));

  // ----------------------------------------------------------------- actions

  const selectedAssets = useMemo(
    () => assets.filter((asset) => selected.has(asset.id)),
    [assets, selected],
  );

  const runScan = async (asset: Asset) => {
    setScanningIds((current) => new Set(current).add(asset.id));
    try {
      await triggerAssetScan(asset.id, "full", `Scan from Surface`);
      setNotice({ tone: "ok", text: `Scan queued for ${asset.value}.` });
      void fetchPage();
    } catch (err) {
      setNotice({ tone: "warn", text: `Could not scan ${asset.value}: ${(err as Error).message}` });
    } finally {
      setScanningIds((current) => {
        const next = new Set(current);
        next.delete(asset.id);
        return next;
      });
    }
  };

  /**
   * Bulk work reports partial success. The old page ran the same loop but let
   * the first rejection abort it, so a single bad asset silently cancelled
   * every scan queued after it and the message still said nothing had failed.
   */
  const runBulk = async (
    label: string,
    action: (asset: Asset) => Promise<Asset | unknown>,
  ) => {
    const targets = selectedAssets;
    if (targets.length === 0) return;
    setBusy(label);
    setNotice(null);
    const failures: string[] = [];

    for (const asset of targets) {
      try {
        const result = await action(asset);
        if (result && typeof result === "object" && "id" in (result as Asset)) patchAsset(result as Asset);
      } catch (err) {
        failures.push(`${asset.value} (${(err as Error).message})`);
      }
    }

    const done = targets.length - failures.length;
    setBusy(null);
    setImportanceMode(false);
    if (failures.length === 0) {
      setNotice({ tone: "ok", text: `${label}: ${done} of ${targets.length} succeeded.` });
      setSelected(new Set());
    } else {
      setNotice({
        tone: "warn",
        text: `${label}: ${done} of ${targets.length} succeeded. Failed — ${failures.slice(0, 3).join("; ")}${
          failures.length > 3 ? ` and ${failures.length - 3} more` : ""
        }.`,
      });
    }
    void fetchPage();
  };

  // ----------------------------------------------------------------- exports

  const download = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const stamp = () => new Date().toISOString().slice(0, 10);

  const toCsv = (records: Asset[]) => {
    const header = [
      "id",
      "type",
      "value",
      "risk_score",
      "risk_level",
      "importance",
      "open_findings",
      "confidence",
      "sources",
      "status",
      "last_scanned_at",
      "first_seen_at",
      "created_at",
    ];
    const cell = (value: unknown) => `"${String(value ?? "").replace(/"/g, '""')}"`;
    const rows = records.map((asset) =>
      [
        asset.id,
        asset.asset_type,
        asset.value,
        asset.risk_score ?? "",
        asset.risk_level ?? "",
        asset.importance,
        asset.open_findings?.total ?? "",
        asset.ownership_confidence.toFixed(2),
        asset.sources.join("; "),
        asset.status,
        asset.last_scanned_at ?? "",
        asset.first_seen_at ?? "",
        asset.created_at,
      ]
        .map(cell)
        .join(","),
    );
    return [header.map(cell).join(","), ...rows].join("\n");
  };

  const exportRecords = (records: Asset[], format: "csv" | "json", prefix: string) => {
    if (records.length === 0) {
      setNotice({ tone: "warn", text: "Nothing to export." });
      return;
    }
    if (format === "csv") {
      download(new Blob([toCsv(records)], { type: "text/csv" }), `${prefix}-${stamp()}.csv`);
    } else {
      download(
        new Blob([JSON.stringify(records, null, 2)], { type: "application/json" }),
        `${prefix}-${stamp()}.json`,
      );
    }
    setNotice({ tone: "ok", text: `Exported ${num(records.length)} assets.` });
  };

  /** Walks the whole result set 500 at a time rather than exporting one page. */
  const exportAll = async (format: "csv" | "json") => {
    setBusy("Exporting");
    setNotice(null);
    try {
      const collected: Asset[] = [];
      let offset = 0;
      let total = Number.POSITIVE_INFINITY;
      while (collected.length < total) {
        const response = await searchAssetsAdvanced(searchParamsForApi(EXPORT_PAGE, offset));
        total = response.total_count;
        if (response.assets.length === 0) break;
        collected.push(...response.assets);
        offset += response.assets.length;
      }
      const ceiling = band?.max;
      const rows = ceiling == null ? collected : collected.filter((a) => a.ownership_confidence < ceiling);
      exportRecords(rows, format, active.length || filters.q ? "surface-filtered" : "surface-all");
    } catch (err) {
      setNotice({ tone: "warn", text: `Export failed: ${(err as Error).message}` });
    } finally {
      setBusy(null);
    }
  };

  const onExportChoice = (choice: string) => {
    switch (choice) {
      case "page-csv":
        return exportRecords(assets, "csv", "surface-page");
      case "page-json":
        return exportRecords(assets, "json", "surface-page");
      case "all-csv":
        return void exportAll("csv");
      case "all-json":
        return void exportAll("json");
      default:
        return undefined;
    }
  };

  // ------------------------------------------------------------------ layout

  const allSelected = assets.length > 0 && assets.every((asset) => selected.has(asset.id));
  const someSelected = assets.some((asset) => selected.has(asset.id));
  const pages = Math.max(1, Math.ceil(totalCount / filters.size));
  const firstRow = totalCount === 0 ? 0 : (filters.page - 1) * filters.size + 1;
  const lastRow = Math.min(filters.page * filters.size, totalCount);

  const sortBy = (field: SortField) =>
    setParams({
      sort: field,
      dir: filters.sortBy === field && filters.sortDir === "desc" ? "asc" : "desc",
    });

  const openDrawer = (asset: Asset) => {
    setDrawerAsset(asset);
    setParams({ asset: asset.id }, false);
  };

  const closeDrawer = () => {
    setParams({ asset: null }, false);
    setDrawerAsset(null);
  };

  return (
    <div className="h-full flex min-h-0">
      <FacetRail
        groups={facets}
        active={active}
        onToggle={toggleFacet}
        onReset={() =>
          setParams({ type: null, risk: null, scan: null, conf: null, source: null, q: null })
        }
      />

      <div className="flex-1 flex flex-col min-w-0">
        <div className="px-6 pt-4 pb-3 shrink-0 flex flex-col gap-3">
          <PageHeader
            title="Surface"
            hint={
              loading && !data ? (
                "Loading…"
              ) : searching ? (
                <span className="inline-flex items-center gap-1.5">
                  <Spinner size={11} />
                  Searching…
                </span>
              ) : (
                capped
                  ? `${num(assets.length)} of ${num(totalCount)} on this page within the band`
                  : `${num(totalCount)} ${totalCount === 1 ? "asset" : "assets"}${active.length || filters.q ? " matching" : ""}`
              )
            }
            actions={
              <>
                <Select
                  aria-label="Sort"
                  className="w-[190px]"
                  value={`${filters.sortBy}:${filters.sortDir}`}
                  onChange={(event) => {
                    const [field, direction] = event.target.value.split(":");
                    setParams({ sort: field, dir: direction });
                  }}
                >
                  {SORTS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </Select>
                <Select
                  aria-label="Export"
                  className="w-[130px]"
                  value=""
                  disabled={busy != null}
                  onChange={(event) => onExportChoice(event.target.value)}
                >
                  <option value="">{busy === "Exporting" ? "Exporting…" : "Export…"}</option>
                  <option value="page-csv">This page · CSV</option>
                  <option value="page-json">This page · JSON</option>
                  <option value="all-csv">All matching · CSV</option>
                  <option value="all-json">All matching · JSON</option>
                </Select>
              </>
            }
          />

          <QueryBar
            tokens={tokens}
            onRemoveToken={(token) => {
              const key = tokenToKey.get(token);
              if (key) toggleFacet(key);
            }}
            value={text}
            onValueChange={setText}
            placeholder="Search domains, IPs, sources…"
          />

          {notice && (
            <Notice
              tone={notice.tone === "ok" ? "ok" : "warn"}
              icon={notice.tone === "ok" ? "check" : "alert"}
              onDismiss={() => setNotice(null)}
            >
              {notice.text}
            </Notice>
          )}
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto px-6 pb-6">
          {error && <ErrorState error={error} onRetry={() => void fetchPage()} className="mb-3" />}

          <Card className="overflow-hidden">
            {loading && !data ? (
              <LoadingBlock label="Loading assets" />
            ) : assets.length === 0 ? (
              <EmptyState
                icon="globe"
                title={active.length || filters.q ? "Nothing matches those filters" : "No assets yet"}
                description={
                  active.length || filters.q
                    ? "Loosen a filter, or clear them all and start again."
                    : "Add a seed and run discovery, and everything it finds lands here."
                }
                action={
                  active.length || filters.q ? (
                    <Button
                      onClick={() =>
                        setParams({ type: null, risk: null, scan: null, conf: null, source: null, q: null })
                      }
                    >
                      Clear filters
                    </Button>
                  ) : (
                    <Button variant="primary" icon="seed" onClick={() => router.push("/ops")}>
                      Go to Ops
                    </Button>
                  )
                }
              />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH className="w-[38px]">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={someSelected && !allSelected}
                        onChange={(next) =>
                          setSelected(next ? new Set(assets.map((asset) => asset.id)) : new Set())
                        }
                        label={<span className="sr-only">Select all on this page</span>}
                      />
                    </TH>
                    <SortableTH
                      active={filters.sortBy === "value"}
                      direction={filters.sortDir}
                      onSort={() => sortBy("value")}
                    >
                      Asset
                    </SortableTH>
                    <TH className="w-[104px]">Type</TH>
                    <SortableTH
                      className="w-[168px]"
                      active={filters.sortBy === "risk_score"}
                      direction={filters.sortDir}
                      onSort={() => sortBy("risk_score")}
                    >
                      Risk
                    </SortableTH>
                    <TH className="w-[186px]">Open findings</TH>
                    <SortableTH
                      className="w-[118px]"
                      active={filters.sortBy === "confidence"}
                      direction={filters.sortDir}
                      onSort={() => sortBy("confidence")}
                    >
                      Confidence
                    </SortableTH>
                    <TH className="w-[152px]">Sources</TH>
                    <TH className="w-[150px]">Last scan</TH>
                    <TH className="w-[74px]">
                      <span className="sr-only">Actions</span>
                    </TH>
                  </TR>
                </THead>
                <TBody>
                  {assets.map((asset) => (
                    <AssetRow
                      key={asset.id}
                      asset={asset}
                      selected={selected.has(asset.id)}
                      active={openId === asset.id}
                      scanning={scanningIds.has(asset.id)}
                      canWrite={canWrite}
                      onSelect={(next) =>
                        setSelected((current) => {
                          const updated = new Set(current);
                          if (next) updated.add(asset.id);
                          else updated.delete(asset.id);
                          return updated;
                        })
                      }
                      onOpen={(event) => {
                        if (event.metaKey || event.ctrlKey) router.push(`/surface/${asset.id}`);
                        else openDrawer(asset);
                      }}
                      onOpenPage={() => router.push(`/surface/${asset.id}`)}
                      onScan={() => void runScan(asset)}
                    />
                  ))}
                </TBody>
              </Table>
            )}
          </Card>

          {assets.length > 0 && (
            <div className="flex items-center justify-between gap-4 mt-3">
              <div className="flex items-center gap-2.5 text-[12px] text-ink-3">
                <span>
                  <span className="mono">{num(firstRow)}</span>–<span className="mono">{num(lastRow)}</span> of{" "}
                  <span className="mono">{num(totalCount)}</span>
                </span>
                <Select
                  aria-label="Rows per page"
                  className="w-[76px]"
                  value={String(filters.size)}
                  onChange={(event) => setParams({ size: event.target.value })}
                >
                  {PAGE_SIZES.map((size) => (
                    <option key={size} value={size}>
                      {size}
                    </option>
                  ))}
                </Select>
              </div>

              <div className="flex items-center gap-1.5">
                <Button size="sm" disabled={filters.page <= 1} onClick={() => setParams({ page: 1 }, false)}>
                  First
                </Button>
                <Button
                  size="sm"
                  disabled={filters.page <= 1}
                  onClick={() => setParams({ page: filters.page - 1 }, false)}
                >
                  Previous
                </Button>
                <span className="mono text-[12px] text-ink-2 px-2">
                  {filters.page} / {pages}
                </span>
                <Button
                  size="sm"
                  disabled={filters.page >= pages}
                  onClick={() => setParams({ page: filters.page + 1 }, false)}
                >
                  Next
                </Button>
                <Button
                  size="sm"
                  disabled={filters.page >= pages}
                  onClick={() => setParams({ page: pages }, false)}
                >
                  Last
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>

      <Drawer
        open={Boolean(openId)}
        onClose={closeDrawer}
        title={drawerAsset?.value ?? "Asset"}
        width={780}
        header={
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <Icon name={assetIcon(drawerAsset?.asset_type)} size={15} className="text-ink-2" />
            <span className="mono text-[15px] font-semibold tracking-[-0.015em] truncate">
              {drawerAsset?.value ?? "Asset"}
            </span>
            {drawerAsset && <Chip>{humanise(drawerAsset.asset_type)}</Chip>}
            {drawerAsset && (drawerAsset.risk_level ?? riskLevelFromScore(drawerAsset.risk_score)) && (
              <RiskChip level={drawerAsset.risk_level ?? riskLevelFromScore(drawerAsset.risk_score)} />
            )}
          </div>
        }
      >
        {openId && (
          <AssetDetail
            key={openId}
            assetId={openId}
            variant="drawer"
            initialAsset={drawerAsset?.id === openId ? drawerAsset : null}
            onAssetChange={patchAsset}
            onBlacklisted={() => void fetchPage()}
            extraActions={
              <Button size="sm" icon="external" onClick={() => router.push(`/surface/${openId}`)}>
                Open full page
              </Button>
            }
          />
        )}
      </Drawer>

      <BulkBar count={selected.size} onClear={() => setSelected(new Set())}>
        {importanceMode ? (
          <>
            <span className="text-[12px] opacity-70">Set importance</span>
            {[1, 2, 3, 4, 5].map((level) => (
              <BulkAction
                key={level}
                disabled={busy != null}
                onClick={() =>
                  void runBulk(`Importance ${level}`, (asset) => updateAssetImportance(asset.id, level))
                }
              >
                {level}
              </BulkAction>
            ))}
            <BulkAction onClick={() => setImportanceMode(false)}>Cancel</BulkAction>
          </>
        ) : (
          <>
            <BulkAction
              primary
              disabled={!canWrite || busy != null}
              onClick={() =>
                void runBulk("Scan", (asset) => triggerAssetScan(asset.id, "full", "Bulk scan from Surface"))
              }
            >
              {busy === "Scan" ? "Scanning…" : "Scan selected"}
            </BulkAction>
            <BulkAction disabled={!canWrite || busy != null} onClick={() => setImportanceMode(true)}>
              Set importance
            </BulkAction>
            <BulkAction onClick={() => exportRecords(selectedAssets, "csv", "surface-selected")}>
              Export CSV
            </BulkAction>
            <BulkAction onClick={() => exportRecords(selectedAssets, "json", "surface-selected")}>
              Export JSON
            </BulkAction>
          </>
        )}
      </BulkBar>
    </div>
  );
}

function AssetRow({
  asset,
  selected,
  active,
  scanning,
  canWrite,
  onSelect,
  onOpen,
  onOpenPage,
  onScan,
}: {
  asset: Asset;
  selected: boolean;
  active: boolean;
  scanning: boolean;
  canWrite: boolean;
  onSelect: (next: boolean) => void;
  onOpen: (event: MouseEvent<HTMLTableRowElement>) => void;
  onOpenPage: () => void;
  onScan: () => void;
}) {
  const level = asset.risk_level ?? riskLevelFromScore(asset.risk_score);
  const tone = riskTone(level);
  const open = asset.open_findings;
  const confidence = asset.ownership_confidence;

  return (
    <TR interactive selected={selected || active} onClick={onOpen}>
      <TD>
        <Checkbox checked={selected} onChange={onSelect} stopPropagation />
      </TD>

      <TD className="w-full max-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <Icon name={assetIcon(asset.asset_type)} size={13} className="text-ink-3 shrink-0" />
          <span className="mono text-[12.5px] text-ink truncate" title={asset.value}>
            {asset.value}
          </span>
          {asset.importance >= 4 && (
            <span className="shrink-0 text-accent" title={`Importance ${asset.importance} of 5`}>
              <Icon name="shield" size={11} />
              <span className="sr-only">Importance {asset.importance} of 5</span>
            </span>
          )}
        </div>
      </TD>

      <TD>
        <span className="text-[12px] text-ink-2">{humanise(asset.asset_type)}</span>
      </TD>

      <TD>
        {asset.risk_score == null ? (
          <span className="text-[12px] text-ink-3">—</span>
        ) : (
          <div className="flex items-center gap-2">
            <span className="mono text-[12.5px] font-medium w-[34px]" style={{ color: tone.dot }}>
              {fmtScore(asset.risk_score)}
            </span>
            <Bar value={asset.risk_score / 100} color={tone.dot} className="w-[44px]" />
            {level && <RiskChip level={level} />}
          </div>
        )}
      </TD>

      <TD>
        {open == null ? (
          <span className="text-[12px] text-ink-3" title="This build of the API does not report per-asset findings">
            —
          </span>
        ) : open.total === 0 ? (
          <span className="text-[12px] text-ink-3">none</span>
        ) : (
          <div className="flex items-center gap-1 flex-wrap">
            {SEVERITY_ORDER.filter((severity) => (open[severity] ?? 0) > 0).map((severity) => (
              <SeverityChip key={severity} severity={severity} short count={open[severity]} />
            ))}
          </div>
        )}
      </TD>

      <TD>
        <div className="flex items-center gap-2">
          <span className="mono text-[12px] text-ink-2 w-[30px]">{pct(confidence)}</span>
          <Bar value={confidence} color={confidenceColor(confidence)} className="w-[48px]" />
        </div>
      </TD>

      <TD>
        <div className="flex items-center gap-1 min-w-0">
          {asset.sources.length === 0 ? (
            <span className="text-[12px] text-ink-3">—</span>
          ) : (
            <>
              <span className="text-[12px] text-ink-2 truncate" title={asset.sources.join(", ")}>
                {asset.sources[0]}
              </span>
              {asset.sources.length > 1 && (
                <span className="mono text-[11px] text-ink-3 shrink-0">+{asset.sources.length - 1}</span>
              )}
            </>
          )}
        </div>
      </TD>

      <TD>
        {asset.last_scanned_at ? (
          <span className="flex items-center gap-1.5 min-w-0">
            <Dot
              color={
                asset.last_scan_status === "completed"
                  ? "var(--ok)"
                  : asset.last_scan_status === "failed"
                    ? "var(--crit)"
                    : asset.last_scan_status === "running"
                      ? "var(--accent)"
                      : "var(--nil)"
              }
            />
            {asset.last_scan_id ? (
              <Link
                href={`/findings?scan=${asset.last_scan_id}`}
                onClick={(event) => event.stopPropagation()}
                className="text-[12px] text-ink-2 hover:text-accent-ink hover:underline truncate"
                title={`${humanise(asset.last_scan_status ?? "scan")} · ${dateTime(asset.last_scanned_at)}`}
              >
                {ago(asset.last_scanned_at)}
              </Link>
            ) : (
              <span className="text-[12px] text-ink-2 truncate" title={dateTime(asset.last_scanned_at)}>
                {ago(asset.last_scanned_at)}
              </span>
            )}
          </span>
        ) : (
          <span className="text-[12px] text-ink-3">Never</span>
        )}
      </TD>

      <TD>
        <RowActions>
          <IconButton
            size="sm"
            variant="ghost"
            icon="play"
            label={`Scan ${asset.value} now`}
            loading={scanning}
            disabled={!canWrite}
            onClick={(event) => {
              event.stopPropagation();
              onScan();
            }}
          />
          <IconButton
            size="sm"
            variant="ghost"
            icon="external"
            label={`Open ${asset.value} full page`}
            onClick={(event) => {
              event.stopPropagation();
              onOpenPage();
            }}
          />
        </RowActions>
      </TD>
    </TR>
  );
}

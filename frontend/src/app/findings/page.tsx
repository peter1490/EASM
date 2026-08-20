"use client";

/**
 * Findings — every security finding, its detail drawer, and the scan result
 * view. Replaces `/security`, the findings half of `/search`, and the
 * 1196-line `/security/scans/[id]` route.
 *
 * Deliberately the same shape as Surface: facet rail on the left, one query
 * bar carrying the active filters as removable tokens, a dense table, a right
 * slide-over for detail. The app is learned once.
 */

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  bulkUpdateSecurityFindings,
  getSecurityFinding,
  getSecurityFindingsSummary,
  listSecurityFindings,
  type FindingSortField,
  type FindingStatus,
  type SecurityFinding,
  type SecurityFindingFilter,
} from "@/app/api";
import {
  BulkAction,
  BulkBar,
  Button,
  Checkbox,
  Dot,
  Drawer,
  EmptyState,
  ErrorState,
  FacetRail,
  Icon,
  LoadingBlock,
  PageHeader,
  QueryBar,
  RowActions,
  SeverityChip,
  SortableTH,
  Spinner,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  type FacetGroup,
} from "@/components/kit";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/cn";
import { ago, num, score } from "@/lib/format";
import {
  FINDING_STATUSES,
  OPEN_STATUSES,
  SEVERITY_ORDER,
  findingStatus,
  severityTone,
  type FindingStatus as Status,
} from "@/lib/severity";
import {
  BULK_ACTIONS,
  FindingDetail,
  FindingDetailActions,
  FindingDetailHeader,
  applyFindingStatus,
  effectiveSeverity,
  transitionsFor,
} from "@/components/finding/FindingDetail";
import { findingTypeLabel } from "@/components/finding/FindingEvidence";
import { ScanDetail } from "@/components/finding/ScanDetail";

const PAGE_SIZE = 100;
/** The bulk endpoint accepts at most 500 ids, so never load more than one bulk. */
const MAX_ROWS = 500;
const REFRESH_MS = 15_000;

/** Facet groups, keyed `group:value` so one token list drives rail and query bar. */
const FACET_GROUPS = ["severity", "status", "type", "asset_type"] as const;
type FacetGroupName = (typeof FACET_GROUPS)[number];

const ASSET_TYPES = ["domain", "ip", "port", "certificate"];

/** The default view hides resolved findings; every other status stays visible. */
const DEFAULT_STATUSES = FINDING_STATUSES.map((s) => s.value).filter((s) => s !== "resolved");

const TRIAGE_ROLES = ["global_admin", "admin", "operator", "analyst"];

const SORT_FIELDS: FindingSortField[] = [
  "first_seen_at",
  "last_seen_at",
  "severity",
  "cvss_score",
  "status",
];

function severityRank(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

/** Active statuses first, then severity, then CVSS. The old `/security` order. */
function triageCompare(a: SecurityFinding, b: SecurityFinding): number {
  const aActive = OPEN_STATUSES.includes((a.status ?? "open") as Status) ? 0 : 1;
  const bActive = OPEN_STATUSES.includes((b.status ?? "open") as Status) ? 0 : 1;
  if (aActive !== bActive) return aActive - bActive;
  const sev = severityRank(effectiveSeverity(a)) - severityRank(effectiveSeverity(b));
  if (sev !== 0) return sev;
  return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
}

function splitParam(value: string): string[] {
  return value ? value.split(",").filter(Boolean) : [];
}

export default function FindingsPage() {
  return (
    <Suspense fallback={<LoadingBlock label="Loading findings" />}>
      <FindingsScreen />
    </Suspense>
  );
}

function FindingsScreen() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, companies, companyId } = useAuth();

  const companyRole = companies.find((company) => company.id === companyId)?.role ?? null;
  const canTriage =
    (user?.roles ?? []).some((role) => TRIAGE_ROLES.includes(role)) ||
    (companyRole ? TRIAGE_ROLES.includes(companyRole) : false);

  /* ---------------- URL state ---------------- */

  const severityParam = searchParams.get("severity") ?? "";
  const statusParam = searchParams.get("status") ?? "";
  const typeParam = searchParams.get("type") ?? "";
  const assetTypeParam = searchParams.get("asset_type") ?? "";
  const qParam = searchParams.get("q") ?? "";
  const scanParam = searchParams.get("scan");
  // Scoping to one asset, so Surface can link "see every finding on this asset".
  const assetParam = searchParams.get("asset");
  const findingParam = searchParams.get("finding");
  const sortParam = searchParams.get("sort") ?? "triage";
  const dirParam: "asc" | "desc" = searchParams.get("dir") === "asc" ? "asc" : "desc";

  const paramsString = searchParams.toString();

  const setParams = useCallback(
    (mutate: (params: URLSearchParams) => void) => {
      const next = new URLSearchParams(paramsString);
      mutate(next);
      const query = next.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
    },
    [paramsString, pathname, router],
  );

  const activeTokens = useMemo(() => {
    const tokens: string[] = [];
    for (const group of FACET_GROUPS) {
      const raw =
        group === "severity"
          ? severityParam
          : group === "status"
            ? statusParam
            : group === "type"
              ? typeParam
              : assetTypeParam;
      for (const value of splitParam(raw)) tokens.push(`${group}:${value}`);
    }
    return tokens;
  }, [severityParam, statusParam, typeParam, assetTypeParam]);

  const toggleFacet = useCallback(
    (key: string) => {
      const separator = key.indexOf(":");
      if (separator < 0) return;
      const group = key.slice(0, separator) as FacetGroupName;
      const value = key.slice(separator + 1);
      if (!FACET_GROUPS.includes(group)) return;
      setParams((params) => {
        const current = splitParam(params.get(group) ?? "");
        const next = current.includes(value)
          ? current.filter((entry) => entry !== value)
          : [...current, value];
        if (next.length > 0) params.set(group, next.join(","));
        else params.delete(group);
      });
    },
    [setParams],
  );

  const resetFilters = useCallback(() => {
    setParams((params) => {
      for (const group of FACET_GROUPS) params.delete(group);
      params.delete("q");
    });
  }, [setParams]);

  /* ---------------- Data ---------------- */

  const [rows, setRows] = useState<SecurityFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [statusSummary, setStatusSummary] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [knownTypes, setKnownTypes] = useState<string[]>([]);
  const hasLoadedRef = useRef(false);
  const rowsRef = useRef<SecurityFinding[]>([]);
  rowsRef.current = rows;
  /** Guards against a slow background poll landing on top of a newer filter. */
  const requestRef = useRef(0);

  const load = useCallback(
    async (silent = false) => {
      const request = ++requestRef.current;
      if (!silent) {
        if (!hasLoadedRef.current) setLoading(true);
        else setBusy(true);
      }
      try {
        const filter: SecurityFindingFilter = {
          limit: Math.min(PAGE_SIZE * pages, MAX_ROWS),
          offset: 0,
          status: splitParam(statusParam).length > 0 ? splitParam(statusParam) : DEFAULT_STATUSES,
        };
        if (severityParam) filter.severity = splitParam(severityParam);
        if (typeParam) filter.finding_type = splitParam(typeParam);
        // Server-side now: this used to be applied over the loaded page only,
        // so the count was per page and unjoined rows silently vanished.
        if (assetTypeParam) filter.asset_type = splitParam(assetTypeParam);
        if (qParam) filter.q = qParam;
        if (scanParam) filter.scan_id = scanParam;
        if (assetParam) filter.asset_id = assetParam;
        if (sortParam !== "triage" && SORT_FIELDS.includes(sortParam as FindingSortField)) {
          filter.sort_by = sortParam as FindingSortField;
          filter.sort_dir = dirParam;
        } else {
          // Triage order is finished client-side, but the server still has to
          // return the right page of rows — severity-first is the closest match.
          filter.sort_by = "severity";
          filter.sort_dir = "desc";
        }

        const [list, summaryResult] = await Promise.all([
          listSecurityFindings(filter),
          getSecurityFindingsSummary().catch(() => null),
        ]);

        if (request !== requestRef.current) return;

        setRows(list.findings);
        setTotal(list.total_count);
        if (summaryResult) {
          setSummary(summaryResult.by_severity ?? {});
          setStatusSummary(summaryResult.by_status ?? {});
        }
        setKnownTypes((previous) => {
          const seen = new Set(previous);
          for (const finding of list.findings) seen.add(finding.finding_type);
          for (const value of splitParam(typeParam)) seen.add(value);
          // Same set, same array — so the facet rail does not churn on a poll.
          return seen.size === previous.length ? previous : [...seen].sort();
        });
        setError(null);
        hasLoadedRef.current = true;
      } catch (err) {
        if (request !== requestRef.current) return;
        if (!silent || !hasLoadedRef.current) setError((err as Error).message);
      } finally {
        if (request === requestRef.current) {
          setLoading(false);
          setBusy(false);
        }
      }
    },
    [severityParam, statusParam, typeParam, assetTypeParam, qParam, scanParam, assetParam, sortParam, dirParam, pages],
  );

  useEffect(() => {
    load(false);
  }, [load]);

  // Background refresh: never a spinner, never a lost scroll position.
  useEffect(() => {
    const timer = setInterval(() => load(true), REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  /* ---------------- Facets ---------------- */

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const finding of rows) {
      counts.set(finding.finding_type, (counts.get(finding.finding_type) ?? 0) + 1);
    }
    return counts;
  }, [rows]);

  const facetGroups: FacetGroup[] = useMemo(
    () =>
      [
        {
          // Counts come from /findings/summary, which counts open, acknowledged
          // and in-progress findings only — so the label says so rather than
          // showing a number that will not add up to the rows below.
          name: "Severity · open",
          items: SEVERITY_ORDER.map((severity) => {
            const tone = severityTone(severity);
            return {
              key: `severity:${severity}`,
              label: tone.label,
              swatch: tone.dot,
              count: summary[severity] ?? undefined,
            };
          }),
        },
        {
          // Unlike the severity counts above, `by_status` spans every status —
          // resolved and false-positive included — so these add up to the whole
          // company rather than to the open subset.
          name: "Status",
          items: FINDING_STATUSES.map((status) => ({
            key: `status:${status.value}`,
            label: status.label,
            swatch: status.dot,
            count: statusSummary[status.value] ?? undefined,
          })),
        },
        {
          name: "Finding type",
          items: knownTypes.map((type) => ({
            key: `type:${type}`,
            label: findingTypeLabel(type),
            count: typeCounts.get(type),
          })),
        },
        {
          name: "Asset type",
          items: ASSET_TYPES.map((assetType) => ({
            key: `asset_type:${assetType}`,
            label: assetType === "ip" ? "IP" : assetType.replace(/^\w/, (c) => c.toUpperCase()),
          })),
        },
      ].filter((group) => group.items.length > 0),
    [summary, statusSummary, knownTypes, typeCounts],
  );

  const facetKeys = useMemo(
    () => new Set(facetGroups.flatMap((group) => group.items.map((item) => item.key))),
    [facetGroups],
  );

  /* ---------------- Query text ---------------- */

  const [text, setText] = useState(qParam);

  useEffect(() => {
    const trimmed = text.trim();
    // `status:resolved` typed into the bar becomes a facet token, not a search.
    // A half-typed token is held rather than searched for, so nothing flickers.
    const tokenMatch = /^(severity|status|type|asset_type)\s*:\s*(.*)$/i.exec(trimmed);
    if (tokenMatch) {
      const key = `${tokenMatch[1].toLowerCase()}:${tokenMatch[2].trim().toLowerCase().replace(/\s+/g, "_")}`;
      if (facetKeys.has(key)) {
        setText("");
        if (!activeTokens.includes(key)) toggleFacet(key);
      }
      return;
    }
    if (trimmed === qParam) return;
    const timer = setTimeout(() => {
      setParams((params) => {
        if (trimmed) params.set("q", trimmed);
        else params.delete("q");
      });
    }, 300);
    return () => clearTimeout(timer);
  }, [text, qParam, setParams, toggleFacet, facetKeys, activeTokens]);

  /* ---------------- Visible rows ---------------- */

  /**
   * Every filter is applied by the server, `asset_type` included — it is sent
   * on the request above and narrows `total_count` with it. The only thing left
   * to do here is triage order, which depends on an effective severity the
   * server has no column for.
   */
  const visibleRows = useMemo(
    () => (sortParam === "triage" ? [...rows].sort(triageCompare) : rows),
    [rows, sortParam],
  );

  const resolvedHidden = !splitParam(statusParam).includes("resolved");

  /* ---------------- Selection ---------------- */

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  // A selection only means something against the rows it was made on.
  useEffect(() => {
    setSelected(new Set());
  }, [severityParam, statusParam, typeParam, assetTypeParam, qParam, scanParam, assetParam]);

  const selectedCount = selected.size;
  const allSelected = visibleRows.length > 0 && visibleRows.every((row) => selected.has(row.id));
  const someSelected = visibleRows.some((row) => selected.has(row.id));

  function toggleAll(checked: boolean) {
    setSelected((previous) => {
      const next = new Set(previous);
      for (const row of visibleRows) {
        if (checked) next.add(row.id);
        else next.delete(row.id);
      }
      return next;
    });
  }

  function toggleOne(id: string, checked: boolean) {
    setSelected((previous) => {
      const next = new Set(previous);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  /* ---------------- Detail ---------------- */

  const [detail, setDetail] = useState<SecurityFinding | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  useEffect(() => {
    setActionError(null);
    if (!findingParam) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    const local = rowsRef.current.find((finding) => finding.id === findingParam);
    if (local) {
      setDetail(local);
      setDetailError(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    getSecurityFinding(findingParam)
      .then((finding) => {
        if (!cancelled) {
          setDetail(finding);
          setDetailError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setDetailError((err as Error).message);
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [findingParam]);

  const openFinding = useCallback(
    (id: string) => setParams((params) => params.set("finding", id)),
    [setParams],
  );

  const closeFinding = useCallback(
    () => setParams((params) => params.delete("finding")),
    [setParams],
  );

  const openScan = useCallback(
    (scanId: string) =>
      setParams((params) => {
        params.set("scan", scanId);
        params.delete("finding");
      }),
    [setParams],
  );

  /** Patch a row (and the open drawer) in place, without waiting for a poll. */
  const patchLocal = useCallback((id: string, patch: Partial<SecurityFinding>) => {
    setRows((previous) =>
      previous.map((finding) => (finding.id === id ? { ...finding, ...patch } : finding)),
    );
    setDetail((previous) => (previous && previous.id === id ? { ...previous, ...patch } : previous));
  }, []);

  const changeStatus = useCallback(
    async (finding: SecurityFinding, status: FindingStatus) => {
      setActionError(null);
      setNotice(null);
      setBusyId(finding.id);
      const previous = { status: finding.status, resolved_at: finding.resolved_at };
      patchLocal(finding.id, {
        status,
        resolved_at: status === "resolved" ? new Date().toISOString() : finding.resolved_at,
      });
      try {
        const updated = await applyFindingStatus(finding.id, status);
        patchLocal(finding.id, updated);
      } catch (err) {
        patchLocal(finding.id, previous);
        setActionError((err as Error).message);
      } finally {
        setBusyId(null);
      }
    },
    [patchLocal],
  );

  const runBulk = useCallback(
    async (status: FindingStatus) => {
      const ids = [...selected].slice(0, MAX_ROWS);
      if (ids.length === 0) return;
      setBulkBusy(true);
      setActionError(null);
      setNotice(null);
      const before = new Map(rowsRef.current.map((finding) => [finding.id, finding.status]));
      setRows((previous) =>
        previous.map((finding) => (selected.has(finding.id) ? { ...finding, status } : finding)),
      );
      try {
        const result = await bulkUpdateSecurityFindings(ids, { status });
        if (result.failed > 0 && Array.isArray(result.failed_ids)) {
          const failed = new Set(result.failed_ids);
          setRows((previous) =>
            previous.map((finding) =>
              failed.has(finding.id)
                ? { ...finding, status: before.get(finding.id) ?? finding.status }
                : finding,
            ),
          );
        }
        setNotice(
          `${num(result.updated)} finding${result.updated === 1 ? "" : "s"} set to ${
            findingStatus(status).label.toLowerCase()
          }${result.failed > 0 ? ` · ${num(result.failed)} failed` : ""}`,
        );
        setSelected(new Set());
        load(true);
      } catch (err) {
        setRows((previous) =>
          previous.map((finding) =>
            before.has(finding.id) ? { ...finding, status: before.get(finding.id) as string } : finding,
          ),
        );
        setActionError((err as Error).message);
      } finally {
        setBulkBusy(false);
      }
    },
    [selected, load],
  );

  /* ---------------- Sorting ---------------- */

  function sortBy(field: FindingSortField, defaultDir: "asc" | "desc") {
    setParams((params) => {
      if (sortParam === field) {
        params.set("dir", dirParam === "asc" ? "desc" : "asc");
      } else {
        params.set("sort", field);
        params.set("dir", defaultDir);
      }
    });
  }

  function resetSort() {
    setParams((params) => {
      params.delete("sort");
      params.delete("dir");
    });
  }

  const sortProps = (field: FindingSortField) => ({
    active: sortParam === field,
    direction: dirParam,
  });

  /* ---------------- Render ---------------- */

  const queryTokens = [
    ...activeTokens,
    ...(scanParam ? [`scan:${scanParam.slice(0, 8)}`] : []),
    ...(assetParam ? [`asset:${assetParam.slice(0, 8)}`] : []),
  ];

  function removeToken(token: string) {
    if (token.startsWith("scan:")) {
      setParams((params) => params.delete("scan"));
      return;
    }
    toggleFacet(token);
  }

  return (
    <div className="h-full flex min-h-0">
      <FacetRail
        groups={facetGroups}
        active={activeTokens}
        onToggle={toggleFacet}
        onReset={resetFilters}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <div className="px-6 pt-4 pb-3 shrink-0 space-y-3">
          <PageHeader
            title="Findings"
            hint={
              scanParam
                ? "Everything one scan turned up, and the triage queue for it."
                : "Everything the scanners found, in one queue."
            }
            actions={
              <Button icon="refresh" onClick={() => load(false)} loading={busy}>
                Refresh
              </Button>
            }
          />
          <QueryBar
            tokens={queryTokens}
            onRemoveToken={removeToken}
            value={text}
            onValueChange={setText}
            placeholder="Search findings, or type status:resolved"
          />
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto px-6 pb-6">
          {scanParam && (
            <div className="mb-4">
              <ScanDetail scanId={scanParam} onClear={() => setParams((p) => p.delete("scan"))} />
            </div>
          )}

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 mb-2.5 min-h-[22px]">
            <span className="text-[12.5px] text-ink-2">
              <span className="mono">{num(visibleRows.length)}</span>
              {visibleRows.length < total && <span className="text-ink-3"> of {num(total)}</span>}{" "}
              finding{visibleRows.length === 1 ? "" : "s"}
              {scanParam && <span className="text-ink-3"> from this scan</span>}
            </span>
            {busy && <Spinner size={12} />}
            {resolvedHidden && (
              <button
                type="button"
                onClick={() => toggleFacet("status:resolved")}
                className="inline-flex items-center gap-1 text-[11.5px] text-ink-3 hover:text-ink"
                title="Add the resolved status to the filter"
              >
                <Icon name="eyeOff" size={11} />
                Resolved hidden — add <span className="mono">status:resolved</span> to include them
              </button>
            )}
            {sortParam !== "triage" && (
              <button
                type="button"
                onClick={resetSort}
                className="inline-flex items-center gap-1 text-[11.5px] text-accent hover:underline"
              >
                <Icon name="sort" size={11} />
                Back to triage order
              </button>
            )}
            {notice && (
              <span className="inline-flex items-center gap-1.5 text-[11.5px] text-ok ml-auto">
                <Icon name="check" size={11} />
                {notice}
                <button
                  type="button"
                  onClick={() => setNotice(null)}
                  aria-label="Dismiss"
                  className="text-ink-3 hover:text-ink"
                >
                  <Icon name="close" size={10} />
                </button>
              </span>
            )}
          </div>

          {actionError && (
            <div className="mb-3">
              <ErrorState error={actionError} />
            </div>
          )}

          {error ? (
            <ErrorState error={error} onRetry={() => load(false)} />
          ) : loading && rows.length === 0 ? (
            <LoadingBlock label="Loading findings" />
          ) : visibleRows.length === 0 ? (
            <div className="bg-surface border border-rule rounded-lg">
              <EmptyState
                icon="shieldCheck"
                title="No findings match these filters"
                description={
                  activeTokens.length > 0 || qParam
                    ? "Nothing here with the current filters. Clear one to widen the search."
                    : "Nothing has been flagged yet. Findings appear as assets are scanned."
                }
                action={
                  activeTokens.length > 0 || qParam ? (
                    <Button onClick={resetFilters}>Clear filters</Button>
                  ) : undefined
                }
              />
            </div>
          ) : (
            <div className="bg-surface border border-rule rounded-lg overflow-hidden">
              <Table>
                <THead>
                  <TR>
                    <TH className="w-[38px]">
                      <Checkbox
                        checked={allSelected}
                        indeterminate={!allSelected && someSelected}
                        onChange={toggleAll}
                        label={<span className="sr-only">Select every visible finding</span>}
                      />
                    </TH>
                    <SortableTH
                      className="w-[92px]"
                      onSort={() => sortBy("severity", "desc")}
                      {...sortProps("severity")}
                    >
                      Severity
                    </SortableTH>
                    <TH>Finding</TH>
                    <TH className="w-[210px]">Asset</TH>
                    <SortableTH
                      className="w-[72px]"
                      onSort={() => sortBy("cvss_score", "desc")}
                      {...sortProps("cvss_score")}
                    >
                      CVSS
                    </SortableTH>
                    <TH className="w-[160px]">Type</TH>
                    <SortableTH
                      className="w-[92px]"
                      onSort={() => sortBy("first_seen_at", "desc")}
                      {...sortProps("first_seen_at")}
                    >
                      Age
                    </SortableTH>
                    <SortableTH
                      className="w-[140px]"
                      onSort={() => sortBy("status", "asc")}
                      {...sortProps("status")}
                    >
                      Status
                    </SortableTH>
                  </TR>
                </THead>
                <TBody>
                  {visibleRows.map((finding) => {
                    const tone = severityTone(effectiveSeverity(finding));
                    const status = findingStatus(finding.status);
                    const cves = finding.cve_ids ?? [];
                    return (
                      <TR
                        key={finding.id}
                        interactive
                        selected={selected.has(finding.id) || findingParam === finding.id}
                        onClick={() => openFinding(finding.id)}
                      >
                        <TD>
                          <Checkbox
                            checked={selected.has(finding.id)}
                            onChange={(checked) => toggleOne(finding.id, checked)}
                            stopPropagation
                            label={<span className="sr-only">Select {finding.title}</span>}
                          />
                        </TD>
                        <TD>
                          <SeverityChip severity={effectiveSeverity(finding)} />
                        </TD>
                        <TD>
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="text-[12.5px] font-medium truncate max-w-[420px]">
                              {finding.title}
                            </span>
                            {cves.slice(0, 2).map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(event) => event.stopPropagation()}
                                title={`${cve} on the NVD`}
                                className="mono text-[10.5px] px-1 py-px rounded bg-crit-wash text-crit hover:underline shrink-0"
                              >
                                {cve}
                              </a>
                            ))}
                            {cves.length > 2 && (
                              <span className="mono text-[10.5px] text-ink-3 shrink-0">
                                +{cves.length - 2}
                              </span>
                            )}
                          </div>
                        </TD>
                        <TD>
                          <Link
                            href={`/surface/${finding.asset_id}`}
                            onClick={(event) => event.stopPropagation()}
                            className="mono text-[11.5px] text-ink-2 hover:text-accent hover:underline truncate block max-w-[196px]"
                            title={finding.asset_value ?? finding.asset_id}
                          >
                            {finding.asset_value ?? `${finding.asset_id.slice(0, 8)}…`}
                          </Link>
                        </TD>
                        <TD>
                          {finding.cvss_score != null ? (
                            <span className={cn("mono text-[12px] font-semibold", tone.text)}>
                              {score(finding.cvss_score, 1)}
                            </span>
                          ) : (
                            <span className="text-ink-3">—</span>
                          )}
                        </TD>
                        <TD>
                          <span
                            className="text-[12px] text-ink-2 truncate block"
                            title={finding.finding_type}
                          >
                            {findingTypeLabel(finding.finding_type)}
                          </span>
                        </TD>
                        <TD>
                          <span
                            className="text-[12px] text-ink-3 whitespace-nowrap"
                            title={finding.first_seen_at}
                          >
                            {ago(finding.first_seen_at)}
                          </span>
                        </TD>
                        <TD>
                          <div className="flex items-center justify-between gap-2">
                            <span className="inline-flex items-center gap-1.5 text-[12px] text-ink-2 whitespace-nowrap">
                              <Dot color={status.dot} />
                              {status.label}
                            </span>
                            {canTriage && (
                              <RowActions>
                                {transitionsFor(finding.status)
                                  .slice(0, 1)
                                  .map((action) => (
                                    <Button
                                      key={action.status}
                                      size="sm"
                                      variant="ghost"
                                      icon={action.icon}
                                      disabled={busyId === finding.id}
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        changeStatus(finding, action.status);
                                      }}
                                    >
                                      {action.label}
                                    </Button>
                                  ))}
                              </RowActions>
                            )}
                          </div>
                        </TD>
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            </div>
          )}

          {visibleRows.length > 0 && rows.length < total && (
            <div className="flex items-center justify-center gap-3 mt-4">
              {rows.length >= MAX_ROWS ? (
                <span className="text-[12px] text-ink-3">
                  Showing the first {num(MAX_ROWS)} — narrow the filters to see the rest.
                </span>
              ) : (
                <Button icon="arrowDown" onClick={() => setPages((p) => p + 1)} loading={busy}>
                  Load {Math.min(PAGE_SIZE, total - rows.length)} more
                </Button>
              )}
            </div>
          )}
        </div>
      </div>

      {canTriage && (
        <BulkBar count={selectedCount} onClear={() => setSelected(new Set())} noun="findings selected">
          {BULK_ACTIONS.map((action) => (
            <BulkAction
              key={action.status}
              primary={action.variant === "primary"}
              disabled={bulkBusy}
              onClick={() => runBulk(action.status)}
            >
              {action.label}
            </BulkAction>
          ))}
        </BulkBar>
      )}

      <Drawer
        open={!!findingParam}
        onClose={closeFinding}
        title={detail?.title ?? "Finding"}
        width={680}
        header={
          detail ? (
            <FindingDetailHeader finding={detail} />
          ) : (
            <span className="text-sm font-semibold">Finding</span>
          )
        }
        footer={
          detail ? (
            <FindingDetailActions
              finding={detail}
              busy={busyId === detail.id}
              canTriage={canTriage}
              onAction={(status) => changeStatus(detail, status)}
            />
          ) : undefined
        }
      >
        {detailLoading && !detail ? (
          <LoadingBlock label="Loading finding" />
        ) : detailError && !detail ? (
          <ErrorState
            error={detailError}
            onRetry={() => {
              if (findingParam) {
                setDetailError(null);
                setDetailLoading(true);
                getSecurityFinding(findingParam)
                  .then(setDetail)
                  .catch((err) => setDetailError((err as Error).message))
                  .finally(() => setDetailLoading(false));
              }
            }}
          />
        ) : detail ? (
          <FindingDetail
            finding={detail}
            busy={busyId === detail.id}
            canTriage={canTriage}
            error={actionError}
            onAction={(status) => changeStatus(detail, status)}
            onOpenScan={openScan}
            onNavigate={closeFinding}
          />
        ) : null}
      </Drawer>
    </div>
  );
}

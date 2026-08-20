"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  cancelSecurityScan,
  listPendingSecurityScans,
  listScans,
  type ScanListItem,
  type ScanListResponse,
  type SecurityScan,
} from "@/app/api";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Icon,
  LoadingBlock,
  RowActions,
  Segmented,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  assetIcon,
  type SegmentOption,
} from "@/components/kit";
import { ago, dateTime, duration, humanise, num } from "@/lib/format";
import { Pagination, StatusChip, triggerLabel, usePoll, useSilentLoad } from "./shared";

const PAGE = 25;
/** How deep we look into the pending queue to report its depth. */
const QUEUE_PROBE = 200;
const POLL_ACTIVE = 6_000;
const POLL_IDLE = 30_000;

type StatusFilter = "all" | "pending" | "running" | "completed" | "failed";

const FILTERS: ReadonlyArray<SegmentOption<StatusFilter>> = [
  { value: "all", label: "All" },
  { value: "pending", label: "Pending" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
];

const CANCELLABLE = new Set(["pending", "running"]);

/**
 * `listScans` is specified to answer with an envelope carrying the joined asset
 * and a total. Older builds answer with a bare array; rather than crashing on
 * `.scans`, we read either shape and lose only the exact total.
 */
function readScans(raw: unknown, status: StatusFilter): { rows: ScanListItem[]; total?: number } {
  if (Array.isArray(raw)) {
    const rows = raw as ScanListItem[];
    return { rows: status === "all" ? rows : rows.filter((scan) => scan.status === status) };
  }
  const envelope = (raw ?? {}) as Partial<ScanListResponse>;
  return { rows: envelope.scans ?? [], total: envelope.total_count };
}

export function ScansSegment({ onCount }: { onCount?: (count: number) => void }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const report = useRef(onCount);
  report.current = onCount;

  const urlStatus = searchParams.get("status");
  const status: StatusFilter = FILTERS.some((filter) => filter.value === urlStatus)
    ? (urlStatus as StatusFilter)
    : "all";

  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [total, setTotal] = useState<number | undefined>(undefined);
  const [offset, setOffset] = useState(0);
  const [queue, setQueue] = useState<SecurityScan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const { loading, begin, done } = useSilentLoad();

  const load = useCallback(async () => {
    begin();
    try {
      const [raw, pending] = await Promise.all([
        listScans({ limit: PAGE, offset, ...(status === "all" ? {} : { status }) }) as Promise<unknown>,
        listPendingSecurityScans(QUEUE_PROBE).catch(() => null),
      ]);
      const parsed = readScans(raw, status);
      setScans(parsed.rows);
      setTotal(parsed.total);
      if (pending) setQueue(pending);
      setError(null);
      report.current?.(pending ? pending.length : (parsed.total ?? parsed.rows.length));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      done();
    }
  }, [offset, status, begin, done]);

  useEffect(() => {
    void load();
  }, [load]);

  const live = useMemo(
    () => scans.some((scan) => CANCELLABLE.has(scan.status)) || (queue?.length ?? 0) > 0,
    [scans, queue],
  );
  usePoll(() => void load(), live ? POLL_ACTIVE : POLL_IDLE);

  function setStatus(next: StatusFilter) {
    const params = new URLSearchParams(searchParams.toString());
    params.set("tab", "scans");
    if (next === "all") params.delete("status");
    else params.set("status", next);
    setOffset(0);
    router.replace(`/ops?${params.toString()}`, { scroll: false });
  }

  async function handleCancel(scan: ScanListItem) {
    setCancelling(scan.id);
    setError(null);
    try {
      await cancelSecurityScan(scan.id);
      // Patch the row now rather than waiting for the next poll.
      setScans((current) =>
        current.map((row) => (row.id === scan.id ? { ...row, status: "cancelled" } : row)),
      );
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCancelling(null);
    }
  }

  const queueDepth = queue?.length ?? null;
  const queueCapped = queueDepth === QUEUE_PROBE;
  const nextUp = queue?.[0] ?? null;
  const hasMore = total != null ? offset + scans.length < total : scans.length === PAGE;

  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-4 md:grid-cols-[minmax(0,260px)_1fr] items-start">
        <Card className="px-[18px] py-3.5">
          <div className="lbl">Queue depth</div>
          <div className="fig text-[30px] mt-1 leading-none">
            {queueDepth == null ? "—" : `${num(queueDepth)}${queueCapped ? "+" : ""}`}
          </div>
          <div className="text-[11.5px] text-ink-2 mt-1.5">
            {nextUp ? (
              <>
                Next up: {humanise(nextUp.scan_type)} at priority <span className="mono">{nextUp.priority}</span>
              </>
            ) : (
              "Nothing waiting to run"
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Scans"
            hint="Every scan this company has queued, run or failed"
            actions={
              <Button size="sm" icon="refresh" onClick={() => void load()}>
                Refresh
              </Button>
            }
          />
          <div className="p-4 flex flex-col gap-2">
            <Segmented options={FILTERS} value={status} onChange={setStatus} ariaLabel="Filter scans by status" />
            <p className="text-[12px] text-ink-2">
              A scan row opens its findings. Pending and running scans can be cancelled from the row.
            </p>
          </div>
        </Card>
      </div>

      <Card>
        {error && (
          <div className="p-4">
            <ErrorState error={error} onRetry={() => void load()} />
          </div>
        )}
        {loading ? (
          <LoadingBlock label="Loading scans" />
        ) : scans.length === 0 ? (
          <EmptyState
            icon="shieldCheck"
            title={status === "all" ? "No scans yet" : `No ${status} scans`}
            description={
              status === "all"
                ? "Scans appear here once discovery queues one or an asset is scanned by hand."
                : "Nothing matches this filter right now."
            }
            action={
              status === "all" ? undefined : (
                <Button size="sm" onClick={() => setStatus("all")}>
                  Show all scans
                </Button>
              )
            }
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Status</TH>
                  <TH>Asset</TH>
                  <TH>Scan</TH>
                  <TH>Trigger</TH>
                  <TH className="text-right">Findings</TH>
                  <TH className="text-right">Duration</TH>
                  <TH>Started</TH>
                  <TH className="w-[104px]" />
                </TR>
              </THead>
              <TBody>
                {scans.map((scan) => (
                  <TR
                    key={scan.id}
                    interactive
                    onClick={() => router.push(`/findings?scan=${scan.id}`)}
                  >
                    <TD>
                      <StatusChip status={scan.status} />
                    </TD>
                    <TD>
                      <Link
                        href={`/surface/${scan.asset_id}`}
                        onClick={(event) => event.stopPropagation()}
                        className="inline-flex items-center gap-1.5 mono text-[12.5px] hover:text-accent-ink hover:underline max-w-[280px]"
                        title={scan.asset_value ?? scan.asset_id}
                      >
                        <Icon name={assetIcon(scan.asset_type)} size={12} className="text-ink-3 shrink-0" />
                        <span className="truncate">{scan.asset_value ?? scan.asset_id}</span>
                      </Link>
                    </TD>
                    <TD className="text-[12.5px]">{humanise(scan.scan_type)}</TD>
                    <TD className="text-ink-2 text-[12.5px]">{triggerLabel(scan.trigger_type)}</TD>
                    <TD className="text-right mono text-[12.5px]">
                      {scan.findings_count == null ? <span className="text-ink-3">—</span> : num(scan.findings_count)}
                    </TD>
                    <TD className="text-right mono text-[12.5px] text-ink-2">
                      {duration(scan.started_at, scan.completed_at)}
                    </TD>
                    <TD className="text-ink-2 text-[12.5px]" title={dateTime(scan.started_at)}>
                      {scan.started_at ? ago(scan.started_at) : "—"}
                    </TD>
                    <TD onClick={(event) => event.stopPropagation()}>
                      {CANCELLABLE.has(scan.status) && (
                        <RowActions>
                          <Button
                            size="sm"
                            variant="danger"
                            icon="ban"
                            loading={cancelling === scan.id}
                            onClick={() => void handleCancel(scan)}
                          >
                            Cancel
                          </Button>
                        </RowActions>
                      )}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            <Pagination
              offset={offset}
              limit={PAGE}
              count={scans.length}
              total={total}
              hasMore={hasMore}
              onOffset={setOffset}
            />
          </>
        )}
      </Card>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  listDiscoveryRuns,
  listSeeds,
  runDiscovery,
  stopDiscovery,
  type DiscoveryRun,
  type DiscoveryStatus,
  type Seed,
} from "@/app/api";
import { useDiscovery, runProgress } from "@/hooks/useDiscovery";
import {
  Bar,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EmptyState,
  ErrorState,
  Icon,
  LoadingBlock,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/kit";
import { cn } from "@/lib/cn";
import { ago, dateTime, duration, num } from "@/lib/format";
import { RunDetailDrawer } from "./RunDetailDrawer";
import { SearchIndexPanel } from "./SearchIndexPanel";
import { Pagination, Slider, StatusChip, triggerLabel, usePoll, useSecondsTick, useSilentLoad } from "./shared";

/**
 * The phases the discovery service actually reports, in the order it walks
 * them (`discovery_service.rs`). A phase it reports that is not one of these —
 * "Cancelled", "Failed", "Asset cap reached" — is shown verbatim instead of
 * being forced into a step.
 */
const PHASES = [
  { key: "initializing", label: "Initialise" },
  { key: "loading seeds", label: "Load seeds" },
  { key: "queuing seeds", label: "Queue seeds" },
  { key: "processing discovery queue", label: "Process queue" },
  { key: "updating risk scores", label: "Score risk" },
  { key: "completed", label: "Complete" },
];

const RUNS_PAGE = 25;
const POLL_ACTIVE = 8_000;
const POLL_IDLE = 45_000;

export function DiscoverySegment() {
  const { status, error: statusError, refresh } = useDiscovery();
  const running = Boolean(status?.running);

  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [seeds, setSeeds] = useState<Seed[]>([]);
  const [offset, setOffset] = useState(0);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedRun, setSelectedRun] = useState<DiscoveryRun | null>(null);
  const { loading, begin, done } = useSilentLoad();

  const load = useCallback(async () => {
    begin();
    try {
      const [runsData, seedsData] = await Promise.all([listDiscoveryRuns(RUNS_PAGE, offset), listSeeds()]);
      setRuns(runsData);
      setSeeds(seedsData);
      setLoadError(null);
    } catch (err) {
      setLoadError((err as Error).message);
    } finally {
      done();
    }
  }, [offset, begin, done]);

  useEffect(() => {
    void load();
  }, [load]);

  // The shell polls discovery status; this only keeps the history table honest.
  usePoll(() => void load(), running ? POLL_ACTIVE : POLL_IDLE);

  const refreshAll = useCallback(async () => {
    await Promise.all([refresh(), load()]);
  }, [refresh, load]);

  return (
    <div className="flex flex-col gap-5">
      {statusError && <ErrorState error={statusError} onRetry={() => void refresh()} />}

      {running ? (
        <LiveRun status={status} onStopped={refreshAll} />
      ) : (
        <StartRun seeds={seeds} onStarted={refreshAll} />
      )}

      <SearchIndexPanel />

      <Card>
        <CardHeader
          title="Run history"
          hint={runs.length > 0 ? `${runs.length} shown` : undefined}
          actions={
            <Button size="sm" icon="refresh" onClick={() => void load()}>
              Refresh
            </Button>
          }
        />
        {loadError && <div className="p-4"><ErrorState error={loadError} onRetry={() => void load()} /></div>}
        {loading ? (
          <LoadingBlock label="Loading runs" />
        ) : runs.length === 0 ? (
          <EmptyState
            icon="activity"
            title={offset > 0 ? "No further runs" : "No discovery runs yet"}
            description={
              offset > 0
                ? "You have reached the end of the history."
                : "Start a run above to find assets from your configured seeds."
            }
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Status</TH>
                  <TH>Trigger</TH>
                  <TH className="text-right">Seeds</TH>
                  <TH className="text-right">Discovered</TH>
                  <TH className="text-right">Updated</TH>
                  <TH className="text-right">Duration</TH>
                  <TH>Started</TH>
                  <TH className="w-10" />
                </TR>
              </THead>
              <TBody>
                {runs.map((run) => (
                  <TR key={run.id} interactive onClick={() => setSelectedRun(run)}>
                    <TD>
                      <StatusChip status={run.status} />
                    </TD>
                    <TD className="text-ink-2 text-[12.5px]">{triggerLabel(run.trigger_type)}</TD>
                    <TD className="text-right mono text-[12.5px]">{num(run.seeds_processed)}</TD>
                    <TD className="text-right mono text-[12.5px]">{num(run.assets_discovered)}</TD>
                    <TD className="text-right mono text-[12.5px] text-ink-2">{num(run.assets_updated)}</TD>
                    <TD className="text-right mono text-[12.5px] text-ink-2">
                      {duration(run.started_at, run.completed_at)}
                    </TD>
                    <TD className="text-ink-2 text-[12.5px]" title={dateTime(run.started_at)}>
                      {run.started_at ? ago(run.started_at) : "—"}
                    </TD>
                    <TD className="text-ink-3">
                      <Icon name="chevronRight" size={13} />
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
            <Pagination
              offset={offset}
              limit={RUNS_PAGE}
              count={runs.length}
              hasMore={runs.length === RUNS_PAGE}
              onOffset={setOffset}
            />
          </>
        )}
      </Card>

      <RunDetailDrawer run={selectedRun} onClose={() => setSelectedRun(null)} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Live run
// ---------------------------------------------------------------------------

function LiveRun({ status, onStopped }: { status: DiscoveryStatus | null; onStopped: () => Promise<void> }) {
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAllErrors, setShowAllErrors] = useState(false);

  // Local clock only — the counters below still come from the shell's poller.
  useSecondsTick(true);

  if (!status) return null;

  const phase = status.current_phase ?? "";
  const phaseIndex = PHASES.findIndex((step) => step.key === phase.toLowerCase());
  const progress = runProgress(status) ?? 0;
  const errors = status.errors ?? [];
  const shownErrors = showAllErrors ? errors : errors.slice(0, 3);
  const hidden = Math.max(errors.length - shownErrors.length, 0);
  const unlisted = Math.max((status.error_count ?? 0) - errors.length, 0);

  async function handleStop() {
    setStopping(true);
    setError(null);
    try {
      await stopDiscovery();
      await onStopped();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStopping(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" aria-hidden="true" />
            Discovery running
          </span>
        }
        hint={
          <>
            {phaseIndex === -1 && phase ? phase : PHASES[Math.max(phaseIndex, 0)]?.label}
            {status.started_at && <> · {duration(status.started_at, null)} elapsed</>}
          </>
        }
        actions={
          <Button
            variant="danger"
            icon="stop"
            onClick={() => void handleStop()}
            loading={stopping}
            title={
              (status.scans_queued ?? 0) > 0
                ? `Stops the run and cancels the ${status.scans_queued} scan${
                    status.scans_queued === 1 ? "" : "s"
                  } it queued`
                : "Stop this discovery run"
            }
          >
            Stop
          </Button>
        }
      />
      <div className="p-4 flex flex-col gap-4">
        {error && <ErrorState error={error} />}

        <Bar value={progress} height={3} />

        <ol className="flex items-center gap-1 flex-wrap">
          {PHASES.map((step, index) => {
            const complete = phaseIndex >= 0 && index < phaseIndex;
            const current = phaseIndex >= 0 && index === phaseIndex;
            return (
              <li key={step.key} className="flex items-center gap-1">
                <span
                  className={cn(
                    "inline-flex items-center gap-1.5 h-[22px] px-2 rounded-[5px] text-[11.5px] font-medium",
                    current ? "bg-accent-wash text-accent-ink" : complete ? "text-ink-2" : "text-ink-3",
                  )}
                >
                  {complete ? (
                    <Icon name="check" size={11} strokeWidth={2.2} />
                  ) : current ? (
                    <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" aria-hidden="true" />
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-full border border-rule-2" aria-hidden="true" />
                  )}
                  {step.label}
                </span>
                {index < PHASES.length - 1 && <span className="w-3 h-px bg-rule" aria-hidden="true" />}
              </li>
            );
          })}
          {phaseIndex === -1 && phase && (
            <li className="inline-flex items-center h-[22px] px-2 rounded-[5px] text-[11.5px] font-medium bg-surface-2 text-ink-2">
              {phase}
            </li>
          )}
        </ol>

        <div className="grid grid-cols-2 md:grid-cols-6 bg-surface-2 border border-rule rounded-lg divide-x divide-rule">
          {[
            {
              label: "Seeds",
              value: (
                <>
                  {num(status.seeds_processed)}
                  <span className="text-ink-3">/{num(status.seeds_total ?? 0)}</span>
                </>
              ),
            },
            { label: "Discovered", value: num(status.assets_discovered) },
            { label: "Updated", value: num(status.assets_updated ?? 0) },
            { label: "Queue pending", value: num(status.queue_pending ?? 0) },
            // Auto-scans this run queued. They stop with the run, so it matters
            // that the operator can see how much stopping it will take down.
            { label: "Scans queued", value: num(status.scans_queued ?? 0) },
            {
              label: "Errors",
              value: <span className={status.error_count > 0 ? "text-crit" : undefined}>{num(status.error_count)}</span>,
            },
          ].map((cell) => (
            <div key={cell.label} className="px-3.5 py-3">
              <div className="lbl">{cell.label}</div>
              <div className="fig text-[21px] mt-1 leading-none">{cell.value}</div>
            </div>
          ))}
        </div>

        {errors.length > 0 && (
          <div className="rounded-lg border border-crit/40 bg-crit-wash p-3">
            <div className="lbl text-crit mb-1.5">Errors</div>
            <ul className="flex flex-col gap-1">
              {shownErrors.map((message, index) => (
                <li key={index} className="mono text-[11.5px] text-ink break-words">
                  {message}
                </li>
              ))}
            </ul>
            {errors.length > 3 && (
              <button
                type="button"
                onClick={() => setShowAllErrors((open) => !open)}
                className="mt-1.5 text-[11.5px] font-medium text-crit hover:underline"
              >
                {showAllErrors ? "Show fewer" : `and ${hidden} more`}
              </button>
            )}
            {unlisted > 0 && (
              <p className="mt-1.5 text-[11.5px] text-ink-2">
                {num(unlisted)} further error{unlisted === 1 ? " was" : "s were"} counted but not reported by the
                run.
              </p>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Start a run
// ---------------------------------------------------------------------------

function StartRun({ seeds, onStarted }: { seeds: Seed[]; onStarted: () => Promise<void> }) {
  const [maxDepth, setMaxDepth] = useState(3);
  const [threshold, setThreshold] = useState(0.7);
  const [picked, setPicked] = useState<Set<string> | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Until someone touches the list, every seed is in — which is also what the
  // backend does with an empty `seed_ids`.
  const selected = useMemo(() => picked ?? new Set(seeds.map((seed) => seed.id)), [picked, seeds]);
  const allSelected = seeds.length > 0 && selected.size === seeds.length;

  function toggleSeed(id: string) {
    setPicked(() => {
      const next = new Set(selected);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleStart() {
    setStarting(true);
    setError(null);
    try {
      await runDiscovery({
        max_depth: maxDepth,
        auto_scan_threshold: threshold,
        ...(allSelected ? {} : { seed_ids: Array.from(selected) }),
      });
      await onStarted();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStarting(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title="Start a discovery run"
        hint={
          seeds.length === 0
            ? "No seeds configured yet"
            : allSelected
              ? `All ${seeds.length} seed${seeds.length === 1 ? "" : "s"}`
              : `${selected.size} of ${seeds.length} seeds`
        }
        actions={
          <Button
            variant="primary"
            icon="play"
            onClick={() => void handleStart()}
            loading={starting}
            disabled={seeds.length === 0 || selected.size === 0}
          >
            Start run
          </Button>
        }
      />
      <div className="p-4 grid gap-5 lg:grid-cols-2">
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <span className="lbl">Seeds</span>
            {seeds.length > 0 && (
              <Checkbox
                checked={allSelected}
                indeterminate={selected.size > 0 && !allSelected}
                onChange={(next) => setPicked(next ? new Set(seeds.map((seed) => seed.id)) : new Set())}
                label={<span className="text-[12px] text-ink-2">Select all</span>}
              />
            )}
          </div>
          {seeds.length === 0 ? (
            <p className="text-[12.5px] text-ink-2">
              Discovery walks out from seeds. Add one in the Seeds segment first.
            </p>
          ) : (
            <div className="border border-rule rounded-md max-h-[168px] overflow-y-auto divide-y divide-rule">
              {seeds.map((seed) => (
                <div key={seed.id} className="flex items-center gap-2.5 px-2.5 h-[32px] hover:bg-surface-2">
                  <Checkbox
                    checked={selected.has(seed.id)}
                    onChange={() => toggleSeed(seed.id)}
                    className="flex-1 min-w-0"
                    label={<span className="mono text-[12px] truncate">{seed.value}</span>}
                  />
                  <span className="lbl shrink-0">{seed.seed_type}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col gap-4">
          <Slider
            label="Max depth"
            value={maxDepth}
            min={1}
            max={5}
            onChange={setMaxDepth}
            minHint="1 · shallow"
            maxHint="5 · deep"
          />
          <div>
            <Slider
              label="Auto-scan threshold"
              value={threshold}
              min={0}
              max={1}
              step={0.05}
              onChange={setThreshold}
              display={threshold.toFixed(2)}
              minHint="0.00 · scan everything"
              maxHint="1.00 · certainties only"
            />
            <p className="text-[12px] text-ink-2 mt-2">
              Every newly discovered asset whose confidence lands at or above{" "}
              <span className="mono text-ink">{threshold.toFixed(2)}</span> is queued for a security scan
              automatically. Lower it to scan more of what the run turns up; raise it to scan only what the run is
              sure about. At <span className="mono text-ink">0.00</span> everything is queued.
            </p>
          </div>
          {error && <ErrorState error={error} />}
        </div>
      </div>
    </Card>
  );
}

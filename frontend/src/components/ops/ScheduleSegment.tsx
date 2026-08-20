"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createDiscoverySchedule,
  listDiscoverySchedules,
  updateDiscoverySchedule,
  type DiscoverySchedule,
} from "@/app/api";
import {
  Button,
  Card,
  CardHeader,
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
  Toggle,
} from "@/components/kit";
import { ScheduleDrawer, ScheduleFields, scheduleTimeZone, type ScheduleForm } from "./ScheduleDrawer";
import { cronGloss, formatInZone, usePoll, useSilentLoad, useTimeZones } from "./shared";

const POLL_MS = 30_000;

function emptyForm(timezone: string): ScheduleForm {
  return { name: "", cron: "", enabled: true, maxDepth: 3, threshold: 0.7, timezone };
}

export function ScheduleSegment({ onCount }: { onCount?: (count: number) => void }) {
  const report = useRef(onCount);
  report.current = onCount;

  const { zones, local } = useTimeZones();
  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [form, setForm] = useState<ScheduleForm>(() => emptyForm(local));
  const [creating, setCreating] = useState(false);
  // Tracked by id so a background refresh keeps the open drawer in sync.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const { loading, begin, done } = useSilentLoad();

  const load = useCallback(async () => {
    begin();
    try {
      const data = await listDiscoverySchedules();
      setSchedules(data);
      setError(null);
      report.current?.(data.filter((schedule) => schedule.enabled).length);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      done();
    }
  }, [begin, done]);

  useEffect(() => {
    void load();
  }, [load]);

  usePoll(() => void load(), POLL_MS);

  const nextUp = useMemo(() => {
    return schedules
      .filter((schedule) => schedule.enabled && schedule.next_run_at)
      .sort(
        (a, b) => new Date(a.next_run_at as string).getTime() - new Date(b.next_run_at as string).getTime(),
      )[0];
  }, [schedules]);

  const activeCount = schedules.filter((schedule) => schedule.enabled).length;
  const editing = schedules.find((schedule) => schedule.id === editingId) ?? null;

  async function handleCreate() {
    if (!form.name.trim()) {
      setFormError("A schedule needs a name.");
      return;
    }
    if (!form.cron.trim()) {
      setFormError("A schedule needs a cron expression.");
      return;
    }
    setCreating(true);
    setFormError(null);
    try {
      await createDiscoverySchedule({
        name: form.name.trim(),
        cron: form.cron.trim(),
        enabled: form.enabled,
        config: {
          max_depth: form.maxDepth,
          auto_scan_threshold: form.threshold,
          timezone: form.timezone,
        },
      });
      setForm(emptyForm(form.timezone));
      await load();
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function handleToggle(schedule: DiscoverySchedule) {
    const next = !schedule.enabled;
    setTogglingId(schedule.id);
    setError(null);
    // Flip the row now; the reload confirms it.
    setSchedules((current) =>
      current.map((row) => (row.id === schedule.id ? { ...row, enabled: next } : row)),
    );
    try {
      await updateDiscoverySchedule(schedule.id, { enabled: next });
      await load();
    } catch (err) {
      setError((err as Error).message);
      setSchedules((current) =>
        current.map((row) => (row.id === schedule.id ? { ...row, enabled: schedule.enabled } : row)),
      );
    } finally {
      setTogglingId(null);
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-4 sm:grid-cols-3">
        <Card className="px-[18px] py-3.5">
          <div className="lbl">Schedules</div>
          <div className="fig text-[30px] mt-1 leading-none">{schedules.length}</div>
        </Card>
        <Card className="px-[18px] py-3.5">
          <div className="lbl">Enabled</div>
          <div className="fig text-[30px] mt-1 leading-none">{activeCount}</div>
        </Card>
        <Card className="px-[18px] py-3.5">
          <div className="lbl">Next run</div>
          <div className="text-[13px] mono mt-2 leading-tight">
            {nextUp ? formatInZone(nextUp.next_run_at, scheduleTimeZone(nextUp)) : "—"}
          </div>
          {nextUp && (
            <div className="text-[11.5px] text-ink-2 mt-1 truncate">
              {nextUp.name} · {scheduleTimeZone(nextUp)}
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,340px)_1fr] items-start">
        <Card>
          <CardHeader title="Create a schedule" hint="Cron, in a zone you choose" />
          <form
            className="p-4 flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void handleCreate();
            }}
          >
            <ScheduleFields form={form} onChange={setForm} zones={zones} idPrefix="schedule-new" />
            {formError && <ErrorState error={formError} />}
            <Button type="submit" variant="primary" icon="plus" loading={creating} disabled={!form.name.trim()}>
              Create schedule
            </Button>
          </form>
        </Card>

        <Card>
          <CardHeader
            title="Scheduled discovery"
            hint={schedules.length > 0 ? `${activeCount} of ${schedules.length} enabled` : undefined}
            actions={
              <Button size="sm" icon="refresh" onClick={() => void load()}>
                Refresh
              </Button>
            }
          />
          {error && (
            <div className="p-4">
              <ErrorState error={error} onRetry={() => void load()} />
            </div>
          )}
          {loading ? (
            <LoadingBlock label="Loading schedules" />
          ) : schedules.length === 0 ? (
            <EmptyState
              icon="clock"
              title="No schedules yet"
              description="Create a cron schedule and discovery runs itself — no one has to remember to press Start."
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Name</TH>
                  <TH>Cron</TH>
                  <TH>Last run</TH>
                  <TH>Next run</TH>
                  <TH className="w-[86px]">Enabled</TH>
                  <TH className="w-10" />
                </TR>
              </THead>
              <TBody>
                {schedules.map((schedule) => {
                  const zone = scheduleTimeZone(schedule);
                  const gloss = cronGloss(schedule.cron);
                  return (
                    <TR key={schedule.id} interactive onClick={() => setEditingId(schedule.id)}>
                      <TD>
                        <div className="text-[12.5px] font-medium truncate max-w-[200px]">{schedule.name}</div>
                        <div className="text-[11px] text-ink-3 truncate max-w-[200px]">{zone}</div>
                      </TD>
                      <TD>
                        <div className="mono text-[12px]">{schedule.cron}</div>
                        {gloss && <div className="text-[11px] text-ink-3">{gloss}</div>}
                      </TD>
                      <TD className="text-ink-2 text-[12.5px] whitespace-nowrap">
                        {formatInZone(schedule.last_run_at, zone)}
                      </TD>
                      <TD className="text-ink-2 text-[12.5px] whitespace-nowrap">
                        {schedule.enabled ? formatInZone(schedule.next_run_at, zone) : "—"}
                      </TD>
                      <TD onClick={(event) => event.stopPropagation()}>
                        <Toggle
                          checked={schedule.enabled}
                          disabled={togglingId === schedule.id}
                          onChange={() => void handleToggle(schedule)}
                          label={`${schedule.enabled ? "Disable" : "Enable"} ${schedule.name}`}
                        />
                      </TD>
                      <TD className="text-ink-3">
                        <Icon name="chevronRight" size={13} />
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </Card>
      </div>

      <ScheduleDrawer
        schedule={editing}
        zones={zones}
        onClose={() => setEditingId(null)}
        onSaved={load}
      />
    </div>
  );
}

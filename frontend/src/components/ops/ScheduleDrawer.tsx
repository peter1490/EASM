"use client";

import { useEffect, useRef, useState } from "react";
import { deleteDiscoverySchedule, updateDiscoverySchedule, type DiscoverySchedule } from "@/app/api";
import { Button, Drawer, ErrorState, Input, Label, Select, Toggle } from "@/components/kit";
import { cronGloss, formatInZone, Slider } from "./shared";

export type ScheduleForm = {
  name: string;
  cron: string;
  enabled: boolean;
  maxDepth: number;
  threshold: number;
  timezone: string;
};

export function scheduleConfigNumber(
  schedule: DiscoverySchedule,
  key: "max_depth" | "auto_scan_threshold",
  fallback: number,
): number {
  const raw = (schedule.config as Record<string, unknown> | undefined)?.[key];
  return typeof raw === "number" && !Number.isNaN(raw) ? raw : fallback;
}

export function scheduleTimeZone(schedule: DiscoverySchedule, fallback = "UTC"): string {
  const raw = (schedule.config as Record<string, unknown> | undefined)?.timezone;
  return typeof raw === "string" && raw.trim().length > 0 ? raw : fallback;
}

export function formFromSchedule(schedule: DiscoverySchedule): ScheduleForm {
  return {
    name: schedule.name,
    cron: schedule.cron,
    enabled: schedule.enabled,
    maxDepth: scheduleConfigNumber(schedule, "max_depth", 3),
    threshold: scheduleConfigNumber(schedule, "auto_scan_threshold", 0.7),
    timezone: scheduleTimeZone(schedule),
  };
}

/** The fields a schedule has, used by both the create form and the edit drawer. */
export function ScheduleFields({
  form,
  onChange,
  zones,
  idPrefix,
}: {
  form: ScheduleForm;
  onChange: (next: ScheduleForm) => void;
  zones: string[];
  idPrefix: string;
}) {
  const gloss = cronGloss(form.cron);
  return (
    <div className="flex flex-col gap-3.5">
      <div>
        <Label>Name</Label>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(event) => onChange({ ...form, name: event.target.value })}
          placeholder="Daily discovery"
        />
      </div>

      <div>
        <Label>Cron expression</Label>
        <Input
          id={`${idPrefix}-cron`}
          value={form.cron}
          onChange={(event) => onChange({ ...form, cron: event.target.value })}
          placeholder="0 3 * * *"
          className="mono"
        />
        <p className="text-[11.5px] text-ink-3 mt-1.5">
          {gloss ? (
            <span className="text-ink-2">{gloss}</span>
          ) : (
            "5 to 7 fields (minute hour day month weekday); seconds and year optional."
          )}
        </p>
      </div>

      <div>
        <Label>Timezone</Label>
        <Select
          id={`${idPrefix}-timezone`}
          value={form.timezone}
          onChange={(event) => onChange({ ...form, timezone: event.target.value })}
        >
          {zones.map((zone) => (
            <option key={zone} value={zone}>
              {zone}
            </option>
          ))}
        </Select>
        <p className="text-[11.5px] text-ink-3 mt-1.5">
          The cron expression is read in this zone, and this schedule&apos;s run times are shown in it.
        </p>
      </div>

      <div className="flex items-center gap-2.5">
        <Toggle
          checked={form.enabled}
          onChange={(next) => onChange({ ...form, enabled: next })}
          label="Schedule enabled"
        />
        <span className="text-[12.5px] text-ink-2">{form.enabled ? "Enabled" : "Disabled"}</span>
      </div>

      <Slider
        label="Max depth"
        value={form.maxDepth}
        min={1}
        max={5}
        onChange={(next) => onChange({ ...form, maxDepth: next })}
        minHint="1 · shallow"
        maxHint="5 · deep"
      />

      <Slider
        label="Auto-scan threshold"
        value={form.threshold}
        min={0}
        max={1}
        step={0.05}
        display={form.threshold.toFixed(2)}
        onChange={(next) => onChange({ ...form, threshold: next })}
        minHint="0.00 · scan everything"
        maxHint="1.00 · certainties only"
      />
    </div>
  );
}

/**
 * Edit one schedule. Deleting is reachable from in here — the drawer swaps to a
 * confirmation rather than stacking a second floating layer over itself.
 */
export function ScheduleDrawer({
  schedule,
  zones,
  onClose,
  onSaved,
}: {
  schedule: DiscoverySchedule | null;
  zones: string[];
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const [form, setForm] = useState<ScheduleForm | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Seed the form once per schedule. A background refresh of the list hands us
  // a new object for the same row; that must not throw away an edit in flight.
  const loadedId = useRef<string | null>(null);
  useEffect(() => {
    if (!schedule) {
      loadedId.current = null;
      setForm(null);
      return;
    }
    if (loadedId.current === schedule.id) return;
    loadedId.current = schedule.id;
    setForm(formFromSchedule(schedule));
    setConfirming(false);
    setError(null);
  }, [schedule]);

  if (!schedule || !form) return null;
  const zone = form.timezone;

  async function handleSave() {
    if (!schedule || !form) return;
    if (!form.name.trim()) {
      setError("A schedule needs a name.");
      return;
    }
    if (!form.cron.trim()) {
      setError("A schedule needs a cron expression.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await updateDiscoverySchedule(schedule.id, {
        name: form.name.trim(),
        cron: form.cron.trim(),
        enabled: form.enabled,
        config: {
          max_depth: form.maxDepth,
          auto_scan_threshold: form.threshold,
          timezone: form.timezone,
        },
      });
      await onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!schedule) return;
    setDeleting(true);
    setError(null);
    try {
      await deleteDiscoverySchedule(schedule.id);
      await onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
      setDeleting(false);
    }
  }

  return (
    <Drawer
      open
      onClose={onClose}
      title={confirming ? "Delete schedule" : "Edit schedule"}
      width={520}
      header={
        <div className="min-w-0">
          <h2 className="text-sm font-semibold tracking-[-0.012em] truncate">
            {confirming ? "Delete schedule" : schedule.name}
          </h2>
          <p className="mono text-[11.5px] text-ink-3 mt-0.5">{schedule.cron}</p>
        </div>
      }
      footer={
        confirming ? (
          <>
            <Button onClick={() => setConfirming(false)} disabled={deleting}>
              Cancel
            </Button>
            <div className="flex-1" />
            <Button variant="danger" icon="trash" loading={deleting} onClick={() => void handleDelete()}>
              Delete schedule
            </Button>
          </>
        ) : (
          <>
            <Button variant="danger" icon="trash" onClick={() => setConfirming(true)} disabled={saving}>
              Delete
            </Button>
            <div className="flex-1" />
            <Button onClick={onClose} disabled={saving}>
              Cancel
            </Button>
            <Button variant="primary" icon="check" loading={saving} onClick={() => void handleSave()}>
              Save changes
            </Button>
          </>
        )
      }
    >
      <div className="flex flex-col gap-4">
        {error && <ErrorState error={error} />}

        {confirming ? (
          <>
            <p className="text-[12.5px] text-ink">
              <span className="font-semibold">{schedule.name}</span> will stop running. Discovery runs it has already
              made are kept; only the schedule itself is removed.
            </p>
            <div className="rounded-lg border border-rule bg-surface-2 p-3">
              <div className="mono text-[12px]">{schedule.cron}</div>
              <div className="text-[11.5px] text-ink-2 mt-1">
                Next run would have been {formatInZone(schedule.next_run_at, zone)} ({zone})
              </div>
            </div>
          </>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3 rounded-lg border border-rule bg-surface-2 p-3">
              <div>
                <div className="lbl">Last run</div>
                <div className="text-[12.5px] mt-0.5">{formatInZone(schedule.last_run_at, zone)}</div>
              </div>
              <div>
                <div className="lbl">Next run</div>
                <div className="text-[12.5px] mt-0.5">{formatInZone(schedule.next_run_at, zone)}</div>
              </div>
              <div className="col-span-2 text-[11.5px] text-ink-3">Shown in {zone}</div>
            </div>

            <ScheduleFields form={form} onChange={setForm} zones={zones} idPrefix="schedule-edit" />
          </>
        )}
      </div>
    </Drawer>
  );
}

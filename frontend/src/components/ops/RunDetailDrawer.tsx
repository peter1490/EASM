"use client";

import { useEffect, useState } from "react";
import { getDiscoveryRun, type DiscoveryRun } from "@/app/api";
import { Drawer, ErrorState, Spinner } from "@/components/kit";
import { dateTime, duration, num } from "@/lib/format";
import { DetailRow, StatusChip, triggerLabel } from "./shared";

/**
 * A discovery run, opened from the history table. The row already carries the
 * counters, so they render immediately; `getDiscoveryRun` then fills in the
 * config and any error message without the drawer ever showing an empty frame.
 */
export function RunDetailDrawer({ run, onClose }: { run: DiscoveryRun | null; onClose: () => void }) {
  const [detail, setDetail] = useState<DiscoveryRun | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runId = run?.id ?? null;

  useEffect(() => {
    if (!runId) {
      setDetail(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    getDiscoveryRun(runId)
      .then((data) => {
        if (!cancelled) setDetail(data);
      })
      .catch((err: Error) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [runId]);

  if (!run) return null;
  const shown = detail ?? run;
  const config = shown.config ?? {};
  const hasConfig = Object.keys(config).length > 0;

  return (
    <Drawer
      open
      onClose={onClose}
      title="Discovery run"
      width={560}
      header={
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center gap-2">
            <StatusChip status={shown.status} />
            {loading && <Spinner size={12} />}
          </div>
          <h2 className="text-sm font-semibold tracking-[-0.012em]">Discovery run</h2>
          <code className="mono text-[11px] text-ink-3 break-all">{shown.id}</code>
        </div>
      }
    >
      <div className="flex flex-col gap-4">
        {error && <ErrorState error={error} />}

        <div className="grid grid-cols-4 bg-surface-2 border border-rule rounded-lg divide-x divide-rule">
          {[
            { label: "Seeds", value: num(shown.seeds_processed) },
            { label: "Found", value: num(shown.assets_discovered) },
            { label: "Updated", value: num(shown.assets_updated) },
            { label: "Duration", value: duration(shown.started_at, shown.completed_at) },
          ].map((cell) => (
            <div key={cell.label} className="px-3 py-2.5">
              <div className="lbl">{cell.label}</div>
              <div className="fig text-[17px] mt-1 leading-none">{cell.value}</div>
            </div>
          ))}
        </div>

        <div>
          <DetailRow label="Trigger">{triggerLabel(shown.trigger_type)}</DetailRow>
          <DetailRow label="Started">{shown.started_at ? dateTime(shown.started_at) : "Not started"}</DetailRow>
          <DetailRow label="Completed">
            {shown.completed_at ? dateTime(shown.completed_at) : "In progress"}
          </DetailRow>
          <DetailRow label="Created">{dateTime(shown.created_at)}</DetailRow>
        </div>

        {shown.error_message && (
          <div className="rounded-lg border border-crit/40 bg-crit-wash p-3">
            <div className="lbl text-crit mb-1">Error</div>
            <p className="text-[12px] text-ink break-words">{shown.error_message}</p>
          </div>
        )}

        <div>
          <div className="lbl mb-1.5">Configuration</div>
          {hasConfig ? (
            <pre className="mono text-[11.5px] leading-relaxed bg-surface-2 border border-rule rounded-lg p-3 overflow-x-auto max-h-64 overflow-y-auto">
              {JSON.stringify(config, null, 2)}
            </pre>
          ) : (
            <p className="text-[12px] text-ink-3">
              {loading ? "Loading configuration…" : "This run recorded no configuration."}
            </p>
          )}
        </div>
      </div>
    </Drawer>
  );
}

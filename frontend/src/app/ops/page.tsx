"use client";

import { Suspense, useCallback, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { LoadingBlock, PageHeader, Segmented, type SegmentOption } from "@/components/kit";
import { useDiscovery } from "@/hooks/useDiscovery";
import { duration } from "@/lib/format";
import { DiscoverySegment } from "@/components/ops/DiscoverySegment";
import { SeedsSegment } from "@/components/ops/SeedsSegment";
import { ScansSegment } from "@/components/ops/ScansSegment";
import { ScheduleSegment } from "@/components/ops/ScheduleSegment";
import { ExclusionsSegment } from "@/components/ops/ExclusionsSegment";

/**
 * Ops — everything that runs on its own: discovery, the seeds it walks from,
 * the scans it queues, the schedule that starts it and the exclusions that keep
 * it out of what is not ours.
 *
 * The segment lives in `?tab=`, so "the schedule screen" is a link you can send
 * someone. It replaces `/discovery` (five tabs of its own) and the Scans tab of
 * `/security`.
 */

const SEGMENTS = ["discovery", "seeds", "scans", "schedule", "exclusions"] as const;
type Segment = (typeof SEGMENTS)[number];

const LABELS: Record<Segment, string> = {
  discovery: "Discovery",
  seeds: "Seeds",
  scans: "Scans",
  schedule: "Schedule",
  exclusions: "Exclusions",
};

function isSegment(value: string | null): value is Segment {
  return value != null && (SEGMENTS as readonly string[]).includes(value);
}

export default function OpsPage() {
  return (
    <Suspense fallback={<LoadingBlock label="Loading Ops" />}>
      <Ops />
    </Suspense>
  );
}

function Ops() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { status } = useDiscovery();

  const tabParam = searchParams.get("tab");
  const tab: Segment = isSegment(tabParam) ? tabParam : "discovery";

  // Counts arrive from whichever segments have loaded; a badge simply stays
  // absent until its segment has something true to report.
  const [counts, setCounts] = useState<Partial<Record<Segment, number>>>({});
  const report = useCallback(
    (key: Segment) => (value: number) =>
      setCounts((current) => (current[key] === value ? current : { ...current, [key]: value })),
    [],
  );

  function goTo(next: Segment) {
    const params = new URLSearchParams(searchParams.toString());
    params.set("tab", next);
    if (next !== "scans") params.delete("status");
    router.replace(`/ops?${params.toString()}`, { scroll: false });
  }

  const options: Array<SegmentOption<Segment>> = SEGMENTS.map((segment) => ({
    value: segment,
    label: LABELS[segment],
    badge: segment === "discovery" ? undefined : counts[segment],
  }));

  const running = Boolean(status?.running);

  return (
    <div className="h-full flex flex-col min-h-0">
      <div className="px-6 pt-4 pb-3 shrink-0 border-b border-rule">
        <PageHeader
          title="Ops"
          hint="Discovery, seeds, scans, schedule and exclusions — everything the platform runs on its own."
          actions={
            running && tab !== "discovery" ? (
              <button
                type="button"
                onClick={() => goTo("discovery")}
                className="inline-flex items-center gap-2 h-[30px] px-[11px] rounded-md border border-accent/40 bg-accent-wash text-accent-ink text-[12.5px] font-medium hover:border-accent"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" aria-hidden="true" />
                Discovery running
                {status?.started_at && <span className="mono">{duration(status.started_at, null)}</span>}
              </button>
            ) : undefined
          }
        />
        <div className="mt-3.5">
          <Segmented options={options} value={tab} onChange={goTo} ariaLabel="Ops sections" />
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-6 py-5">
        {tab === "discovery" && <DiscoverySegment />}
        {tab === "seeds" && <SeedsSegment onCount={report("seeds")} />}
        {tab === "scans" && <ScansSegment onCount={report("scans")} />}
        {tab === "schedule" && <ScheduleSegment onCount={report("schedule")} />}
        {tab === "exclusions" && <ExclusionsSegment onCount={report("exclusions")} />}
      </div>
    </div>
  );
}

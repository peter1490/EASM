"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { getDiscoveryStatus, type DiscoveryStatus } from "@/app/api";
import { useAuth } from "@/context/AuthContext";

/**
 * One poller for discovery status, shared by everything that needs it.
 *
 * The previous build polled `getDiscoveryStatus` independently from the
 * dashboard, the asset inventory and the discovery page — three timers hitting
 * the same endpoint every five seconds, and three copies of the same banner.
 * Now it is polled once here and surfaced as a hairline in the top bar.
 */

interface DiscoveryContextValue {
  status: DiscoveryStatus | null;
  error: string | null;
  /** Reads the status now and returns it, or null if the read failed or landed
   *  after a company switch. The poller schedules from the returned value. */
  refresh: () => Promise<DiscoveryStatus | null>;
}

const DiscoveryContext = createContext<DiscoveryContextValue>({
  status: null,
  error: null,
  refresh: async () => null,
});

const IDLE_MS = 30_000;
const ACTIVE_MS = 4_000;

export function DiscoveryProvider({ children }: { children: ReactNode }) {
  const { companyId } = useAuth();
  const [status, setStatus] = useState<DiscoveryStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isRunning = Boolean(status?.running);

  // A poll started before a company switch must not land after it.
  const activeCompany = useRef(companyId);

  // Declared before the poll below, so the poll starts on a company change with
  // the ref already naming the company it is starting for, and with the
  // previous company's run cleared out of the top-bar hairline.
  useEffect(() => {
    activeCompany.current = companyId;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setStatus(null);
    setError(null);
  }, [companyId]);

  const refresh = useCallback(async (): Promise<DiscoveryStatus | null> => {
    const requestedFor = activeCompany.current;
    try {
      const next = await getDiscoveryStatus();
      if (activeCompany.current !== requestedFor) return null;
      setStatus(next);
      setError(null);
      return next;
    } catch (err) {
      if (activeCompany.current !== requestedFor) return null;
      setError((err as Error).message);
      return null;
    }
  }, []);

  /** The company the loop below has already read for. */
  const polledFor = useRef<string | null>(null);

  /**
   * The poll. It re-runs on `isRunning` as well as on the company, because both
   * decide how long the next read waits, and both used to be read too late:
   *
   *   - Inside `tick`, `refresh` has only *queued* its state update, so the
   *     status it just read was not observable through state yet. Scheduling
   *     from the returned value means the read that first sees a run start is
   *     followed 4s later, not 30s later.
   *   - Outside `tick`, a run can start from this app -- the ops page starts
   *     one and calls `refresh` -- while the loop is parked on the idle 30s.
   *     Re-running on `isRunning` pulls that next read forward instead of
   *     leaving the top-bar hairline frozen for half a minute.
   *
   * A re-run for the cadence alone only re-arms the timer: the status is
   * already current, so there is nothing to read yet.
   */
  useEffect(() => {
    if (!companyId) {
      polledFor.current = null;
      return;
    }

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      const next = await refresh();
      if (cancelled) return;
      // `isRunning` is this effect's own -- the last committed status -- and is
      // the best guess when a read fails; dropping to idle mid-run would be
      // wrong.
      timer = setTimeout(tick, (next ? next.running : isRunning) ? ACTIVE_MS : IDLE_MS);
    };

    if (polledFor.current === companyId) {
      timer = setTimeout(tick, isRunning ? ACTIVE_MS : IDLE_MS);
    } else {
      polledFor.current = companyId;
      void tick();
    }

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [refresh, companyId, isRunning]);

  return <DiscoveryContext.Provider value={{ status, error, refresh }}>{children}</DiscoveryContext.Provider>;
}

export function useDiscovery() {
  return useContext(DiscoveryContext);
}

/** Fraction of the current run that is complete, or null when idle. */
export function runProgress(status: DiscoveryStatus | null): number | null {
  if (!status?.running) return null;
  const total = status.seeds_total ?? 0;
  if (total <= 0) return 0.05;
  return Math.min(0.98, Math.max(0.02, status.seeds_processed / total));
}

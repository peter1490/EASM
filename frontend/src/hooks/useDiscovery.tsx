"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { getDiscoveryStatus, type DiscoveryStatus } from "@/app/api";

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
  refresh: () => Promise<void>;
}

const DiscoveryContext = createContext<DiscoveryContextValue>({
  status: null,
  error: null,
  refresh: async () => {},
});

const IDLE_MS = 30_000;
const ACTIVE_MS = 4_000;

export function DiscoveryProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<DiscoveryStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Read inside the polling loop so the cadence follows the live value rather
  // than the one captured when the effect first ran.
  const running = useRef(false);
  running.current = Boolean(status?.running);

  const refresh = useCallback(async () => {
    try {
      const next = await getDiscoveryStatus();
      setStatus(next);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      await refresh();
      if (cancelled) return;
      timer = setTimeout(tick, running.current ? ACTIVE_MS : IDLE_MS);
    };

    void tick();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [refresh]);

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

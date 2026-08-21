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
  const { companyId } = useAuth();
  const [status, setStatus] = useState<DiscoveryStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Read inside the polling loop so the cadence follows the live value rather
  // than the one captured when the effect first ran.
  const running = useRef(false);
  running.current = Boolean(status?.running);

  // A poll started before a company switch must not land after it.
  const activeCompany = useRef(companyId);
  activeCompany.current = companyId;

  const refresh = useCallback(async () => {
    const requestedFor = activeCompany.current;
    try {
      const next = await getDiscoveryStatus();
      if (activeCompany.current !== requestedFor) return;
      setStatus(next);
      setError(null);
    } catch (err) {
      if (activeCompany.current !== requestedFor) return;
      setError((err as Error).message);
    }
  }, []);

  // Discovery status is company-scoped, so the poll restarts whenever the
  // active company changes. Clearing first means the top-bar hairline never
  // keeps showing the run of the company we just left.
  useEffect(() => {
    setStatus(null);
    setError(null);
    if (!companyId) return;

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
  }, [refresh, companyId]);

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

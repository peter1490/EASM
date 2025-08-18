"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getDiscoveryStatus, listAssets, type Asset } from "@/app/api";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [minConf, setMinConf] = useState(0);
  const [discoveryRunning, setDiscoveryRunning] = useState(false);

  async function refresh(conf = minConf) {
    try {
      const data = await listAssets(conf);
      const sorted = [...data].sort((a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
      setAssets(sorted);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => {
    let mounted = true;
    let iv: NodeJS.Timeout | null = null;
    async function tick() {
      try {
        const s = await getDiscoveryStatus();
        if (!mounted) return;
        setDiscoveryRunning(s.running);
      } catch {
        // ignore
      }
      try {
        await refresh(minConf);
      } catch {
        // ignore
      }
      iv = setTimeout(tick, 1500);
    }
    tick();
    return () => {
      mounted = false;
      if (iv) clearTimeout(iv);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [minConf]);

  // manual refresh when slider changes is handled by the polling effect

  return (
    <div className="min-h-screen p-6 sm:p-10 bg-background text-foreground">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Assets</h1>
        <Link href="/" className="text-sm underline">Back</Link>
      </div>

      {error && <div className="mb-4 text-sm text-red-500">{error}</div>}

      <div className="mb-4 flex items-center gap-3 text-sm">
        <label className="flex items-center gap-2">
          <span className="text-foreground/70">Min confidence</span>
          <input
            type="number"
            min={0}
            max={1}
            step={0.05}
            value={minConf}
            onChange={(e) => setMinConf(Number(e.target.value))}
            className="h-9 w-24 rounded-md border border-foreground/15 bg-background px-2"
          />
        </label>
        <span className={`text-xs ${discoveryRunning ? "text-amber-600" : "text-foreground/60"}`}>
          {discoveryRunning ? "Discovery running… new assets will appear live" : "Idle"}
        </span>
      </div>

      <div className="overflow-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b border-foreground/10">
              <th className="py-2 pr-4">Discovered</th>
              <th className="py-2 pr-4">Type</th>
              <th className="py-2 pr-4">Value</th>
              <th className="py-2 pr-4">Confidence</th>
              <th className="py-2 pr-4">Sources</th>
              <th className="py-2 pr-4">Tracking</th>
              <th className="py-2 pr-4">Last scan</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id} className="border-b border-foreground/5">
                <td className="py-2 pr-4">{new Date(a.created_at).toLocaleString()}</td>
                <td className="py-2 pr-4 font-mono text-xs">{a.asset_type}</td>
                <td className="py-2 pr-4">{a.value}</td>
                <td className="py-2 pr-4">{a.ownership_confidence.toFixed(2)}</td>
                <td className="py-2 pr-4">{a.sources.join(", ")}</td>
                <td className="py-2 pr-4">
                  <AssetTracking metadata={a.metadata} />
                </td>
                <td className="py-2 pr-4 text-foreground/70">
                  {a.last_scanned_at ? (
                    <div className="flex flex-col">
                      <span>{new Date(a.last_scanned_at).toLocaleString()}</span>
                      <span className="text-xs font-mono">{a.last_scan_status ?? ""}</span>
                      {a.last_scan_id && (
                        <span className="text-xs text-foreground/50">scan: {a.last_scan_id}</span>
                      )}
                    </div>
                  ) : (
                    <span className="text-foreground/40">—</span>
                  )}
                </td>
              </tr>
            ))}
            {assets.length === 0 && (
              <tr>
                <td colSpan={7} className="py-6 text-foreground/60">No assets yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AssetTracking({ metadata }: { metadata: Record<string, unknown> }) {
  const raw: unknown = (metadata && typeof metadata === "object")
    ? (metadata as Record<string, unknown>)["origin_path"]
    : undefined;
  const path: string[] = Array.isArray(raw)
    ? (raw.filter((x): x is string => typeof x === "string"))
    : [];
  if (path.length === 0) return <span className="text-foreground/40">—</span>;
  // Parse labels for nicer boxes
  const labels = path.map((step) => {
    const s = String(step);
    if (s.startsWith("seed:")) {
      return s.replace(/^seed:/, "SEED: ");
    }
    if (s.startsWith("organization:")) {
      return s.replace(/^organization:/, "ORG: ");
    }
    if (s.startsWith("asset:")) {
      return s.replace(/^asset:/, "DOMAIN: ");
    }
    return s;
  });
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {labels.map((label, idx) => (
        <div key={idx} className="flex items-center gap-2">
          <div className="px-2 py-0.5 rounded border border-foreground/20 text-xs bg-foreground/5">
            {label}
          </div>
          {idx < labels.length - 1 && (
            <span className="text-foreground/50">→</span>
          )}
        </div>
      ))}
    </div>
  );
}



"use client";

import { useEffect, useState, useTransition } from "react";
import Link from "next/link";
import { createSeed, deleteSeed, listSeeds, runDiscovery, getDiscoveryStatus, type Seed, type SeedType } from "@/app/api";

const SEED_TYPES: Array<{ value: SeedType; label: string }> = [
  { value: "root_domain", label: "Root domain" },
  { value: "acquisition_domain", label: "Acquisition domain" },
  { value: "cidr", label: "CIDR" },
  { value: "asn", label: "ASN" },
  { value: "keyword", label: "Keyword" },
  { value: "organization", label: "Organization" },
];

export default function SeedsPage() {
  const [seeds, setSeeds] = useState<Seed[]>([]);
  const [seedType, setSeedType] = useState<SeedType>("root_domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();
  const [discovering, startDiscovery] = useTransition();
  const [discoveryRunning, setDiscoveryRunning] = useState(false);
  const [confidence, setConfidence] = useState(0.7);

  async function refresh() {
    try {
      const data = await listSeeds();
      setSeeds(data);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    async function poll() {
      try {
        const s = await getDiscoveryStatus();
        setDiscoveryRunning(s.running);
      } catch {
        // ignore; keep prior state
      }
      timer = setTimeout(poll, 1500);
    }
    poll();
    return () => { if (timer) clearTimeout(timer); };
  }, []);

  function onAdd() {
    if (!value.trim()) return;
    setError(null);
    startTransition(async () => {
      try {
        await createSeed({ seed_type: seedType, value: value.trim(), note: note.trim() || undefined });
        setValue("");
        setNote("");
        await refresh();
      } catch (e) {
        setError((e as Error).message);
      }
    });
  }

  function onDelete(id: string) {
    startTransition(async () => {
      try {
        await deleteSeed(id);
        await refresh();
      } catch (e) {
        setError((e as Error).message);
      }
    });
  }

  function onRunDiscovery() {
    setError(null);
    if (discoveryRunning) {
      setError("Discovery already running");
      return;
    }
    startDiscovery(async () => {
      try {
        await runDiscovery({ confidence_threshold: confidence, include_scan: true });
        setDiscoveryRunning(true);
      } catch (e) {
        setError((e as Error).message);
      }
    });
  }

  return (
    <div className="min-h-screen p-6 sm:p-10 bg-background text-foreground">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Seeds</h1>
        <Link href="/" className="text-sm underline">Back</Link>
      </div>

      {error && <div className="mb-4 text-sm text-red-500">{error}</div>}

      <div className="mb-6 grid gap-3 sm:grid-cols-[auto_1fr_1fr_auto] items-end">
        <label className="grid gap-1">
          <span className="text-sm text-foreground/70">Type</span>
          <select
            className="h-10 rounded-md border border-foreground/15 bg-background px-3"
            value={seedType}
            onChange={(e) => setSeedType(e.target.value as SeedType)}
          >
            {SEED_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </label>
        <label className="grid gap-1">
          <span className="text-sm text-foreground/70">Value</span>
          <input
            className="h-10 rounded-md border border-foreground/15 bg-background px-3"
            placeholder={seedType === "cidr" ? "10.0.0.0/24" : seedType === "asn" ? "AS12345" : "example.com or keyword"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </label>
        <label className="grid gap-1">
          <span className="text-sm text-foreground/70">Note</span>
          <input
            className="h-10 rounded-md border border-foreground/15 bg-background px-3"
            placeholder="optional"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
        <button
          onClick={onAdd}
          disabled={isPending || !value.trim()}
          className="h-10 rounded-md bg-foreground text-background px-4 disabled:opacity-50"
        >
          {isPending ? "Adding…" : "Add seed"}
        </button>
      </div>

      <div className="mb-6 flex items-center gap-3">
        <button
          onClick={onRunDiscovery}
          disabled={discovering || discoveryRunning}
          className="h-9 rounded-md border border-foreground/20 px-3 disabled:opacity-60"
        >
          {discovering || discoveryRunning ? "Discovery running…" : "Run discovery"}
        </button>
        <label className="flex items-center gap-2">
          <span className="text-sm text-foreground/70">Threshold</span>
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={confidence}
            onChange={(e) => setConfidence(parseFloat(e.target.value))}
            className="w-40"
          />
          <input
            type="number"
            min={0}
            max={1}
            step={0.01}
            value={confidence.toFixed(2)}
            onChange={(e) => {
              const v = parseFloat(e.target.value);
              if (!Number.isNaN(v)) setConfidence(Math.max(0, Math.min(1, v)));
            }}
            className="h-9 w-20 rounded-md border border-foreground/20 bg-background px-2"
          />
        </label>
        <span className="text-sm text-foreground/60">
          {discoveryRunning ? "A discovery is already running; please wait for it to finish." : "Runs subdomain enumeration and schedules scans for high-confidence assets."}
        </span>
      </div>

      <div className="overflow-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b border-foreground/10">
              <th className="py-2 pr-4">Created</th>
              <th className="py-2 pr-4">Type</th>
              <th className="py-2 pr-4">Value</th>
              <th className="py-2 pr-4">Note</th>
              <th className="py-2 pr-4"></th>
            </tr>
          </thead>
          <tbody>
            {seeds.map((s) => (
              <tr key={s.id} className="border-b border-foreground/5">
                <td className="py-2 pr-4">{new Date(s.created_at).toLocaleString()}</td>
                <td className="py-2 pr-4 font-mono text-xs">{s.seed_type}</td>
                <td className="py-2 pr-4">{s.value}</td>
                <td className="py-2 pr-4">{s.note ?? ""}</td>
                <td className="py-2 pr-4 text-right">
                  <button
                    onClick={() => onDelete(s.id)}
                    className="h-8 rounded-md border border-foreground/20 px-2"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {seeds.length === 0 && (
              <tr>
                <td colSpan={5} className="py-6 text-foreground/60">No seeds yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}



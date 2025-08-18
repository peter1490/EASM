"use client";

import Link from "next/link";
import { useEffect, useState, useTransition } from "react";
import { createScan, listScans, type Scan, type ScanOptions } from "@/app/api";

type OptionKey = keyof Required<Pick<ScanOptions,
  | "enumerate_subdomains"
  | "resolve_dns"
  | "reverse_dns"
  | "scan_common_ports"
  | "http_probe"
  | "tls_info"
>>;

const OPTION_ENTRIES: Array<[OptionKey, string]> = [
  ["enumerate_subdomains", "Enumerate subdomains"],
  ["resolve_dns", "Resolve DNS"],
  ["reverse_dns", "Reverse DNS"],
  ["scan_common_ports", "Scan ports"],
  ["http_probe", "HTTP probe"],
  ["tls_info", "TLS info"],
];

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [target, setTarget] = useState("");
  const [note, setNote] = useState("");
  const [opts, setOpts] = useState<ScanOptions>({});
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const data = await listScans();
      setScans(data);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 1500);
    return () => clearInterval(id);
  }, []);

  function onCreate() {
    if (!target.trim()) return;
    setError(null);
    startTransition(async () => {
      try {
        await createScan(target.trim(), note.trim() || undefined, opts);
        setTarget("");
        setNote("");
        await refresh();
      } catch (err) {
        setError((err as Error).message);
      }
    });
  }

  return (
    <div className="min-h-screen p-6 sm:p-10 bg-background text-foreground">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">EASM Dashboard</h1>
        <div className="flex items-center gap-3 text-sm">
          <Link href="/seeds" className="underline">Seeds</Link>
          <Link href="/assets" className="underline">Assets</Link>
        </div>
      </div>

      <div className="mb-4 grid gap-3 sm:grid-cols-[1fr_1fr_auto] items-end">
        <label className="grid gap-1">
          <span className="text-sm text-foreground/70">Target</span>
          <input
            className="h-10 rounded-md border border-foreground/15 bg-background px-3 outline-none focus:ring-2 focus:ring-foreground/20"
            placeholder="example.com or 1.2.3.4 or 10.0.0.0/24"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </label>
        <label className="grid gap-1">
          <span className="text-sm text-foreground/70">Note</span>
          <input
            className="h-10 rounded-md border border-foreground/15 bg-background px-3 outline-none focus:ring-2 focus:ring-foreground/20"
            placeholder="optional"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
        <button
          onClick={onCreate}
          disabled={isPending || !target.trim()}
          className="h-10 rounded-md bg-foreground text-background px-4 disabled:opacity-50"
        >
          {isPending ? "Queuing…" : "Start scan"}
        </button>
      </div>

      <div className="mb-8 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 text-sm">
        {OPTION_ENTRIES.map(([key, label]) => {
          const current = (opts as Record<string, unknown>)[key];
          const checked = typeof current === "boolean" ? current : true;
          return (
            <label key={key} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={checked}
                onChange={(e) => setOpts((o) => ({ ...o, [key]: e.target.checked }))}
              />
              {label}
            </label>
          );
        })}
      </div>

      {error && (
        <div className="mb-6 text-sm text-red-500">{error}</div>
      )}

      <div className="overflow-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left border-b border-foreground/10">
              <th className="py-2 pr-4">Created</th>
              <th className="py-2 pr-4">Target</th>
              <th className="py-2 pr-4">Status</th>
              <th className="py-2 pr-4">Findings</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-b border-foreground/5 hover:bg-foreground/5">
                <td className="py-2 pr-4">
                  <Link href={`/scan/${s.id}`}>{new Date(s.created_at).toLocaleString()}</Link>
                </td>
                <td className="py-2 pr-4 font-medium">
                  <Link href={`/scan/${s.id}`}>{s.target}</Link>
                </td>
                <td className="py-2 pr-4">
                  <Link href={`/scan/${s.id}`} className="inline-block">
                    <span
                      className={`inline-flex items-center rounded px-2 py-0.5 text-xs ${
                        s.status === "completed"
                          ? "bg-green-500/15 text-green-600"
                          : "bg-amber-500/15 text-amber-600"
                      }`}
                    >
                      {s.status}
                    </span>
                  </Link>
                </td>
                <td className="py-2 pr-4">
                  <Link href={`/scan/${s.id}`}>{(s.findings_count ?? s.findings?.length ?? 0)}</Link>
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr>
                <td colSpan={4} className="py-6 text-foreground/60">
                  No scans yet. Create one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

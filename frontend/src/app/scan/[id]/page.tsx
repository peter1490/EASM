"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { getScan, type Scan } from "@/app/api";

function Badge({ children, tone = "default" }: { children: React.ReactNode; tone?: "default" | "success" | "warn" | "error" }) {
  const cls =
    tone === "success"
      ? "bg-green-500/15 text-green-600"
      : tone === "warn"
      ? "bg-amber-500/15 text-amber-600"
      : tone === "error"
      ? "bg-red-500/15 text-red-600"
      : "bg-foreground/10 text-foreground/80";
  return <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs ${cls}`}>{children}</span>;
}

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const s = await getScan(id);
        if (mounted) setScan(s);
      } catch (e) {
        if (mounted) setError((e as Error).message);
      }
    }
    load();
    const iv = setInterval(load, 2000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, [id]);

  const grouped = useMemo(() => {
    const byCategory: Record<string, Scan["findings"]> = {};
    for (const f of scan?.findings ?? []) {
      if (!byCategory[f.category]) byCategory[f.category] = [] as Scan["findings"];
      byCategory[f.category].push(f);
    }
    return byCategory;
  }, [scan]);

  return (
    <div className="min-h-screen p-6 sm:p-10 bg-background text-foreground">
      <div className="mb-6 flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold">Scan {id.slice(0, 8)}</h1>
        <Link href="/" className="text-sm underline">Back</Link>
      </div>

      {error && <div className="mb-4 text-sm text-red-500">{error}</div>}

      {!scan && !error && <div className="text-sm">Loading…</div>}

      {scan && (
        <div className="grid gap-6">
          <div className="grid gap-1">
            <div className="text-sm text-foreground/70">Target</div>
            <div className="text-base font-medium">{scan.target}</div>
          </div>
          <div className="grid gap-1">
            <div className="text-sm text-foreground/70">Status</div>
            <Badge tone={scan.status === "completed" ? "success" : "warn"}>{scan.status}</Badge>
          </div>
          <div className="grid gap-1">
            <div className="text-sm text-foreground/70">Created</div>
            <div>{new Date(scan.created_at).toLocaleString()}</div>
          </div>

          <div className="grid gap-4">
            {Object.entries(grouped).length === 0 && (
              <div className="text-sm text-foreground/60">No findings yet.</div>
            )}
            {Object.entries(grouped).map(([category, findings]) => (
              <div key={category} className="border border-foreground/10 rounded-md">
                <div className="px-3 py-2 border-b border-foreground/10 font-medium capitalize">{category}</div>
                <div className="p-3 grid gap-2">
                  {findings.map((f) => (
                    <div key={f.id} className="text-sm">
                      <div className="font-medium">{f.title}</div>
                      <pre className="mt-1 text-xs bg-foreground/5 p-2 rounded overflow-auto">
                        {JSON.stringify(f.data, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import { useState } from "react";
import { Icon } from "@/components/kit";
import { cn } from "@/lib/cn";
import { humanise } from "@/lib/format";
import type { Asset } from "@/app/api";
import { KV, Mono } from "./shared";

/**
 * The old Metadata tab, folded into a disclosure at the foot of the overview.
 *
 * It was a whole tab for three JSON dumps that an analyst opens roughly once a
 * month, and having it up there meant the tab bar promised five equal things
 * when only three were. It keeps everything it had, including the parent-asset
 * link, which is the one part of it people did use.
 */
export function RawMetadata({ asset }: { asset: Asset }) {
  const [open, setOpen] = useState(false);
  const metadataKeys = Object.keys(asset.metadata ?? {});

  return (
    <section className="bg-surface border border-rule rounded-lg">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex items-center gap-2 w-full px-4 py-2.5 text-left hover:bg-surface-2 rounded-lg transition-colors"
      >
        <Icon
          name="chevronRight"
          size={12}
          className={cn("text-ink-3 transition-transform duration-150", open && "rotate-90")}
        />
        <span className="text-sm font-semibold tracking-[-0.012em]">Raw metadata</span>
        <span className="text-[11.5px] text-ink-3">
          identifiers · {metadataKeys.length} metadata {metadataKeys.length === 1 ? "key" : "keys"} · full record
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-rule flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-x-4 gap-y-3 pt-3">
            <KV label="Asset ID">
              <Mono value={asset.id} />
            </KV>
            {asset.parent_id && (
              <KV label="Parent asset">
                <Mono value={asset.parent_id} href={`/surface/${asset.parent_id}`} />
              </KV>
            )}
            {asset.seed_id && (
              <KV label="Seed ID">
                <Mono value={asset.seed_id} />
              </KV>
            )}
            {asset.last_discovery_run_id && (
              <KV label="Last discovery run">
                <Mono value={asset.last_discovery_run_id} />
              </KV>
            )}
            {asset.discovery_method && <KV label="Discovery method">{humanise(asset.discovery_method)}</KV>}
            {asset.last_scan_id && (
              <KV label="Last scan">
                <Mono value={asset.last_scan_id} href={`/findings?scan=${asset.last_scan_id}`} />
              </KV>
            )}
          </div>

          <Dump label="Metadata" value={asset.metadata ?? {}} />
          <Dump label="Full asset record" value={asset} />
        </div>
      )}
    </section>
  );
}

function Dump({ label, value }: { label: string; value: unknown }) {
  return (
    <div>
      <div className="lbl mb-1.5">{label}</div>
      <pre className="mono text-[11.5px] leading-relaxed text-ink-2 bg-surface-2 border border-rule rounded-md p-3 max-h-72 overflow-auto">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

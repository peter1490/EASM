"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Button, Icon } from "@/components/kit";
import { cn } from "@/lib/cn";
import type { AssetTagDetail, TagWithCount } from "@/app/api";

/**
 * Tags on an asset.
 *
 * A tag applied by an auto-rule is marked, because removing one by hand only
 * lasts until the rule runs again — the fix is to edit the rule, and the marker
 * links you there.
 */
export function TagsPanel({
  applied,
  available,
  onTag,
  onUntag,
  busy,
}: {
  applied: AssetTagDetail[];
  available: TagWithCount[];
  onTag: (tagId: string) => void | Promise<void>;
  onUntag: (tagId: string) => void | Promise<void>;
  busy?: boolean;
}) {
  const [picking, setPicking] = useState(false);

  const unapplied = useMemo(
    () => available.filter((tag) => !applied.some((entry) => entry.tag.id === tag.id)),
    [available, applied],
  );

  return (
    <div className="flex flex-col gap-3">
      {applied.length === 0 ? (
        <p className="text-[12.5px] text-ink-3">No tags yet.</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {applied.map((entry) => {
            const auto = entry.applied_by === "auto_rule";
            return (
              <span
                key={entry.tag.id}
                className="group inline-flex items-center gap-1.5 h-[24px] pl-2 pr-1 rounded-[5px] border border-rule-2 bg-surface text-[11.5px] font-medium text-ink"
                title={
                  auto
                    ? `Applied automatically by rule${entry.matched_rule ? ` (${entry.matched_rule})` : ""}`
                    : "Applied manually"
                }
              >
                <span
                  className="w-[7px] h-[7px] rounded-full shrink-0"
                  style={{ background: entry.tag.color || "var(--accent)" }}
                  aria-hidden="true"
                />
                {entry.tag.name}
                {auto && (
                  <span className="text-ink-3">
                    <Icon name="activity" size={10} />
                    <span className="sr-only">applied by rule</span>
                  </span>
                )}
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => onUntag(entry.tag.id)}
                  aria-label={`Remove tag ${entry.tag.name}`}
                  className="grid place-items-center w-[16px] h-[16px] rounded-[3px] text-ink-3 opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-crit hover:bg-crit-wash disabled:opacity-40"
                >
                  <Icon name="close" size={9} strokeWidth={1.8} />
                </button>
              </span>
            );
          })}
        </div>
      )}

      {picking ? (
        <div className="rounded-lg border border-rule bg-surface-2 p-2.5">
          {unapplied.length === 0 ? (
            <p className="text-[12.5px] text-ink-3">
              {available.length === 0 ? "No tags have been defined yet." : "Every tag is already applied."}{" "}
              <Link href="/settings?tab=tags" className="text-accent-ink hover:underline">
                Manage tags
              </Link>
            </p>
          ) : (
            <>
              <div className="lbl mb-2">Apply a tag</div>
              <div className="flex flex-wrap gap-1.5">
                {unapplied.map((tag) => (
                  <button
                    key={tag.id}
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      void onTag(tag.id);
                      setPicking(false);
                    }}
                    title={tag.description ?? undefined}
                    className={cn(
                      "inline-flex items-center gap-1.5 h-[24px] px-2 rounded-[5px] border border-rule-2 bg-surface",
                      "text-[11.5px] font-medium text-ink-2",
                      "hover:border-accent hover:text-accent-ink disabled:opacity-40",
                    )}
                  >
                    <span
                      className="w-[7px] h-[7px] rounded-full shrink-0"
                      style={{ background: tag.color || "var(--accent)" }}
                      aria-hidden="true"
                    />
                    {tag.name}
                    {tag.rule_type && <Icon name="activity" size={10} className="text-ink-3" />}
                  </button>
                ))}
              </div>
            </>
          )}
          <div className="flex justify-end mt-2.5">
            <Button size="sm" variant="ghost" onClick={() => setPicking(false)}>
              Done
            </Button>
          </div>
        </div>
      ) : (
        <div>
          <Button size="sm" icon="plus" onClick={() => setPicking(true)} disabled={busy}>
            Add tag
          </Button>
        </div>
      )}
    </div>
  );
}

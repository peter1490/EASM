"use client";

import Link from "next/link";
import { useState } from "react";
import { Button, Checkbox, ErrorState, Icon, Textarea } from "@/components/kit";
import { blacklistFromAsset, type Asset, type BlacklistCheckResult, type BlacklistResult } from "@/app/api";
import { Notice, Section, toBlacklistObjectType } from "./shared";

/**
 * Discovery exclusion for one asset: the status banner and the confirmation
 * flow that creates the blacklist entry.
 *
 * Two states look alike and are not: an asset can be blacklisted itself, or it
 * can be swept up by a blacklist on a parent domain. Only the first can be
 * undone from here, so only the first disables the button — the second names
 * the parent instead, because that is the entry you actually need to edit.
 *
 * The confirmation is an inline panel rather than a second modal: `<Drawer>` is
 * the app's only floating layer, and this body renders inside one.
 */
export function BlacklistPanel({
  asset,
  status,
  onBlacklisted,
}: {
  asset: Asset;
  status: BlacklistCheckResult | null;
  onBlacklisted: (result: BlacklistResult) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  const [deleteDescendants, setDeleteDescendants] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BlacklistResult | null>(null);

  const objectType = toBlacklistObjectType(asset.asset_type);
  const blacklistedExactly = Boolean(status?.is_blacklisted && !status.parent_blacklisted);
  const viaParent = Boolean(status?.parent_blacklisted);

  const reset = () => {
    setConfirming(false);
    setReason("");
    setDeleteDescendants(true);
    setError(null);
    setResult(null);
  };

  const submit = async () => {
    setWorking(true);
    setError(null);
    try {
      const created = await blacklistFromAsset(asset.id, reason.trim() || undefined, deleteDescendants);
      setResult(created);
      onBlacklisted(created);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setWorking(false);
    }
  };

  return (
    <Section
      title="Discovery exclusion"
      hint={blacklistedExactly ? "Blacklisted" : viaParent ? "Excluded by a parent" : undefined}
      actions={
        !confirming && !result ? (
          <Button
            size="sm"
            variant="danger"
            icon="ban"
            onClick={() => setConfirming(true)}
            disabled={blacklistedExactly || objectType == null}
            title={
              objectType == null
                ? `${asset.asset_type} assets cannot be blacklisted`
                : blacklistedExactly
                  ? "Already blacklisted"
                  : "Exclude this asset from discovery"
            }
          >
            {blacklistedExactly ? "Blacklisted" : "Blacklist"}
          </Button>
        ) : null
      }
    >
      <div className="flex flex-col gap-3">
        {status?.is_blacklisted && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg border border-med/45 bg-med-wash">
            <Icon name="ban" size={14} className="text-med mt-px shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-[12.5px] font-semibold text-ink">
                {viaParent ? "Excluded by a parent-domain blacklist" : "This asset is blacklisted"}
              </div>
              <p className="text-[12px] text-ink-2 mt-0.5 break-words">
                {viaParent ? (
                  <>
                    <span className="mono">{status.parent_entry?.object_value ?? "A parent domain"}</span> is
                    blacklisted, so this asset is excluded from discovery.
                    {status.parent_entry?.reason ? ` Reason given: ${status.parent_entry.reason}.` : ""}
                  </>
                ) : (
                  <>
                    Excluded from every future discovery run.
                    {status.entry?.reason ? ` Reason given: ${status.entry.reason}.` : ""}
                  </>
                )}
              </p>
              <Link
                href="/ops?tab=exclusions"
                className="inline-flex items-center gap-1 text-[12px] font-medium text-accent-ink hover:underline mt-1.5"
              >
                Manage exclusions
                <Icon name="arrowRight" size={11} />
              </Link>
            </div>
          </div>
        )}

        {!status?.is_blacklisted && !confirming && !result && (
          <p className="text-[12.5px] text-ink-2">
            {objectType == null
              ? `A ${asset.asset_type} asset cannot be blacklisted directly — exclude its domain or IP instead.`
              : "Blacklisting removes this asset from every future discovery run, and optionally deletes everything discovered through it."}
          </p>
        )}

        {error && <ErrorState error={error} />}

        {result && (
          <Notice tone="ok" onDismiss={reset}>
            <span className="mono">{asset.value}</span> is now blacklisted.{" "}
            {result.descendants_deleted > 0 ? (
              <>
                <span className="mono">{result.descendants_deleted}</span> descendant
                {result.descendants_deleted === 1 ? "" : "s"} were deleted.
              </>
            ) : (
              "No descendants were deleted."
            )}
            {/* Only shown when a run was actually in flight — the counts are
                zero otherwise, and a line saying so would be noise. */}
            <InFlightEffect result={result} />
          </Notice>
        )}

        {confirming && !result && (
          <div className="rounded-lg border border-crit/40 bg-crit-wash/60 p-3.5 flex flex-col gap-3">
            <div className="flex items-start gap-2.5">
              <Icon name="alert" size={14} className="text-crit mt-px shrink-0" />
              <div className="text-[12.5px] text-ink">
                <div className="font-semibold text-crit">
                  Blacklist <span className="mono">{asset.value}</span>?
                </div>
                <ul className="list-disc ml-4 mt-1.5 text-ink-2 space-y-0.5 text-[12px]">
                  <li>It is excluded from all future discovery runs.</li>
                  <li>Subdomains and related assets may be excluded with it.</li>
                  <li>With the option below, everything discovered through it is deleted.</li>
                </ul>
              </div>
            </div>

            <div>
              <div className="lbl mb-1.5">Reason (optional)</div>
              <Textarea
                rows={3}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="CDN provider, not ours, false positive…"
                aria-label="Blacklist reason"
              />
            </div>

            <Checkbox
              checked={deleteDescendants}
              onChange={setDeleteDescendants}
              label={
                <span className="text-[12.5px]">
                  <span className="font-medium">Delete descendant assets</span>
                  <span className="block text-[12px] text-ink-2 mt-0.5">
                    Subdomains, resolved IPs and anything else discovered through this asset are removed from the
                    database.
                  </span>
                </span>
              }
            />

            <div className="flex items-center justify-end gap-2">
              <Button size="sm" onClick={reset} disabled={working}>
                Cancel
              </Button>
              <Button size="sm" variant="danger" icon="ban" onClick={submit} loading={working}>
                Blacklist asset
              </Button>
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}

/**
 * What blacklisting did to work already running.
 *
 * A discovery in progress holds a queue built before the entry existed, and may
 * have scans in flight against the host just excluded; the backend clears both
 * on the way in. Reporting it closes the loop for the operator who expected
 * "blacklist" to mean "and stop what you are doing to it".
 */
function InFlightEffect({ result }: { result: BlacklistResult }) {
  const queued = result.queue_items_removed ?? 0;
  const scans = result.scans_cancelled ?? 0;
  if (queued === 0 && scans === 0) return null;

  const parts: string[] = [];
  if (queued > 0) parts.push(`${queued} queued discovery item${queued === 1 ? "" : "s"} dropped`);
  if (scans > 0) parts.push(`${scans} running scan${scans === 1 ? "" : "s"} cancelled`);

  return (
    <span className="block mt-1">
      From the run in progress: {parts.join(", ")}.
    </span>
  );
}

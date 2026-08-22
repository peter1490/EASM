"use client";

import Link from "next/link";
import { useState } from "react";
import { Button, Checkbox, ErrorState, Icon, Textarea } from "@/components/kit";
import { excludeAsset, type Asset, type ExclusionCheckResult, type ExclusionResult } from "@/app/api";
import { Notice, Section, toExclusionObjectType } from "./shared";

/**
 * Discovery exclusion for one asset: the status banner and the confirmation
 * flow that creates the entry.
 *
 * Two strengths and two states, and none of the four look alike by accident.
 *
 * *Excluding* stops discovery finding more through this asset; the asset stays,
 * keeps its findings, keeps counting in the score, and is still auto-scanned.
 * *Blacklisting* — the checkbox, off unless asked for — deletes it instead, so
 * it reaches no score, no scan and no list. Excluding is reversible and
 * blacklisting is not, which is why the deletion is never the default.
 *
 * An asset can also be swept up by an entry on a parent domain. Only its own
 * entry can be undone from here, so only that disables the button — the parent
 * case names the parent instead, because that is the entry to go and edit.
 *
 * The confirmation is an inline panel rather than a second modal: `<Drawer>` is
 * the app's only floating layer, and this body renders inside one.
 */
export function ExclusionPanel({
  asset,
  status,
  onExcluded,
}: {
  asset: Asset;
  status: ExclusionCheckResult | null;
  onExcluded: (result: ExclusionResult) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  const [deleteDescendants, setDeleteDescendants] = useState(true);
  const [blacklist, setBlacklist] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExclusionResult | null>(null);

  const objectType = toExclusionObjectType(asset.asset_type);
  const excludedExactly = Boolean(status?.is_excluded && !status.parent_excluded);
  const viaParent = Boolean(status?.parent_excluded);
  const alreadyBlacklisted = Boolean(status?.is_blacklisted);
  // An asset already excluded can still be blacklisted: that is a promotion,
  // not a duplicate. Only the strongest state leaves nothing left to do.
  const nothingLeftToDo = excludedExactly && alreadyBlacklisted;

  const reset = () => {
    setConfirming(false);
    setReason("");
    setDeleteDescendants(true);
    setBlacklist(false);
    setError(null);
    setResult(null);
  };

  const submit = async () => {
    setWorking(true);
    setError(null);
    try {
      const created = await excludeAsset(asset.id, {
        reason: reason.trim() || undefined,
        deleteDescendants,
        blacklisted: blacklist,
      });
      setResult(created);
      onExcluded(created);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setWorking(false);
    }
  };

  const buttonLabel = nothingLeftToDo
    ? "Blacklisted"
    : excludedExactly
      ? "Blacklist"
      : "Exclude";

  return (
    <Section
      title="Discovery exclusion"
      hint={
        alreadyBlacklisted
          ? "Blacklisted"
          : excludedExactly
            ? "Excluded"
            : viaParent
              ? "Excluded by a parent"
              : undefined
      }
      actions={
        !confirming && !result ? (
          <Button
            size="sm"
            variant="danger"
            icon="ban"
            onClick={() => {
              // Coming from "already excluded", the only thing left to offer is
              // the stronger option, so it starts ticked.
              setBlacklist(excludedExactly);
              setConfirming(true);
            }}
            disabled={nothingLeftToDo || objectType == null}
            title={
              objectType == null
                ? `${asset.asset_type} assets cannot be excluded`
                : nothingLeftToDo
                  ? "Already blacklisted"
                  : excludedExactly
                    ? "Delete this asset and keep it out for good"
                    : "Stop discovery finding more through this asset"
            }
          >
            {buttonLabel}
          </Button>
        ) : null
      }
    >
      <div className="flex flex-col gap-3">
        {status?.is_excluded && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg border border-med/45 bg-med-wash">
            <Icon name="ban" size={14} className="text-med mt-px shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-[12.5px] font-semibold text-ink">
                {viaParent
                  ? `Excluded by a parent domain${alreadyBlacklisted ? " (blacklisted)" : ""}`
                  : alreadyBlacklisted
                    ? "This asset is blacklisted"
                    : "This asset is excluded"}
              </div>
              <p className="text-[12px] text-ink-2 mt-0.5 break-words">
                {viaParent ? (
                  <>
                    <span className="mono">{status.parent_entry?.object_value ?? "A parent domain"}</span> is{" "}
                    {alreadyBlacklisted ? "blacklisted" : "excluded"}, so discovery will not look for more
                    beneath it.
                    {status.parent_entry?.reason ? ` Reason given: ${status.parent_entry.reason}.` : ""}
                  </>
                ) : alreadyBlacklisted ? (
                  <>
                    Deleted from the inventory and kept out of every score and scan. Discovery will not store it
                    again.
                    {status.entry?.reason ? ` Reason given: ${status.entry.reason}.` : ""}
                  </>
                ) : (
                  <>
                    Discovery will not find anything new through it, but the asset is kept and still gets
                    auto-scanned.
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

        {!status?.is_excluded && !confirming && !result && (
          <p className="text-[12.5px] text-ink-2">
            {objectType == null
              ? `A ${asset.asset_type} asset cannot be excluded directly — exclude its domain or IP instead.`
              : "Excluding stops discovery finding anything new through this asset. It stays in the inventory, keeps its findings and is still auto-scanned — unless you blacklist it, which deletes it instead."}
          </p>
        )}

        {error && <ErrorState error={error} />}

        {result && (
          <Notice tone="ok" onDismiss={reset}>
            <span className="mono">{asset.value}</span> is now{" "}
            {result.entry.blacklisted ? "blacklisted" : "excluded"}.{" "}
            {result.entry.blacklisted ? (
              <>
                <span className="mono">{result.assets_deleted ?? 0}</span> asset
                {(result.assets_deleted ?? 0) === 1 ? " was" : "s were"} deleted, along with their findings and
                scans.
              </>
            ) : result.descendants_deleted > 0 ? (
              <>
                <span className="mono">{result.descendants_deleted}</span> descendant
                {result.descendants_deleted === 1 ? "" : "s"} were deleted.
              </>
            ) : (
              "No assets were deleted."
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
                  {blacklist ? "Blacklist" : "Exclude"} <span className="mono">{asset.value}</span>?
                </div>
                <ul className="list-disc ml-4 mt-1.5 text-ink-2 space-y-0.5 text-[12px]">
                  <li>Discovery stops finding anything new through it.</li>
                  <li>Subdomains and related assets are covered with it.</li>
                  {blacklist ? (
                    <li className="text-crit">
                      It is deleted along with everything discovered through it — findings, scans and all. It will
                      never appear in a score or a list again.
                    </li>
                  ) : (
                    <li>It stays in the inventory, keeps counting in the score, and is still auto-scanned.</li>
                  )}
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
                aria-label="Exclusion reason"
              />
            </div>

            <Checkbox
              checked={blacklist}
              onChange={setBlacklist}
              label={
                <span className="text-[12.5px]">
                  <span className="font-medium">Blacklist it as well</span>
                  <span className="block text-[12px] text-ink-2 mt-0.5">
                    Delete this asset outright instead of keeping it. Its findings, scans and score contribution go
                    with it, and discovery will never store it again. This cannot be undone.
                  </span>
                </span>
              }
            />

            {!blacklist && (
              <Checkbox
                checked={deleteDescendants}
                onChange={setDeleteDescendants}
                label={
                  <span className="text-[12.5px]">
                    <span className="font-medium">Delete descendant assets</span>
                    <span className="block text-[12px] text-ink-2 mt-0.5">
                      Subdomains, resolved IPs and anything else discovered through this asset are removed from the
                      database. The asset itself is kept.
                    </span>
                  </span>
                }
              />
            )}

            <div className="flex items-center justify-end gap-2">
              <Button size="sm" onClick={reset} disabled={working}>
                Cancel
              </Button>
              <Button size="sm" variant="danger" icon="ban" onClick={submit} loading={working}>
                {blacklist ? "Blacklist asset" : "Exclude asset"}
              </Button>
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}

/**
 * What the entry did to work already running.
 *
 * A discovery in progress holds a queue built before the entry existed, and a
 * blacklist may have scans in flight against a host it just deleted; the
 * backend clears both on the way in. Reporting it closes the loop for the
 * operator who expected this to mean "and stop what you are doing to it".
 */
function InFlightEffect({ result }: { result: ExclusionResult }) {
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

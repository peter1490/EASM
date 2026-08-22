"use client";

import { useMemo, useState } from "react";
import { excludeAsset, type Asset } from "@/app/api";
import { Button, Checkbox, Chip, Drawer, ErrorState, Icon, Textarea } from "@/components/kit";
import { num } from "@/lib/format";
import { toExclusionObjectType } from "./shared";

/** What a whole run of the bulk exclusion added up to. */
export type BulkExcludeSummary = {
  entries: number;
  assetsDeleted: number;
  descendantsDeleted: number;
  queueItemsRemoved: number;
  scansCancelled: number;
  /** Assets an earlier entry in this same run had already deleted. */
  alreadyGone: number;
  failures: string[];
  /** Which strength the run used, so a caller can word its own notice. */
  blacklisted: boolean;
};

const EMPTY: BulkExcludeSummary = {
  entries: 0,
  assetsDeleted: 0,
  descendantsDeleted: 0,
  queueItemsRemoved: 0,
  scansCancelled: 0,
  alreadyGone: 0,
  failures: [],
  blacklisted: false,
};

/** How many values to name before the rest become a count. */
const PREVIEW = 8;

/**
 * Deepest first.
 *
 * Blacklisting deletes an asset together with everything discovered through it,
 * so a parent handled before its child would take the child's row away before
 * the child got an entry of its own — and that entry is a rule the operator
 * asked for, which a purge of the parent does not replace: a domain rule does
 * not cover the IP that was found under it. Counting how many of the *selected*
 * assets sit above each one and running the deepest first keeps every entry,
 * and leaves the parent's purge with less left to delete.
 */
function deepestFirst(assets: Asset[]): Asset[] {
  const byId = new Map(assets.map((asset) => [asset.id, asset]));

  const selectedAncestors = (asset: Asset): number => {
    let depth = 0;
    // Bounded by the selection, but a cycle in `parent_id` would still spin
    // here, so the visited set is not optional.
    const seen = new Set([asset.id]);
    let parent = asset.parent_id ? byId.get(asset.parent_id) : undefined;
    while (parent && !seen.has(parent.id)) {
      depth += 1;
      seen.add(parent.id);
      parent = parent.parent_id ? byId.get(parent.parent_id) : undefined;
    }
    return depth;
  };

  return [...assets].sort((a, b) => selectedAncestors(b) - selectedAncestors(a));
}

/**
 * Exclude every asset in a selection, one entry each, with the same options the
 * single-asset panel offers.
 *
 * One entry per asset rather than one rule for the lot: the selection is a list
 * of things the operator picked, not a pattern, and collapsing it into a
 * guessed common parent would exclude names they never chose.
 *
 * Ports are dropped from the run rather than failing it. They cannot carry an
 * exclusion — the host they belong to is what gets excluded — and a selection
 * made from a mixed list will routinely contain one.
 */
export function BulkExcludeDrawer({
  assets,
  open,
  onClose,
  onDone,
}: {
  assets: Asset[];
  open: boolean;
  onClose: () => void;
  onDone: (summary: BulkExcludeSummary) => void;
}) {
  const [reason, setReason] = useState("");
  const [cascade, setCascade] = useState(true);
  const [blacklist, setBlacklist] = useState(false);
  const [working, setWorking] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<BulkExcludeSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { eligible, skipped } = useMemo(() => {
    const eligible: Asset[] = [];
    const skipped: Asset[] = [];
    for (const asset of assets) {
      (toExclusionObjectType(asset.asset_type) ? eligible : skipped).push(asset);
    }
    return { eligible, skipped };
  }, [assets]);

  function reset() {
    setReason("");
    setCascade(true);
    setBlacklist(false);
    setProgress(0);
    setResult(null);
    setError(null);
  }

  function close() {
    if (working) return;
    reset();
    onClose();
  }

  async function submit() {
    if (eligible.length === 0) {
      setError("Nothing in this selection can carry an exclusion.");
      return;
    }
    setWorking(true);
    setError(null);
    setProgress(0);

    const summary: BulkExcludeSummary = { ...EMPTY, failures: [], blacklisted: blacklist };
    const trimmed = reason.trim();

    // Sequential, and it keeps going after a rejection. These writes delete
    // assets and cancel scans; firing them at once would have entries racing to
    // purge each other's descendants, and one bad asset must not silently
    // cancel every exclusion queued behind it.
    for (const asset of deepestFirst(eligible)) {
      try {
        const entry = await excludeAsset(asset.id, {
          reason: trimmed || undefined,
          deleteDescendants: cascade,
          blacklisted: blacklist,
        });
        summary.entries += 1;
        summary.assetsDeleted += entry.assets_deleted ?? 0;
        summary.descendantsDeleted += entry.descendants_deleted ?? 0;
        summary.queueItemsRemoved += entry.queue_items_removed ?? 0;
        summary.scansCancelled += entry.scans_cancelled ?? 0;
      } catch (err) {
        const message = (err as Error).message;
        // Expected during a blacklist run: an asset an earlier entry deleted as
        // one of its descendants. Ordering makes it rare rather than
        // impossible, and it is not a failure worth alarming anyone with.
        if (/not found/i.test(message)) summary.alreadyGone += 1;
        else summary.failures.push(`${asset.value} — ${message}`);
      }
      setProgress((done) => done + 1);
    }

    setResult(summary);
    setWorking(false);
    onDone(summary);
  }

  if (!open) return null;

  const verb = blacklist ? "Blacklist" : "Exclude";
  const preview = eligible.slice(0, PREVIEW);
  const rest = eligible.length - preview.length;

  return (
    <Drawer
      open
      onClose={close}
      title={result ? `${eligible.length} assets processed` : `${verb} ${eligible.length} assets`}
      width={560}
      header={
        <div>
          <h2 className="text-sm font-semibold tracking-[-0.012em]">
            {result ? "Selection processed" : `${verb} ${num(eligible.length)} selected asset${eligible.length === 1 ? "" : "s"}`}
          </h2>
          <p className="text-[12px] text-ink-2 mt-0.5">
            {result
              ? `One ${result.blacklisted ? "blacklist" : "exclusion"} entry was added per asset.`
              : blacklist
                ? "Each asset is deleted and kept out of every score, scan and list."
                : "Discovery stops finding new assets through each of these. What it already found is kept and still scanned."}
          </p>
        </div>
      }
      footer={
        result ? (
          <>
            <div className="flex-1" />
            <Button variant="primary" onClick={close}>
              Done
            </Button>
          </>
        ) : (
          <>
            <div className="flex-1" />
            <Button onClick={close} disabled={working}>
              Cancel
            </Button>
            <Button
              variant={blacklist ? "danger" : "primary"}
              icon="ban"
              loading={working}
              disabled={eligible.length === 0}
              onClick={() => void submit()}
            >
              {working
                ? `${progress} of ${eligible.length}…`
                : `${verb} ${num(eligible.length)} asset${eligible.length === 1 ? "" : "s"}`}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <BulkResult result={result} />
      ) : (
        <div className="flex flex-col gap-3.5">
          {error && <ErrorState error={error} />}

          <div className="rounded-lg border border-rule bg-surface-2 p-3">
            <div className="lbl mb-2">
              {num(eligible.length)} asset{eligible.length === 1 ? "" : "s"}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {preview.map((asset) => (
                <Chip key={asset.id} wrap title={asset.value}>
                  <Icon name="ban" size={10} className="text-ink-3" />
                  <span className="mono text-[11.5px]">{asset.value}</span>
                </Chip>
              ))}
              {rest > 0 && <Chip>+{num(rest)} more</Chip>}
            </div>
          </div>

          {skipped.length > 0 && (
            <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg border border-rule bg-surface-2">
              <Icon name="alert" size={14} className="text-ink-3 mt-px shrink-0" />
              <p className="text-[12px] text-ink-2">
                <span className="mono text-ink">{num(skipped.length)}</span> selected asset
                {skipped.length === 1 ? "" : "s"} cannot carry an exclusion and{" "}
                {skipped.length === 1 ? "is" : "are"} left out — exclude the host{" "}
                {skipped.length === 1 ? "it belongs" : "they belong"} to instead.
              </p>
            </div>
          )}

          <div>
            <div className="lbl mb-1.5">Reason (optional)</div>
            <Textarea
              rows={3}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="CDN provider, not ours, false positive…"
              aria-label="Exclusion reason"
            />
            <p className="text-[12px] text-ink-3 mt-1">Recorded on every entry this creates.</p>
          </div>

          {!blacklist && (
            <div className="rounded-lg border border-rule bg-surface-2 p-3">
              <Checkbox
                checked={cascade}
                onChange={setCascade}
                label={<span className="font-medium text-[12.5px]">Delete descendant assets</span>}
              />
              <p className="text-[12px] text-ink-2 mt-1.5 pl-[23px]">
                Everything discovered through each asset — subdomains, resolved IPs, anything reached by pivoting
                — is deleted. The selected assets themselves are kept.
              </p>
            </div>
          )}

          <div className="rounded-lg border border-crit/40 bg-crit-wash/60 p-3">
            <Checkbox
              checked={blacklist}
              onChange={setBlacklist}
              label={<span className="font-medium text-[12.5px]">Blacklist them as well</span>}
            />
            <p className="text-[12px] text-ink-2 mt-1.5 pl-[23px]">
              Delete the selected assets outright, together with everything discovered through them. Their
              findings, scans and score contribution go with them, and discovery will never store them again.
              This cannot be undone.
            </p>
          </div>
        </div>
      )}
    </Drawer>
  );
}

/** The counts a bulk run produced, and anything that went wrong in it. */
function BulkResult({ result }: { result: BulkExcludeSummary }) {
  const blacklisted = result.blacklisted;
  const deleted = blacklisted ? result.assetsDeleted : result.descendantsDeleted;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start gap-3 p-3.5 rounded-lg border border-ok/40 bg-ok-wash">
        <Icon name="check" size={15} className="text-ok mt-px" strokeWidth={2.2} />
        <div className="min-w-0">
          <div className="text-[12.5px] font-semibold text-ink">
            {num(result.entries)} {blacklisted ? "blacklist" : "exclusion"} entr
            {result.entries === 1 ? "y" : "ies"} added
          </div>
          <p className="text-[12px] text-ink-2 mt-0.5">
            {blacklisted
              ? "Discovery will not store any of them again."
              : "Discovery will stop expanding on them from the next run onwards."}
          </p>
        </div>
      </div>

      {deleted > 0 && (
        <div
          className={`flex items-start gap-3 p-3.5 rounded-lg border ${
            blacklisted ? "border-crit/40 bg-crit-wash" : "border-med/40 bg-med-wash"
          }`}
        >
          <Icon name="alert" size={15} className={blacklisted ? "text-crit mt-px" : "text-med mt-px"} />
          <div className="min-w-0">
            <div className="text-[12.5px] font-semibold text-ink">
              {blacklisted ? "Blacklist deletion" : "Cascade deletion"}
            </div>
            <p className="text-[12px] text-ink-2 mt-0.5">
              <span className="mono text-ink">{num(deleted)}</span> asset{deleted === 1 ? "" : "s"}{" "}
              {blacklisted
                ? "— the selected objects and everything discovered through them — were deleted, along with their findings and scans."
                : "discovered through the selection were deleted. The selected assets themselves were kept."}
            </p>
          </div>
        </div>
      )}

      {result.alreadyGone > 0 && (
        <p className="text-[12.5px] text-ink-2">
          <span className="mono text-ink">{num(result.alreadyGone)}</span> selected asset
          {result.alreadyGone === 1 ? " was" : "s were"} already deleted by another entry in this selection.
        </p>
      )}

      {(result.queueItemsRemoved > 0 || result.scansCancelled > 0) && (
        <div className="flex items-start gap-3 p-3.5 rounded-lg border border-rule bg-surface-2">
          <Icon name="stop" size={15} className="text-ink-2 mt-px" />
          <div className="min-w-0">
            <div className="text-[12.5px] font-semibold text-ink">Applied to the run in progress</div>
            <p className="text-[12px] text-ink-2 mt-0.5">
              {result.queueItemsRemoved > 0 && (
                <>
                  <span className="mono text-ink">{num(result.queueItemsRemoved)}</span> queued discovery item
                  {result.queueItemsRemoved === 1 ? " was" : "s were"} dropped
                  {result.scansCancelled > 0 ? ", and " : "."}
                </>
              )}
              {result.scansCancelled > 0 && (
                <>
                  <span className="mono text-ink">{num(result.scansCancelled)}</span> running scan
                  {result.scansCancelled === 1 ? " was" : "s were"} cancelled.
                </>
              )}
            </p>
          </div>
        </div>
      )}

      {result.failures.length > 0 && (
        <div className="flex items-start gap-3 p-3.5 rounded-lg border border-crit/40 bg-crit-wash">
          <Icon name="alert" size={15} className="text-crit mt-px" />
          <div className="min-w-0">
            <div className="text-[12.5px] font-semibold text-crit">
              {num(result.failures.length)} failed
            </div>
            <ul className="text-[12px] text-ink-2 mt-1 space-y-0.5">
              {result.failures.map((failure) => (
                <li key={failure} className="break-words">
                  {failure}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

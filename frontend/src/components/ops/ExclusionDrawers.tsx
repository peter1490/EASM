"use client";

import { useState } from "react";
import {
  createExclusion,
  deleteExclusion,
  type ExclusionEntry,
  type ExclusionObjectType,
  type ExclusionResult,
} from "@/app/api";
import { Button, Checkbox, Chip, Drawer, ErrorState, Icon, Input, Label, Select, Textarea } from "@/components/kit";
import { num } from "@/lib/format";
import { EXCLUSION_TYPES, exclusionType, isPattern, WILDCARD } from "./exclusionTypes";

/**
 * Add an exclusion.
 *
 * The two checkboxes are the consequential part and they are not the same
 * thing. *Delete descendants* removes what was found through the object but
 * keeps the object's own asset. *Blacklist* removes the object too, and keeps
 * discovery from ever storing it again — it is off by default because
 * excluding can be undone and deleting cannot.
 */
export function ExclusionCreateDrawer({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => Promise<void> | void;
}) {
  const [objectType, setObjectType] = useState<ExclusionObjectType>("domain");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [cascade, setCascade] = useState(true);
  const [blacklist, setBlacklist] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ExclusionResult | null>(null);

  const type = exclusionType(objectType);

  function reset() {
    setObjectType("domain");
    setValue("");
    setReason("");
    setCascade(true);
    setBlacklist(false);
    setError(null);
    setResult(null);
  }

  function close() {
    reset();
    onClose();
  }

  async function handleCreate() {
    const trimmed = value.trim();
    if (!trimmed) {
      setError("A value is required.");
      return;
    }
    // A fact about the type, so it is answered here rather than in a round
    // trip. How *broad* a pattern may be is the server's call — it is the one
    // that has to live with the entry.
    if (isPattern(trimmed) && !type.wildcards) {
      setError(
        `Wildcards are not allowed on ${type.label} exclusions. Use a CIDR entry for a range of addresses.`,
      );
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const created = await createExclusion({
        object_type: objectType,
        object_value: trimmed,
        reason: reason.trim() || undefined,
        delete_descendants: cascade,
        blacklisted: blacklist,
      });
      setResult(created);
      await onCreated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (!open) return null;

  return (
    <Drawer
      open
      onClose={close}
      title={result ? "Exclusion added" : "Add an exclusion"}
      width={520}
      header={
        <div>
          <h2 className="text-sm font-semibold tracking-[-0.012em]">
            {result ? "Exclusion added" : "Add an exclusion"}
          </h2>
          <p className="text-[12px] text-ink-2 mt-0.5">
            {result
              ? result.entry.blacklisted
                ? "Deleted, and kept out of every future run."
                : "Discovery will stop expanding on it from the next run onwards."
              : "Discovery stops finding new assets through an excluded object. What it already found is kept and still scanned — unless you blacklist it."}
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
            <Button onClick={close} disabled={saving}>
              Cancel
            </Button>
            <Button
              variant={blacklist ? "danger" : "primary"}
              icon="ban"
              loading={saving}
              disabled={!value.trim()}
              onClick={() => void handleCreate()}
            >
              {blacklist ? "Blacklist" : "Add exclusion"}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="flex flex-col gap-4">
          <div className="flex items-start gap-3 p-3.5 rounded-lg border border-ok/40 bg-ok-wash">
            <Icon name="check" size={15} className="text-ok mt-px" strokeWidth={2.2} />
            <div className="min-w-0">
              <div className="text-[12.5px] font-semibold text-ink flex items-center gap-1.5">
                {result.entry.blacklisted ? "Blacklisted" : "Excluded"}
                {isPattern(result.entry.object_value) && <Chip>Pattern</Chip>}
              </div>
              <p className="mono text-[12px] text-ink-2 mt-0.5 break-all">
                {result.entry.object_type} · {result.entry.object_value}
              </p>
            </div>
          </div>

          {result.entry.blacklisted ? (
            <div className="flex items-start gap-3 p-3.5 rounded-lg border border-crit/40 bg-crit-wash">
              <Icon name="alert" size={15} className="text-crit mt-px" />
              <div className="min-w-0">
                <div className="text-[12.5px] font-semibold text-ink">Blacklist deletion</div>
                <p className="text-[12px] text-ink-2 mt-0.5">
                  <span className="mono text-ink">{num(result.assets_deleted ?? 0)}</span> asset
                  {(result.assets_deleted ?? 0) === 1 ? "" : "s"} — the object itself and everything discovered
                  through it — {(result.assets_deleted ?? 0) === 1 ? "has" : "have"} been deleted, along with
                  their findings and scans. Discovery will not store them again.
                </p>
              </div>
            </div>
          ) : result.descendants_deleted > 0 ? (
            <div className="flex items-start gap-3 p-3.5 rounded-lg border border-med/40 bg-med-wash">
              <Icon name="alert" size={15} className="text-med mt-px" />
              <div className="min-w-0">
                <div className="text-[12.5px] font-semibold text-ink">Cascade deletion</div>
                <p className="text-[12px] text-ink-2 mt-0.5">
                  <span className="mono text-ink">{num(result.descendants_deleted)}</span> asset
                  {result.descendants_deleted === 1 ? " that was" : "s that were"} discovered through this object
                  {result.descendants_deleted === 1 ? " has" : " have"} been deleted from the database.
                </p>
              </div>
            </div>
          ) : (
            <p className="text-[12.5px] text-ink-2">No assets were deleted.</p>
          )}

          {(result.queue_items_removed ?? 0) > 0 || (result.scans_cancelled ?? 0) > 0 ? (
            <div className="flex items-start gap-3 p-3.5 rounded-lg border border-rule bg-surface-2">
              <Icon name="stop" size={15} className="text-ink-2 mt-px" />
              <div className="min-w-0">
                <div className="text-[12.5px] font-semibold text-ink">Applied to the run in progress</div>
                <p className="text-[12px] text-ink-2 mt-0.5">
                  {(result.queue_items_removed ?? 0) > 0 && (
                    <>
                      <span className="mono text-ink">{num(result.queue_items_removed ?? 0)}</span> queued
                      discovery item
                      {(result.queue_items_removed ?? 0) === 1 ? " was" : "s were"} dropped
                      {(result.scans_cancelled ?? 0) > 0 ? ", and " : "."}
                    </>
                  )}
                  {(result.scans_cancelled ?? 0) > 0 && (
                    <>
                      <span className="mono text-ink">{num(result.scans_cancelled ?? 0)}</span> running scan
                      {(result.scans_cancelled ?? 0) === 1 ? " was" : "s were"} cancelled.
                    </>
                  )}
                </p>
              </div>
            </div>
          ) : null}
        </div>
      ) : (
        <div className="flex flex-col gap-3.5">
          {error && <ErrorState error={error} />}

          <div>
            <Label>Object type</Label>
            <Select
              value={objectType}
              onChange={(event) => setObjectType(event.target.value as ExclusionObjectType)}
              aria-label="Object type"
            >
              {EXCLUSION_TYPES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </div>

          <div>
            <Label>Value</Label>
            <Input
              autoFocus
              value={value}
              onChange={(event) => setValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void handleCreate();
                }
              }}
              placeholder={type.placeholder}
              className="mono"
              aria-label="Value to exclude"
            />
            {type.wildcards && (
              <p className="text-[12px] text-ink-2 mt-1.5">
                <span className="mono text-ink">{WILDCARD}</span> stands for anything, dots included:{" "}
                <span className="mono">*.cdn.example.com</span> covers every name under{" "}
                <span className="mono">cdn.example.com</span> at any depth, and leaves the apex itself alone.
                A plain domain entry already covers both.
              </p>
            )}
          </div>

          <div>
            <Label>Reason (optional)</Label>
            <Textarea
              rows={3}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Why is this excluded? A CDN, not ours, a false positive…"
            />
          </div>

          {!blacklist && (
            <div className="rounded-lg border border-rule bg-surface-2 p-3">
              <Checkbox
                checked={cascade}
                onChange={setCascade}
                label={<span className="font-medium">Delete descendant assets</span>}
              />
              <p className="text-[12px] text-ink-2 mt-1.5 pl-[23px]">
                Everything discovered from this object — subdomains, resolved IPs, anything reached by pivoting —
                is deleted from the database. The object itself is kept. Leave it off to stop future
                discovery without removing history.
              </p>
            </div>
          )}

          <div className="rounded-lg border border-crit/40 bg-crit-wash/60 p-3">
            <Checkbox
              checked={blacklist}
              onChange={setBlacklist}
              label={<span className="font-medium">Blacklist it as well</span>}
            />
            <p className="text-[12px] text-ink-2 mt-1.5 pl-[23px]">
              Delete the matching assets outright, together with everything discovered through them. Their
              findings, scans and score contribution go with them, and discovery will never store them again.
              This cannot be undone.
            </p>
          </div>
        </div>
      )}
    </Drawer>
  );
}

/**
 * Promote an existing exclusion to a blacklist.
 *
 * A separate confirmation rather than a toggle in the row, because the two
 * strengths are not two settings of one switch: this one deletes assets, and a
 * misclick on a table row is not consent for that.
 */
export function ExclusionPromoteDrawer({
  entry,
  working,
  onClose,
  onConfirm,
}: {
  entry: ExclusionEntry | null;
  working: boolean;
  onClose: () => void;
  onConfirm: (entry: ExclusionEntry) => Promise<void> | void;
}) {
  if (!entry) return null;
  const type = exclusionType(entry.object_type);

  return (
    <Drawer
      open
      onClose={onClose}
      title="Blacklist this object"
      width={480}
      header={
        <div>
          <h2 className="text-sm font-semibold tracking-[-0.012em]">Blacklist this object</h2>
          <p className="text-[12px] text-ink-2 mt-0.5">Excluding can be undone. This cannot.</p>
        </div>
      }
      footer={
        <>
          <div className="flex-1" />
          <Button onClick={onClose} disabled={working}>
            Cancel
          </Button>
          <Button variant="danger" icon="ban" loading={working} onClick={() => void onConfirm(entry)}>
            Blacklist
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <div className="rounded-lg border border-rule bg-surface-2 p-3">
          <div className="flex items-center gap-2">
            <Chip>
              <Icon name={type.icon} size={11} className="text-ink-3" />
              {type.label}
            </Chip>
            <span className="mono text-[12.5px] break-all">{entry.object_value}</span>
          </div>
          {entry.reason && <p className="text-[12px] text-ink-2 mt-2">{entry.reason}</p>}
        </div>

        <div className="flex items-start gap-3 p-3.5 rounded-lg border border-crit/40 bg-crit-wash">
          <Icon name="alert" size={15} className="text-crit mt-px" />
          <div className="text-[12px] text-ink">
            <p className="font-semibold text-crit">The matching assets are deleted.</p>
            <p className="mt-1 text-ink-2">
              The asset this entry names and everything discovered through it are removed, along with their
              findings, scans and their contribution to the risk score. Discovery will never store them again.
            </p>
          </div>
        </div>
      </div>
    </Drawer>
  );
}

/** Removing an exclusion puts the object back in scope; say so before it happens. */
export function ExclusionDeleteDrawer({
  entry,
  onClose,
  onDeleted,
}: {
  entry: ExclusionEntry | null;
  onClose: () => void;
  onDeleted: () => Promise<void> | void;
}) {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!entry) return null;
  const type = exclusionType(entry.object_type);

  async function handleDelete() {
    if (!entry) return;
    setDeleting(true);
    setError(null);
    try {
      await deleteExclusion(entry.id);
      await onDeleted();
      onClose();
    } catch (err) {
      setError((err as Error).message);
      setDeleting(false);
    }
  }

  return (
    <Drawer
      open
      onClose={onClose}
      title="Remove exclusion"
      width={480}
      header={
        <div>
          <h2 className="text-sm font-semibold tracking-[-0.012em]">Remove exclusion</h2>
          <p className="text-[12px] text-ink-2 mt-0.5">This object becomes discoverable again.</p>
        </div>
      }
      footer={
        <>
          <div className="flex-1" />
          <Button onClick={onClose} disabled={deleting}>
            Cancel
          </Button>
          <Button variant="danger" icon="trash" loading={deleting} onClick={() => void handleDelete()}>
            Remove exclusion
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {error && <ErrorState error={error} />}

        <div className="rounded-lg border border-rule bg-surface-2 p-3">
          <div className="flex items-center gap-2">
            <Chip>
              <Icon name={type.icon} size={11} className="text-ink-3" />
              {type.label}
            </Chip>
            <span className="mono text-[12.5px] break-all">{entry.object_value}</span>
          </div>
          {entry.reason && <p className="text-[12px] text-ink-2 mt-2">{entry.reason}</p>}
        </div>

        <div className="flex items-start gap-3 p-3.5 rounded-lg border border-med/40 bg-med-wash">
          <Icon name="alert" size={15} className="text-med mt-px" />
          <p className="text-[12px] text-ink">
            Once removed, this object and everything under it can be rediscovered by the next run. Assets a
            cascade or a blacklist deleted are gone for good, but equivalents may be discovered again.
          </p>
        </div>
      </div>
    </Drawer>
  );
}

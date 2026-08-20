"use client";

import { useState } from "react";
import {
  createBlacklistEntry,
  deleteBlacklistEntry,
  type BlacklistEntry,
  type BlacklistObjectType,
  type BlacklistResult,
} from "@/app/api";
import { Button, Checkbox, Chip, Drawer, ErrorState, Icon, Input, Label, Select, Textarea } from "@/components/kit";
import { num } from "@/lib/format";
import { EXCLUSION_TYPES, exclusionType } from "./exclusionTypes";

/**
 * Add an exclusion. The cascade checkbox is the consequential part: with it on,
 * everything already discovered *through* this object is deleted as well, and
 * the confirmation says how many rows that was.
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
  const [objectType, setObjectType] = useState<BlacklistObjectType>("domain");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [cascade, setCascade] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BlacklistResult | null>(null);

  const type = exclusionType(objectType);

  function reset() {
    setObjectType("domain");
    setValue("");
    setReason("");
    setCascade(true);
    setError(null);
    setResult(null);
  }

  function close() {
    reset();
    onClose();
  }

  async function handleCreate() {
    if (!value.trim()) {
      setError("A value is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const created = await createBlacklistEntry({
        object_type: objectType,
        object_value: value.trim(),
        reason: reason.trim() || undefined,
        delete_descendants: cascade,
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
              ? "Discovery will skip it from the next run onwards."
              : "Excluded objects are skipped by every discovery run, along with anything beneath them."}
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
              variant="primary"
              icon="ban"
              loading={saving}
              disabled={!value.trim()}
              onClick={() => void handleCreate()}
            >
              Add exclusion
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
              <div className="text-[12.5px] font-semibold text-ink">Excluded</div>
              <p className="mono text-[12px] text-ink-2 mt-0.5 break-all">
                {result.entry.object_type} · {result.entry.object_value}
              </p>
            </div>
          </div>

          {result.descendants_deleted > 0 ? (
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
            <p className="text-[12.5px] text-ink-2">No descendant assets were deleted.</p>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-3.5">
          {error && <ErrorState error={error} />}

          <div>
            <Label>Object type</Label>
            <Select
              value={objectType}
              onChange={(event) => setObjectType(event.target.value as BlacklistObjectType)}
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

          <div className="rounded-lg border border-rule bg-surface-2 p-3">
            <Checkbox
              checked={cascade}
              onChange={setCascade}
              label={<span className="font-medium">Delete descendant assets</span>}
            />
            <p className="text-[12px] text-ink-2 mt-1.5 pl-[23px]">
              Everything discovered from this object — subdomains, resolved IPs, anything reached by pivoting — is
              deleted from the database. Leave it off to stop future discovery without removing history.
            </p>
          </div>
        </div>
      )}
    </Drawer>
  );
}

/** Removing an exclusion puts the object back in scope; say so before it happens. */
export function ExclusionDeleteDrawer({
  entry,
  onClose,
  onDeleted,
}: {
  entry: BlacklistEntry | null;
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
      await deleteBlacklistEntry(entry.id);
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
            Once removed, this object and everything under it can be rediscovered by the next run, and any assets the
            cascade deleted may come back.
          </p>
        </div>
      </div>
    </Drawer>
  );
}

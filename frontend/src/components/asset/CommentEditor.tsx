"use client";

import { useEffect, useRef, useState } from "react";
import { Button, Textarea } from "@/components/kit";
import { cn } from "@/lib/cn";

const MAX_LENGTH = 1000;

/**
 * The analyst note on an asset.
 *
 * The detail view refreshes itself in the background every few seconds, so the
 * one thing this component must guarantee is that a poll landing mid-sentence
 * cannot overwrite what someone is typing: the saved value is only copied into
 * the draft while the draft is clean.
 */
export function CommentEditor({
  comment,
  onSave,
  disabled,
}: {
  comment: string | null | undefined;
  onSave: (next: string | null) => Promise<void>;
  disabled?: boolean;
}) {
  const saved = comment ?? "";
  const [draft, setDraft] = useState(saved);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const dirtyRef = useRef(false);
  dirtyRef.current = dirty;

  // Adopt the server value only when there is nothing unsaved to lose.
  useEffect(() => {
    if (dirtyRef.current) return;
    setDraft(saved);
  }, [saved]);

  const change = (next: string) => {
    setDraft(next);
    setDirty(next !== saved);
  };

  const reset = () => {
    setDraft(saved);
    setDirty(false);
  };

  const save = async () => {
    setSaving(true);
    try {
      const trimmed = draft.trim();
      await onSave(trimmed.length > 0 ? trimmed : null);
      // The parent hands the persisted asset back on the next render; until then
      // treat the draft as clean so a poll may resynchronise it.
      setDirty(false);
    } finally {
      setSaving(false);
    }
  };

  const remaining = MAX_LENGTH - draft.length;

  return (
    <div className="flex flex-col gap-2">
      <Textarea
        value={draft}
        onChange={(event) => change(event.target.value)}
        maxLength={MAX_LENGTH}
        rows={4}
        disabled={disabled || saving}
        placeholder="Why does this asset matter, what is it for, who owns it…"
        aria-label="Analyst comment"
      />
      <div className="flex items-center justify-between gap-3">
        <span className={cn("mono text-[11px]", remaining < 100 ? "text-med" : "text-ink-3")}>
          {draft.length}/{MAX_LENGTH}
        </span>
        <div className="flex items-center gap-2">
          {dirty && <span className="text-[11.5px] text-ink-3">Unsaved</span>}
          <Button size="sm" onClick={reset} disabled={!dirty || saving || disabled}>
            Reset
          </Button>
          <Button size="sm" variant="primary" onClick={save} loading={saving} disabled={!dirty || disabled}>
            Save
          </Button>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Card,
  CardHeader,
  Drawer,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Select,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Textarea,
} from "@/components/kit";
import {
  createTag,
  deleteTag,
  listTags,
  runAutoTagAll,
  runAutoTagForTag,
  updateTag,
  type AutoTagResult,
  type TagCreate,
  type TagUpdate,
  type TagWithCount,
} from "@/app/api";
import { num } from "@/lib/format";
import { cn } from "@/lib/cn";
import { ConfirmDrawer, Field, Note, ResultBanner, errorMessage } from "./shared";

/** Swatch palette. These are stored per tag, so they are content, not theme. */
const TAG_COLORS = [
  "#6366f1",
  "#8b5cf6",
  "#ec4899",
  "#ef4444",
  "#f97316",
  "#eab308",
  "#22c55e",
  "#14b8a6",
  "#06b6d4",
  "#3b82f6",
];

const emptyForm = (): TagCreate => ({
  name: "",
  description: "",
  importance: 3,
  rule_type: undefined,
  rule_value: "",
  color: TAG_COLORS[Math.floor(Math.random() * TAG_COLORS.length)],
});

/** Importance as five segments — readable down a column, unlike a number alone. */
function Importance({ value }: { value: number }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span className="flex gap-0.5" aria-hidden="true">
        {Array.from({ length: 5 }).map((_, i) => (
          <span
            key={i}
            className={cn("block w-[7px] h-[13px] rounded-[2px]", i < value ? "bg-accent" : "bg-surface-2")}
          />
        ))}
      </span>
      <span className="mono text-[11px] text-ink-3">{value}/5</span>
    </span>
  );
}

export function TagsPane() {
  const [tags, setTags] = useState<TagWithCount[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editing, setEditing] = useState<TagWithCount | "new" | null>(null);
  const [form, setForm] = useState<TagCreate>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [deleting, setDeleting] = useState<TagWithCount | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [autoTagResult, setAutoTagResult] = useState<AutoTagResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await listTags(100, 0);
      setTags(response.tags);
      setTotalCount(response.total_count);
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function openCreate() {
    setForm(emptyForm());
    setFormError(null);
    setEditing("new");
  }

  function openEdit(tag: TagWithCount) {
    setForm({
      name: tag.name,
      description: tag.description || "",
      importance: tag.importance,
      rule_type: tag.rule_type || undefined,
      rule_value: tag.rule_value || "",
      color: tag.color || TAG_COLORS[0],
    });
    setFormError(null);
    setEditing(tag);
  }

  async function submit() {
    if (!form.name.trim()) {
      setFormError("Tag name is required");
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      if (editing && editing !== "new") {
        const payload: TagUpdate = {
          name: form.name.trim(),
          description: form.description?.trim() || undefined,
          importance: form.importance,
          color: form.color,
        };
        // Emptying either half of the rule clears it on the server; without the
        // explicit flag a PATCH would simply leave the old rule in place.
        if (!form.rule_type || !form.rule_value?.trim()) {
          payload.clear_rule = true;
        } else {
          payload.rule_type = form.rule_type;
          payload.rule_value = form.rule_value.trim();
        }
        await updateTag(editing.id, payload);
      } else {
        const payload: TagCreate = {
          name: form.name.trim(),
          description: form.description?.trim() || undefined,
          importance: form.importance,
          color: form.color,
        };
        if (form.rule_type && form.rule_value?.trim()) {
          payload.rule_type = form.rule_type;
          payload.rule_value = form.rule_value.trim();
        }
        await createTag(payload);
      }
      setEditing(null);
      await load();
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete() {
    if (!deleting) return;
    setSubmitting(true);
    try {
      await deleteTag(deleting.id);
      setDeleting(null);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSubmitting(false);
    }
  }

  async function runFor(tagId: string) {
    setRunning(tagId);
    setAutoTagResult(null);
    try {
      setAutoTagResult(await runAutoTagForTag(tagId));
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRunning(null);
    }
  }

  async function runAll() {
    setRunning("all");
    setAutoTagResult(null);
    try {
      setAutoTagResult(await runAutoTagAll());
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRunning(null);
    }
  }

  const withRules = tags.filter((t) => t.rule_type).length;
  const applications = tags.reduce((sum, t) => sum + t.asset_count, 0);

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} onRetry={load} />}

      {autoTagResult && (
        <ResultBanner
          tone={autoTagResult.errors.length > 0 ? "warn" : "ok"}
          title={autoTagResult.errors.length > 0 ? "Auto-tagging finished with warnings" : "Auto-tagging finished"}
          detail={`Tagged ${num(autoTagResult.assets_tagged)} assets with ${num(autoTagResult.tags_applied)} tag applications.`}
          errors={autoTagResult.errors}
          onDismiss={() => setAutoTagResult(null)}
        />
      )}

      <Card>
        <CardHeader
          title="Tags"
          hint={`${num(totalCount)} defined · ${num(withRules)} with rules · ${num(applications)} applications`}
          actions={
            <>
              <Button
                size="sm"
                icon="play"
                onClick={runAll}
                loading={running === "all"}
                disabled={!!running || withRules === 0}
              >
                Run all rules
              </Button>
              <Button size="sm" variant="primary" icon="plus" onClick={openCreate}>
                New tag
              </Button>
            </>
          }
        />
        {loading && tags.length === 0 ? (
          <LoadingBlock label="Loading tags" />
        ) : tags.length === 0 ? (
          <EmptyState
            icon="tag"
            title="No tags defined"
            description="Tags carry importance onto the assets they touch, and can apply themselves by rule."
            action={
              <Button variant="primary" icon="plus" onClick={openCreate}>
                Create the first tag
              </Button>
            }
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Tag</TH>
                <TH className="w-[130px]">Importance</TH>
                <TH>Auto-tag rule</TH>
                <TH className="w-[80px] text-right">Assets</TH>
                <TH className="w-[210px] text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {tags.map((tag) => (
                <TR key={tag.id}>
                  <TD>
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span
                        className="block w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ background: tag.color || TAG_COLORS[0] }}
                        aria-hidden="true"
                      />
                      <div className="min-w-0">
                        <div className="font-medium truncate">{tag.name}</div>
                        {tag.description && (
                          <div className="text-[11.5px] text-ink-3 truncate max-w-[280px]">{tag.description}</div>
                        )}
                      </div>
                    </div>
                  </TD>
                  <TD>
                    <Importance value={tag.importance} />
                  </TD>
                  <TD>
                    {tag.rule_type ? (
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="lbl shrink-0">{tag.rule_type === "regex" ? "Regex" : "IP range"}</span>
                        <code className="mono text-[11px] text-ink-2 truncate max-w-[240px]">{tag.rule_value}</code>
                      </div>
                    ) : (
                      <span className="text-[12px] text-ink-3">Manual only</span>
                    )}
                  </TD>
                  <TD className="text-right">
                    <span className="fig text-[12.5px]">{num(tag.asset_count)}</span>
                  </TD>
                  <TD>
                    <div className="flex gap-1.5 justify-end">
                      {tag.rule_type && (
                        <Button
                          size="sm"
                          icon="play"
                          onClick={() => runFor(tag.id)}
                          loading={running === tag.id}
                          disabled={!!running}
                        >
                          Run
                        </Button>
                      )}
                      <Button size="sm" onClick={() => openEdit(tag)}>
                        Edit
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => setDeleting(tag)}>
                        Delete
                      </Button>
                    </div>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <Drawer
        open={!!editing}
        onClose={() => {
          if (!submitting) setEditing(null);
        }}
        title={editing === "new" ? "New tag" : "Edit tag"}
        width={560}
        header={
          <div className="min-w-0">
            <div className="text-sm font-semibold tracking-[-0.012em]">
              {editing === "new" ? "New tag" : "Edit tag"}
            </div>
            <p className="text-[12px] text-ink-2 mt-0.5">
              Importance rides onto every asset this tag touches.
            </p>
          </div>
        }
        footer={
          <>
            <Button variant="primary" onClick={submit} loading={submitting} disabled={!form.name.trim()}>
              {editing === "new" ? "Create tag" : "Save changes"}
            </Button>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={submitting}>
              Cancel
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name">
            <Input
              value={form.name}
              autoFocus
              placeholder="Production, Customer-facing, Legacy…"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </Field>

          <Field label="Colour">
            <div className="flex items-center gap-2 flex-wrap">
              {TAG_COLORS.map((color) => (
                <button
                  key={color}
                  type="button"
                  aria-label={`Use colour ${color}`}
                  onClick={() => setForm({ ...form, color })}
                  className={cn(
                    "w-[22px] h-[22px] rounded-md border-2 transition-transform",
                    form.color === color ? "border-ink scale-110" : "border-transparent hover:scale-105",
                  )}
                  style={{ background: color }}
                />
              ))}
              <input
                type="color"
                aria-label="Custom colour"
                value={form.color || TAG_COLORS[0]}
                onChange={(e) => setForm({ ...form, color: e.target.value })}
                className="w-[34px] h-[26px] rounded-md border border-rule-2 bg-surface cursor-pointer p-0.5"
              />
            </div>
          </Field>

          <Field label="Description">
            <Textarea
              rows={3}
              value={form.description || ""}
              placeholder="What does this tag mean?"
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </Field>

          <Field label="Default importance">
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={1}
                max={5}
                step={1}
                value={form.importance ?? 3}
                onChange={(e) => setForm({ ...form, importance: Number(e.target.value) })}
                className="flex-1 accent-[var(--accent)]"
                aria-label="Default importance"
              />
              <Importance value={form.importance ?? 3} />
            </div>
          </Field>

          <div className="h-px bg-rule" />

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Rule type">
              <Select
                value={form.rule_type || ""}
                onChange={(e) =>
                  setForm({
                    ...form,
                    rule_type: (e.target.value as "regex" | "ip_range") || undefined,
                  })
                }
              >
                <option value="">No rule — manual only</option>
                <option value="regex">Regex (domains, ASNs, certificates, orgs)</option>
                <option value="ip_range">IP range (CIDR)</option>
              </Select>
            </Field>
            <Field label={form.rule_type === "ip_range" ? "CIDR ranges" : "Regex pattern"}>
              <Input
                className="mono"
                spellCheck={false}
                disabled={!form.rule_type}
                value={form.rule_value || ""}
                placeholder={
                  form.rule_type === "ip_range" ? "10.0.0.0/8, 192.168.1.0/24" : ".*\\.prod\\.example\\.com$"
                }
                onChange={(e) => setForm({ ...form, rule_value: e.target.value })}
              />
            </Field>
          </div>

          {form.rule_type === "regex" && (
            <Note icon="tag">
              Matched against domain names, ASN numbers, certificate subjects and organisation names.
            </Note>
          )}
          {form.rule_type === "ip_range" && (
            <Note icon="tag">Matched against IP addresses. Separate multiple ranges with commas.</Note>
          )}
          {editing !== "new" && editing?.rule_type && !form.rule_type && (
            <Note icon="alert">The existing rule will be removed when you save.</Note>
          )}

          {formError && (
            <div role="alert" className="rounded-md border border-crit/40 bg-crit-wash px-3 py-2 text-[12px] text-crit">
              {formError}
            </div>
          )}
        </div>
      </Drawer>

      <ConfirmDrawer
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title="Delete tag"
        hint={deleting?.name}
        confirmLabel="Delete tag"
        onConfirm={handleDelete}
        busy={submitting}
      >
        {deleting && (
          <>
            <p className="text-[12.5px] text-ink-2">
              <span className="font-medium text-ink">{deleting.name}</span> is removed from the tag list.
            </p>
            {deleting.asset_count > 0 && (
              <div className="rounded-md border border-med/40 bg-med-wash px-3 py-2.5 text-[12px] text-ink-2">
                It is applied to {num(deleting.asset_count)} asset
                {deleting.asset_count === 1 ? "" : "s"}, which will be untagged.
              </div>
            )}
          </>
        )}
      </ConfirmDrawer>
    </div>
  );
}

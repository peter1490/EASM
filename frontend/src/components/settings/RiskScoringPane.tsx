"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
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
  SeverityChip,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Textarea,
  Toggle,
} from "@/components/kit";
import {
  bulkUpdateFindingTypeConfigs,
  listFindingTypeConfigs,
  recalculateAllRisks,
  updateFindingTypeConfig,
  type FindingTypeConfig,
  type FindingTypeConfigUpdate,
  type RiskRecalculationResult,
} from "@/app/api";
import { num, score } from "@/lib/format";
import { SEVERITY_ORDER, severityTone } from "@/lib/severity";
import { cn } from "@/lib/cn";
import { Field, Note, ResultBanner, errorMessage } from "./shared";

// Limits the backend enforces. Checked here so a bad row never reaches the API.
const SCORE_MIN = 0;
const SCORE_MAX = 100;
const MULTIPLIER_MIN = 0.1;
const MULTIPLIER_MAX = 10;

const DEFAULT_SEVERITY_SCORES: Array<[string, number]> = [
  ["critical", 40],
  ["high", 20],
  ["medium", 10],
  ["low", 3],
  ["info", 0.5],
];

function scoreValid(v: number) {
  return Number.isFinite(v) && v >= SCORE_MIN && v <= SCORE_MAX;
}
function multiplierValid(v: number) {
  return Number.isFinite(v) && v >= MULTIPLIER_MIN && v <= MULTIPLIER_MAX;
}
function severityValid(v: string) {
  return (SEVERITY_ORDER as string[]).includes(v);
}

function humaniseCategory(category: string) {
  return category.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function RiskScoringPane() {
  const [configs, setConfigs] = useState<FindingTypeConfig[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [category, setCategory] = useState("all");
  /** Staged inline edits, keyed by finding_type. One bulk PATCH commits them. */
  const [pending, setPending] = useState<Map<string, FindingTypeConfigUpdate>>(new Map());
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const [editing, setEditing] = useState<FindingTypeConfig | null>(null);
  const [draft, setDraft] = useState<FindingTypeConfigUpdate>({});
  const [draftError, setDraftError] = useState<string | null>(null);
  const [draftSaving, setDraftSaving] = useState(false);

  const [recalculating, setRecalculating] = useState(false);
  const [recalcResult, setRecalcResult] = useState<RiskRecalculationResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await listFindingTypeConfigs();
      setConfigs(response.configs);
      setCategories(response.categories);
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

  const visible = useMemo(
    () => configs.filter((c) => category === "all" || c.category === category),
    [configs, category],
  );

  function stage(findingType: string, field: keyof FindingTypeConfigUpdate, value: unknown) {
    setPending((prev) => {
      const next = new Map(prev);
      next.set(findingType, { ...(next.get(findingType) || {}), [field]: value });
      return next;
    });
    setSaveError(null);
  }

  /** Every staged row that would be rejected by the backend's own validation. */
  const invalidRows = useMemo(() => {
    const bad: string[] = [];
    for (const [findingType, update] of pending.entries()) {
      if (update.severity_score !== undefined && !scoreValid(update.severity_score)) bad.push(findingType);
      else if (update.type_multiplier !== undefined && !multiplierValid(update.type_multiplier)) bad.push(findingType);
      else if (update.default_severity !== undefined && !severityValid(update.default_severity)) bad.push(findingType);
    }
    return bad;
  }, [pending]);

  async function saveAll() {
    if (pending.size === 0) return;
    if (invalidRows.length > 0) {
      setSaveError(
        `Out of range: ${invalidRows.slice(0, 3).join(", ")}. Score must be ${SCORE_MIN}–${SCORE_MAX} and multiplier ${MULTIPLIER_MIN}–${MULTIPLIER_MAX}.`,
      );
      return;
    }
    setSaving(true);
    setSaveError(null);
    try {
      const result = await bulkUpdateFindingTypeConfigs(
        [...pending.entries()].map(([finding_type, update]) => ({ finding_type, ...update })),
      );
      if (result.error_count > 0) {
        setSaveError(`${result.error_count} rejected: ${result.errors.slice(0, 3).join(", ")}`);
      }
      setPending(new Map());
      await load();
    } catch (e) {
      setSaveError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  function openEdit(config: FindingTypeConfig) {
    const staged = pending.get(config.finding_type);
    setDraft({
      display_name: config.display_name,
      default_severity: staged?.default_severity ?? config.default_severity,
      severity_score: staged?.severity_score ?? config.severity_score,
      type_multiplier: staged?.type_multiplier ?? config.type_multiplier,
      description: config.description || undefined,
      is_enabled: staged?.is_enabled ?? config.is_enabled,
    });
    setDraftError(null);
    setEditing(config);
  }

  async function saveDraft() {
    if (!editing) return;
    if (draft.severity_score !== undefined && !scoreValid(draft.severity_score)) {
      setDraftError(`Severity score must be between ${SCORE_MIN} and ${SCORE_MAX}.`);
      return;
    }
    if (draft.type_multiplier !== undefined && !multiplierValid(draft.type_multiplier)) {
      setDraftError(`Type multiplier must be between ${MULTIPLIER_MIN} and ${MULTIPLIER_MAX}.`);
      return;
    }
    if (draft.default_severity !== undefined && !severityValid(draft.default_severity)) {
      setDraftError("Pick one of critical, high, medium, low or info.");
      return;
    }
    setDraftSaving(true);
    setDraftError(null);
    try {
      await updateFindingTypeConfig(editing.finding_type, draft);
      // The row is now authoritative on the server; drop any staged copy of it.
      setPending((prev) => {
        const next = new Map(prev);
        next.delete(editing.finding_type);
        return next;
      });
      setEditing(null);
      setDraft({});
      await load();
    } catch (e) {
      setDraftError(errorMessage(e));
    } finally {
      setDraftSaving(false);
    }
  }

  async function recalculate() {
    setRecalculating(true);
    setRecalcResult(null);
    try {
      setRecalcResult(await recalculateAllRisks());
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRecalculating(false);
    }
  }

  const enabled = configs.filter((c) => c.is_enabled).length;

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} onRetry={load} />}

      {recalcResult && (
        <ResultBanner
          tone={recalcResult.error_count > 0 ? "warn" : "ok"}
          title={recalcResult.error_count > 0 ? "Recalculation finished with errors" : "Recalculation finished"}
          detail={`${num(recalcResult.success_count)} assets rescored${
            recalcResult.error_count > 0 ? `, ${num(recalcResult.error_count)} failed` : ""
          }.`}
          errors={recalcResult.errors}
          onDismiss={() => setRecalcResult(null)}
        />
      )}

      {pending.size > 0 && (
        <div className="sticky top-0 z-20 flex items-center justify-between gap-4 rounded-lg border border-accent/40 bg-accent-wash px-3.5 py-2.5">
          <div className="min-w-0">
            <div className="text-[12.5px] font-semibold text-accent-ink">
              {pending.size} unsaved change{pending.size === 1 ? "" : "s"}
            </div>
            <p className="text-[11.5px] text-ink-2 mt-0.5">
              Edits are staged locally and sent as one update. Recalculation is held until you save.
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <Button size="sm" variant="ghost" onClick={() => setPending(new Map())} disabled={saving}>
              Discard
            </Button>
            <Button size="sm" variant="primary" onClick={saveAll} loading={saving}>
              Save all changes
            </Button>
          </div>
        </div>
      )}

      {saveError && <ErrorState error={saveError} />}

      <Card>
        <CardHeader
          title="Finding types"
          hint={`${num(configs.length)} types · ${num(enabled)} enabled · ${num(categories.length)} categories`}
          actions={
            <>
              <Select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-[190px] h-[26px] text-[12px]"
                aria-label="Filter by category"
              >
                <option value="all">All categories</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {humaniseCategory(c)}
                  </option>
                ))}
              </Select>
              <Button
                size="sm"
                icon="refresh"
                onClick={recalculate}
                loading={recalculating}
                disabled={pending.size > 0}
                title={pending.size > 0 ? "Save your changes first" : "Rescore every asset"}
              >
                Recalculate all risks
              </Button>
            </>
          }
        />
        {loading && configs.length === 0 ? (
          <LoadingBlock label="Loading finding types" />
        ) : visible.length === 0 ? (
          <EmptyState
            icon="chart"
            title="No finding types"
            description="Nothing is configured for this category yet."
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Finding type</TH>
                <TH className="w-[130px]">Category</TH>
                <TH className="w-[90px]">Severity</TH>
                <TH className="w-[100px]">Score</TH>
                <TH className="w-[110px]">Multiplier</TH>
                <TH className="w-[80px]">Enabled</TH>
                <TH className="w-[70px] text-right">Edit</TH>
              </TR>
            </THead>
            <TBody>
              {visible.map((config) => {
                const staged = pending.get(config.finding_type);
                const currentScore = staged?.severity_score ?? config.severity_score;
                const currentMultiplier = staged?.type_multiplier ?? config.type_multiplier;
                const currentEnabled = staged?.is_enabled ?? config.is_enabled;
                const currentSeverity = staged?.default_severity ?? config.default_severity;
                return (
                  <TR key={config.id} className={cn(staged && "bg-accent-wash")}>
                    <TD>
                      <div className="min-w-0">
                        <div className="font-medium truncate">{config.display_name}</div>
                        <code className="mono text-[11px] text-ink-3 truncate block">{config.finding_type}</code>
                      </div>
                    </TD>
                    <TD className="text-ink-2 text-[12px]">{humaniseCategory(config.category)}</TD>
                    <TD>
                      <SeverityChip severity={currentSeverity} short />
                    </TD>
                    <TD>
                      <Input
                        type="number"
                        min={SCORE_MIN}
                        max={SCORE_MAX}
                        step={0.5}
                        value={currentScore}
                        invalid={!scoreValid(currentScore)}
                        className="w-[76px] h-[26px] mono text-center"
                        aria-label={`Severity score for ${config.display_name}`}
                        onChange={(e) => stage(config.finding_type, "severity_score", parseFloat(e.target.value) || 0)}
                      />
                    </TD>
                    <TD>
                      <Input
                        type="number"
                        min={MULTIPLIER_MIN}
                        max={MULTIPLIER_MAX}
                        step={0.1}
                        value={currentMultiplier}
                        invalid={!multiplierValid(currentMultiplier)}
                        className="w-[76px] h-[26px] mono text-center"
                        aria-label={`Type multiplier for ${config.display_name}`}
                        onChange={(e) =>
                          stage(config.finding_type, "type_multiplier", parseFloat(e.target.value) || MULTIPLIER_MIN)
                        }
                      />
                    </TD>
                    <TD>
                      <Toggle
                        checked={currentEnabled}
                        label={`Include ${config.display_name} in risk`}
                        onChange={(v) => stage(config.finding_type, "is_enabled", v)}
                      />
                    </TD>
                    <TD>
                      <div className="flex justify-end">
                        <Button size="sm" onClick={() => openEdit(config)}>
                          Edit
                        </Button>
                      </div>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="How a risk score is built" hint="Defaults applied when a finding carries no score" />
        <div className="p-4 space-y-3">
          <div className="grid gap-2 sm:grid-cols-5">
            {DEFAULT_SEVERITY_SCORES.map(([severity, value]) => {
              const tone = severityTone(severity);
              return (
                <div key={severity} className="rounded-md bg-surface-2 px-2.5 py-2">
                  <div className={cn("lbl", tone.text)}>{tone.label}</div>
                  <div className="fig text-[17px] mt-0.5">{score(value)}</div>
                </div>
              );
            })}
          </div>
          <code className="block mono text-[11px] text-ink-2 bg-surface-2 rounded-md px-3 py-2.5 leading-relaxed break-words">
            risk_score = (exposure_score + Σ((severity_score + cvss_bonus) × type_multiplier)) × importance_multiplier
          </code>
          <Note icon="chart">
            The result is capped at 100 and mapped to a level: critical at 80 and above, high at 60, medium at 40, low
            at 20, informational below that.
          </Note>
        </div>
      </Card>

      <Drawer
        open={!!editing}
        onClose={() => {
          if (!draftSaving) setEditing(null);
        }}
        title="Edit finding type"
        width={560}
        header={
          <div className="min-w-0">
            <div className="text-sm font-semibold tracking-[-0.012em] truncate">{editing?.display_name}</div>
            <code className="mono text-[11px] text-ink-3">{editing?.finding_type}</code>
          </div>
        }
        footer={
          <>
            <Button variant="primary" onClick={saveDraft} loading={draftSaving}>
              Save changes
            </Button>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={draftSaving}>
              Cancel
            </Button>
          </>
        }
      >
        {editing && (
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Display name">
                <Input
                  value={draft.display_name ?? ""}
                  onChange={(e) => setDraft({ ...draft, display_name: e.target.value })}
                />
              </Field>
              <Field label="Default severity">
                <Select
                  value={draft.default_severity ?? editing.default_severity}
                  onChange={(e) => setDraft({ ...draft, default_severity: e.target.value })}
                >
                  {SEVERITY_ORDER.map((s) => (
                    <option key={s} value={s}>
                      {severityTone(s).label}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>

            <Field label="Severity score" hint={`${SCORE_MIN} to ${SCORE_MAX}`}>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={SCORE_MIN}
                  max={SCORE_MAX}
                  step={0.5}
                  value={draft.severity_score ?? editing.severity_score}
                  onChange={(e) => setDraft({ ...draft, severity_score: parseFloat(e.target.value) })}
                  className="flex-1 accent-[var(--accent)]"
                  aria-label="Severity score"
                />
                <span className="fig text-[13px] w-[46px] text-right">
                  {score(draft.severity_score ?? editing.severity_score)}
                </span>
              </div>
            </Field>

            <Field label="Type multiplier" hint={`${MULTIPLIER_MIN} to ${MULTIPLIER_MAX}`}>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={MULTIPLIER_MIN}
                  max={MULTIPLIER_MAX}
                  step={0.1}
                  value={draft.type_multiplier ?? editing.type_multiplier}
                  onChange={(e) => setDraft({ ...draft, type_multiplier: parseFloat(e.target.value) })}
                  className="flex-1 accent-[var(--accent)]"
                  aria-label="Type multiplier"
                />
                <span className="fig text-[13px] w-[46px] text-right">
                  {score(draft.type_multiplier ?? editing.type_multiplier)}x
                </span>
              </div>
            </Field>

            <Field label="Description">
              <Textarea
                rows={3}
                value={draft.description ?? ""}
                placeholder="What does this finding type mean?"
                onChange={(e) => setDraft({ ...draft, description: e.target.value })}
              />
            </Field>

            <div className="flex items-center justify-between gap-3 rounded-md bg-surface-2 px-3 py-2.5">
              <div>
                <div className="text-[12.5px] font-medium">Include in risk calculations</div>
                <p className="text-[11.5px] text-ink-2 mt-0.5">
                  Disabled types stay visible as findings but stop contributing score.
                </p>
              </div>
              <Toggle
                checked={draft.is_enabled ?? editing.is_enabled}
                label="Include in risk calculations"
                onChange={(v) => setDraft({ ...draft, is_enabled: v })}
              />
            </div>

            {draftError && (
              <div role="alert" className="rounded-md border border-crit/40 bg-crit-wash px-3 py-2 text-[12px] text-crit">
                {draftError}
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createSeed, deleteSeed, listSeeds, type Seed, type SeedType } from "@/app/api";
import {
  Button,
  Card,
  CardHeader,
  Chip,
  EmptyState,
  ErrorState,
  Icon,
  Input,
  Label,
  LoadingBlock,
  RowActions,
  Select,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  type IconName,
} from "@/components/kit";
import { ago, dateTime, humanise } from "@/lib/format";
import { usePoll, useSilentLoad } from "./shared";

/**
 * The six seed types the form offers. `root_domain` and `acquisition_domain`
 * are a distinction this screen makes and the backend does not: both are saved
 * as `domain` (`api.ts` collapses them). The form says so rather than letting
 * you believe the label came back.
 */
const SEED_TYPES: Array<{ value: SeedType; label: string; icon: IconName; placeholder: string; savedAs?: string }> = [
  { value: "root_domain", label: "Root domain", icon: "globe", placeholder: "e.g. example.com", savedAs: "domain" },
  {
    value: "acquisition_domain",
    label: "Acquisition domain",
    icon: "building",
    placeholder: "Domain from an acquisition",
    savedAs: "domain",
  },
  { value: "cidr", label: "CIDR range", icon: "server", placeholder: "e.g. 10.0.0.0/24" },
  { value: "asn", label: "ASN", icon: "activity", placeholder: "e.g. AS12345" },
  { value: "keyword", label: "Keyword", icon: "key", placeholder: "Search keyword" },
  { value: "organization", label: "Organization", icon: "building", placeholder: "Company name" },
];

/** How a *stored* seed type reads — never guessing which form option produced it. */
function storedType(seedType: string): { label: string; icon: IconName } {
  if (seedType === "domain") return { label: "Domain", icon: "globe" };
  const match = SEED_TYPES.find((type) => type.value === seedType);
  return match ? { label: match.label, icon: match.icon } : { label: humanise(seedType), icon: "seed" };
}

export function SeedsSegment({ onCount }: { onCount?: (count: number) => void }) {
  // Held in a ref so an inline callback from the shell cannot re-trigger loads.
  const report = useRef(onCount);
  report.current = onCount;

  const [seeds, setSeeds] = useState<Seed[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const { loading, begin, done } = useSilentLoad();

  const [seedType, setSeedType] = useState<SeedType>("root_domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [adding, setAdding] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const load = useCallback(async () => {
    begin();
    try {
      const data = await listSeeds();
      setSeeds(data);
      setError(null);
      report.current?.(data.length);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      done();
    }
  }, [begin, done]);

  useEffect(() => {
    void load();
  }, [load]);

  usePoll(() => void load(), 60_000);

  const selected = SEED_TYPES.find((type) => type.value === seedType);

  const byType = useMemo(() => {
    const counts = new Map<string, number>();
    for (const seed of seeds) counts.set(seed.seed_type, (counts.get(seed.seed_type) ?? 0) + 1);
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [seeds]);

  async function handleAdd() {
    const trimmed = value.trim();
    if (!trimmed || adding) return;
    setAdding(true);
    setFormError(null);
    try {
      await createSeed({ seed_type: seedType, value: trimmed, note: note.trim() || undefined });
      setValue("");
      setNote("");
      await load();
    } catch (err) {
      setFormError((err as Error).message);
    } finally {
      setAdding(false);
    }
  }

  async function handleDelete(id: string) {
    setDeleting(id);
    try {
      await deleteSeed(id);
      setConfirmDelete(null);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDeleting(null);
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <Card>
        <CardHeader title="Add a seed" hint="Seeds are where every discovery run starts walking" />
        {/* Enter adds the seed from any field — the form would do that on its
            own, but the old screen bound it explicitly and people rely on it. */}
        <form
          className="p-4 flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void handleAdd();
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              void handleAdd();
            }
          }}
        >
          <div className="grid gap-3 md:grid-cols-[220px_1fr_1fr_auto] md:items-end">
            <div>
              <Label>Type</Label>
              <Select value={seedType} onChange={(event) => setSeedType(event.target.value as SeedType)}>
                {SEED_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <Label>Value</Label>
              <Input
                value={value}
                onChange={(event) => setValue(event.target.value)}
                placeholder={selected?.placeholder ?? "Enter a value"}
                aria-label="Seed value"
              />
            </div>
            <div>
              <Label>Note (optional)</Label>
              <Input
                value={note}
                onChange={(event) => setNote(event.target.value)}
                placeholder="Why this seed is here"
                aria-label="Seed note"
              />
            </div>
            <Button type="submit" variant="primary" icon="plus" loading={adding} disabled={!value.trim()}>
              Add seed
            </Button>
          </div>

          <p className="text-[12px] text-ink-2">
            {selected?.savedAs ? (
              <>
                <span className="font-medium text-ink">{selected.label}</span> is stored as{" "}
                <span className="mono text-ink">{selected.savedAs}</span> — the backend keeps one domain type, so this
                seed will come back labelled Domain, not {selected.label}.
              </>
            ) : (
              <>
                Stored as <span className="mono text-ink">{seedType}</span>. Press Enter from any field to add.
              </>
            )}
          </p>

          {formError && <ErrorState error={formError} />}
        </form>
      </Card>

      <Card>
        <CardHeader
          title="Configured seeds"
          hint={seeds.length > 0 ? `${seeds.length} total` : undefined}
          actions={
            <Button size="sm" icon="refresh" onClick={() => void load()}>
              Refresh
            </Button>
          }
        />
        {byType.length > 0 && (
          <div className="flex flex-wrap gap-1.5 px-4 py-3 border-b border-rule">
            {byType.map(([type, count]) => {
              const info = storedType(type);
              return (
                <Chip key={type}>
                  <Icon name={info.icon} size={11} className="text-ink-3" />
                  {info.label}
                  <span className="mono text-ink-3">{count}</span>
                </Chip>
              );
            })}
          </div>
        )}
        {error && (
          <div className="p-4">
            <ErrorState error={error} onRetry={() => void load()} />
          </div>
        )}
        {loading ? (
          <LoadingBlock label="Loading seeds" />
        ) : seeds.length === 0 ? (
          <EmptyState
            icon="seed"
            title="No seeds configured"
            description="Add a root domain, an ASN or a CIDR range above and discovery has somewhere to start."
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Value</TH>
                <TH>Note</TH>
                <TH>Added</TH>
                <TH className="w-[168px]" />
              </TR>
            </THead>
            <TBody>
              {seeds.map((seed) => {
                const info = storedType(seed.seed_type);
                const confirming = confirmDelete === seed.id;
                return (
                  <TR key={seed.id}>
                    <TD>
                      <Chip>
                        <Icon name={info.icon} size={11} className="text-ink-3" />
                        {info.label}
                      </Chip>
                    </TD>
                    <TD className="mono text-[12.5px]">{seed.value}</TD>
                    <TD className="text-ink-2 text-[12.5px] max-w-[320px] truncate">{seed.note || "—"}</TD>
                    <TD className="text-ink-2 text-[12.5px]" title={dateTime(seed.created_at)}>
                      {ago(seed.created_at)}
                    </TD>
                    <TD>
                      {confirming ? (
                        <div className="flex gap-1.5 justify-end">
                          <Button size="sm" onClick={() => setConfirmDelete(null)}>
                            Cancel
                          </Button>
                          <Button
                            size="sm"
                            variant="danger"
                            loading={deleting === seed.id}
                            onClick={() => void handleDelete(seed.id)}
                          >
                            Delete seed
                          </Button>
                        </div>
                      ) : (
                        <RowActions>
                          <Button size="sm" variant="ghost" icon="trash" onClick={() => setConfirmDelete(seed.id)}>
                            Delete
                          </Button>
                        </RowActions>
                      )}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}

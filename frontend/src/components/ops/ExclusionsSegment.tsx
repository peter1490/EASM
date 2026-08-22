"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  getExclusionStats,
  listExclusions,
  updateExclusion,
  type ExclusionEntry,
  type ExclusionStats,
} from "@/app/api";
import {
  Button,
  Card,
  CardHeader,
  Chip,
  EmptyState,
  ErrorState,
  Icon,
  Input,
  LoadingBlock,
  RowActions,
  Select,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/kit";
import { ago, dateTime, num } from "@/lib/format";
import { EXCLUSION_TYPES, exclusionType, isPattern } from "./exclusionTypes";
import {
  ExclusionCreateDrawer,
  ExclusionDeleteDrawer,
  ExclusionPromoteDrawer,
} from "./ExclusionDrawers";
import { Pagination, useOpsRoles, usePoll, useSilentLoad } from "./shared";

const PAGE = 25;
const POLL_MS = 60_000;

/** The hard entries read as a destructive state, not a neutral one. */
const BLACKLIST_TONE = { text: "text-crit", wash: "bg-crit-wash" };

export function ExclusionsSegment({ onCount }: { onCount?: (count: number) => void }) {
  const { isAnalyst } = useOpsRoles();
  const report = useRef(onCount);
  report.current = onCount;

  const [entries, setEntries] = useState<ExclusionEntry[]>([]);
  const [stats, setStats] = useState<ExclusionStats | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [typeFilter, setTypeFilter] = useState("");
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const { loading, begin, done } = useSilentLoad();

  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<ExclusionEntry | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [savingReason, setSavingReason] = useState(false);
  const [promoteTarget, setPromoteTarget] = useState<ExclusionEntry | null>(null);
  const [promoting, setPromoting] = useState<string | null>(null);

  // Typing filters the list, but not on every keystroke — and a new search
  // always starts from the first page.
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(query.trim());
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  const load = useCallback(async () => {
    begin();
    try {
      const [page, statsData] = await Promise.all([
        listExclusions(PAGE, offset, typeFilter || undefined, search || undefined),
        getExclusionStats().catch(() => null),
      ]);
      setEntries(page.entries);
      setTotal(page.total_count);
      if (statsData) {
        setStats(statsData);
        report.current?.(statsData.total_entries);
      } else {
        report.current?.(page.total_count);
      }
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      done();
    }
  }, [offset, typeFilter, search, begin, done]);

  useEffect(() => {
    void load();
  }, [load]);

  usePoll(() => void load(), POLL_MS);

  async function saveReason(entry: ExclusionEntry) {
    setSavingReason(true);
    setError(null);
    try {
      const { entry: updated } = await updateExclusion(entry.id, { reason: draft.trim() });
      setEntries((current) => current.map((row) => (row.id === entry.id ? updated : row)));
      setEditingId(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSavingReason(false);
    }
  }

  /**
   * Promote an exclusion to a blacklist from the list.
   *
   * Only ever one way: the deletion a promotion causes cannot be undone, so
   * offering a toggle back would promise something the data cannot keep. To
   * stop the rule entirely, remove the entry.
   */
  async function blacklistEntry(entry: ExclusionEntry) {
    setPromoting(entry.id);
    setError(null);
    try {
      await updateExclusion(entry.id, { blacklisted: true });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPromoting(null);
      setPromoteTarget(null);
    }
  }

  const filtered = Boolean(search || typeFilter);

  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-4 lg:grid-cols-8">
        <Card className="px-3.5 py-3">
          <div className="lbl">Entries</div>
          <div className="fig text-[24px] mt-1 leading-none">{num(stats?.total_entries ?? total)}</div>
        </Card>
        <Card className="px-3.5 py-3">
          <div className="lbl flex items-center gap-1.5">
            <Icon name="trash" size={11} />
            Blacklisted
          </div>
          <div className="fig text-[24px] mt-1 leading-none text-crit">
            {num(stats?.blacklisted_entries ?? 0)}
          </div>
        </Card>
        {EXCLUSION_TYPES.map((type) => (
          <Card key={type.value} className="px-3.5 py-3">
            <div className="lbl flex items-center gap-1.5">
              <Icon name={type.icon} size={11} />
              {type.label}
            </div>
            <div className="fig text-[24px] mt-1 leading-none text-ink-2">
              {num(stats?.by_type?.[type.value] ?? 0)}
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader
          title="Exclusions"
          hint="Discovery finds nothing new through these; blacklisted ones are deleted outright"
          actions={
            <div className="flex items-center gap-2">
              <Button size="sm" icon="refresh" onClick={() => void load()}>
                Refresh
              </Button>
              {isAnalyst && (
                <Button size="sm" variant="primary" icon="ban" onClick={() => setCreating(true)}>
                  Add exclusion
                </Button>
              )}
            </div>
          }
        />

        <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-rule">
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search values and reasons"
            aria-label="Search exclusions"
            className="w-full sm:w-[280px]"
          />
          <div className="w-full sm:w-[190px]">
            <Select
              value={typeFilter}
              onChange={(event) => {
                setTypeFilter(event.target.value);
                setOffset(0);
              }}
              aria-label="Filter by object type"
            >
              <option value="">All types</option>
              {EXCLUSION_TYPES.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </Select>
          </div>
          <span className="text-[11.5px] text-ink-3 ml-auto">
            Subdomains of an excluded domain and IPs inside an excluded CIDR are covered too. A value can
            carry a <span className="mono">*</span>.
          </span>
        </div>

        {error && (
          <div className="p-4">
            <ErrorState error={error} onRetry={() => void load()} />
          </div>
        )}

        {loading ? (
          <LoadingBlock label="Loading exclusions" />
        ) : entries.length === 0 ? (
          <EmptyState
            icon="ban"
            title={filtered ? "Nothing matches" : "No exclusions"}
            description={
              filtered
                ? "No exclusion matches this search or type."
                : "Exclude a CDN, a shared host or anything else that is not yours, and discovery will stop finding more of it."
            }
            action={
              filtered ? (
                <Button
                  size="sm"
                  onClick={() => {
                    setQuery("");
                    setTypeFilter("");
                    setOffset(0);
                  }}
                >
                  Clear filters
                </Button>
              ) : isAnalyst ? (
                <Button size="sm" variant="primary" icon="ban" onClick={() => setCreating(true)}>
                  Add exclusion
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <Table>
              <THead>
                <TR>
                  <TH>Type</TH>
                  <TH>Value</TH>
                  <TH>Mode</TH>
                  <TH>Reason</TH>
                  <TH>Added by</TH>
                  <TH>Added</TH>
                  {isAnalyst && <TH className="w-[240px]" />}
                </TR>
              </THead>
              <TBody>
                {entries.map((entry) => {
                  const type = exclusionType(entry.object_type);
                  const editing = editingId === entry.id;
                  return (
                    <TR key={entry.id}>
                      <TD>
                        <Chip>
                          <Icon name={type.icon} size={11} className="text-ink-3" />
                          {type.label}
                        </Chip>
                      </TD>
                      <TD className="max-w-[260px]">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="mono text-[12.5px] truncate" title={entry.object_value}>
                            {entry.object_value}
                          </span>
                          {isPattern(entry.object_value) && (
                            <Chip title="A pattern: * stands for anything, dots included">Pattern</Chip>
                          )}
                        </div>
                      </TD>
                      <TD>
                        {entry.blacklisted ? (
                          <Chip tone={BLACKLIST_TONE} title="Deleted, and never stored again">
                            <Icon name="trash" size={11} />
                            Blacklisted
                          </Chip>
                        ) : (
                          <Chip title="Kept and still scanned; discovery just stops expanding on it">
                            <Icon name="ban" size={11} className="text-ink-3" />
                            Excluded
                          </Chip>
                        )}
                      </TD>
                      <TD className="max-w-[320px]">
                        {editing ? (
                          <div className="flex items-center gap-1.5">
                            <Input
                              autoFocus
                              value={draft}
                              onChange={(event) => setDraft(event.target.value)}
                              onKeyDown={(event) => {
                                if (event.key === "Enter") {
                                  event.preventDefault();
                                  void saveReason(entry);
                                }
                                if (event.key === "Escape") {
                                  event.preventDefault();
                                  setEditingId(null);
                                }
                              }}
                              placeholder="Why is this excluded?"
                              aria-label={`Reason for ${entry.object_value}`}
                              className="h-[26px]"
                            />
                            <Button
                              size="sm"
                              variant="primary"
                              icon="check"
                              loading={savingReason}
                              onClick={() => void saveReason(entry)}
                              aria-label="Save reason"
                            />
                            <Button size="sm" variant="ghost" icon="close" onClick={() => setEditingId(null)} aria-label="Cancel" />
                          </div>
                        ) : (
                          <span className={entry.reason ? "text-ink-2 text-[12.5px]" : "text-ink-3 text-[12.5px]"}>
                            {entry.reason || "No reason recorded"}
                          </span>
                        )}
                      </TD>
                      <TD className="text-ink-2 text-[12.5px] max-w-[160px] truncate" title={entry.created_by ?? ""}>
                        {entry.created_by || "—"}
                      </TD>
                      <TD className="text-ink-2 text-[12.5px] whitespace-nowrap" title={dateTime(entry.created_at)}>
                        {ago(entry.created_at)}
                      </TD>
                      {isAnalyst && (
                        <TD>
                          {!editing && (
                            <RowActions>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => {
                                  setEditingId(entry.id);
                                  setDraft(entry.reason ?? "");
                                }}
                              >
                                Edit reason
                              </Button>
                              {!entry.blacklisted && (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  loading={promoting === entry.id}
                                  onClick={() => setPromoteTarget(entry)}
                                >
                                  Blacklist
                                </Button>
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                icon="trash"
                                onClick={() => setDeleteTarget(entry)}
                                aria-label={`Remove ${entry.object_value}`}
                              />
                            </RowActions>
                          )}
                        </TD>
                      )}
                    </TR>
                  );
                })}
              </TBody>
            </Table>
            <Pagination
              offset={offset}
              limit={PAGE}
              count={entries.length}
              total={total}
              hasMore={offset + entries.length < total}
              onOffset={setOffset}
            />
          </>
        )}
      </Card>

      <ExclusionCreateDrawer open={creating} onClose={() => setCreating(false)} onCreated={load} />
      <ExclusionDeleteDrawer entry={deleteTarget} onClose={() => setDeleteTarget(null)} onDeleted={load} />
      <ExclusionPromoteDrawer
        entry={promoteTarget}
        working={promoting != null}
        onClose={() => setPromoteTarget(null)}
        onConfirm={blacklistEntry}
      />
    </div>
  );
}

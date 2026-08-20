"use client";

import { useCallback, useEffect, useState } from "react";
import { getSearchStatus, reindexSearch } from "@/app/api";
import { Button, Card, CardHeader, Chip, ErrorState, Icon, Spinner } from "@/components/kit";
import { num } from "@/lib/format";
import { useOpsRoles } from "./shared";

type SearchStatus = { status: string; search_available: boolean; message: string };

/**
 * Search index administration. It used to sit on `/search`, where any signed-in
 * user — viewer included — could kick off a full reindex with no gate at all.
 * It lives here now and only operators (and above) can trigger it.
 */
export function SearchIndexPanel() {
  const { isOperator } = useOpsRoles();
  const [status, setStatus] = useState<SearchStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);
  const [reindexing, setReindexing] = useState(false);
  const [result, setResult] = useState<{ assets_indexed: number; findings_indexed: number } | null>(null);

  const check = useCallback(async () => {
    setChecking(true);
    try {
      setStatus(await getSearchStatus());
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void check();
  }, [check]);

  async function handleReindex() {
    setReindexing(true);
    setError(null);
    setResult(null);
    try {
      setResult(await reindexSearch());
      await check();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReindexing(false);
    }
  }

  const available = status?.search_available === true;

  return (
    <Card>
      <CardHeader
        title="Search index"
        hint="Rebuilt from the database — powers the command palette and every search box"
        actions={
          <div className="flex items-center gap-2">
            <Button size="sm" icon="refresh" onClick={() => void check()} disabled={checking}>
              Check
            </Button>
            {isOperator && (
              <Button
                size="sm"
                variant="primary"
                icon="activity"
                onClick={() => void handleReindex()}
                loading={reindexing}
                disabled={!available}
              >
                Reindex all
              </Button>
            )}
          </div>
        }
      />
      <div className="p-4 flex flex-col gap-3">
        {error && <ErrorState error={error} onRetry={() => void check()} />}

        <div className="flex items-center gap-2.5 flex-wrap">
          <span className="lbl">Status</span>
          {checking && !status ? (
            <Spinner size={13} />
          ) : (
            <Chip
              tone={
                available
                  ? { text: "text-ok", wash: "bg-ok-wash" }
                  : { text: "text-med", wash: "bg-med-wash" }
              }
            >
              {status?.status ?? "Unknown"}
            </Chip>
          )}
          {status?.message && <span className="text-[12px] text-ink-2">{status.message}</span>}
        </div>

        {status && !available && (
          <div className="flex items-start gap-2.5 p-3 rounded-lg border border-med/40 bg-med-wash">
            <Icon name="alert" size={14} className="text-med mt-px shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-[12.5px] font-semibold text-ink">Search service unavailable</div>
              <p className="text-[12px] text-ink-2 mt-0.5">
                Assets and findings are still browsable from Surface and Findings; only free-text search and the
                command palette are affected. Reindexing is disabled until the service answers.
              </p>
            </div>
            <Button size="sm" icon="refresh" onClick={() => void check()} disabled={checking}>
              Retry
            </Button>
          </div>
        )}

        {result && (
          <p className="text-[12px] text-ink-2">
            Reindexed <span className="mono text-ink">{num(result.assets_indexed)}</span> assets and{" "}
            <span className="mono text-ink">{num(result.findings_indexed)}</span> findings.
          </p>
        )}

        {!isOperator && (
          <p className="text-[12px] text-ink-3">Rebuilding the index requires the operator role.</p>
        )}
      </div>
    </Card>
  );
}

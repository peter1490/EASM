"use client";

import { useEffect, useState } from "react";
import { Input } from "@/components/kit";
import {
  clearCompanyData,
  deleteCompany,
  type CompanyWithRole,
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import { num } from "@/lib/format";
import { ConfirmDrawer, ResultBanner, errorMessage } from "./shared";

export type DangerMode = "delete" | "clear";
export type DangerTarget = { company: CompanyWithRole; mode: DangerMode };

export type DangerResult = {
  mode: DangerMode;
  companyName: string;
  deleted?: Record<string, number>;
};

/**
 * Delete-a-company and clear-a-company share one confirmation, one guard and
 * one recovery rule, so they share one component. Both panes that expose them
 * render this.
 */
export function CompanyDangerDrawer({
  target,
  onClose,
  onDone,
}: {
  target: DangerTarget | null;
  onClose: () => void;
  onDone: (result: DangerResult) => void;
}) {
  const { companyId: activeCompanyId, companies, setCompanyId, refreshCompanies } = useAuth();
  const [confirmName, setConfirmName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setConfirmName("");
    setError(null);
  }, [target]);

  const company = target?.company;
  const mode = target?.mode;
  const matches = !!company && confirmName.trim() === company.name;

  async function confirm() {
    if (!company || !mode) return;
    if (confirmName.trim() !== company.name) {
      setError("Company name does not match");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      let result: DangerResult;
      if (mode === "delete") {
        await deleteCompany(company.id);
        result = { mode, companyName: company.name };

        // The company the user was scoped to no longer exists, so the cached id
        // in the auth context (and localStorage) is stale. Switching to any
        // remaining company forces a reload so every screen refetches with a
        // valid X-Company-ID header.
        if (company.id === activeCompanyId) {
          const next = companies.find((c) => c.id !== company.id);
          if (next) {
            setCompanyId(next.id);
            return;
          }
        }
      } else {
        const summary = await clearCompanyData(company.id);
        result = { mode, companyName: company.name, deleted: summary.deleted || {} };
      }

      await refreshCompanies();
      onDone(result);
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ConfirmDrawer
      open={!!target}
      onClose={onClose}
      title={mode === "clear" ? "Clear company data" : "Delete company"}
      hint={company?.name}
      confirmLabel={mode === "clear" ? "Clear data" : "Delete company"}
      onConfirm={confirm}
      busy={busy}
      disabled={!matches}
      error={error}
    >
      {company && (
        <>
          <div
            className={
              mode === "clear"
                ? "rounded-md border border-med/40 bg-med-wash px-3 py-2.5 text-[12px] text-ink-2"
                : "rounded-md border border-crit/40 bg-crit-wash px-3 py-2.5 text-[12px] text-ink-2"
            }
          >
            {mode === "clear" ? (
              <>
                Every asset, scan, finding, seed, tag, discovery run and security scan belonging to{" "}
                <span className="font-semibold text-ink">{company.name}</span> is permanently deleted. The company
                itself and its members are kept.
              </>
            ) : (
              <>
                Deleting <span className="font-semibold text-ink">{company.name}</span> permanently removes the company
                and all of its data — assets, scans, findings, seeds, tags and members. This cannot be undone.
              </>
            )}
          </div>

          <div>
            <div className="lbl mb-1.5">
              Type <span className="mono normal-case tracking-normal text-ink">{company.name}</span> to confirm
            </div>
            <Input
              value={confirmName}
              autoFocus
              spellCheck={false}
              placeholder={company.name}
              onChange={(e) => setConfirmName(e.target.value)}
            />
          </div>
        </>
      )}
    </ConfirmDrawer>
  );
}

/** The outcome, including the per-table breakdown a clear returns. */
export function DangerResultBanner({ result, onDismiss }: { result: DangerResult; onDismiss: () => void }) {
  if (result.mode === "delete") {
    return (
      <ResultBanner
        tone="ok"
        title={`Deleted ${result.companyName}`}
        detail="The company and everything scoped to it are gone."
        onDismiss={onDismiss}
      />
    );
  }

  const rows = Object.entries(result.deleted ?? {}).filter(([, n]) => n > 0);
  const total = rows.reduce((sum, [, n]) => sum + n, 0);

  return (
    <ResultBanner
      tone="ok"
      title={`Cleared ${num(total)} rows from ${result.companyName}`}
      detail={
        rows.length === 0 ? (
          "There was nothing left to delete."
        ) : (
          <div className="mt-1.5 grid gap-x-6 gap-y-0.5 sm:grid-cols-2 lg:grid-cols-3">
            {rows.map(([table, n]) => (
              <div key={table} className="flex items-baseline justify-between gap-3 border-b border-rule py-0.5">
                <span className="mono text-[11px] text-ink-2 truncate">{table}</span>
                <span className="fig text-[11.5px]">{num(n)}</span>
              </div>
            ))}
          </div>
        )
      }
      onDismiss={onDismiss}
    />
  );
}

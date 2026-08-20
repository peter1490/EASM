"use client";

import { useEffect, useRef, useState } from "react";
import { Button, Card, CardHeader, EmptyState, ErrorState, Input } from "@/components/kit";
import { DEFAULT_COMPANY_ID, updateCompany } from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import { absolute } from "@/lib/format";
import {
  CompanyDangerDrawer,
  DangerResultBanner,
  type DangerResult,
  type DangerTarget,
} from "./CompanyDanger";
import { Note, RoleChip, errorMessage } from "./shared";

export function CompanyPane({ companyId }: { companyId: string | null }) {
  const { companies, refreshCompanies } = useAuth();
  const company = companies.find((c) => c.id === companyId) ?? null;

  const seededFor = useRef<string | null>(null);
  const [name, setName] = useState(company?.name ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [renamed, setRenamed] = useState(false);
  const [danger, setDanger] = useState<DangerTarget | null>(null);
  const [result, setResult] = useState<DangerResult | null>(null);

  // Seed the field once per company. Re-seeding on every context refresh would
  // wipe the "Saved" state the moment a rename lands.
  useEffect(() => {
    if (!company || seededFor.current === company.id) return;
    seededFor.current = company.id;
    setName(company.name);
    setRenamed(false);
  }, [company]);

  if (!company) {
    return (
      <EmptyState
        icon="building"
        title="No active company"
        description="Pick a company in the top bar, or ask an admin to add you to one."
      />
    );
  }

  const isDefault = company.id === DEFAULT_COMPANY_ID;
  const trimmed = name.trim();
  const canRename = trimmed.length > 0 && trimmed !== company.name;

  async function handleRename() {
    if (!company || !canRename) return;
    setSaving(true);
    setError(null);
    try {
      await updateCompany(company.id, trimmed);
      await refreshCompanies();
      setRenamed(true);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} />}
      {result && <DangerResultBanner result={result} onDismiss={() => setResult(null)} />}

      <Card>
        <CardHeader title="Identity" hint={renamed ? "Saved" : undefined} />
        <div className="p-4 space-y-4">
          <div className="grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
            <div>
              <div className="lbl mb-1.5">Company name</div>
              <Input
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setRenamed(false);
                }}
                placeholder="Acme Corp"
              />
            </div>
            <Button variant="primary" onClick={handleRename} loading={saving} disabled={!canRename}>
              Save name
            </Button>
          </div>

          <div className="grid gap-y-2.5 gap-x-6 sm:grid-cols-3 pt-1">
            <div>
              <div className="lbl">Company ID</div>
              <div className="mono text-[11.5px] text-ink-2 mt-1 break-all">{company.id}</div>
            </div>
            <div>
              <div className="lbl">Created</div>
              <div className="text-[12.5px] mt-1">{absolute(company.created_at)}</div>
            </div>
            <div>
              <div className="lbl">Your role</div>
              <div className="mt-1.5">
                <RoleChip role={company.role} />
              </div>
            </div>
          </div>
        </div>
      </Card>

      <Card className="border-crit/30">
        <CardHeader title="Danger zone" hint="Both actions are irreversible" />
        <div className="p-4 space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="text-[12.5px] font-medium">Clear data</div>
              <p className="text-[11.5px] text-ink-2 mt-0.5">
                Delete every asset, scan, finding, seed and tag in this company. The company and its members stay.
              </p>
            </div>
            <Button variant="danger" icon="trash" onClick={() => setDanger({ company, mode: "clear" })}>
              Clear data
            </Button>
          </div>

          <div className="h-px bg-rule" />

          {isDefault ? (
            <Note icon="shield">
              This is the default company. It anchors every unscoped record, so it cannot be deleted — clear its data
              instead.
            </Note>
          ) : (
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="text-[12.5px] font-medium">Delete company</div>
                <p className="text-[11.5px] text-ink-2 mt-0.5">
                  Remove the company itself along with all of its data and memberships.
                </p>
              </div>
              <Button variant="danger" icon="trash" onClick={() => setDanger({ company, mode: "delete" })}>
                Delete company
              </Button>
            </div>
          )}
        </div>
      </Card>

      <CompanyDangerDrawer target={danger} onClose={() => setDanger(null)} onDone={setResult} />
    </div>
  );
}

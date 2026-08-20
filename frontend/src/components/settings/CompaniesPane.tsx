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
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/kit";
import {
  DEFAULT_COMPANY_ID,
  createCompany,
  listCompanies,
  updateCompany,
  type CompanyWithRole,
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import { absolute } from "@/lib/format";
import {
  CompanyDangerDrawer,
  DangerResultBanner,
  type DangerResult,
  type DangerTarget,
} from "./CompanyDanger";
import { MembersEditor } from "./MembersPane";
import { ALL_COMPANY_ROLES, Note, RoleChip, RoleLegend, errorMessage } from "./shared";

export function CompaniesPane() {
  const { companyId: activeCompanyId, refreshCompanies } = useAuth();

  const [companies, setCompanies] = useState<CompanyWithRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editing, setEditing] = useState<CompanyWithRole | "new" | null>(null);
  const [formName, setFormName] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [membersOf, setMembersOf] = useState<CompanyWithRole | null>(null);
  const [danger, setDanger] = useState<DangerTarget | null>(null);
  const [result, setResult] = useState<DangerResult | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setCompanies(await listCompanies());
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

  const sync = useCallback(async () => {
    await load();
    await refreshCompanies();
  }, [load, refreshCompanies]);

  function openCreate() {
    setEditing("new");
    setFormName("");
    setFormError(null);
  }

  function openRename(company: CompanyWithRole) {
    setEditing(company);
    setFormName(company.name);
    setFormError(null);
  }

  async function submitForm() {
    const name = formName.trim();
    if (!name) {
      setFormError("Company name is required");
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      if (editing && editing !== "new") await updateCompany(editing.id, name);
      else await createCompany(name);
      setEditing(null);
      await sync();
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} onRetry={load} />}
      {result && <DangerResultBanner result={result} onDismiss={() => setResult(null)} />}

      <Card>
        <CardHeader
          title="Companies"
          hint={`${companies.length} total`}
          actions={
            <>
              <Button size="sm" icon="refresh" onClick={sync} loading={loading}>
                Refresh
              </Button>
              <Button size="sm" variant="primary" icon="plus" onClick={openCreate}>
                New company
              </Button>
            </>
          }
        />
        {loading && companies.length === 0 ? (
          <LoadingBlock label="Loading companies" />
        ) : companies.length === 0 ? (
          <EmptyState
            icon="building"
            title="No companies"
            description="Create the first company to start scoping assets and scans."
            action={
              <Button variant="primary" icon="plus" onClick={openCreate}>
                Create company
              </Button>
            }
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Company</TH>
                <TH className="w-[120px]">Your role</TH>
                <TH className="w-[110px]">Created</TH>
                <TH className="w-[290px] text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {companies.map((company) => {
                const isDefault = company.id === DEFAULT_COMPANY_ID;
                return (
                  <TR key={company.id}>
                    <TD>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium truncate">{company.name}</span>
                          {company.id === activeCompanyId && <span className="lbl text-accent">Active</span>}
                          {isDefault && <span className="lbl">Default</span>}
                        </div>
                        <div className="mono text-[11px] text-ink-3 truncate">{company.id}</div>
                      </div>
                    </TD>
                    <TD>
                      <RoleChip role={company.role} />
                    </TD>
                    <TD className="text-ink-2">{absolute(company.created_at)}</TD>
                    <TD>
                      <div className="flex gap-1.5 justify-end">
                        <Button size="sm" onClick={() => setMembersOf(company)}>
                          Members
                        </Button>
                        <Button size="sm" onClick={() => openRename(company)}>
                          Rename
                        </Button>
                        <Button size="sm" variant="danger" onClick={() => setDanger({ company, mode: "clear" })}>
                          Clear
                        </Button>
                        {!isDefault && (
                          <Button size="sm" variant="danger" onClick={() => setDanger({ company, mode: "delete" })}>
                            Delete
                          </Button>
                        )}
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
        <CardHeader title="How access works" hint="Two tiers, one hierarchy" />
        <div className="p-4 space-y-3">
          <p className="text-[12px] text-ink-2 leading-relaxed">
            <span className="font-semibold text-ink">Global admin</span>, granted under All users, is the system-wide
            super-admin: full access to every company, and the only role that can create or delete companies and manage
            accounts. Every other role is scoped to a single company.
          </p>
          <RoleLegend roles={ALL_COMPANY_ROLES} />
          <Note icon="building">
            This list shows the companies you belong to. A company created by someone else, that you were never added
            to, will not appear here.
          </Note>
        </div>
      </Card>

      <Drawer
        open={!!editing}
        onClose={() => {
          if (!submitting) setEditing(null);
        }}
        title={editing === "new" ? "Create company" : "Rename company"}
        width={440}
        header={
          <div>
            <div className="text-sm font-semibold tracking-[-0.012em]">
              {editing === "new" ? "Create company" : "Rename company"}
            </div>
            {editing && editing !== "new" && <p className="text-[12px] text-ink-2 mt-0.5">{editing.name}</p>}
          </div>
        }
        footer={
          <>
            <Button variant="primary" onClick={submitForm} loading={submitting} disabled={!formName.trim()}>
              {editing === "new" ? "Create" : "Save name"}
            </Button>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={submitting}>
              Cancel
            </Button>
          </>
        }
      >
        <div className="space-y-3.5">
          <div>
            <div className="lbl mb-1.5">Company name</div>
            <Input value={formName} autoFocus placeholder="Acme Corp" onChange={(e) => setFormName(e.target.value)} />
          </div>
          {formError && (
            <div role="alert" className="rounded-md border border-crit/40 bg-crit-wash px-3 py-2 text-[12px] text-crit">
              {formError}
            </div>
          )}
        </div>
      </Drawer>

      <Drawer
        open={!!membersOf}
        onClose={() => setMembersOf(null)}
        title={membersOf ? `Members of ${membersOf.name}` : "Members"}
        width={640}
        header={
          <div className="min-w-0">
            <div className="text-sm font-semibold tracking-[-0.012em] truncate">{membersOf?.name}</div>
            <p className="text-[12px] text-ink-2 mt-0.5">Who can reach this company, and with which role</p>
          </div>
        }
      >
        {membersOf && (
          <MembersEditor key={membersOf.id} companyId={membersOf.id} companyName={membersOf.name} isGlobalAdmin inline />
        )}
      </Drawer>

      <CompanyDangerDrawer
        target={danger}
        onClose={() => setDanger(null)}
        onDone={async (r) => {
          setResult(r);
          await load();
        }}
      />
    </div>
  );
}

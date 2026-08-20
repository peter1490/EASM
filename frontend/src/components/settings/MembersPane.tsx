"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Segmented,
  Select,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/kit";
import {
  addCompanyMember,
  listCompanyMembers,
  listUsers,
  removeCompanyMember,
  updateCompanyMemberRole,
  type CompanyMember,
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import { absolute } from "@/lib/format";
import { cn } from "@/lib/cn";
import {
  ALL_COMPANY_ROLES,
  ConfirmDrawer,
  Field,
  Monogram,
  Note,
  RoleChip,
  RoleLegend,
  errorMessage,
  roleLabel,
} from "./shared";

type Candidate = { id: string; email: string; display_name: string | null };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Who may reach one company. Rendered as the Members pane for the active
 * company, and inside a drawer from the Companies pane for any other one —
 * a single implementation used two ways.
 */
export function MembersEditor({
  companyId,
  companyName,
  isGlobalAdmin,
  inline,
}: {
  companyId: string;
  companyName: string;
  isGlobalAdmin: boolean;
  inline?: boolean;
}) {
  const { companies, user } = useAuth();

  const [members, setMembers] = useState<CompanyMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [candidatesLoaded, setCandidatesLoaded] = useState(false);

  const [mode, setMode] = useState<"directory" | "id">("directory");
  const [addUserId, setAddUserId] = useState("");
  const [addRole, setAddRole] = useState("viewer");
  const [adding, setAdding] = useState(false);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<CompanyMember | null>(null);

  /** Companies this user administers — the set whose members they may read. */
  const adminCompanyIds = useMemo(
    () =>
      companies
        .filter((c) => c.role === "admin")
        .map((c) => c.id)
        .join(","),
    [companies],
  );

  const loadMembers = useCallback(async () => {
    setLoading(true);
    try {
      setMembers(await listCompanyMembers(companyId));
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, [companyId]);

  useEffect(() => {
    loadMembers();
  }, [loadMembers]);

  /**
   * The candidate directory. `listUsers()` is global-admin only, so a company
   * admin used to get an empty dropdown and could not add anyone at all. They
   * are allowed to read the members of every company they administer, so build
   * the list from those instead — and the user-ID path covers anybody missing.
   */
  useEffect(() => {
    let cancelled = false;
    async function loadCandidates() {
      try {
        if (isGlobalAdmin) {
          const users = await listUsers();
          if (!cancelled) {
            setCandidates(users.map((u) => ({ id: u.id, email: u.email, display_name: u.display_name })));
          }
        } else {
          const ids = adminCompanyIds ? adminCompanyIds.split(",") : [];
          const lists = await Promise.allSettled(ids.map((id) => listCompanyMembers(id)));
          const seen = new Map<string, Candidate>();
          for (const result of lists) {
            if (result.status !== "fulfilled") continue;
            for (const m of result.value) {
              if (!seen.has(m.user_id)) {
                seen.set(m.user_id, { id: m.user_id, email: m.email, display_name: m.display_name });
              }
            }
          }
          if (!cancelled) setCandidates([...seen.values()]);
        }
      } catch {
        if (!cancelled) setCandidates([]);
      } finally {
        if (!cancelled) setCandidatesLoaded(true);
      }
    }
    loadCandidates();
    return () => {
      cancelled = true;
    };
  }, [isGlobalAdmin, adminCompanyIds]);

  const available = useMemo(
    () =>
      candidates
        .filter((c) => !members.some((m) => m.user_id === c.id))
        .sort((a, b) => (a.display_name || a.email).localeCompare(b.display_name || b.email)),
    [candidates, members],
  );

  const idValid = UUID_RE.test(addUserId.trim());
  const canAdd = mode === "directory" ? !!addUserId : idValid;

  async function handleAdd() {
    if (!canAdd) return;
    setAdding(true);
    setError(null);
    try {
      setMembers(await addCompanyMember(companyId, addUserId.trim(), addRole));
      setAddUserId("");
      setAddRole("viewer");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setAdding(false);
    }
  }

  async function handleRoleChange(member: CompanyMember, role: string) {
    if (role === member.role) return;
    setRowBusy(member.user_id);
    setError(null);
    try {
      setMembers(await updateCompanyMemberRole(companyId, member.user_id, role));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRowBusy(null);
    }
  }

  async function handleRemove() {
    if (!confirmRemove) return;
    setRowBusy(confirmRemove.user_id);
    setError(null);
    try {
      setMembers(await removeCompanyMember(companyId, confirmRemove.user_id));
      setConfirmRemove(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRowBusy(null);
    }
  }

  const addForm = (
    <div className={cn("space-y-3.5", inline ? "" : "p-4")}>
      <Segmented
        ariaLabel="How to identify the person"
        value={mode}
        onChange={(next) => {
          setMode(next);
          setAddUserId("");
        }}
        options={[
          { value: "directory", label: "From directory", badge: available.length },
          { value: "id", label: "By user ID" },
        ]}
      />

      <div className={cn("grid gap-3", inline ? "sm:grid-cols-[1fr_auto]" : "sm:grid-cols-[1fr_160px_auto]", "sm:items-end")}>
        {mode === "directory" ? (
          <Field label="Person" className={inline ? "sm:col-span-2" : undefined}>
            <Select
              value={addUserId}
              onChange={(e) => setAddUserId(e.target.value)}
              disabled={!candidatesLoaded || available.length === 0}
            >
              <option value="">
                {!candidatesLoaded
                  ? "Loading people…"
                  : available.length === 0
                    ? "Nobody left to add"
                    : "Select a person…"}
              </option>
              {available.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.display_name ? `${c.display_name} (${c.email})` : c.email}
                </option>
              ))}
            </Select>
          </Field>
        ) : (
          <Field
            label="User ID"
            hint={addUserId && !idValid ? "Expected a UUID." : "The account's UUID."}
            className={inline ? "sm:col-span-2" : undefined}
          >
            <Input
              value={addUserId}
              invalid={!!addUserId && !idValid}
              spellCheck={false}
              placeholder="00000000-0000-0000-0000-000000000000"
              className="mono"
              onChange={(e) => setAddUserId(e.target.value)}
            />
          </Field>
        )}

        <Field label="Role">
          <Select value={addRole} onChange={(e) => setAddRole(e.target.value)}>
            {ALL_COMPANY_ROLES.map((r) => (
              <option key={r} value={r}>
                {roleLabel(r)}
              </option>
            ))}
          </Select>
        </Field>

        <Button variant="primary" icon="plus" onClick={handleAdd} loading={adding} disabled={!canAdd}>
          Add
        </Button>
      </div>

      {!isGlobalAdmin && mode === "directory" && (
        <Note icon="users">
          As a company admin you see the people who already belong to a company you administer. To grant access to
          someone new, ask a global admin to create the account, then add them here by user ID.
        </Note>
      )}
    </div>
  );

  const membersTable = loading ? (
    <LoadingBlock label="Loading members" />
  ) : members.length === 0 ? (
    <EmptyState icon="users" title="No members" description="Nobody has been granted access to this company yet." />
  ) : (
    <Table>
      <THead>
        <TR>
          <TH>Person</TH>
          <TH className="w-[170px]">Role</TH>
          {!inline && <TH className="w-[120px]">Added</TH>}
          <TH className="w-[110px] text-right">Actions</TH>
        </TR>
      </THead>
      <TBody>
        {members.map((m) => (
          <TR key={m.user_id}>
            <TD>
              <div className="flex items-center gap-2.5 min-w-0">
                <Monogram label={m.display_name || m.email} />
                <div className="min-w-0">
                  <div className="font-medium truncate">{m.display_name || m.email}</div>
                  {m.display_name && <div className="mono text-[11px] text-ink-3 truncate">{m.email}</div>}
                </div>
                {m.user_id === user?.user_id && <span className="lbl text-accent shrink-0">You</span>}
              </div>
            </TD>
            <TD>
              <Select
                value={m.role}
                disabled={rowBusy === m.user_id}
                onChange={(e) => handleRoleChange(m, e.target.value)}
              >
                {ALL_COMPANY_ROLES.map((r) => (
                  <option key={r} value={r}>
                    {roleLabel(r)}
                  </option>
                ))}
              </Select>
            </TD>
            {!inline && <TD className="text-ink-2">{absolute(m.assigned_at)}</TD>}
            <TD>
              <div className="flex justify-end">
                <Button
                  size="sm"
                  variant="danger"
                  disabled={rowBusy === m.user_id}
                  onClick={() => setConfirmRemove(m)}
                >
                  Remove
                </Button>
              </div>
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );

  const removeDrawer = (
    <ConfirmDrawer
      open={!!confirmRemove}
      onClose={() => setConfirmRemove(null)}
      title="Remove member"
      hint={companyName}
      confirmLabel="Remove"
      onConfirm={handleRemove}
      busy={rowBusy === confirmRemove?.user_id}
    >
      {confirmRemove && (
        <p className="text-[12.5px] text-ink-2">
          <span className="font-medium text-ink">{confirmRemove.display_name || confirmRemove.email}</span> loses their{" "}
          <RoleChip role={confirmRemove.role} className="mx-0.5" /> access to {companyName}. Their account and any other
          company memberships are untouched.
        </p>
      )}
    </ConfirmDrawer>
  );

  if (inline) {
    return (
      <div className="space-y-4">
        {error && <ErrorState error={error} onRetry={loadMembers} />}
        {addForm}
        <div className="border border-rule rounded-lg overflow-hidden">{membersTable}</div>
        {removeDrawer}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} onRetry={loadMembers} />}

      <Card>
        <CardHeader title="Add a member" hint={companyName} />
        {addForm}
      </Card>

      <Card>
        <CardHeader title="Members" hint={`${members.length} with access`} />
        {membersTable}
      </Card>

      <Card>
        <CardHeader title="What each role can do" hint="Scoped to this company only" />
        <div className="p-4">
          <RoleLegend roles={ALL_COMPANY_ROLES} />
        </div>
      </Card>

      {removeDrawer}
    </div>
  );
}

export function MembersPane({
  companyId,
  companyName,
  isGlobalAdmin,
}: {
  companyId: string | null;
  companyName: string;
  isGlobalAdmin: boolean;
}) {
  if (!companyId) {
    return (
      <EmptyState
        icon="building"
        title="No active company"
        description="Pick a company in the top bar to manage who can reach it."
      />
    );
  }
  return <MembersEditor companyId={companyId} companyName={companyName} isGlobalAdmin={isGlobalAdmin} />;
}

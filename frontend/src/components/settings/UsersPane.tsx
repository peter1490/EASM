"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Card,
  CardHeader,
  Checkbox,
  Drawer,
  EmptyState,
  ErrorState,
  Icon,
  Input,
  LoadingBlock,
  Select,
  Stat,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/kit";
import {
  addCompanyMember,
  createUser,
  deleteUser,
  listUserCompanies,
  listUsers,
  removeCompanyMember,
  updateCompanyMemberRole,
  updateUser,
  updateUserRole,
  type CompanyWithRole,
  type CreateUserRequest,
  type UpdateUserRequest,
  type UserWithRoles,
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
import { absolute, num } from "@/lib/format";
import {
  ALL_COMPANY_ROLES,
  ALL_GLOBAL_ROLES,
  ConfirmDrawer,
  Field,
  Monogram,
  Note,
  RoleChip,
  RoleLegend,
  errorMessage,
  highestRoleFor,
  roleLabel,
} from "./shared";

type UserForm = {
  email: string;
  password: string;
  display_name: string;
  is_active: boolean;
  roles: string[];
};

const emptyUserForm = (): UserForm => ({
  email: "",
  password: "",
  display_name: "",
  is_active: true,
  roles: [],
});

export function UsersPane() {
  const { user: currentUser, companies } = useAuth();

  const [users, setUsers] = useState<UserWithRoles[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Create / edit
  const [editing, setEditing] = useState<UserWithRoles | "new" | null>(null);
  const [form, setForm] = useState<UserForm>(emptyUserForm);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Access drawer: global roles plus per-user company memberships
  const [access, setAccess] = useState<UserWithRoles | null>(null);
  const [userCompanies, setUserCompanies] = useState<CompanyWithRole[]>([]);
  const [accessLoading, setAccessLoading] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessBusy, setAccessBusy] = useState<string | null>(null);
  const [addCompanyId, setAddCompanyId] = useState("");
  const [addCompanyRole, setAddCompanyRole] = useState("viewer");
  const [addingCompany, setAddingCompany] = useState(false);

  const [deleting, setDeleting] = useState<UserWithRoles | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setUsers(await listUsers());
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

  // -------------------------------------------------------------- create/edit

  function openCreate() {
    setForm({ ...emptyUserForm() });
    setFormError(null);
    setEditing("new");
  }

  function openEdit(u: UserWithRoles) {
    setForm({
      email: u.email,
      password: "",
      display_name: u.display_name || "",
      is_active: u.is_active,
      roles: u.roles || [],
    });
    setFormError(null);
    setEditing(u);
  }

  async function submitUser() {
    setSubmitting(true);
    setFormError(null);
    try {
      if (editing && editing !== "new") {
        const patch: UpdateUserRequest = {};
        if (form.email !== editing.email) patch.email = form.email;
        if (form.display_name !== (editing.display_name || "")) {
          patch.display_name = form.display_name || undefined;
        }
        if (form.is_active !== editing.is_active) patch.is_active = form.is_active;
        if (form.password) patch.password = form.password;

        await updateUser(editing.id, patch);

        // Roles live on their own endpoint, so the difference between the old
        // and new sets becomes one add or remove call per changed role.
        const oldRoles = editing.roles || [];
        for (const role of oldRoles) {
          if (!form.roles.includes(role)) await updateUserRole(editing.id, role, "remove");
        }
        for (const role of form.roles) {
          if (!oldRoles.includes(role)) await updateUserRole(editing.id, role, "add");
        }
      } else {
        const payload: CreateUserRequest = {
          email: form.email,
          password: form.password || undefined,
          display_name: form.display_name || undefined,
          roles: form.roles.length > 0 ? form.roles : undefined,
        };
        await createUser(payload);
      }
      setEditing(null);
      await load();
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setSubmitting(false);
    }
  }

  // ------------------------------------------------------------------- access

  const loadUserCompanies = useCallback(async (userId: string) => {
    setAccessLoading(true);
    setAccessError(null);
    try {
      setUserCompanies(await listUserCompanies(userId));
    } catch (e) {
      setAccessError(errorMessage(e));
      setUserCompanies([]);
    } finally {
      setAccessLoading(false);
    }
  }, []);

  function openAccess(u: UserWithRoles) {
    setAccess(u);
    setUserCompanies([]);
    setAccessError(null);
    setAddCompanyId("");
    setAddCompanyRole("viewer");
    loadUserCompanies(u.id);
  }

  async function toggleGlobalRole(role: string, add: boolean) {
    if (!access) return;
    setAccessBusy(role);
    setAccessError(null);
    try {
      await updateUserRole(access.id, role, add ? "add" : "remove");
      const refreshed = await listUsers();
      setUsers(refreshed);
      const next = refreshed.find((u) => u.id === access.id);
      if (next) setAccess(next);
    } catch (e) {
      setAccessError(errorMessage(e));
    } finally {
      setAccessBusy(null);
    }
  }

  async function addUserCompany() {
    if (!access || !addCompanyId) return;
    setAddingCompany(true);
    setAccessError(null);
    try {
      await addCompanyMember(addCompanyId, access.id, addCompanyRole);
      await loadUserCompanies(access.id);
      setAddCompanyId("");
      setAddCompanyRole("viewer");
      await load();
    } catch (e) {
      setAccessError(errorMessage(e));
    } finally {
      setAddingCompany(false);
    }
  }

  async function changeUserCompanyRole(companyId: string, role: string) {
    if (!access) return;
    setAccessBusy(companyId);
    setAccessError(null);
    try {
      await updateCompanyMemberRole(companyId, access.id, role);
      await loadUserCompanies(access.id);
      await load();
    } catch (e) {
      setAccessError(errorMessage(e));
    } finally {
      setAccessBusy(null);
    }
  }

  async function removeUserCompany(companyId: string) {
    if (!access) return;
    setAccessBusy(companyId);
    setAccessError(null);
    try {
      await removeCompanyMember(companyId, access.id);
      await loadUserCompanies(access.id);
      await load();
    } catch (e) {
      setAccessError(errorMessage(e));
    } finally {
      setAccessBusy(null);
    }
  }

  // ------------------------------------------------------------------- delete

  async function confirmDelete() {
    if (!deleting) return;
    setDeleteBusy(true);
    try {
      await deleteUser(deleting.id);
      setDeleting(null);
      await load();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setDeleteBusy(false);
    }
  }

  const globalAdmins = users.filter((u) => u.roles?.includes("global_admin")).length;
  const active = users.filter((u) => u.is_active).length;
  const scoped = users.filter((u) => (u.companies || []).length > 0).length;

  return (
    <div className="space-y-4">
      {error && <ErrorState error={error} onRetry={load} />}

      <Card className="grid grid-cols-2 sm:grid-cols-4">
        <Stat label="Accounts" value={<span className="text-[22px]">{num(users.length)}</span>} />
        <Stat
          className="border-l border-rule"
          label="Global admins"
          value={<span className="text-[22px]">{num(globalAdmins)}</span>}
        />
        <Stat
          className="border-l border-rule"
          label="In a company"
          value={<span className="text-[22px]">{num(scoped)}</span>}
        />
        <Stat
          className="border-l border-rule"
          label="Active"
          value={<span className="text-[22px]">{num(active)}</span>}
        />
      </Card>

      <Card>
        <CardHeader
          title="Users"
          hint="Accounts, global roles and company access"
          actions={
            <>
              <Button size="sm" icon="refresh" onClick={load} loading={loading}>
                Refresh
              </Button>
              <Button size="sm" variant="primary" icon="plus" onClick={openCreate}>
                Add user
              </Button>
            </>
          }
        />
        {loading && users.length === 0 ? (
          <LoadingBlock label="Loading users" />
        ) : users.length === 0 ? (
          <EmptyState icon="users" title="No users" description="Create the first account to grant access." />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Person</TH>
                <TH className="w-[90px]">Status</TH>
                <TH className="w-[180px]">Highest role</TH>
                <TH className="w-[110px]">Created</TH>
                <TH className="w-[190px] text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {users
                .filter((u) => u.id)
                .map((u) => {
                  const top = highestRoleFor(u);
                  const companyCount = (u.companies || []).length;
                  const isSelf = u.id === currentUser?.user_id;
                  return (
                    <TR key={u.id}>
                      <TD>
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Monogram label={u.display_name || u.email} />
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium truncate">{u.display_name || u.email}</span>
                              {isSelf && <span className="lbl text-accent">You</span>}
                            </div>
                            {u.display_name && <div className="mono text-[11px] text-ink-3 truncate">{u.email}</div>}
                          </div>
                        </div>
                      </TD>
                      <TD>
                        <span
                          className={
                            u.is_active
                              ? "inline-flex items-center h-[19px] px-1.5 rounded text-[10px] font-semibold uppercase tracking-[0.06em] bg-ok-wash text-ok"
                              : "inline-flex items-center h-[19px] px-1.5 rounded text-[10px] font-semibold uppercase tracking-[0.06em] bg-nil-wash text-ink-3"
                          }
                        >
                          {u.is_active ? "Active" : "Inactive"}
                        </span>
                      </TD>
                      <TD>
                        {top ? (
                          <div className="flex items-center gap-2 min-w-0">
                            <RoleChip role={top} />
                            {companyCount > 0 && (
                              <span className="text-[11px] text-ink-3 whitespace-nowrap">
                                in {companyCount} {companyCount === 1 ? "company" : "companies"}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-[12px] text-ink-3">No roles</span>
                        )}
                      </TD>
                      <TD className="text-ink-2">{absolute(u.created_at)}</TD>
                      <TD>
                        <div className="flex gap-1.5 justify-end">
                          <Button size="sm" onClick={() => openEdit(u)}>
                            Edit
                          </Button>
                          <Button size="sm" onClick={() => openAccess(u)}>
                            Access
                          </Button>
                          <Button
                            size="sm"
                            variant="danger"
                            disabled={isSelf}
                            title={isSelf ? "You cannot delete your own account" : "Delete user"}
                            onClick={() => setDeleting(u)}
                          >
                            Delete
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
        <CardHeader title="Role tiers" hint="Global roles are system-wide; the rest are per company" />
        <div className="p-4 space-y-3">
          <RoleLegend roles={ALL_GLOBAL_ROLES} />
          <RoleLegend roles={ALL_COMPANY_ROLES} />
        </div>
      </Card>

      {/* Create / edit ------------------------------------------------------ */}
      <Drawer
        open={!!editing}
        onClose={() => {
          if (!submitting) setEditing(null);
        }}
        title={editing === "new" ? "Add user" : "Edit user"}
        width={520}
        header={
          <div className="min-w-0">
            <div className="text-sm font-semibold tracking-[-0.012em]">
              {editing === "new" ? "Add user" : "Edit user"}
            </div>
            {editing && editing !== "new" && (
              <p className="mono text-[11px] text-ink-3 mt-0.5 truncate">{editing.email}</p>
            )}
          </div>
        }
        footer={
          <>
            <Button
              variant="primary"
              onClick={submitUser}
              loading={submitting}
              disabled={!form.email || (editing === "new" && !form.password)}
            >
              {editing === "new" ? "Create user" : "Save changes"}
            </Button>
            <Button variant="ghost" onClick={() => setEditing(null)} disabled={submitting}>
              Cancel
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Email">
            <Input
              type="email"
              value={form.email}
              placeholder="person@example.com"
              onChange={(e) => setForm({ ...form, email: e.target.value })}
            />
          </Field>
          <Field label="Display name">
            <Input
              value={form.display_name}
              placeholder="Optional"
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
            />
          </Field>
          <Field
            label={editing === "new" ? "Password" : "New password"}
            hint={editing === "new" ? "At least 8 characters." : "Leave empty to keep the current one."}
          >
            <Input
              type="password"
              autoComplete="new-password"
              value={form.password}
              placeholder={editing === "new" ? "Min. 8 characters" : "••••••••"}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
          </Field>

          {editing !== "new" && (
            <Checkbox
              checked={form.is_active}
              onChange={(v) => setForm({ ...form, is_active: v })}
              label="Account is active"
            />
          )}

          <div>
            <div className="lbl mb-1.5">Global roles</div>
            <p className="text-[11.5px] text-ink-2 mb-2">
              Optional. A user with no global role still reaches everything their company memberships allow.
            </p>
            <div className="space-y-1.5">
              {ALL_GLOBAL_ROLES.map((role) => (
                <Checkbox
                  key={role}
                  checked={form.roles.includes(role)}
                  onChange={(v) =>
                    setForm({
                      ...form,
                      roles: v ? [...form.roles, role] : form.roles.filter((r) => r !== role),
                    })
                  }
                  label={<RoleChip role={role} />}
                />
              ))}
            </div>
          </div>

          {formError && (
            <div role="alert" className="rounded-md border border-crit/40 bg-crit-wash px-3 py-2 text-[12px] text-crit">
              {formError}
            </div>
          )}
        </div>
      </Drawer>

      {/* Access -------------------------------------------------------------- */}
      <Drawer
        open={!!access}
        onClose={() => setAccess(null)}
        title="Access"
        width={620}
        header={
          <div className="flex items-center gap-2.5 min-w-0">
            <Monogram label={access?.display_name || access?.email || "?"} size={30} />
            <div className="min-w-0">
              <div className="text-sm font-semibold tracking-[-0.012em] truncate">
                {access?.display_name || access?.email}
              </div>
              <p className="mono text-[11px] text-ink-3 truncate">{access?.email}</p>
            </div>
          </div>
        }
      >
        {access && (
          <div className="space-y-5">
            {accessError && <ErrorState error={accessError} />}

            <section>
              <div className="lbl mb-2">Global roles</div>
              <div className="space-y-1.5">
                {ALL_GLOBAL_ROLES.map((role) => {
                  const held = access.roles.includes(role);
                  return (
                    <div
                      key={role}
                      className="flex items-center justify-between gap-3 rounded-md bg-surface-2 px-3 py-2"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <RoleChip role={role} />
                        <span className="text-[11.5px] text-ink-2 truncate">
                          Full access to every company and every account.
                        </span>
                      </div>
                      <Button
                        size="sm"
                        variant={held ? "danger" : "default"}
                        loading={accessBusy === role}
                        onClick={() => toggleGlobalRole(role, !held)}
                      >
                        {held ? "Revoke" : "Grant"}
                      </Button>
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="space-y-2.5">
              <div className="flex items-baseline justify-between gap-3">
                <div className="lbl">Company memberships</div>
                <span className="text-[11px] text-ink-3">Scope this account company by company</span>
              </div>

              <div className="grid gap-3 sm:grid-cols-[1fr_140px_auto] sm:items-end">
                <Field label="Company">
                  <Select value={addCompanyId} onChange={(e) => setAddCompanyId(e.target.value)}>
                    <option value="">Select a company…</option>
                    {companies
                      .filter((c) => !userCompanies.some((uc) => uc.id === c.id))
                      .map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name}
                        </option>
                      ))}
                  </Select>
                </Field>
                <Field label="Role">
                  <Select value={addCompanyRole} onChange={(e) => setAddCompanyRole(e.target.value)}>
                    {ALL_COMPANY_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {roleLabel(r)}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Button
                  variant="primary"
                  icon="plus"
                  onClick={addUserCompany}
                  loading={addingCompany}
                  disabled={!addCompanyId}
                >
                  Add
                </Button>
              </div>

              {accessLoading ? (
                <LoadingBlock label="Loading memberships" />
              ) : userCompanies.length === 0 ? (
                <Note icon="building">This account does not belong to any company yet.</Note>
              ) : (
                <div className="border border-rule rounded-lg overflow-hidden">
                  <Table>
                    <THead>
                      <TR>
                        <TH>Company</TH>
                        <TH className="w-[150px]">Role</TH>
                        <TH className="w-[100px] text-right">Actions</TH>
                      </TR>
                    </THead>
                    <TBody>
                      {userCompanies.map((c) => (
                        <TR key={c.id}>
                          <TD>
                            <div className="font-medium truncate">{c.name}</div>
                          </TD>
                          <TD>
                            <Select
                              value={c.role}
                              disabled={accessBusy === c.id}
                              onChange={(e) => changeUserCompanyRole(c.id, e.target.value)}
                            >
                              {ALL_COMPANY_ROLES.map((r) => (
                                <option key={r} value={r}>
                                  {roleLabel(r)}
                                </option>
                              ))}
                            </Select>
                          </TD>
                          <TD>
                            <div className="flex justify-end">
                              <Button
                                size="sm"
                                variant="danger"
                                disabled={accessBusy === c.id}
                                onClick={() => removeUserCompany(c.id)}
                              >
                                Remove
                              </Button>
                            </div>
                          </TD>
                        </TR>
                      ))}
                    </TBody>
                  </Table>
                </div>
              )}

              <div className="flex items-start gap-2 text-[11px] text-ink-3">
                <Icon name="building" size={12} className="mt-0.5 shrink-0" />
                <span>Only companies you belong to can be assigned from here.</span>
              </div>
            </section>
          </div>
        )}
      </Drawer>

      {/* Delete -------------------------------------------------------------- */}
      <ConfirmDrawer
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title="Delete user"
        hint={deleting?.email}
        confirmLabel="Delete user"
        onConfirm={confirmDelete}
        busy={deleteBusy}
        disabled={deleting?.id === currentUser?.user_id}
      >
        {deleting && (
          <p className="text-[12.5px] text-ink-2">
            <span className="font-medium text-ink">{deleting.display_name || deleting.email}</span> loses their account
            and every company membership. This cannot be undone.
          </p>
        )}
      </ConfirmDrawer>
    </div>
  );
}

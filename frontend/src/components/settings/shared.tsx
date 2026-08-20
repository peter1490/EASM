"use client";

import { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Button, Drawer, Icon, Toggle, type IconName } from "@/components/kit";
import type { UserWithRoles } from "@/app/api";

// ---------------------------------------------------------------------------
// Role vocabulary
// ---------------------------------------------------------------------------

/** Roles assignable in `user_roles` — the global tier. */
export const ALL_GLOBAL_ROLES = ["global_admin"];

/** Roles assignable in `user_companies` — the per-company tier. */
export const ALL_COMPANY_ROLES = ["admin", "operator", "analyst", "viewer"];

export const ROLE_DESCRIPTIONS: Record<string, string> = {
  global_admin:
    "System-wide super-admin: full access to every company, can create and delete companies and manage users.",
  admin: "Per-company admin: manage the company (rename, clear, members) within their company only.",
  operator: "Can run scans, discovery, and modify assets within their company.",
  analyst: "Can view assets, findings, and update importance within their company.",
  viewer: "Read-only access within their company.",
};

/**
 * Ranking used to pick the highest role across a user's global roles and
 * per-company memberships. Higher number = more privileges.
 */
export const ROLE_RANK: Record<string, number> = {
  global_admin: 5,
  admin: 4,
  operator: 3,
  analyst: 2,
  viewer: 1,
};

export function highestRoleFor(u: UserWithRoles): string | null {
  const candidates: string[] = [...(u.roles || []), ...(u.companies || []).map((c) => c.role)];
  if (candidates.length === 0) return null;
  return candidates.reduce<string | null>((best, role) => {
    if (best === null) return role;
    return (ROLE_RANK[role] || 0) > (ROLE_RANK[best] || 0) ? role : best;
  }, null);
}

/**
 * Roles are their own vocabulary, not severities — but they borrow the same
 * token scale so the page never introduces a second colour system.
 */
const ROLE_TONE: Record<string, { text: string; wash: string }> = {
  global_admin: { text: "text-crit", wash: "bg-crit-wash" },
  admin: { text: "text-high", wash: "bg-high-wash" },
  operator: { text: "text-med", wash: "bg-med-wash" },
  analyst: { text: "text-low", wash: "bg-low-wash" },
  viewer: { text: "text-ink-3", wash: "bg-nil-wash" },
};

export function roleLabel(role: string): string {
  return role.replace(/_/g, " ");
}

export function RoleChip({ role, className }: { role: string; className?: string }) {
  const tone = ROLE_TONE[role] ?? { text: "text-ink-3", wash: "bg-nil-wash" };
  return (
    <span
      className={cn(
        "inline-flex items-center h-[19px] px-1.5 rounded",
        "text-[10px] font-semibold uppercase tracking-[0.06em] whitespace-nowrap",
        tone.wash,
        tone.text,
        className,
      )}
    >
      {roleLabel(role)}
    </span>
  );
}

/** What each role may do — shown next to any surface that assigns one. */
export function RoleLegend({ roles, className }: { roles: string[]; className?: string }) {
  return (
    <div className={cn("grid gap-2 sm:grid-cols-2", className)}>
      {roles.map((role) => (
        <div key={role} className="flex items-start gap-2.5 p-2.5 rounded-md bg-surface-2">
          <RoleChip role={role} className="mt-px shrink-0" />
          <p className="text-[11.5px] text-ink-2 leading-snug">{ROLE_DESCRIPTIONS[role]}</p>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Form primitives
// ---------------------------------------------------------------------------

/** Uppercase micro-label with a hover/focus help bubble. */
export function InfoLabel({ text, help, className }: { text: ReactNode; help?: string; className?: string }) {
  return (
    <div className={cn("flex items-center gap-1.5", className)}>
      <span className="lbl">{text}</span>
      {help && (
        <span className="relative inline-flex items-center group">
          <button
            type="button"
            tabIndex={0}
            aria-label={help}
            className="grid place-items-center w-[13px] h-[13px] rounded-full border border-rule-2 text-[9px] font-semibold text-ink-3 hover:text-ink hover:border-ink-3 cursor-help"
          >
            i
          </button>
          <span className="pointer-events-none absolute left-0 top-full mt-1.5 z-50 hidden w-60 whitespace-pre-wrap rounded-md border border-rule-2 bg-surface px-2.5 py-2 text-[11.5px] font-normal normal-case tracking-normal text-ink-2 shadow-[0_8px_24px_-8px_rgba(0,0,0,0.25)] group-hover:block group-focus-within:block">
            {help}
          </span>
        </span>
      )}
    </div>
  );
}

/** A labelled control. */
export function Field({
  label,
  help,
  hint,
  children,
  className,
}: {
  label: ReactNode;
  help?: string;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <InfoLabel text={label} help={help} />
      <div className="mt-1.5">{children}</div>
      {hint && <div className="text-[11px] text-ink-3 mt-1">{hint}</div>}
    </div>
  );
}

/** A boolean setting: label and help on the left, switch on the right. */
export function ToggleRow({
  label,
  help,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  help?: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <InfoLabel text={label} help={help} />
      <Toggle checked={checked} onChange={onChange} label={label} disabled={disabled} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Feedback
// ---------------------------------------------------------------------------

/** Result of a long-running job: what happened, plus the first few errors. */
export function ResultBanner({
  tone,
  title,
  detail,
  errors,
  onDismiss,
}: {
  tone: "ok" | "warn";
  title: string;
  detail?: ReactNode;
  errors?: string[];
  onDismiss: () => void;
}) {
  const shown = (errors ?? []).slice(0, 5);
  return (
    <div
      role="status"
      className={cn(
        "rounded-lg border p-3.5",
        tone === "ok" ? "border-ok/40 bg-ok-wash" : "border-med/40 bg-med-wash",
      )}
    >
      <div className="flex items-start gap-3">
        <Icon
          name={tone === "ok" ? "check" : "alert"}
          size={15}
          className={cn("mt-px shrink-0", tone === "ok" ? "text-ok" : "text-med")}
        />
        <div className="flex-1 min-w-0">
          <div className={cn("text-[12.5px] font-semibold", tone === "ok" ? "text-ok" : "text-med")}>{title}</div>
          {detail && <div className="text-[12px] text-ink-2 mt-0.5">{detail}</div>}
          {shown.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-[11.5px] text-ink-2">
              {shown.map((err, i) => (
                <li key={i} className="mono break-words">
                  {err}
                </li>
              ))}
              {(errors?.length ?? 0) > shown.length && (
                <li className="text-ink-3">and {(errors?.length ?? 0) - shown.length} more</li>
              )}
            </ul>
          )}
        </div>
        <Button size="sm" variant="ghost" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
    </div>
  );
}

/** A note that is neither an error nor a success — context the user should read. */
export function Note({
  children,
  icon = "alert",
  className,
}: {
  children: ReactNode;
  icon?: IconName;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start gap-2.5 rounded-md bg-surface-2 px-3 py-2.5", className)}>
      <Icon name={icon} size={13} className="text-ink-3 mt-0.5 shrink-0" />
      <div className="text-[11.5px] text-ink-2 leading-relaxed">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------

/**
 * The one confirmation surface. `<Drawer>` already owns Escape, focus trap,
 * scroll lock and the scrim, so nothing here re-implements a modal.
 */
export function ConfirmDrawer({
  open,
  onClose,
  title,
  hint,
  confirmLabel,
  confirmVariant = "danger",
  onConfirm,
  busy,
  disabled,
  error,
  children,
  width = 460,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  hint?: ReactNode;
  confirmLabel: string;
  confirmVariant?: "primary" | "danger";
  onConfirm: () => void;
  busy?: boolean;
  disabled?: boolean;
  error?: string | null;
  children?: ReactNode;
  width?: number;
}) {
  return (
    <Drawer
      open={open}
      onClose={() => {
        if (!busy) onClose();
      }}
      title={title}
      width={width}
      header={
        <div className="min-w-0">
          <div className="text-sm font-semibold tracking-[-0.012em]">{title}</div>
          {hint && <p className="text-[12px] text-ink-2 mt-0.5">{hint}</p>}
        </div>
      }
      footer={
        <>
          <Button variant={confirmVariant} onClick={onConfirm} loading={busy} disabled={disabled}>
            {confirmLabel}
          </Button>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
        </>
      }
    >
      <div className="space-y-3.5">
        {children}
        {error && (
          <div role="alert" className="rounded-md border border-crit/40 bg-crit-wash px-3 py-2 text-[12px] text-crit">
            {error}
          </div>
        )}
      </div>
    </Drawer>
  );
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/** Monogram for a user, so a row reads as a person without an avatar service. */
export function Monogram({ label, size = 26 }: { label: string; size?: number }) {
  const letter = label.trim()[0]?.toUpperCase() || "?";
  return (
    <span
      className="grid place-items-center shrink-0 rounded-md bg-surface-2 text-ink-2 font-semibold"
      style={{ width: size, height: size, fontSize: size * 0.42 }}
      aria-hidden="true"
    >
      {letter}
    </span>
  );
}

/** Read a thrown API error as a message. */
export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

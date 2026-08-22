"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Icon } from "@/components/kit";
import { useAuth } from "@/context/AuthContext";
import type { Asset, ExclusionObjectType } from "@/app/api";

/**
 * Whether this user may change anything on an asset.
 *
 * The write endpoints behind these controls — importance, comment, tags,
 * exclusions — all gate on Analyst or higher, counting the active company's
 * role, so `viewer` is the one role that is genuinely read-only.
 *
 * Deliberately permissive beyond that: an unknown or missing role still gets
 * the buttons and lets the backend be the one to say no — a UI that greys
 * everything out because it could not classify a role is worse than a request
 * that returns 403.
 */
export function useCanWrite(): boolean {
  const { user, companies, companyId } = useAuth();
  const roles = user?.roles ?? [];
  const companyRole = companies.find((company) => company.id === companyId)?.role ?? null;
  const all = [...roles, ...(companyRole ? [companyRole] : [])];
  if (all.length === 0) return true;
  if (all.includes("global_admin")) return true;
  return !all.every((role) => role === "viewer");
}

/**
 * Small pieces shared by the asset detail body, its panels and the inventory
 * table. Colour and severity vocabulary always comes from `@/lib/severity` —
 * the only thing declared here is ownership confidence, which is not a severity
 * and therefore has no entry there.
 */

/** Ownership confidence reads as a quality, not a severity: good / uncertain / poor. */
export function confidenceColor(value: number | null | undefined): string {
  if (value == null) return "var(--nil)";
  if (value >= 0.7) return "var(--ok)";
  if (value >= 0.4) return "var(--med)";
  return "var(--crit)";
}

/** Exclusion entries are typed by object, and ports cannot be excluded. */
export function toExclusionObjectType(assetType: Asset["asset_type"]): ExclusionObjectType | null {
  switch (assetType) {
    case "domain":
      return "domain";
    case "ip":
      return "ip";
    case "organization":
      return "organization";
    case "asn":
      return "asn";
    case "certificate":
      return "certificate";
    default:
      return null;
  }
}

/** A labelled value in a detail grid. */
export function KV({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="lbl mb-1">{label}</div>
      <div className="text-[12.5px] text-ink break-words">{children}</div>
    </div>
  );
}

/** A section inside the detail body. */
export function Section({
  title,
  hint,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("bg-surface border border-rule rounded-lg", className)}>
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-rule">
        <div className="flex items-baseline gap-2.5 min-w-0">
          <h2 className="text-sm font-semibold tracking-[-0.012em] truncate">{title}</h2>
          {hint && <span className="text-[11.5px] text-ink-3 truncate">{hint}</span>}
        </div>
        {actions && <div className="flex items-center gap-1.5 shrink-0">{actions}</div>}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

/** A copyable identifier. Rendered as a link when it points at another asset. */
export function Mono({ value, href }: { value: string; href?: string }) {
  const body = (
    <code className="mono text-[11.5px] px-1.5 py-0.5 rounded bg-surface-2 text-ink-2 break-all">{value}</code>
  );
  if (!href) return body;
  return (
    <Link href={href} className="inline-flex items-center gap-1 hover:text-accent-ink group">
      {body}
      <Icon name="arrowRight" size={11} className="text-ink-3 group-hover:text-accent" />
    </Link>
  );
}

/** Inline success / neutral notice. Failures use `<ErrorState>`; this is the other half. */
export function Notice({
  tone = "ok",
  icon = "check",
  children,
  onDismiss,
}: {
  tone?: "ok" | "info" | "warn";
  icon?: "check" | "clock" | "ban" | "alert";
  children: ReactNode;
  onDismiss?: () => void;
}) {
  const tones = {
    ok: "border-ok/40 bg-ok-wash text-ok",
    info: "border-accent/35 bg-accent-wash text-accent-ink",
    warn: "border-med/45 bg-med-wash text-med",
  } as const;
  return (
    <div role="status" className={cn("flex items-start gap-2.5 px-3 py-2.5 rounded-lg border", tones[tone])}>
      <Icon name={icon} size={14} className="mt-px shrink-0" />
      <div className="flex-1 min-w-0 text-[12.5px] text-ink">{children}</div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="grid place-items-center w-5 h-5 rounded text-ink-3 hover:text-ink hover:bg-surface-2"
        >
          <Icon name="close" size={10} strokeWidth={1.8} />
        </button>
      )}
    </div>
  );
}

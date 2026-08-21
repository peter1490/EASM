"use client";

/**
 * THE finding detail surface.
 *
 * One implementation, two compositions: `variant="drawer"` renders the body
 * only (the `<Drawer>` supplies the header and footer slots from the exported
 * `FindingDetailHeader` / `FindingDetailActions`), `variant="page"` renders all
 * three stacked for a full-width route. There is no second, modal-shaped copy
 * of this — the old build had three (security list, asset page, scan page) and
 * they had drifted apart: only the asset page offered Accept risk and Reopen.
 */

import { ReactNode } from "react";
import Link from "next/link";
import {
  resolveSecurityFinding,
  updateSecurityFinding,
  type FindingStatus,
  type SecurityFinding,
} from "@/app/api";
import { Button, Chip, Dot, ErrorState, Icon, SeverityChip, type IconName } from "@/components/kit";
import { cn } from "@/lib/cn";
import { uniq } from "@/lib/list";
import { absolute, ago, dateTime, score } from "@/lib/format";
import { findingStatus, severityFromCvss, severityTone } from "@/lib/severity";
import { FindingEvidence, findingTypeIcon, findingTypeLabel } from "./FindingEvidence";

export const NVD_BASE = "https://nvd.nist.gov/vuln/detail/";

export interface FindingAction {
  status: FindingStatus;
  label: string;
  icon: IconName;
  variant?: "primary" | "default" | "ghost" | "danger";
}

/**
 * The complete transition set. `/security` only ever offered a subset; Accept
 * risk and Reopen lived on the asset page alone. Both are here now, for every
 * screen that shows a finding.
 */
export function transitionsFor(status: string | null | undefined): FindingAction[] {
  switch (status) {
    case "acknowledged":
      return [
        { status: "in_progress", label: "Start working", icon: "play", variant: "primary" },
        { status: "resolved", label: "Resolve", icon: "check" },
      ];
    case "in_progress":
      return [{ status: "resolved", label: "Resolve", icon: "check", variant: "primary" }];
    case "resolved":
    case "false_positive":
    case "accepted":
      return [{ status: "open", label: "Reopen", icon: "refresh" }];
    case "open":
    default:
      return [
        { status: "acknowledged", label: "Acknowledge", icon: "check", variant: "primary" },
        { status: "false_positive", label: "False positive", icon: "ban" },
        { status: "accepted", label: "Accept risk", icon: "shield" },
      ];
  }
}

/** Bulk bar offers every transition, since a selection can mix statuses. */
export const BULK_ACTIONS: FindingAction[] = [
  { status: "acknowledged", label: "Acknowledge", icon: "check" },
  { status: "in_progress", label: "Start working", icon: "play" },
  { status: "resolved", label: "Resolve", icon: "check", variant: "primary" },
  { status: "false_positive", label: "False positive", icon: "ban" },
  { status: "accepted", label: "Accept risk", icon: "shield" },
  { status: "open", label: "Reopen", icon: "refresh" },
];

/**
 * One mutation path. `resolved` goes through the resolve endpoint so the
 * backend stamps `resolved_at` / `resolved_by`; everything else is a PATCH.
 */
export function applyFindingStatus(id: string, status: FindingStatus): Promise<SecurityFinding> {
  if (status === "resolved") return resolveSecurityFinding(id);
  return updateSecurityFinding(id, { status });
}

/** Severity a finding should be shown as, falling back to its CVSS band. */
export function effectiveSeverity(finding: SecurityFinding): string {
  return finding.severity || severityFromCvss(finding.cvss_score) || "info";
}

/* ------------------------------------------------------------------ */

export function FindingStatusLabel({ status }: { status: string | null | undefined }) {
  const meta = findingStatus(status);
  return (
    <span className="inline-flex items-center gap-1.5 text-[12.5px] text-ink-2 whitespace-nowrap">
      <Dot color={meta.dot} />
      {meta.label}
    </span>
  );
}

export function FindingDetailHeader({ finding }: { finding: SecurityFinding }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-2 mb-1.5">
        <SeverityChip severity={effectiveSeverity(finding)} />
        <span className="inline-flex items-center gap-1.5 text-[11.5px] text-ink-3">
          <Icon name={findingTypeIcon(finding.finding_type)} size={12} />
          {findingTypeLabel(finding.finding_type)}
        </span>
        <span className="w-px h-3 bg-rule-2" aria-hidden="true" />
        <FindingStatusLabel status={finding.status} />
      </div>
      <h2 className="text-[15px] font-semibold tracking-[-0.015em] leading-snug break-words">
        {finding.title}
      </h2>
    </div>
  );
}

export function FindingDetailActions({
  finding,
  busy,
  canTriage = true,
  onAction,
}: {
  finding: SecurityFinding;
  busy?: boolean;
  canTriage?: boolean;
  onAction: (status: FindingStatus) => void;
}) {
  if (!canTriage) {
    return (
      <span className="text-[12px] text-ink-3">
        Your role can view findings but not change their status.
      </span>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      {transitionsFor(finding.status).map((action) => (
        <Button
          key={action.status}
          size="sm"
          variant={action.variant ?? "default"}
          icon={action.icon}
          disabled={busy}
          onClick={() => onAction(action.status)}
        >
          {action.label}
        </Button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */

function Section({
  title,
  children,
  actions,
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h3 className="lbl">{title}</h3>
        {actions}
      </div>
      {children}
    </section>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="lbl">{label}</div>
      <div className="text-[12.5px] mt-0.5 break-words">{children}</div>
    </div>
  );
}

export function FindingDetail({
  finding,
  variant = "drawer",
  busy,
  canTriage = true,
  error,
  onAction,
  onOpenScan,
  onNavigate,
}: {
  finding: SecurityFinding;
  variant?: "drawer" | "page";
  busy?: boolean;
  canTriage?: boolean;
  /** Failure of the last status change, rendered inline — never an alert(). */
  error?: string | null;
  onAction: (status: FindingStatus) => void;
  /** Opens the owning scan; the Findings screen answers this with `?scan=<id>`. */
  onOpenScan?: (scanId: string) => void;
  /** Called before following an internal link, so a drawer can close itself. */
  onNavigate?: () => void;
}) {
  const tone = severityTone(effectiveSeverity(finding));
  const sourceUrl = typeof finding.data?.source_url === "string" ? finding.data.source_url : null;
  const sourceName =
    typeof finding.data?.source_name === "string" ? finding.data.source_name : "external source";
  const cves = uniq(finding.cve_ids ?? []);
  const tags = uniq(finding.tags ?? []);
  const dataKeys = Object.keys(finding.data ?? {});

  return (
    <div className="space-y-5">
      {variant === "page" && <FindingDetailHeader finding={finding} />}

      {error && <ErrorState error={error} />}

      {/* Toolbar: the external source link the old modal rendered in three places. */}
      {(sourceUrl || finding.security_scan_id) && (
        <div className="flex flex-wrap items-center gap-2">
          {sourceUrl && (
            <a
              href={sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              title={`View on ${sourceName}`}
              className="inline-flex items-center gap-1.5 h-[26px] px-[9px] rounded-[5px] border border-rule-2 bg-surface
                         text-[12px] font-medium text-ink hover:bg-surface-2 hover:border-ink-3"
            >
              <Icon name="external" size={12} />
              {sourceName === "external source" ? "View source" : sourceName}
            </a>
          )}
          {finding.security_scan_id && onOpenScan && (
            <Button
              size="sm"
              icon="activity"
              onClick={() => onOpenScan(finding.security_scan_id as string)}
            >
              View scan
            </Button>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 gap-x-4 gap-y-3 p-3 rounded-lg border border-rule bg-surface-2">
        <Meta label="Asset">
          <Link
            href={`/surface/${finding.asset_id}`}
            onClick={onNavigate}
            className="inline-flex items-center gap-1 text-accent hover:underline"
          >
            <span className="mono text-[12px] break-all">
              {finding.asset_value ?? `${finding.asset_id.slice(0, 8)}…`}
            </span>
            <Icon name="arrowRight" size={11} />
          </Link>
          {finding.asset_type && <span className="text-ink-3"> · {finding.asset_type}</span>}
        </Meta>
        <Meta label="CVSS">
          {finding.cvss_score != null ? (
            <span className={cn("mono font-semibold", tone.text)}>{score(finding.cvss_score, 1)}</span>
          ) : (
            <span className="text-ink-3">—</span>
          )}
        </Meta>
        <Meta label="First seen">
          <span title={dateTime(finding.first_seen_at)}>
            {absolute(finding.first_seen_at)}{" "}
            <span className="text-ink-3">· {ago(finding.first_seen_at)}</span>
          </span>
        </Meta>
        <Meta label="Last seen">
          <span title={dateTime(finding.last_seen_at)}>{ago(finding.last_seen_at)}</span>
        </Meta>
        {finding.resolved_at && (
          <Meta label="Resolved">
            {dateTime(finding.resolved_at)}
            {finding.resolved_by && <span className="text-ink-3"> · {finding.resolved_by}</span>}
          </Meta>
        )}
        <Meta label="Type">
          <span className="mono text-[12px]">{finding.finding_type}</span>
        </Meta>
      </div>

      {finding.description && (
        <Section title="Description">
          <p className="text-[12.5px] text-ink-2 leading-relaxed whitespace-pre-wrap">
            {finding.description}
          </p>
        </Section>
      )}

      {finding.remediation && (
        <Section title="Remediation">
          <div className="text-[12.5px] leading-relaxed whitespace-pre-wrap rounded-lg border border-rule bg-ok-wash/60 p-3">
            {finding.remediation}
          </div>
        </Section>
      )}

      {cves.length > 0 && (
        <Section title={`CVE${cves.length > 1 ? "s" : ""} (${cves.length})`}>
          <div className="flex flex-wrap gap-1.5">
            {cves.map((cve) => (
              <a
                key={cve}
                href={`${NVD_BASE}${encodeURIComponent(cve)}`}
                target="_blank"
                rel="noopener noreferrer"
                title={`${cve} on the NVD`}
                className="inline-flex items-center gap-1 h-[22px] px-[7px] rounded-[5px] border border-transparent
                           bg-crit-wash text-crit text-[11.5px] font-medium mono hover:border-crit"
              >
                {cve}
                <Icon name="external" size={10} />
              </a>
            ))}
          </div>
        </Section>
      )}

      {tags.length > 0 && (
        <Section title="Tags">
          <div className="flex flex-wrap gap-1.5">
            {tags.map((tag) => (
              <Chip key={tag}>
                <Icon name="tag" size={10} />
                {tag}
              </Chip>
            ))}
          </div>
        </Section>
      )}

      <Section title="Evidence">
        <div className="rounded-lg border border-rule bg-surface p-3">
          <FindingEvidence findingType={finding.finding_type} data={finding.data} />
        </div>
        {dataKeys.length > 0 && (
          <details className="group mt-2">
            <summary className="flex items-center gap-1.5 cursor-pointer text-[12px] text-ink-3 hover:text-ink list-none">
              <Icon name="chevronRight" size={11} className="transition-transform group-open:rotate-90" />
              Raw data
            </summary>
            <pre className="mt-2 max-h-64 overflow-auto rounded-md border border-rule bg-surface-2 p-2.5 text-[11px] mono">
              {JSON.stringify(finding.data, null, 2)}
            </pre>
          </details>
        )}
      </Section>

      {variant === "page" && (
        <div className="pt-1 border-t border-rule">
          <div className="pt-3">
            <FindingDetailActions
              finding={finding}
              busy={busy}
              canTriage={canTriage}
              onAction={onAction}
            />
          </div>
        </div>
      )}
    </div>
  );
}

export default FindingDetail;

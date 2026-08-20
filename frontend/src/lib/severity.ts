/**
 * One place for severity, risk level and finding status vocabulary.
 *
 * Before the consolidation these tables were re-declared in page after page
 * (RISK_COLORS in risk/page.tsx, asset/[id]/page.tsx, assets/page.tsx, and a
 * separate severity switch in security/page.tsx), which is how "critical" ended
 * up orange in one table and red in another.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
/**
 * The five levels `risk_service.rs` writes into `assets.risk_level`. The fifth
 * one is `info`, not `minimal` — an `assets_by_level` bucket keyed `minimal`
 * never arrives, and a `risk_level=info` filter never matched.
 */
export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "false_positive"
  | "accepted";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
export const RISK_ORDER: RiskLevel[] = ["critical", "high", "medium", "low", "info"];

type Tone = { label: string; short: string; text: string; wash: string; dot: string };

const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: { label: "Critical", short: "Crit", text: "text-crit", wash: "bg-crit-wash", dot: "var(--crit)" },
  high: { label: "High", short: "High", text: "text-high", wash: "bg-high-wash", dot: "var(--high)" },
  medium: { label: "Medium", short: "Med", text: "text-med", wash: "bg-med-wash", dot: "var(--med)" },
  low: { label: "Low", short: "Low", text: "text-low", wash: "bg-low-wash", dot: "var(--low)" },
  info: { label: "Info", short: "Info", text: "text-ink-3", wash: "bg-nil-wash", dot: "var(--nil)" },
};

const RISK_TONE: Record<RiskLevel, Tone> = {
  critical: SEVERITY_TONE.critical,
  high: SEVERITY_TONE.high,
  medium: SEVERITY_TONE.medium,
  low: SEVERITY_TONE.low,
  info: { label: "Informational", short: "Info", text: "text-ink-3", wash: "bg-nil-wash", dot: "var(--nil)" },
};

const UNKNOWN: Tone = { label: "Unknown", short: "—", text: "text-ink-3", wash: "bg-nil-wash", dot: "var(--nil)" };

export function severityTone(severity: string | null | undefined): Tone {
  if (!severity) return UNKNOWN;
  return SEVERITY_TONE[severity.toLowerCase() as Severity] ?? UNKNOWN;
}

export function riskTone(level: string | null | undefined): Tone {
  if (!level) return UNKNOWN;
  return RISK_TONE[level.toLowerCase() as RiskLevel] ?? UNKNOWN;
}

/**
 * Risk level derived from a score, for assets the backend has not levelled yet.
 * The cut-offs are the ones `RiskService::calculate_asset_risk` applies, so a
 * score shown next to a level never contradicts the level the server stored.
 */
export function riskLevelFromScore(score: number | null | undefined): RiskLevel | null {
  if (score == null) return null;
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "info";
}

export const FINDING_STATUSES: Array<{ value: FindingStatus; label: string; dot: string }> = [
  { value: "open", label: "Open", dot: "var(--ink-3)" },
  { value: "acknowledged", label: "Acknowledged", dot: "var(--low)" },
  { value: "in_progress", label: "In progress", dot: "var(--accent)" },
  { value: "resolved", label: "Resolved", dot: "var(--ok)" },
  { value: "false_positive", label: "False positive", dot: "var(--nil)" },
  { value: "accepted", label: "Risk accepted", dot: "var(--med)" },
];

export function findingStatus(status: string | null | undefined) {
  return (
    FINDING_STATUSES.find((s) => s.value === status) ?? {
      value: (status ?? "open") as FindingStatus,
      label: status ? status.replace(/_/g, " ") : "Open",
      dot: "var(--ink-3)",
    }
  );
}

/** A finding still needing work — the definition of "open" used across the app. */
export const OPEN_STATUSES: FindingStatus[] = ["open", "acknowledged", "in_progress"];

export function isOpen(status: string | null | undefined): boolean {
  return OPEN_STATUSES.includes((status ?? "open") as FindingStatus);
}

/** Severity implied by a CVSS base score, when a finding carries no severity. */
export function severityFromCvss(score: number | null | undefined): Severity | null {
  if (score == null) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

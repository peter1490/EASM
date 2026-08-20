"use client";

import { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Icon } from "./Icon";
import { riskTone, severityTone } from "@/lib/severity";

export function Chip({
  children,
  className,
  tone,
  onClick,
  selected,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  tone?: { text: string; wash: string };
  selected?: boolean;
}) {
  const base = cn(
    "inline-flex items-center gap-1.5 h-[22px] px-[7px] rounded-[5px] border",
    "text-[11.5px] font-medium whitespace-nowrap",
    selected
      ? "border-accent bg-accent-wash text-accent-ink"
      : tone
        ? cn("border-transparent", tone.wash, tone.text)
        : "border-rule-2 bg-surface text-ink-2",
    onClick && !selected && "hover:border-ink-3 hover:text-ink cursor-pointer",
    className,
  );
  if (!onClick) return <span className={base}>{children}</span>;
  return (
    <button type="button" onClick={onClick} className={base} {...props}>
      {children}
    </button>
  );
}

/** Severity pill. Same colour for the same word on every screen. */
export function SeverityChip({
  severity,
  short,
  count,
  className,
}: {
  severity: string | null | undefined;
  short?: boolean;
  count?: number;
  className?: string;
}) {
  const tone = severityTone(severity);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 h-[19px] px-1.5 rounded",
        "text-[10px] font-semibold uppercase tracking-[0.06em]",
        tone.wash,
        tone.text,
        className,
      )}
    >
      {count != null && <span className="mono">{count}</span>}
      {short ? tone.short : tone.label}
    </span>
  );
}

export function RiskChip({ level, className }: { level: string | null | undefined; className?: string }) {
  const tone = riskTone(level);
  return (
    <span
      className={cn(
        "inline-flex items-center h-[19px] px-1.5 rounded",
        "text-[10px] font-semibold uppercase tracking-[0.06em]",
        tone.wash,
        tone.text,
        className,
      )}
    >
      {tone.label}
    </span>
  );
}

export function Dot({ color, className }: { color: string; className?: string }) {
  return (
    <span
      className={cn("rounded-full shrink-0", className)}
      style={{ width: 6, height: 6, background: color }}
      aria-hidden="true"
    />
  );
}

/** A filter expressed as a removable token in the query bar. */
export function QueryToken({ label, onRemove }: { label: ReactNode; onRemove: () => void }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 h-[22px] pl-2 pr-1 rounded-[5px] text-[11.5px] font-medium text-accent-ink bg-accent-wash"
      style={{ border: "1px solid color-mix(in oklch, var(--accent) 28%, transparent)" }}
    >
      <span className="mono text-[11px]">{label}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove filter ${typeof label === "string" ? label : ""}`}
        className="grid place-items-center w-[15px] h-[15px] rounded-[3px] opacity-65 hover:opacity-100 hover:bg-accent/15"
      >
        <Icon name="close" size={9} strokeWidth={1.8} />
      </button>
    </span>
  );
}

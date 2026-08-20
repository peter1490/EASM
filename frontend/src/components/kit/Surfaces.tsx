"use client";

import { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Card({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("bg-surface border border-rule rounded-lg", className)} {...props}>
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  hint,
  actions,
  className,
}: {
  title: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center justify-between gap-4 px-4 py-3 border-b border-rule", className)}>
      <div className="flex items-baseline gap-2.5 min-w-0">
        <h2 className="text-sm font-semibold tracking-[-0.012em] truncate">{title}</h2>
        {hint && <span className="text-[11.5px] text-ink-3 truncate">{hint}</span>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

export function PageHeader({
  title,
  hint,
  actions,
}: {
  title: ReactNode;
  hint?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-end justify-between gap-4">
      <div>
        <h1 className="text-[23px] font-semibold tracking-[-0.025em] leading-tight">{title}</h1>
        {hint && <p className="text-[12.5px] text-ink-2 mt-1">{hint}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

/** A labelled figure. The exposure strip is a row of these behind one border. */
export function Stat({
  label,
  value,
  tone,
  footnote,
  className,
}: {
  label: ReactNode;
  value: ReactNode;
  tone?: string;
  footnote?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("px-[18px] py-3.5", className)}>
      <div className="lbl">{label}</div>
      <div className="fig text-[30px] mt-1 leading-none" style={tone ? { color: tone } : undefined}>
        {value}
      </div>
      {footnote && <div className="text-[11.5px] mt-1.5">{footnote}</div>}
    </div>
  );
}

/** Thin proportional bar — risk scores, confidence, progress. */
export function Bar({
  value,
  color = "var(--accent)",
  className,
  height = 4,
}: {
  value: number;
  color?: string;
  className?: string;
  height?: number;
}) {
  const width = `${Math.max(0, Math.min(100, value * 100))}%`;
  return (
    <span
      className={cn("block rounded-sm bg-surface-2 overflow-hidden", className)}
      style={{ height }}
      role="presentation"
    >
      <span className="block h-full rounded-sm transition-[width] duration-500" style={{ width, background: color }} />
    </span>
  );
}

/** Multi-segment bar — the composition breakdowns on Overview. */
export function StackedBar({
  segments,
  height = 8,
  className,
}: {
  segments: Array<{ value: number; color: string; label?: string }>;
  height?: number;
  className?: string;
}) {
  const total = segments.reduce((sum, s) => sum + s.value, 0) || 1;
  return (
    <span className={cn("flex rounded-sm overflow-hidden gap-[1.5px]", className)} style={{ height }}>
      {segments.map((s, i) => (
        <span
          key={i}
          title={s.label}
          style={{ width: `${(s.value / total) * 100}%`, background: s.color }}
          className="block"
        />
      ))}
    </span>
  );
}

export function Divider({ className }: { className?: string }) {
  return <div className={cn("h-px bg-rule", className)} aria-hidden="true" />;
}

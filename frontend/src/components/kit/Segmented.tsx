"use client";

import { ReactNode } from "react";
import { cn } from "@/lib/cn";

export interface SegmentOption<T extends string> {
  value: T;
  label: ReactNode;
  badge?: ReactNode;
}

/** The house switch: a few mutually exclusive views of one thing. */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  className,
  fill,
  ariaLabel,
}: {
  options: ReadonlyArray<SegmentOption<T>>;
  value: T;
  onChange: (next: T) => void;
  className?: string;
  fill?: boolean;
  ariaLabel?: string;
}) {
  return (
    // A group of pressed-state buttons, not tabs: a segmented control here
    // switches a filter or a range, and there is no tabpanel to point at.
    <div
      role="group"
      aria-label={ariaLabel}
      className={cn("inline-flex p-0.5 gap-0.5 bg-surface-2 border border-rule rounded-[7px]", fill && "w-full", className)}
    >
      {options.map((option) => {
        const on = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(option.value)}
            className={cn(
              "inline-flex items-center justify-center gap-1.5 h-6 px-2.5 rounded-[5px] text-[12px] font-medium",
              "transition-[background-color,color] duration-100",
              fill && "flex-1",
              on ? "bg-surface text-ink shadow-[0_1px_2px_rgba(0,0,0,0.07)]" : "text-ink-2 hover:text-ink",
            )}
          >
            {option.label}
            {option.badge != null && <span className="mono text-[10.5px] opacity-60">{option.badge}</span>}
          </button>
        );
      })}
    </div>
  );
}

/** Underlined tabs, for switching panes inside a detail page. */
export function Tabs<T extends string>({
  options,
  value,
  onChange,
  className,
}: {
  options: ReadonlyArray<SegmentOption<T>>;
  value: T;
  onChange: (next: T) => void;
  className?: string;
}) {
  return (
    <div role="tablist" className={cn("flex gap-5", className)}>
      {options.map((option) => {
        const on = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="tab"
            aria-selected={on}
            onClick={() => onChange(option.value)}
            className={cn(
              "inline-flex items-center gap-1.5 h-[34px] text-[13px] font-medium border-b-2",
              "transition-[color,border-color] duration-100",
              on ? "text-ink border-ink" : "text-ink-3 border-transparent hover:text-ink",
            )}
          >
            {option.label}
            {option.badge != null && <span className="mono text-[11px] opacity-65">{option.badge}</span>}
          </button>
        );
      })}
    </div>
  );
}

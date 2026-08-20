"use client";

import { cn } from "@/lib/cn";
import { Icon } from "@/components/kit";

const LEVELS = [1, 2, 3, 4, 5] as const;

const LABELS: Record<number, string> = {
  1: "Negligible",
  2: "Low",
  3: "Normal",
  4: "High",
  5: "Business critical",
};

/**
 * Business importance, 1–5. It feeds the risk score, so it is an input, not a
 * read-out: click the level directly rather than opening an editor first.
 */
export function ImportancePicker({
  value,
  onChange,
  disabled,
  size = "md",
  showLabel = true,
  className,
}: {
  value: number;
  onChange: (next: number) => void;
  disabled?: boolean;
  size?: "sm" | "md";
  showLabel?: boolean;
  className?: string;
}) {
  const glyph = size === "sm" ? 13 : 16;

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="flex items-center gap-0.5" role="group" aria-label="Importance">
        {LEVELS.map((level) => {
          const on = level <= value;
          return (
            <button
              key={level}
              type="button"
              disabled={disabled}
              aria-label={`Set importance to ${level} — ${LABELS[level]}`}
              aria-pressed={value === level}
              title={`${level} · ${LABELS[level]}`}
              onClick={() => onChange(level)}
              className={cn(
                "grid place-items-center rounded transition-colors duration-100",
                size === "sm" ? "w-[19px] h-[19px]" : "w-[22px] h-[22px]",
                on ? "text-accent" : "text-rule-2",
                !disabled && "hover:text-accent-ink hover:bg-surface-2",
                disabled && "opacity-50 cursor-not-allowed",
              )}
            >
              <Icon name="shield" size={glyph} strokeWidth={on ? 2 : 1.4} />
            </button>
          );
        })}
      </div>
      {showLabel && (
        <span className="text-[12px] text-ink-2">
          <span className="mono">{value}</span>
          <span className="text-ink-3">/5</span>
          <span className="text-ink-3"> · {LABELS[value] ?? "—"}</span>
        </span>
      )}
    </div>
  );
}

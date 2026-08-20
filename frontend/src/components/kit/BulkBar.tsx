"use client";

import { ReactNode } from "react";
import { Icon } from "./Icon";

/**
 * Floating action bar for a multi-row selection. Replaces the per-row dropdown
 * menus: pick rows, then act on them once.
 */
export function BulkBar({
  count,
  onClear,
  children,
  noun = "selected",
}: {
  count: number;
  onClear: () => void;
  children: ReactNode;
  noun?: string;
}) {
  if (count === 0) return null;
  return (
    <div
      role="region"
      aria-label={`${count} ${noun}`}
      className="fixed left-1/2 bottom-6 z-30 flex items-center gap-2 h-11 pl-4 pr-2 rounded-[10px] animate-pop
                 bg-ink text-paper shadow-[0_12px_32px_-8px_rgba(0,0,0,0.45)]"
      style={{ transform: "translateX(-50%)" }}
    >
      <span className="text-[12.5px] font-medium">
        <span className="mono">{count}</span> {noun}
      </span>
      <span className="w-px h-5 bg-white/20" aria-hidden="true" />
      {children}
      <button
        type="button"
        onClick={onClear}
        aria-label="Clear selection"
        className="grid place-items-center w-7 h-7 rounded-md text-white/70 hover:text-white hover:bg-white/10"
      >
        <Icon name="close" size={12} strokeWidth={1.6} />
      </button>
    </div>
  );
}

/** Button styled for use inside the dark bulk bar. */
export function BulkAction({
  children,
  onClick,
  primary,
  disabled,
}: {
  children: ReactNode;
  onClick?: () => void;
  primary?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center h-7 px-2.5 rounded-md text-[12.5px] font-medium whitespace-nowrap
                  transition-colors disabled:opacity-40 disabled:cursor-not-allowed
                  ${primary ? "bg-white/15 hover:bg-white/25" : "hover:bg-white/10"}`}
    >
      {children}
    </button>
  );
}

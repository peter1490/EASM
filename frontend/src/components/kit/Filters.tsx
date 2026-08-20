"use client";

import { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Icon } from "./Icon";
import { QueryToken } from "./Chip";

export interface FacetItem {
  key: string;
  label: string;
  count?: number | string;
  swatch?: string;
}

export interface FacetGroup {
  name: string;
  items: FacetItem[];
}

/**
 * Left-hand facet rail. Clicking a facet writes a token into the query bar, so
 * the filter state is one list, shown in one place, and shareable as a URL.
 * Surface and Findings use the same component — that is the point.
 */
export function FacetRail({
  groups,
  active,
  onToggle,
  onReset,
  className,
}: {
  groups: FacetGroup[];
  active: string[];
  onToggle: (key: string) => void;
  onReset: () => void;
  className?: string;
}) {
  return (
    <aside
      className={cn("w-[216px] shrink-0 border-r border-rule bg-surface flex flex-col overflow-hidden", className)}
      aria-label="Filters"
    >
      <div className="flex items-center justify-between px-3 pt-3.5 pb-2.5">
        <span className="lbl">Filters</span>
        <button
          type="button"
          onClick={onReset}
          disabled={active.length === 0}
          className="text-[12px] font-medium text-ink-3 hover:text-ink disabled:opacity-40 disabled:hover:text-ink-3"
        >
          Reset
        </button>
      </div>
      <div className="flex-1 overflow-y-auto px-2 pb-4 flex flex-col gap-3.5">
        {groups.map((group) => (
          <div key={group.name} className="flex flex-col gap-px">
            <div className="lbl px-2 mb-1.5">{group.name}</div>
            {group.items.map((item) => {
              const on = active.includes(item.key);
              return (
                <button
                  key={item.key}
                  type="button"
                  aria-pressed={on}
                  onClick={() => onToggle(item.key)}
                  className={cn(
                    "flex items-center gap-2 w-full h-[26px] px-2 rounded-[5px] text-[12.5px] text-left",
                    "transition-colors duration-100",
                    on ? "bg-accent-wash text-accent-ink font-semibold" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
                  )}
                >
                  <span
                    className="w-[9px] h-[9px] rounded-[2.5px] shrink-0"
                    style={{
                      border: `1.3px solid ${item.swatch ?? "var(--rule-2)"}`,
                      background: on ? (item.swatch ?? "var(--accent)") : "transparent",
                    }}
                    aria-hidden="true"
                  />
                  <span className="truncate">{item.label}</span>
                  {item.count != null && (
                    <span className={cn("ml-auto mono text-[11px]", on ? "text-accent-ink" : "text-ink-3")}>
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>
    </aside>
  );
}

/** One search field carrying the active filters as removable tokens. */
export function QueryBar({
  tokens,
  onRemoveToken,
  value,
  onValueChange,
  placeholder,
  actions,
}: {
  tokens: string[];
  onRemoveToken: (token: string) => void;
  value: string;
  onValueChange: (next: string) => void;
  placeholder: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 flex items-center gap-1.5 flex-wrap min-h-[34px] px-2.5 py-1 border border-rule-2 rounded-[7px] bg-surface focus-within:border-accent focus-within:shadow-[0_0_0_3px_var(--accent-wash)] transition-[border-color,box-shadow]">
        <Icon name="search" size={14} className="text-ink-3" />
        {tokens.map((token) => (
          <QueryToken key={token} label={token} onRemove={() => onRemoveToken(token)} />
        ))}
        <input
          value={value}
          onChange={(e) => onValueChange(e.target.value)}
          placeholder={placeholder}
          aria-label={placeholder}
          className="flex-1 min-w-[180px] h-6 bg-transparent border-0 outline-none text-[12.5px] placeholder:text-ink-3"
        />
      </div>
      {actions}
    </div>
  );
}

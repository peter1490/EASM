"use client";

import { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export function Table({ className, ...props }: HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full border-collapse", className)} {...props} />
    </div>
  );
}

export function THead(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead {...props} />;
}

export function TBody(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody {...props} />;
}

export function TH({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        "h-[30px] px-3 text-left align-middle border-b border-rule whitespace-nowrap",
        "text-[10px] font-semibold uppercase tracking-[0.09em] text-ink-3",
        className,
      )}
      {...props}
    />
  );
}

export function TD({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("h-[42px] px-3 align-middle border-b border-rule", className)} {...props} />;
}

export function TR({
  className,
  selected,
  interactive,
  ...props
}: HTMLAttributes<HTMLTableRowElement> & { selected?: boolean; interactive?: boolean }) {
  return (
    <tr
      className={cn(
        "transition-colors duration-100",
        interactive && "cursor-pointer hover:bg-accent-wash",
        selected && "bg-accent-wash",
        "last:[&>td]:border-b-0",
        className,
      )}
      {...props}
    />
  );
}

/** Right-aligned action cluster that only appears on row hover or focus. */
export function RowActions({ children }: { children: ReactNode }) {
  return <div className="row-actions flex gap-1 justify-end">{children}</div>;
}

/** A sortable column header. */
export function SortableTH({
  children,
  active,
  direction,
  onSort,
  className,
  ...props
}: ThHTMLAttributes<HTMLTableCellElement> & {
  active?: boolean;
  direction?: "asc" | "desc";
  onSort?: () => void;
}) {
  return (
    <TH className={className} aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"} {...props}>
      {/*
        `text-transform` is one of the properties the UA stylesheet hard-sets on
        form controls, and Tailwind's preflight does not inherit it back, so a
        header rendered through this button came out in sentence case while
        every plain `TH` beside it was upper case. Inherit it explicitly.
      */}
      <button
        type="button"
        onClick={onSort}
        className={cn(
          "inline-flex items-center gap-1 [text-transform:inherit] hover:text-ink transition-colors",
          active && "text-ink",
        )}
      >
        {children}
        {active && <span aria-hidden="true">{direction === "asc" ? "↑" : "↓"}</span>}
      </button>
    </TH>
  );
}

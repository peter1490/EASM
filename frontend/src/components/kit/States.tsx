"use client";

import { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Icon, type IconName } from "./Icon";
import { Button } from "./Button";

export function Spinner({ size = 16, className }: { size?: number; className?: string }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={cn("inline-block animate-spin rounded-full border-2 border-rule-2 border-t-accent", className)}
      style={{ width: size, height: size }}
    />
  );
}

export function LoadingBlock({ label = "Loading", className }: { label?: string; className?: string }) {
  return (
    // `data-page-loading` is the signal AppShell waits on before revealing a
    // page after a company switch, so the switch never dips out to a spinner.
    <div
      data-page-loading=""
      className={cn("flex flex-col items-center justify-center gap-3 py-14 text-ink-3", className)}
    >
      <Spinner size={20} />
      <span className="text-[12.5px]">{label}</span>
    </div>
  );
}

export function EmptyState({
  icon = "search",
  title,
  description,
  action,
  className,
}: {
  icon?: IconName;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center text-center px-6 py-14", className)}>
      <span className="grid place-items-center w-9 h-9 rounded-lg bg-surface-2 text-ink-3 mb-3">
        <Icon name={icon} size={17} />
      </span>
      <h3 className="text-sm font-semibold tracking-[-0.012em]">{title}</h3>
      {description && <p className="text-[12.5px] text-ink-2 mt-1.5 max-w-sm">{description}</p>}
      {action && <div className="mt-3.5">{action}</div>}
    </div>
  );
}

/** Inline failure with a retry, rather than a screen that silently shows nothing. */
export function ErrorState({
  error,
  onRetry,
  className,
}: {
  error: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn("flex items-start gap-3 p-3.5 rounded-lg border border-crit/40 bg-crit-wash", className)}
    >
      <Icon name="alert" size={15} className="text-crit mt-px" />
      <div className="flex-1 min-w-0">
        <div className="text-[12.5px] font-semibold text-crit">Something went wrong</div>
        <p className="text-[12px] text-ink-2 mt-0.5 break-words">{error}</p>
      </div>
      {onRetry && (
        <Button size="sm" onClick={onRetry} icon="refresh">
          Retry
        </Button>
      )}
    </div>
  );
}

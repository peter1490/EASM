"use client";

import { ReactNode, useEffect, useRef } from "react";
import { cn } from "@/lib/cn";
import { IconButton } from "./Button";

/**
 * Right-hand slide-over. This is THE detail surface: the same detail component
 * renders in here over a list, and full-width on its own route. There is no
 * second, modal-shaped implementation of an asset or a finding any more.
 */
export function Drawer({
  open,
  onClose,
  title,
  width = 624,
  header,
  footer,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  width?: number;
  header?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreFocus.current = document.activeElement as HTMLElement | null;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown, true);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    panelRef.current?.focus();

    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.body.style.overflow = previousOverflow;
      restoreFocus.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-40 animate-scrim"
        style={{ background: "color-mix(in oklch, var(--ink) 18%, transparent)" }}
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={cn(
          "fixed right-0 top-0 bottom-0 z-50 flex flex-col outline-none",
          "bg-surface border-l border-rule-2 animate-drawer",
          "shadow-[-24px_0_60px_-20px_rgba(0,0,0,0.18)]",
        )}
        style={{ width: `min(${width}px, 100vw)` }}
      >
        <div className="flex items-start gap-3 px-[18px] pt-4 pb-3 border-b border-rule shrink-0">
          <div className="flex-1 min-w-0">{header}</div>
          <IconButton icon="close" label="Close" variant="ghost" onClick={onClose} className="text-ink-2" />
        </div>
        <div className="flex-1 overflow-y-auto px-[18px] py-4">{children}</div>
        {footer && (
          <div className="flex items-center gap-2 px-[18px] py-3 border-t border-rule bg-surface-2 shrink-0">
            {footer}
          </div>
        )}
      </div>
    </>
  );
}

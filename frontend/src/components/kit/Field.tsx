"use client";

import { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/cn";
import { Icon } from "./Icon";

const FIELD_BASE =
  "w-full px-2.5 rounded-md border border-rule-2 bg-surface text-ink text-[12.5px] outline-none " +
  "placeholder:text-ink-3 transition-[border-color,box-shadow] duration-100 " +
  "focus:border-accent focus:shadow-[0_0_0_3px_var(--accent-wash)] " +
  "disabled:opacity-50 disabled:cursor-not-allowed";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(
  function Input({ className, invalid, ...props }, ref) {
    return (
      <input
        ref={ref}
        className={cn(FIELD_BASE, "h-[30px]", invalid && "border-crit focus:border-crit focus:shadow-[0_0_0_3px_var(--crit-wash)]", className)}
        {...props}
      />
    );
  },
);

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, ...props }, ref) {
    return <textarea ref={ref} className={cn(FIELD_BASE, "py-2 leading-relaxed resize-y", className)} {...props} />;
  },
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, ...props }, ref) {
    return (
      <div className="relative">
        <select ref={ref} className={cn(FIELD_BASE, "h-[30px] pr-8 appearance-none cursor-pointer", className)} {...props}>
          {children}
        </select>
        <Icon
          name="chevronDown"
          size={12}
          className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-ink-3"
        />
      </div>
    );
  },
);

export function Label({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("lbl mb-1.5", className)}>{children}</div>;
}

export function Checkbox({
  checked,
  indeterminate,
  onChange,
  label,
  disabled,
  stopPropagation,
  className,
}: {
  checked: boolean;
  indeterminate?: boolean;
  onChange: (next: boolean) => void;
  label?: ReactNode;
  disabled?: boolean;
  stopPropagation?: boolean;
  className?: string;
}) {
  const on = checked || indeterminate;
  const box = (
    <span
      className={cn(
        "grid place-items-center w-[15px] h-[15px] rounded border-[1.4px] shrink-0 transition-colors duration-100",
        on ? "border-accent bg-accent text-on-accent" : "border-rule-2 bg-surface",
        disabled && "opacity-50",
      )}
    >
      {on && <Icon name={indeterminate && !checked ? "minus" : "check"} size={9} strokeWidth={2.2} />}
    </span>
  );
  return (
    // `relative` matters: the visually-hidden input is `position: absolute`, and
    // without a positioned ancestor it resolves against the initial containing
    // block — escaping every `overflow: hidden` between here and the viewport and
    // stretching the document. One hidden input per table row is enough to give
    // the whole window a scrollbar.
    <label
      className={cn("relative inline-flex items-center gap-2 text-[12.5px]", !disabled && "cursor-pointer", className)}
      onClick={stopPropagation ? (e) => e.stopPropagation() : undefined}
    >
      <input
        type="checkbox"
        className="sr-only"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {box}
      {label}
    </label>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative block w-7 h-4 rounded-full transition-colors duration-150 shrink-0",
        checked ? "bg-accent" : "bg-rule-2",
        disabled && "opacity-50 cursor-not-allowed",
      )}
    >
      <span
        className="absolute top-0.5 w-3 h-3 rounded-full bg-surface transition-[left] duration-150"
        style={{ left: checked ? 14 : 2 }}
      />
    </button>
  );
}

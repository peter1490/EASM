"use client";

import { ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/cn";
import { Icon, type IconName } from "./Icon";

type Variant = "primary" | "default" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

const VARIANT: Record<Variant, string> = {
  primary: "bg-accent border-accent text-on-accent hover:bg-accent-ink hover:border-accent-ink",
  default: "bg-surface border-rule-2 text-ink hover:bg-surface-2 hover:border-ink-3",
  ghost: "bg-transparent border-transparent text-ink hover:bg-surface-2 hover:border-rule",
  danger: "bg-surface border-rule-2 text-crit hover:bg-crit-wash hover:border-crit",
};

const SIZE: Record<Size, string> = {
  sm: "h-[26px] px-[9px] text-[12px] rounded-[5px] gap-1.5",
  md: "h-[30px] px-[11px] text-[12.5px] rounded-md gap-1.5",
  lg: "h-[38px] px-4 text-[13.5px] rounded-md gap-2",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  icon?: IconName;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "default", size = "md", icon, loading, disabled, children, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center border font-medium whitespace-nowrap",
        "transition-[background-color,border-color,color] duration-100",
        "disabled:opacity-45 disabled:cursor-not-allowed",
        VARIANT[variant],
        SIZE[size],
        className,
      )}
      {...props}
    >
      {loading ? (
        <span
          aria-hidden="true"
          className="animate-spin rounded-full border-2 border-current border-t-transparent"
          style={{ width: 12, height: 12, opacity: 0.7 }}
        />
      ) : icon ? (
        <Icon name={icon} size={size === "sm" ? 12 : 13} />
      ) : null}
      {children}
    </button>
  );
});

/** Square icon-only button; `label` becomes the accessible name and tooltip. */
export const IconButton = forwardRef<
  HTMLButtonElement,
  Omit<ButtonProps, "icon" | "children"> & { icon: IconName; label: string }
>(function IconButton({ icon, label, className, size = "md", variant = "default", ...props }, ref) {
  return (
    <Button
      ref={ref}
      variant={variant}
      size={size}
      title={label}
      aria-label={label}
      className={cn("px-0", size === "sm" ? "w-[26px]" : "w-[30px]", className)}
      {...props}
    >
      <Icon name={icon} size={size === "sm" ? 12 : 14} />
    </Button>
  );
});

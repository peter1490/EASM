import { HTMLAttributes, forwardRef } from "react";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "success" | "warning" | "error" | "info" | "secondary";
}

const Badge = forwardRef<HTMLSpanElement, BadgeProps>(({ className = "", variant = "default", children, ...props }, ref) => {
  const variants = {
    default: "bg-accent text-accent-foreground border-border",
    success: "bg-success/15 text-success border-success/30",
    warning: "bg-warning/15 text-warning border-warning/30",
    error: "bg-destructive/15 text-destructive border-destructive/30",
    info: "bg-info/15 text-info border-info/30",
    secondary: "bg-secondary/15 text-secondary border-secondary/30",
  };
  
  return (
    <span
      ref={ref}
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </span>
  );
});

Badge.displayName = "Badge";

export default Badge;

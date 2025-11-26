import { InputHTMLAttributes, forwardRef, ReactNode } from "react";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode;
  error?: string;
  rightSlot?: ReactNode;
}

const Input = forwardRef<HTMLInputElement, InputProps>(({ className = "", label, error, rightSlot, ...props }, ref) => {
  return (
    <div className="w-full">
      {label && (
        <label className="block text-sm font-medium text-foreground mb-1.5">
          {label}
        </label>
      )}
      <div className="relative">
        <input
          ref={ref}
          className={`
            w-full h-10 px-3 ${rightSlot ? "pr-10" : "pr-3"} rounded-lg border border-border bg-input text-foreground
            placeholder:text-muted-foreground text-sm
            focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary
            disabled:opacity-50 disabled:cursor-not-allowed
            transition-all duration-200
            ${error ? "border-destructive focus:ring-destructive/30 focus:border-destructive" : ""}
            ${className}
          `}
          {...props}
        />
        {rightSlot && (
          <div className="absolute inset-y-0 right-2 flex items-center">
            {rightSlot}
          </div>
        )}
      </div>
      {error && (
        <p className="mt-1.5 text-xs text-destructive">{error}</p>
      )}
    </div>
  );
});

Input.displayName = "Input";

export default Input;

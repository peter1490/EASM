import { SelectHTMLAttributes, forwardRef } from "react";

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
}

const Select = forwardRef<HTMLSelectElement, SelectProps>(({ className = "", label, error, children, ...props }, ref) => {
  return (
    <div className="w-full">
      {label && (
        <label className="block text-sm font-medium text-foreground mb-1.5">
          {label}
        </label>
      )}
      <select
        ref={ref}
        className={`
          w-full h-10 px-3 rounded-lg border border-border bg-input text-foreground text-sm
          focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary
          disabled:opacity-50 disabled:cursor-not-allowed
          transition-all duration-200
          appearance-none cursor-pointer
          bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2012%2012%22%3E%3Cpath%20fill%3D%22%236b7294%22%20d%3D%22M6%208L1%203h10z%22%2F%3E%3C%2Fsvg%3E')]
          bg-no-repeat bg-[right_0.75rem_center]
          pr-10
          ${error ? "border-destructive focus:ring-destructive/30 focus:border-destructive" : ""}
          ${className}
        `}
        {...props}
      >
        {children}
      </select>
      {error && (
        <p className="mt-1.5 text-xs text-destructive">{error}</p>
      )}
    </div>
  );
});

Select.displayName = "Select";

export default Select;

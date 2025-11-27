export interface CheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: React.ReactNode;
  disabled?: boolean;
  indeterminate?: boolean;
}

export default function Checkbox({ checked, onChange, label, disabled = false, indeterminate = false }: CheckboxProps) {
  return (
    <label className="flex items-center gap-2 cursor-pointer group">
      <div className="relative">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          disabled={disabled}
          className="sr-only"
          ref={(input) => {
            if (input) {
              input.indeterminate = indeterminate;
            }
          }}
        />
        <div
          className={`w-5 h-5 border-2 rounded transition-all ${
            checked || indeterminate
              ? "bg-primary border-primary"
              : "bg-background border-muted-foreground/30 group-hover:border-primary"
          } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
        >
          {(checked || indeterminate) && (
            <svg
              className="w-full h-full text-primary-foreground"
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="3"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              {indeterminate ? (
                <path d="M6 12h12" />
              ) : (
                <path d="M5 13l4 4L19 7" />
              )}
            </svg>
          )}
        </div>
      </div>
      {label && (
        <span className={`text-sm ${disabled ? "opacity-50" : "text-foreground"}`}>
          {label}
        </span>
      )}
    </label>
  );
}

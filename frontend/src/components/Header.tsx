"use client";

interface HeaderProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export default function Header({ title, description, action }: HeaderProps) {
  return (
    <div className="mb-8 flex justify-between items-start">
      <div className="space-y-1">
        <h1 className="text-3xl font-bold text-foreground tracking-tight">{title}</h1>
        {description && (
          <p className="text-muted-foreground text-sm">{description}</p>
        )}
      </div>
      {action && (
        <div className="flex items-center gap-3">
          {action}
        </div>
      )}
    </div>
  );
}

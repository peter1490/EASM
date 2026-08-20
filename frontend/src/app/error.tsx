"use client";

import { useEffect } from "react";
import { Button } from "@/components/kit/Button";
import { Icon } from "@/components/kit/Icon";

export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="h-full grid place-items-center px-6">
      <div className="max-w-md w-full">
        <div className="flex items-start gap-3 p-4 rounded-lg border border-crit/40 bg-crit-wash">
          <Icon name="alert" size={16} className="text-crit mt-px" />
          <div className="min-w-0">
            <h1 className="text-sm font-semibold text-crit">Something went wrong</h1>
            <p className="text-[12.5px] text-ink-2 mt-1 break-words">{error.message}</p>
            {error.digest && <p className="mono text-[11px] text-ink-3 mt-2">Reference {error.digest}</p>}
          </div>
        </div>
        <div className="flex gap-2 mt-4">
          <Button variant="primary" icon="refresh" onClick={reset}>
            Try again
          </Button>
          <Button onClick={() => window.location.assign("/")}>Back to Overview</Button>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useEffect } from "react";
import Button from "@/components/ui/Button";
import { Card, CardContent } from "@/components/ui/Card";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    console.error("Application error:", error);
  }, [error]);

  return (
    <div className="flex items-center justify-center min-h-[70vh]">
      <Card className="max-w-md border-destructive">
        <CardContent className="py-12 text-center">
          <div className="text-6xl mb-4">⚠️</div>
          <h1 className="text-3xl font-bold mb-2">Something went wrong</h1>
          <p className="text-muted-foreground mb-6">
            An unexpected error occurred. Please try again.
          </p>
          <div className="flex gap-3 justify-center">
            <Button onClick={reset}>
              Try Again
            </Button>
            <Button variant="outline" onClick={() => window.location.href = "/"}>
              Go Home
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}


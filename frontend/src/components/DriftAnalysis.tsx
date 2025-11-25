"use client";

import { useEffect, useState } from "react";
import { detectDrift, getDriftFindings, type Finding } from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";

interface DriftAnalysisProps {
  scanId: string;
}

// Extract drift data from finding.data
interface DriftData {
  state: "new" | "missing" | "changed";
  port: number;
  protocol: string;
  previous_state?: string;
  current_state: string;
  asset_identifier?: string;
}

function extractDriftData(finding: Finding): DriftData | null {
  const data = finding.data as Record<string, unknown>;
  if (!data.state || !data.port) return null;
  
  return {
    state: data.state as DriftData["state"],
    port: Number(data.port),
    protocol: (data.protocol as string) || "tcp",
    previous_state: data.previous_state as string | undefined,
    current_state: (data.current_state as string) || "unknown",
    asset_identifier: data.asset_identifier as string | undefined,
  };
}

export default function DriftAnalysis({ scanId }: DriftAnalysisProps) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ranAnalysis, setRanAnalysis] = useState(false);

  async function loadFindings() {
    try {
      setLoading(true);
      const data = await getDriftFindings(scanId);
      setFindings(data);
    } catch (err) {
      console.error("Failed to load drift findings:", err);
      // Don't show error on initial load as there might just be no drift analysis run yet
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFindings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  async function runAnalysis() {
    try {
      setAnalyzing(true);
      setError(null);
      await detectDrift(scanId);
      setRanAnalysis(true);
      await loadFindings();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setAnalyzing(false);
    }
  }

  // Parse drift data from findings
  const driftFindings = findings
    .map(f => ({ finding: f, drift: extractDriftData(f) }))
    .filter((x): x is { finding: Finding; drift: DriftData } => x.drift !== null);

  const stats = {
    new: driftFindings.filter(f => f.drift.state === "new").length,
    missing: driftFindings.filter(f => f.drift.state === "missing").length,
    changed: driftFindings.filter(f => f.drift.state === "changed").length,
  };

  if (loading && !ranAnalysis) {
    return <div className="py-8 flex justify-center"><LoadingSpinner /></div>;
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Port Drift Analysis</CardTitle>
              <CardDescription>
                Compare this scan with previous results to detect changes in open ports
              </CardDescription>
            </div>
            <Button 
              onClick={runAnalysis} 
              disabled={analyzing}
              loading={analyzing}
            >
              {driftFindings.length > 0 ? "Re-run Analysis" : "Run Analysis"}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {error && (
             <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
               {error}
             </div>
          )}

          {driftFindings.length > 0 ? (
            <div className="space-y-6">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 rounded-lg bg-muted/50 border border-border">
                  <div className="text-sm text-muted-foreground mb-1">New Ports</div>
                  <div className="text-2xl font-bold text-success">{stats.new}</div>
                </div>
                <div className="p-4 rounded-lg bg-muted/50 border border-border">
                  <div className="text-sm text-muted-foreground mb-1">Closed Ports</div>
                  <div className="text-2xl font-bold text-destructive">{stats.missing}</div>
                </div>
                <div className="p-4 rounded-lg bg-muted/50 border border-border">
                  <div className="text-sm text-muted-foreground mb-1">State Changes</div>
                  <div className="text-2xl font-bold text-warning">{stats.changed}</div>
                </div>
              </div>

              {/* Findings List */}
              <div className="border rounded-lg overflow-hidden">
                <table className="w-full text-sm text-left">
                  <thead className="bg-muted text-muted-foreground">
                    <tr>
                      <th className="px-4 py-3 font-medium">State</th>
                      <th className="px-4 py-3 font-medium">Port</th>
                      <th className="px-4 py-3 font-medium">Protocol</th>
                      <th className="px-4 py-3 font-medium">Details</th>
                      <th className="px-4 py-3 font-medium">Detected At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {driftFindings.map(({ finding, drift }) => (
                      <tr key={finding.id} className="bg-card hover:bg-muted/30">
                        <td className="px-4 py-3">
                          <Badge 
                            variant={
                              drift.state === "new" ? "success" :
                              drift.state === "missing" ? "error" :
                              "warning"
                            }
                          >
                            {drift.state.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 font-mono">{drift.port}</td>
                        <td className="px-4 py-3 text-muted-foreground">{drift.protocol}</td>
                        <td className="px-4 py-3">
                          {drift.state === "changed" ? (
                            <span>
                              {drift.previous_state || "unknown"} → <span className="font-medium">{drift.current_state}</span>
                            </span>
                          ) : (
                            <span className="text-muted-foreground">{drift.current_state}</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-muted-foreground text-xs">
                          {new Date(finding.created_at).toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <EmptyState
              icon="⚓"
              title="No drift detected"
              description={ranAnalysis 
                ? "No changes in open ports found compared to previous scans." 
                : "Run an analysis to detect changes in your attack surface."
              }
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

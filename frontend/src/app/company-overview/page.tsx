"use client";

import { useCallback, useEffect, useState } from "react";
import Header from "@/components/Header";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { Card, CardContent } from "@/components/ui/Card";
import RiskFindingsEvolutionChart, { type EvolutionPoint } from "@/components/RiskFindingsEvolutionChart";
import { getCompanyEvolution, type CompanyEvolutionResponse } from "@/app/api";

export default function CompanyOverviewPage() {
  const [evolution, setEvolution] = useState<CompanyEvolutionResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getCompanyEvolution(60);
      setEvolution(data);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const series: EvolutionPoint[] = (evolution?.series || []).map((point) => ({
    timestamp: point.timestamp,
    risk_score: point.risk_score,
    active_findings: point.active_findings,
  }));

  return (
    <div className="space-y-8 animate-fade-in">
      <Header
        title="Company Overview"
        description="Portfolio-level risk score and active findings over time"
      />

      {error && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-4">
            <div className="text-destructive flex items-center gap-2">
              <span>!</span>
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      ) : (
        <RiskFindingsEvolutionChart
          title="Company Risk and Findings Evolution"
          description="Risk score (left axis) and active findings (right axis) for the selected company"
          data={series}
          emptyState={{
            title: "No company evolution data",
            description: "Run scans and risk calculations to start tracking portfolio trends.",
            icon: "chart",
          }}
        />
      )}
    </div>
  );
}

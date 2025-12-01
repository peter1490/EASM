"use client";

import { useEffect, useState, useRef } from "react";
import {
  getRiskOverview,
  listAssets,
  recalculateAssetRisk,
  recalculateAllRisks,
  getHighRiskAssets,
  type Asset,
  type RiskRecalculationResult,
} from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";
import Link from "next/link";

const RISK_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  minimal: "success",
};

export default function RiskPage() {
  const [overview, setOverview] = useState<Record<string, unknown> | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [highRiskAssets, setHighRiskAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recalculating, setRecalculating] = useState<string | null>(null);
  const [recalculatingAll, setRecalculatingAll] = useState(false);
  const [recalcResult, setRecalcResult] = useState<RiskRecalculationResult | null>(null);
  
  // Track if initial load has happened (ref to avoid re-renders)
  const hasInitialLoadRef = useRef(false);

  async function loadData(isRefresh = false) {
    try {
      // Only show full loading spinner on initial load, not refreshes
      if (!isRefresh) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }
      const [overviewData, assetsData, highRiskData] = await Promise.all([
        getRiskOverview(),
        listAssets(0, 100),
        getHighRiskAssets(10),
      ]);
      setOverview(overviewData);
      // Sort assets by risk score descending
      const sortedAssets = [...assetsData.assets].sort((a, b) => 
        (b.risk_score || 0) - (a.risk_score || 0)
      );
      setAssets(sortedAssets);
      setHighRiskAssets(highRiskData);
      setError(null);
      hasInitialLoadRef.current = true;
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadData(false); // Initial load with full spinner
    const interval = setInterval(() => loadData(true), 30000); // Silent refreshes
    return () => clearInterval(interval);
  }, []);

  async function handleRecalculate(assetId: string) {
    setRecalculating(assetId);
    try {
      const updated = await recalculateAssetRisk(assetId);
      setAssets(prev => prev.map(a => a.id === assetId ? updated : a));
      setHighRiskAssets(prev => prev.map(a => a.id === assetId ? updated : a));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRecalculating(null);
    }
  }

  async function handleRecalculateAll() {
    setRecalculatingAll(true);
    setRecalcResult(null);
    try {
      const result = await recalculateAllRisks();
      setRecalcResult(result);
      loadData(true); // Refresh data after recalculation (preserve scroll)
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRecalculatingAll(false);
    }
  }

  const assetsByRisk = overview?.assets_by_level as Record<string, number> | undefined;
  const findingsBySeverity = overview?.findings_by_severity as Record<string, number> | undefined;
  
  // Get counts from API (real data)
  const criticalCount = assetsByRisk?.critical || 0;
  const highCount = assetsByRisk?.high || 0;
  const mediumCount = assetsByRisk?.medium || 0;
  const lowCount = assetsByRisk?.low || 0;
  const infoCount = assetsByRisk?.info || 0;

  // Use API-provided stats
  const avgRiskScore = (overview?.average_risk_score as number) || 0;
  const assetsWithScores = (overview?.assets_with_scores as number) || 0;
  const assetsPending = (overview?.assets_pending_calculation as number) || 0;

  // Top risky assets from dedicated endpoint
  const topRiskyAssets = highRiskAssets.length > 0 ? highRiskAssets : assets.filter(a => a.risk_score !== null && a.risk_score !== undefined).slice(0, 10);

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Risk Dashboard" 
        description="Asset risk scores and vulnerability exposure"
      />

      {error && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-4">
            <div className="text-destructive flex items-center gap-2">
              <span>⚠️</span>
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
        <>
          {/* Bulk Recalculate Action */}
          <Card className="bg-muted/30">
            <CardContent className="py-4">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                  <h3 className="font-medium">Risk Recalculation</h3>
                  <p className="text-sm text-muted-foreground">
                    {assetsPending > 0 
                      ? `${assetsPending} assets pending risk calculation`
                      : `${assetsWithScores} assets have risk scores calculated`}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  {recalcResult && (
                    <div className="text-sm">
                      <span className="text-success">{recalcResult.success_count} updated</span>
                      {recalcResult.error_count > 0 && (
                        <span className="text-destructive ml-2">{recalcResult.error_count} errors</span>
                      )}
                    </div>
                  )}
                  <Button 
                    onClick={handleRecalculateAll}
                    disabled={recalculatingAll}
                    variant="outline"
                  >
                    {recalculatingAll ? "Recalculating..." : "Recalculate All Risks"}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Risk Overview Cards */}
          <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6 stagger-children">
            <Card className="border-l-4 border-l-destructive group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Critical Risk</CardDescription>
                <CardTitle className="text-3xl font-mono text-destructive">{criticalCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Assets at critical risk</div>
              </CardContent>
            </Card>
            <Card className="border-l-4 border-l-orange-500 group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>High Risk</CardDescription>
                <CardTitle className="text-3xl font-mono text-orange-500">{highCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Assets at high risk</div>
              </CardContent>
            </Card>
            <Card className="border-l-4 border-l-warning group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Medium Risk</CardDescription>
                <CardTitle className="text-3xl font-mono text-warning">{mediumCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Assets at medium risk</div>
              </CardContent>
            </Card>
            <Card className="border-l-4 border-l-info group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Low Risk</CardDescription>
                <CardTitle className="text-3xl font-mono text-info">{lowCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Assets at low risk</div>
              </CardContent>
            </Card>
            <Card className="border-l-4 border-l-secondary group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Info Level</CardDescription>
                <CardTitle className="text-3xl font-mono text-secondary">{infoCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Minimal risk assets</div>
              </CardContent>
            </Card>
            <Card className="border-l-4 border-l-primary group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Avg. Risk Score</CardDescription>
                <CardTitle className="text-3xl font-mono">{avgRiskScore.toFixed(1)}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Out of 100 max</div>
              </CardContent>
            </Card>
          </div>

          {/* Findings by Severity (if available) */}
          {findingsBySeverity && Object.keys(findingsBySeverity).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Security Findings Summary</CardTitle>
                <CardDescription>Open security findings by severity</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-4">
                  {findingsBySeverity.critical > 0 && (
                    <div className="flex items-center gap-2">
                      <Badge variant="error">Critical</Badge>
                      <span className="font-mono font-bold">{findingsBySeverity.critical}</span>
                    </div>
                  )}
                  {findingsBySeverity.high > 0 && (
                    <div className="flex items-center gap-2">
                      <Badge variant="error">High</Badge>
                      <span className="font-mono font-bold">{findingsBySeverity.high}</span>
                    </div>
                  )}
                  {findingsBySeverity.medium > 0 && (
                    <div className="flex items-center gap-2">
                      <Badge variant="warning">Medium</Badge>
                      <span className="font-mono font-bold">{findingsBySeverity.medium}</span>
                    </div>
                  )}
                  {findingsBySeverity.low > 0 && (
                    <div className="flex items-center gap-2">
                      <Badge variant="info">Low</Badge>
                      <span className="font-mono font-bold">{findingsBySeverity.low}</span>
                    </div>
                  )}
                  {findingsBySeverity.info > 0 && (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">Info</Badge>
                      <span className="font-mono font-bold">{findingsBySeverity.info}</span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Risk Distribution Visualization */}
          <Card>
            <CardHeader>
              <CardTitle>Risk Distribution</CardTitle>
              <CardDescription>Distribution of assets by risk level</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-5">
                {[
                  { level: "Critical", count: criticalCount, color: "bg-destructive", textColor: "text-destructive" },
                  { level: "High", count: highCount, color: "bg-orange-500", textColor: "text-orange-500" },
                  { level: "Medium", count: mediumCount, color: "bg-warning", textColor: "text-warning" },
                  { level: "Low", count: lowCount, color: "bg-info", textColor: "text-info" },
                  { level: "Info", count: infoCount, color: "bg-secondary", textColor: "text-secondary" },
                ].map((item) => {
                  const total = criticalCount + highCount + mediumCount + lowCount + infoCount;
                  const percentage = total > 0 ? (item.count / total) * 100 : 0;
                  return (
                    <div key={item.level} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className={`h-3 w-3 rounded ${item.color}`} />
                          <span className="font-medium">{item.level}</span>
                        </div>
                        <div className="text-sm">
                          <span className={`font-mono font-semibold ${item.textColor}`}>{item.count}</span>
                          <span className="text-muted-foreground ml-2">({percentage.toFixed(1)}%)</span>
                        </div>
                      </div>
                      <div className="h-2.5 bg-muted rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${item.color} transition-all duration-700 ease-out`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Top Risky Assets Table */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Highest Risk Assets</CardTitle>
                  <CardDescription>Assets with the highest risk scores</CardDescription>
                </div>
                <Button variant="outline" onClick={() => loadData(true)} disabled={refreshing}>
                  {refreshing ? "Refreshing..." : "Refresh"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {topRiskyAssets.length === 0 ? (
                <EmptyState
                  icon="📊"
                  title="No risk data available"
                  description="Risk scores will appear after running security scans on your assets"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Risk Score</TableHead>
                      <TableHead>Risk Level</TableHead>
                      <TableHead>Importance</TableHead>
                      <TableHead>Last Calculated</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topRiskyAssets.map((asset) => (
                      <TableRow key={asset.id} className="hover:bg-muted/50 cursor-pointer">
                        <TableCell className="font-mono text-sm">
                          <Link href={`/asset/${asset.id}`} className="hover:text-primary transition-colors">
                            {asset.value}
                          </Link>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{asset.asset_type}</Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <div className="w-20 h-2.5 bg-muted rounded-full overflow-hidden">
                              <div 
                                className={`h-full transition-all ${
                                  (asset.risk_score || 0) >= 8 ? "bg-destructive" :
                                  (asset.risk_score || 0) >= 6 ? "bg-orange-500" :
                                  (asset.risk_score || 0) >= 4 ? "bg-warning" :
                                  (asset.risk_score || 0) >= 2 ? "bg-info" : "bg-success"
                                }`}
                                style={{ width: `${((asset.risk_score || 0) / 10) * 100}%` }}
                              />
                            </div>
                            <span className={`font-mono font-semibold ${
                              (asset.risk_score || 0) >= 8 ? "text-destructive" :
                              (asset.risk_score || 0) >= 6 ? "text-orange-500" :
                              (asset.risk_score || 0) >= 4 ? "text-warning" :
                              "text-muted-foreground"
                            }`}>
                              {asset.risk_score?.toFixed(1) || "N/A"}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          {asset.risk_level ? (
                            <Badge variant={RISK_COLORS[asset.risk_level.toLowerCase()] || "secondary"}>
                              {asset.risk_level}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            {[1, 2, 3, 4, 5].map((i) => (
                              <div
                                key={i}
                                className={`h-2 w-2 rounded-full transition-colors ${
                                  i <= asset.importance ? "bg-primary" : "bg-muted"
                                }`}
                              />
                            ))}
                            <span className="ml-2 text-sm text-muted-foreground font-mono">{asset.importance}/5</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {asset.last_risk_run 
                            ? new Date(asset.last_risk_run).toLocaleDateString()
                            : "Never"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleRecalculate(asset.id)}
                            disabled={recalculating === asset.id}
                          >
                            {recalculating === asset.id ? "..." : "Recalculate"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* All Assets with Risk */}
          <Card>
            <CardHeader>
              <CardTitle>All Assets Risk Status</CardTitle>
              <CardDescription>
                Complete list of assets with their risk assessment ({assetsWithScores} with scores, {assetsPending} pending)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {assets.slice(0, 12).map((asset) => (
                  <Link key={asset.id} href={`/asset/${asset.id}`}>
                    <div
                      className="p-4 border border-border rounded-xl hover:bg-muted/30 hover:border-primary/30 transition-all cursor-pointer group h-full"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1 min-w-0">
                          <p className="font-mono text-sm truncate group-hover:text-primary transition-colors">{asset.value}</p>
                          <p className="text-xs text-muted-foreground">{asset.asset_type}</p>
                        </div>
                        {asset.risk_level && (
                          <Badge variant={RISK_COLORS[asset.risk_level.toLowerCase()] || "secondary"} className="ml-2">
                            {asset.risk_level}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
                        <div className="text-sm">
                          <span className="text-muted-foreground">Score: </span>
                          <span className="font-mono font-semibold">
                            {asset.risk_score?.toFixed(1) || "N/A"}
                          </span>
                        </div>
                        <div className="text-sm">
                          <span className="text-muted-foreground">Importance: </span>
                          <span className="font-mono">{asset.importance}/5</span>
                        </div>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
              {assets.length > 12 && (
                <div className="text-center mt-6 pt-4 border-t border-border">
                  <p className="text-muted-foreground text-sm">
                    And {assets.length - 12} more assets...
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

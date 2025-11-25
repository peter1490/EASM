"use client";

import { useEffect, useState } from "react";
import {
  getRiskOverview,
  listAssets,
  recalculateAssetRisk,
  type Asset,
} from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [recalculating, setRecalculating] = useState<string | null>(null);

  async function loadData() {
    try {
      setLoading(true);
      const [overviewData, assetsData] = await Promise.all([
        getRiskOverview(),
        listAssets(0, 100),
      ]);
      setOverview(overviewData);
      // Sort assets by risk score descending
      const sortedAssets = [...assetsData.assets].sort((a, b) => 
        (b.risk_score || 0) - (a.risk_score || 0)
      );
      setAssets(sortedAssets);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  async function handleRecalculate(assetId: string) {
    setRecalculating(assetId);
    try {
      const updated = await recalculateAssetRisk(assetId);
      setAssets(prev => prev.map(a => a.id === assetId ? updated : a));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRecalculating(null);
    }
  }

  const assetsByRisk = overview?.assets_by_level as Record<string, number> | undefined;
  
  // Get counts
  const criticalCount = assetsByRisk?.critical || 0;
  const highCount = assetsByRisk?.high || 0;
  const mediumCount = assetsByRisk?.medium || 0;
  const lowCount = assetsByRisk?.low || 0;
  const minimalCount = assetsByRisk?.minimal || 0;

  // Assets with risk scores
  const assetsWithRisk = assets.filter(a => a.risk_score !== null && a.risk_score !== undefined);
  const avgRiskScore = assetsWithRisk.length > 0 
    ? assetsWithRisk.reduce((sum, a) => sum + (a.risk_score || 0), 0) / assetsWithRisk.length 
    : 0;

  // Top risky assets
  const topRiskyAssets = assetsWithRisk.slice(0, 10);

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
            <Card className="border-l-4 border-l-success group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Minimal Risk</CardDescription>
                <CardTitle className="text-3xl font-mono text-success">{minimalCount}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Well protected assets</div>
              </CardContent>
            </Card>
            <Card className="border-l-4 border-l-primary group hover:shadow-lg transition-all">
              <CardHeader className="pb-2">
                <CardDescription>Avg. Risk Score</CardDescription>
                <CardTitle className="text-3xl font-mono">{avgRiskScore.toFixed(1)}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Across all assets</div>
              </CardContent>
            </Card>
          </div>

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
                  { level: "Minimal", count: minimalCount, color: "bg-success", textColor: "text-success" },
                ].map((item) => {
                  const total = criticalCount + highCount + mediumCount + lowCount + minimalCount;
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
                <Button variant="outline" onClick={loadData}>Refresh</Button>
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
                      <TableRow key={asset.id}>
                        <TableCell className="font-mono text-sm">{asset.value}</TableCell>
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
                Complete list of assets with their risk assessment ({assetsWithRisk.length} with scores, {assets.length - assetsWithRisk.length} pending)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {assets.slice(0, 12).map((asset) => (
                  <div
                    key={asset.id}
                    className="p-4 border border-border rounded-xl hover:bg-muted/30 hover:border-primary/30 transition-all cursor-pointer group"
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

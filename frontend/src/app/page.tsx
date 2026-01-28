"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { 
  getMetrics, 
  getDiscoveryStatus, 
  getSecurityFindingsSummary,
  getRiskOverview,
  listSecurityScans,
  type SecurityScan,
  type SystemMetrics,
  type DiscoveryStatus,
} from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Header from "@/components/Header";
import { useAuth } from "@/context/AuthContext";

export default function Dashboard() {
  const { user } = useAuth();
  const [scans, setScans] = useState<SecurityScan[]>([]);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [discoveryStatus, setDiscoveryStatus] = useState<DiscoveryStatus | null>(null);
  const [findingsSummary, setFindingsSummary] = useState<Record<string, number>>({});
  const [riskOverview, setRiskOverview] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    try {
      const [scansData, metricsData, discoveryData, findingsData, riskData] = await Promise.all([
        listSecurityScans(25),
        getMetrics(),
        getDiscoveryStatus(),
        getSecurityFindingsSummary(),
        getRiskOverview(),
      ]);
      setScans(scansData);
      setMetrics(metricsData);
      setDiscoveryStatus(discoveryData);
      setFindingsSummary(findingsData.by_severity || {});
      setRiskOverview(riskData);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const id = setInterval(loadData, 5000);
    return () => clearInterval(id);
  }, []);

  // Security findings breakdown
  const criticalFindings = findingsSummary.critical || 0;
  const highFindings = findingsSummary.high || 0;
  const totalSecurityFindings = Object.values(findingsSummary).reduce((a, b) => a + b, 0);

  // Risk breakdown
  const assetsByRisk = riskOverview?.assets_by_level as Record<string, number> | undefined;
  const criticalRiskAssets = assetsByRisk?.critical || 0;
  const highRiskAssets = assetsByRisk?.high || 0;

  const recentScans = scans.slice(0, 5);

  const getFindingsCount = (scan: SecurityScan) => {
    const summary = scan.result_summary as Record<string, unknown> | undefined;
    const bySeverity = summary?.findings_by_severity as Record<string, number> | undefined;
    if (!bySeverity) return 0;
    return Object.values(bySeverity).reduce((acc, val) => acc + (Number(val) || 0), 0);
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title={`Welcome back, ${user?.email?.split('@')[0] || 'User'}`}
        description="Your External Attack Surface Management overview"
      />

      {/* Discovery Status Alert */}
      {discoveryStatus?.running && (
        <Card className="border-primary/50 bg-gradient-to-r from-primary/5 via-info/5 to-primary/5 glow-primary">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="relative">
                  <div className="h-12 w-12 rounded-xl bg-primary/20 flex items-center justify-center">
                    <LoadingSpinner size="md" />
                  </div>
                  <div className="absolute -top-1 -right-1 h-3 w-3 bg-primary rounded-full animate-pulse" />
                </div>
                <div>
                  <div className="font-semibold text-primary">Discovery in Progress</div>
                  <div className="text-sm text-muted-foreground">
                    {discoveryStatus.assets_discovered} assets discovered • {discoveryStatus.seeds_processed} seeds processed
                  </div>
                </div>
              </div>
              <Link href="/discovery">
                <Button variant="outline" size="sm">View Details →</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Critical Alerts */}
      {(criticalFindings > 0 || highFindings > 0 || criticalRiskAssets > 0) && (
        <Card className="border-destructive/50 bg-gradient-to-r from-destructive/5 to-orange-500/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-8">
                <div className="text-center">
                  <div className="text-3xl font-bold font-mono text-destructive">{criticalFindings + highFindings}</div>
                  <div className="text-xs text-muted-foreground">Critical/High Findings</div>
                </div>
                <div className="h-10 w-px bg-border" />
                <div className="text-center">
                  <div className="text-3xl font-bold font-mono text-orange-500">{criticalRiskAssets + highRiskAssets}</div>
                  <div className="text-xs text-muted-foreground">High Risk Assets</div>
                </div>
              </div>
              <Link href="/security">
                <Button variant="destructive" size="sm">Review Findings →</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4 stagger-children">
        <Card className="group hover:shadow-lg transition-all hover:border-primary/30">
          <CardHeader className="pb-3">
            <CardDescription>Total Assets</CardDescription>
            <CardTitle className="text-4xl font-mono">{metrics?.total_assets || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <Link href="/assets" className="text-xs text-primary hover:underline inline-flex items-center gap-1 group-hover:gap-2 transition-all">
              View all assets <span>→</span>
            </Link>
          </CardContent>
        </Card>
        
        <Card className="group hover:shadow-lg transition-all hover:border-warning/30">
          <CardHeader className="pb-3">
            <CardDescription>Security Findings</CardDescription>
            <CardTitle className="text-4xl font-mono text-warning">{totalSecurityFindings}</CardTitle>
          </CardHeader>
          <CardContent>
            <Link href="/security" className="text-xs text-primary hover:underline inline-flex items-center gap-1 group-hover:gap-2 transition-all">
              View findings <span>→</span>
            </Link>
          </CardContent>
        </Card>
        
        <Card className="group hover:shadow-lg transition-all hover:border-info/30">
          <CardHeader className="pb-3">
            <CardDescription>Active Scans</CardDescription>
            <CardTitle className="text-4xl font-mono text-info">{metrics?.active_scans || 0}</CardTitle>
          </CardHeader>
          <CardContent>
            <Link href="/discovery" className="text-xs text-primary hover:underline inline-flex items-center gap-1 group-hover:gap-2 transition-all">
              Manage scans <span>→</span>
            </Link>
          </CardContent>
        </Card>
        
        <Card className="group hover:shadow-lg transition-all hover:border-success/30">
          <CardHeader className="pb-3">
            <CardDescription>System Health</CardDescription>
            <CardTitle className="text-4xl font-mono text-success flex items-center gap-2">
              <div className="h-3 w-3 rounded-full bg-success animate-pulse" />
              OK
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Link href="/settings" className="text-xs text-primary hover:underline inline-flex items-center gap-1 group-hover:gap-2 transition-all">
              View status <span>→</span>
            </Link>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[
          { href: "/discovery", icon: "🔄", title: "Run Discovery", desc: "Find new assets", color: "from-primary/10 to-primary/5" },
          { href: "/security", icon: "🛡️", title: "Security Scan", desc: "Scan for vulnerabilities", color: "from-destructive/10 to-destructive/5" },
          { href: "/risk", icon: "⚠️", title: "Risk Dashboard", desc: "View risk scores", color: "from-warning/10 to-warning/5" },
          { href: "/search", icon: "🔎", title: "Global Search", desc: "Find assets & findings", color: "from-info/10 to-info/5" },
        ].map((action) => (
          <Link key={action.href} href={action.href}>
            <Card className={`hover:border-primary/50 transition-all cursor-pointer h-full bg-gradient-to-br ${action.color} hover:shadow-lg group`}>
              <CardContent className="pt-6">
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-xl bg-card flex items-center justify-center text-2xl shadow-sm group-hover:scale-110 transition-transform">
                    {action.icon}
                  </div>
                  <div>
                    <div className="font-semibold">{action.title}</div>
                    <div className="text-sm text-muted-foreground">{action.desc}</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Security Findings Summary */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Security Findings by Severity</CardTitle>
                <CardDescription>Breakdown of vulnerabilities found</CardDescription>
              </div>
              <Link href="/security">
                <Button variant="outline" size="sm">View All →</Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { level: "Critical", count: findingsSummary.critical || 0, color: "bg-destructive" },
                { level: "High", count: findingsSummary.high || 0, color: "bg-orange-500" },
                { level: "Medium", count: findingsSummary.medium || 0, color: "bg-warning" },
                { level: "Low", count: findingsSummary.low || 0, color: "bg-info" },
                { level: "Info", count: findingsSummary.info || 0, color: "bg-secondary" },
              ].map((item) => {
                const percentage = totalSecurityFindings > 0 ? (item.count / totalSecurityFindings) * 100 : 0;
                return (
                  <div key={item.level} className="flex items-center gap-4">
                    <div className="w-16 text-sm font-medium">{item.level}</div>
                    <div className="flex-1 h-2.5 bg-muted rounded-full overflow-hidden">
                      <div 
                        className={`h-full ${item.color} transition-all duration-700 ease-out`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <div className="w-10 text-sm text-right font-mono">{item.count}</div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Risk Distribution</CardTitle>
                <CardDescription>Assets by risk level</CardDescription>
              </div>
              <Link href="/risk">
                <Button variant="outline" size="sm">View All →</Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { level: "Critical", count: assetsByRisk?.critical || 0, color: "bg-destructive" },
                { level: "High", count: assetsByRisk?.high || 0, color: "bg-orange-500" },
                { level: "Medium", count: assetsByRisk?.medium || 0, color: "bg-warning" },
                { level: "Low", count: assetsByRisk?.low || 0, color: "bg-info" },
                { level: "Minimal", count: assetsByRisk?.minimal || 0, color: "bg-success" },
              ].map((item) => {
                const total = Object.values(assetsByRisk || {}).reduce((a, b) => a + b, 0);
                const percentage = total > 0 ? (item.count / total) * 100 : 0;
                return (
                  <div key={item.level} className="flex items-center gap-4">
                    <div className="w-16 text-sm font-medium">{item.level}</div>
                    <div className="flex-1 h-2.5 bg-muted rounded-full overflow-hidden">
                      <div 
                        className={`h-full ${item.color} transition-all duration-700 ease-out`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <div className="w-10 text-sm text-right font-mono">{item.count}</div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>Latest scan operations and their status</CardDescription>
            </div>
            <Link href="/assets">
              <Button variant="outline" size="sm">View All Assets →</Button>
            </Link>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : scans.length === 0 ? (
            <EmptyState
              icon="🔍"
              title="No scans yet"
              description="Run discovery or start a security scan to assess your assets"
              action={
                <Link href="/discovery">
                  <Button>Start Discovery</Button>
                </Link>
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead>Scan Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentScans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>
                      <Link href={`/asset/${scan.asset_id}`}>
                        <span className="font-medium font-mono hover:text-primary transition-colors">
                          {scan.asset_id.slice(0, 8)}...
                        </span>
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant="info">{scan.scan_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge 
                        variant={
                          scan.status === "completed" ? "success" : 
                          scan.status === "failed" ? "error" : 
                          "warning"
                        }
                      >
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-medium">
                          {getFindingsCount(scan)}
                        </span>
                        <span className="text-xs text-muted-foreground">findings</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(scan.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Link href={`/security/scans/${scan.id}`}>
                        <Button variant="ghost" size="sm">View Details →</Button>
                      </Link>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* System Health */}
      {metrics && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>System Health</CardTitle>
                <CardDescription>Backend performance metrics</CardDescription>
              </div>
              <Link href="/settings">
                <Button variant="outline" size="sm">Full Report →</Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-4">
              {[
                { label: "CPU Usage", value: `${metrics.cpu_usage_percent.toFixed(1)}%`, icon: "⚡" },
                { label: "Memory", value: `${((metrics.memory_usage.used_bytes / metrics.memory_usage.total_bytes) * 100).toFixed(1)}%`, icon: "💾" },
                { label: "Requests/sec", value: metrics.requests_per_second.toFixed(2), icon: "🚀" },
                { label: "Uptime", value: `${Math.floor(metrics.uptime_seconds / 3600)}h`, icon: "⏱️" },
              ].map((stat, idx) => (
                <div key={idx} className="p-4 bg-muted/50 rounded-xl text-center">
                  <div className="text-2xl mb-1">{stat.icon}</div>
                  <div className="text-2xl font-bold font-mono">{stat.value}</div>
                  <div className="text-xs text-muted-foreground">{stat.label}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { getHealth, getMetrics, type SystemMetrics } from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Badge from "@/components/ui/Badge";

export default function SettingsPage() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [health, setHealth] = useState<{ status: string; version: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    try {
      const [m, h] = await Promise.all([getMetrics(), getHealth()]);
      setMetrics(m);
      setHealth(h);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const iv = setInterval(loadData, 5000);
    return () => clearInterval(iv);
  }, []);

  function formatBytes(bytes: number) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function formatUptime(seconds: number) {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  }

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="System Status" 
        description="Monitor backend performance and system health"
      />

      {error && (
        <Card className="border-destructive">
          <CardContent className="py-4">
            <div className="text-destructive">Error loading metrics: {error}</div>
          </CardContent>
        </Card>
      )}

      {loading && !metrics ? (
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      ) : metrics && health ? (
        <div className="space-y-6">
          {/* System Overview */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="pb-3">
                <CardDescription>System Status</CardDescription>
                <CardTitle className="flex items-center gap-2">
                  <div className={`h-3 w-3 rounded-full ${health.status === "healthy" || health.status === "ok" ? "bg-success animate-pulse" : "bg-destructive"}`} />
                  {health.status.toUpperCase()}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Version: {health.version}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Uptime</CardDescription>
                <CardTitle>{formatUptime(metrics.uptime_seconds)}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Since last restart
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>Memory Usage</CardDescription>
                <CardTitle>{formatBytes(metrics.memory_usage.used_bytes)}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  of {formatBytes(metrics.memory_usage.total_bytes)} total
                </div>
                <div className="mt-2 h-1.5 w-full bg-muted rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-primary transition-all duration-500" 
                    style={{ width: `${(metrics.memory_usage.used_bytes / metrics.memory_usage.total_bytes) * 100}%` }}
                  />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardDescription>CPU Usage</CardDescription>
                <CardTitle>{metrics.cpu_usage_percent.toFixed(1)}%</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">
                  Current load
                </div>
                <div className="mt-2 h-1.5 w-full bg-muted rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ${metrics.cpu_usage_percent > 80 ? "bg-destructive" : metrics.cpu_usage_percent > 50 ? "bg-warning" : "bg-success"}`}
                    style={{ width: `${Math.min(metrics.cpu_usage_percent, 100)}%` }}
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Application Stats */}
          <div className="grid gap-6 md:grid-cols-2">
             <Card>
               <CardHeader>
                 <CardTitle>Application Statistics</CardTitle>
                 <CardDescription>Core metrics for the EASM platform</CardDescription>
               </CardHeader>
               <CardContent className="space-y-4">
                 <div className="flex items-center justify-between p-4 border rounded-lg">
                   <div className="flex items-center gap-3">
                     <span className="text-2xl">🎯</span>
                     <div className="font-medium">Total Assets</div>
                   </div>
                   <span className="text-2xl font-bold">{metrics.total_assets}</span>
                 </div>
                 <div className="flex items-center justify-between p-4 border rounded-lg">
                   <div className="flex items-center gap-3">
                     <span className="text-2xl">🔍</span>
                     <div className="font-medium">Total Findings</div>
                   </div>
                   <span className="text-2xl font-bold text-info">{metrics.total_findings}</span>
                 </div>
                 <div className="flex items-center justify-between p-4 border rounded-lg">
                   <div className="flex items-center gap-3">
                     <span className="text-2xl">⚡</span>
                     <div className="font-medium">Active Scans</div>
                   </div>
                   <span className="text-2xl font-bold text-warning">{metrics.active_scans}</span>
                 </div>
                 <div className="flex items-center justify-between p-4 border rounded-lg">
                   <div className="flex items-center gap-3">
                     <span className="text-2xl">🚀</span>
                     <div className="font-medium">Requests / Sec</div>
                   </div>
                   <span className="text-2xl font-bold text-success">{metrics.requests_per_second.toFixed(2)}</span>
                 </div>
               </CardContent>
             </Card>

             <Card>
               <CardHeader>
                 <CardTitle>Feature Status</CardTitle>
                 <CardDescription>Operational status of system components</CardDescription>
               </CardHeader>
               <CardContent>
                 <div className="space-y-4">
                   {[
                     { name: "Scanner Engine", status: "operational" },
                     { name: "Drift Detection", status: "operational" },
                     { name: "Search Index", status: "operational" },
                     { name: "Risk Scoring", status: "operational" },
                   ].map((component) => (
                     <div key={component.name} className="flex items-center justify-between">
                       <div className="flex items-center gap-2">
                         <div className="h-2 w-2 rounded-full bg-success" />
                         <span>{component.name}</span>
                       </div>
                       <Badge variant="outline" className="text-success border-success/20 bg-success/10">
                         {component.status}
                       </Badge>
                     </div>
                   ))}
                 </div>
               </CardContent>
             </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
}


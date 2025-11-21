"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { getScan, type Scan, type Finding } from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import FindingRenderer, { getFindingTypeLabel, getFindingTypeIcon } from "@/components/FindingRenderer";
import DriftAnalysis from "@/components/DriftAnalysis";

type TabType = "overview" | "findings" | "drift" | "raw";

export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabType>("overview");

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const s = await getScan(id);
        if (mounted) {
          setScan(s);
          setLoading(false);
        }
      } catch (e) {
        if (mounted) {
          setError((e as Error).message);
          setLoading(false);
        }
      }
    }
    load();
    const iv = setInterval(load, 3000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, [id]);

  const grouped = useMemo(() => {
    const byType: Record<string, Finding[]> = {};
    for (const f of scan?.findings ?? []) {
      if (!byType[f.finding_type]) byType[f.finding_type] = [];
      byType[f.finding_type].push(f);
    }
    return byType;
  }, [scan]);

  const stats = useMemo(() => {
    const findings = scan?.findings ?? [];
    return {
      total: findings.length,
      types: Object.keys(grouped).length,
      byType: Object.entries(grouped).reduce((acc, [type, findings]) => {
        acc[type] = findings.length;
        return acc;
      }, {} as Record<string, number>),
    };
  }, [scan, grouped]);

  const tabs: Array<{ id: TabType; label: string; icon: string }> = [
    { id: "overview", label: "Overview", icon: "📊" },
    { id: "findings", label: `Findings (${stats.total})`, icon: "🔍" },
    { id: "drift", label: "Drift Analysis", icon: "⚓" },
    { id: "raw", label: "Raw Data", icon: "📄" },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">Scan Details</h1>
          <p className="text-muted-foreground">View scan results and findings</p>
        </div>
        <Card className="border-destructive">
          <CardContent className="py-8">
            <div className="text-center">
              <div className="text-6xl mb-4">❌</div>
              <h3 className="text-lg font-semibold text-destructive mb-2">Error Loading Scan</h3>
              <p className="text-sm text-muted-foreground mb-6">{error}</p>
              <Link href="/">
                <Button>Back to Dashboard</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!scan) {
    return null;
  }

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Link href="/">
              <Button variant="ghost" size="sm">← Back</Button>
            </Link>
            <h1 className="text-3xl font-bold">Scan Details</h1>
          </div>
          <p className="text-muted-foreground">
            Scan ID: <span className="font-mono text-sm">{id}</span>
          </p>
        </div>
        <Badge 
          variant={
            scan.status === "completed" ? "success" : 
            scan.status === "failed" ? "error" : 
            "warning"
          }
        >
          {scan.status}
        </Badge>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Findings</CardDescription>
            <CardTitle className="text-3xl">{stats.total}</CardTitle>
          </CardHeader>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Finding Types</CardDescription>
            <CardTitle className="text-3xl text-primary">{stats.types}</CardTitle>
          </CardHeader>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Target</CardDescription>
            <CardTitle className="text-lg font-mono truncate">{scan.target}</CardTitle>
          </CardHeader>
        </Card>
        
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Duration</CardDescription>
            <CardTitle className="text-lg">
              {Math.round((new Date(scan.updated_at).getTime() - new Date(scan.created_at).getTime()) / 1000)}s
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Tabs */}
      <div className="border-b border-border">
        <nav className="flex gap-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`pb-3 px-1 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Scan Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="text-sm text-muted-foreground mb-1">Target</div>
                <div className="font-medium font-mono text-lg">{scan.target}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground mb-1">Status</div>
                <Badge 
                  variant={
                    scan.status === "completed" ? "success" : 
                    scan.status === "failed" ? "error" : 
                    "warning"
                  }
                >
                  {scan.status}
                </Badge>
              </div>
              <div>
                <div className="text-sm text-muted-foreground mb-1">Created</div>
                <div className="font-medium">{new Date(scan.created_at).toLocaleString()}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground mb-1">Last Updated</div>
                <div className="font-medium">{new Date(scan.updated_at).toLocaleString()}</div>
              </div>
              {scan.note && (
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Note</div>
                  <div className="font-medium">{scan.note}</div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Findings Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="text-sm text-muted-foreground mb-1">Total Findings</div>
                <div className="text-2xl font-bold">{stats.total}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground mb-1">Finding Types</div>
                <div className="text-2xl font-bold">{stats.types}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground mb-2">Type Distribution</div>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {Object.entries(stats.byType)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                          <span className="text-lg">{getFindingTypeIcon(type)}</span>
                          <span className="text-sm truncate">{getFindingTypeLabel(type)}</span>
                        </div>
                        <Badge variant="secondary">{count}</Badge>
                      </div>
                    ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === "findings" && (
        <div className="space-y-6">
          {Object.keys(grouped).length === 0 ? (
            <Card>
              <CardContent className="py-8">
                <EmptyState
                  icon="🔍"
                  title="No findings yet"
                  description={
                    scan.status === "completed" 
                      ? "This scan completed without any findings" 
                      : "Findings will appear here as the scan progresses"
                  }
                />
              </CardContent>
            </Card>
          ) : (
            Object.entries(grouped)
              .sort((a, b) => b[1].length - a[1].length)
              .map(([findingType, findings]) => (
                <Card key={findingType}>
                  <CardHeader>
                    <div className="flex items-center gap-2">
                      <span className="text-2xl">{getFindingTypeIcon(findingType)}</span>
                      <div className="flex-1">
                        <CardTitle>{getFindingTypeLabel(findingType)}</CardTitle>
                        <CardDescription>{findings.length} finding{findings.length !== 1 ? "s" : ""}</CardDescription>
                      </div>
                      <Badge variant="secondary">{findings.length}</Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {findings.map((finding, idx) => (
                        <div key={finding.id} className="border-b border-border last:border-0 pb-4 last:pb-0">
                          <div className="flex items-start justify-between mb-2">
                            <div className="text-xs text-muted-foreground">
                              Finding #{idx + 1}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {new Date(finding.created_at).toLocaleString()}
                            </div>
                          </div>
                          <FindingRenderer findingType={finding.finding_type} data={finding.data} />
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))
          )}
        </div>
      )}

      {activeTab === "drift" && (
        <DriftAnalysis scanId={id} />
      )}

      {activeTab === "raw" && (
        <Card>
          <CardHeader>
            <CardTitle>Raw Scan Data</CardTitle>
            <CardDescription>Complete JSON response from the API</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-96">
              {JSON.stringify(scan, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

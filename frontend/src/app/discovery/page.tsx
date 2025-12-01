"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import {
  runDiscovery,
  stopDiscovery,
  getDiscoveryStatus,
  listDiscoveryRuns,
  listSeeds,
  createSeed,
  deleteSeed,
  type DiscoveryStatus,
  type DiscoveryRun,
  type Seed,
  type SeedType,
} from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import Input from "@/components/ui/Input";
import Select from "@/components/ui/Select";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";
import Modal from "@/components/ui/Modal";

type TabType = "overview" | "seeds" | "history";

const STATUS_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  pending: "secondary",
  running: "warning",
  completed: "success",
  failed: "error",
  cancelled: "secondary",
};

const TRIGGER_LABELS: Record<string, string> = {
  manual: "Manual",
  scheduled: "Scheduled",
  seed_added: "Seed Added",
};

const SEED_TYPES: Array<{ value: SeedType; label: string; icon: string; description: string; backendValue?: string }> = [
  { value: "root_domain", label: "Root Domain", icon: "🌐", description: "e.g., example.com", backendValue: "domain" },
  { value: "acquisition_domain", label: "Acquisition Domain", icon: "🏢", description: "Domain from acquisition", backendValue: "domain" },
  { value: "cidr", label: "CIDR Range", icon: "📡", description: "e.g., 10.0.0.0/24" },
  { value: "asn", label: "ASN", icon: "🔢", description: "e.g., AS12345" },
  { value: "keyword", label: "Keyword", icon: "🔑", description: "Search keyword" },
  { value: "organization", label: "Organization", icon: "🏛️", description: "Company name" },
];

const getSeedTypeInfo = (seedType: string) => {
  return SEED_TYPES.find(t => t.value === seedType || t.backendValue === seedType);
};

export default function DiscoveryPage() {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [status, setStatus] = useState<DiscoveryStatus | null>(null);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [seeds, setSeeds] = useState<Seed[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Discovery controls
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [maxDepth, setMaxDepth] = useState(3);
  const [autoScanThreshold, setAutoScanThreshold] = useState(0.7);
  
  // Seed form
  const [seedType, setSeedType] = useState<SeedType>("root_domain");
  const [seedValue, setSeedValue] = useState("");
  const [seedNote, setSeedNote] = useState("");
  const [adding, setAdding] = useState(false);
  
  // Run detail modal
  const [selectedRun, setSelectedRun] = useState<DiscoveryRun | null>(null);

  const loadData = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      }
      const [statusData, runsData, seedsData] = await Promise.all([
        getDiscoveryStatus(),
        listDiscoveryRuns(50),
        listSeeds(),
      ]);
      setStatus(statusData);
      setRuns(runsData);
      setSeeds(seedsData);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData(false);
    const interval = setInterval(() => loadData(true), status?.running ? 3000 : 10000);
    return () => clearInterval(interval);
  }, [loadData, status?.running]);

  async function handleStartDiscovery() {
    setStarting(true);
    setError(null);
    try {
      await runDiscovery({
        max_depth: maxDepth,
        auto_scan_threshold: autoScanThreshold,
      });
      loadData(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStarting(false);
    }
  }

  async function handleStopDiscovery() {
    setStopping(true);
    setError(null);
    try {
      await stopDiscovery();
      loadData(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStopping(false);
    }
  }

  async function handleAddSeed() {
    if (!seedValue.trim()) return;
    setError(null);
    setAdding(true);
    try {
      await createSeed({ seed_type: seedType, value: seedValue.trim(), note: seedNote.trim() || undefined });
      setSeedValue("");
      setSeedNote("");
      await loadData(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  }

  async function handleDeleteSeed(id: string) {
    try {
      await deleteSeed(id);
      await loadData(true);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function formatDuration(startedAt: string | null, completedAt: string | null): string {
    if (!startedAt) return "—";
    const start = new Date(startedAt).getTime();
    const end = completedAt ? new Date(completedAt).getTime() : Date.now();
    const seconds = Math.floor((end - start) / 1000);
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  }

  // Stats
  const completedRuns = runs.filter(r => r.status === "completed").length;
  const failedRuns = runs.filter(r => r.status === "failed").length;
  const totalAssetsDiscovered = runs.reduce((sum, r) => sum + r.assets_discovered, 0);
  
  const seedStats = useMemo(() => ({
    total: seeds.length,
    byType: SEED_TYPES.map(type => ({
      ...type,
      count: seeds.filter(s => s.seed_type === type.value || s.seed_type === type.backendValue).length,
    })),
  }), [seeds]);

  const selectedType = SEED_TYPES.find(t => t.value === seedType);

  const tabs = [
    { id: "overview" as TabType, label: "Overview", icon: "📊" },
    { id: "seeds" as TabType, label: "Seeds", icon: "🌱", badge: seeds.length },
    { id: "history" as TabType, label: "History", icon: "📜", badge: runs.length },
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Discovery" 
        description="Manage seeds and discover your attack surface"
      />

      {/* Live Discovery Status Banner */}
      {status?.running && (
        <Card className="border-primary/50 bg-gradient-to-r from-primary/5 via-info/5 to-primary/5 glow-primary">
          <CardContent className="py-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="relative">
                  <div className="h-14 w-14 rounded-xl bg-primary/20 flex items-center justify-center">
                    <LoadingSpinner size="lg" />
                  </div>
                  <div className="absolute -top-1 -right-1 h-4 w-4 bg-primary rounded-full animate-pulse-glow" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-primary">Discovery in Progress</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    Phase: {status.current_phase || "Processing"}
                    {status.started_at && (
                      <span className="ml-2">• Running for {formatDuration(status.started_at, null)}</span>
                    )}
                  </p>
                </div>
              </div>
              <Button
                variant="destructive"
                onClick={handleStopDiscovery}
                disabled={stopping}
              >
                {stopping ? "Stopping..." : "Stop Discovery"}
              </Button>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-6">
              {[
                { label: "Total Seeds", value: status.seeds_total || 0, color: "text-foreground" },
                { label: "Seeds Processed", value: status.seeds_processed, color: "text-success" },
                { label: "Assets Found", value: status.assets_discovered, color: "text-primary" },
                { label: "Assets Updated", value: status.assets_updated || 0, color: "text-info" },
                { label: "Queue Pending", value: status.queue_pending || 0, color: "text-muted-foreground" },
              ].map((stat, idx) => (
                <div key={idx} className="text-center p-3 bg-card/50 rounded-lg">
                  <div className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
                  <div className="text-xs text-muted-foreground">{stat.label}</div>
                </div>
              ))}
            </div>

            {status.errors && status.errors.length > 0 && (
              <div className="mt-4 p-3 bg-destructive/10 rounded-lg border border-destructive/20">
                <div className="text-sm font-medium text-destructive mb-2">
                  Errors ({status.error_count})
                </div>
                <div className="text-xs text-destructive/80 space-y-1">
                  {status.errors.slice(0, 3).map((err, idx) => (
                    <div key={idx}>{err}</div>
                  ))}
                  {status.errors.length > 3 && (
                    <div>...and {status.errors.length - 3} more</div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Tab Navigation */}
      <div className="tab-list">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`tab-item flex items-center gap-2 ${activeTab === tab.id ? "active" : ""}`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-primary/20 text-primary text-xs rounded-full font-medium">
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

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

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <div className="space-y-6 stagger-children">
          {/* Stats Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className="group hover:border-primary/30 transition-colors">
              <CardHeader className="pb-2">
                <CardDescription>Total Seeds</CardDescription>
                <CardTitle className="text-3xl font-mono">{seeds.length}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Configured seeds for discovery</div>
              </CardContent>
            </Card>
            <Card className="group hover:border-success/30 transition-colors">
              <CardHeader className="pb-2">
                <CardDescription>Completed Runs</CardDescription>
                <CardTitle className="text-3xl font-mono text-success">{completedRuns}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Successful discovery runs</div>
              </CardContent>
            </Card>
            <Card className="group hover:border-destructive/30 transition-colors">
              <CardHeader className="pb-2">
                <CardDescription>Failed Runs</CardDescription>
                <CardTitle className="text-3xl font-mono text-destructive">{failedRuns}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Runs with errors</div>
              </CardContent>
            </Card>
            <Card className="group hover:border-primary/30 transition-colors">
              <CardHeader className="pb-2">
                <CardDescription>Assets Discovered</CardDescription>
                <CardTitle className="text-3xl font-mono text-primary">{totalAssetsDiscovered}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xs text-muted-foreground">Total across all runs</div>
              </CardContent>
            </Card>
          </div>

          {/* Start Discovery */}
          {!status?.running && (
            <Card className="border-dashed border-2 border-primary/30 bg-gradient-to-br from-primary/5 to-transparent">
              <CardHeader>
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-xl bg-primary/20 flex items-center justify-center text-2xl">
                    🚀
                  </div>
                  <div>
                    <CardTitle>Start Discovery</CardTitle>
                    <CardDescription>
                      Discover assets from {seeds.length} configured seed{seeds.length !== 1 ? "s" : ""}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-6 md:grid-cols-2">
                  <div>
                    <label className="block text-sm font-medium mb-2">
                      Max Depth: <span className="text-primary font-mono">{maxDepth}</span>
                    </label>
                    <input
                      type="range"
                      min={1}
                      max={5}
                      value={maxDepth}
                      onChange={(e) => setMaxDepth(Number(e.target.value))}
                      className="w-full h-2 bg-muted rounded-full appearance-none cursor-pointer accent-primary"
                    />
                    <div className="flex justify-between text-xs text-muted-foreground mt-1">
                      <span>1 (shallow)</span>
                      <span>5 (deep)</span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-2">
                      Auto-Scan Threshold: <span className="text-primary font-mono">{autoScanThreshold.toFixed(2)}</span>
                    </label>
                    <input
                      type="range"
                      min={0}
                      max={1}
                      step={0.05}
                      value={autoScanThreshold}
                      onChange={(e) => setAutoScanThreshold(Number(e.target.value))}
                      className="w-full h-2 bg-muted rounded-full appearance-none cursor-pointer accent-primary"
                    />
                    <div className="flex justify-between text-xs text-muted-foreground mt-1">
                      <span>0.0 (scan all)</span>
                      <span>1.0 (high confidence only)</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center justify-between pt-4 border-t border-border">
                  <div className="text-sm text-muted-foreground">
                    Higher depth = more thorough but slower • Lower threshold = more scans
                  </div>
                  <Button
                    onClick={handleStartDiscovery}
                    disabled={starting || seeds.length === 0}
                    loading={starting}
                    size="lg"
                  >
                    Start Discovery
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Quick Add Seed */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-4">
                <div className="h-10 w-10 rounded-lg bg-success/20 flex items-center justify-center text-xl">
                  🌱
                </div>
                <div>
                  <CardTitle>Quick Add Seed</CardTitle>
                  <CardDescription>Add a new seed to start discovering assets</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3 flex-wrap md:flex-nowrap">
                <Select
                  value={seedType}
                  onChange={(e) => setSeedType(e.target.value as SeedType)}
                  className="w-full md:w-48"
                >
                  {SEED_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.icon} {t.label}
                    </option>
                  ))}
                </Select>
                <Input
                  placeholder={selectedType?.description || "Enter value"}
                  value={seedValue}
                  onChange={(e) => setSeedValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAddSeed()}
                  className="flex-1"
                />
                <Button
                  onClick={handleAddSeed}
                  disabled={!seedValue.trim() || adding}
                  loading={adding}
                >
                  Add Seed
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Seeds Tab */}
      {activeTab === "seeds" && (
        <div className="space-y-6 stagger-children">
          {/* Seed Stats */}
          <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
            <Card className="col-span-1">
              <CardHeader className="pb-2">
                <CardDescription>Total Seeds</CardDescription>
                <CardTitle className="text-2xl font-mono">{seedStats.total}</CardTitle>
              </CardHeader>
            </Card>
            {seedStats.byType.filter(t => t.count > 0).slice(0, 5).map((type) => (
              <Card key={type.value}>
                <CardHeader className="pb-2">
                  <CardDescription className="flex items-center gap-1">
                    <span>{type.icon}</span>
                    <span>{type.label}</span>
                  </CardDescription>
                  <CardTitle className="text-2xl font-mono">{type.count}</CardTitle>
                </CardHeader>
              </Card>
            ))}
          </div>

          {/* Add New Seed Form */}
          <Card>
            <CardHeader>
              <CardTitle>Add New Seed</CardTitle>
              <CardDescription>Seeds are starting points for asset discovery</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-3">
                <Select
                  label="Seed Type"
                  value={seedType}
                  onChange={(e) => setSeedType(e.target.value as SeedType)}
                >
                  {SEED_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.icon} {t.label}
                    </option>
                  ))}
                </Select>
                <Input
                  label="Value"
                  placeholder={selectedType?.description || "Enter value"}
                  value={seedValue}
                  onChange={(e) => setSeedValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAddSeed()}
                />
                <Input
                  label="Note (optional)"
                  placeholder="Add a description"
                  value={seedNote}
                  onChange={(e) => setSeedNote(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAddSeed()}
                />
              </div>
              <div className="flex gap-3">
                <Button onClick={handleAddSeed} disabled={!seedValue.trim()} loading={adding}>
                  Add Seed
                </Button>
                <Button
                  variant="outline"
                  onClick={() => { setSeedValue(""); setSeedNote(""); setError(null); }}
                  disabled={adding}
                >
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Seeds Table */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Configured Seeds ({seeds.length})</CardTitle>
                  <CardDescription>All discovery starting points</CardDescription>
                </div>
                <Button variant="outline" onClick={() => loadData(true)} disabled={refreshing}>
                  {refreshing ? "Refreshing..." : "Refresh"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="py-12 flex justify-center">
                  <LoadingSpinner size="lg" />
                </div>
              ) : seeds.length === 0 ? (
                <EmptyState
                  icon="🌱"
                  title="No seeds configured"
                  description="Add your first seed above to start discovering your attack surface"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead>Note</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {seeds.map((seed) => {
                      const typeInfo = getSeedTypeInfo(seed.seed_type);
                      return (
                        <TableRow key={seed.id}>
                          <TableCell>
                            <Badge variant="info">
                              {typeInfo?.icon} {typeInfo?.label || seed.seed_type}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-medium font-mono">{seed.value}</TableCell>
                          <TableCell className="text-muted-foreground">{seed.note || "—"}</TableCell>
                          <TableCell className="text-muted-foreground">
                            {new Date(seed.created_at).toLocaleString()}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDeleteSeed(seed.id)}
                              className="text-destructive hover:text-destructive"
                            >
                              Delete
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* History Tab */}
      {activeTab === "history" && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Discovery Run History</CardTitle>
                  <CardDescription>Past and current discovery operations</CardDescription>
                </div>
                <Button variant="outline" onClick={() => loadData(true)} disabled={refreshing}>
                  {refreshing ? "Refreshing..." : "Refresh"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="flex justify-center py-12">
                  <LoadingSpinner size="lg" />
                </div>
              ) : runs.length === 0 ? (
                <EmptyState
                  icon="📜"
                  title="No discovery runs yet"
                  description="Start your first discovery to find assets from your configured seeds"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Trigger</TableHead>
                      <TableHead>Seeds</TableHead>
                      <TableHead>Discovered</TableHead>
                      <TableHead>Updated</TableHead>
                      <TableHead>Duration</TableHead>
                      <TableHead>Started</TableHead>
                      <TableHead className="text-right">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {runs.map((run) => (
                      <TableRow 
                        key={run.id}
                        className="cursor-pointer hover:bg-muted/50"
                        onClick={() => setSelectedRun(run)}
                      >
                        <TableCell>
                          <Badge variant={STATUS_COLORS[run.status] || "secondary"}>
                            {run.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-muted-foreground">
                            {TRIGGER_LABELS[run.trigger_type] || run.trigger_type}
                          </span>
                        </TableCell>
                        <TableCell><span className="font-mono">{run.seeds_processed}</span></TableCell>
                        <TableCell><span className="font-mono text-success">{run.assets_discovered}</span></TableCell>
                        <TableCell><span className="font-mono text-info">{run.assets_updated}</span></TableCell>
                        <TableCell>
                          <span className="text-muted-foreground font-mono">
                            {formatDuration(run.started_at, run.completed_at)}
                          </span>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {run.started_at ? new Date(run.started_at).toLocaleString() : "Not started"}
                        </TableCell>
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          <Button size="sm" variant="ghost" onClick={() => setSelectedRun(run)}>
                            View →
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Run Detail Modal */}
      <Modal
        isOpen={!!selectedRun}
        onClose={() => setSelectedRun(null)}
        title="Discovery Run Details"
        size="lg"
      >
        {selectedRun && (
          <div className="space-y-6">
            <div className="flex items-start justify-between">
              <div>
                <Badge variant={STATUS_COLORS[selectedRun.status] || "secondary"} className="mb-2">
                  {selectedRun.status.toUpperCase()}
                </Badge>
                <h3 className="text-lg font-semibold">Discovery Run</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  ID: <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{selectedRun.id}</code>
                </p>
              </div>
              <div className="text-right text-sm">
                <div className="text-muted-foreground">Trigger</div>
                <div className="font-medium">{TRIGGER_LABELS[selectedRun.trigger_type] || selectedRun.trigger_type}</div>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-4 bg-muted rounded-lg text-center">
                <div className="text-2xl font-bold font-mono">{selectedRun.seeds_processed}</div>
                <div className="text-xs text-muted-foreground">Seeds Processed</div>
              </div>
              <div className="p-4 bg-success/10 rounded-lg text-center">
                <div className="text-2xl font-bold font-mono text-success">{selectedRun.assets_discovered}</div>
                <div className="text-xs text-muted-foreground">Assets Discovered</div>
              </div>
              <div className="p-4 bg-info/10 rounded-lg text-center">
                <div className="text-2xl font-bold font-mono text-info">{selectedRun.assets_updated}</div>
                <div className="text-xs text-muted-foreground">Assets Updated</div>
              </div>
              <div className="p-4 bg-muted rounded-lg text-center">
                <div className="text-2xl font-bold font-mono">
                  {formatDuration(selectedRun.started_at, selectedRun.completed_at)}
                </div>
                <div className="text-xs text-muted-foreground">Duration</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Started:</span>
                <span className="ml-2">
                  {selectedRun.started_at ? new Date(selectedRun.started_at).toLocaleString() : "Not started"}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Completed:</span>
                <span className="ml-2">
                  {selectedRun.completed_at ? new Date(selectedRun.completed_at).toLocaleString() : "In progress"}
                </span>
              </div>
            </div>

            {selectedRun.error_message && (
              <div className="p-4 bg-destructive/10 rounded-lg border border-destructive/20">
                <div className="font-medium text-destructive mb-1">Error</div>
                <div className="text-sm text-destructive/80">{selectedRun.error_message}</div>
              </div>
            )}

            {Object.keys(selectedRun.config).length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Configuration</h4>
                <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs max-h-32 font-mono">
                  {JSON.stringify(selectedRun.config, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex gap-3 pt-4 border-t">
              <Button variant="outline" onClick={() => setSelectedRun(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

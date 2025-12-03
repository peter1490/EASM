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
  listBlacklist,
  createBlacklistEntry,
  deleteBlacklistEntry,
  getBlacklistStats,
  type DiscoveryStatus,
  type DiscoveryRun,
  type Seed,
  type SeedType,
  type BlacklistEntry,
  type BlacklistCreate,
  type BlacklistStats,
  type BlacklistObjectType,
} from "@/app/api";
import { useAuth } from "@/context/AuthContext";
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
import Checkbox from "@/components/ui/Checkbox";

type TabType = "overview" | "seeds" | "history" | "blacklist";

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

const BLACKLIST_TYPE_OPTIONS: { value: BlacklistObjectType; label: string; icon: string }[] = [
  { value: "domain", label: "Domain", icon: "🌐" },
  { value: "ip", label: "IP Address", icon: "🖥️" },
  { value: "organization", label: "Organization", icon: "🏢" },
  { value: "asn", label: "ASN", icon: "🔗" },
  { value: "cidr", label: "CIDR Range", icon: "📡" },
  { value: "certificate", label: "Certificate", icon: "🔒" },
];

const BLACKLIST_BADGE_COLORS: Record<string, "info" | "warning" | "error" | "success" | "secondary"> = {
  domain: "info",
  ip: "warning",
  organization: "secondary",
  asn: "success",
  cidr: "error",
  certificate: "info",
};

export default function DiscoveryPage() {
  const { user } = useAuth();
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

  // Blacklist state
  const [blacklistEntries, setBlacklistEntries] = useState<BlacklistEntry[]>([]);
  const [blacklistStats, setBlacklistStats] = useState<BlacklistStats | null>(null);
  const [blacklistLoading, setBlacklistLoading] = useState(false);
  const [blacklistTotalCount, setBlacklistTotalCount] = useState(0);
  const [blacklistPage, setBlacklistPage] = useState(0);
  const [blacklistPageSize] = useState(25);
  const [blacklistFilterType, setBlacklistFilterType] = useState<string>("");
  const [blacklistSearchQuery, setBlacklistSearchQuery] = useState("");
  
  // Blacklist modals
  const [showBlacklistCreateModal, setShowBlacklistCreateModal] = useState(false);
  const [blacklistCreateFormData, setBlacklistCreateFormData] = useState<BlacklistCreate>({
    object_type: "domain",
    object_value: "",
    reason: "",
    delete_descendants: true,
  });
  const [blacklistCreating, setBlacklistCreating] = useState(false);
  const [blacklistCreateError, setBlacklistCreateError] = useState<string | null>(null);
  const [blacklistCreateResult, setBlacklistCreateResult] = useState<{ entry: BlacklistEntry; descendants_deleted: number } | null>(null);
  const [blacklistDeleteConfirm, setBlacklistDeleteConfirm] = useState<BlacklistEntry | null>(null);
  const [blacklistDeleting, setBlacklistDeleting] = useState(false);

  const isAdmin = user?.roles?.includes("admin");
  const isAnalyst = user?.roles?.includes("analyst") || user?.roles?.includes("operator") || isAdmin;

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

  // Blacklist functions
  const loadBlacklistData = useCallback(async () => {
    try {
      setBlacklistLoading(true);
      const [entriesData, statsData] = await Promise.all([
        listBlacklist(blacklistPageSize, blacklistPage * blacklistPageSize, blacklistFilterType || undefined, blacklistSearchQuery || undefined),
        getBlacklistStats(),
      ]);
      setBlacklistEntries(entriesData.entries);
      setBlacklistTotalCount(entriesData.total_count);
      setBlacklistStats(statsData);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBlacklistLoading(false);
    }
  }, [blacklistPage, blacklistPageSize, blacklistFilterType, blacklistSearchQuery]);

  useEffect(() => {
    if (activeTab === "blacklist") {
      loadBlacklistData();
    }
  }, [activeTab, loadBlacklistData]);

  async function handleBlacklistCreate() {
    if (!blacklistCreateFormData.object_value.trim()) {
      setBlacklistCreateError("Value is required");
      return;
    }

    setBlacklistCreating(true);
    setBlacklistCreateError(null);

    try {
      const result = await createBlacklistEntry({
        ...blacklistCreateFormData,
        object_value: blacklistCreateFormData.object_value.trim(),
        reason: blacklistCreateFormData.reason?.trim() || undefined,
      });
      setBlacklistCreateResult(result);
      loadBlacklistData();
    } catch (err) {
      setBlacklistCreateError((err as Error).message);
    } finally {
      setBlacklistCreating(false);
    }
  }

  async function handleBlacklistDelete() {
    if (!blacklistDeleteConfirm) return;

    setBlacklistDeleting(true);
    try {
      await deleteBlacklistEntry(blacklistDeleteConfirm.id);
      setBlacklistDeleteConfirm(null);
      loadBlacklistData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBlacklistDeleting(false);
    }
  }

  function closeBlacklistCreateModal() {
    setShowBlacklistCreateModal(false);
    setBlacklistCreateFormData({
      object_type: "domain",
      object_value: "",
      reason: "",
      delete_descendants: true,
    });
    setBlacklistCreateError(null);
    setBlacklistCreateResult(null);
  }

  const blacklistTotalPages = Math.ceil(blacklistTotalCount / blacklistPageSize);

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
    { id: "blacklist" as TabType, label: "Blacklist", icon: "🚫", badge: blacklistStats?.total_entries },
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
                <div key={idx} className="text-center px-4 py-3 bg-card/50 rounded-lg border border-border/50">
                  <div className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
                  <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
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
              <CardHeader className="pb-3">
                <CardDescription>Total Seeds</CardDescription>
                <CardTitle className="text-3xl font-mono">{seeds.length}</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 pb-5">
                <div className="text-xs text-muted-foreground">Configured seeds for discovery</div>
              </CardContent>
            </Card>
            <Card className="group hover:border-success/30 transition-colors">
              <CardHeader className="pb-3">
                <CardDescription>Completed Runs</CardDescription>
                <CardTitle className="text-3xl font-mono text-success">{completedRuns}</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 pb-5">
                <div className="text-xs text-muted-foreground">Successful discovery runs</div>
              </CardContent>
            </Card>
            <Card className="group hover:border-destructive/30 transition-colors">
              <CardHeader className="pb-3">
                <CardDescription>Failed Runs</CardDescription>
                <CardTitle className="text-3xl font-mono text-destructive">{failedRuns}</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 pb-5">
                <div className="text-xs text-muted-foreground">Runs with errors</div>
              </CardContent>
            </Card>
            <Card className="group hover:border-primary/30 transition-colors">
              <CardHeader className="pb-3">
                <CardDescription>Assets Discovered</CardDescription>
                <CardTitle className="text-3xl font-mono text-primary">{totalAssetsDiscovered}</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 pb-5">
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
            <CardHeader className="pb-4">
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
            <CardContent className="pb-6">
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
              <CardHeader className="pb-4">
                <CardDescription>Total Seeds</CardDescription>
                <CardTitle className="text-2xl font-mono">{seedStats.total}</CardTitle>
              </CardHeader>
            </Card>
            {seedStats.byType.filter(t => t.count > 0).slice(0, 5).map((type) => (
              <Card key={type.value}>
                <CardHeader className="pb-4">
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

      {/* Blacklist Tab */}
      {activeTab === "blacklist" && (
        <div className="space-y-6 stagger-children">
          {/* Blacklist Stats Cards */}
          {blacklistStats && (
            <div className="grid gap-4 md:grid-cols-4 lg:grid-cols-7">
              <Card className="md:col-span-1">
                <CardHeader className="pb-3">
                  <CardDescription>Total Blocked</CardDescription>
                  <CardTitle className="text-3xl font-mono">{blacklistStats.total_entries}</CardTitle>
                </CardHeader>
              </Card>
              {BLACKLIST_TYPE_OPTIONS.map((opt) => (
                <Card key={opt.value}>
                  <CardHeader className="pb-3">
                    <CardDescription className="flex items-center gap-2">
                      <span>{opt.icon}</span>
                      <span>{opt.label}s</span>
                    </CardDescription>
                    <CardTitle className="text-2xl font-mono">
                      {blacklistStats.by_type[opt.value] || 0}
                    </CardTitle>
                  </CardHeader>
                </Card>
              ))}
            </div>
          )}

          {/* Filters and Actions */}
          <Card>
            <CardContent className="!pt-6 pb-6">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 flex-1 w-full md:w-auto">
                  <Input
                    placeholder="Search values or reasons..."
                    value={blacklistSearchQuery}
                    onChange={(e) => {
                      setBlacklistSearchQuery(e.target.value);
                      setBlacklistPage(0);
                    }}
                    className="w-full sm:w-64"
                  />
                  <Select
                    value={blacklistFilterType}
                    onChange={(e) => {
                      setBlacklistFilterType(e.target.value);
                      setBlacklistPage(0);
                    }}
                    className="w-full sm:w-48"
                  >
                    <option value="">All Types</option>
                    {BLACKLIST_TYPE_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.icon} {opt.label}
                      </option>
                    ))}
                  </Select>
                </div>
                <div className="flex items-center gap-3">
                  <Button variant="outline" onClick={loadBlacklistData} disabled={blacklistLoading}>
                    {blacklistLoading ? "Refreshing..." : "Refresh"}
                  </Button>
                  {isAnalyst && (
                    <Button onClick={() => setShowBlacklistCreateModal(true)}>
                      + Add to Blacklist
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Blacklist Table */}
          <Card>
            <CardHeader>
              <CardTitle>
                Blacklisted Objects
                {blacklistTotalCount > 0 && (
                  <span className="ml-2 text-muted-foreground font-normal text-base">
                    ({blacklistTotalCount} total)
                  </span>
                )}
              </CardTitle>
              <CardDescription>
                Objects in this list are excluded from discovery. Subdomains of blacklisted domains and IPs within blacklisted CIDRs are also excluded.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {blacklistLoading && blacklistEntries.length === 0 ? (
                <div className="flex justify-center py-12">
                  <LoadingSpinner size="lg" />
                </div>
              ) : blacklistEntries.length === 0 ? (
                <EmptyState
                  icon="🚫"
                  title="No blacklist entries"
                  description={blacklistSearchQuery || blacklistFilterType ? "No entries match your filters" : "Add objects to the blacklist to exclude them from discovery"}
                  action={
                    isAnalyst ? (
                      <Button onClick={() => setShowBlacklistCreateModal(true)}>
                        Add First Entry
                      </Button>
                    ) : undefined
                  }
                />
              ) : (
                <>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Created By</TableHead>
                        <TableHead>Created At</TableHead>
                        {isAnalyst && <TableHead className="text-right">Actions</TableHead>}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {blacklistEntries.map((entry) => {
                        const typeOpt = BLACKLIST_TYPE_OPTIONS.find((o) => o.value === entry.object_type);
                        return (
                          <TableRow key={entry.id}>
                            <TableCell>
                              <Badge variant={BLACKLIST_BADGE_COLORS[entry.object_type] || "secondary"}>
                                {typeOpt?.icon} {entry.object_type}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-sm max-w-xs truncate">
                              {entry.object_value}
                            </TableCell>
                            <TableCell className="max-w-xs truncate text-muted-foreground">
                              {entry.reason || "—"}
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm">
                              {entry.created_by ? `${entry.created_by.slice(0, 20)}...` : "—"}
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                              {new Date(entry.created_at).toLocaleDateString()}
                            </TableCell>
                            {isAnalyst && (
                              <TableCell className="text-right">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => setBlacklistDeleteConfirm(entry)}
                                  className="text-destructive hover:bg-destructive/10"
                                >
                                  Remove
                                </Button>
                              </TableCell>
                            )}
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>

                  {/* Pagination */}
                  {blacklistTotalPages > 1 && (
                    <div className="flex items-center justify-between mt-6 pt-4 border-t">
                      <div className="text-sm text-muted-foreground">
                        Showing {blacklistPage * blacklistPageSize + 1} - {Math.min((blacklistPage + 1) * blacklistPageSize, blacklistTotalCount)} of{" "}
                        {blacklistTotalCount}
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setBlacklistPage((p) => Math.max(0, p - 1))}
                          disabled={blacklistPage === 0}
                        >
                          Previous
                        </Button>
                        <span className="text-sm text-muted-foreground px-2">
                          Page {blacklistPage + 1} of {blacklistTotalPages}
                        </span>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setBlacklistPage((p) => Math.min(blacklistTotalPages - 1, p + 1))}
                          disabled={blacklistPage >= blacklistTotalPages - 1}
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  )}
                </>
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

      {/* Create Blacklist Entry Modal */}
      <Modal
        isOpen={showBlacklistCreateModal}
        onClose={closeBlacklistCreateModal}
        title={blacklistCreateResult ? "Entry Created" : "Add to Blacklist"}
        size="lg"
      >
        {blacklistCreateResult ? (
          <div className="space-y-6">
            <div className="flex items-center gap-4 p-4 bg-success/10 rounded-lg border border-success/20">
              <span className="text-3xl">✅</span>
              <div>
                <div className="font-medium text-success">Successfully blacklisted</div>
                <div className="text-sm text-muted-foreground">
                  {blacklistCreateResult.entry.object_type}: {blacklistCreateResult.entry.object_value}
                </div>
              </div>
            </div>

            {blacklistCreateResult.descendants_deleted > 0 && (
              <div className="p-4 bg-warning/10 rounded-lg border border-warning/20">
                <div className="flex items-center gap-2 text-warning font-medium">
                  <span>⚠️</span>
                  <span>Cascade Deletion</span>
                </div>
                <div className="text-sm text-muted-foreground mt-1">
                  {blacklistCreateResult.descendants_deleted} descendant asset(s) were deleted from the database.
                </div>
              </div>
            )}

            <div className="flex justify-end">
              <Button onClick={closeBlacklistCreateModal}>Done</Button>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {blacklistCreateError && (
              <div className="p-3 bg-destructive/10 rounded-lg border border-destructive/20 text-destructive text-sm">
                {blacklistCreateError}
              </div>
            )}

            <div className="grid gap-4 md:grid-cols-2">
              <Select
                label="Object Type"
                value={blacklistCreateFormData.object_type}
                onChange={(e) =>
                  setBlacklistCreateFormData((prev) => ({
                    ...prev,
                    object_type: e.target.value as BlacklistObjectType,
                  }))
                }
              >
                {BLACKLIST_TYPE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.icon} {opt.label}
                  </option>
                ))}
              </Select>

              <Input
                label="Value *"
                placeholder={
                  blacklistCreateFormData.object_type === "domain"
                    ? "e.g., cloudflare.com"
                    : blacklistCreateFormData.object_type === "ip"
                    ? "e.g., 192.168.1.1"
                    : blacklistCreateFormData.object_type === "cidr"
                    ? "e.g., 10.0.0.0/8"
                    : blacklistCreateFormData.object_type === "asn"
                    ? "e.g., AS13335"
                    : blacklistCreateFormData.object_type === "organization"
                    ? "e.g., Cloudflare Inc"
                    : "Enter value..."
                }
                value={blacklistCreateFormData.object_value}
                onChange={(e) =>
                  setBlacklistCreateFormData((prev) => ({
                    ...prev,
                    object_value: e.target.value,
                  }))
                }
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Reason (optional)
              </label>
              <textarea
                className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring min-h-[80px]"
                placeholder="Why is this being blacklisted? (e.g., CDN provider, not owned by us, false positive...)"
                value={blacklistCreateFormData.reason || ""}
                onChange={(e) =>
                  setBlacklistCreateFormData((prev) => ({
                    ...prev,
                    reason: e.target.value,
                  }))
                }
              />
            </div>

            <div className="p-4 bg-muted rounded-lg">
              <Checkbox
                checked={blacklistCreateFormData.delete_descendants ?? true}
                onChange={(checked) =>
                  setBlacklistCreateFormData((prev) => ({
                    ...prev,
                    delete_descendants: checked,
                  }))
                }
                label={
                  <div>
                    <span className="font-medium">Delete descendant assets</span>
                    <p className="text-sm text-muted-foreground mt-1">
                      If checked, all assets that were discovered from this object will be deleted from the database.
                      This includes subdomains, resolved IPs, and any assets discovered via pivoting from this object.
                    </p>
                  </div>
                }
              />
            </div>

            <div className="flex justify-end gap-3 pt-4 border-t">
              <Button variant="outline" onClick={closeBlacklistCreateModal} disabled={blacklistCreating}>
                Cancel
              </Button>
              <Button
                onClick={handleBlacklistCreate}
                loading={blacklistCreating}
                disabled={!blacklistCreateFormData.object_value.trim()}
              >
                Add to Blacklist
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Blacklist Delete Confirmation Modal */}
      <Modal
        isOpen={!!blacklistDeleteConfirm}
        onClose={() => setBlacklistDeleteConfirm(null)}
        title="Remove from Blacklist"
      >
        {blacklistDeleteConfirm && (
          <div className="space-y-4">
            <p className="text-muted-foreground">
              Are you sure you want to remove this entry from the blacklist?
            </p>
            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center gap-3">
                <Badge variant={BLACKLIST_BADGE_COLORS[blacklistDeleteConfirm.object_type] || "secondary"}>
                  {blacklistDeleteConfirm.object_type}
                </Badge>
                <span className="font-mono text-sm">{blacklistDeleteConfirm.object_value}</span>
              </div>
              {blacklistDeleteConfirm.reason && (
                <div className="text-sm text-muted-foreground mt-2">
                  Reason: {blacklistDeleteConfirm.reason}
                </div>
              )}
            </div>
            <div className="p-3 bg-warning/10 rounded-lg text-warning text-sm">
              ⚠️ After removal, this object and its descendants will be discovered again in future discovery runs.
            </div>
            <div className="flex justify-end gap-3 pt-4 border-t">
              <Button variant="outline" onClick={() => setBlacklistDeleteConfirm(null)} disabled={blacklistDeleting}>
                Cancel
              </Button>
              <Button
                onClick={handleBlacklistDelete}
                loading={blacklistDeleting}
                className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
              >
                Remove from Blacklist
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

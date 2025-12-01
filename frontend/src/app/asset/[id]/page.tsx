"use client";

import Link from "next/link";
import { useEffect, useState, useCallback, useRef } from "react";
import { useParams } from "next/navigation";
import {
  getAsset,
  getAssetFindings,
  recalculateAssetRisk,
  triggerAssetScan,
  updateAssetImportance,
  listSecurityScans,
  listScans,
  updateSecurityFinding,
  resolveSecurityFinding,
  getAssetTags,
  tagAsset,
  untagAsset,
  listTags,
  type Asset,
  type SecurityFinding,
  type SecurityScan,
  type Scan,
  type FindingStatus,
  type AssetTagDetail,
  type TagWithCount,
} from "@/app/api";
import Header from "@/components/Header";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Modal from "@/components/ui/Modal";
import AssetDiscoveryGraph from "@/components/AssetDiscoveryGraph";

type TabType = "overview" | "security" | "scans" | "metadata";

const SEVERITY_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  info: "secondary",
};

const STATUS_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  open: "error",
  acknowledged: "warning",
  in_progress: "info",
  resolved: "success",
  false_positive: "secondary",
  accepted: "secondary",
};

const RISK_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  minimal: "success",
};

const SCAN_STATUS_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  pending: "secondary",
  running: "warning",
  completed: "success",
  failed: "error",
  cancelled: "secondary",
};

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id as string;
  
  const [asset, setAsset] = useState<Asset | null>(null);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [securityScans, setSecurityScans] = useState<SecurityScan[]>([]);
  const [legacyScans, setLegacyScans] = useState<Scan[]>([]);
  const [assetTags, setAssetTags] = useState<AssetTagDetail[]>([]);
  const [allTags, setAllTags] = useState<TagWithCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  
  // Action states
  const [scanning, setScanning] = useState(false);
  const [scanSuccess, setScanSuccess] = useState(false);
  const [recalculating, setRecalculating] = useState(false);
  const [updatingImportance, setUpdatingImportance] = useState(false);
  
  // Finding modal state
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [updatingFinding, setUpdatingFinding] = useState(false);

  // Tag modal state
  const [showTagModal, setShowTagModal] = useState(false);
  const [taggingInProgress, setTaggingInProgress] = useState(false);
  
  const hasInitialLoadRef = useRef(false);

  const loadData = useCallback(async (showRefreshIndicator = false) => {
    try {
      // Only show loading spinner on initial load (when no asset data yet)
      if (!hasInitialLoadRef.current) {
        setLoading(true);
      } else if (showRefreshIndicator) {
        // Only show refreshing indicator when user manually clicks refresh
        setRefreshing(true);
      }
      // For auto-refresh in background, don't change any loading states
      
      const [assetData, findingsData, securityScansData, legacyScansData, assetTagsData, allTagsData] = await Promise.all([
        getAsset(id),
        getAssetFindings(id).catch(() => []),
        listSecurityScans(50, 0, id).catch(() => []),
        listScans().catch(() => []),
        getAssetTags(id).catch(() => []),
        listTags(100, 0).catch(() => ({ tags: [], total_count: 0 })),
      ]);
      
      setAsset(assetData);
      setFindings(findingsData);
      setSecurityScans(securityScansData);
      setAssetTags(assetTagsData);
      setAllTags(allTagsData.tags);
      
      // Filter legacy scans that target this asset's value
      const relatedScans = legacyScansData.filter(
        s => s.target.toLowerCase().trim() === assetData.value.toLowerCase().trim()
      );
      setLegacyScans(relatedScans);
      
      setError(null);
      hasInitialLoadRef.current = true;
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [id]);

  useEffect(() => {
    loadData(false); // Initial load, no refresh indicator
    const interval = setInterval(() => loadData(false), 10000); // Auto-refresh silently in background
    return () => clearInterval(interval);
  }, [loadData]);

  async function handleScan() {
    if (!asset) return;
    
    setScanning(true);
    setScanSuccess(false);
    setError(null);
    
    try {
      await triggerAssetScan(asset.id, "full", `Scan initiated from asset page`);
      setScanSuccess(true);
      loadData(false); // Refresh silently - success message is already shown
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setScanning(false);
    }
  }

  async function handleRecalculateRisk() {
    if (!asset) return;
    
    setRecalculating(true);
    setError(null);
    
    try {
      const updated = await recalculateAssetRisk(asset.id);
      setAsset(updated);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRecalculating(false);
    }
  }

  async function handleImportanceChange(newImportance: number) {
    if (!asset) return;
    
    setUpdatingImportance(true);
    setError(null);
    
    try {
      const updated = await updateAssetImportance(asset.id, newImportance);
      setAsset(updated);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdatingImportance(false);
    }
  }

  async function handleFindingStatusUpdate(findingId: string, newStatus: FindingStatus) {
    setUpdatingFinding(true);
    try {
      const updated = await updateSecurityFinding(findingId, { status: newStatus });
      setFindings(prev => prev.map(f => f.id === findingId ? updated : f));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdatingFinding(false);
    }
  }

  async function handleFindingResolve(findingId: string) {
    setUpdatingFinding(true);
    try {
      const updated = await resolveSecurityFinding(findingId);
      setFindings(prev => prev.map(f => f.id === findingId ? updated : f));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdatingFinding(false);
    }
  }

  async function handleTagAsset(tagId: string) {
    if (!asset) return;
    setTaggingInProgress(true);
    try {
      await tagAsset(asset.id, tagId);
      // Refresh tags
      const updatedTags = await getAssetTags(asset.id);
      setAssetTags(updatedTags);
      setShowTagModal(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setTaggingInProgress(false);
    }
  }

  async function handleUntagAsset(tagId: string) {
    if (!asset) return;
    setTaggingInProgress(true);
    try {
      await untagAsset(asset.id, tagId);
      // Refresh tags
      const updatedTags = await getAssetTags(asset.id);
      setAssetTags(updatedTags);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setTaggingInProgress(false);
    }
  }

  // Findings stats
  const findingsStats = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
    info: findings.filter(f => f.severity === "info").length,
    open: findings.filter(f => f.status === "open").length,
  };

  const tabs: Array<{ id: TabType; label: string; icon: string; badge?: number }> = [
    { id: "overview", label: "Overview", icon: "📊" },
    { id: "security", label: "Security", icon: "🛡️", badge: findingsStats.total },
    { id: "scans", label: "Scans", icon: "🔍", badge: securityScans.length + legacyScans.length },
    { id: "metadata", label: "Metadata", icon: "📋" },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error && !asset) {
    return (
      <div className="space-y-6 animate-fade-in">
        <Header title="Asset Details" description="View asset information" />
        <Card className="border-destructive">
          <CardContent className="py-8">
            <div className="text-center">
              <div className="text-6xl mb-4">❌</div>
              <h3 className="text-lg font-semibold text-destructive mb-2">Error Loading Asset</h3>
              <p className="text-sm text-muted-foreground mb-6">{error}</p>
              <Link href="/assets">
                <Button>Back to Assets</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!asset) {
    return null;
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Link href="/assets">
              <Button variant="ghost" size="sm">← Back to Assets</Button>
            </Link>
          </div>
          <div className="flex items-center gap-4">
            <div>
              <h1 className="text-3xl font-bold font-mono">{asset.value}</h1>
              <p className="text-muted-foreground mt-1">
                Asset ID: <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{asset.id}</code>
              </p>
            </div>
            <Badge variant={asset.asset_type === "domain" ? "info" : "secondary"} className="text-sm">
              {asset.asset_type}
            </Badge>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button
            onClick={handleScan}
            disabled={scanning}
            loading={scanning}
          >
            {scanning ? "Scanning..." : "Run Security Scan"}
          </Button>
          <Button
            variant="outline"
            onClick={() => loadData(true)} // true = show refresh indicator
            disabled={refreshing}
          >
            {refreshing ? "Refreshing..." : "Refresh"}
          </Button>
        </div>
      </div>

      {/* Success/Error Messages */}
      {scanSuccess && (
        <Card className="border-success/50 bg-success/5">
          <CardContent className="py-4">
            <div className="text-success flex items-center gap-2">
              <span>✅</span>
              <span>Security scan initiated successfully! It will run in the background.</span>
            </div>
          </CardContent>
        </Card>
      )}

      {error && asset && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-4">
            <div className="text-destructive flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Quick Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5 stagger-children">
        {/* Confidence */}
        <Card className="group hover:shadow-lg transition-all">
          <CardHeader className="pb-2">
            <CardDescription>Ownership Confidence</CardDescription>
            <div className="flex items-center gap-3">
              <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all ${
                    asset.ownership_confidence >= 0.7 ? "bg-success" :
                    asset.ownership_confidence >= 0.4 ? "bg-warning" : "bg-destructive"
                  }`}
                  style={{ width: `${asset.ownership_confidence * 100}%` }}
                />
              </div>
              <CardTitle className="text-2xl font-mono">
                {(asset.ownership_confidence * 100).toFixed(0)}%
              </CardTitle>
            </div>
          </CardHeader>
        </Card>

        {/* Risk Score */}
        <Card className="group hover:shadow-lg transition-all">
          <CardHeader className="pb-2">
            <CardDescription>Risk Score</CardDescription>
            <div className="flex items-center gap-2">
              <CardTitle className={`text-3xl font-mono ${
                (asset.risk_score || 0) >= 8 ? "text-destructive" :
                (asset.risk_score || 0) >= 6 ? "text-orange-500" :
                (asset.risk_score || 0) >= 4 ? "text-warning" :
                "text-muted-foreground"
              }`}>
                {asset.risk_score?.toFixed(1) || "N/A"}
              </CardTitle>
              {asset.risk_level && (
                <Badge variant={RISK_COLORS[asset.risk_level.toLowerCase()] || "secondary"}>
                  {asset.risk_level}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRecalculateRisk}
              disabled={recalculating}
              className="text-xs"
            >
              {recalculating ? "Recalculating..." : "Recalculate Risk"}
            </Button>
          </CardContent>
        </Card>

        {/* Importance */}
        <Card className="group hover:shadow-lg transition-all">
          <CardHeader className="pb-2">
            <CardDescription>Importance</CardDescription>
            <div className="flex items-center gap-1">
              {[1, 2, 3, 4, 5].map((level) => (
                <button
                  key={level}
                  onClick={() => handleImportanceChange(level)}
                  disabled={updatingImportance}
                  className={`transition-all hover:scale-110 ${updatingImportance ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                >
                  <svg
                    className={`w-6 h-6 ${level <= asset.importance ? "text-primary" : "text-muted-foreground/30"}`}
                    viewBox="0 0 24 24"
                    fill="currentColor"
                  >
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                </button>
              ))}
              <span className="ml-2 text-lg font-mono font-semibold">{asset.importance}/5</span>
            </div>
          </CardHeader>
        </Card>

        {/* Security Findings */}
        <Card className={`group hover:shadow-lg transition-all ${findingsStats.open > 0 ? "border-l-4 border-l-warning" : ""}`}>
          <CardHeader className="pb-2">
            <CardDescription>Open Findings</CardDescription>
            <CardTitle className={`text-3xl font-mono ${findingsStats.open > 0 ? "text-warning" : "text-success"}`}>
              {findingsStats.open}
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="text-xs text-muted-foreground">
              {findingsStats.critical > 0 && <span className="text-destructive">{findingsStats.critical} critical</span>}
              {findingsStats.critical > 0 && findingsStats.high > 0 && " • "}
              {findingsStats.high > 0 && <span className="text-orange-500">{findingsStats.high} high</span>}
            </div>
          </CardContent>
        </Card>

        {/* Discovery Sources */}
        <Card className="group hover:shadow-lg transition-all">
          <CardHeader className="pb-2">
            <CardDescription>Discovery Sources</CardDescription>
            <CardTitle className="text-3xl font-mono">{asset.sources.length}</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex flex-wrap gap-1">
              {asset.sources.slice(0, 2).map((source, idx) => (
                <Badge key={idx} variant="secondary" className="text-xs">{source}</Badge>
              ))}
              {asset.sources.length > 2 && (
                <Badge variant="secondary" className="text-xs">+{asset.sources.length - 2}</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

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

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="space-y-6 stagger-children">
          {/* Asset Information */}
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Asset Information</CardTitle>
                <CardDescription>Core details about this asset</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Type</div>
                    <Badge variant={asset.asset_type === "domain" ? "info" : "secondary"}>
                      {asset.asset_type}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Status</div>
                    <Badge variant={asset.status === "active" ? "success" : "secondary"}>
                      {asset.status}
                    </Badge>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">First Seen</div>
                    <div className="text-sm">{asset.first_seen_at ? new Date(asset.first_seen_at).toLocaleString() : "—"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Last Seen</div>
                    <div className="text-sm">{asset.last_seen_at ? new Date(asset.last_seen_at).toLocaleString() : "—"}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Created</div>
                    <div className="text-sm">{new Date(asset.created_at).toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Last Updated</div>
                    <div className="text-sm">{new Date(asset.updated_at).toLocaleString()}</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Risk Assessment</CardTitle>
                <CardDescription>Current risk evaluation for this asset</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="flex-1">
                    <div className="text-sm text-muted-foreground mb-2">Risk Score</div>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
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
                      <span className="text-2xl font-bold font-mono">
                        {asset.risk_score?.toFixed(1) || "N/A"}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4 pt-2">
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Risk Level</div>
                    {asset.risk_level ? (
                      <Badge variant={RISK_COLORS[asset.risk_level.toLowerCase()] || "secondary"}>
                        {asset.risk_level}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground">Not calculated</span>
                    )}
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Last Calculated</div>
                    <div className="text-sm">
                      {asset.last_risk_run ? new Date(asset.last_risk_run).toLocaleDateString() : "Never"}
                    </div>
                  </div>
                </div>
                <div className="pt-4 border-t border-border">
                  <Button
                    variant="outline"
                    onClick={handleRecalculateRisk}
                    disabled={recalculating}
                    className="w-full"
                  >
                    {recalculating ? "Recalculating..." : "Recalculate Risk"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Discovery Sources */}
          <Card>
            <CardHeader>
              <CardTitle>Discovery Sources</CardTitle>
              <CardDescription>How this asset was discovered</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {asset.sources.map((source, idx) => (
                  <Badge key={idx} variant="secondary" className="text-sm px-3 py-1">
                    {source}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Tags */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Tags</CardTitle>
                  <CardDescription>Categorize and organize this asset</CardDescription>
                </div>
                <Button 
                  variant="outline" 
                  size="sm"
                  onClick={() => setShowTagModal(true)}
                >
                  + Add Tag
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {assetTags.length === 0 ? (
                <div className="text-sm text-muted-foreground">
                  No tags applied to this asset.{" "}
                  <button 
                    className="text-primary hover:underline"
                    onClick={() => setShowTagModal(true)}
                  >
                    Add one now
                  </button>
                </div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {assetTags.map((assetTag) => (
                    <div
                      key={assetTag.tag.id}
                      className="group inline-flex items-center gap-2 pl-3 pr-1 py-1 rounded-full text-sm font-medium text-white transition-all hover:shadow-md"
                      style={{ backgroundColor: assetTag.tag.color || "#6366f1" }}
                    >
                      <span>{assetTag.tag.name}</span>
                      {assetTag.applied_by === "auto_rule" && (
                        <span className="text-xs opacity-75" title="Auto-tagged">⚡</span>
                      )}
                      <button
                        onClick={() => handleUntagAsset(assetTag.tag.id)}
                        disabled={taggingInProgress}
                        className="w-5 h-5 rounded-full bg-black/20 hover:bg-black/40 flex items-center justify-center transition-colors opacity-0 group-hover:opacity-100"
                        title="Remove tag"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Discovery Path */}
          <Card>
            <CardHeader>
              <CardTitle>Discovery Path</CardTitle>
              <CardDescription>Visual lineage of how this asset was discovered</CardDescription>
            </CardHeader>
            <CardContent>
              <AssetDiscoveryGraph assetId={asset.id} />
            </CardContent>
          </Card>

          {/* Scan Information */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Security Scans</CardTitle>
                  <CardDescription>
                    {asset.last_scanned_at
                      ? `Last scanned on ${new Date(asset.last_scanned_at).toLocaleString()}`
                      : "This asset has never been scanned"}
                  </CardDescription>
                </div>
                <Button onClick={handleScan} disabled={scanning}>
                  {scanning ? "Scanning..." : "Run Scan"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {securityScans.length > 0 ? (
                <div className="space-y-3">
                  <div className="text-sm text-muted-foreground mb-2">Recent scans:</div>
                  {securityScans.slice(0, 3).map((scan) => (
                    <Link key={scan.id} href={`/security/scans/${scan.id}`}>
                      <div className="flex items-center justify-between p-3 rounded-lg bg-muted hover:bg-muted/80 transition-colors cursor-pointer">
                        <div className="flex items-center gap-3">
                          <Badge variant="info">{scan.scan_type}</Badge>
                          <Badge variant={SCAN_STATUS_COLORS[scan.status] || "secondary"}>
                            {scan.status}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-xs text-muted-foreground">
                            {scan.completed_at 
                              ? new Date(scan.completed_at).toLocaleDateString() 
                              : scan.started_at 
                              ? `Started ${new Date(scan.started_at).toLocaleDateString()}`
                              : "Pending"}
                          </span>
                          <span className="text-muted-foreground">→</span>
                        </div>
                      </div>
                    </Link>
                  ))}
                  {securityScans.length > 3 && (
                    <button 
                      onClick={() => setActiveTab("scans")} 
                      className="text-sm text-primary hover:underline w-full text-center py-2"
                    >
                      View all {securityScans.length} scans →
                    </button>
                  )}
                </div>
              ) : asset.last_scan_status ? (
                <div className="flex items-center gap-4">
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Status</div>
                    {asset.last_scan_id ? (
                      <Link href={`/scan/${asset.last_scan_id}`}>
                        <Badge
                          variant={SCAN_STATUS_COLORS[asset.last_scan_status] || "secondary"}
                          className="cursor-pointer hover:opacity-80"
                        >
                          {asset.last_scan_status} ↗
                        </Badge>
                      </Link>
                    ) : (
                      <Badge variant={SCAN_STATUS_COLORS[asset.last_scan_status] || "secondary"}>
                        {asset.last_scan_status}
                      </Badge>
                    )}
                  </div>
                </div>
              ) : (
                <p className="text-muted-foreground text-sm">No scans have been run for this asset yet.</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === "security" && (
        <div className="space-y-6 stagger-children">
          {/* Security Summary */}
          <div className="grid gap-4 md:grid-cols-5">
            {[
              { label: "Critical", count: findingsStats.critical, color: "bg-destructive", textColor: "text-destructive" },
              { label: "High", count: findingsStats.high, color: "bg-orange-500", textColor: "text-orange-500" },
              { label: "Medium", count: findingsStats.medium, color: "bg-warning", textColor: "text-warning" },
              { label: "Low", count: findingsStats.low, color: "bg-info", textColor: "text-info" },
              { label: "Info", count: findingsStats.info, color: "bg-secondary", textColor: "text-secondary" },
            ].map((item) => (
              <Card key={item.label} className={`border-l-4 ${item.color.replace("bg-", "border-l-")}`}>
                <CardHeader className="pb-2">
                  <CardDescription>{item.label}</CardDescription>
                  <CardTitle className={`text-3xl font-mono ${item.textColor}`}>{item.count}</CardTitle>
                </CardHeader>
              </Card>
            ))}
          </div>

          {/* Findings List */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Security Findings</CardTitle>
                  <CardDescription>{findings.length} findings for this asset</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <EmptyState
                  icon="🛡️"
                  title="No security findings"
                  description="No security issues have been detected for this asset"
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>CVSS</TableHead>
                      <TableHead>First Seen</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((finding) => (
                      <TableRow 
                        key={finding.id} 
                        className="hover:bg-muted/50 cursor-pointer"
                        onClick={() => setSelectedFinding(finding)}
                      >
                        <TableCell>
                          <Badge variant={SEVERITY_COLORS[finding.severity] || "secondary"}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium max-w-xs truncate">
                          {finding.title}
                        </TableCell>
                        <TableCell>
                          <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">
                            {finding.finding_type}
                          </code>
                        </TableCell>
                        <TableCell>
                          <Badge variant={STATUS_COLORS[finding.status] || "secondary"}>
                            {finding.status.replace("_", " ")}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {finding.cvss_score ? (
                            <span className={`font-mono ${
                              finding.cvss_score >= 7 ? "text-destructive font-semibold" :
                              finding.cvss_score >= 4 ? "text-warning" : "text-muted-foreground"
                            }`}>
                              {finding.cvss_score.toFixed(1)}
                            </span>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {new Date(finding.first_seen_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          {finding.status === "open" && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleFindingStatusUpdate(finding.id, "acknowledged")}
                              disabled={updatingFinding}
                            >
                              Acknowledge
                            </Button>
                          )}
                          {(finding.status === "acknowledged" || finding.status === "in_progress") && (
                            <Button
                              size="sm"
                              onClick={() => handleFindingResolve(finding.id)}
                              disabled={updatingFinding}
                            >
                              Resolve
                            </Button>
                          )}
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

      {activeTab === "scans" && (
        <div className="space-y-6 stagger-children">
          {/* Security Scans */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Security Scans</CardTitle>
                  <CardDescription>{securityScans.length} security scans for this asset</CardDescription>
                </div>
                <Button onClick={handleScan} disabled={scanning}>
                  {scanning ? "Scanning..." : "New Scan"}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {securityScans.length === 0 ? (
                <EmptyState
                  icon="🔍"
                  title="No security scans"
                  description="Run a security scan to check for vulnerabilities"
                  action={
                    <Button onClick={handleScan} disabled={scanning}>
                      {scanning ? "Scanning..." : "Run Security Scan"}
                    </Button>
                  }
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Scan Type</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Started</TableHead>
                      <TableHead>Completed</TableHead>
                      <TableHead>Note</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {securityScans.map((scan) => (
                      <TableRow key={scan.id} className="hover:bg-muted/50">
                        <TableCell>
                          <Badge variant="info">{scan.scan_type}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={SCAN_STATUS_COLORS[scan.status] || "secondary"}>
                            {scan.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className={`font-mono ${
                            scan.priority >= 8 ? "text-destructive font-semibold" :
                            scan.priority >= 5 ? "text-warning" : "text-muted-foreground"
                          }`}>
                            P{scan.priority}
                          </span>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}
                        </TableCell>
                        <TableCell className="text-muted-foreground max-w-xs truncate">
                          {scan.note || "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Link href={`/security/scans/${scan.id}`}>
                            <Button size="sm" variant="outline">
                              View Details
                            </Button>
                          </Link>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          {/* Legacy Scans */}
          {legacyScans.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Related Scans</CardTitle>
                <CardDescription>Legacy scans targeting this asset</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {legacyScans.map((scan) => (
                    <Link key={scan.id} href={`/scan/${scan.id}`}>
                      <div className="flex items-center justify-between p-3 rounded-lg bg-muted hover:bg-muted/80 transition-colors cursor-pointer">
                        <div className="space-y-1">
                          <div className="text-sm font-medium">{scan.target}</div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(scan.created_at).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={SCAN_STATUS_COLORS[scan.status] || "secondary"}>
                            {scan.status}
                          </Badge>
                          {scan.findings_count !== undefined && (
                            <span className="text-xs text-muted-foreground">
                              {scan.findings_count} findings
                            </span>
                          )}
                          <span className="text-muted-foreground">→</span>
                        </div>
                      </div>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {activeTab === "metadata" && (
        <div className="space-y-6 stagger-children">
          {/* IDs and References */}
          <Card>
            <CardHeader>
              <CardTitle>Asset Identifiers</CardTitle>
              <CardDescription>System identifiers and references</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Asset ID</div>
                  <code className="bg-muted px-2 py-1 rounded text-xs font-mono">{asset.id}</code>
                </div>
                {asset.seed_id && (
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Seed ID</div>
                    <code className="bg-muted px-2 py-1 rounded text-xs font-mono">{asset.seed_id}</code>
                  </div>
                )}
                {asset.parent_id && (
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Parent Asset ID</div>
                    <Link href={`/asset/${asset.parent_id}`}>
                      <code className="bg-muted px-2 py-1 rounded text-xs font-mono hover:bg-primary/20 transition-colors cursor-pointer">
                        {asset.parent_id} ↗
                      </code>
                    </Link>
                  </div>
                )}
                {asset.last_discovery_run_id && (
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Last Discovery Run</div>
                    <code className="bg-muted px-2 py-1 rounded text-xs font-mono">{asset.last_discovery_run_id}</code>
                  </div>
                )}
                {asset.discovery_method && (
                  <div>
                    <div className="text-sm text-muted-foreground mb-1">Discovery Method</div>
                    <Badge variant="secondary">{asset.discovery_method}</Badge>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Raw Metadata */}
          <Card>
            <CardHeader>
              <CardTitle>Raw Metadata</CardTitle>
              <CardDescription>Complete metadata stored for this asset</CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted rounded-lg p-4 text-xs overflow-x-auto max-h-96 overflow-y-auto font-mono">
                {JSON.stringify(asset.metadata, null, 2)}
              </pre>
            </CardContent>
          </Card>

          {/* Full Asset Object */}
          <Card>
            <CardHeader>
              <CardTitle>Complete Asset Data</CardTitle>
              <CardDescription>Full JSON representation of this asset</CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted rounded-lg p-4 text-xs overflow-x-auto max-h-96 overflow-y-auto font-mono">
                {JSON.stringify(asset, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Security Finding Detail Modal */}
      <Modal
        isOpen={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
        title="Finding Details"
        size="lg"
      >
        {selectedFinding && (
          <div className="space-y-6">
            <div className="flex items-start justify-between">
              <div>
                <Badge variant={SEVERITY_COLORS[selectedFinding.severity] || "secondary"} className="mb-2">
                  {selectedFinding.severity.toUpperCase()}
                </Badge>
                <h3 className="text-xl font-semibold">{selectedFinding.title}</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Type: <code className="bg-muted px-1.5 rounded font-mono text-xs">{selectedFinding.finding_type}</code>
                </p>
              </div>
              <div className="flex items-center gap-2">
                {selectedFinding.data?.source_url ? (
                  <a
                    href={selectedFinding.data.source_url as string}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
                    title={`View on ${selectedFinding.data.source_name || 'external source'}`}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                      <polyline points="15 3 21 3 21 9" />
                      <line x1="10" y1="14" x2="21" y2="3" />
                    </svg>
                    {(selectedFinding.data.source_name as string) || 'View Source'}
                  </a>
                ) : null}
                <Badge variant={STATUS_COLORS[selectedFinding.status] || "secondary"}>
                  {selectedFinding.status.replace("_", " ")}
                </Badge>
              </div>
            </div>

            {selectedFinding.description && (
              <div>
                <h4 className="font-medium mb-2">Description</h4>
                <p className="text-muted-foreground text-sm">{selectedFinding.description}</p>
              </div>
            )}

            {selectedFinding.remediation && (
              <div>
                <h4 className="font-medium mb-2">Remediation</h4>
                <p className="text-muted-foreground text-sm">{selectedFinding.remediation}</p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">CVSS Score:</span>
                <span className="ml-2 font-mono font-medium">{selectedFinding.cvss_score || "N/A"}</span>
              </div>
              <div>
                <span className="text-muted-foreground">First Seen:</span>
                <span className="ml-2">{new Date(selectedFinding.first_seen_at).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Last Seen:</span>
                <span className="ml-2">{new Date(selectedFinding.last_seen_at).toLocaleString()}</span>
              </div>
              {selectedFinding.resolved_at && (
                <div>
                  <span className="text-muted-foreground">Resolved At:</span>
                  <span className="ml-2">{new Date(selectedFinding.resolved_at).toLocaleString()}</span>
                </div>
              )}
            </div>

            {selectedFinding.cve_ids && selectedFinding.cve_ids.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">CVE IDs</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedFinding.cve_ids.map((cve) => (
                    <Badge key={cve} variant="secondary">{cve}</Badge>
                  ))}
                </div>
              </div>
            )}

            {selectedFinding.tags && selectedFinding.tags.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Tags</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedFinding.tags.map((tag) => (
                    <Badge key={tag} variant="info">{tag}</Badge>
                  ))}
                </div>
              </div>
            )}

            {Object.keys(selectedFinding.data).length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Technical Details</h4>
                <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs max-h-48 font-mono">
                  {JSON.stringify(selectedFinding.data, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex gap-3 pt-4 border-t flex-wrap">
              {selectedFinding.status === "open" && (
                <>
                  <Button
                    onClick={() => handleFindingStatusUpdate(selectedFinding.id, "acknowledged")}
                    disabled={updatingFinding}
                  >
                    Acknowledge
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => handleFindingStatusUpdate(selectedFinding.id, "false_positive")}
                    disabled={updatingFinding}
                  >
                    Mark as False Positive
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => handleFindingStatusUpdate(selectedFinding.id, "accepted")}
                    disabled={updatingFinding}
                  >
                    Accept Risk
                  </Button>
                </>
              )}
              {selectedFinding.status === "acknowledged" && (
                <>
                  <Button
                    onClick={() => handleFindingStatusUpdate(selectedFinding.id, "in_progress")}
                    disabled={updatingFinding}
                  >
                    Start Working
                  </Button>
                  <Button
                    onClick={() => handleFindingResolve(selectedFinding.id)}
                    disabled={updatingFinding}
                  >
                    Resolve
                  </Button>
                </>
              )}
              {selectedFinding.status === "in_progress" && (
                <Button
                  onClick={() => handleFindingResolve(selectedFinding.id)}
                  disabled={updatingFinding}
                >
                  Mark as Resolved
                </Button>
              )}
              {(selectedFinding.status === "false_positive" || selectedFinding.status === "accepted" || selectedFinding.status === "resolved") && (
                <Button
                  variant="outline"
                  onClick={() => handleFindingStatusUpdate(selectedFinding.id, "open")}
                  disabled={updatingFinding}
                >
                  Reopen
                </Button>
              )}
              <Button variant="outline" onClick={() => setSelectedFinding(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Tag Selection Modal */}
      <Modal
        isOpen={showTagModal}
        onClose={() => setShowTagModal(false)}
        title="Add Tag to Asset"
      >
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Select a tag to apply to this asset. Tags help categorize and organize your assets.
          </p>
          
          {allTags.length === 0 ? (
            <div className="py-6 text-center">
              <div className="text-4xl mb-3">🏷️</div>
              <p className="text-muted-foreground mb-3">No tags defined yet</p>
              <Link href="/tags">
                <Button variant="outline">Create Tags</Button>
              </Link>
            </div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {allTags
                .filter(tag => !assetTags.some(at => at.tag.id === tag.id))
                .map((tag) => (
                  <button
                    key={tag.id}
                    onClick={() => handleTagAsset(tag.id)}
                    disabled={taggingInProgress}
                    className="w-full flex items-center gap-3 p-3 rounded-lg border border-border hover:bg-muted transition-colors text-left disabled:opacity-50"
                  >
                    <div
                      className="w-4 h-4 rounded-full ring-2 ring-offset-2 ring-offset-background flex-shrink-0"
                      style={{ backgroundColor: tag.color || "#6366f1", ringColor: tag.color || "#6366f1" }}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="font-medium">{tag.name}</div>
                      {tag.description && (
                        <div className="text-xs text-muted-foreground truncate">{tag.description}</div>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <div className="flex items-center gap-0.5">
                        {Array.from({ length: 5 }).map((_, i) => (
                          <svg
                            key={i}
                            className={`w-3 h-3 ${i < tag.importance ? "text-primary" : "text-muted-foreground/30"}`}
                            viewBox="0 0 24 24"
                            fill="currentColor"
                          >
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                          </svg>
                        ))}
                      </div>
                      {tag.rule_type && (
                        <Badge variant="secondary" className="text-xs">
                          {tag.rule_type === "regex" ? "Regex" : "IP"}
                        </Badge>
                      )}
                    </div>
                  </button>
                ))}
              {allTags.filter(tag => !assetTags.some(at => at.tag.id === tag.id)).length === 0 && (
                <div className="py-6 text-center text-muted-foreground">
                  All available tags are already applied to this asset.
                </div>
              )}
            </div>
          )}

          <div className="flex justify-between pt-4 border-t border-border">
            <Link href="/tags">
              <Button variant="ghost" size="sm">
                Manage Tags →
              </Button>
            </Link>
            <Button variant="outline" onClick={() => setShowTagModal(false)}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}


"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import {
  searchAssetsAdvanced,
  getDiscoveryStatus,
  triggerAssetScan,
  type Asset,
  type AssetSearchParams,
  type AssetSearchResponse,
  type DiscoveryStatus,
} from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import Select from "@/components/ui/Select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Header from "@/components/Header";
import AssetDetailModal from "@/components/AssetDetailModal";
import Checkbox from "@/components/ui/Checkbox";
import Link from "next/link";

// Debounce hook
function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}

export default function AssetsPage() {
  // Search state
  const [searchQuery, setSearchQuery] = useState("");
  const [assetType, setAssetType] = useState<"all" | "domain" | "ip">("all");
  const [scanStatus, setScanStatus] = useState<"all" | "scanned" | "never_scanned">("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [minConfidence, setMinConfidence] = useState(0);
  const [sortBy, setSortBy] = useState<"created_at" | "confidence" | "value" | "importance">("created_at");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  // Pagination state
  const [limit, setLimit] = useState(25);
  const [currentPage, setCurrentPage] = useState(1);

  // Data state
  const [searchResponse, setSearchResponse] = useState<AssetSearchResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [discoveryStatus, setDiscoveryStatus] = useState<DiscoveryStatus | null>(null);

  // Selection state
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());
  const [bulkScanning, setBulkScanning] = useState(false);
  const [bulkScanMessage, setBulkScanMessage] = useState<string | null>(null);

  // Debounced search query
  const debouncedQuery = useDebounce(searchQuery, 300);
  const debouncedConfidence = useDebounce(minConfidence, 300);

  // Ref for tracking search requests
  const searchAbortController = useRef<AbortController | null>(null);

  // Search function
  const performSearch = useCallback(async (isInitial = false) => {
    // Cancel previous request
    if (searchAbortController.current) {
      searchAbortController.current.abort();
    }
    searchAbortController.current = new AbortController();

    if (!isInitial) {
      setSearching(true);
    }
    setError(null);

    try {
      const params: AssetSearchParams = {
        q: debouncedQuery || undefined,
        asset_type: assetType,
        min_confidence: debouncedConfidence > 0 ? debouncedConfidence : undefined,
        scan_status: scanStatus,
        source: sourceFilter !== "all" ? sourceFilter : undefined,
        sort_by: sortBy,
        sort_dir: sortDir,
        limit,
        offset: (currentPage - 1) * limit,
      };

      const response = await searchAssetsAdvanced(params);
      setSearchResponse(response);

      if (isInitial) {
        setLoading(false);
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        setError((e as Error).message);
      }
    } finally {
      setSearching(false);
    }
  }, [debouncedQuery, assetType, debouncedConfidence, scanStatus, sourceFilter, sortBy, sortDir, limit, currentPage]);

  // Fetch discovery status
  const fetchDiscoveryStatus = useCallback(async () => {
    try {
      const status = await getDiscoveryStatus();
      setDiscoveryStatus(status);
    } catch {
      // Ignore errors
    }
  }, []);

  // Initial load and search effect
  useEffect(() => {
    performSearch(loading);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQuery, assetType, debouncedConfidence, scanStatus, sourceFilter, sortBy, sortDir, limit, currentPage]);

  // Discovery status polling
  useEffect(() => {
    fetchDiscoveryStatus();
    const interval = setInterval(fetchDiscoveryStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchDiscoveryStatus]);

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [debouncedQuery, assetType, debouncedConfidence, scanStatus, sourceFilter, sortBy, sortDir, limit]);

  // Derived data
  const assets = searchResponse?.assets || [];
  const totalCount = searchResponse?.total_count || 0;
  const availableSources = searchResponse?.sources || [];
  const totalPages = Math.ceil(totalCount / limit);

  // Stats (from current page)
  const stats = {
    total: totalCount,
    domains: assets.filter(a => a.asset_type === "domain").length,
    ips: assets.filter(a => a.asset_type === "ip").length,
    highConfidence: assets.filter(a => a.ownership_confidence >= 0.7).length,
  };

  // Bulk scan handler
  const handleBulkScan = async () => {
    if (selectedAssets.size === 0) return;

    setBulkScanning(true);
    setBulkScanMessage(null);

    try {
      const selectedAssetList = Array.from(selectedAssets)
        .map(id => assets.find(a => a.id === id))
        .filter((a): a is Asset => !!a);

      for (const asset of selectedAssetList) {
        await triggerAssetScan(asset.id, "full", `Bulk scan from assets page`);
      }

      setBulkScanMessage(`Successfully initiated ${selectedAssetList.length} scans`);
      setSelectedAssets(new Set());
    } catch (e) {
      setBulkScanMessage(`Error: ${(e as Error).message}`);
    } finally {
      setBulkScanning(false);
    }
  };

  // Export functions
  const exportToCSV = () => {
    const headers = ["ID", "Type", "Value", "Confidence", "Sources", "Last Scanned", "Created"];
    const rows = assets.map(a => [
      a.id,
      a.asset_type,
      a.value,
      a.ownership_confidence.toFixed(2),
      a.sources.join("; "),
      a.last_scanned_at ? new Date(a.last_scanned_at).toISOString() : "Never",
      new Date(a.created_at).toISOString()
    ]);

    const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assets-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportToJSON = () => {
    const json = JSON.stringify(assets, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assets-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Selection handlers
  const toggleAssetSelection = (assetId: string) => {
    const newSelected = new Set(selectedAssets);
    if (newSelected.has(assetId)) {
      newSelected.delete(assetId);
    } else {
      newSelected.add(assetId);
    }
    setSelectedAssets(newSelected);
  };

  const toggleAllAssets = () => {
    if (selectedAssets.size === assets.length) {
      setSelectedAssets(new Set());
    } else {
      setSelectedAssets(new Set(assets.map(a => a.id)));
    }
  };

  // Clear all filters
  const clearFilters = () => {
    setSearchQuery("");
    setAssetType("all");
    setScanStatus("all");
    setSourceFilter("all");
    setMinConfidence(0);
    setSortBy("created_at");
    setSortDir("desc");
    setLimit(25);
    setCurrentPage(1);
  };

  const hasActiveFilters = searchQuery || assetType !== "all" || scanStatus !== "all" || 
    sourceFilter !== "all" || minConfidence > 0;

  return (
    <div className="space-y-6 animate-fade-in">
      <Header
        title="Asset Inventory"
        description="Search and explore your discovered attack surface"
      />

      {/* Discovery Status Banner */}
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

      {/* Main Search Card */}
      <Card className="border-primary/20 bg-gradient-to-br from-card via-card to-primary/5">
        <CardContent className="pt-6">
          {/* Search Input */}
          <div className="relative mb-6">
            <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
              <svg className="w-5 h-5 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input
              type="text"
              placeholder="Search assets by domain, IP, or source..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full h-14 pl-12 pr-4 rounded-xl border-2 border-border bg-input text-foreground text-lg
                placeholder:text-muted-foreground
                focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary
                transition-all duration-200"
            />
            {searching && (
              <div className="absolute inset-y-0 right-4 flex items-center">
                <LoadingSpinner size="sm" />
              </div>
            )}
          </div>

          {/* Filters Row */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
            <Select
              label="Asset Type"
              value={assetType}
              onChange={(e) => setAssetType(e.target.value as "all" | "domain" | "ip")}
            >
              <option value="all">All Types</option>
              <option value="domain">Domains</option>
              <option value="ip">IP Addresses</option>
            </Select>

            <Select
              label="Scan Status"
              value={scanStatus}
              onChange={(e) => setScanStatus(e.target.value as "all" | "scanned" | "never_scanned")}
            >
              <option value="all">All Status</option>
              <option value="scanned">Scanned</option>
              <option value="never_scanned">Never Scanned</option>
            </Select>

            <Select
              label="Discovery Source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <option value="all">All Sources</option>
              {availableSources.map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </Select>

            <Select
              label="Sort By"
              value={`${sortBy}-${sortDir}`}
              onChange={(e) => {
                const [field, dir] = e.target.value.split("-");
                setSortBy(field as "created_at" | "confidence" | "value" | "importance");
                setSortDir(dir as "asc" | "desc");
              }}
            >
              <option value="created_at-desc">Newest First</option>
              <option value="created_at-asc">Oldest First</option>
              <option value="confidence-desc">Highest Confidence</option>
              <option value="confidence-asc">Lowest Confidence</option>
              <option value="value-asc">Value (A-Z)</option>
              <option value="value-desc">Value (Z-A)</option>
              <option value="importance-desc">Most Important</option>
            </Select>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Min Confidence: {minConfidence.toFixed(2)}
              </label>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={minConfidence}
                onChange={(e) => setMinConfidence(Number(e.target.value))}
                className="w-full h-10 accent-primary"
              />
            </div>
          </div>

          {/* Active Filters & Results Count */}
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-border">
            <div className="flex items-center gap-3">
              <div className="text-sm text-muted-foreground">
                {searching ? (
                  <span className="flex items-center gap-2">
                    <LoadingSpinner size="sm" /> Searching...
                  </span>
                ) : (
                  <span>
                    Found <span className="font-semibold text-foreground">{totalCount.toLocaleString()}</span> assets
                    {hasActiveFilters && <span className="text-primary ml-1">(filtered)</span>}
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2">
              {hasActiveFilters && (
                <Button variant="outline" size="sm" onClick={clearFilters}>
                  Clear Filters
                </Button>
              )}
              <Select
                value={limit.toString()}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="w-20"
              >
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card className="bg-gradient-to-br from-card to-primary/5">
          <CardContent className="py-4">
            <div className="text-2xl font-bold">{totalCount.toLocaleString()}</div>
            <div className="text-sm text-muted-foreground">Total Assets</div>
          </CardContent>
        </Card>
        <Card className="bg-gradient-to-br from-card to-info/5">
          <CardContent className="py-4">
            <div className="text-2xl font-bold text-info">{stats.domains}</div>
            <div className="text-sm text-muted-foreground">Domains (this page)</div>
          </CardContent>
        </Card>
        <Card className="bg-gradient-to-br from-card to-secondary/5">
          <CardContent className="py-4">
            <div className="text-2xl font-bold text-secondary">{stats.ips}</div>
            <div className="text-sm text-muted-foreground">IPs (this page)</div>
          </CardContent>
        </Card>
        <Card className="bg-gradient-to-br from-card to-success/5">
          <CardContent className="py-4">
            <div className="text-2xl font-bold text-success">{stats.highConfidence}</div>
            <div className="text-sm text-muted-foreground">High Confidence</div>
          </CardContent>
        </Card>
      </div>

      {/* Bulk Actions */}
      {selectedAssets.size > 0 && (
        <Card className="border-primary bg-primary/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="font-medium">{selectedAssets.size} asset(s) selected</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSelectedAssets(new Set())}
                >
                  Clear Selection
                </Button>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  onClick={handleBulkScan}
                  disabled={bulkScanning}
                  size="sm"
                >
                  {bulkScanning ? "Scanning..." : `Scan ${selectedAssets.size} Asset(s)`}
                </Button>
                <Button variant="outline" size="sm" onClick={exportToCSV}>
                  Export CSV
                </Button>
                <Button variant="outline" size="sm" onClick={exportToJSON}>
                  Export JSON
                </Button>
              </div>
            </div>
            {bulkScanMessage && (
              <div className={`mt-3 p-2 rounded text-sm ${bulkScanMessage.startsWith("Error")
                ? "bg-destructive/10 text-destructive"
                : "bg-success/10 text-success"
              }`}>
                {bulkScanMessage}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Assets Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Assets</CardTitle>
              <CardDescription>
                Page {currentPage} of {totalPages || 1} • Showing {((currentPage - 1) * limit) + 1}-{Math.min(currentPage * limit, totalCount)} of {totalCount.toLocaleString()}
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={exportToCSV}>
                Export CSV
              </Button>
              <Button variant="outline" size="sm" onClick={exportToJSON}>
                Export JSON
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12 flex flex-col items-center gap-4">
              <LoadingSpinner size="lg" />
              <div className="text-muted-foreground">Loading assets...</div>
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
              {error}
            </div>
          ) : assets.length === 0 ? (
            <EmptyState
              icon="🎯"
              title="No assets found"
              description={hasActiveFilters
                ? "Try adjusting your search or filters"
                : "Start a discovery process from the Seeds page to find assets"}
            />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">
                      <Checkbox
                        checked={selectedAssets.size === assets.length && assets.length > 0}
                        onChange={toggleAllAssets}
                        indeterminate={selectedAssets.size > 0 && selectedAssets.size < assets.length}
                      />
                    </TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Sources</TableHead>
                    <TableHead>Tracking</TableHead>
                    <TableHead>Last Scan</TableHead>
                    <TableHead className="w-24">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => (
                    <TableRow
                      key={asset.id}
                      className="cursor-pointer hover:bg-muted/50 transition-colors"
                    >
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selectedAssets.has(asset.id)}
                          onChange={() => toggleAssetSelection(asset.id)}
                        />
                      </TableCell>
                      <TableCell onClick={() => setSelectedAssetId(asset.id)}>
                        <Badge variant={asset.asset_type === "domain" ? "info" : "secondary"}>
                          {asset.asset_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium font-mono" onClick={() => setSelectedAssetId(asset.id)}>
                        {asset.value}
                      </TableCell>
                      <TableCell onClick={() => setSelectedAssetId(asset.id)}>
                        <div className="flex items-center gap-2">
                          <div className="flex-1 max-w-24">
                            <div className="h-2 bg-muted rounded-full overflow-hidden">
                              <div
                                className={`h-full transition-all ${asset.ownership_confidence >= 0.7
                                  ? "bg-success"
                                  : asset.ownership_confidence >= 0.4
                                    ? "bg-warning"
                                    : "bg-destructive"
                                }`}
                                style={{ width: `${asset.ownership_confidence * 100}%` }}
                              />
                            </div>
                          </div>
                          <span className="text-sm font-medium">
                            {asset.ownership_confidence.toFixed(2)}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell onClick={() => setSelectedAssetId(asset.id)}>
                        <div className="flex flex-wrap gap-1">
                          {asset.sources.slice(0, 2).map((source, idx) => (
                            <Badge key={idx} variant="secondary">
                              {source}
                            </Badge>
                          ))}
                          {asset.sources.length > 2 && (
                            <Badge variant="secondary">+{asset.sources.length - 2}</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell onClick={() => setSelectedAssetId(asset.id)}>
                        <AssetTracking metadata={asset.metadata} />
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm" onClick={() => setSelectedAssetId(asset.id)}>
                        {asset.last_scanned_at ? (
                          <div className="space-y-1">
                            <div className="text-xs">{new Date(asset.last_scanned_at).toLocaleString()}</div>
                            {asset.last_scan_status && (
                              <div onClick={(e) => e.stopPropagation()}>
                                {asset.last_scan_id ? (
                                  <Link href={`/security/scans/${asset.last_scan_id}`}>
                                    <Badge
                                      variant={asset.last_scan_status === "completed" ? "success" : asset.last_scan_status === "failed" ? "error" : "warning"}
                                      className="cursor-pointer hover:opacity-80 transition-opacity"
                                    >
                                      {asset.last_scan_status} ↗
                                    </Badge>
                                  </Link>
                                ) : (
                                  <Badge variant={asset.last_scan_status === "completed" ? "success" : asset.last_scan_status === "failed" ? "error" : "warning"}>
                                    {asset.last_scan_status}
                                  </Badge>
                                )}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">Never scanned</span>
                        )}
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={async () => {
                            try {
                              await triggerAssetScan(asset.id, "full", `Quick scan of ${asset.value}`);
                              alert(`Security scan initiated for ${asset.value}`);
                            } catch (e) {
                              alert(`Error: ${(e as Error).message}`);
                            }
                          }}
                        >
                          Scan
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {/* Pagination */}
              <div className="mt-6 flex items-center justify-between border-t border-border pt-4">
                <div className="text-sm text-muted-foreground">
                  Page {currentPage} of {totalPages || 1} • {totalCount.toLocaleString()} total assets
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(1)}
                    disabled={currentPage === 1}
                  >
                    First
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </Button>
                  <span className="px-3 py-1 bg-muted rounded-lg text-sm font-medium">
                    {currentPage}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => p + 1)}
                    disabled={currentPage >= totalPages}
                  >
                    Next
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(totalPages)}
                    disabled={currentPage >= totalPages}
                  >
                    Last
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Asset Detail Modal */}
      <AssetDetailModal
        assetId={selectedAssetId}
        onClose={() => setSelectedAssetId(null)}
      />
    </div>
  );
}

function AssetTracking({ metadata }: { metadata: Record<string, unknown> }) {
  const raw: unknown = (metadata && typeof metadata === "object")
    ? (metadata as Record<string, unknown>)["origin_path"]
    : undefined;
  const path: string[] = Array.isArray(raw)
    ? (raw.filter((x): x is string => typeof x === "string"))
    : [];

  if (path.length === 0) return <span className="text-muted-foreground">—</span>;

  const labels = path.map((step) => {
    const s = String(step);
    if (s.startsWith("seed:")) return { text: s.replace(/^seed:/, ""), type: "seed" };
    if (s.startsWith("organization:")) return { text: s.replace(/^organization:/, ""), type: "org" };
    if (s.startsWith("asset:")) return { text: s.replace(/^asset:/, ""), type: "asset" };
    return { text: s, type: "default" };
  });

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {labels.map((label, idx) => (
        <div key={idx} className="flex items-center gap-1.5">
          <Badge variant="secondary" className="text-xs">
            {label.text}
          </Badge>
          {idx < labels.length - 1 && (
            <span className="text-muted-foreground">→</span>
          )}
        </div>
      ))}
    </div>
  );
}

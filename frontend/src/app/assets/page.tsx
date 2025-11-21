"use client";

import { useEffect, useState, useMemo } from "react";
import { getDiscoveryStatus, listAssets, type Asset, type AssetListResponse, type DiscoveryStatus, createScan } from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import Input from "@/components/ui/Input";
import Select from "@/components/ui/Select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Header from "@/components/Header";
import AssetDetailModal from "@/components/AssetDetailModal";
import Checkbox from "@/components/ui/Checkbox";

import Link from "next/link";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [minConf, setMinConf] = useState(0);
  const [discoveryStatus, setDiscoveryStatus] = useState<DiscoveryStatus | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "domain" | "ip">("all");
  const [scanStatusFilter, setScanStatusFilter] = useState<"all" | "scanned" | "never_scanned">("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());
  const [bulkScanning, setBulkScanning] = useState(false);
  const [bulkScanMessage, setBulkScanMessage] = useState<string | null>(null);
  const [limit, setLimit] = useState(25);
  const [showLimitSelector, setShowLimitSelector] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [hasMorePages, setHasMorePages] = useState(false);
  const [totalAssets, setTotalAssets] = useState(0);

  async function refresh(conf = minConf, isInitial = false, page = currentPage) {
    try {
      const offset = (page - 1) * limit;
      const response = await listAssets(conf, limit, offset);
      const sorted = [...response.assets].sort((a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
      setAssets(sorted);
      setTotalAssets(response.total_count);

      // Check if there are more pages
      setHasMorePages(offset + response.assets.length < response.total_count);

      if (isInitial) {
        setLoading(false);
      }
    } catch (e) {
      setError((e as Error).message);
      setLoading(false);
    }
  }

  useEffect(() => {
    let mounted = true;
    let iv: NodeJS.Timeout | null = null;
    let isFirstLoad = true;

    async function tick() {
      try {
        const s = await getDiscoveryStatus();
        if (!mounted) return;
        setDiscoveryStatus(s);
      } catch {
        // ignore
      }
      try {
        await refresh(minConf, isFirstLoad, currentPage);
        isFirstLoad = false;
      } catch {
        // ignore
      }
      iv = setTimeout(tick, 2000);
    }
    tick();
    return () => {
      mounted = false;
      if (iv) clearTimeout(iv);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [minConf, limit, currentPage]);

  // Get unique sources for filter dropdown (memoized)
  const allSources = useMemo(
    () => Array.from(new Set(assets.flatMap(a => a.sources))),
    [assets]
  );

  // Filter assets based on search and type (memoized)
  const filteredAssets = useMemo(() => {
    let filtered = assets;

    // Filter by type
    if (typeFilter !== "all") {
      filtered = filtered.filter(a => a.asset_type === typeFilter);
    }

    // Filter by scan status
    if (scanStatusFilter === "scanned") {
      filtered = filtered.filter(a => a.last_scanned_at);
    } else if (scanStatusFilter === "never_scanned") {
      filtered = filtered.filter(a => !a.last_scanned_at);
    }

    // Filter by source
    if (sourceFilter !== "all") {
      filtered = filtered.filter(a => a.sources.includes(sourceFilter));
    }

    // Filter by search term
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(a =>
        a.value.toLowerCase().includes(term) ||
        a.sources.some(s => s.toLowerCase().includes(term)) ||
        a.id.toLowerCase().includes(term)
      );
    }

    return filtered;
  }, [assets, searchTerm, typeFilter, scanStatusFilter, sourceFilter]);

  // Bulk scan selected assets
  const handleBulkScan = async () => {
    if (selectedAssets.size === 0) return;

    setBulkScanning(true);
    setBulkScanMessage(null);

    try {
      const selectedAssetList = Array.from(selectedAssets)
        .map(id => assets.find(a => a.id === id))
        .filter((a): a is Asset => !!a);

      for (const asset of selectedAssetList) {
        await createScan(asset.value, `Bulk scan from assets page`);
      }

      setBulkScanMessage(`Successfully initiated ${selectedAssetList.length} scans`);
      setSelectedAssets(new Set());
    } catch (e) {
      setBulkScanMessage(`Error: ${(e as Error).message}`);
    } finally {
      setBulkScanning(false);
    }
  };

  // Export assets to CSV
  const exportToCSV = () => {
    const headers = ["ID", "Type", "Value", "Confidence", "Sources", "Last Scanned", "Created"];
    const rows = filteredAssets.map(a => [
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

  // Export assets to JSON
  const exportToJSON = () => {
    const json = JSON.stringify(filteredAssets, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assets-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Toggle asset selection
  const toggleAssetSelection = (assetId: string) => {
    const newSelected = new Set(selectedAssets);
    if (newSelected.has(assetId)) {
      newSelected.delete(assetId);
    } else {
      newSelected.add(assetId);
    }
    setSelectedAssets(newSelected);
  };

  // Toggle all assets selection
  const toggleAllAssets = () => {
    if (selectedAssets.size === filteredAssets.length) {
      setSelectedAssets(new Set());
    } else {
      setSelectedAssets(new Set(filteredAssets.map(a => a.id)));
    }
  };

  // Pagination handlers
  const goToNextPage = () => {
    if (hasMorePages) {
      setCurrentPage(prev => prev + 1);
    }
  };

  const goToPreviousPage = () => {
    if (currentPage > 1) {
      setCurrentPage(prev => prev - 1);
    }
  };

  const goToFirstPage = () => {
    setCurrentPage(1);
  };

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [minConf, typeFilter, scanStatusFilter, sourceFilter, searchTerm, limit]);

  const stats = {
    total: totalAssets,
    totalOnPage: assets.length,
    domains: assets.filter(a => a.asset_type === "domain").length,
    ips: assets.filter(a => a.asset_type === "ip").length,
    highConfidence: assets.filter(a => a.ownership_confidence >= 0.7).length,
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <Header
        title="Asset Inventory"
        description="Discovered assets from your attack surface"
      />

      {/* Discovery Status Banner */}
      {discoveryStatus?.running && (
        <Card className="border-warning bg-warning/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <LoadingSpinner size="sm" />
                <div>
                  <div className="font-medium text-warning">Discovery in Progress</div>
                  <div className="text-sm text-muted-foreground">
                    New assets will appear automatically as they are discovered
                  </div>
                </div>
              </div>
              <div className="flex gap-4 text-sm">
                <div className="text-right">
                  <div className="text-muted-foreground">Seeds Processed</div>
                  <div className="font-semibold">{discoveryStatus.seeds_processed}</div>
                </div>
                <div className="text-right">
                  <div className="text-muted-foreground">Assets Discovered</div>
                  <div className="font-semibold">{discoveryStatus.assets_discovered}</div>
                </div>
                {discoveryStatus.error_count > 0 && (
                  <div className="text-right">
                    <div className="text-muted-foreground">Errors</div>
                    <div className="font-semibold text-destructive">{discoveryStatus.error_count}</div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Total Assets</CardDescription>
            <CardTitle className="text-3xl">{stats.total.toLocaleString()}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              All discovered assets in database
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>Domains</CardDescription>
            <CardTitle className="text-3xl text-primary">{stats.domains}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Domain assets
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>IP Addresses</CardDescription>
            <CardTitle className="text-3xl text-info">{stats.ips}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              IP assets
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>High Confidence</CardDescription>
            <CardTitle className="text-3xl text-success">{stats.highConfidence}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              Confidence ≥ 0.7
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Filter Assets</CardTitle>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Showing up to:</span>
              {showLimitSelector ? (
                <div className="flex items-center gap-2">
                  <Select
                    value={limit.toString()}
                    onChange={(e) => {
                      setLimit(Number(e.target.value));
                      setShowLimitSelector(false);
                    }}
                    className="w-24"
                  >
                    <option value="10">10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="250">250</option>
                    <option value="500">500</option>
                    <option value="1000">All</option>
                  </Select>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowLimitSelector(false)}
                  >
                    Cancel
                  </Button>
                </div>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowLimitSelector(true)}
                >
                  {limit === 1000 ? "All" : limit} assets
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <Input
              label="Search"
              placeholder="Search by value, source, or ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <Select
              label="Asset Type"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value as "all" | "domain" | "ip")}
            >
              <option value="all">All Types</option>
              <option value="domain">Domains Only</option>
              <option value="ip">IPs Only</option>
            </Select>
            <Select
              label="Scan Status"
              value={scanStatusFilter}
              onChange={(e) => setScanStatusFilter(e.target.value as "all" | "scanned" | "never_scanned")}
            >
              <option value="all">All Assets</option>
              <option value="scanned">Scanned</option>
              <option value="never_scanned">Never Scanned</option>
            </Select>
            <Select
              label="Discovery Source"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <option value="all">All Sources</option>
              {allSources.map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </Select>
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Min Confidence: {minConf.toFixed(2)}
              </label>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={minConf}
                onChange={(e) => setMinConf(Number(e.target.value))}
                className="w-full h-10 accent-primary"
              />
            </div>
          </div>
        </CardContent>
      </Card>

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
              <CardTitle>Assets ({filteredAssets.length})</CardTitle>
              <CardDescription>
                Page {currentPage} of {Math.ceil(totalAssets / limit)} • {filteredAssets.length === assets.length
                  ? `Showing ${assets.length} of ${totalAssets.toLocaleString()} total assets`
                  : `Filtered to ${filteredAssets.length} from ${assets.length} assets on this page`}
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => {
                  setSearchTerm("");
                  setTypeFilter("all");
                  setScanStatusFilter("all");
                  setSourceFilter("all");
                  setMinConf(0);
                  setLimit(25);
                  setCurrentPage(1);
                }}
                disabled={!searchTerm && typeFilter === "all" && scanStatusFilter === "all" && sourceFilter === "all" && minConf === 0 && limit === 25}
              >
                Clear Filters
              </Button>
              <Button variant="outline" onClick={exportToCSV}>
                Export CSV
              </Button>
              <Button variant="outline" onClick={exportToJSON}>
                Export JSON
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : error ? (
            <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
              {error}
            </div>
          ) : filteredAssets.length === 0 ? (
            <EmptyState
              icon="🎯"
              title="No assets found"
              description={assets.length === 0
                ? "Start a discovery process from the Seeds page to find assets"
                : "Try adjusting your filters to see more assets"}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={selectedAssets.size === filteredAssets.length && filteredAssets.length > 0}
                      onChange={toggleAllAssets}
                      indeterminate={selectedAssets.size > 0 && selectedAssets.size < filteredAssets.length}
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
                {filteredAssets.map((asset) => (
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
                                <Link href={`/scan/${asset.last_scan_id}`}>
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
                            await createScan(asset.value, `Quick scan of ${asset.value}`);
                            alert(`Scan initiated for ${asset.value}`);
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
          )}

          {/* Pagination Controls */}
          {!loading && !error && filteredAssets.length > 0 && (
            <div className="mt-6 flex items-center justify-between border-t border-border pt-4">
              <div className="text-sm text-muted-foreground">
                Page {currentPage} of {Math.ceil(totalAssets / limit)} • Showing {((currentPage - 1) * limit) + 1}-{Math.min(currentPage * limit, totalAssets)} of {totalAssets.toLocaleString()} total assets
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={goToFirstPage}
                  disabled={currentPage === 1}
                >
                  First
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={goToPreviousPage}
                  disabled={currentPage === 1}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={goToNextPage}
                  disabled={!hasMorePages}
                >
                  Next
                </Button>
              </div>
            </div>
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

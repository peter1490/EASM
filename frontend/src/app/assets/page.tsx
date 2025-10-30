"use client";

import { useEffect, useState } from "react";
import { getDiscoveryStatus, listAssets, type Asset } from "@/app/api";
import Button from "@/components/ui/Button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import Input from "@/components/ui/Input";
import Select from "@/components/ui/Select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import EmptyState from "@/components/ui/EmptyState";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Header from "@/components/Header";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [filteredAssets, setFilteredAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [minConf, setMinConf] = useState(0);
  const [discoveryRunning, setDiscoveryRunning] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "domain" | "ip">("all");

  async function refresh(conf = minConf) {
    try {
      const data = await listAssets(conf);
      const sorted = [...data].sort((a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
      setAssets(sorted);
      setFilteredAssets(sorted);
      setLoading(false);
    } catch (e) {
      setError((e as Error).message);
      setLoading(false);
    }
  }

  useEffect(() => {
    let mounted = true;
    let iv: NodeJS.Timeout | null = null;
    async function tick() {
      try {
        const s = await getDiscoveryStatus();
        if (!mounted) return;
        setDiscoveryRunning(s.running);
      } catch {
        // ignore
      }
      try {
        await refresh(minConf);
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
  }, [minConf]);

  // Filter assets based on search and type
  useEffect(() => {
    let filtered = assets;
    
    // Filter by type
    if (typeFilter !== "all") {
      filtered = filtered.filter(a => a.asset_type === typeFilter);
    }
    
    // Filter by search term
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(a => 
        a.value.toLowerCase().includes(term) ||
        a.sources.some(s => s.toLowerCase().includes(term))
      );
    }
    
    setFilteredAssets(filtered);
  }, [assets, searchTerm, typeFilter]);

  const stats = {
    total: assets.length,
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
      {discoveryRunning && (
        <Card className="border-warning bg-warning/5">
          <CardContent className="py-4">
            <div className="flex items-center gap-3">
              <LoadingSpinner size="sm" />
              <div>
                <div className="font-medium text-warning">Discovery in Progress</div>
                <div className="text-sm text-muted-foreground">
                  New assets will appear automatically as they are discovered
                </div>
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
            <CardTitle className="text-3xl">{stats.total}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground">
              All discovered assets
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
          <CardTitle>Filter Assets</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <Input
              label="Search"
              placeholder="Search by value or source..."
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

      {/* Assets Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Assets ({filteredAssets.length})</CardTitle>
              <CardDescription>
                {filteredAssets.length === assets.length 
                  ? "Showing all assets" 
                  : `Filtered from ${assets.length} total assets`}
              </CardDescription>
            </div>
            <Button 
              variant="outline" 
              onClick={() => {
                setSearchTerm("");
                setTypeFilter("all");
                setMinConf(0);
              }}
              disabled={!searchTerm && typeFilter === "all" && minConf === 0}
            >
              Clear Filters
            </Button>
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
                  <TableHead>Type</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Sources</TableHead>
                  <TableHead>Tracking</TableHead>
                  <TableHead>Last Scan</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAssets.map((asset) => (
                  <TableRow key={asset.id}>
                    <TableCell>
                      <Badge variant={asset.asset_type === "domain" ? "info" : "secondary"}>
                        {asset.asset_type}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-medium font-mono">
                      {asset.value}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 max-w-24">
                          <div className="h-2 bg-muted rounded-full overflow-hidden">
                            <div
                              className={`h-full transition-all ${
                                asset.ownership_confidence >= 0.7 
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
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {asset.sources.map((source, idx) => (
                          <Badge key={idx} variant="secondary">
                            {source}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <AssetTracking metadata={asset.metadata} />
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {asset.last_scanned_at ? (
                        <div className="space-y-1">
                          <div>{new Date(asset.last_scanned_at).toLocaleString()}</div>
                          {asset.last_scan_status && (
                            <Badge variant={asset.last_scan_status === "completed" ? "success" : "warning"}>
                              {asset.last_scan_status}
                            </Badge>
                          )}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">Never scanned</span>
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

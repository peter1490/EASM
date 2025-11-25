"use client";

import { useState, useEffect } from "react";
import {
  searchAssets,
  searchFindings,
  getSearchStatus,
  reindexSearch,
  type IndexedAsset,
  type IndexedFinding,
} from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import Input from "@/components/ui/Input";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";

type SearchMode = "assets" | "findings";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [searchMode, setSearchMode] = useState<SearchMode>("assets");
  const [assetResults, setAssetResults] = useState<IndexedAsset[]>([]);
  const [findingResults, setFindingResults] = useState<IndexedFinding[]>([]);
  const [totalResults, setTotalResults] = useState(0);
  const [searchTime, setSearchTime] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchStatus, setSearchStatus] = useState<{ status: string; search_available: boolean } | null>(null);
  const [reindexing, setReindexing] = useState(false);

  async function handleSearch(e?: React.FormEvent) {
    e?.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    
    try {
      if (searchMode === "assets") {
        const result = await searchAssets(query);
        setAssetResults(result.results);
        setFindingResults([]);
        setTotalResults(result.total);
        setSearchTime(result.took);
      } else {
        const result = await searchFindings(query);
        setFindingResults(result.results);
        setAssetResults([]);
        setTotalResults(result.total);
        setSearchTime(result.took);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function checkSearchStatus() {
    try {
      const status = await getSearchStatus();
      setSearchStatus(status);
    } catch {
      setSearchStatus({ status: "error", search_available: false });
    }
  }

  async function handleReindex() {
    setReindexing(true);
    setError(null);
    try {
      await reindexSearch();
      checkSearchStatus();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReindexing(false);
    }
  }

  useEffect(() => {
    checkSearchStatus();
  }, []);

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Search" 
        description="Full-text search across assets and findings"
      />

      {/* Search Status */}
      {searchStatus && !searchStatus.search_available && (
        <Card className="border-warning/50 bg-warning/5">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-2xl">⚠️</span>
                <div>
                  <div className="font-medium text-warning">Search Service Unavailable</div>
                  <div className="text-sm text-muted-foreground mt-1">
                    Elasticsearch is not configured or not reachable. Full-text search is disabled.
                  </div>
                </div>
              </div>
              <Button variant="outline" onClick={checkSearchStatus}>
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

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

      {/* Search Box */}
      <Card className="border-primary/30 bg-gradient-to-br from-primary/5 to-transparent">
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-xl bg-primary/20 flex items-center justify-center text-2xl">
              🔎
            </div>
            <div>
              <CardTitle>Global Search</CardTitle>
              <CardDescription>
                Search for assets, domains, IPs, or findings across your entire inventory
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSearch} className="space-y-4">
            {/* Search Mode Toggle */}
            <div className="tab-list inline-flex">
              <button
                type="button"
                className={`tab-item ${searchMode === "assets" ? "active" : ""}`}
                onClick={() => setSearchMode("assets")}
              >
                🎯 Assets
              </button>
              <button
                type="button"
                className={`tab-item ${searchMode === "findings" ? "active" : ""}`}
                onClick={() => setSearchMode("findings")}
              >
                🔍 Findings
              </button>
            </div>

            {/* Search Input */}
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  placeholder={searchMode === "assets" 
                    ? "Search domains, IPs, organizations..." 
                    : "Search finding types, descriptions..."}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  className="h-12 text-base"
                />
              </div>
              <Button type="submit" disabled={loading || !query.trim()} size="lg">
                {loading ? "Searching..." : "Search"}
              </Button>
            </div>

            {/* Search Tips */}
            <div className="text-sm text-muted-foreground p-3 bg-muted/50 rounded-lg">
              <strong className="text-foreground">Tips:</strong> Use wildcards (*) for partial matches. 
              Search by domain (example.com), IP (1.2.3.4), or any keyword.
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Search Results */}
      {(assetResults.length > 0 || findingResults.length > 0) && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>
                  {searchMode === "assets" ? "Asset" : "Finding"} Results
                </CardTitle>
                <CardDescription>
                  Found <span className="font-mono text-foreground">{totalResults}</span> result{totalResults !== 1 ? "s" : ""} in <span className="font-mono text-foreground">{searchTime}ms</span>
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {searchMode === "assets" ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Identifier</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Sources</TableHead>
                    <TableHead>Discovered</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assetResults.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell>
                        <Badge variant={asset.asset_type === "domain" ? "info" : "secondary"}>
                          {asset.asset_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono">{asset.identifier}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="w-16 h-2.5 bg-muted rounded-full overflow-hidden">
                            <div 
                              className={`h-full ${
                                asset.confidence >= 0.7 ? "bg-success" :
                                asset.confidence >= 0.4 ? "bg-warning" : "bg-destructive"
                              }`}
                              style={{ width: `${asset.confidence * 100}%` }}
                            />
                          </div>
                          <span className="text-sm font-mono">{asset.confidence.toFixed(2)}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {asset.sources.slice(0, 2).map((source, idx) => (
                            <Badge key={idx} variant="secondary">{source}</Badge>
                          ))}
                          {asset.sources.length > 2 && (
                            <Badge variant="secondary">+{asset.sources.length - 2}</Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {new Date(asset.created_at).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Scan ID</TableHead>
                    <TableHead>Data Preview</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingResults.map((finding) => (
                    <TableRow key={finding.id}>
                      <TableCell>
                        <Badge variant="info">{finding.finding_type}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {finding.scan_id.slice(0, 8)}...
                      </TableCell>
                      <TableCell className="max-w-md">
                        <pre className="text-xs bg-muted p-2 rounded-lg overflow-hidden text-ellipsis font-mono">
                          {JSON.stringify(finding.data).slice(0, 100)}...
                        </pre>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {new Date(finding.created_at).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!loading && query && assetResults.length === 0 && findingResults.length === 0 && (
        <Card>
          <CardContent className="py-12">
            <EmptyState
              icon="🔎"
              title="No results found"
              description={`No ${searchMode} matching "${query}" were found. Try a different search term.`}
            />
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {loading && (
        <Card>
          <CardContent className="py-12">
            <div className="flex flex-col items-center gap-4">
              <LoadingSpinner size="lg" />
              <div className="text-muted-foreground">Searching...</div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Search Admin */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Search Administration</CardTitle>
          <CardDescription>Manage the search index</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm flex items-center gap-2">
                <span className="text-muted-foreground">Status:</span>
                <Badge variant={searchStatus?.status === "healthy" ? "success" : "warning"}>
                  {searchStatus?.status || "Unknown"}
                </Badge>
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                Reindexing will rebuild the search index from the database
              </div>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={checkSearchStatus}>
                Check Status
              </Button>
              <Button 
                variant="outline" 
                onClick={handleReindex}
                disabled={reindexing}
              >
                {reindexing ? "Reindexing..." : "Reindex All"}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

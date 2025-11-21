"use client";

import { useState, useEffect } from "react";
import { Finding, FindingFilterParams, filterFindings, FindingListResponse } from "../api";
import FindingFilterPanel from "@/components/FindingFilterPanel";
import FindingRenderer from "@/components/FindingRenderer";
import { Card } from "@/components/ui/Card";
import Button from "@/components/ui/Button";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentFilters, setCurrentFilters] = useState<FindingFilterParams>({
    limit: 50,
    offset: 0,
  });

  // Load findings
  const loadFindings = async (filters: FindingFilterParams) => {
    setLoading(true);
    setError(null);
    
    try {
      const response: FindingListResponse = await filterFindings({
        ...filters,
        limit: filters.limit || 50,
        offset: filters.offset || 0,
      });
      
      setFindings(response.findings);
      setTotalCount(response.total_count);
      setCurrentFilters(filters);
    } catch (err) {
      console.error("Failed to load findings:", err);
      setError(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  };

  // Initial load
  useEffect(() => {
    loadFindings(currentFilters);
  }, []);

  // Handle filter changes
  const handleFilterChange = (newFilters: FindingFilterParams) => {
    loadFindings({
      ...newFilters,
      limit: 50,
      offset: 0,
    });
  };

  // Handle pagination
  const handleNextPage = () => {
    const newOffset = (currentFilters.offset || 0) + (currentFilters.limit || 50);
    loadFindings({
      ...currentFilters,
      offset: newOffset,
    });
  };

  const handlePrevPage = () => {
    const newOffset = Math.max(0, (currentFilters.offset || 0) - (currentFilters.limit || 50));
    loadFindings({
      ...currentFilters,
      offset: newOffset,
    });
  };

  // Calculate pagination info
  const currentPage = Math.floor((currentFilters.offset || 0) / (currentFilters.limit || 50)) + 1;
  const totalPages = Math.ceil(totalCount / (currentFilters.limit || 50));
  const hasNextPage = (currentFilters.offset || 0) + (currentFilters.limit || 50) < totalCount;
  const hasPrevPage = (currentFilters.offset || 0) > 0;

  // Format finding type for display
  const formatFindingType = (type: string) => {
    return type.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
  };

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-foreground mb-2">Findings</h1>
        <p className="text-muted-foreground">
          Search and filter security findings from all scans
        </p>
      </div>

      {/* Filter Panel */}
      <FindingFilterPanel
        onFilterChange={handleFilterChange}
        initialFilters={currentFilters}
      />

      {/* Results Section */}
      <Card>
        <div className="p-6">
          {/* Results Header */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-foreground">Results</h2>
              {!loading && (
                <span className="text-sm text-muted-foreground">
                  ({totalCount} finding{totalCount !== 1 ? "s" : ""})
                </span>
              )}
            </div>
            
            {!loading && findings.length > 0 && (
              <Button
                onClick={() => loadFindings(currentFilters)}
                variant="outline"
                size="sm"
              >
                Refresh
              </Button>
            )}
          </div>

          {/* Loading State */}
          {loading && (
            <div className="flex justify-center py-12">
              <LoadingSpinner />
            </div>
          )}

          {/* Error State */}
          {error && !loading && (
            <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
              <p className="font-medium">Error loading findings</p>
              <p className="text-sm mt-1">{error}</p>
            </div>
          )}

          {/* Empty State */}
          {!loading && !error && findings.length === 0 && (
            <EmptyState
              title="No findings found"
              description="Try adjusting your filters or run a new scan to generate findings."
            />
          )}

          {/* Findings List */}
          {!loading && !error && findings.length > 0 && (
            <div className="space-y-4">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  className="border border-border rounded-lg p-4 hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary mb-2">
                        {formatFindingType(finding.finding_type)}
                      </span>
                      <p className="text-xs text-muted-foreground">
                        Scan ID: {finding.scan_id.slice(0, 8)}... • {new Date(finding.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  
                  {/* Finding Data */}
                  <div className="mt-3">
                    <FindingRenderer findingType={finding.finding_type} data={finding.data} />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {!loading && !error && findings.length > 0 && totalPages > 1 && (
            <div className="flex items-center justify-between mt-6 pt-6 border-t border-border">
              <div className="text-sm text-muted-foreground">
                Page {currentPage} of {totalPages}
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={handlePrevPage}
                  disabled={!hasPrevPage}
                  variant="outline"
                  size="sm"
                >
                  Previous
                </Button>
                <Button
                  onClick={handleNextPage}
                  disabled={!hasNextPage}
                  variant="outline"
                  size="sm"
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}


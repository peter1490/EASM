"use client";

import { useState, useEffect } from "react";
import { FindingFilterParams, getFindingTypes, listScans } from "@/app/api";
import Button from "./ui/Button";
import Input from "./ui/Input";
import Select from "./ui/Select";
import Checkbox from "./ui/Checkbox";
import { Card } from "./ui/Card";

export interface FindingFilterPanelProps {
  onFilterChange: (filters: FindingFilterParams) => void;
  initialFilters?: FindingFilterParams;
}

export default function FindingFilterPanel({ onFilterChange, initialFilters }: FindingFilterPanelProps) {
  // State for filter values
  const [scans, setScans] = useState<Array<{ id: string; target: string }>>([]);
  const [availableFindingTypes, setAvailableFindingTypes] = useState<string[]>([]);
  
  // Filter form state
  const [selectedTypes, setSelectedTypes] = useState<string[]>(initialFilters?.finding_types || []);
  const [selectedScans, setSelectedScans] = useState<string[]>(initialFilters?.scan_ids || []);
  const [searchText, setSearchText] = useState(initialFilters?.search_text || "");
  const [createdAfter, setCreatedAfter] = useState(initialFilters?.created_after || "");
  const [createdBefore, setCreatedBefore] = useState(initialFilters?.created_before || "");
  const [sortBy, setSortBy] = useState<"created_at" | "finding_type">(initialFilters?.sort_by || "created_at");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">(initialFilters?.sort_direction || "desc");
  
  // UI state
  const [isExpanded, setIsExpanded] = useState(false);
  const [loading, setLoading] = useState(false);

  // Load available finding types and scans
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const [types, scanList] = await Promise.all([
          getFindingTypes(),
          listScans(),
        ]);
        setAvailableFindingTypes(types);
        setScans(scanList.map(s => ({ id: s.id, target: s.target })));
      } catch (error) {
        console.error("Failed to load filter data:", error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  // Handle filter type toggle
  const toggleFindingType = (type: string) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  // Handle scan toggle
  const toggleScan = (scanId: string) => {
    setSelectedScans((prev) =>
      prev.includes(scanId) ? prev.filter((id) => id !== scanId) : [...prev, scanId]
    );
  };

  // Select/deselect all finding types
  const toggleAllTypes = () => {
    if (selectedTypes.length === availableFindingTypes.length) {
      setSelectedTypes([]);
    } else {
      setSelectedTypes(availableFindingTypes);
    }
  };

  // Apply filters
  const handleApplyFilters = () => {
    const filters: FindingFilterParams = {
      finding_types: selectedTypes.length > 0 ? selectedTypes : undefined,
      scan_ids: selectedScans.length > 0 ? selectedScans : undefined,
      search_text: searchText.trim() || undefined,
      created_after: createdAfter || undefined,
      created_before: createdBefore || undefined,
      sort_by: sortBy,
      sort_direction: sortDirection,
    };
    onFilterChange(filters);
  };

  // Reset filters
  const handleReset = () => {
    setSelectedTypes([]);
    setSelectedScans([]);
    setSearchText("");
    setCreatedAfter("");
    setCreatedBefore("");
    setSortBy("created_at");
    setSortDirection("desc");
    onFilterChange({});
  };

  // Count active filters
  const activeFilterCount = 
    (selectedTypes.length > 0 ? 1 : 0) +
    (selectedScans.length > 0 ? 1 : 0) +
    (searchText.trim() ? 1 : 0) +
    (createdAfter ? 1 : 0) +
    (createdBefore ? 1 : 0);

  return (
    <Card className="mb-6">
      <div className="p-4">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-foreground">
              Filter Findings
            </h3>
            {activeFilterCount > 0 && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary">
                {activeFilterCount} active
              </span>
            )}
          </div>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            {isExpanded ? "Collapse" : "Expand"}
          </button>
        </div>

        {/* Quick Filters (always visible) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
          <Input
            type="text"
            placeholder="Search findings..."
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleApplyFilters()}
          />
          <Select value={sortBy} onChange={(e) => setSortBy(e.target.value as "created_at" | "finding_type")}>
            <option value="created_at">Sort by Date</option>
            <option value="finding_type">Sort by Type</option>
          </Select>
          <Select value={sortDirection} onChange={(e) => setSortDirection(e.target.value as "asc" | "desc")}>
            <option value="desc">Descending</option>
            <option value="asc">Ascending</option>
          </Select>
        </div>

        {/* Expanded Filters */}
        {isExpanded && (
          <div className="space-y-4 pt-4 border-t border-border">
            {/* Date Range */}
            <div>
              <h4 className="text-sm font-medium text-foreground mb-2">Date Range</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <Input
                  type="datetime-local"
                  label="From"
                  value={createdAfter}
                  onChange={(e) => setCreatedAfter(e.target.value)}
                />
                <Input
                  type="datetime-local"
                  label="To"
                  value={createdBefore}
                  onChange={(e) => setCreatedBefore(e.target.value)}
                />
              </div>
            </div>

            {/* Finding Types */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium text-foreground">Finding Types</h4>
                <button
                  onClick={toggleAllTypes}
                  className="text-xs text-primary hover:text-primary/80 transition-colors"
                  disabled={loading || availableFindingTypes.length === 0}
                >
                  {selectedTypes.length === availableFindingTypes.length ? "Deselect All" : "Select All"}
                </button>
              </div>
              {loading ? (
                <p className="text-sm text-muted-foreground">Loading finding types...</p>
              ) : availableFindingTypes.length === 0 ? (
                <p className="text-sm text-muted-foreground">No finding types available</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-48 overflow-y-auto p-2 bg-background/50 rounded-lg border border-border">
                  {availableFindingTypes.map((type) => (
                    <Checkbox
                      key={type}
                      label={type.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                      checked={selectedTypes.includes(type)}
                      onChange={() => toggleFindingType(type)}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* Scans */}
            <div>
              <h4 className="text-sm font-medium text-foreground mb-2">Filter by Scan</h4>
              {loading ? (
                <p className="text-sm text-muted-foreground">Loading scans...</p>
              ) : scans.length === 0 ? (
                <p className="text-sm text-muted-foreground">No scans available</p>
              ) : (
                <div className="max-h-48 overflow-y-auto p-2 bg-background/50 rounded-lg border border-border">
                  <div className="space-y-2">
                    {scans.map((scan) => (
                      <Checkbox
                        key={scan.id}
                        label={`${scan.target} (${scan.id.slice(0, 8)}...)`}
                        checked={selectedScans.includes(scan.id)}
                        onChange={() => toggleScan(scan.id)}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-2 mt-4">
          <Button onClick={handleApplyFilters} variant="primary" size="sm">
            Apply Filters
          </Button>
          <Button onClick={handleReset} variant="outline" size="sm">
            Reset
          </Button>
        </div>
      </div>
    </Card>
  );
}

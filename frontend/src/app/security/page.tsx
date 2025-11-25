"use client";

import { useEffect, useState, useMemo } from "react";
import {
  listSecurityScans,
  listSecurityFindings,
  getSecurityFindingsSummary,
  updateSecurityFinding,
  resolveSecurityFinding,
  filterFindings,
  type SecurityScan,
  type SecurityFinding,
  type SecurityFindingFilter,
  type FindingStatus,
  type Finding,
} from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import Select from "@/components/ui/Select";
import Input from "@/components/ui/Input";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";
import Modal from "@/components/ui/Modal";
import FindingRenderer from "@/components/FindingRenderer";

type TabType = "findings" | "scans" | "legacy";

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

const SCAN_STATUS_COLORS: Record<string, "error" | "warning" | "info" | "secondary" | "success"> = {
  pending: "secondary",
  running: "warning",
  completed: "success",
  failed: "error",
  cancelled: "secondary",
};

export default function SecurityPage() {
  const [activeTab, setActiveTab] = useState<TabType>("findings");
  const [scans, setScans] = useState<SecurityScan[]>([]);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [legacyFindings, setLegacyFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");
  
  // Pagination
  const [offset, setOffset] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const [legacyTotalCount, setLegacyTotalCount] = useState(0);
  const limit = 25;
  
  // Finding detail modal
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [selectedLegacyFinding, setSelectedLegacyFinding] = useState<Finding | null>(null);
  const [updating, setUpdating] = useState(false);

  async function loadData() {
    try {
      setLoading(true);
      const [scansData, summaryData] = await Promise.all([
        listSecurityScans(50),
        getSecurityFindingsSummary(),
      ]);
      setScans(scansData);
      setSummary(summaryData.by_severity || {});
      
      const filter: SecurityFindingFilter = { limit, offset };
      if (severityFilter !== "all") filter.severity = severityFilter;
      if (statusFilter !== "all") filter.status = statusFilter;
      
      const findingsData = await listSecurityFindings(filter);
      setFindings(findingsData.findings);
      setTotalCount(findingsData.total_count);
      
      // Load legacy findings
      const legacyData = await filterFindings({ limit, offset: 0 });
      setLegacyFindings(legacyData.findings);
      setLegacyTotalCount(legacyData.total_count);
      
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [severityFilter, statusFilter, offset]);

  async function handleStatusUpdate(findingId: string, newStatus: FindingStatus) {
    setUpdating(true);
    try {
      const updated = await updateSecurityFinding(findingId, { status: newStatus });
      setFindings(prev => prev.map(f => f.id === findingId ? updated : f));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(false);
    }
  }

  async function handleResolve(findingId: string) {
    setUpdating(true);
    try {
      const updated = await resolveSecurityFinding(findingId);
      setFindings(prev => prev.map(f => f.id === findingId ? updated : f));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(updated);
      }
      loadData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUpdating(false);
    }
  }

  const filteredFindings = useMemo(() => {
    if (!searchTerm) return findings;
    const term = searchTerm.toLowerCase();
    return findings.filter(f =>
      f.title.toLowerCase().includes(term) ||
      f.finding_type.toLowerCase().includes(term) ||
      f.description?.toLowerCase().includes(term)
    );
  }, [findings, searchTerm]);

  const totalPages = Math.ceil(totalCount / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  // Stats from summary
  const stats = {
    critical: summary.critical || 0,
    high: summary.high || 0,
    medium: summary.medium || 0,
    low: summary.low || 0,
    info: summary.info || 0,
    total: Object.values(summary).reduce((a, b) => a + b, 0),
  };

  const formatFindingType = (type: string) => {
    return type.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
  };

  const tabs = [
    { id: "findings" as TabType, label: "Security Findings", icon: "🛡️", badge: totalCount },
    { id: "scans" as TabType, label: "Scans", icon: "🔍", badge: scans.length },
    { id: "legacy" as TabType, label: "Scan Findings", icon: "📋", badge: legacyTotalCount },
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      <Header 
        title="Security" 
        description="Security vulnerabilities and scan findings"
      />

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6 stagger-children">
        <Card className="border-l-4 border-l-destructive group hover:shadow-lg transition-shadow">
          <CardHeader className="pb-2">
            <CardDescription>Critical</CardDescription>
            <CardTitle className="text-3xl font-mono text-destructive">{stats.critical}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-orange-500 group hover:shadow-lg transition-shadow">
          <CardHeader className="pb-2">
            <CardDescription>High</CardDescription>
            <CardTitle className="text-3xl font-mono text-orange-500">{stats.high}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-warning group hover:shadow-lg transition-shadow">
          <CardHeader className="pb-2">
            <CardDescription>Medium</CardDescription>
            <CardTitle className="text-3xl font-mono text-warning">{stats.medium}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-info group hover:shadow-lg transition-shadow">
          <CardHeader className="pb-2">
            <CardDescription>Low</CardDescription>
            <CardTitle className="text-3xl font-mono text-info">{stats.low}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-secondary group hover:shadow-lg transition-shadow">
          <CardHeader className="pb-2">
            <CardDescription>Info</CardDescription>
            <CardTitle className="text-3xl font-mono text-secondary">{stats.info}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-primary group hover:shadow-lg transition-shadow">
          <CardHeader className="pb-2">
            <CardDescription>Total</CardDescription>
            <CardTitle className="text-3xl font-mono">{stats.total}</CardTitle>
          </CardHeader>
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

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <Input
              placeholder="Search title, type, description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <Select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setOffset(0); }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </Select>
            <Select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }}
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
              <option value="accepted">Accepted</option>
            </Select>
            <Button
              variant="outline"
              onClick={() => {
                setSeverityFilter("all");
                setStatusFilter("all");
                setSearchTerm("");
                setOffset(0);
              }}
            >
              Clear Filters
            </Button>
          </div>
        </CardContent>
      </Card>

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

      {/* Security Findings Tab */}
      {activeTab === "findings" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Security Findings</CardTitle>
                <CardDescription>{totalCount} findings found</CardDescription>
              </div>
              <Button variant="outline" onClick={loadData}>Refresh</Button>
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner size="lg" />
              </div>
            ) : filteredFindings.length === 0 ? (
              <EmptyState
                icon="🛡️"
                title="No findings found"
                description="No security findings match your current filters"
              />
            ) : (
              <>
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
                    {filteredFindings.map((finding) => (
                      <TableRow 
                        key={finding.id}
                        className="cursor-pointer hover:bg-muted/50"
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
                            <span className={`font-mono ${finding.cvss_score >= 7 ? "text-destructive font-semibold" : finding.cvss_score >= 4 ? "text-warning" : "text-muted-foreground"}`}>
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
                              onClick={() => handleStatusUpdate(finding.id, "acknowledged")}
                              disabled={updating}
                            >
                              Acknowledge
                            </Button>
                          )}
                          {(finding.status === "acknowledged" || finding.status === "in_progress") && (
                            <Button
                              size="sm"
                              onClick={() => handleResolve(finding.id)}
                              disabled={updating}
                            >
                              Resolve
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {totalPages > 1 && (
                  <div className="flex items-center justify-between mt-6 pt-4 border-t">
                    <div className="text-sm text-muted-foreground">
                      Page {currentPage} of {totalPages}
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={offset === 0}
                        onClick={() => setOffset(Math.max(0, offset - limit))}
                      >
                        Previous
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={offset + limit >= totalCount}
                        onClick={() => setOffset(offset + limit)}
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
      )}

      {/* Scans Tab */}
      {activeTab === "scans" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Security Scans</CardTitle>
                <CardDescription>{scans.length} scans</CardDescription>
              </div>
              <Button variant="outline" onClick={loadData}>Refresh</Button>
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner size="lg" />
              </div>
            ) : scans.length === 0 ? (
              <EmptyState
                icon="🔍"
                title="No security scans"
                description="Security scans will appear here when assets are scanned"
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scan Type</TableHead>
                    <TableHead>Asset ID</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Completed</TableHead>
                    <TableHead>Note</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>
                        <Badge variant="info">{scan.scan_type}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {scan.asset_id.slice(0, 8)}...
                      </TableCell>
                      <TableCell>
                        <Badge variant={SCAN_STATUS_COLORS[scan.status] || "secondary"}>
                          {scan.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className={`font-mono ${scan.priority >= 8 ? "text-destructive font-semibold" : scan.priority >= 5 ? "text-warning" : "text-muted-foreground"}`}>
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
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {/* Legacy Findings Tab */}
      {activeTab === "legacy" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Scan Findings</CardTitle>
                <CardDescription>
                  Legacy findings from direct scans ({legacyTotalCount} total)
                </CardDescription>
              </div>
              <Button variant="outline" onClick={loadData}>Refresh</Button>
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center py-12">
                <LoadingSpinner size="lg" />
              </div>
            ) : legacyFindings.length === 0 ? (
              <EmptyState
                icon="📋"
                title="No scan findings"
                description="Run a scan to generate findings"
              />
            ) : (
              <div className="space-y-4">
                {legacyFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="border border-border rounded-lg p-4 hover:bg-muted/30 transition-colors cursor-pointer"
                    onClick={() => setSelectedLegacyFinding(finding)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <Badge variant="info" className="mb-2">
                          {formatFindingType(finding.finding_type)}
                        </Badge>
                        <p className="text-xs text-muted-foreground">
                          Scan ID: {finding.scan_id.slice(0, 8)}... • {new Date(finding.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="mt-3">
                      <FindingRenderer findingType={finding.finding_type} data={finding.data} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
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
              <Badge variant={STATUS_COLORS[selectedFinding.status] || "secondary"}>
                {selectedFinding.status.replace("_", " ")}
              </Badge>
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
                <span className="text-muted-foreground">Asset ID:</span>
                <span className="ml-2 font-mono text-xs">{selectedFinding.asset_id.slice(0, 12)}...</span>
              </div>
              <div>
                <span className="text-muted-foreground">First Seen:</span>
                <span className="ml-2">{new Date(selectedFinding.first_seen_at).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Last Seen:</span>
                <span className="ml-2">{new Date(selectedFinding.last_seen_at).toLocaleString()}</span>
              </div>
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
                    onClick={() => handleStatusUpdate(selectedFinding.id, "acknowledged")}
                    disabled={updating}
                  >
                    Acknowledge
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => handleStatusUpdate(selectedFinding.id, "false_positive")}
                    disabled={updating}
                  >
                    Mark as False Positive
                  </Button>
                </>
              )}
              {selectedFinding.status === "acknowledged" && (
                <>
                  <Button
                    onClick={() => handleStatusUpdate(selectedFinding.id, "in_progress")}
                    disabled={updating}
                  >
                    Start Working
                  </Button>
                  <Button
                    onClick={() => handleResolve(selectedFinding.id)}
                    disabled={updating}
                  >
                    Resolve
                  </Button>
                </>
              )}
              {selectedFinding.status === "in_progress" && (
                <Button
                  onClick={() => handleResolve(selectedFinding.id)}
                  disabled={updating}
                >
                  Mark as Resolved
                </Button>
              )}
              <Button variant="outline" onClick={() => setSelectedFinding(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Legacy Finding Detail Modal */}
      <Modal
        isOpen={!!selectedLegacyFinding}
        onClose={() => setSelectedLegacyFinding(null)}
        title="Scan Finding Details"
        size="lg"
      >
        {selectedLegacyFinding && (
          <div className="space-y-6">
            <div>
              <Badge variant="info" className="mb-3">
                {formatFindingType(selectedLegacyFinding.finding_type)}
              </Badge>
              <p className="text-sm text-muted-foreground">
                Scan ID: <code className="bg-muted px-1.5 rounded font-mono text-xs">{selectedLegacyFinding.scan_id}</code>
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                Created: {new Date(selectedLegacyFinding.created_at).toLocaleString()}
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-2">Finding Data</h4>
              <div className="bg-muted rounded-lg p-4">
                <FindingRenderer findingType={selectedLegacyFinding.finding_type} data={selectedLegacyFinding.data} />
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-2">Raw Data</h4>
              <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs max-h-64 font-mono">
                {JSON.stringify(selectedLegacyFinding.data, null, 2)}
              </pre>
            </div>

            <div className="flex gap-3 pt-4 border-t">
              <Button variant="outline" onClick={() => setSelectedLegacyFinding(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

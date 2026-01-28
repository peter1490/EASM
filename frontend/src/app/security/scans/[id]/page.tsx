"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  getSecurityScan,
  type SecurityScanDetail,
} from "@/app/api";
import Header from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/Table";
import Badge from "@/components/ui/Badge";
import Button from "@/components/ui/Button";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import EmptyState from "@/components/ui/EmptyState";
import Link from "next/link";

type SeverityColor = "error" | "warning" | "info" | "secondary" | "success";

const SEVERITY_COLORS: Record<string, SeverityColor> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  info: "secondary",
};

const STATUS_COLORS: Record<string, SeverityColor> = {
  pending: "secondary",
  running: "warning",
  completed: "success",
  failed: "error",
  cancelled: "secondary",
};

// Type definitions for scan result summary
interface DetectedService {
  port: number;
  protocol: string;
  service_name: string;
  product?: string;
  version?: string;
  banner?: string;
  cpe?: string;
  confidence: number;
  is_encrypted: boolean;
  vulnerabilities: string[];
}

interface VulnerabilityResult {
  cve_id: string;
  title: string;
  severity: string;
  cvss_score?: number;
  affected_service: string;
  affected_version: string;
  exploitable: boolean;
  has_public_exploit: boolean;
  description: string;
  remediation?: string;
  references: string[];
}

interface MissingSecurityHeader {
  name: string;
  severity: string;
  description: string;
  recommendation: string;
}

interface SecurityHeadersResult {
  url: string;
  headers_present: string[];
  headers_missing: MissingSecurityHeader[];
  server_info?: string;
  is_https: boolean;
  hsts_enabled: boolean;
  hsts_max_age?: number;
  csp_present: boolean;
  csp_policy?: string;
  x_frame_options?: string;
  score: number;
}

interface TlsCertificateInfo {
  subject: string;
  issuer: string;
  organization?: string | null;
  common_name?: string | null;
  san_domains: string[];
  not_before: string;
  not_after: string;
  serial_number: string;
  signature_algorithm: string;
  public_key_type?: string | null;
  public_key_bits?: number | null;
}

interface TlsCertificateDetails {
  host: string;
  port: number;
  certificate_chain: TlsCertificateInfo[];
  error?: string | null;
}

interface DnsIssue {
  issue_type: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
}

interface DnsSecurityResult {
  domain: string;
  has_spf: boolean;
  spf_record?: string;
  spf_valid: boolean;
  spf_issues: string[];
  has_dkim: boolean;
  dkim_selectors_found: string[];
  has_dmarc: boolean;
  dmarc_record?: string;
  dmarc_policy?: string;
  dmarc_issues: string[];
  has_dnssec: boolean;
  dnssec_valid?: boolean;
  has_caa: boolean;
  caa_records: string[];
  zone_transfer_possible: boolean;
  nameservers: string[];
  issues: DnsIssue[];
}

interface ProxyDetectionResult {
  behind_proxy: boolean;
  proxy_type?: string;
  proxy_headers_found: string[];
  waf_detected: boolean;
  waf_type?: string;
  waf_signatures: string[];
  cdn_detected: boolean;
  cdn_provider?: string;
  load_balancer_detected: boolean;
  direct_ip_access: boolean;
}

interface RiskFactor {
  factor_type: string;
  name: string;
  severity: string;
  description: string;
  impact_score: number;
  data: Record<string, unknown>;
}

interface ScanResultSummary {
  open_ports?: number[];
  tls_version?: string;
  tls_certificates?: TlsCertificateDetails[];
  http_status?: number;
  findings_by_severity?: Record<string, number>;
  scan_duration_ms?: number;
  errors?: string[];
  services_detected?: DetectedService[];
  vulnerabilities_found?: VulnerabilityResult[];
  security_headers?: SecurityHeadersResult;
  dns_security?: DnsSecurityResult;
  proxy_detection?: ProxyDetectionResult;
  technology_stack?: string[];
  risk_factors?: RiskFactor[];
}

type TabType = "overview" | "services" | "vulnerabilities" | "headers" | "dns" | "tls" | "findings";

export default function SecurityScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scanDetail, setScanDetail] = useState<SecurityScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("overview");

  const loadScanDetail = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getSecurityScan(scanId);
      setScanDetail(data);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    loadScanDetail();
    
    // Auto-refresh if scan is running
    const interval = setInterval(() => {
      if (scanDetail?.scan.status === "running" || scanDetail?.scan.status === "pending") {
        loadScanDetail();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [loadScanDetail, scanDetail?.scan.status]);

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-[50vh]">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error || !scanDetail) {
    return (
      <div className="space-y-8">
        <Header title="Security Scan" description="Scan details" />
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="py-8">
            <EmptyState
              icon="⚠️"
              title="Scan Not Found"
              description={error || "The requested scan could not be found"}
            />
            <div className="flex justify-center mt-4">
              <Button onClick={() => router.push("/security")}>Back to Security</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const { scan, asset, findings } = scanDetail;
  const summary = scan.result_summary as ScanResultSummary;

  // Calculate findings stats
  const findingStats = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    total: findings.length,
  };

  const tabs = [
    { id: "overview" as TabType, label: "Overview", icon: "📊" },
    { id: "services" as TabType, label: "Services", icon: "🔌", badge: summary.services_detected?.length },
    { id: "vulnerabilities" as TabType, label: "Vulnerabilities", icon: "🛡️", badge: summary.vulnerabilities_found?.length },
    { id: "headers" as TabType, label: "Security Headers", icon: "📋" },
    { id: "dns" as TabType, label: "DNS Security", icon: "🌐" },
    { id: "tls" as TabType, label: "SSL/TLS", icon: "🔒", badge: summary.tls_certificates?.length },
    { id: "findings" as TabType, label: "All Findings", icon: "📝", badge: findings.length },
  ];

  const formatDuration = (ms?: number) => {
    if (!ms) return "N/A";
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${Math.floor(ms / 60000)}m ${((ms % 60000) / 1000).toFixed(0)}s`;
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="flex items-center justify-between">
        <Header
          title={`Security Scan: ${asset.value}`}
          description={`Scan ID: ${scan.id.slice(0, 8)}...`}
        />
        <div className="flex items-center gap-3">
          <Badge variant={STATUS_COLORS[scan.status] || "secondary"} className="text-sm px-3 py-1">
            {scan.status.toUpperCase()}
          </Badge>
          <Button variant="outline" onClick={() => router.push("/security")}>
            ← Back to Security
          </Button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-4 lg:grid-cols-7">
        <Card className="border-l-4 border-l-destructive">
          <CardHeader className="pb-2">
            <CardDescription>Critical</CardDescription>
            <CardTitle className="text-2xl font-mono text-destructive">{findingStats.critical}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-orange-500">
          <CardHeader className="pb-2">
            <CardDescription>High</CardDescription>
            <CardTitle className="text-2xl font-mono text-orange-500">{findingStats.high}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-warning">
          <CardHeader className="pb-2">
            <CardDescription>Medium</CardDescription>
            <CardTitle className="text-2xl font-mono text-warning">{findingStats.medium}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-info">
          <CardHeader className="pb-2">
            <CardDescription>Low</CardDescription>
            <CardTitle className="text-2xl font-mono text-info">{findingStats.low}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-secondary">
          <CardHeader className="pb-2">
            <CardDescription>Info</CardDescription>
            <CardTitle className="text-2xl font-mono text-secondary">{findingStats.info}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-primary">
          <CardHeader className="pb-2">
            <CardDescription>Open Ports</CardDescription>
            <CardTitle className="text-2xl font-mono">{summary.open_ports?.length || 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card className="border-l-4 border-l-primary">
          <CardHeader className="pb-2">
            <CardDescription>Duration</CardDescription>
            <CardTitle className="text-2xl font-mono">{formatDuration(summary.scan_duration_ms)}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Tab Navigation */}
      <div className="tab-list flex flex-wrap gap-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`tab-item flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
              activeTab === tab.id
                ? "bg-primary text-primary-foreground"
                : "hover:bg-muted"
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-primary/20 text-xs rounded-full font-medium">
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Scan Info */}
          <Card>
            <CardHeader>
              <CardTitle>Scan Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Asset:</span>
                  <Link href={`/asset/${asset.id}`}>
                    <p className="font-medium hover:text-primary transition-colors">{asset.value} ↗</p>
                  </Link>
                </div>
                <div>
                  <span className="text-muted-foreground">Asset Type:</span>
                  <p className="font-medium capitalize">{asset.asset_type}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Scan Type:</span>
                  <p className="font-medium capitalize">{scan.scan_type.replace(/_/g, " ")}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Trigger:</span>
                  <p className="font-medium capitalize">{scan.trigger_type}</p>
                </div>
                <div>
                  <span className="text-muted-foreground">Started:</span>
                  <p className="font-medium">
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">Completed:</span>
                  <p className="font-medium">
                    {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "—"}
                  </p>
                </div>
              </div>
              {scan.note && (
                <div className="mt-4 p-3 bg-muted rounded-lg">
                  <span className="text-muted-foreground text-sm">Note:</span>
                  <p className="mt-1">{scan.note}</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Protection Status */}
          <Card>
            <CardHeader>
              <CardTitle>Protection Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* WAF Detection */}
                <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{summary.proxy_detection?.waf_detected ? "🛡️" : "⚠️"}</span>
                    <div>
                      <p className="font-medium">Web Application Firewall</p>
                      <p className="text-sm text-muted-foreground">
                        {summary.proxy_detection?.waf_detected
                          ? summary.proxy_detection.waf_type || "Detected"
                          : "Not detected"}
                      </p>
                    </div>
                  </div>
                  <Badge variant={summary.proxy_detection?.waf_detected ? "success" : "warning"}>
                    {summary.proxy_detection?.waf_detected ? "Protected" : "Unprotected"}
                  </Badge>
                </div>

                {/* CDN Detection */}
                <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{summary.proxy_detection?.cdn_detected ? "🌐" : "📡"}</span>
                    <div>
                      <p className="font-medium">Content Delivery Network</p>
                      <p className="text-sm text-muted-foreground">
                        {summary.proxy_detection?.cdn_detected
                          ? summary.proxy_detection.cdn_provider || "Detected"
                          : "Not detected"}
                      </p>
                    </div>
                  </div>
                  <Badge variant={summary.proxy_detection?.cdn_detected ? "success" : "info"}>
                    {summary.proxy_detection?.cdn_detected ? "Using CDN" : "Direct"}
                  </Badge>
                </div>

                {/* HTTPS */}
                <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{summary.security_headers?.is_https ? "🔒" : "🔓"}</span>
                    <div>
                      <p className="font-medium">HTTPS</p>
                      <p className="text-sm text-muted-foreground">
                        {summary.security_headers?.hsts_enabled
                          ? `HSTS enabled (${summary.security_headers.hsts_max_age ? `max-age: ${summary.security_headers.hsts_max_age}` : ""})`
                          : summary.security_headers?.is_https
                          ? "HSTS not enabled"
                          : "Not using HTTPS"}
                      </p>
                    </div>
                  </div>
                  <Badge variant={summary.security_headers?.is_https ? "success" : "error"}>
                    {summary.security_headers?.is_https ? "Encrypted" : "Unencrypted"}
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Open Ports */}
          <Card>
            <CardHeader>
              <CardTitle>Open Ports ({summary.open_ports?.length || 0})</CardTitle>
            </CardHeader>
            <CardContent>
              {summary.open_ports && summary.open_ports.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {summary.open_ports.map((port) => {
                    const isSensitive = [22, 23, 3306, 5432, 3389, 6379, 27017].includes(port);
                    const isWeb = [80, 443, 8080, 8443].includes(port);
                    return (
                      <Badge
                        key={port}
                        variant={isSensitive ? "warning" : isWeb ? "success" : "secondary"}
                        className="font-mono"
                      >
                        {port}
                      </Badge>
                    );
                  })}
                </div>
              ) : (
                <p className="text-muted-foreground">No open ports detected</p>
              )}
            </CardContent>
          </Card>

          {/* Risk Factors */}
          {summary.risk_factors && summary.risk_factors.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Risk Factors ({summary.risk_factors.length})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {summary.risk_factors.map((factor, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg"
                    >
                      <Badge variant={SEVERITY_COLORS[factor.severity] || "secondary"}>
                        {factor.severity}
                      </Badge>
                      <div className="flex-1">
                        <p className="font-medium text-sm">{factor.name}</p>
                        <p className="text-xs text-muted-foreground">{factor.description}</p>
                      </div>
                      <span className="text-sm font-mono text-muted-foreground">
                        {(factor.impact_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Services Tab */}
      {activeTab === "services" && (
        <Card>
          <CardHeader>
            <CardTitle>Detected Services ({summary.services_detected?.length || 0})</CardTitle>
            <CardDescription>Services discovered during port scanning with version detection</CardDescription>
          </CardHeader>
          <CardContent>
            {summary.services_detected && summary.services_detected.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Port</TableHead>
                    <TableHead>Service</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Encrypted</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>CPE</TableHead>
                    <TableHead>Vulnerabilities</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.services_detected.map((service, idx) => (
                    <TableRow key={idx}>
                      <TableCell className="font-mono font-semibold">{service.port}</TableCell>
                      <TableCell>
                        <div>
                          <span className="font-medium">{service.service_name}</span>
                          {service.product && (
                            <p className="text-xs text-muted-foreground">{service.product}</p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {service.version || "—"}
                      </TableCell>
                      <TableCell className="uppercase text-sm">{service.protocol}</TableCell>
                      <TableCell>
                        <Badge variant={service.is_encrypted ? "success" : "warning"}>
                          {service.is_encrypted ? "Yes" : "No"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                            <div
                              className="h-full bg-primary"
                              style={{ width: `${service.confidence}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono">{service.confidence}%</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs font-mono max-w-xs truncate">
                        {service.cpe || "—"}
                      </TableCell>
                      <TableCell>
                        {service.vulnerabilities.length > 0 ? (
                          <Badge variant="error">{service.vulnerabilities.length} CVE(s)</Badge>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                icon="🔌"
                title="No services detected"
                description="No services were detected during the port scan"
              />
            )}
          </CardContent>
        </Card>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === "vulnerabilities" && (
        <Card>
          <CardHeader>
            <CardTitle>Vulnerabilities ({summary.vulnerabilities_found?.length || 0})</CardTitle>
            <CardDescription>Known CVEs detected based on service versions</CardDescription>
          </CardHeader>
          <CardContent>
            {summary.vulnerabilities_found && summary.vulnerabilities_found.length > 0 ? (
              <div className="space-y-4">
                {summary.vulnerabilities_found.map((vuln, idx) => (
                  <div
                    key={idx}
                    className="border border-border rounded-lg p-4 hover:bg-muted/30 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant={SEVERITY_COLORS[vuln.severity] || "secondary"}>
                            {vuln.severity.toUpperCase()}
                          </Badge>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono font-semibold text-primary hover:underline"
                          >
                            {vuln.cve_id} ↗
                          </a>
                          {vuln.has_public_exploit && (
                            <Badge variant="error">Public Exploit</Badge>
                          )}
                          {vuln.exploitable && (
                            <Badge variant="warning">Exploitable</Badge>
                          )}
                        </div>
                        <h4 className="font-medium">{vuln.title}</h4>
                      </div>
                      {vuln.cvss_score !== undefined && (
                        <div className="text-right">
                          <span
                            className={`text-2xl font-mono font-bold ${
                              vuln.cvss_score >= 9
                                ? "text-destructive"
                                : vuln.cvss_score >= 7
                                ? "text-orange-500"
                                : vuln.cvss_score >= 4
                                ? "text-warning"
                                : "text-info"
                            }`}
                          >
                            {vuln.cvss_score.toFixed(1)}
                          </span>
                          <p className="text-xs text-muted-foreground">CVSS Score</p>
                        </div>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">{vuln.description}</p>
                    <div className="flex items-center gap-4 text-sm">
                      <span>
                        <span className="text-muted-foreground">Affected:</span>{" "}
                        <code className="bg-muted px-1.5 py-0.5 rounded font-mono text-xs">
                          {vuln.affected_service} {vuln.affected_version}
                        </code>
                      </span>
                    </div>
                    {vuln.remediation && (
                      <div className="mt-3 p-3 bg-muted/50 rounded-lg">
                        <span className="text-xs text-muted-foreground">Remediation:</span>
                        <p className="text-sm mt-1">{vuln.remediation}</p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon="✅"
                title="No vulnerabilities detected"
                description="No known CVEs were found for the detected service versions"
              />
            )}
          </CardContent>
        </Card>
      )}

      {/* Security Headers Tab */}
      {activeTab === "headers" && (
        <div className="space-y-6">
          {summary.security_headers ? (
            <>
              {/* Headers Score */}
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle>Security Headers Score</CardTitle>
                      <CardDescription>{summary.security_headers.url}</CardDescription>
                    </div>
                    <div className="text-right">
                      <span
                        className={`text-4xl font-mono font-bold ${
                          summary.security_headers.score >= 80
                            ? "text-success"
                            : summary.security_headers.score >= 50
                            ? "text-warning"
                            : "text-destructive"
                        }`}
                      >
                        {summary.security_headers.score}
                      </span>
                      <p className="text-sm text-muted-foreground">/100</p>
                    </div>
                  </div>
                </CardHeader>
              </Card>

              <div className="grid gap-6 lg:grid-cols-2">
                {/* Present Headers */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-success">
                      ✓ Present Headers ({summary.security_headers.headers_present.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {summary.security_headers.headers_present.length > 0 ? (
                      <ul className="space-y-2">
                        {summary.security_headers.headers_present.map((header, idx) => (
                          <li key={idx} className="flex items-center gap-2 text-sm">
                            <span className="text-success">✓</span>
                            <code className="bg-muted px-2 py-1 rounded font-mono">{header}</code>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-muted-foreground">No security headers present</p>
                    )}
                  </CardContent>
                </Card>

                {/* Missing Headers */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-destructive">
                      ✗ Missing Headers ({summary.security_headers.headers_missing.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {summary.security_headers.headers_missing.length > 0 ? (
                      <div className="space-y-4">
                        {summary.security_headers.headers_missing.map((header, idx) => (
                          <div key={idx} className="border-l-2 border-destructive pl-3">
                            <div className="flex items-center gap-2 mb-1">
                              <code className="bg-muted px-2 py-0.5 rounded font-mono text-sm">
                                {header.name}
                              </code>
                              <Badge variant={SEVERITY_COLORS[header.severity] || "secondary"}>
                                {header.severity}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mb-1">
                              {header.description}
                            </p>
                            <p className="text-xs text-info">{header.recommendation}</p>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-success">All recommended security headers are present!</p>
                    )}
                  </CardContent>
                </Card>
              </div>
            </>
          ) : (
            <Card>
              <CardContent className="py-8">
                <EmptyState
                  icon="📋"
                  title="No HTTP analysis data"
                  description="HTTP security headers were not analyzed for this scan"
                />
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* DNS Security Tab */}
      {activeTab === "dns" && (
        <div className="space-y-6">
          {summary.dns_security ? (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>DNS Security for {summary.dns_security.domain}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                    {/* SPF */}
                    <div className="p-4 border border-border rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={summary.dns_security.has_spf ? "text-success" : "text-destructive"}>
                          {summary.dns_security.has_spf ? "✓" : "✗"}
                        </span>
                        <h4 className="font-medium">SPF Record</h4>
                      </div>
                      {summary.dns_security.has_spf ? (
                        <code className="text-xs bg-muted p-2 rounded block overflow-x-auto">
                          {summary.dns_security.spf_record}
                        </code>
                      ) : (
                        <p className="text-sm text-destructive">No SPF record found</p>
                      )}
                      {summary.dns_security.spf_issues.length > 0 && (
                        <ul className="mt-2 text-xs text-warning">
                          {summary.dns_security.spf_issues.map((issue, idx) => (
                            <li key={idx}>⚠ {issue}</li>
                          ))}
                        </ul>
                      )}
                    </div>

                    {/* DMARC */}
                    <div className="p-4 border border-border rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={summary.dns_security.has_dmarc ? "text-success" : "text-destructive"}>
                          {summary.dns_security.has_dmarc ? "✓" : "✗"}
                        </span>
                        <h4 className="font-medium">DMARC Record</h4>
                      </div>
                      {summary.dns_security.has_dmarc ? (
                        <>
                          <Badge variant={
                            summary.dns_security.dmarc_policy === "reject" ? "success" :
                            summary.dns_security.dmarc_policy === "quarantine" ? "warning" : "info"
                          }>
                            Policy: {summary.dns_security.dmarc_policy || "none"}
                          </Badge>
                          <code className="text-xs bg-muted p-2 rounded block overflow-x-auto mt-2">
                            {summary.dns_security.dmarc_record}
                          </code>
                        </>
                      ) : (
                        <p className="text-sm text-destructive">No DMARC record found</p>
                      )}
                      {summary.dns_security.dmarc_issues.length > 0 && (
                        <ul className="mt-2 text-xs text-warning">
                          {summary.dns_security.dmarc_issues.map((issue, idx) => (
                            <li key={idx}>⚠ {issue}</li>
                          ))}
                        </ul>
                      )}
                    </div>

                    {/* DKIM */}
                    <div className="p-4 border border-border rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={summary.dns_security.has_dkim ? "text-success" : "text-warning"}>
                          {summary.dns_security.has_dkim ? "✓" : "?"}
                        </span>
                        <h4 className="font-medium">DKIM</h4>
                      </div>
                      {summary.dns_security.has_dkim ? (
                        <p className="text-sm text-success">
                          Found {summary.dns_security.dkim_selectors_found.length} selector(s)
                        </p>
                      ) : (
                        <p className="text-sm text-muted-foreground">
                          Unable to detect DKIM (requires selector knowledge)
                        </p>
                      )}
                    </div>

                    {/* CAA */}
                    <div className="p-4 border border-border rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={summary.dns_security.has_caa ? "text-success" : "text-warning"}>
                          {summary.dns_security.has_caa ? "✓" : "✗"}
                        </span>
                        <h4 className="font-medium">CAA Records</h4>
                      </div>
                      {summary.dns_security.has_caa ? (
                        <ul className="text-xs">
                          {summary.dns_security.caa_records.map((record, idx) => (
                            <li key={idx} className="bg-muted p-1 rounded mb-1 font-mono">
                              {record}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-sm text-warning">No CAA records (any CA can issue certs)</p>
                      )}
                    </div>

                    {/* DNSSEC */}
                    <div className="p-4 border border-border rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={summary.dns_security.has_dnssec ? "text-success" : "text-warning"}>
                          {summary.dns_security.has_dnssec ? "✓" : "✗"}
                        </span>
                        <h4 className="font-medium">DNSSEC</h4>
                      </div>
                      {summary.dns_security.has_dnssec ? (
                        <Badge variant={summary.dns_security.dnssec_valid ? "success" : "error"}>
                          {summary.dns_security.dnssec_valid ? "Valid" : "Invalid"}
                        </Badge>
                      ) : (
                        <p className="text-sm text-warning">DNSSEC not enabled</p>
                      )}
                    </div>

                    {/* Nameservers */}
                    <div className="p-4 border border-border rounded-lg">
                      <h4 className="font-medium mb-2">Nameservers</h4>
                      {summary.dns_security.nameservers.length > 0 ? (
                        <ul className="text-xs font-mono">
                          {summary.dns_security.nameservers.map((ns, idx) => (
                            <li key={idx} className="bg-muted p-1 rounded mb-1">{ns}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-sm text-muted-foreground">No nameservers found</p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* DNS Issues */}
              {summary.dns_security.issues.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle>DNS Issues ({summary.dns_security.issues.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {summary.dns_security.issues.map((issue, idx) => (
                        <div key={idx} className="border-l-4 border-warning pl-4 py-2">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant={SEVERITY_COLORS[issue.severity] || "warning"}>
                              {issue.severity}
                            </Badge>
                            <span className="font-medium">{issue.title}</span>
                          </div>
                          <p className="text-sm text-muted-foreground">{issue.description}</p>
                          <p className="text-xs text-info mt-1">{issue.remediation}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card>
              <CardContent className="py-8">
                <EmptyState
                  icon="🌐"
                  title="No DNS security data"
                  description="DNS security analysis was not performed for this scan"
                />
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* SSL/TLS Tab */}
      {activeTab === "tls" && (
        <div className="space-y-6">
          {summary.tls_certificates && summary.tls_certificates.length > 0 ? (
            summary.tls_certificates.map((tls, idx) => (
              <Card key={`${tls.host}-${tls.port}-${idx}`}>
                <CardHeader>
                  <CardTitle>
                    Certificate Details • {tls.host}:{tls.port}
                  </CardTitle>
                  <CardDescription>Advanced SSL/TLS analysis results</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {tls.error && (
                    <div className="p-3 rounded-lg bg-destructive/10 text-sm text-destructive">
                      {tls.error}
                    </div>
                  )}

                  {tls.certificate_chain.length === 0 ? (
                    <EmptyState
                      icon="🔒"
                      title="No certificate data"
                      description="No TLS certificate details were collected for this scan."
                    />
                  ) : (
                    <div className="space-y-4">
                      {tls.certificate_chain.map((cert, certIdx) => (
                        <div
                          key={`${cert.serial_number}-${certIdx}`}
                          className="border border-border rounded-lg p-4 bg-muted/30"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <Badge variant={certIdx === 0 ? "success" : "secondary"}>
                                {certIdx === 0 ? "Leaf" : `Chain ${certIdx + 1}`}
                              </Badge>
                              <span className="text-sm font-medium">Serial: {cert.serial_number}</span>
                            </div>
                            <Badge variant="info">{cert.signature_algorithm}</Badge>
                          </div>
                          <div className="grid gap-3 md:grid-cols-2 text-sm">
                            <div>
                              <div className="text-muted-foreground">Subject</div>
                              <div className="font-mono text-xs break-all">{cert.subject}</div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">Issuer</div>
                              <div className="font-mono text-xs break-all">{cert.issuer}</div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">Valid From</div>
                              <div>{new Date(cert.not_before).toLocaleString()}</div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">Valid Until</div>
                              <div>{new Date(cert.not_after).toLocaleString()}</div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">Common Name</div>
                              <div>{cert.common_name || "—"}</div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">Organization</div>
                              <div>{cert.organization || "—"}</div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">Public Key</div>
                              <div>
                                {cert.public_key_type ? cert.public_key_type.toUpperCase() : "Unknown"}
                                {cert.public_key_bits ? ` • ${cert.public_key_bits} bits` : ""}
                              </div>
                            </div>
                            <div>
                              <div className="text-muted-foreground">SAN Domains</div>
                              <div className="flex flex-wrap gap-2">
                                {cert.san_domains.length > 0 ? (
                                  cert.san_domains.slice(0, 6).map((san) => (
                                    <Badge key={san} variant="secondary" className="text-xs">
                                      {san}
                                    </Badge>
                                  ))
                                ) : (
                                  <span className="text-muted-foreground">—</span>
                                )}
                                {cert.san_domains.length > 6 && (
                                  <Badge variant="secondary" className="text-xs">
                                    +{cert.san_domains.length - 6} more
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))
          ) : (
            <Card>
              <CardContent className="py-8">
                <EmptyState
                  icon="🔒"
                  title="No TLS data captured"
                  description="SSL/TLS analysis was not performed for this scan."
                />
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* All Findings Tab */}
      {activeTab === "findings" && (
        <Card>
          <CardHeader>
            <CardTitle>All Findings ({findings.length})</CardTitle>
            <CardDescription>Complete list of security findings from this scan</CardDescription>
          </CardHeader>
          <CardContent>
            {findings.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>First Seen</TableHead>
                    <TableHead>Source</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((finding) => (
                    <TableRow key={finding.id}>
                      <TableCell>
                        <Badge variant={SEVERITY_COLORS[finding.severity] || "secondary"}>
                          {finding.severity.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="max-w-md">
                          <p className="font-medium truncate">{finding.title}</p>
                          {finding.description && (
                            <p className="text-xs text-muted-foreground truncate">
                              {finding.description}
                            </p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">
                          {finding.finding_type}
                        </code>
                      </TableCell>
                      <TableCell>
                        <Badge variant={
                          finding.status === "open" ? "error" :
                          finding.status === "resolved" ? "success" : "secondary"
                        }>
                          {finding.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(finding.first_seen_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        {finding.data?.source_url ? (
                          <a
                            href={finding.data.source_url as string}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-primary hover:underline"
                          >
                            {(finding.data.source_name as string) || "View"} ↗
                          </a>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                icon="✅"
                title="No findings"
                description="No security findings were generated by this scan"
              />
            )}
          </CardContent>
        </Card>
      )}

      {/* Errors */}
      {summary.errors && summary.errors.length > 0 && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardHeader>
            <CardTitle className="text-destructive">Scan Errors</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {summary.errors.map((error, idx) => (
                <li key={idx} className="text-sm text-destructive">
                  {error}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

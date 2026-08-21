// ============================================================================
// EASM Frontend API Client
// Complete API client matching all backend endpoints
// ============================================================================

const DEFAULT_API_BASE = "http://localhost:8000";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function isLoopbackHost(hostname: string) {
  return LOOPBACK_HOSTS.has(hostname);
}

export function getApiBase() {
  const envBase = process.env.NEXT_PUBLIC_API_BASE?.trim();
  if (envBase) {
    if (typeof window !== "undefined") {
      try {
        const envUrl = new URL(envBase);
        const browserHost = window.location.hostname;
        if (isLoopbackHost(envUrl.hostname) && !isLoopbackHost(browserHost)) {
          const protocol = window.location.protocol === "https:" ? "https:" : envUrl.protocol;
          const port = envUrl.port || "8000";
          return `${protocol}//${browserHost}:${port}`;
        }
      } catch {
        // Ignore invalid env base and fall through to return envBase as-is.
      }
    }
    return envBase;
  }

  if (typeof window !== "undefined") {
    const protocol = window.location.protocol === "https:" ? "https:" : "http:";
    return `${protocol}//${window.location.hostname}:8000`;
  }

  return DEFAULT_API_BASE;
}

const API_BASE = getApiBase();
const COMPANY_STORAGE_KEY = "easm_company_id";
const CSRF_COOKIE_NAME = "csrf_token";

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const parts = document.cookie.split(";").map((part) => part.trim());
  for (const part of parts) {
    if (!part) continue;
    const [key, ...rest] = part.split("=");
    if (key === name) {
      return rest.join("=") || null;
    }
  }
  return null;
}

export function getStoredCompanyId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(COMPANY_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredCompanyId(companyId: string | null) {
  if (typeof window === "undefined") return;
  try {
    if (companyId) {
      window.localStorage.setItem(COMPANY_STORAGE_KEY, companyId);
    } else {
      window.localStorage.removeItem(COMPANY_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors (private mode, etc.)
  }
}

async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  const companyId = getStoredCompanyId();
  if (companyId) {
    headers.set("X-Company-ID", companyId);
  }
  const method = (init.method ?? "GET").toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const csrfToken = getCookie(CSRF_COOKIE_NAME);
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }
  const credentials = init.credentials ?? "include";
  return fetch(input, { ...init, headers, credentials });
}

function parseContentDispositionFilename(contentDisposition: string | null): string | null {
  if (!contentDisposition) return null;

  const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      // ignore malformed encoding and fall through
    }
  }

  const basicMatch = contentDisposition.match(/filename="?([^"]+)"?/i);
  if (basicMatch?.[1]) {
    return basicMatch[1];
  }

  return null;
}

// ============================================================================
// COMMON TYPES
// ============================================================================

export type Company = {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
};

export type CompanyWithRole = Company & {
  role: string;
  assigned_at: string;
};

export type CompanyListResponse = {
  companies: CompanyWithRole[];
};

export type CompanyMember = {
  user_id: string;
  email: string;
  display_name: string | null;
  role: string;
  assigned_at: string;
};

export type CompanyMembersResponse = {
  members: CompanyMember[];
};

export type ClearCompanyDataResponse = {
  deleted: Record<string, number>;
};

export const DEFAULT_COMPANY_ID = "00000000-0000-0000-0000-000000000000";

// ============================================================================
// SEED & ASSET TYPES
// ============================================================================

// SeedType includes both frontend-friendly names and backend names
export type SeedType = "domain" | "asn" | "cidr" | "organization" | "keyword" | "root_domain" | "acquisition_domain";

export type Seed = {
  id: string;
  seed_type: SeedType;
  value: string;
  note?: string | null;
  created_at: string;
  updated_at: string;
};

export type AssetType = "domain" | "ip" | "port" | "certificate" | "organization" | "asn";

/**
 * Open-finding rollup carried on an asset. Populated by the list, search and
 * detail endpoints via a lateral join, so a table can show "3 critical, 2 high"
 * without a request per row.
 */
export type OpenFindingCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
};

export type Asset = {
  id: string;
  asset_type: AssetType;
  value: string;
  ownership_confidence: number;
  /** Absent when the endpoint does not compute it (e.g. /assets/:id/path). */
  open_findings?: OpenFindingCounts;
  sources: string[];
  metadata: Record<string, unknown>;
  comment?: string | null;
  seed_id?: string | null;
  parent_id?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  last_discovery_run_id?: string | null;
  status: string;
  discovery_method?: string | null;
  importance: number;
  risk_score?: number | null;
  risk_level?: string | null;
  last_risk_run?: string | null;
  last_scan_id?: string | null;
  last_scan_status?: string | null;
  last_scanned_at?: string | null;
  created_at: string;
  updated_at: string;
};

export type AssetListResponse = {
  assets: Asset[];
  total_count: number;
  limit: number;
  offset: number;
};

export type AssetRiskHistoryEntry = {
  risk_score: number;
  risk_level: string;
  factors: Record<string, unknown>;
  calculated_at: string;
};

export type AssetScanHistoryEntry = {
  id: string;
  scan_type: string;
  status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  result_summary: Record<string, unknown>;
};

export type AssetEvolutionResponse = {
  risk_history: AssetRiskHistoryEntry[];
  scan_history: AssetScanHistoryEntry[];
};

export type CompanyEvolutionPoint = {
  timestamp: string;
  risk_score: number | null;
  active_findings: number;
};

export type CompanyEvolutionResponse = {
  series: CompanyEvolutionPoint[];
};

// ============================================================================
// DISCOVERY TYPES
// ============================================================================

export type DiscoveryStatus = {
  running: boolean;
  run_id?: string | null;
  started_at: string | null;
  completed_at: string | null;
  current_phase?: string | null;
  seeds_total?: number;
  seeds_processed: number;
  assets_discovered: number;
  assets_updated?: number;
  queue_pending?: number;
  scans_queued?: number;
  errors: string[];
  error_count: number;
};

export type DiscoveryRun = {
  id: string;
  status: string;
  trigger_type: string;
  started_at: string | null;
  completed_at: string | null;
  seeds_processed: number;
  assets_discovered: number;
  assets_updated: number;
  error_message: string | null;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

/**
 * `models::discovery::DiscoveryConfig`. A schedule stores the whole thing;
 * `POST /api/discovery/run` reads only the four fields marked below, because
 * `RunDiscoveryRequest` carries no others — anything else sent to it is
 * accepted and dropped.
 */
export type DiscoveryConfig = {
  /** Minimum confidence to auto-trigger security scans (0.0-1.0, 0 = disabled). Honoured by both. */
  auto_scan_threshold?: number;
  /** Maximum recursion depth for pivoting. Honoured by both. */
  max_depth?: number;
  /** Specific seed IDs to process (omit for all seeds). Honoured by both. */
  seed_ids?: string[];
  /** Timezone for scheduled runs (IANA string). Honoured by both. */
  timezone?: string;
  /** Skip recently processed seeds. Schedules only. */
  skip_recent?: boolean;
  /** Recent threshold in hours. Schedules only. */
  recent_hours?: number;
};

export type DiscoverySchedule = {
  id: string;
  name: string;
  cron: string;
  enabled: boolean;
  config: Record<string, unknown>;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
  updated_at: string;
};

export type DiscoveryScheduleCreate = {
  name: string;
  cron: string;
  enabled?: boolean;
  config?: DiscoveryConfig;
};

export type DiscoveryScheduleUpdate = {
  name?: string;
  cron?: string;
  enabled?: boolean;
  config?: DiscoveryConfig;
};

// ============================================================================
// SECURITY SCAN TYPES
// ============================================================================

export type SecurityScanType =
  | "port_scan"
  | "tls_analysis"
  | "http_probe"
  /** DNS, email authentication and zone hygiene, with no active probing of the host. */
  | "dns_audit"
  | "threat_intel"
  | "full";
export type SecurityScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "open" | "acknowledged" | "in_progress" | "resolved" | "false_positive" | "accepted";

export type SecurityScan = {
  id: string;
  asset_id: string;
  scan_type: string;
  status: string;
  trigger_type: string;
  priority: number;
  started_at: string | null;
  completed_at: string | null;
  note: string | null;
  config: Record<string, unknown>;
  result_summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type SecurityScanDetail = {
  scan: SecurityScan;
  asset: Asset;
  findings: SecurityFinding[];
  findings_count: number;
};

export type SecurityFinding = {
  id: string;
  security_scan_id: string | null;
  asset_id: string;
  /** Joined from the asset; absent on endpoints that do not join. */
  asset_value?: string | null;
  asset_type?: string | null;
  finding_type: string;
  severity: string;
  title: string;
  description: string | null;
  remediation: string | null;
  data: Record<string, unknown>;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  cvss_score: number | null;
  cve_ids: string[] | null;
  tags: string[] | null;
  created_at: string;
  updated_at: string;
};

export type SecurityFindingListResponse = {
  findings: SecurityFinding[];
  total_count: number;
  limit: number;
  offset: number;
};

export type FindingSortField = "first_seen_at" | "last_seen_at" | "severity" | "cvss_score" | "status";

export type SecurityFindingFilter = {
  asset_id?: string;
  scan_id?: string;
  /** Single value or a list; a list is sent comma-separated. */
  severity?: string | string[];
  status?: string | string[];
  finding_type?: string | string[];
  /** Filters on the joined asset's type — server-side, not per page. */
  asset_type?: string | string[];
  /** Free text over title, description and finding type. */
  q?: string;
  sort_by?: FindingSortField;
  sort_dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
};

export type SecurityFindingUpdate = {
  status?: FindingStatus;
  description?: string;
  remediation?: string;
  tags?: string[];
};

// ============================================================================
// RISK TYPES
// ============================================================================

/** Exactly what GET /api/risk/overview returns. */
export type RiskOverview = {
  total_risk_score: number;
  average_risk_score: number;
  total_assets: number;
  assets_with_scores: number;
  assets_pending_calculation: number;
  /** Always carries all five levels, zero-filled. */
  assets_by_level: Record<string, number>;
  /** Always carries all six types, zero-filled. */
  assets_by_type: Record<string, number>;
  assets_never_scanned: number;
  /** Sparse — an absent severity means zero. */
  findings_by_severity: Record<string, number>;
};

// ============================================================================
// METRICS TYPES
// ============================================================================

export type SystemMetrics = {
  uptime_seconds: number;
  memory_usage: {
    total_bytes: number;
    used_bytes: number;
    free_bytes: number;
  };
  active_scans: number;
  total_assets: number;
  total_findings: number;
  cpu_usage_percent: number;
  requests_per_second: number;
};

// ============================================================================
// SEARCH TYPES
// ============================================================================

export type SearchResult<T> = {
  results: T[];
  total: number;
  took: number;
  query: string;
};

export type IndexedAsset = {
  id: string;
  asset_type: string;
  identifier: string;
  confidence: number;
  sources: string[];
  created_at: string;
};

export type IndexedFinding = {
  id: string;
  scan_id: string;
  finding_type: string;
  data: Record<string, unknown>;
  created_at: string;
};

// ============================================================================
// USER TYPES
// ============================================================================

export type User = {
  id: string;
  email: string;
  display_name: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at?: string | null;
};

export type UserWithRoles = {
  id: string;
  email: string;
  display_name: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at?: string | null;
  roles: string[];
  companies: CompanyWithRole[];
};

export type CreateUserRequest = {
  email: string;
  password?: string;
  display_name?: string;
  roles?: string[];
};

export type UpdateUserRequest = {
  email?: string;
  display_name?: string;
  is_active?: boolean;
  password?: string;
};

// ============================================================================
// SEED API
// ============================================================================

export async function listSeeds(): Promise<Seed[]> {
  const res = await apiFetch(`${API_BASE}/api/seeds`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list seeds: ${res.status}`);
  return res.json();
}

export async function createSeed(seed: { seed_type: SeedType | string; value: string; note?: string }): Promise<Seed> {
  // Map frontend seed types to backend
  const backendSeedType = seed.seed_type === "root_domain" || seed.seed_type === "acquisition_domain"
    ? "domain"
    : seed.seed_type;

  const res = await apiFetch(`${API_BASE}/api/seeds`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...seed, seed_type: backendSeedType }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to create seed: ${res.status}`);
  return res.json();
}

export async function deleteSeed(seedId: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/seeds/${seedId}`, { method: "DELETE", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to delete seed: ${res.status}`);
}

// ============================================================================
// ASSET API
// ============================================================================

export async function listAssets(min_confidence = 0, limit?: number, offset?: number): Promise<AssetListResponse> {
  const params = new URLSearchParams();
  params.append("min_confidence", min_confidence.toString());
  if (limit !== undefined) params.append("limit", limit.toString());
  if (offset !== undefined) params.append("offset", offset.toString());

  const res = await apiFetch(`${API_BASE}/api/assets?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list assets: ${res.status}`);
  return res.json();
}

// ============================================================================
// ADVANCED ASSET SEARCH
// ============================================================================

export type AssetSearchParams = {
  q?: string;
  /** Single value or a list; a list is sent comma-separated. */
  asset_type?: AssetType | "all" | AssetType[];
  min_confidence?: number;
  scan_status?: "all" | "scanned" | "never_scanned";
  source?: string | string[];
  risk_level?: string | string[];
  sort_by?: "created_at" | "confidence" | "value" | "importance" | "risk_score";
  sort_dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
};

export type AssetSearchResponse = {
  assets: Asset[];
  total_count: number;
  sources: string[];
  limit: number;
  offset: number;
};

/** Comma-joins a list filter; the backend splits on commas for every list param. */
function listParam(value: string | string[] | undefined): string | undefined {
  if (!value) return undefined;
  const joined = Array.isArray(value) ? value.join(",") : value;
  return joined.length > 0 ? joined : undefined;
}

export async function searchAssetsAdvanced(params: AssetSearchParams): Promise<AssetSearchResponse> {
  const queryParams = new URLSearchParams();

  if (params.q) queryParams.append("q", params.q);
  const assetType = listParam(params.asset_type === "all" ? undefined : params.asset_type);
  if (assetType) queryParams.append("asset_type", assetType);
  if (params.min_confidence !== undefined) queryParams.append("min_confidence", params.min_confidence.toString());
  if (params.scan_status && params.scan_status !== "all") queryParams.append("scan_status", params.scan_status);
  const source = listParam(params.source);
  if (source) queryParams.append("source", source);
  const riskLevel = listParam(params.risk_level);
  if (riskLevel) queryParams.append("risk_level", riskLevel);
  if (params.sort_by) queryParams.append("sort_by", params.sort_by);
  if (params.sort_dir) queryParams.append("sort_dir", params.sort_dir);
  if (params.limit !== undefined) queryParams.append("limit", params.limit.toString());
  if (params.offset !== undefined) queryParams.append("offset", params.offset.toString());

  const res = await apiFetch(`${API_BASE}/api/assets/search?${queryParams.toString()}`, {
    cache: "no-store",
    credentials: "include"
  });
  if (!res.ok) throw new Error(`Failed to search assets: ${res.status}`);
  return res.json();
}

export async function getAsset(id: string): Promise<Asset> {
  const res = await apiFetch(`${API_BASE}/api/assets/${id}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get asset: ${res.status}`);
  return res.json();
}

export async function getAssetPath(assetId: string): Promise<Asset[]> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/path`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get asset path: ${res.status}`);
  return res.json();
}

export async function getAssetEvolution(assetId: string, limit = 50): Promise<AssetEvolutionResponse> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/evolution?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get asset evolution: ${res.status}`);
  return res.json();
}

export async function updateAssetImportance(assetId: string, importance: number): Promise<Asset> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/importance`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ importance }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update asset importance: ${res.status}`);
  return res.json();
}

export async function updateAssetComment(assetId: string, comment: string | null): Promise<Asset> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/comment`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ comment }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update asset comment: ${res.status}`);
  return res.json();
}

export function getAssetPathUrl(assetId: string): string {
  return `${API_BASE}/api/assets/${assetId}/path`;
}

export async function getAssetPdfReport(
  assetId: string
): Promise<{ blob: Blob; filename: string }> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/report`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to download asset report: ${res.status}`);

  const blob = await res.blob();
  const filename =
    parseContentDispositionFilename(res.headers.get("content-disposition")) ||
    `asset-security-risk-overview-${assetId}.pdf`;

  return { blob, filename };
}

// ============================================================================
// DISCOVERY API
// ============================================================================

export async function runDiscovery(config?: DiscoveryConfig): Promise<DiscoveryRun> {
  const res = await apiFetch(`${API_BASE}/api/discovery/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config || {}),
    credentials: "include",
  });
  if (!res.ok) {
    if (res.status === 409) throw new Error("Discovery already running");
    throw new Error(`Failed to run discovery: ${res.status}`);
  }
  return res.json();
}

export async function stopDiscovery(): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/discovery/stop`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to stop discovery: ${res.status}`);
}

export async function getDiscoveryStatus(): Promise<DiscoveryStatus> {
  const res = await apiFetch(`${API_BASE}/api/discovery/status`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get discovery status: ${res.status}`);
  return res.json();
}

export async function listDiscoveryRuns(limit = 50, offset = 0): Promise<DiscoveryRun[]> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());
  params.append("offset", offset.toString());

  const res = await apiFetch(`${API_BASE}/api/discovery/runs?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list discovery runs: ${res.status}`);
  return res.json();
}

export async function getDiscoveryRun(id: string): Promise<DiscoveryRun> {
  const res = await apiFetch(`${API_BASE}/api/discovery/runs/${id}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get discovery run: ${res.status}`);
  return res.json();
}

export async function listDiscoverySchedules(): Promise<DiscoverySchedule[]> {
  const res = await apiFetch(`${API_BASE}/api/discovery/schedules`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list discovery schedules: ${res.status}`);
  return res.json();
}

export async function createDiscoverySchedule(payload: DiscoveryScheduleCreate): Promise<DiscoverySchedule> {
  const res = await apiFetch(`${API_BASE}/api/discovery/schedules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to create discovery schedule: ${res.status}`);
  return res.json();
}

export async function updateDiscoverySchedule(id: string, payload: DiscoveryScheduleUpdate): Promise<DiscoverySchedule> {
  const res = await apiFetch(`${API_BASE}/api/discovery/schedules/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update discovery schedule: ${res.status}`);
  return res.json();
}

export async function deleteDiscoverySchedule(id: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/discovery/schedules/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to delete discovery schedule: ${res.status}`);
}

// ============================================================================
// SECURITY SCAN API
// ============================================================================

export async function createSecurityScan(assetId: string, scanType?: string, note?: string): Promise<SecurityScan> {
  const res = await apiFetch(`${API_BASE}/api/security/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asset_id: assetId, scan_type: scanType, note }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to create security scan: ${res.status}`);
  return res.json();
}

export type ScanListParams = {
  limit?: number;
  offset?: number;
  asset_id?: string;
  /** Single value or list: pending | running | completed | failed | cancelled. */
  status?: string | string[];
  scan_type?: string | string[];
};

export type ScanListItem = SecurityScan & {
  /** Joined from the asset so a queue table needs no request per row. */
  asset_value?: string | null;
  asset_type?: string | null;
  findings_count?: number;
};

export type ScanListResponse = {
  scans: ScanListItem[];
  total_count: number;
  limit: number;
  offset: number;
};

export async function listScans(params?: ScanListParams): Promise<ScanListResponse> {
  const query = new URLSearchParams();
  if (params?.limit) query.append("limit", params.limit.toString());
  if (params?.offset !== undefined) query.append("offset", params.offset.toString());
  if (params?.asset_id) query.append("asset_id", params.asset_id);
  const status = listParam(params?.status);
  if (status) query.append("status", status);
  const scanType = listParam(params?.scan_type);
  if (scanType) query.append("scan_type", scanType);

  const res = await apiFetch(`${API_BASE}/api/security/scans?${query.toString()}`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to list security scans: ${res.status}`);
  return res.json();
}

export async function getSecurityScan(id: string): Promise<SecurityScanDetail> {
  const res = await apiFetch(`${API_BASE}/api/security/scans/${id}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get security scan: ${res.status}`);
  return res.json();
}

export async function cancelSecurityScan(id: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/security/scans/${id}/cancel`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to cancel security scan: ${res.status}`);
}

export async function listSecurityFindings(filter?: SecurityFindingFilter): Promise<SecurityFindingListResponse> {
  const params = new URLSearchParams();
  if (filter?.asset_id) params.append("asset_id", filter.asset_id);
  if (filter?.scan_id) params.append("scan_id", filter.scan_id);
  const severity = listParam(filter?.severity);
  if (severity) params.append("severity", severity);
  const status = listParam(filter?.status);
  if (status) params.append("status", status);
  const findingType = listParam(filter?.finding_type);
  if (findingType) params.append("finding_type", findingType);
  const assetType = listParam(filter?.asset_type);
  if (assetType) params.append("asset_type", assetType);
  if (filter?.q) params.append("q", filter.q);
  if (filter?.sort_by) params.append("sort_by", filter.sort_by);
  if (filter?.sort_dir) params.append("sort_dir", filter.sort_dir);
  if (filter?.limit) params.append("limit", filter.limit.toString());
  if (filter?.offset !== undefined) params.append("offset", filter.offset.toString());

  const res = await apiFetch(`${API_BASE}/api/security/findings?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list security findings: ${res.status}`);
  return res.json();
}

export async function getSecurityFinding(id: string): Promise<SecurityFinding> {
  const res = await apiFetch(`${API_BASE}/api/security/findings/${id}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get security finding: ${res.status}`);
  return res.json();
}

export async function updateSecurityFinding(id: string, update: SecurityFindingUpdate): Promise<SecurityFinding> {
  const res = await apiFetch(`${API_BASE}/api/security/findings/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(update),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update security finding: ${res.status}`);
  return res.json();
}

export async function bulkUpdateSecurityFindings(
  ids: string[],
  update: SecurityFindingUpdate,
): Promise<{ updated: number; failed: number; updated_ids: string[]; failed_ids: string[] }> {
  const res = await apiFetch(`${API_BASE}/api/security/findings/bulk`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ids, update }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to bulk update findings: ${res.status}`);
  return res.json();
}

export async function resolveSecurityFinding(id: string): Promise<SecurityFinding> {
  const res = await apiFetch(`${API_BASE}/api/security/findings/${id}/resolve`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to resolve security finding: ${res.status}`);
  return res.json();
}

export type FindingsSummary = {
  /** Counts only open, acknowledged and in_progress. */
  by_severity: Record<string, number>;
  /** Every status, including resolved and false_positive. */
  by_status: Record<string, number>;
};

export async function getSecurityFindingsSummary(): Promise<FindingsSummary> {
  const res = await apiFetch(`${API_BASE}/api/security/findings/summary`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get findings summary: ${res.status}`);
  return res.json();
}

export async function triggerAssetScan(assetId: string, scanType?: string, note?: string): Promise<SecurityScan> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_type: scanType, note }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to trigger asset scan: ${res.status}`);
  return res.json();
}

export async function getAssetFindings(assetId: string): Promise<SecurityFinding[]> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/findings`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get asset findings: ${res.status}`);
  return res.json();
}

export async function listPendingSecurityScans(limit = 50): Promise<SecurityScan[]> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());

  const res = await apiFetch(`${API_BASE}/api/security/scans/pending?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list pending scans: ${res.status}`);
  return res.json();
}

// ============================================================================
// RISK API
// ============================================================================

export async function getAssetRisk(assetId: string): Promise<Asset> {
  const res = await apiFetch(`${API_BASE}/api/risk/assets/${assetId}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get asset risk: ${res.status}`);
  return res.json();
}

export async function getCompanyEvolution(limit = 60): Promise<CompanyEvolutionResponse> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());
  const res = await apiFetch(`${API_BASE}/api/risk/evolution?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get company evolution: ${res.status}`);
  return res.json();
}

export async function recalculateAssetRisk(assetId: string): Promise<Asset> {
  const res = await apiFetch(`${API_BASE}/api/risk/assets/${assetId}/recalculate`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to recalculate asset risk: ${res.status}`);
  return res.json();
}

export async function getRiskOverview(): Promise<RiskOverview> {
  const res = await apiFetch(`${API_BASE}/api/risk/overview`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get risk overview: ${res.status}`);
  return res.json();
}

export type RiskRecalculationResult = {
  success_count: number;
  error_count: number;
  errors: string[];
};

export async function recalculateAllRisks(): Promise<RiskRecalculationResult> {
  const res = await apiFetch(`${API_BASE}/api/risk/recalculate-all`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to recalculate all risks: ${res.status}`);
  return res.json();
}

export async function getHighRiskAssets(limit = 20): Promise<Asset[]> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());

  const res = await apiFetch(`${API_BASE}/api/risk/high-risk-assets?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get high risk assets: ${res.status}`);
  return res.json();
}

// ============================================================================
// SEARCH API
// ============================================================================

export async function searchAssets(query: string, size = 20, from = 0): Promise<SearchResult<IndexedAsset>> {
  const params = new URLSearchParams();
  params.append("q", query);
  params.append("size", size.toString());
  params.append("from", from.toString());

  const res = await apiFetch(`${API_BASE}/api/search/assets?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to search assets: ${res.status}`);
  return res.json();
}

export async function searchFindings(query: string, size = 20, from = 0): Promise<SearchResult<IndexedFinding>> {
  const params = new URLSearchParams();
  params.append("q", query);
  params.append("size", size.toString());
  params.append("from", from.toString());

  const res = await apiFetch(`${API_BASE}/api/search/findings?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to search findings: ${res.status}`);
  return res.json();
}

export async function reindexSearch(): Promise<{ assets_indexed: number; findings_indexed: number }> {
  const res = await apiFetch(`${API_BASE}/api/search/reindex`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to reindex: ${res.status}`);
  return res.json();
}

export async function getSearchStatus(): Promise<{ status: string; search_available: boolean; message: string }> {
  const res = await apiFetch(`${API_BASE}/api/search/status`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get search status: ${res.status}`);
  return res.json();
}

// ============================================================================
// METRICS API
// ============================================================================

export async function getMetrics(): Promise<SystemMetrics> {
  const res = await apiFetch(`${API_BASE}/api/metrics`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get metrics: ${res.status}`);
  return res.json();
}

export async function getPerformanceReport(): Promise<Record<string, unknown>> {
  const res = await apiFetch(`${API_BASE}/api/metrics/report`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get performance report: ${res.status}`);
  return res.json();
}

export async function getHealthMetrics(): Promise<Record<string, unknown>> {
  const res = await apiFetch(`${API_BASE}/api/metrics/health`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get health metrics: ${res.status}`);
  return res.json();
}

export async function clearMetrics(): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/metrics/clear`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to clear metrics: ${res.status}`);
}

// ============================================================================
// HEALTH API
// ============================================================================

export async function getHealth(): Promise<{ status: string; timestamp: string; version: string }> {
  const res = await apiFetch(`${API_BASE}/api/health`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get health: ${res.status}`);
  return res.json();
}

// ============================================================================
// COMPANY API
// ============================================================================

export async function listCompanies(): Promise<CompanyWithRole[]> {
  const res = await apiFetch(`${API_BASE}/api/companies`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list companies: ${res.status}`);
  const data: CompanyListResponse = await res.json();
  return data.companies || [];
}

export async function createCompany(name: string): Promise<Company> {
  const res = await apiFetch(`${API_BASE}/api/companies`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to create company: ${res.status}`);
  }
  return res.json();
}

export async function updateCompany(id: string, name: string): Promise<Company> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to update company: ${res.status}`);
  }
  return res.json();
}

export async function deleteCompany(id: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to delete company: ${res.status}`);
  }
}

export async function clearCompanyData(id: string): Promise<ClearCompanyDataResponse> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}/clear-data`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to clear company data: ${res.status}`);
  }
  return res.json();
}

export async function listCompanyMembers(id: string): Promise<CompanyMember[]> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}/members`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to list members: ${res.status}`);
  }
  const data: CompanyMembersResponse = await res.json();
  return data.members || [];
}

export async function addCompanyMember(
  id: string,
  userId: string,
  role: string,
): Promise<CompanyMember[]> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId, role }),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to add member: ${res.status}`);
  }
  const data: CompanyMembersResponse = await res.json();
  return data.members || [];
}

export async function updateCompanyMemberRole(
  id: string,
  userId: string,
  role: string,
): Promise<CompanyMember[]> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}/members/${userId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to update member role: ${res.status}`);
  }
  const data: CompanyMembersResponse = await res.json();
  return data.members || [];
}

export async function removeCompanyMember(
  id: string,
  userId: string,
): Promise<CompanyMember[]> {
  const res = await apiFetch(`${API_BASE}/api/companies/${id}/members/${userId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to remove member: ${res.status}`);
  }
  const data: CompanyMembersResponse = await res.json();
  return data.members || [];
}

export async function listUserCompanies(userId: string): Promise<CompanyWithRole[]> {
  const res = await apiFetch(`${API_BASE}/api/admin/users/${userId}/companies`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to list user companies: ${res.status}`);
  }
  const data: { companies: CompanyWithRole[] } = await res.json();
  return data.companies || [];
}

// ============================================================================
// ADMIN API
// ============================================================================

export async function listUsers(): Promise<UserWithRoles[]> {
  const res = await apiFetch(`${API_BASE}/api/admin/users`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list users: ${res.status}`);
  return res.json();
}

export async function getUser(userId: string): Promise<UserWithRoles> {
  const res = await apiFetch(`${API_BASE}/api/admin/users/${userId}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get user: ${res.status}`);
  return res.json();
}

export async function createUser(userData: CreateUserRequest): Promise<UserWithRoles> {
  const res = await apiFetch(`${API_BASE}/api/admin/users`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(userData),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to create user: ${res.status}`);
  }
  return res.json();
}

export async function updateUser(userId: string, userData: UpdateUserRequest): Promise<UserWithRoles> {
  const res = await apiFetch(`${API_BASE}/api/admin/users/${userId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(userData),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to update user: ${res.status}`);
  }
  return res.json();
}

export async function deleteUser(userId: string): Promise<string> {
  const res = await apiFetch(`${API_BASE}/api/admin/users/${userId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to delete user: ${res.status}`);
  }
  return res.json();
}

export async function updateUserRole(userId: string, role: string, action: "add" | "remove"): Promise<string> {
  const res = await apiFetch(`${API_BASE}/api/admin/users/${userId}/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role, action }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update user role: ${res.status}`);
  return res.json();
}

// ============================================================================
// SETTINGS API
// ============================================================================

export type SecretField = {
  is_set: boolean;
  value?: string | null;
};

export type SettingsView = {
  google_client_id: string | null;
  google_client_secret: SecretField;
  google_discovery_url: string | null;
  google_redirect_uri: string | null;
  google_allowed_domains: string[];
  keycloak_client_id: string | null;
  keycloak_client_secret: SecretField;
  keycloak_discovery_url: string | null;
  keycloak_redirect_uri: string | null;
  keycloak_realm: string | null;
  certspotter_api_token: SecretField;
  virustotal_api_key: SecretField;
  shodan_api_key: SecretField;
  urlscan_api_key: SecretField;
  otx_api_key: SecretField;
  clearbit_api_key: SecretField;
  opencorporates_api_token: SecretField;
  securitytrails_api_key: SecretField;
  censys_api_key: SecretField;
  censys_org_id: string | null;
  chaos_api_key: SecretField;
  leakix_api_key: SecretField;
  fullhunt_api_key: SecretField;
  binaryedge_api_key: SecretField;
  netlas_api_key: SecretField;
  cors_allow_origins: string[];
  log_level: string;
  log_format: string;
  rate_limit_enabled: boolean;
  rate_limit_requests: number;
  rate_limit_window_seconds: number;
  http_timeout_seconds: number;
  tls_timeout_seconds: number;
  dns_concurrency: number;
  rdns_concurrency: number;
  max_concurrent_scans: number;
  max_active_scans_per_user: number;
  max_active_discovery_per_user: number;
  block_internal_ip_scans: boolean;
  max_evidence_bytes: number;
  evidence_allowed_types: string[];
  max_cidr_hosts: number;
  max_discovery_depth: number;
  subdomain_enum_timeout: number;
  enable_wayback: boolean;
  enable_urlscan: boolean;
  enable_otx: boolean;
  enable_dns_record_expansion: boolean;
  enable_web_crawl: boolean;
  enable_cloud_storage_discovery: boolean;
  enable_wikidata: boolean;
  enable_opencorporates: boolean;
  max_assets_per_discovery: number;
  min_pivot_confidence: number;
  max_orgs_per_domain: number;
  max_domains_per_org: number;
  skip_unresolved_domains: boolean;

  // Passive OSINT fan-out
  osint_source_concurrency: number;
  osint_source_timeout_seconds: number;
  osint_max_results_per_source: number;

  // Active DNS discovery
  enable_dns_bruteforce: boolean;
  enable_dns_permutations: boolean;
  enable_nsec_walk: boolean;
  enable_srv_probe: boolean;
  dns_bruteforce_wordlist_path: string | null;
  dns_bruteforce_max_words: number;
  dns_permutation_max_candidates: number;
  dns_permutation_max_seeds: number;
  active_dns_concurrency: number;

  // Infrastructure attribution
  enable_asn_discovery: boolean;
  enable_rdap_lookup: boolean;
  enable_saas_tenant_discovery: boolean;
  enable_cname_chain_analysis: boolean;
  asn_max_prefixes: number;
  reverse_dns_sweep_max_hosts: number;

  // Search
  reindex_min_interval_seconds: number;
};

export type SettingsResponse = {
  settings: SettingsView;
  updated_at: string;
  updated_by?: string | null;
};

export type SettingsUpdatePayload = {
  google_client_id?: string | null;
  google_client_secret?: string | null;
  google_discovery_url?: string | null;
  google_redirect_uri?: string | null;
  google_allowed_domains?: string[];
  keycloak_client_id?: string | null;
  keycloak_client_secret?: string | null;
  keycloak_discovery_url?: string | null;
  keycloak_redirect_uri?: string | null;
  keycloak_realm?: string | null;
  certspotter_api_token?: string | null;
  virustotal_api_key?: string | null;
  shodan_api_key?: string | null;
  urlscan_api_key?: string | null;
  otx_api_key?: string | null;
  clearbit_api_key?: string | null;
  opencorporates_api_token?: string | null;
  securitytrails_api_key?: string | null;
  censys_api_key?: string | null;
  censys_org_id?: string | null;
  chaos_api_key?: string | null;
  leakix_api_key?: string | null;
  fullhunt_api_key?: string | null;
  binaryedge_api_key?: string | null;
  netlas_api_key?: string | null;
  cors_allow_origins?: string[];
  log_level?: string;
  log_format?: string;
  rate_limit_enabled?: boolean;
  rate_limit_requests?: number;
  rate_limit_window_seconds?: number;
  http_timeout_seconds?: number;
  tls_timeout_seconds?: number;
  dns_concurrency?: number;
  rdns_concurrency?: number;
  max_concurrent_scans?: number;
  max_active_scans_per_user?: number;
  max_active_discovery_per_user?: number;
  block_internal_ip_scans?: boolean;
  max_evidence_bytes?: number;
  evidence_allowed_types?: string[];
  max_cidr_hosts?: number;
  max_discovery_depth?: number;
  subdomain_enum_timeout?: number;
  enable_wayback?: boolean;
  enable_urlscan?: boolean;
  enable_otx?: boolean;
  enable_dns_record_expansion?: boolean;
  enable_web_crawl?: boolean;
  enable_cloud_storage_discovery?: boolean;
  enable_wikidata?: boolean;
  enable_opencorporates?: boolean;
  max_assets_per_discovery?: number;
  min_pivot_confidence?: number;
  max_orgs_per_domain?: number;
  max_domains_per_org?: number;
  skip_unresolved_domains?: boolean;

  osint_source_concurrency?: number;
  osint_source_timeout_seconds?: number;
  osint_max_results_per_source?: number;

  enable_dns_bruteforce?: boolean;
  enable_dns_permutations?: boolean;
  enable_nsec_walk?: boolean;
  enable_srv_probe?: boolean;
  dns_bruteforce_wordlist_path?: string | null;
  dns_bruteforce_max_words?: number;
  dns_permutation_max_candidates?: number;
  dns_permutation_max_seeds?: number;
  active_dns_concurrency?: number;

  enable_asn_discovery?: boolean;
  enable_rdap_lookup?: boolean;
  enable_saas_tenant_discovery?: boolean;
  enable_cname_chain_analysis?: boolean;
  asn_max_prefixes?: number;
  reverse_dns_sweep_max_hosts?: number;

  reindex_min_interval_seconds?: number;
};

export async function getSettings(revealSecrets = false): Promise<SettingsResponse> {
  const res = await apiFetch(`${API_BASE}/api/admin/settings?reveal_secrets=${revealSecrets}`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to load settings: ${res.status}`);
  return res.json();
}

export async function updateSettings(payload: SettingsUpdatePayload, revealSecrets = false): Promise<SettingsResponse> {
  const res = await apiFetch(`${API_BASE}/api/admin/settings?reveal_secrets=${revealSecrets}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update settings: ${res.status}`);
  return res.json();
}

// ============================================================================
// TAG TYPES
// ============================================================================

export type Tag = {
  id: string;
  name: string;
  description: string | null;
  importance: number;
  rule_type: "regex" | "ip_range" | null;
  rule_value: string | null;
  color: string | null;
  company_id: string;
  created_at: string;
  updated_at: string;
};

export type TagWithCount = {
  id: string;
  name: string;
  description: string | null;
  importance: number;
  rule_type: "regex" | "ip_range" | null;
  rule_value: string | null;
  color: string | null;
  company_id: string;
  created_at: string;
  updated_at: string;
  asset_count: number;
};

export type TagListResponse = {
  tags: TagWithCount[];
  total_count: number;
  limit: number;
  offset: number;
};

export type TagCreate = {
  name: string;
  description?: string;
  importance?: number;
  rule_type?: "regex" | "ip_range";
  rule_value?: string;
  color?: string;
};

export type TagUpdate = {
  name?: string;
  description?: string;
  importance?: number;
  rule_type?: "regex" | "ip_range";
  rule_value?: string;
  color?: string;
  clear_rule?: boolean;
};

export type AssetTagDetail = {
  tag: Tag;
  applied_by: "manual" | "auto_rule";
  matched_rule: string | null;
  tagged_at: string;
};

export type AutoTagResult = {
  tags_applied: number;
  assets_tagged: number;
  errors: string[];
};

// ============================================================================
// TAG API
// ============================================================================

export async function listTags(limit = 100, offset = 0): Promise<TagListResponse> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());
  params.append("offset", offset.toString());

  const res = await apiFetch(`${API_BASE}/api/tags?${params.toString()}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to list tags: ${res.status}`);
  return res.json();
}

export async function getTag(id: string): Promise<Tag> {
  const res = await apiFetch(`${API_BASE}/api/tags/${id}`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get tag: ${res.status}`);
  return res.json();
}

export async function createTag(tag: TagCreate): Promise<Tag> {
  const res = await apiFetch(`${API_BASE}/api/tags`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(tag),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to create tag: ${res.status}`);
  }
  return res.json();
}

export async function updateTag(id: string, update: TagUpdate): Promise<Tag> {
  const res = await apiFetch(`${API_BASE}/api/tags/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(update),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to update tag: ${res.status}`);
  }
  return res.json();
}

export async function deleteTag(id: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/tags/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to delete tag: ${res.status}`);
}

export async function getAssetTags(assetId: string): Promise<AssetTagDetail[]> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/tags`, { cache: "no-store", credentials: "include" });
  if (!res.ok) throw new Error(`Failed to get asset tags: ${res.status}`);
  return res.json();
}

export async function tagAsset(assetId: string, tagId: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/tags`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tag_id: tagId }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to tag asset: ${res.status}`);
}

export async function untagAsset(assetId: string, tagId: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/assets/${assetId}/tags/${tagId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to untag asset: ${res.status}`);
}

export async function runAutoTagForTag(tagId: string): Promise<AutoTagResult> {
  const res = await apiFetch(`${API_BASE}/api/tags/${tagId}/run-auto-tag`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to run auto-tagging: ${res.status}`);
  return res.json();
}

export async function runAutoTagAll(): Promise<AutoTagResult> {
  const res = await apiFetch(`${API_BASE}/api/tags/run-auto-tag-all`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to run auto-tagging: ${res.status}`);
  return res.json();
}

// ============================================================================
// BLACKLIST TYPES
// ============================================================================

export type BlacklistObjectType = "domain" | "ip" | "organization" | "asn" | "cidr" | "certificate";

export type BlacklistEntry = {
  id: string;
  object_type: string;
  object_value: string;
  company_id: string;
  reason: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

export type BlacklistCreate = {
  object_type: BlacklistObjectType;
  object_value: string;
  reason?: string;
  delete_descendants?: boolean;
};

export type BlacklistResult = {
  entry: BlacklistEntry;
  descendants_deleted: number;
};

export type BlacklistListResponse = {
  entries: BlacklistEntry[];
  total_count: number;
  limit: number;
  offset: number;
};

export type BlacklistCheckResult = {
  is_blacklisted: boolean;
  entry: BlacklistEntry | null;
  parent_blacklisted: boolean;
  parent_entry: BlacklistEntry | null;
};

export type BlacklistStats = {
  total_entries: number;
  by_type: Record<string, number>;
};

// ============================================================================
// BLACKLIST API
// ============================================================================

export async function listBlacklist(
  limit = 50,
  offset = 0,
  objectType?: string,
  q?: string
): Promise<BlacklistListResponse> {
  const params = new URLSearchParams();
  params.append("limit", limit.toString());
  params.append("offset", offset.toString());
  if (objectType) params.append("object_type", objectType);
  if (q) params.append("q", q);

  const res = await apiFetch(`${API_BASE}/api/blacklist?${params.toString()}`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to list blacklist: ${res.status}`);
  return res.json();
}

export async function createBlacklistEntry(entry: BlacklistCreate): Promise<BlacklistResult> {
  const res = await apiFetch(`${API_BASE}/api/blacklist`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(entry),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to create blacklist entry: ${res.status}`);
  }
  return res.json();
}

export async function getBlacklistEntry(id: string): Promise<BlacklistEntry> {
  const res = await apiFetch(`${API_BASE}/api/blacklist/${id}`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to get blacklist entry: ${res.status}`);
  return res.json();
}

export async function updateBlacklistEntry(id: string, reason: string): Promise<BlacklistEntry> {
  const res = await apiFetch(`${API_BASE}/api/blacklist/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to update blacklist entry: ${res.status}`);
  return res.json();
}

export async function deleteBlacklistEntry(id: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/api/blacklist/${id}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to delete blacklist entry: ${res.status}`);
}

export async function checkBlacklist(
  objectType: BlacklistObjectType,
  objectValue: string
): Promise<BlacklistCheckResult> {
  const res = await apiFetch(`${API_BASE}/api/blacklist/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ object_type: objectType, object_value: objectValue }),
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to check blacklist: ${res.status}`);
  return res.json();
}

export async function blacklistFromAsset(
  assetId: string,
  reason?: string,
  deleteDescendants = true
): Promise<BlacklistResult> {
  const res = await apiFetch(`${API_BASE}/api/blacklist/from-asset/${assetId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason, delete_descendants: deleteDescendants }),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to blacklist asset: ${res.status}`);
  }
  return res.json();
}

export async function getBlacklistStats(): Promise<BlacklistStats> {
  const res = await apiFetch(`${API_BASE}/api/blacklist/stats`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to get blacklist stats: ${res.status}`);
  return res.json();
}

// ============================================================================
// FINDING TYPE CONFIG TYPES
// ============================================================================

export type FindingTypeConfig = {
  id: string;
  finding_type: string;
  display_name: string;
  category: string;
  /** The only scoring input configuration contributes. A finding's base score comes
   *  from its own severity. */
  type_multiplier: number;
  description: string | null;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type FindingTypeConfigListResponse = {
  configs: FindingTypeConfig[];
  categories: string[];
  total_count: number;
};

export type FindingTypeConfigUpdate = {
  display_name?: string;
  type_multiplier?: number;
  description?: string;
  is_enabled?: boolean;
};

export type FindingTypeConfigBulkUpdateItem = {
  finding_type: string;
  type_multiplier?: number;
  is_enabled?: boolean;
};

export type FindingTypeConfigBulkUpdateResult = {
  updated: FindingTypeConfig[];
  updated_count: number;
  errors: string[];
  error_count: number;
};

// ============================================================================
// FINDING TYPE CONFIG API
// ============================================================================

export async function listFindingTypeConfigs(): Promise<FindingTypeConfigListResponse> {
  const res = await apiFetch(`${API_BASE}/api/admin/finding-type-config`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to list finding type configs: ${res.status}`);
  return res.json();
}

export async function getFindingTypeConfig(findingType: string): Promise<FindingTypeConfig> {
  const res = await apiFetch(`${API_BASE}/api/admin/finding-type-config/${encodeURIComponent(findingType)}`, {
    cache: "no-store",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`Failed to get finding type config: ${res.status}`);
  return res.json();
}

export async function updateFindingTypeConfig(
  findingType: string,
  update: FindingTypeConfigUpdate
): Promise<FindingTypeConfig> {
  const res = await apiFetch(`${API_BASE}/api/admin/finding-type-config/${encodeURIComponent(findingType)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(update),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to update finding type config: ${res.status}`);
  }
  return res.json();
}

export async function bulkUpdateFindingTypeConfigs(
  configs: FindingTypeConfigBulkUpdateItem[]
): Promise<FindingTypeConfigBulkUpdateResult> {
  const res = await apiFetch(`${API_BASE}/api/admin/finding-type-config/bulk`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ configs }),
    credentials: "include",
  });
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `Failed to bulk update finding type configs: ${res.status}`);
  }
  return res.json();
}

// ============================================================================
// DRIFT API — deliberately not bound
// ============================================================================
//
// `/api/security/scans/:id/drift` is not callable from here on purpose.
//
// `drift_handlers` resolves the `:id` against the legacy `scans` table, which
// nothing has written to since the legacy pipeline was unrouted, so the POST
// 404s for every scan this UI can produce an id for. The GET answers with
// `models::Finding` — `{ id, scan_id, finding_type, data, created_at }` — which
// is a different record from `SecurityFinding` and is never returned by any
// other endpoint.
//
// The bindings that used to sit here typed the GET as `SecurityFinding[]` and
// the POST as `void`; neither was true, and nothing called them. Retargeting
// `drift_service` at `security_scans` is the fix; until then, adding a caller
// here would only bind the UI to a shape the server does not send.

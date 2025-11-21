export type ScanOptions = {
  enumerate_subdomains?: boolean;
  resolve_dns?: boolean;
  reverse_dns?: boolean;
  scan_common_ports?: boolean;
  http_probe?: boolean;
  tls_info?: boolean;
  common_ports?: number[];
  max_hosts?: number;
};

export type Finding = {
  id: string;
  scan_id: string;
  finding_type: string;
  data: Record<string, unknown>;
  created_at: string;
};

export type Scan = {
  id: string;
  target: string;
  note?: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  findings_count?: number;
  findings: Finding[];
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export async function createScan(target: string, note?: string, options?: ScanOptions): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, note, options }),
  });
  if (!res.ok) throw new Error(`Failed to create scan: ${res.status}`);
  return res.json();
}

export async function listScans(): Promise<Scan[]> {
  const res = await fetch(`${API_BASE}/api/scans`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to list scans: ${res.status}`);
  return res.json();
}

export async function getScan(id: string): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get scan: ${res.status}`);
  return res.json();
}

// Seeds & Assets (Module 1)
export type SeedType = "root_domain" | "asn" | "cidr" | "acquisition_domain" | "keyword" | "organization";

export type Seed = {
  id: string;
  seed_type: SeedType;
  value: string;
  note?: string | null;
  created_at: string;
  updated_at: string;
};

export async function listSeeds(): Promise<Seed[]> {
  const res = await fetch(`${API_BASE}/api/seeds`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to list seeds: ${res.status}`);
  return res.json();
}

export async function createSeed(seed: { seed_type: SeedType; value: string; note?: string }): Promise<Seed> {
  const res = await fetch(`${API_BASE}/api/seeds`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(seed),
  });
  if (!res.ok) throw new Error(`Failed to create seed: ${res.status}`);
  return res.json();
}

export async function deleteSeed(seedId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/seeds/${seedId}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Failed to delete seed: ${res.status}`);
}

export type Asset = {
  id: string;
  asset_type: "domain" | "ip";
  value: string;
  ownership_confidence: number;
  sources: string[];
  metadata: Record<string, unknown>;
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

export async function listAssets(min_confidence = 0, limit?: number, offset?: number): Promise<AssetListResponse> {
  const params = new URLSearchParams();
  params.append("min_confidence", min_confidence.toString());
  if (limit !== undefined) params.append("limit", limit.toString());
  if (offset !== undefined) params.append("offset", offset.toString());
  
  const res = await fetch(`${API_BASE}/api/assets?${params.toString()}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to list assets: ${res.status}`);
  return res.json();
}

export async function getAsset(id: string): Promise<Asset> {
  const res = await fetch(`${API_BASE}/api/assets/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get asset: ${res.status}`);
  return res.json();
}

export async function runDiscovery(opts: { confidence_threshold?: number; include_scan?: boolean }): Promise<{ discovered_assets: number; scheduled_scans: number; }> {
  const res = await fetch(`${API_BASE}/api/discovery/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confidence_threshold: 0.7, include_scan: true, ...opts }),
  });
  if (!res.ok) {
    if (res.status === 409) throw new Error("Discovery already running");
    throw new Error(`Failed to run discovery: ${res.status}`);
  }
  return res.json();
}

export async function stopDiscovery(): Promise<void> {
  const res = await fetch(`${API_BASE}/api/discovery/stop`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`Failed to stop discovery: ${res.status}`);
}

export type DiscoveryStatus = {
  running: boolean;
  started_at: string | null;
  completed_at: string | null;
  seeds_processed: number;
  assets_discovered: number;
  errors: string[];
  error_count: number;
};

export async function getDiscoveryStatus(): Promise<DiscoveryStatus> {
  const res = await fetch(`${API_BASE}/api/discovery/status`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get discovery status: ${res.status}`);
  return res.json();
}

// ... existing code ...

export type DriftFinding = {
  id: string;
  scan_id: string;
  asset_id: string;
  previous_scan_id?: string;
  port: number;
  protocol: string;
  state: "new" | "missing" | "changed";
  previous_state?: string;
  current_state: string;
  detected_at: string;
};

export async function detectDrift(scanId: string): Promise<{ drift_findings_count: number }> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/drift/detect`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`Failed to detect drift: ${res.status}`);
  return res.json();
}

export async function getDriftFindings(scanId: string): Promise<DriftFinding[]> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/drift/findings`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get drift findings: ${res.status}`);
  return res.json();
}

// Metrics & System Status
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

export async function getMetrics(): Promise<SystemMetrics> {
  const res = await fetch(`${API_BASE}/api/metrics`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get metrics: ${res.status}`);
  return res.json();
}

export async function getHealth(): Promise<{ status: string; timestamp: string; version: string }> {
  const res = await fetch(`${API_BASE}/api/health`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get health: ${res.status}`);
  return res.json();
}

// Risk scoring (Module 3)
export type RiskScoreRequest = {
  cvss_score: number;
  asset_criticality?: number;
  exploitability?: number;
  asset_type?: string;
  has_public_exploit?: boolean;
  is_internet_facing?: boolean;
  has_sensitive_data?: boolean;
};

export type RiskScoreResponse = {
  cvss_score: number;
  risk_score: number;
  risk_level: string;
  asset_criticality_multiplier: number;
  exploitability_multiplier: number;
  calculation_details: {
    base_score: number;
    criticality_adjustment: number;
    exploitability_adjustment: number;
    context_adjustments: string[];
    final_calculation: string;
  };
};

export async function calculateRisk(params: RiskScoreRequest): Promise<RiskScoreResponse> {
  const queryParams = new URLSearchParams();
  queryParams.append("cvss_score", params.cvss_score.toString());
  if (params.asset_criticality) queryParams.append("asset_criticality", params.asset_criticality.toString());
  if (params.exploitability) queryParams.append("exploitability", params.exploitability.toString());
  if (params.asset_type) queryParams.append("asset_type", params.asset_type);
  if (params.has_public_exploit) queryParams.append("has_public_exploit", params.has_public_exploit.toString());
  if (params.is_internet_facing) queryParams.append("is_internet_facing", params.is_internet_facing.toString());
  if (params.has_sensitive_data) queryParams.append("has_sensitive_data", params.has_sensitive_data.toString());

  const res = await fetch(`${API_BASE}/api/risk/calculate?${queryParams.toString()}`, {
    method: "GET",
  });
  if (!res.ok) throw new Error(`Failed to calculate risk: ${res.status}`);
  return res.json();
}

// Finding filter types
export type FindingFilterParams = {
  finding_types?: string[];
  scan_ids?: string[];
  created_after?: string;
  created_before?: string;
  search_text?: string;
  sort_by?: "created_at" | "finding_type";
  sort_direction?: "asc" | "desc";
  limit?: number;
  offset?: number;
};

export type FindingListResponse = {
  findings: Finding[];
  total_count: number;
  limit: number;
  offset: number;
};

// Filter findings with advanced criteria
export async function filterFindings(params: FindingFilterParams): Promise<FindingListResponse> {
  const queryParams = new URLSearchParams();
  
  if (params.finding_types && params.finding_types.length > 0) {
    queryParams.append("finding_types", params.finding_types.join(","));
  }
  
  if (params.scan_ids && params.scan_ids.length > 0) {
    queryParams.append("scan_ids", params.scan_ids.join(","));
  }
  
  if (params.created_after) {
    queryParams.append("created_after", params.created_after);
  }
  
  if (params.created_before) {
    queryParams.append("created_before", params.created_before);
  }
  
  if (params.search_text) {
    queryParams.append("search_text", params.search_text);
  }
  
  if (params.sort_by) {
    queryParams.append("sort_by", params.sort_by);
  }
  
  if (params.sort_direction) {
    queryParams.append("sort_direction", params.sort_direction);
  }
  
  if (params.limit !== undefined) {
    queryParams.append("limit", params.limit.toString());
  }
  
  if (params.offset !== undefined) {
    queryParams.append("offset", params.offset.toString());
  }
  
  const res = await fetch(`${API_BASE}/api/findings/filter?${queryParams.toString()}`, {
    cache: "no-store",
  });
  
  if (!res.ok) throw new Error(`Failed to filter findings: ${res.status}`);
  return res.json();
}

// Get all distinct finding types for filter UI
export async function getFindingTypes(): Promise<string[]> {
  const res = await fetch(`${API_BASE}/api/findings/types`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get finding types: ${res.status}`);
  return res.json();
}

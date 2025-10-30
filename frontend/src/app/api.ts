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

export async function listAssets(min_confidence = 0, limit?: number, offset?: number): Promise<Asset[]> {
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

// Risk scoring (Module 3)
export async function scoreRisk(body: { cvss_base: number; asset_criticality_weight: number; exploitability_multiplier: number; }): Promise<{ risk_score: number; components: Record<string, number>; }> {
  const res = await fetch(`${API_BASE}/api/risk/score`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Failed to score risk: ${res.status}`);
  return res.json();
}

-- Migration 009: Complete refactor of discovery and scanning flow
-- This migration separates Discovery (passive asset reconnaissance) from 
-- Security Scanning (active security assessment)

-- ============================================================================
-- PART 1: NEW DISCOVERY INFRASTRUCTURE
-- ============================================================================

-- Discovery runs track each discovery execution
CREATE TABLE IF NOT EXISTS discovery_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status VARCHAR(20) NOT NULL DEFAULT 'pending', 
    -- Status: pending, running, completed, failed, cancelled
    trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual',
    -- Trigger: manual, scheduled, seed_added
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    seeds_processed INTEGER DEFAULT 0,
    assets_discovered INTEGER DEFAULT 0,
    assets_updated INTEGER DEFAULT 0,
    error_message TEXT,
    config JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_discovery_runs_status ON discovery_runs(status);
CREATE INDEX IF NOT EXISTS idx_discovery_runs_created_at ON discovery_runs(created_at DESC);

-- ============================================================================
-- PART 2: ASSET LIFECYCLE IMPROVEMENTS
-- ============================================================================

-- Add lifecycle tracking to assets
ALTER TABLE assets 
ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ DEFAULT NOW(),
ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ DEFAULT NOW(),
ADD COLUMN IF NOT EXISTS last_discovery_run_id UUID REFERENCES discovery_runs(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active',
ADD COLUMN IF NOT EXISTS discovery_method VARCHAR(100);

-- Add index for status filtering
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen_at DESC);

-- Asset sources track discovery source details (supports multiple sources per asset)
CREATE TABLE IF NOT EXISTS asset_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    discovery_run_id UUID REFERENCES discovery_runs(id) ON DELETE SET NULL,
    source_type VARCHAR(50) NOT NULL, 
    -- Types: shodan, crtsh, certspotter, virustotal, dns_resolution, tls_certificate, 
    --        cidr_expansion, reverse_dns, seed, user_input
    source_confidence FLOAT NOT NULL DEFAULT 0.5,
    raw_data JSONB DEFAULT '{}',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, source_type, discovery_run_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_sources_asset ON asset_sources(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_sources_discovery_run ON asset_sources(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_asset_sources_type ON asset_sources(source_type);

-- ============================================================================
-- PART 3: SECURITY SCANNING (separate from discovery)
-- ============================================================================

-- Security scans are active assessments of known assets
CREATE TABLE IF NOT EXISTS security_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
    -- Types: port_scan, tls_analysis, http_probe, threat_intel, full
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- Status: pending, running, completed, failed, cancelled
    trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual',
    -- Trigger: manual, scheduled, discovery, on_change
    priority INTEGER DEFAULT 5 CHECK (priority >= 1 AND priority <= 10),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    note TEXT,
    config JSONB DEFAULT '{}',
    result_summary JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_scans_asset ON security_scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_security_scans_status ON security_scans(status);
CREATE INDEX IF NOT EXISTS idx_security_scans_created_at ON security_scans(created_at DESC);

-- Security findings from scans (more structured than generic findings)
CREATE TABLE IF NOT EXISTS security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    security_scan_id UUID REFERENCES security_scans(id) ON DELETE SET NULL,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    finding_type VARCHAR(100) NOT NULL,
    -- Types: open_port, weak_tls, expired_cert, http_security_header_missing, 
    --        malware_detected, reputation_issue, dns_issue, etc.
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    -- Severity: critical, high, medium, low, info
    title VARCHAR(500) NOT NULL,
    description TEXT,
    remediation TEXT,
    data JSONB NOT NULL DEFAULT '{}',
    -- Status tracking
    status VARCHAR(20) DEFAULT 'open',
    -- Status: open, acknowledged, in_progress, resolved, false_positive, accepted
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id),
    -- Metadata
    cvss_score FLOAT,
    cve_ids TEXT[],
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_findings_asset ON security_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_scan ON security_findings(security_scan_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_security_findings_status ON security_findings(status);
CREATE INDEX IF NOT EXISTS idx_security_findings_type ON security_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_security_findings_first_seen ON security_findings(first_seen_at DESC);

-- ============================================================================
-- PART 4: ASSET RELATIONSHIPS (improved graph model)
-- ============================================================================

-- Explicit relationship table for asset graph
CREATE TABLE IF NOT EXISTS asset_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relationship_type VARCHAR(50) NOT NULL,
    -- Types: resolves_to, reverse_resolves_to, has_subdomain, has_certificate,
    --        belongs_to_org, belongs_to_asn, discovered_via
    confidence FLOAT DEFAULT 1.0,
    metadata JSONB DEFAULT '{}',
    discovery_run_id UUID REFERENCES discovery_runs(id) ON DELETE SET NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_asset_relationships_source ON asset_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_relationships_target ON asset_relationships(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_relationships_type ON asset_relationships(relationship_type);

-- ============================================================================
-- PART 5: DISCOVERY QUEUE (for async processing)
-- ============================================================================

CREATE TABLE IF NOT EXISTS discovery_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    discovery_run_id UUID NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
    item_type VARCHAR(20) NOT NULL, -- seed, domain, organization, asn, ip
    item_value TEXT NOT NULL,
    parent_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    seed_id UUID REFERENCES seeds(id) ON DELETE SET NULL,
    depth INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 5,
    status VARCHAR(20) DEFAULT 'pending', -- pending, processing, completed, failed, skipped
    error_message TEXT,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(discovery_run_id, item_type, item_value)
);

CREATE INDEX IF NOT EXISTS idx_discovery_queue_run ON discovery_queue(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_discovery_queue_status ON discovery_queue(status);
CREATE INDEX IF NOT EXISTS idx_discovery_queue_priority ON discovery_queue(priority DESC);

-- ============================================================================
-- PART 6: MIGRATE EXISTING DATA
-- ============================================================================

-- Update existing assets with lifecycle data
UPDATE assets 
SET first_seen_at = created_at,
    last_seen_at = updated_at,
    status = 'active'
WHERE first_seen_at IS NULL;

-- Set default discovery method based on sources
UPDATE assets 
SET discovery_method = 
    CASE 
        WHEN sources::text LIKE '%shodan%' THEN 'shodan'
        WHEN sources::text LIKE '%crt.sh%' THEN 'crtsh'
        WHEN sources::text LIKE '%dns%' THEN 'dns_resolution'
        WHEN sources::text LIKE '%seed%' THEN 'seed'
        WHEN sources::text LIKE '%scan%' THEN 'scan'
        ELSE 'unknown'
    END
WHERE discovery_method IS NULL;

-- ============================================================================
-- PART 7: COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE discovery_runs IS 'Tracks each execution of the discovery process';
COMMENT ON TABLE asset_sources IS 'Records which sources contributed to discovering each asset';
COMMENT ON TABLE security_scans IS 'Active security assessments of known assets';
COMMENT ON TABLE security_findings IS 'Security issues discovered during scans';
COMMENT ON TABLE asset_relationships IS 'Graph relationships between assets';
COMMENT ON TABLE discovery_queue IS 'Queue for async discovery processing';

COMMENT ON COLUMN assets.first_seen_at IS 'When this asset was first discovered';
COMMENT ON COLUMN assets.last_seen_at IS 'When this asset was last confirmed to exist';
COMMENT ON COLUMN assets.status IS 'Asset lifecycle status: active, stale, removed';
COMMENT ON COLUMN assets.discovery_method IS 'Primary method used to discover this asset';

COMMENT ON COLUMN security_findings.severity IS 'Finding severity: critical, high, medium, low, info';
COMMENT ON COLUMN security_findings.status IS 'Finding status: open, acknowledged, in_progress, resolved, false_positive, accepted';


-- Initial database schema for EASM backend

-- Create custom types
CREATE TYPE scan_status AS ENUM ('queued', 'running', 'completed', 'failed');
CREATE TYPE asset_type AS ENUM ('domain', 'ip', 'port', 'certificate');
CREATE TYPE seed_type AS ENUM ('domain', 'asn', 'cidr', 'organization', 'keyword');

-- Scans table
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    target VARCHAR NOT NULL,
    note TEXT,
    status scan_status NOT NULL DEFAULT 'queued',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_type VARCHAR NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Assets table
CREATE TABLE assets (
    id UUID PRIMARY KEY,
    asset_type asset_type NOT NULL,
    identifier VARCHAR NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    sources JSONB NOT NULL DEFAULT '[]',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_type, identifier)
);

-- Seeds table
CREATE TABLE seeds (
    id UUID PRIMARY KEY,
    seed_type seed_type NOT NULL,
    value VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(seed_type, value)
);

-- Evidence table
CREATE TABLE evidence (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    filename VARCHAR NOT NULL,
    content_type VARCHAR NOT NULL,
    file_size BIGINT NOT NULL,
    file_path VARCHAR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_type ON findings(finding_type);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_confidence ON assets(confidence);
CREATE INDEX idx_evidence_scan_id ON evidence(scan_id);
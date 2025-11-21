-- Add indexes for finding filter performance
-- These indexes optimize the advanced finding filter queries

-- Index for date range filtering
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);

-- Composite index for common filter combinations (type + date)
CREATE INDEX IF NOT EXISTS idx_findings_type_created_at ON findings(finding_type, created_at DESC);

-- Composite index for scan + date filtering
CREATE INDEX IF NOT EXISTS idx_findings_scan_created_at ON findings(scan_id, created_at DESC);

-- GIN index for JSONB data field to support full-text search and JSONB queries
CREATE INDEX IF NOT EXISTS idx_findings_data_gin ON findings USING GIN (data);

-- GIN index for text search on data field (PostgreSQL specific)
-- This enables efficient ILIKE searches on the JSONB data converted to text
CREATE INDEX IF NOT EXISTS idx_findings_data_text ON findings USING GIN (to_tsvector('english', data::text));

-- Composite index for multi-column filtering (type + scan)
CREATE INDEX IF NOT EXISTS idx_findings_type_scan ON findings(finding_type, scan_id);

-- Add comment explaining the indexes
COMMENT ON INDEX idx_findings_created_at IS 'Optimizes date range filtering on findings';
COMMENT ON INDEX idx_findings_type_created_at IS 'Optimizes filtering by type with date sorting';
COMMENT ON INDEX idx_findings_scan_created_at IS 'Optimizes filtering by scan with date sorting';
COMMENT ON INDEX idx_findings_data_gin IS 'Enables efficient JSONB queries and containment operations';
COMMENT ON INDEX idx_findings_data_text IS 'Enables full-text search on JSONB data content';
COMMENT ON INDEX idx_findings_type_scan IS 'Optimizes filtering by both type and scan_id';


-- Migration 013: Asset Tagging System
-- This migration adds support for tagging assets with optional auto-tagging rules

-- ============================================================================
-- PART 1: TAGS TABLE
-- ============================================================================

-- Tags table stores tag definitions with optional auto-tagging rules
CREATE TABLE IF NOT EXISTS tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    -- Default importance value applied to tagged assets (1-5 scale)
    importance INTEGER NOT NULL DEFAULT 3 CHECK (importance >= 1 AND importance <= 5),
    -- Auto-tagging rule type: 'regex' for string matching, 'ip_range' for CIDR ranges, NULL for manual only
    rule_type VARCHAR(20) CHECK (rule_type IN ('regex', 'ip_range') OR rule_type IS NULL),
    -- The actual rule value: regex pattern or CIDR notation
    rule_value TEXT,
    -- Color for UI display (hex color code)
    color VARCHAR(7) DEFAULT '#6366f1',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- PART 2: ASSET TAGS JUNCTION TABLE
-- ============================================================================

-- Junction table for many-to-many relationship between assets and tags
CREATE TABLE IF NOT EXISTS asset_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    -- How this tag was applied
    applied_by VARCHAR(20) NOT NULL DEFAULT 'manual' CHECK (applied_by IN ('manual', 'auto_rule')),
    -- Which rule matched (for auto-tagged items)
    matched_rule TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Unique constraint to prevent duplicate tagging
    UNIQUE(asset_id, tag_id)
);

-- ============================================================================
-- PART 3: INDEXES FOR PERFORMANCE
-- ============================================================================

-- Index for finding tags by name
CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);

-- Index for filtering by rule type (for auto-tagging queries)
CREATE INDEX IF NOT EXISTS idx_tags_rule_type ON tags(rule_type) WHERE rule_type IS NOT NULL;

-- Indexes for the junction table
CREATE INDEX IF NOT EXISTS idx_asset_tags_asset_id ON asset_tags(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_tag_id ON asset_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_applied_by ON asset_tags(applied_by);

-- ============================================================================
-- PART 4: COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE tags IS 'Tag definitions with optional auto-tagging rules';
COMMENT ON COLUMN tags.name IS 'Unique tag name for display and identification';
COMMENT ON COLUMN tags.description IS 'Optional description of what this tag represents';
COMMENT ON COLUMN tags.importance IS 'Default importance value (1-5) applied to tagged assets';
COMMENT ON COLUMN tags.rule_type IS 'Auto-tagging rule type: regex for string matching, ip_range for CIDR ranges';
COMMENT ON COLUMN tags.rule_value IS 'The actual rule: regex pattern or CIDR notation';
COMMENT ON COLUMN tags.color IS 'Hex color code for UI display';

COMMENT ON TABLE asset_tags IS 'Junction table linking assets to their tags';
COMMENT ON COLUMN asset_tags.applied_by IS 'How this tag was applied: manual or auto_rule';
COMMENT ON COLUMN asset_tags.matched_rule IS 'The rule that matched when auto-tagged';


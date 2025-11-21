-- Add new asset types
ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'organization';
ALTER TYPE asset_type ADD VALUE IF NOT EXISTS 'asn';

-- Add lineage columns to assets table
ALTER TABLE assets 
ADD COLUMN seed_id UUID REFERENCES seeds(id) ON DELETE SET NULL,
ADD COLUMN parent_id UUID REFERENCES assets(id) ON DELETE SET NULL;

-- Add indexes for lineage queries
CREATE INDEX idx_assets_seed_id ON assets(seed_id);
CREATE INDEX idx_assets_parent_id ON assets(parent_id);

-- Scope tags and asset tags by company

-- Add company_id to tags
ALTER TABLE tags ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE tags SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE tags ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE tags
    ADD CONSTRAINT fk_tags_company
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

-- Drop global unique constraint and enforce company-scoped uniqueness
ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_company_name ON tags(company_id, name);
CREATE INDEX IF NOT EXISTS idx_tags_company_id ON tags(company_id);

-- Add company_id to asset_tags
ALTER TABLE asset_tags ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE asset_tags at
SET company_id = a.company_id
FROM assets a
WHERE at.asset_id = a.id AND at.company_id IS NULL;
ALTER TABLE asset_tags ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE asset_tags
    ADD CONSTRAINT fk_asset_tags_company
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

-- Replace global unique constraint with company-scoped
ALTER TABLE asset_tags DROP CONSTRAINT IF EXISTS asset_tags_asset_id_tag_id_key;
ALTER TABLE asset_tags
    ADD CONSTRAINT asset_tags_company_asset_tag_key
    UNIQUE (company_id, asset_id, tag_id);

CREATE INDEX IF NOT EXISTS idx_asset_tags_company_id ON asset_tags(company_id);

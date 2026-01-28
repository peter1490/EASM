-- Create companies table
CREATE TABLE IF NOT EXISTS companies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert Default Company
INSERT INTO companies (id, name) VALUES ('00000000-0000-0000-0000-000000000000', 'Default Company')
ON CONFLICT (id) DO NOTHING;

-- User Companies (Many-to-Many)
CREATE TABLE IF NOT EXISTS user_companies (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer', -- Role within the company (admin, operator, etc.)
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, company_id)
);

-- Assign all existing users to Default Company as Admin (for now, to maintain access)
INSERT INTO user_companies (user_id, company_id, role)
SELECT id, '00000000-0000-0000-0000-000000000000', 'admin'
FROM users
ON CONFLICT DO NOTHING;

-- Update Assets table
ALTER TABLE assets ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE assets SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE assets ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE assets ADD CONSTRAINT fk_assets_company FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

-- Drop old unique constraint on assets and add new one scoped to company
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_asset_type_identifier_key;
ALTER TABLE assets ADD CONSTRAINT assets_company_type_identifier_key UNIQUE (company_id, asset_type, identifier);

-- Update Seeds table
ALTER TABLE seeds ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE seeds SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE seeds ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE seeds ADD CONSTRAINT fk_seeds_company FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

-- Drop old unique constraint on seeds and add new one scoped to company
ALTER TABLE seeds DROP CONSTRAINT IF EXISTS seeds_seed_type_value_key;
ALTER TABLE seeds ADD CONSTRAINT seeds_company_type_value_key UNIQUE (company_id, seed_type, value);

-- Update Scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE scans SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE scans ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE scans ADD CONSTRAINT fk_scans_company FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_assets_company_id ON assets(company_id);
CREATE INDEX IF NOT EXISTS idx_seeds_company_id ON seeds(company_id);
CREATE INDEX IF NOT EXISTS idx_scans_company_id ON scans(company_id);

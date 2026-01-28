-- Add company_id to blacklist entries for multi-tenancy
ALTER TABLE blacklist ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE blacklist SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE blacklist ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE blacklist
    ADD CONSTRAINT fk_blacklist_company
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

-- Replace global index with company-scoped unique index
DROP INDEX IF EXISTS idx_blacklist_type_value;
CREATE UNIQUE INDEX IF NOT EXISTS idx_blacklist_company_type_value
    ON blacklist(company_id, object_type, object_value);

CREATE INDEX IF NOT EXISTS idx_blacklist_company_id ON blacklist(company_id);
CREATE INDEX IF NOT EXISTS idx_blacklist_company_object_type ON blacklist(company_id, object_type);

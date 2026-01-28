-- Add company_id to discovery_runs
ALTER TABLE discovery_runs ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE discovery_runs SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE discovery_runs ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE discovery_runs ADD CONSTRAINT fk_discovery_runs_company FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_discovery_runs_company_id ON discovery_runs(company_id);

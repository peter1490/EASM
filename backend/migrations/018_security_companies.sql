-- Add company_id to security_scans
ALTER TABLE security_scans ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE security_scans SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE security_scans ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE security_scans ADD CONSTRAINT fk_security_scans_company FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_security_scans_company_id ON security_scans(company_id);

-- Add company_id to security_findings
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS company_id UUID;
UPDATE security_findings SET company_id = '00000000-0000-0000-0000-000000000000' WHERE company_id IS NULL;
ALTER TABLE security_findings ALTER COLUMN company_id SET NOT NULL;
ALTER TABLE security_findings ADD CONSTRAINT fk_security_findings_company FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_security_findings_company_id ON security_findings(company_id);

-- Add company_id to findings table
ALTER TABLE findings ADD COLUMN company_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';
CREATE INDEX idx_findings_company_id ON findings(company_id);

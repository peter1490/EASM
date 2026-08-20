-- The asset list's default ordering, so the sort is index-provided.
--
-- Without it, `ORDER BY importance DESC, confidence DESC, created_at DESC`
-- forces a sort over every asset in the tenant *before* LIMIT applies, which in
-- turn makes the latest-scan and open-finding laterals in `assets_enriched` run
-- for the whole set rather than for the page being returned.
CREATE INDEX IF NOT EXISTS idx_assets_company_list_order
    ON assets (company_id, importance DESC, confidence DESC, created_at DESC);

-- The findings list is always ordered by first_seen_at within a company.
CREATE INDEX IF NOT EXISTS idx_security_findings_company_first_seen
    ON security_findings (company_id, first_seen_at DESC);

-- The scan list is always ordered by created_at within a company.
CREATE INDEX IF NOT EXISTS idx_security_scans_company_created
    ON security_scans (company_id, created_at DESC);

-- Asset list enrichment: latest scan + open-finding rollup, in one place.
--
-- Two problems this fixes.
--
-- 1. The `latest_scans` CTE was copy-pasted into eight queries in asset_repo.rs,
--    and two further queries hard-coded the same columns to NULL — so
--    /api/risk/high-risk-assets claimed every high-risk asset had never been
--    scanned. One view, one definition.
--
-- 2. Nothing anywhere joined assets to security_findings, so a list could not
--    show "3 critical, 2 high" without one request per row. The rollup lateral
--    below does it in the same pass.
--
-- The lifecycle columns added in 009 (first_seen_at, last_seen_at,
-- last_discovery_run_id, status, discovery_method) were never selected by any
-- read path, which is why every asset reported status "active" and no
-- first/last-seen at all. Selecting `a.*` here brings them back.

CREATE OR REPLACE VIEW assets_enriched AS
SELECT
    a.*,
    ls.id           AS last_scan_id,
    ls.status::text AS last_scan_status,
    ls.created_at   AS last_scanned_at,
    COALESCE(fr.open_critical, 0) AS open_critical,
    COALESCE(fr.open_high, 0)     AS open_high,
    COALESCE(fr.open_medium, 0)   AS open_medium,
    COALESCE(fr.open_low, 0)      AS open_low,
    COALESCE(fr.open_info, 0)     AS open_info,
    COALESCE(fr.open_total, 0)    AS open_total
FROM assets a
LEFT JOIN LATERAL (
    SELECT s.id, s.status, s.created_at
    FROM security_scans s
    WHERE s.asset_id = a.id
      AND s.company_id = a.company_id
    ORDER BY s.created_at DESC
    LIMIT 1
) ls ON TRUE
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) FILTER (WHERE f.severity = 'critical') AS open_critical,
        COUNT(*) FILTER (WHERE f.severity = 'high')     AS open_high,
        COUNT(*) FILTER (WHERE f.severity = 'medium')   AS open_medium,
        COUNT(*) FILTER (WHERE f.severity = 'low')      AS open_low,
        COUNT(*) FILTER (WHERE f.severity = 'info')     AS open_info,
        COUNT(*)                                        AS open_total
    FROM security_findings f
    WHERE f.asset_id = a.id
      AND f.company_id = a.company_id
      -- Keep in step with ACTIVE_FINDING_STATUSES in models/security.rs.
      AND f.status IN ('open', 'acknowledged', 'in_progress')
) fr ON TRUE;

-- Indexes the two laterals need. Every query in this codebase is company-scoped
-- but every existing index was single-column, so each asset page was sorting the
-- tenant's entire scan history.
CREATE INDEX IF NOT EXISTS idx_security_scans_company_asset_created
    ON security_scans (company_id, asset_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_findings_company_asset_status
    ON security_findings (company_id, asset_id, status);

-- Supporting the aggregate endpoints (/api/risk/overview, findings summary).
CREATE INDEX IF NOT EXISTS idx_security_findings_company_severity
    ON security_findings (company_id, severity);

CREATE INDEX IF NOT EXISTS idx_security_findings_company_status
    ON security_findings (company_id, status);

CREATE INDEX IF NOT EXISTS idx_security_scans_company_status
    ON security_scans (company_id, status);

CREATE INDEX IF NOT EXISTS idx_assets_company_confidence
    ON assets (company_id, confidence DESC);

CREATE INDEX IF NOT EXISTS idx_assets_company_risk_level
    ON assets (company_id, risk_level);

-- Pure write amplification: both duplicate an existing index's leading columns.
DROP INDEX IF EXISTS idx_finding_type_config_finding_type;
DROP INDEX IF EXISTS idx_assets_company_id;

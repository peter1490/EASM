-- Say "Cancelled", not "Never", when a cancellation is the whole story.
--
-- Migration 033 stopped a cancelled scan from being reported as the asset's last
-- scan, which is right -- it looked at nothing -- but the column then fell all
-- the way back to "Never", which is the one thing an operator who has just
-- stopped a scan already knows is wrong. "Never" and "we tried and you stopped
-- it" are different states and the surface has to tell them apart.
--
-- So the newest cancelled scan is carried alongside, and the column reads:
--
--   last_scanned_at        -> the newest scan that actually looked (033's rule)
--   last_cancelled_scan_at -> else "Cancelled", when one was stopped
--   neither                -> "Never"
--
-- Kept as its own column rather than folded back into last_scan_status, because
-- `last_scan_id IS NOT NULL` is what the "Scanned" facet and the never-scanned
-- rollup on the overview mean by scanned. An asset whose only scan was cancelled
-- has still never been scanned; it just now says why.
--
-- Populated whenever a cancelled scan exists, not only when it is the whole
-- history: an asset scanned last week and stopped this morning keeps reporting
-- last week's scan, and the cancellation stays available to anything that wants
-- to show both.

-- Dropped and rebuilt rather than replaced: CREATE OR REPLACE VIEW can only
-- append columns, and the new one belongs next to the scan columns it qualifies
-- rather than trailing the finding rollup. Nothing else in the schema selects
-- from this view, so the DROP is deliberately left without CASCADE -- if that
-- ever stops being true, this migration should fail rather than take the
-- dependent object with it.
DROP VIEW IF EXISTS assets_enriched;

CREATE VIEW assets_enriched AS
SELECT
    a.*,
    ls.id           AS last_scan_id,
    ls.status::text AS last_scan_status,
    ls.created_at   AS last_scanned_at,
    cs.created_at   AS last_cancelled_scan_at,
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
      AND s.status <> 'cancelled'
    ORDER BY s.created_at DESC
    LIMIT 1
) ls ON TRUE
LEFT JOIN LATERAL (
    SELECT s.created_at
    FROM security_scans s
    WHERE s.asset_id = a.id
      AND s.company_id = a.company_id
      AND s.status = 'cancelled'
    ORDER BY s.created_at DESC
    LIMIT 1
) cs ON TRUE
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

-- The cancelled lateral is the one that cannot early-exit: on the ordinary asset
-- with no cancelled scan it would walk that asset's whole scan history to prove
-- it, once per row on every list page. A partial index holds only the cancelled
-- rows -- a small fraction of the table, and a scan reaches that status at most
-- once -- so the lookup is a single probe and writes barely notice.
CREATE INDEX IF NOT EXISTS idx_security_scans_cancelled_by_asset
    ON security_scans (company_id, asset_id, created_at DESC)
    WHERE status = 'cancelled';

COMMENT ON VIEW assets_enriched IS
    'Assets with their latest non-cancelled scan, the latest cancelled one, and an open-finding rollup. last_scan_* describe the newest scan that actually ran; last_cancelled_scan_at is what the UI shows when nothing else did.';

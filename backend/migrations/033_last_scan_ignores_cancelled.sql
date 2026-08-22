-- A cancelled scan is not a scan of the asset, and must not be reported as one.
--
-- `assets_enriched` picked the newest `security_scans` row per asset with no
-- regard for its status, so cancelling a scan -- from the stop button on its row
-- in Ops, or wholesale by stopping the discovery run that queued it, or by
-- blacklisting the target mid-run -- promoted that cancelled row to the asset's
-- "last scan". Surface then showed a fresh timestamp under LAST SCAN for a host
-- that had just been left unscanned, and an asset whose only scan was cancelled
-- read as scanned seconds ago rather than never. Migration 032 made this visible
-- on every stopped run at once, because stopping a run now cancels every scan it
-- had outstanding.
--
-- The distinction the column needs is "did we look at this host?", so only
-- `cancelled` is excluded. A `failed` scan did look and reports what it hit;
-- `pending` and `running` are what the list renders as queued and in flight, and
-- dropping those would make a scan vanish from the column for as long as it ran.
-- With every scan of an asset cancelled, the lateral now yields no row, the
-- three last_scan_* columns come back NULL, and the UI reads "Never" -- the same
-- state as an asset that was never scanned, which is what it is.
--
-- No new index: `idx_security_scans_company_asset_created` still drives the
-- lateral, and the LIMIT 1 walk stops at the newest surviving scan, so the added
-- filter costs one index tuple per cancelled scan sitting at the top of that
-- asset's history.

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
      AND s.status <> 'cancelled'
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

COMMENT ON VIEW assets_enriched IS
    'Assets with their latest non-cancelled scan and open-finding rollup. A cancelled scan leaves last_scan_* NULL unless an earlier scan survives it.';

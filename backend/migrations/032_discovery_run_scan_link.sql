-- Discovery-triggered scans record the run that queued them.
--
-- Auto-scans are submitted by discovery through the ordinary scan path, so once
-- the row was written nothing tied it back to the run. Stopping a discovery
-- therefore cancelled the discovery task and left its scans probing targets the
-- operator had just asked us to stop touching -- and, when the stop was a
-- blacklist decision, kept scanning the very host that was blacklisted.
--
-- The column is nullable: manual and scheduled scans have no run.
ALTER TABLE security_scans
    ADD COLUMN IF NOT EXISTS discovery_run_id UUID REFERENCES discovery_runs(id) ON DELETE SET NULL;

-- Cancelling a run reads this by (run, status), and only ever for scans that are
-- still in flight; the partial index keeps that lookup off the full scan table.
CREATE INDEX IF NOT EXISTS idx_security_scans_discovery_run
    ON security_scans(discovery_run_id)
    WHERE discovery_run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_security_scans_active_by_run
    ON security_scans(discovery_run_id, status)
    WHERE status IN ('pending', 'running');

COMMENT ON COLUMN security_scans.discovery_run_id IS
    'Discovery run that auto-triggered this scan; NULL for manual and scheduled scans';

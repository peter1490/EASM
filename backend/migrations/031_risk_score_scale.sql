-- Risk scoring moves from a clamped 0–100 to a 0–1000 hazard model.
--
-- The previous score was `min(100, (exposure + Σ findings) × importance)`. A sum with
-- no ceiling against a display range with a hard one saturates: measured over a
-- synthetic population of 4,000 assets, 41% landed on exactly 100.0 and the worst 400
-- assets shared a single score, so the triage queue was ordered arbitrarily wherever
-- it mattered most. Two findings of CVSS 9.8 were enough to reach the cap.
--
-- The replacement scores each finding as impact × likelihood — using the CISA KEV and
-- FIRST EPSS signals the scanners were already recording and scoring never read —
-- folds them into an additive hazard, and projects that onto 0–1000 with a
-- log-logistic curve that approaches the ceiling without ever reaching it. See
-- `services/risk_model.rs`.
--
-- 0–1000 is the range Qualys TruRisk, Tenable AES and Rapid7 Active Risk all settled
-- on, for the same reason: a hundred integers cannot separate the assets that matter.

-- History rows carry the scale they were computed on, so a trend chart spanning the
-- change does not read a 0–100 score as a collapse from a 0–1000 one. Existing rows
-- are stamped 100; everything written from here on is 1000.
ALTER TABLE asset_risk_history
    ADD COLUMN IF NOT EXISTS scale_max INTEGER NOT NULL DEFAULT 1000;

UPDATE asset_risk_history SET scale_max = 100 WHERE calculated_at < NOW();

-- Live scores are stale rather than wrong-scaled: every band boundary moved and the
-- model changed shape, so rescaling by 10 would invent numbers the new model would
-- never produce. Clear them and let the next run recalculate. `risk_level` goes with
-- the score — a level with no score behind it is what the asset list would otherwise
-- filter on.
--
-- Assets read as "pending calculation" until then, which the overview already
-- reports via `assets_pending_calculation`.
UPDATE assets
SET risk_score = NULL,
    risk_level = NULL,
    last_risk_run = NULL
WHERE risk_score IS NOT NULL;

COMMENT ON COLUMN assets.risk_score IS
    'Asset risk on a 0-1000 scale (services/risk_model.rs). Bands: critical >= 800, high >= 600, medium >= 400, low >= 200, info below.';
COMMENT ON COLUMN asset_risk_history.scale_max IS
    'Top of the scale this row was scored on. 100 for rows predating the hazard model, 1000 after.';

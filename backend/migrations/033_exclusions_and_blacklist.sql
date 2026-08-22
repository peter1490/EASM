-- The blacklist becomes the exclusion list, and grows a hard mode.
--
-- The table has always held two different intentions under one name. Most
-- entries mean "stop discovering more of this" -- a CDN, a shared host, a
-- provider netblock -- and the assets already found under them are still real
-- assets the operator wants scanned and scored. A few mean "this is not ours,
-- erase it", which is a different thing entirely and was never expressible.
--
-- So: `blacklist` is renamed `exclusions`, which is what the UI has called it
-- for a while, and `blacklisted` marks the entries that mean the hard thing.
-- Defaulting it to FALSE keeps every existing row on the soft behaviour, which
-- is the one they were almost certainly created for.

ALTER TABLE IF EXISTS blacklist RENAME TO exclusions;

-- Indexes and constraints keep the old table's name until they are renamed too,
-- which makes every later migration that touches them read as a mistake.
ALTER INDEX IF EXISTS blacklist_pkey RENAME TO exclusions_pkey;
ALTER INDEX IF EXISTS idx_blacklist_object_type RENAME TO idx_exclusions_object_type;
ALTER INDEX IF EXISTS idx_blacklist_value_pattern RENAME TO idx_exclusions_value_pattern;
ALTER INDEX IF EXISTS idx_blacklist_company_type_value RENAME TO idx_exclusions_company_type_value;
ALTER INDEX IF EXISTS idx_blacklist_company_id RENAME TO idx_exclusions_company_id;
ALTER INDEX IF EXISTS idx_blacklist_company_object_type RENAME TO idx_exclusions_company_object_type;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_blacklist_company') THEN
        ALTER TABLE exclusions RENAME CONSTRAINT fk_blacklist_company TO fk_exclusions_company;
    END IF;
END $$;

-- The hard mode. An excluded object is left alone by discovery but keeps the
-- assets already found under it; a blacklisted one is deleted outright and
-- never written again, so it reaches no score, no scan and no list.
ALTER TABLE exclusions ADD COLUMN IF NOT EXISTS blacklisted BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial: discovery asks "is this one of the hard ones?" on every check, and
-- the hard ones are the small minority.
CREATE INDEX IF NOT EXISTS idx_exclusions_company_blacklisted
    ON exclusions(company_id) WHERE blacklisted;

COMMENT ON TABLE exclusions IS 'Objects discovery must not expand on; blacklisted ones are additionally deleted and never stored';
COMMENT ON COLUMN exclusions.object_type IS 'Type: domain, ip, organization, asn, cidr, certificate';
COMMENT ON COLUMN exclusions.object_value IS 'The value to exclude (e.g., cloudflare.com, 192.168.1.0/24)';
COMMENT ON COLUMN exclusions.reason IS 'Optional explanation for why this was excluded';
COMMENT ON COLUMN exclusions.blacklisted IS 'TRUE: purge matching assets and never store them again. FALSE: keep and keep scanning what is already known.';

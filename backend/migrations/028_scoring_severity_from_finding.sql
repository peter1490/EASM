-- Risk scoring: a finding's base score comes from the finding's own severity.
--
-- `finding_type_config` used to carry a `severity_score` that overrode it. Because
-- the scorer looked the row up by `finding_type`, every finding of a type shared one
-- score and the per-finding severity the scanners compute was silently discarded:
-- a HIGH "Missing Content-Security-Policy" and a LOW "Missing Referrer-Policy" are
-- both `missing_security_header`, so both scored 3.0 — the value seeded for the type.
-- The UI showed the real severity, the score ignored it, and the two never agreed.
--
-- The config's job is now exactly one thing: a per-type multiplier applied on top of
-- the finding's own severity score. `default_severity` goes with it — nothing ever
-- read it, and a type-level severity is the same mistake in a different column.

ALTER TABLE finding_type_config DROP COLUMN IF EXISTS severity_score;
ALTER TABLE finding_type_config DROP COLUMN IF EXISTS default_severity;

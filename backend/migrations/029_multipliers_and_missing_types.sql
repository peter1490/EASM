-- Recalibrate type multipliers, and reconcile the table with what scanners emit.
--
-- Now that a finding's base score comes from its own severity (migration 028), the
-- multiplier is the only thing this table contributes — so what it should express is
-- the one thing severity cannot. It wasn't doing that. Grouped by the severity each
-- type shipped with, the seeded multipliers came out perfectly monotonic:
--
--     info 1.00 · low 1.08 · medium 1.19 · high 1.57 · critical 1.83
--
-- which is severity again, in a second column. Multiplying one by the other made a
-- critical finding worth 160x an informational one and let hygiene findings saturate
-- the 0-100 scale.
--
-- A multiplier above 1.0 now means one thing: the finding type asserts the weakness is
-- reachable and usable *now*, which its severity does not say. An exposed database is
-- worse than its CVSS because it is on the internet. A missing Referrer-Policy header
-- is exactly as bad as "low" already says.

-- 1. Everything scores at its severity, unless it earns otherwise below.
UPDATE finding_type_config SET type_multiplier = 1.0, updated_at = now();

-- 2. The exceptions: active exposure, or evidence of active compromise.
UPDATE finding_type_config SET type_multiplier = 2.0, updated_at = now()
 WHERE finding_type IN (
    'default_credentials',        -- exploitable by anyone who reads the manual
    'malware_detected',           -- not a weakness; an incident
    'exploitable_vulnerability'   -- a weaponised exploit exists, not just a CVE id
 );

UPDATE finding_type_config SET type_multiplier = 1.8, updated_at = now()
 WHERE finding_type IN (
    'database_exposed',           -- the data itself, reachable from the internet
    'blocklisted_ip'              -- third parties already observed abuse from it
 );

UPDATE finding_type_config SET type_multiplier = 1.5, updated_at = now()
 WHERE finding_type IN (
    'admin_port_exposed',         -- the control plane, reachable from the internet
    'dangling_dns'                -- an attacker can claim the name today
 );

-- `known_cve` deliberately falls back to 1.0. Its severity is derived from the CVE's
-- CVSS, and the scorer already adds `cvss * 2.0` on top; a multiplier counted the same
-- CVSS a third time. A critical CVE at 9.8 scored (40 + 19.6) * 1.5 = 89.4 — one
-- finding, and the asset was capped. `critical_vulnerability` likewise: "critical" is
-- the severity, so weighting it again just says it twice.

-- 3. Types the scanners emit that had no row at all.
--
-- With no row, `score_finding` treats a type as unconfigured: it still scores, at a
-- neutral 1.0, but no admin can see or tune it. All seven are certificate or
-- inventory hygiene, so 1.0 is also the right value — the point is that it is now a
-- decision on the record rather than a gap.
INSERT INTO finding_type_config (finding_type, display_name, category, type_multiplier, description) VALUES
('certificate_hostname_mismatch', 'Certificate Hostname Mismatch', 'tls', 1.0, 'The certificate does not cover the hostname it was served for'),
('certificate_missing_san', 'Certificate Missing SAN', 'tls', 1.0, 'The certificate has no Subject Alternative Name entries'),
('certificate_not_yet_valid', 'Certificate Not Yet Valid', 'tls', 1.0, 'The certificate''s validity period has not started'),
('weak_signature_algorithm', 'Weak Signature Algorithm', 'tls', 1.0, 'The certificate is signed with a deprecated algorithm'),
('weak_key_strength', 'Weak Certificate Key', 'tls', 1.0, 'The certificate key is below the recommended strength'),
('dns_resolution_failed', 'DNS Resolution Failed', 'dns', 1.0, 'The asset could not be resolved during the scan'),
('technology_detected', 'Technology Detected', 'service', 1.0, 'A technology or product was fingerprinted on the asset')
ON CONFLICT (finding_type) DO NOTHING;

-- 4. One concept, two names. The TLS analyser emits `certificate_hostname_mismatch`
-- (added above); `mismatched_certificate` was the name in the seeded table and in the
-- `FindingType` enum, and nothing has ever emitted it. Keeping both would leave an
-- admin tuning a weight that can never apply to a finding.
DELETE FROM finding_type_config WHERE finding_type = 'mismatched_certificate';

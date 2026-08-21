-- Finding types emitted by the deep TLS, DNS and HTTP scanners.
--
-- `finding_type_config` is what lets an admin weight or silence a type, and what
-- the risk scorer reads for its multiplier. A type with no row here still scores
-- — at a neutral 1.0 — but is invisible in the settings UI, so an operator cannot
-- see it exists, let alone tune it. Every type the new scanners can emit gets a
-- row, and the multiplier is a decision on the record rather than a gap.
--
-- The multiplier convention set in migration 029 is unchanged: 1.0 means "exactly
-- as bad as its severity says", and above 1.0 is reserved for findings that
-- assert the weakness is reachable and usable *now*, which severity alone does
-- not say.

INSERT INTO finding_type_config (finding_type, display_name, category, type_multiplier, description) VALUES
-- ---------------------------------------------------------------- TLS -----
('weak_tls_version',                 'Deprecated TLS Protocol',            'tls',  1.0, 'The endpoint still negotiates SSLv2/SSLv3/TLS 1.0/TLS 1.1'),
('no_forward_secrecy',               'No Forward Secrecy',                 'tls',  1.0, 'Cipher suites without ephemeral key exchange are offered, so recorded traffic is decryptable if the key later leaks'),
-- An attack that works against the configuration as it stands, today.
('tls_vulnerability',                'TLS Vulnerability',                  'tls',  1.5, 'The endpoint is exposed to a named TLS attack (POODLE, SWEET32, Heartbleed, DROWN, …)'),
('tls_misconfiguration',             'TLS Misconfiguration',               'tls',  1.0, 'The TLS configuration is internally inconsistent, e.g. Must-Staple set without stapling'),
('certificate_untrusted',            'Untrusted Certificate',              'tls',  1.0, 'The chain does not validate against the public root store'),
('certificate_lifetime_excessive',   'Certificate Lifetime Too Long',      'tls',  1.0, 'Validity exceeds the 398-day CA/Browser Forum maximum'),
('certificate_transparency_missing', 'Not in Certificate Transparency',    'tls',  1.0, 'The certificate carries no embedded SCTs, so misissuance would be invisible'),
('missing_ocsp_stapling',            'OCSP Stapling Not Enabled',          'tls',  1.0, 'Revocation status is not stapled, so most clients skip the check entirely'),

-- ---------------------------------------------------------------- DNS -----
('weak_spf_policy',                  'Weak SPF Policy',                    'dns',  1.0, 'The SPF record does not reject unauthorised senders'),
('spf_lookup_limit_exceeded',        'SPF Exceeds Lookup Limit',           'dns',  1.0, 'The policy needs more than the ten DNS lookups RFC 7208 permits, so receivers discard it'),
('multiple_spf_records',             'Multiple SPF Records',               'dns',  1.0, 'More than one v=spf1 record is published, which is a permanent error'),
('missing_mta_sts',                  'Missing MTA-STS Policy',             'dns',  1.0, 'SMTP TLS is opportunistic and strippable without an MTA-STS policy'),
('mta_sts_misconfigured',            'MTA-STS Not Enforcing',              'dns',  1.0, 'The MTA-STS policy exists but does not enforce TLS'),
('missing_tls_rpt',                  'Missing SMTP TLS Reporting',         'dns',  1.0, 'No TLS-RPT record, so mail TLS failures are never reported'),
('dnssec_misconfigured',             'DNSSEC Misconfigured',               'dns',  1.0, 'The zone is signed but unanchored, or anchored but unsigned'),
('caa_incomplete',                   'CAA Policy Incomplete',              'dns',  1.0, 'CAA records are published but omit issuewild or iodef'),
('nameserver_misconfigured',         'Nameserver Misconfiguration',        'dns',  1.0, 'Too few nameservers, no network diversity, or a lame delegation'),
('soa_misconfigured',                'SOA Timers Out of Range',            'dns',  1.0, 'SOA refresh/retry/expire/minimum fall outside the RFC 1912 and RFC 2308 ranges'),

-- --------------------------------------------------------------- HTTP -----
('weak_security_header',             'Weak Security Header',               'http', 1.0, 'A security header is present but its value provides little or none of the protection it implies'),
('cors_misconfiguration',            'CORS Misconfiguration',              'http', 1.3, 'Cross-origin access is granted more broadly than intended, reachable from any site the victim visits'),
('dangerous_http_method',            'Dangerous HTTP Method',              'http', 1.0, 'TRACE or an unauthenticated write method is enabled'),
('mixed_content',                    'Mixed Content',                      'http', 1.0, 'An HTTPS page references subresources over plain HTTP'),
('missing_sri',                      'Missing Subresource Integrity',      'http', 1.0, 'Externally hosted scripts carry no integrity attribute'),
('security_txt_missing',             'No security.txt',                    'http', 1.0, 'No RFC 9116 contact is published for vulnerability reports'),
('information_disclosure',           'Information Disclosure',             'http', 1.0, 'The response or DNS discloses internal detail an attacker would otherwise have to work for')
ON CONFLICT (finding_type) DO NOTHING;

-- Types the scanners emit that pre-date this change but never had a row.
INSERT INTO finding_type_config (finding_type, display_name, category, type_multiplier, description) VALUES
('missing_dnssec',    'DNSSEC Not Enabled',      'dns',  1.0, 'The zone is unsigned, so its answers carry no origin authentication'),
('missing_dkim',      'No DKIM Selector Found',  'dns',  1.0, 'No common DKIM selector answered — inconclusive, since selectors cannot be enumerated'),
('dns_misconfiguration', 'DNS Misconfiguration', 'dns',  1.0, 'A DNS record does not conform to the relevant RFC'),
-- An attacker can claim the name today, which is why this is weighted above its severity.
('dangling_dns',      'Dangling DNS Record',     'dns',  1.5, 'A record points at a released third-party resource that can be re-registered')
ON CONFLICT (finding_type) DO NOTHING;

-- `zone_transfer_allowed` hands over the entire zone to an unauthenticated
-- client. Whatever its severity, the exposure is complete and live.
UPDATE finding_type_config SET type_multiplier = 1.5, updated_at = now()
 WHERE finding_type = 'zone_transfer_allowed';

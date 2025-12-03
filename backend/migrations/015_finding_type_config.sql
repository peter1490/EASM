-- Finding Type Configuration
-- Allows customization of severity scores and type multipliers for risk calculation

CREATE TABLE IF NOT EXISTS finding_type_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_type VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(200) NOT NULL,
    category VARCHAR(50) NOT NULL DEFAULT 'other',
    default_severity VARCHAR(20) NOT NULL DEFAULT 'info',
    severity_score FLOAT NOT NULL DEFAULT 1.0,
    type_multiplier FLOAT NOT NULL DEFAULT 1.0,
    description TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for lookups
CREATE INDEX IF NOT EXISTS idx_finding_type_config_finding_type ON finding_type_config(finding_type);
CREATE INDEX IF NOT EXISTS idx_finding_type_config_category ON finding_type_config(category);

-- Insert default configurations for all known finding types
INSERT INTO finding_type_config (finding_type, display_name, category, default_severity, severity_score, type_multiplier, description) VALUES
-- Port scan findings
('open_port', 'Open Port', 'port_scan', 'info', 0.5, 1.0, 'A port is open and accepting connections'),
('unexpected_service', 'Unexpected Service', 'port_scan', 'medium', 10.0, 1.2, 'A service is running on an unexpected port'),
('sensitive_port', 'Sensitive Port Exposed', 'port_scan', 'high', 20.0, 1.5, 'A sensitive port (SSH, RDP, etc.) is exposed'),
('database_exposed', 'Database Exposed', 'port_scan', 'critical', 40.0, 1.8, 'A database port is exposed to the internet'),
('admin_port_exposed', 'Admin Port Exposed', 'port_scan', 'high', 20.0, 1.5, 'An administrative port is exposed'),

-- Service detection findings
('service_detected', 'Service Detected', 'service', 'info', 0.5, 1.0, 'A service was detected'),
('outdated_service', 'Outdated Service', 'service', 'medium', 10.0, 1.3, 'An outdated version of a service is running'),
('vulnerable_service', 'Vulnerable Service', 'service', 'high', 20.0, 1.5, 'A known vulnerable service is running'),
('unencrypted_service', 'Unencrypted Service', 'service', 'medium', 10.0, 1.2, 'A service is running without encryption'),
('default_credentials', 'Default Credentials', 'service', 'critical', 40.0, 2.0, 'Default credentials were detected'),

-- TLS findings
('weak_tls_version', 'Weak TLS Version', 'tls', 'high', 20.0, 1.5, 'TLS 1.0 or 1.1 is enabled'),
('weak_cipher_suite', 'Weak Cipher Suite', 'tls', 'medium', 10.0, 1.2, 'Weak cipher suites are enabled'),
('expired_certificate', 'Expired Certificate', 'tls', 'critical', 40.0, 1.5, 'The SSL/TLS certificate has expired'),
('self_signed_certificate', 'Self-Signed Certificate', 'tls', 'medium', 10.0, 1.2, 'The certificate is self-signed'),
('certificate_expiring_soon', 'Certificate Expiring Soon', 'tls', 'low', 3.0, 1.2, 'The certificate will expire within 30 days'),
('mismatched_certificate', 'Mismatched Certificate', 'tls', 'medium', 10.0, 1.2, 'The certificate does not match the domain'),
('certificate_chain_incomplete', 'Incomplete Certificate Chain', 'tls', 'low', 3.0, 1.1, 'The certificate chain is incomplete'),
('certificate_revoked', 'Certificate Revoked', 'tls', 'critical', 40.0, 1.5, 'The certificate has been revoked'),

-- HTTP security findings
('missing_security_header', 'Missing Security Header', 'http', 'low', 3.0, 1.1, 'A security header is missing'),
('insecure_cookies', 'Insecure Cookies', 'http', 'medium', 10.0, 1.2, 'Cookies are set without secure flags'),
('https_not_enforced', 'HTTPS Not Enforced', 'http', 'medium', 10.0, 1.1, 'HTTP to HTTPS redirection is not enforced'),
('sensitive_data_exposed', 'Sensitive Data Exposed', 'http', 'high', 20.0, 1.5, 'Sensitive data is exposed in responses'),
('directory_listing', 'Directory Listing Enabled', 'http', 'low', 3.0, 1.1, 'Directory listing is enabled'),
('server_version_exposed', 'Server Version Exposed', 'http', 'info', 0.5, 1.0, 'Server version is disclosed in headers'),
('debug_endpoint_exposed', 'Debug Endpoint Exposed', 'http', 'high', 20.0, 1.5, 'Debug endpoints are accessible'),

-- WAF/Proxy/CDN findings
('no_waf_detected', 'No WAF Detected', 'infrastructure', 'info', 0.5, 1.0, 'No Web Application Firewall detected'),
('waf_bypass_possible', 'WAF Bypass Possible', 'infrastructure', 'high', 20.0, 1.5, 'WAF can be bypassed'),
('direct_ip_accessible', 'Direct IP Accessible', 'infrastructure', 'low', 3.0, 1.1, 'Origin server is directly accessible'),
('cdn_misconfigured', 'CDN Misconfigured', 'infrastructure', 'medium', 10.0, 1.2, 'CDN is misconfigured'),

-- Threat intelligence
('malware_detected', 'Malware Detected', 'threat_intel', 'critical', 40.0, 2.0, 'Malware was detected'),
('reputation_issue', 'Reputation Issue', 'threat_intel', 'high', 20.0, 2.0, 'The asset has reputation issues'),
('blocklisted_ip', 'Blocklisted IP', 'threat_intel', 'high', 20.0, 1.8, 'The IP is on a blocklist'),
('suspicious_behavior', 'Suspicious Behavior', 'threat_intel', 'medium', 10.0, 1.5, 'Suspicious behavior was detected'),

-- DNS findings
('dns_misconfiguration', 'DNS Misconfiguration', 'dns', 'medium', 10.0, 1.2, 'DNS is misconfigured'),
('dangling_dns', 'Dangling DNS', 'dns', 'high', 20.0, 1.5, 'Dangling DNS record detected (subdomain takeover risk)'),
('zone_transfer_allowed', 'Zone Transfer Allowed', 'dns', 'high', 20.0, 1.5, 'DNS zone transfer is allowed'),
('missing_spf', 'Missing SPF Record', 'dns', 'medium', 10.0, 1.1, 'No SPF record found'),
('missing_dkim', 'Missing DKIM', 'dns', 'low', 3.0, 1.0, 'No DKIM record found'),
('missing_dmarc', 'Missing DMARC', 'dns', 'medium', 10.0, 1.1, 'No DMARC record found'),
('weak_dmarc_policy', 'Weak DMARC Policy', 'dns', 'low', 3.0, 1.0, 'DMARC policy is weak (none or quarantine)'),
('missing_dnssec', 'Missing DNSSEC', 'dns', 'low', 3.0, 1.0, 'DNSSEC is not enabled'),
('missing_caa', 'Missing CAA Record', 'dns', 'info', 0.5, 1.0, 'No CAA record found'),

-- Vulnerability findings
('known_cve', 'Known CVE', 'vulnerability', 'high', 20.0, 1.5, 'A known CVE vulnerability was found'),
('exploitable_vulnerability', 'Exploitable Vulnerability', 'vulnerability', 'critical', 40.0, 2.0, 'An exploitable vulnerability was found'),
('critical_vulnerability', 'Critical Vulnerability', 'vulnerability', 'critical', 40.0, 2.0, 'A critical severity vulnerability was found'),

-- Generic
('configuration_issue', 'Configuration Issue', 'other', 'medium', 10.0, 1.0, 'A configuration issue was found'),
('vulnerability_detected', 'Vulnerability Detected', 'other', 'medium', 10.0, 1.2, 'A vulnerability was detected'),
('compliance_violation', 'Compliance Violation', 'other', 'medium', 10.0, 1.2, 'A compliance violation was found'),
('information_disclosure', 'Information Disclosure', 'other', 'low', 3.0, 1.1, 'Information disclosure was detected'),
('other', 'Other Finding', 'other', 'info', 0.5, 1.0, 'Other finding type')
ON CONFLICT (finding_type) DO NOTHING;


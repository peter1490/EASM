use crate::config::Settings;
use serde::{Deserialize, Serialize};

fn default_cors() -> Vec<String> {
    vec![
        "http://localhost:3000".to_string(),
        "http://127.0.0.1:3000".to_string(),
    ]
}

fn default_google_discovery_url() -> Option<String> {
    Some("https://accounts.google.com".to_string())
}

fn default_google_redirect_uri() -> Option<String> {
    Some("http://localhost:3000/api/auth/callback/google".to_string())
}

fn default_keycloak_redirect_uri() -> Option<String> {
    Some("http://localhost:3000/api/auth/callback/keycloak".to_string())
}

fn default_log_level() -> String {
    "INFO".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_evidence_types() -> Vec<String> {
    "image/png,image/jpeg,image/gif,text/plain,application/pdf,application/json,text/csv"
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Settings that are editable from the frontend and persisted in the database.
/// These values intentionally exclude bootstrap-only values (database URL, auth secret, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSettings {
    // Google OIDC
    #[serde(default)]
    pub google_client_id: Option<String>,
    #[serde(default)]
    pub google_client_secret: Option<String>,
    #[serde(default = "default_google_discovery_url")]
    pub google_discovery_url: Option<String>,
    #[serde(default = "default_google_redirect_uri")]
    pub google_redirect_uri: Option<String>,
    #[serde(default)]
    pub google_allowed_domains: Vec<String>,

    // Keycloak
    #[serde(default)]
    pub keycloak_client_id: Option<String>,
    #[serde(default)]
    pub keycloak_client_secret: Option<String>,
    #[serde(default)]
    pub keycloak_discovery_url: Option<String>,
    #[serde(default = "default_keycloak_redirect_uri")]
    pub keycloak_redirect_uri: Option<String>,
    #[serde(default)]
    pub keycloak_realm: Option<String>,

    // External API Keys
    #[serde(default)]
    pub certspotter_api_token: Option<String>,
    #[serde(default)]
    pub virustotal_api_key: Option<String>,
    #[serde(default)]
    pub shodan_api_key: Option<String>,
    #[serde(default)]
    pub urlscan_api_key: Option<String>,
    #[serde(default)]
    pub otx_api_key: Option<String>,
    #[serde(default)]
    pub clearbit_api_key: Option<String>,
    #[serde(default)]
    pub opencorporates_api_token: Option<String>,

    // CORS
    #[serde(default = "default_cors")]
    pub cors_allow_origins: Vec<String>,

    // Logging
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,

    // Rate limiting
    #[serde(default = "default_rate_limit_enabled")]
    pub rate_limit_enabled: bool,
    #[serde(default = "default_rate_limit_requests")]
    pub rate_limit_requests: u32,
    #[serde(default = "default_rate_limit_window")]
    pub rate_limit_window_seconds: u32,

    // Performance
    #[serde(default = "default_http_timeout")]
    pub http_timeout_seconds: f64,
    #[serde(default = "default_tls_timeout")]
    pub tls_timeout_seconds: f64,
    #[serde(default = "default_dns_concurrency")]
    pub dns_concurrency: u32,
    #[serde(default = "default_rdns_concurrency")]
    pub rdns_concurrency: u32,
    #[serde(default = "default_max_concurrent_scans")]
    pub max_concurrent_scans: u32,

    // Evidence storage
    #[serde(default = "default_max_evidence_bytes")]
    pub max_evidence_bytes: u64,
    #[serde(default = "default_evidence_types")]
    pub evidence_allowed_types: Vec<String>,

    // Discovery settings
    #[serde(default = "default_max_cidr_hosts")]
    pub max_cidr_hosts: u32,
    #[serde(default = "default_max_discovery_depth")]
    pub max_discovery_depth: u32,
    #[serde(default = "default_subdomain_timeout")]
    pub subdomain_enum_timeout: f64,

    // OSINT toggles
    #[serde(default = "default_true")]
    pub enable_wayback: bool,
    #[serde(default = "default_false")]
    pub enable_urlscan: bool,
    #[serde(default = "default_false")]
    pub enable_otx: bool,
    #[serde(default = "default_true")]
    pub enable_dns_record_expansion: bool,
    #[serde(default = "default_true")]
    pub enable_web_crawl: bool,
    #[serde(default = "default_true")]
    pub enable_cloud_storage_discovery: bool,
    #[serde(default = "default_true")]
    pub enable_wikidata: bool,
    #[serde(default = "default_false")]
    pub enable_opencorporates: bool,

    // Recursive discovery
    #[serde(default = "default_max_assets_per_discovery")]
    pub max_assets_per_discovery: u32,
    #[serde(default = "default_min_pivot_confidence")]
    pub min_pivot_confidence: f64,
    #[serde(default = "default_max_orgs_per_domain")]
    pub max_orgs_per_domain: u32,
    #[serde(default = "default_max_domains_per_org")]
    pub max_domains_per_org: u32,
}

const fn default_rate_limit_enabled() -> bool {
    true
}

const fn default_rate_limit_requests() -> u32 {
    100
}

const fn default_rate_limit_window() -> u32 {
    60
}

fn default_http_timeout() -> f64 {
    8.0
}

fn default_tls_timeout() -> f64 {
    4.0
}

const fn default_dns_concurrency() -> u32 {
    256
}

const fn default_rdns_concurrency() -> u32 {
    256
}

const fn default_max_concurrent_scans() -> u32 {
    5
}

const fn default_max_evidence_bytes() -> u64 {
    52_428_800
}

const fn default_max_cidr_hosts() -> u32 {
    4096
}

const fn default_max_discovery_depth() -> u32 {
    3
}

fn default_subdomain_timeout() -> f64 {
    60.0
}

const fn default_true() -> bool {
    true
}

const fn default_false() -> bool {
    false
}

const fn default_max_assets_per_discovery() -> u32 {
    5000
}

fn default_min_pivot_confidence() -> f64 {
    0.5
}

const fn default_max_orgs_per_domain() -> u32 {
    3
}

const fn default_max_domains_per_org() -> u32 {
    20
}

impl Default for ManagedSettings {
    fn default() -> Self {
        Self {
            google_client_id: None,
            google_client_secret: None,
            google_discovery_url: default_google_discovery_url(),
            google_redirect_uri: default_google_redirect_uri(),
            google_allowed_domains: Vec::new(),

            keycloak_client_id: None,
            keycloak_client_secret: None,
            keycloak_discovery_url: None,
            keycloak_redirect_uri: default_keycloak_redirect_uri(),
            keycloak_realm: None,

            certspotter_api_token: None,
            virustotal_api_key: None,
            shodan_api_key: None,
            urlscan_api_key: None,
            otx_api_key: None,
            clearbit_api_key: None,
            opencorporates_api_token: None,

            cors_allow_origins: default_cors(),

            log_level: default_log_level(),
            log_format: default_log_format(),

            rate_limit_enabled: default_rate_limit_enabled(),
            rate_limit_requests: default_rate_limit_requests(),
            rate_limit_window_seconds: default_rate_limit_window(),

            http_timeout_seconds: default_http_timeout(),
            tls_timeout_seconds: default_tls_timeout(),
            dns_concurrency: default_dns_concurrency(),
            rdns_concurrency: default_rdns_concurrency(),
            max_concurrent_scans: default_max_concurrent_scans(),

            max_evidence_bytes: default_max_evidence_bytes(),
            evidence_allowed_types: default_evidence_types(),

            max_cidr_hosts: default_max_cidr_hosts(),
            max_discovery_depth: default_max_discovery_depth(),
            subdomain_enum_timeout: default_subdomain_timeout(),

            enable_wayback: default_true(),
            enable_urlscan: default_false(),
            enable_otx: default_false(),
            enable_dns_record_expansion: default_true(),
            enable_web_crawl: default_true(),
            enable_cloud_storage_discovery: default_true(),
            enable_wikidata: default_true(),
            enable_opencorporates: default_false(),

            max_assets_per_discovery: default_max_assets_per_discovery(),
            min_pivot_confidence: default_min_pivot_confidence(),
            max_orgs_per_domain: default_max_orgs_per_domain(),
            max_domains_per_org: default_max_domains_per_org(),
        }
    }
}

impl ManagedSettings {
    /// Normalize strings (trim, convert empties to None).
    pub fn normalized(&self) -> Self {
        let mut clone = self.clone();
        clone.google_client_id = normalize_opt(&clone.google_client_id);
        clone.google_client_secret = normalize_opt(&clone.google_client_secret);
        clone.google_discovery_url = normalize_opt(&clone.google_discovery_url);
        clone.google_redirect_uri = normalize_opt(&clone.google_redirect_uri);
        clone.keycloak_client_id = normalize_opt(&clone.keycloak_client_id);
        clone.keycloak_client_secret = normalize_opt(&clone.keycloak_client_secret);
        clone.keycloak_discovery_url = normalize_opt(&clone.keycloak_discovery_url);
        clone.keycloak_redirect_uri = normalize_opt(&clone.keycloak_redirect_uri);
        clone.keycloak_realm = normalize_opt(&clone.keycloak_realm);
        clone.certspotter_api_token = normalize_opt(&clone.certspotter_api_token);
        clone.virustotal_api_key = normalize_opt(&clone.virustotal_api_key);
        clone.shodan_api_key = normalize_opt(&clone.shodan_api_key);
        clone.urlscan_api_key = normalize_opt(&clone.urlscan_api_key);
        clone.otx_api_key = normalize_opt(&clone.otx_api_key);
        clone.clearbit_api_key = normalize_opt(&clone.clearbit_api_key);
        clone.opencorporates_api_token = normalize_opt(&clone.opencorporates_api_token);
        clone.google_allowed_domains = normalize_vec(&clone.google_allowed_domains);
        clone.cors_allow_origins = normalize_vec(&clone.cors_allow_origins);
        clone.evidence_allowed_types = normalize_vec(&clone.evidence_allowed_types);
        clone
    }

    pub fn apply_to_settings(&self, settings: &mut Settings) {
        let normalized = self.normalized();

        // SSO
        settings.google_client_id = normalized.google_client_id;
        settings.google_client_secret = normalized.google_client_secret;
        settings.google_discovery_url = normalized.google_discovery_url;
        settings.google_redirect_uri = normalized.google_redirect_uri;
        settings.google_allowed_domains = normalized.google_allowed_domains;

        settings.keycloak_client_id = normalized.keycloak_client_id;
        settings.keycloak_client_secret = normalized.keycloak_client_secret;
        settings.keycloak_discovery_url = normalized.keycloak_discovery_url;
        settings.keycloak_redirect_uri = normalized.keycloak_redirect_uri;
        settings.keycloak_realm = normalized.keycloak_realm;

        // API Keys
        settings.certspotter_api_token = normalized.certspotter_api_token;
        settings.virustotal_api_key = normalized.virustotal_api_key;
        settings.shodan_api_key = normalized.shodan_api_key;
        settings.urlscan_api_key = normalized.urlscan_api_key;
        settings.otx_api_key = normalized.otx_api_key;
        settings.clearbit_api_key = normalized.clearbit_api_key;
        settings.opencorporates_api_token = normalized.opencorporates_api_token;

        // CORS
        settings.cors_allow_origins = normalized.cors_allow_origins;

        // Logging
        settings.log_level = normalized.log_level;
        settings.log_format = normalized.log_format;

        // Rate limiting
        settings.rate_limit_enabled = normalized.rate_limit_enabled;
        settings.rate_limit_requests = normalized.rate_limit_requests;
        settings.rate_limit_window_seconds = normalized.rate_limit_window_seconds;

        // Performance
        settings.http_timeout_seconds = normalized.http_timeout_seconds;
        settings.tls_timeout_seconds = normalized.tls_timeout_seconds;
        settings.dns_concurrency = normalized.dns_concurrency;
        settings.rdns_concurrency = normalized.rdns_concurrency;
        settings.max_concurrent_scans = normalized.max_concurrent_scans;

        // Evidence
        settings.max_evidence_bytes = normalized.max_evidence_bytes;
        settings.evidence_allowed_types = normalized.evidence_allowed_types;

        // Discovery + OSINT
        settings.max_cidr_hosts = normalized.max_cidr_hosts;
        settings.max_discovery_depth = normalized.max_discovery_depth;
        settings.subdomain_enum_timeout = normalized.subdomain_enum_timeout;
        settings.enable_wayback = normalized.enable_wayback;
        settings.enable_urlscan = normalized.enable_urlscan;
        settings.enable_otx = normalized.enable_otx;
        settings.enable_dns_record_expansion = normalized.enable_dns_record_expansion;
        settings.enable_web_crawl = normalized.enable_web_crawl;
        settings.enable_cloud_storage_discovery = normalized.enable_cloud_storage_discovery;
        settings.enable_wikidata = normalized.enable_wikidata;
        settings.enable_opencorporates = normalized.enable_opencorporates;

        // Recursive discovery
        settings.max_assets_per_discovery = normalized.max_assets_per_discovery;
        settings.min_pivot_confidence = normalized.min_pivot_confidence;
        settings.max_orgs_per_domain = normalized.max_orgs_per_domain;
        settings.max_domains_per_org = normalized.max_domains_per_org;
    }
}

impl From<&Settings> for ManagedSettings {
    fn from(settings: &Settings) -> Self {
        Self {
            google_client_id: settings.google_client_id.clone(),
            google_client_secret: settings.google_client_secret.clone(),
            google_discovery_url: settings.google_discovery_url.clone(),
            google_redirect_uri: settings.google_redirect_uri.clone(),
            google_allowed_domains: settings.google_allowed_domains.clone(),

            keycloak_client_id: settings.keycloak_client_id.clone(),
            keycloak_client_secret: settings.keycloak_client_secret.clone(),
            keycloak_discovery_url: settings.keycloak_discovery_url.clone(),
            keycloak_redirect_uri: settings.keycloak_redirect_uri.clone(),
            keycloak_realm: settings.keycloak_realm.clone(),

            certspotter_api_token: settings.certspotter_api_token.clone(),
            virustotal_api_key: settings.virustotal_api_key.clone(),
            shodan_api_key: settings.shodan_api_key.clone(),
            urlscan_api_key: settings.urlscan_api_key.clone(),
            otx_api_key: settings.otx_api_key.clone(),
            clearbit_api_key: settings.clearbit_api_key.clone(),
            opencorporates_api_token: settings.opencorporates_api_token.clone(),

            cors_allow_origins: settings.cors_allow_origins.clone(),

            log_level: settings.log_level.clone(),
            log_format: settings.log_format.clone(),

            rate_limit_enabled: settings.rate_limit_enabled,
            rate_limit_requests: settings.rate_limit_requests,
            rate_limit_window_seconds: settings.rate_limit_window_seconds,

            http_timeout_seconds: settings.http_timeout_seconds,
            tls_timeout_seconds: settings.tls_timeout_seconds,
            dns_concurrency: settings.dns_concurrency,
            rdns_concurrency: settings.rdns_concurrency,
            max_concurrent_scans: settings.max_concurrent_scans,

            max_evidence_bytes: settings.max_evidence_bytes,
            evidence_allowed_types: settings.evidence_allowed_types.clone(),

            max_cidr_hosts: settings.max_cidr_hosts,
            max_discovery_depth: settings.max_discovery_depth,
            subdomain_enum_timeout: settings.subdomain_enum_timeout,

            enable_wayback: settings.enable_wayback,
            enable_urlscan: settings.enable_urlscan,
            enable_otx: settings.enable_otx,
            enable_dns_record_expansion: settings.enable_dns_record_expansion,
            enable_web_crawl: settings.enable_web_crawl,
            enable_cloud_storage_discovery: settings.enable_cloud_storage_discovery,
            enable_wikidata: settings.enable_wikidata,
            enable_opencorporates: settings.enable_opencorporates,

            max_assets_per_discovery: settings.max_assets_per_discovery,
            min_pivot_confidence: settings.min_pivot_confidence,
            max_orgs_per_domain: settings.max_orgs_per_domain,
            max_domains_per_org: settings.max_domains_per_org,
        }
    }
}

fn normalize_opt(value: &Option<String>) -> Option<String> {
    value.as_ref().and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}

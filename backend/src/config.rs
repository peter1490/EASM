use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::rbac::Role;
use ipnet::IpNet;
use sha2::{Digest, Sha256};

pub mod managed;
mod secure_store;
pub mod store;
pub use managed::ManagedSettings;
pub use store::{SettingsService, SharedSettings};

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// Custom deserializer for comma-separated strings
fn deserialize_comma_separated<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(s.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }
}

fn deserialize_ipnet_list<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }

    s.split(',')
        .map(|raw| {
            let item = raw.trim();
            if item.is_empty() {
                return Err(serde::de::Error::custom("Empty CIDR entry in allowlist"));
            }
            if let Ok(net) = item.parse::<IpNet>() {
                return Ok(net);
            }
            if let Ok(ip) = item.parse::<std::net::IpAddr>() {
                return Ok(IpNet::from(ip));
            }
            Err(serde::de::Error::custom(format!(
                "Invalid CIDR or IP entry '{}'",
                item
            )))
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ApiKeyScope {
    pub key_hash: [u8; 32],
    pub company_id: Uuid,
    pub role: Role,
    pub allow_company_override: bool,
}

impl ApiKeyScope {
    pub fn key_id(&self) -> String {
        // Use first 8 bytes of the hash as a stable identifier for logging
        self.key_hash[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    pub fn matches(&self, candidate: &str) -> bool {
        let candidate_hash = hash_api_key(candidate);
        constant_time_eq(&candidate_hash, &self.key_hash)
    }
}

fn deserialize_api_keys<'de, D>(deserializer: D) -> Result<Vec<ApiKeyScope>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }

    s.split(',')
        .map(|raw| parse_api_key_entry(raw.trim()).map_err(serde::de::Error::custom))
        .collect()
}

fn parse_api_key_entry(entry: &str) -> Result<ApiKeyScope, String> {
    if entry.is_empty() {
        return Err("API key entry is empty".to_string());
    }

    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return Err(format!(
            "API key entry '{}' must be in format key:company_uuid:role[:allow_override]",
            entry
        ));
    }

    let key = parts[0].trim();
    let company_raw = parts[1].trim();
    let role_raw = parts[2].trim();

    if key.is_empty() {
        return Err("API key entry has empty key".to_string());
    }

    let company_id = Uuid::parse_str(company_raw).map_err(|_| {
        format!(
            "API key entry '{}' has invalid company UUID '{}'",
            entry, company_raw
        )
    })?;

    let role = Role::from_str(role_raw)
        .ok_or_else(|| format!("API key entry '{}' has invalid role '{}'", entry, role_raw))?;

    let allow_company_override = parts
        .get(3)
        .map(|flag| matches!(flag.trim().to_ascii_lowercase().as_str(), "true" | "allow"))
        .unwrap_or(false);

    let key_hash = hash_api_key(key);

    Ok(ApiKeyScope {
        key_hash,
        company_id,
        role,
        allow_company_override,
    })
}

fn hash_api_key(key: &str) -> [u8; 32] {
    let digest = Sha256::digest(key.as_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Application settings with environment variable support
/// Matches the Python backend configuration exactly
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    // Environment
    pub environment: String,

    // Database
    pub database_url: String,

    // Elasticsearch
    pub elasticsearch_url: Option<String>,
    pub elasticsearch_asset_index: Option<String>,
    pub elasticsearch_finding_index: Option<String>,

    // API Keys
    pub certspotter_api_token: Option<String>,
    pub virustotal_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    pub urlscan_api_key: Option<String>,
    pub otx_api_key: Option<String>,
    pub clearbit_api_key: Option<String>,
    pub opencorporates_api_token: Option<String>,
    // Additional passive OSINT corpora. All optional: a source without its key
    // is skipped, never failed, so discovery still runs on the eight key-free
    // sources alone.
    pub securitytrails_api_key: Option<String>,
    pub censys_api_key: Option<String>,
    pub censys_org_id: Option<String>,
    pub chaos_api_key: Option<String>,
    pub leakix_api_key: Option<String>,
    pub fullhunt_api_key: Option<String>,
    pub binaryedge_api_key: Option<String>,
    pub netlas_api_key: Option<String>,

    // Security
    #[serde(deserialize_with = "deserialize_comma_separated")]
    pub cors_allow_origins: Vec<String>,
    pub api_key_header: String,
    pub allow_anonymous: bool,
    #[serde(deserialize_with = "deserialize_api_keys")]
    pub api_keys: Vec<ApiKeyScope>,
    #[serde(deserialize_with = "deserialize_ipnet_list")]
    pub api_key_ip_allowlist: Vec<IpNet>,
    pub break_glass_token: Option<String>,

    // Authentication (OIDC/SAML)
    pub auth_secret: String, // For session signing
    pub auth_session_expiry_seconds: u64,

    // Google OIDC
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_discovery_url: Option<String>,
    pub google_redirect_uri: Option<String>,
    #[serde(deserialize_with = "deserialize_comma_separated")]
    pub google_allowed_domains: Vec<String>,

    // Keycloak (OIDC for now as SAML crate support is mixed)
    pub keycloak_client_id: Option<String>,
    pub keycloak_client_secret: Option<String>,
    pub keycloak_discovery_url: Option<String>,
    pub keycloak_redirect_uri: Option<String>,
    pub keycloak_realm: Option<String>,

    // Logging
    pub log_level: String,
    pub log_format: String,
    pub sql_log_level: String,

    // Evidence Storage
    pub max_evidence_bytes: u64,
    #[serde(deserialize_with = "deserialize_comma_separated")]
    pub evidence_allowed_types: Vec<String>,
    pub evidence_storage_path: String,

    // Performance Tuning
    pub http_timeout_seconds: f64,
    pub tls_timeout_seconds: f64,
    pub dns_concurrency: u32,
    pub rdns_concurrency: u32,
    pub tcp_scan_timeout: f64,
    pub tcp_scan_concurrency: u32,
    pub block_internal_ip_scans: bool,
    pub allow_internal_scans: bool,

    // Scan target allowlists
    #[serde(deserialize_with = "deserialize_ipnet_list")]
    pub scan_allowlist_cidrs: Vec<IpNet>,
    #[serde(deserialize_with = "deserialize_comma_separated")]
    pub scan_allowlist_domains: Vec<String>,

    // Discovery Settings
    pub max_cidr_hosts: u32,
    pub max_discovery_depth: u32,
    pub subdomain_enum_timeout: f64,
    pub enable_wayback: bool,
    pub enable_urlscan: bool,
    pub enable_otx: bool,
    pub enable_dns_record_expansion: bool,
    pub enable_web_crawl: bool,
    pub enable_cloud_storage_discovery: bool,
    pub enable_wikidata: bool,
    pub enable_opencorporates: bool,
    pub skip_unresolved_domains: bool,
    pub related_asset_confidence_default: f64,

    // Recursive Discovery Limits (to reduce false-positives)
    pub max_assets_per_discovery: u32, // Max assets per discovery run
    pub min_pivot_confidence: f64,     // Min confidence to follow pivot
    pub max_orgs_per_domain: u32,      // Max orgs to pivot from per domain
    pub max_domains_per_org: u32,      // Max domains to pivot from per org

    // Lateral OSINT Pivots
    // Phase-1 pivots (favicon / JARM / HTML / SPF / DMARC / MX) surface apex
    // domains that share infrastructure or mail relays with the seed. They can
    // match unrelated SaaS tenants — keep these bounded.
    pub shodan_lateral_pivots_enabled: bool, // Master switch for Shodan-backed lateral pivots
    pub lateral_pivot_max_results: u32,      // Max hosts a single Shodan pivot may yield
    pub lateral_pivot_max_html_needles: u32, // Max unique HTML fingerprints to pivot per host

    // Passive OSINT fan-out
    // Sources are queried concurrently, so enumeration costs the slowest source
    // rather than the sum of all of them.
    pub osint_source_concurrency: u32, // Sources queried at once
    pub osint_source_timeout_seconds: f64, // Wall-clock budget per source
    pub osint_max_results_per_source: u32, // Cap on hostnames taken from one source

    // Active DNS discovery
    // Reaches names no passive corpus recorded. Every technique is gated behind
    // wildcard detection, which runs unconditionally when any of them is on.
    pub enable_dns_bruteforce: bool,
    pub enable_dns_permutations: bool,
    pub enable_nsec_walk: bool,
    pub enable_srv_probe: bool,
    pub dns_bruteforce_wordlist_path: Option<String>, // Overrides the built-in list
    pub dns_bruteforce_max_words: u32,
    pub dns_permutation_max_candidates: u32,
    pub dns_permutation_max_seeds: u32,
    pub active_dns_concurrency: u32,

    // Infrastructure attribution
    pub enable_asn_discovery: bool, // Team Cymru + RIPEstat netblock attribution
    pub enable_rdap_lookup: bool,   // Registry organisation / contact pivot
    pub enable_saas_tenant_discovery: bool, // TXT verification tokens
    pub enable_cname_chain_analysis: bool,
    pub asn_max_prefixes: u32, // Announced prefixes recorded per ASN
    pub reverse_dns_sweep_max_hosts: u32, // Addresses swept per netblock (0 disables)

    // Rate Limiting
    pub rate_limit_enabled: bool,
    pub rate_limit_requests: u32,
    pub rate_limit_window_seconds: u32,

    // Background Tasks
    pub max_concurrent_scans: u32,
    pub scan_queue_check_interval: f64,
    pub max_active_scans_per_user: u32,
    pub max_active_discovery_per_user: u32,

    // Search
    pub reindex_min_interval_seconds: u32,
}

impl Settings {
    /// Create new settings instance from environment variables and .env file
    pub fn new() -> Result<Self, ConfigError> {
        Self::new_with_options(true, true)
    }

    /// Create new settings instance with optional .env file loading
    pub fn new_with_env_file(load_env_file: bool) -> Result<Self, ConfigError> {
        Self::new_with_options(load_env_file, true)
    }

    /// Create new settings instance with control over env file loading and env overrides
    pub fn new_with_options(
        load_env_file: bool,
        apply_env_overrides: bool,
    ) -> Result<Self, ConfigError> {
        // Serialize settings construction to avoid cross-test environment races
        // Tests frequently mutate process env; locking ensures consistent reads
        static SETTINGS_BUILD_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        let build_mutex = SETTINGS_BUILD_MUTEX.get_or_init(|| Mutex::new(()));
        let _guard = build_mutex
            .lock()
            .expect("Failed to lock settings build mutex");

        // Load .env file if it exists and requested (skip during tests for determinism)
        #[cfg(not(test))]
        {
            if load_env_file {
                dotenvy::dotenv().ok();
            }
        }

        let mut builder = config::Config::builder()
            .set_default(
                "environment",
                if cfg!(test) { "development" } else { "production" },
            )?
            // Database defaults
            .set_default("database_url", "postgresql://easm:easm@localhost:5432/easm")?
            .set_default("elasticsearch_url", None::<String>)?
            .set_default("elasticsearch_asset_index", None::<String>)?
            .set_default("elasticsearch_finding_index", None::<String>)?

            // API Keys defaults (all optional)
            .set_default("certspotter_api_token", None::<String>)?
            .set_default("virustotal_api_key", None::<String>)?
            .set_default("shodan_api_key", None::<String>)?
            .set_default("urlscan_api_key", None::<String>)?
            .set_default("otx_api_key", None::<String>)?
            .set_default("clearbit_api_key", None::<String>)?
            .set_default("opencorporates_api_token", None::<String>)?
            .set_default("securitytrails_api_key", None::<String>)?
            .set_default("censys_api_key", None::<String>)?
            .set_default("censys_org_id", None::<String>)?
            .set_default("chaos_api_key", None::<String>)?
            .set_default("leakix_api_key", None::<String>)?
            .set_default("fullhunt_api_key", None::<String>)?
            .set_default("binaryedge_api_key", None::<String>)?
            .set_default("netlas_api_key", None::<String>)?

            // Security defaults
            .set_default("cors_allow_origins", "http://localhost:80,http://127.0.0.1:80")?
            .set_default("api_key_header", "X-API-Key")?
            .set_default("api_keys", "")?
            .set_default("allow_anonymous", false)?
            .set_default("api_key_ip_allowlist", "")?
            .set_default("break_glass_token", None::<String>)?

            // Auth defaults
            .set_default("auth_secret", "changeme_super_secret_session_key_must_be_at_least_64_bytes_long_for_security_reasons_so_here_is_a_very_long_string_!!")?
            .set_default("auth_session_expiry_seconds", 86400u64)? // 24 hours
            .set_default("google_client_id", None::<String>)?
            .set_default("google_client_secret", None::<String>)?
            .set_default("google_discovery_url", Some("https://accounts.google.com".to_string()))?
            .set_default("google_redirect_uri", Some("http://localhost:3000/api/auth/callback/google".to_string()))?
            .set_default("google_allowed_domains", "")?
            .set_default("keycloak_client_id", None::<String>)?
            .set_default("keycloak_client_secret", None::<String>)?
            .set_default("keycloak_discovery_url", None::<String>)?
            .set_default("keycloak_redirect_uri", Some("http://localhost:3000/api/auth/callback/keycloak".to_string()))?
            .set_default("keycloak_realm", None::<String>)?

            // Logging defaults
            .set_default("log_level", "INFO")?
            .set_default("log_format", "json")?
            .set_default("sql_log_level", "WARNING")?

            // Evidence Storage defaults
            .set_default("max_evidence_bytes", 52428800u64)?  // 50MB
            .set_default("evidence_allowed_types", "image/png,image/jpeg,image/gif,text/plain,application/pdf,application/json,text/csv")?
            .set_default("evidence_storage_path", "./data/evidence")?

            // Performance Tuning defaults
            .set_default("http_timeout_seconds", 8.0)?
            .set_default("tls_timeout_seconds", 4.0)?
            .set_default("dns_concurrency", 256u32)?
            .set_default("rdns_concurrency", 256u32)?
            .set_default("tcp_scan_timeout", 0.35)?
            .set_default("tcp_scan_concurrency", 64u32)?
            .set_default("block_internal_ip_scans", true)?
            .set_default("allow_internal_scans", false)?

            // Scan target allowlists
            .set_default("scan_allowlist_cidrs", "")?
            .set_default("scan_allowlist_domains", "")?

            // Discovery Settings defaults
            .set_default("max_cidr_hosts", 4096u32)?
            .set_default("max_discovery_depth", 3u32)?
            .set_default("subdomain_enum_timeout", 60.0)?
            .set_default("enable_wayback", true)?
            // urlscan.io and AlienVault OTX default off historically only
            // because they were unimplemented. Both are now real, key-free
            // corpora, so both default on.
            .set_default("enable_urlscan", true)?
            .set_default("enable_otx", true)?
            .set_default("enable_dns_record_expansion", true)?
            .set_default("enable_web_crawl", true)?
            .set_default("enable_cloud_storage_discovery", true)?
            .set_default("enable_wikidata", true)?
            .set_default("enable_opencorporates", false)?
            .set_default("skip_unresolved_domains", false)?
            .set_default("related_asset_confidence_default", 0.3)?

            // Recursive Discovery Limits defaults
            .set_default("max_assets_per_discovery", 5000u32)?
            .set_default("min_pivot_confidence", 0.5)?
            .set_default("max_orgs_per_domain", 3u32)?
            .set_default("max_domains_per_org", 20u32)?

            // Lateral OSINT Pivot defaults
            .set_default("shodan_lateral_pivots_enabled", true)?
            .set_default("lateral_pivot_max_results", 200u32)?
            .set_default("lateral_pivot_max_html_needles", 3u32)?
            .set_default("osint_source_concurrency", 12u32)?
            .set_default("osint_source_timeout_seconds", 25.0)?
            .set_default("osint_max_results_per_source", 5000u32)?
            .set_default("enable_dns_bruteforce", true)?
            .set_default("enable_dns_permutations", true)?
            .set_default("enable_nsec_walk", true)?
            .set_default("enable_srv_probe", true)?
            .set_default("dns_bruteforce_wordlist_path", None::<String>)?
            .set_default("dns_bruteforce_max_words", 2000u32)?
            .set_default("dns_permutation_max_candidates", 5000u32)?
            .set_default("dns_permutation_max_seeds", 50u32)?
            .set_default("active_dns_concurrency", 50u32)?
            .set_default("enable_asn_discovery", true)?
            .set_default("enable_rdap_lookup", true)?
            .set_default("enable_saas_tenant_discovery", true)?
            .set_default("enable_cname_chain_analysis", true)?
            .set_default("asn_max_prefixes", 64u32)?
            .set_default("reverse_dns_sweep_max_hosts", 256u32)?

            // Rate Limiting defaults
            .set_default("rate_limit_enabled", true)?
            .set_default("rate_limit_requests", 100u32)?
            .set_default("rate_limit_window_seconds", 60u32)?

            // Background Tasks defaults
            .set_default("max_concurrent_scans", 5u32)?
            .set_default("scan_queue_check_interval", 5.0)?
            .set_default("max_active_scans_per_user", 2u32)?
            .set_default("max_active_discovery_per_user", 1u32)?

            // Search defaults
            .set_default("reindex_min_interval_seconds", 300u32)?
            ;

        // Load .env as a configuration source instead of mutating process environment (skip in tests)
        #[cfg(not(test))]
        {
            if load_env_file {
                builder = builder.add_source(config::File::with_name(".env").required(false));
            }
        }

        if apply_env_overrides {
            // Apply environment overrides using explicit, uppercase-only mapping
            fn read_env(key: &str) -> Option<String> {
                std::env::var(key).ok()
            }

            fn parse_bool_env(key: &str) -> Option<bool> {
                read_env(key).and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
                    "true" | "1" => Some(true),
                    "false" | "0" => Some(false),
                    _ => None,
                })
            }

            // String overrides (UPPERCASE only, special-case database_url to also consider lowercase for tests)
            if let Some(v) = read_env("ENVIRONMENT") {
                builder = builder.set_override("environment", v)?;
            }
            if let Some(v) = read_env("DATABASE_URL").or_else(|| std::env::var("database_url").ok())
            {
                builder = builder.set_override("database_url", v)?;
            }
            if let Some(v) = read_env("ELASTICSEARCH_URL") {
                builder = builder.set_override("elasticsearch_url", v)?;
            }
            if let Some(v) = read_env("ELASTICSEARCH_ASSET_INDEX") {
                builder = builder.set_override("elasticsearch_asset_index", v)?;
            }
            if let Some(v) = read_env("ELASTICSEARCH_FINDING_INDEX") {
                builder = builder.set_override("elasticsearch_finding_index", v)?;
            }
            if let Some(v) = read_env("CERTSPOTTER_API_TOKEN") {
                builder = builder.set_override("certspotter_api_token", v)?;
            }
            if let Some(v) = read_env("VIRUSTOTAL_API_KEY") {
                builder = builder.set_override("virustotal_api_key", v)?;
            }
            if let Some(v) = read_env("SHODAN_API_KEY") {
                builder = builder.set_override("shodan_api_key", v)?;
            }
            if let Some(v) = read_env("URLSCAN_API_KEY") {
                builder = builder.set_override("urlscan_api_key", v)?;
            }
            if let Some(v) = read_env("OTX_API_KEY") {
                builder = builder.set_override("otx_api_key", v)?;
            }
            if let Some(v) = read_env("CLEARBIT_API_KEY") {
                builder = builder.set_override("clearbit_api_key", v)?;
            }
            if let Some(v) = read_env("OPENCORPORATES_API_TOKEN") {
                builder = builder.set_override("opencorporates_api_token", v)?;
            }
            if let Some(v) = read_env("SECURITYTRAILS_API_KEY") {
                builder = builder.set_override("securitytrails_api_key", v)?;
            }
            if let Some(v) = read_env("CENSYS_API_KEY") {
                builder = builder.set_override("censys_api_key", v)?;
            }
            if let Some(v) = read_env("CENSYS_ORG_ID") {
                builder = builder.set_override("censys_org_id", v)?;
            }
            if let Some(v) = read_env("CHAOS_API_KEY") {
                builder = builder.set_override("chaos_api_key", v)?;
            }
            if let Some(v) = read_env("LEAKIX_API_KEY") {
                builder = builder.set_override("leakix_api_key", v)?;
            }
            if let Some(v) = read_env("FULLHUNT_API_KEY") {
                builder = builder.set_override("fullhunt_api_key", v)?;
            }
            if let Some(v) = read_env("BINARYEDGE_API_KEY") {
                builder = builder.set_override("binaryedge_api_key", v)?;
            }
            if let Some(v) = read_env("NETLAS_API_KEY") {
                builder = builder.set_override("netlas_api_key", v)?;
            }
            if let Some(v) = read_env("DNS_BRUTEFORCE_WORDLIST_PATH") {
                builder = builder.set_override("dns_bruteforce_wordlist_path", v)?;
            }
            if let Some(v) =
                read_env("CORS_ALLOW_ORIGINS").or_else(|| std::env::var("CORS_ALLOW_ORIGINS").ok())
            {
                builder = builder.set_override("cors_allow_origins", v)?;
            }
            if let Some(v) = read_env("API_KEY_HEADER") {
                builder = builder.set_override("api_key_header", v)?;
            }
            if let Some(v) = read_env("API_KEYS") {
                builder = builder.set_override("api_keys", v)?;
            }
            if let Some(v) = read_env("API_KEY_IP_ALLOWLIST") {
                builder = builder.set_override("api_key_ip_allowlist", v)?;
            }
            if let Some(v) = read_env("BREAK_GLASS_TOKEN") {
                builder = builder.set_override("break_glass_token", v)?;
            }

            // Auth overrides
            if let Some(v) = read_env("AUTH_SECRET") {
                builder = builder.set_override("auth_secret", v)?;
            }
            if let Some(v) = read_env("GOOGLE_CLIENT_ID") {
                builder = builder.set_override("google_client_id", v)?;
            }
            if let Some(v) = read_env("GOOGLE_CLIENT_SECRET") {
                builder = builder.set_override("google_client_secret", v)?;
            }
            if let Some(v) = read_env("GOOGLE_DISCOVERY_URL") {
                builder = builder.set_override("google_discovery_url", v)?;
            }
            if let Some(v) = read_env("GOOGLE_REDIRECT_URI") {
                builder = builder.set_override("google_redirect_uri", v)?;
            }
            if let Some(v) = read_env("GOOGLE_ALLOWED_DOMAINS") {
                builder = builder.set_override("google_allowed_domains", v)?;
            }
            if let Some(v) = read_env("KEYCLOAK_CLIENT_ID") {
                builder = builder.set_override("keycloak_client_id", v)?;
            }
            if let Some(v) = read_env("KEYCLOAK_CLIENT_SECRET") {
                builder = builder.set_override("keycloak_client_secret", v)?;
            }
            if let Some(v) = read_env("KEYCLOAK_DISCOVERY_URL") {
                builder = builder.set_override("keycloak_discovery_url", v)?;
            }
            if let Some(v) = read_env("KEYCLOAK_REDIRECT_URI") {
                builder = builder.set_override("keycloak_redirect_uri", v)?;
            }
            if let Some(v) = read_env("KEYCLOAK_REALM") {
                builder = builder.set_override("keycloak_realm", v)?;
            }

            if let Some(v) = read_env("LOG_LEVEL") {
                builder = builder.set_override("log_level", v)?;
            }
            if let Some(v) = read_env("LOG_FORMAT") {
                builder = builder.set_override("log_format", v)?;
            }
            if let Some(v) = read_env("SQL_LOG_LEVEL") {
                builder = builder.set_override("sql_log_level", v)?;
            }
            if let Some(v) = read_env("EVIDENCE_ALLOWED_TYPES") {
                builder = builder.set_override("evidence_allowed_types", v)?;
            }
            if let Some(v) = read_env("EVIDENCE_STORAGE_PATH") {
                builder = builder.set_override("evidence_storage_path", v)?;
            }
            if let Some(v) = read_env("SCAN_ALLOWLIST_CIDRS") {
                builder = builder.set_override("scan_allowlist_cidrs", v)?;
            }
            if let Some(v) = read_env("SCAN_ALLOWLIST_DOMAINS") {
                builder = builder.set_override("scan_allowlist_domains", v)?;
            }

            // Numeric overrides
            if let Some(v) = read_env("MAX_EVIDENCE_BYTES").and_then(|s| s.parse::<u64>().ok()) {
                builder = builder.set_override("max_evidence_bytes", v)?;
            }
            if let Some(v) = read_env("HTTP_TIMEOUT_SECONDS").and_then(|s| s.parse::<f64>().ok()) {
                builder = builder.set_override("http_timeout_seconds", v)?;
            }
            if let Some(v) = read_env("TLS_TIMEOUT_SECONDS").and_then(|s| s.parse::<f64>().ok()) {
                builder = builder.set_override("tls_timeout_seconds", v)?;
            }
            if let Some(v) = read_env("DNS_CONCURRENCY").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("dns_concurrency", v)?;
            }
            if let Some(v) = read_env("RDNS_CONCURRENCY").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("rdns_concurrency", v)?;
            }
            if let Some(v) = read_env("TCP_SCAN_TIMEOUT").and_then(|s| s.parse::<f64>().ok()) {
                builder = builder.set_override("tcp_scan_timeout", v)?;
            }
            if let Some(v) = read_env("TCP_SCAN_CONCURRENCY").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("tcp_scan_concurrency", v)?;
            }
            if let Some(v) = read_env("MAX_CIDR_HOSTS").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("max_cidr_hosts", v)?;
            }
            if let Some(v) = read_env("MAX_DISCOVERY_DEPTH").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("max_discovery_depth", v)?;
            }
            if let Some(v) = read_env("SUBDOMAIN_ENUM_TIMEOUT").and_then(|s| s.parse::<f64>().ok())
            {
                builder = builder.set_override("subdomain_enum_timeout", v)?;
            }
            if let Some(v) =
                read_env("RELATED_ASSET_CONFIDENCE_DEFAULT").and_then(|s| s.parse::<f64>().ok())
            {
                builder = builder.set_override("related_asset_confidence_default", v)?;
            }
            if let Some(v) =
                read_env("MAX_ASSETS_PER_DISCOVERY").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("max_assets_per_discovery", v)?;
            }
            if let Some(v) = read_env("MIN_PIVOT_CONFIDENCE").and_then(|s| s.parse::<f64>().ok()) {
                builder = builder.set_override("min_pivot_confidence", v)?;
            }
            if let Some(v) = read_env("MAX_ORGS_PER_DOMAIN").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("max_orgs_per_domain", v)?;
            }
            if let Some(v) = read_env("MAX_DOMAINS_PER_ORG").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("max_domains_per_org", v)?;
            }
            if let Some(v) = read_env("RATE_LIMIT_REQUESTS").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("rate_limit_requests", v)?;
            }
            if let Some(v) =
                read_env("RATE_LIMIT_WINDOW_SECONDS").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("rate_limit_window_seconds", v)?;
            }
            if let Some(v) = read_env("MAX_CONCURRENT_SCANS").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("max_concurrent_scans", v)?;
            }
            if let Some(v) =
                read_env("SCAN_QUEUE_CHECK_INTERVAL").and_then(|s| s.parse::<f64>().ok())
            {
                builder = builder.set_override("scan_queue_check_interval", v)?;
            }
            if let Some(v) =
                read_env("MAX_ACTIVE_SCANS_PER_USER").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("max_active_scans_per_user", v)?;
            }
            if let Some(v) =
                read_env("MAX_ACTIVE_DISCOVERY_PER_USER").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("max_active_discovery_per_user", v)?;
            }
            if let Some(v) =
                read_env("REINDEX_MIN_INTERVAL_SECONDS").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("reindex_min_interval_seconds", v)?;
            }
            if let Some(v) =
                read_env("OSINT_SOURCE_CONCURRENCY").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("osint_source_concurrency", v)?;
            }
            if let Some(v) =
                read_env("OSINT_SOURCE_TIMEOUT_SECONDS").and_then(|s| s.parse::<f64>().ok())
            {
                builder = builder.set_override("osint_source_timeout_seconds", v)?;
            }
            if let Some(v) =
                read_env("OSINT_MAX_RESULTS_PER_SOURCE").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("osint_max_results_per_source", v)?;
            }
            if let Some(v) =
                read_env("DNS_BRUTEFORCE_MAX_WORDS").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("dns_bruteforce_max_words", v)?;
            }
            if let Some(v) =
                read_env("DNS_PERMUTATION_MAX_CANDIDATES").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("dns_permutation_max_candidates", v)?;
            }
            if let Some(v) =
                read_env("DNS_PERMUTATION_MAX_SEEDS").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("dns_permutation_max_seeds", v)?;
            }
            if let Some(v) = read_env("ACTIVE_DNS_CONCURRENCY").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("active_dns_concurrency", v)?;
            }
            if let Some(v) = read_env("ASN_MAX_PREFIXES").and_then(|s| s.parse::<u32>().ok()) {
                builder = builder.set_override("asn_max_prefixes", v)?;
            }
            if let Some(v) =
                read_env("REVERSE_DNS_SWEEP_MAX_HOSTS").and_then(|s| s.parse::<u32>().ok())
            {
                builder = builder.set_override("reverse_dns_sweep_max_hosts", v)?;
            }
            if let Some(v) =
                read_env("AUTH_SESSION_EXPIRY_SECONDS").and_then(|s| s.parse::<u64>().ok())
            {
                builder = builder.set_override("auth_session_expiry_seconds", v)?;
            }

            // Boolean overrides
            if let Some(v) = parse_bool_env("ENABLE_WAYBACK") {
                builder = builder.set_override("enable_wayback", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_URLSCAN") {
                builder = builder.set_override("enable_urlscan", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_OTX") {
                builder = builder.set_override("enable_otx", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_DNS_RECORD_EXPANSION") {
                builder = builder.set_override("enable_dns_record_expansion", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_WEB_CRAWL") {
                builder = builder.set_override("enable_web_crawl", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_CLOUD_STORAGE_DISCOVERY") {
                builder = builder.set_override("enable_cloud_storage_discovery", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_WIKIDATA") {
                builder = builder.set_override("enable_wikidata", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_OPENCORPORATES") {
                builder = builder.set_override("enable_opencorporates", v)?;
            }
            if let Some(v) = parse_bool_env("SKIP_UNRESOLVED_DOMAINS") {
                builder = builder.set_override("skip_unresolved_domains", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_DNS_BRUTEFORCE") {
                builder = builder.set_override("enable_dns_bruteforce", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_DNS_PERMUTATIONS") {
                builder = builder.set_override("enable_dns_permutations", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_NSEC_WALK") {
                builder = builder.set_override("enable_nsec_walk", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_SRV_PROBE") {
                builder = builder.set_override("enable_srv_probe", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_ASN_DISCOVERY") {
                builder = builder.set_override("enable_asn_discovery", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_RDAP_LOOKUP") {
                builder = builder.set_override("enable_rdap_lookup", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_SAAS_TENANT_DISCOVERY") {
                builder = builder.set_override("enable_saas_tenant_discovery", v)?;
            }
            if let Some(v) = parse_bool_env("ENABLE_CNAME_CHAIN_ANALYSIS") {
                builder = builder.set_override("enable_cname_chain_analysis", v)?;
            }
            if let Some(v) = parse_bool_env("RATE_LIMIT_ENABLED") {
                builder = builder.set_override("rate_limit_enabled", v)?;
            }
            if let Some(v) = parse_bool_env("BLOCK_INTERNAL_IP_SCANS") {
                builder = builder.set_override("block_internal_ip_scans", v)?;
            }
            if let Some(v) = parse_bool_env("ALLOW_INTERNAL_SCANS") {
                builder = builder.set_override("allow_internal_scans", v)?;
            }
            if let Some(v) = parse_bool_env("ALLOW_ANON") {
                builder = builder.set_override("allow_anonymous", v)?;
            }
        }

        let settings = builder.build()?;

        let config: Settings = settings.try_deserialize()?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration values
    fn validate(&self) -> Result<(), ConfigError> {
        let environment = self.environment.to_ascii_lowercase();
        let is_production = environment == "production";

        if is_production && self.allow_anonymous {
            return Err(ConfigError::Validation(
                "allow_anonymous cannot be enabled in production".to_string(),
            ));
        }

        if is_production && self.api_keys.is_empty() {
            return Err(ConfigError::Validation(
                "api_keys must be configured in production".to_string(),
            ));
        }

        if is_production
            && (self.cors_allow_origins.is_empty()
                || self
                    .cors_allow_origins
                    .iter()
                    .any(|origin| origin.trim() == "*"))
        {
            return Err(ConfigError::Validation(
                "cors_allow_origins must be a non-empty allowlist (no '*') in production"
                    .to_string(),
            ));
        }

        if let Some(token) = &self.break_glass_token {
            if token.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "break_glass_token cannot be empty when set".to_string(),
                ));
            }
        }

        // Validate log format
        if !matches!(self.log_format.as_str(), "json" | "plain") {
            return Err(ConfigError::Validation(
                "log_format must be 'json' or 'plain'".to_string(),
            ));
        }

        // Validate positive numeric values
        if self.max_evidence_bytes == 0 {
            return Err(ConfigError::Validation(
                "max_evidence_bytes must be greater than 0".to_string(),
            ));
        }

        if self.http_timeout_seconds <= 0.0 {
            return Err(ConfigError::Validation(
                "http_timeout_seconds must be greater than 0".to_string(),
            ));
        }

        if self.tls_timeout_seconds <= 0.0 {
            return Err(ConfigError::Validation(
                "tls_timeout_seconds must be greater than 0".to_string(),
            ));
        }

        if self.tcp_scan_timeout <= 0.0 {
            return Err(ConfigError::Validation(
                "tcp_scan_timeout must be greater than 0".to_string(),
            ));
        }

        if self.subdomain_enum_timeout <= 0.0 {
            return Err(ConfigError::Validation(
                "subdomain_enum_timeout must be greater than 0".to_string(),
            ));
        }

        if self.scan_queue_check_interval <= 0.0 {
            return Err(ConfigError::Validation(
                "scan_queue_check_interval must be greater than 0".to_string(),
            ));
        }

        // Validate concurrency limits
        if self.dns_concurrency == 0 {
            return Err(ConfigError::Validation(
                "dns_concurrency must be greater than 0".to_string(),
            ));
        }

        if self.rdns_concurrency == 0 {
            return Err(ConfigError::Validation(
                "rdns_concurrency must be greater than 0".to_string(),
            ));
        }

        if self.tcp_scan_concurrency == 0 {
            return Err(ConfigError::Validation(
                "tcp_scan_concurrency must be greater than 0".to_string(),
            ));
        }

        if self.max_concurrent_scans == 0 {
            return Err(ConfigError::Validation(
                "max_concurrent_scans must be greater than 0".to_string(),
            ));
        }

        if self.rate_limit_requests == 0 {
            return Err(ConfigError::Validation(
                "rate_limit_requests must be greater than 0".to_string(),
            ));
        }

        if self.rate_limit_window_seconds == 0 {
            return Err(ConfigError::Validation(
                "rate_limit_window_seconds must be greater than 0".to_string(),
            ));
        }

        if self.max_active_scans_per_user == 0 {
            return Err(ConfigError::Validation(
                "max_active_scans_per_user must be greater than 0".to_string(),
            ));
        }

        if self.max_active_discovery_per_user == 0 {
            return Err(ConfigError::Validation(
                "max_active_discovery_per_user must be greater than 0".to_string(),
            ));
        }

        if self.reindex_min_interval_seconds == 0 {
            return Err(ConfigError::Validation(
                "reindex_min_interval_seconds must be greater than 0".to_string(),
            ));
        }

        // Validate ranges
        if self.max_cidr_hosts == 0 || self.max_cidr_hosts > 20000 {
            return Err(ConfigError::Validation(
                "max_cidr_hosts must be between 1 and 20000".to_string(),
            ));
        }

        if self.max_discovery_depth == 0 || self.max_discovery_depth > 10 {
            return Err(ConfigError::Validation(
                "max_discovery_depth must be between 1 and 10".to_string(),
            ));
        }

        if !(0.0..=1.0).contains(&self.related_asset_confidence_default) {
            return Err(ConfigError::Validation(
                "related_asset_confidence_default must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.osint_source_concurrency == 0 || self.osint_source_concurrency > 64 {
            return Err(ConfigError::Validation(
                "osint_source_concurrency must be between 1 and 64".to_string(),
            ));
        }

        if self.osint_source_timeout_seconds <= 0.0 || self.osint_source_timeout_seconds > 300.0 {
            return Err(ConfigError::Validation(
                "osint_source_timeout_seconds must be between 0 and 300".to_string(),
            ));
        }

        if self.osint_max_results_per_source == 0 {
            return Err(ConfigError::Validation(
                "osint_max_results_per_source must be greater than 0".to_string(),
            ));
        }

        if self.active_dns_concurrency == 0 || self.active_dns_concurrency > 1000 {
            return Err(ConfigError::Validation(
                "active_dns_concurrency must be between 1 and 1000".to_string(),
            ));
        }

        // A brute force big enough to be a denial-of-service against the target's
        // own resolvers is not discovery. The cap is generous but finite.
        if self.dns_bruteforce_max_words > 1_000_000 {
            return Err(ConfigError::Validation(
                "dns_bruteforce_max_words must not exceed 1000000".to_string(),
            ));
        }

        if self.dns_permutation_max_candidates > 250_000 {
            return Err(ConfigError::Validation(
                "dns_permutation_max_candidates must not exceed 250000".to_string(),
            ));
        }

        // Validate recursive discovery limits
        if self.max_assets_per_discovery == 0 || self.max_assets_per_discovery > 100000 {
            return Err(ConfigError::Validation(
                "max_assets_per_discovery must be between 1 and 100000".to_string(),
            ));
        }

        if !(0.0..=1.0).contains(&self.min_pivot_confidence) {
            return Err(ConfigError::Validation(
                "min_pivot_confidence must be between 0.0 and 1.0".to_string(),
            ));
        }

        if self.max_orgs_per_domain == 0 || self.max_orgs_per_domain > 50 {
            return Err(ConfigError::Validation(
                "max_orgs_per_domain must be between 1 and 50".to_string(),
            ));
        }

        if self.max_domains_per_org == 0 || self.max_domains_per_org > 500 {
            return Err(ConfigError::Validation(
                "max_domains_per_org must be between 1 and 500".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new().expect("Failed to create default settings")
    }
}

/// Global settings instance
static SETTINGS: OnceLock<Settings> = OnceLock::new();

/// Get cached settings instance (equivalent to Python's @lru_cache)
pub fn get_settings() -> &'static Settings {
    SETTINGS.get_or_init(|| Settings::new().expect("Failed to initialize settings"))
}

/// Common ports for scanning (matches Python backend)
pub const COMMON_PORTS: &[u16] = &[
    80, 443, 22, 25, 53, 110, 143, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 3389, 5900,
];

/// HTTP security headers (matches Python backend)
pub fn security_headers() -> HashMap<&'static str, &'static str> {
    let mut headers = HashMap::new();
    headers.insert("X-Content-Type-Options", "nosniff");
    headers.insert("X-Frame-Options", "DENY");
    headers.insert("X-XSS-Protection", "1; mode=block");
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin");
    headers
}

/// Subdomain wordlist for brute-force fallback (matches Python backend)
pub const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www",
    "mail",
    "mx",
    "smtp",
    "imap",
    "pop",
    "vpn",
    "dev",
    "staging",
    "api",
    "app",
    "portal",
    "intranet",
    "test",
    "beta",
    "cdn",
    "assets",
    "static",
    "gw",
    "gateway",
    "sso",
    "auth",
    "admin",
    "docs",
    "blog",
    "status",
    "shop",
    "store",
    "pay",
    "files",
    "download",
    "downloads",
    "jira",
    "confluence",
    "git",
    "gitlab",
    "grafana",
    "kibana",
    "log",
    "logs",
    "monitor",
    "monitoring",
    "ns1",
    "ns2",
    "ns",
    "devops",
    "prod",
    "production",
    "stage",
    "ci",
    "cd",
    "build",
    "jenkins",
    "backup",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "cache",
    "queue",
    "ftp",
    "sftp",
    "ssh",
    "remote",
    "rdp",
    "webmail",
    "cpanel",
    "whm",
    "plesk",
];

#[cfg(test)]
mod tests;

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;

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

/// Application settings with environment variable support
/// Matches the Python backend configuration exactly
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    // Database
    pub database_url: String,
    
    // OpenSearch/Elasticsearch
    pub opensearch_url: Option<String>,
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
    
    // Security
    #[serde(deserialize_with = "deserialize_comma_separated")]
    pub cors_allow_origins: Vec<String>,
    pub api_key_header: String,
    #[serde(deserialize_with = "deserialize_comma_separated")]
    pub api_keys: Vec<String>,
    
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
    pub related_asset_confidence_default: f64,
    
    // Rate Limiting
    pub rate_limit_enabled: bool,
    pub rate_limit_requests: u32,
    pub rate_limit_window_seconds: u32,
    
    // Background Tasks
    pub max_concurrent_scans: u32,
    pub scan_queue_check_interval: f64,
}

impl Settings {
    /// Create new settings instance from environment variables and .env file
    pub fn new() -> Result<Self, ConfigError> {
        Self::new_with_env_file(true)
    }
    
    /// Create new settings instance with optional .env file loading
    pub fn new_with_env_file(load_env_file: bool) -> Result<Self, ConfigError> {
        // Serialize settings construction to avoid cross-test environment races
        // Tests frequently mutate process env; locking ensures consistent reads
        static SETTINGS_BUILD_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        let build_mutex = SETTINGS_BUILD_MUTEX.get_or_init(|| Mutex::new(()));
        let _guard = build_mutex.lock().expect("Failed to lock settings build mutex");

        // Load .env file if it exists and requested (skip during tests for determinism)
        #[cfg(not(test))]
        {
            if load_env_file {
                dotenvy::dotenv().ok();
            }
        }

        let mut builder = config::Config::builder()
            // Database defaults
            .set_default("database_url", "postgresql://easm:easm@localhost:5432/easm")?
            .set_default("opensearch_url", None::<String>)?
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
            
            // Security defaults
            .set_default("cors_allow_origins", "http://localhost:3000,http://127.0.0.1:3000")?
            .set_default("api_key_header", "X-API-Key")?
            .set_default("api_keys", "")?
            
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
            
            // Discovery Settings defaults
            .set_default("max_cidr_hosts", 4096u32)?
            .set_default("max_discovery_depth", 3u32)?
            .set_default("subdomain_enum_timeout", 120.0)?
            .set_default("enable_wayback", true)?
            .set_default("enable_urlscan", false)?
            .set_default("enable_otx", false)?
            .set_default("enable_dns_record_expansion", true)?
            .set_default("enable_web_crawl", true)?
            .set_default("enable_cloud_storage_discovery", true)?
            .set_default("enable_wikidata", true)?
            .set_default("enable_opencorporates", false)?
            .set_default("related_asset_confidence_default", 0.3)?
            
            // Rate Limiting defaults
            .set_default("rate_limit_enabled", true)?
            .set_default("rate_limit_requests", 100u32)?
            .set_default("rate_limit_window_seconds", 60u32)?
            
            // Background Tasks defaults
            .set_default("max_concurrent_scans", 5u32)?
            .set_default("scan_queue_check_interval", 5.0)?
            ;

        // Load .env as a configuration source instead of mutating process environment (skip in tests)
        #[cfg(not(test))]
        {
            if load_env_file {
                builder = builder.add_source(config::File::with_name(".env").required(false));
            }
        }

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
        if let Some(v) = read_env("DATABASE_URL").or_else(|| std::env::var("database_url").ok()) { builder = builder.set_override("database_url", v)?; }
        if let Some(v) = read_env("OPENSEARCH_URL") { builder = builder.set_override("opensearch_url", v)?; }
        if let Some(v) = read_env("ELASTICSEARCH_URL") { builder = builder.set_override("elasticsearch_url", v)?; }
        if let Some(v) = read_env("ELASTICSEARCH_ASSET_INDEX") { builder = builder.set_override("elasticsearch_asset_index", v)?; }
        if let Some(v) = read_env("ELASTICSEARCH_FINDING_INDEX") { builder = builder.set_override("elasticsearch_finding_index", v)?; }
        if let Some(v) = read_env("CERTSPOTTER_API_TOKEN") { builder = builder.set_override("certspotter_api_token", v)?; }
        if let Some(v) = read_env("VIRUSTOTAL_API_KEY") { builder = builder.set_override("virustotal_api_key", v)?; }
        if let Some(v) = read_env("SHODAN_API_KEY") { builder = builder.set_override("shodan_api_key", v)?; }
        if let Some(v) = read_env("URLSCAN_API_KEY") { builder = builder.set_override("urlscan_api_key", v)?; }
        if let Some(v) = read_env("OTX_API_KEY") { builder = builder.set_override("otx_api_key", v)?; }
        if let Some(v) = read_env("CLEARBIT_API_KEY") { builder = builder.set_override("clearbit_api_key", v)?; }
        if let Some(v) = read_env("OPENCORPORATES_API_TOKEN") { builder = builder.set_override("opencorporates_api_token", v)?; }
        if let Some(v) = read_env("CORS_ALLOW_ORIGINS") { builder = builder.set_override("cors_allow_origins", v)?; }
        if let Some(v) = read_env("API_KEY_HEADER") { builder = builder.set_override("api_key_header", v)?; }
        if let Some(v) = read_env("API_KEYS") { builder = builder.set_override("api_keys", v)?; }
        if let Some(v) = read_env("LOG_LEVEL") { builder = builder.set_override("log_level", v)?; }
        if let Some(v) = read_env("LOG_FORMAT") { builder = builder.set_override("log_format", v)?; }
        if let Some(v) = read_env("SQL_LOG_LEVEL") { builder = builder.set_override("sql_log_level", v)?; }
        if let Some(v) = read_env("EVIDENCE_ALLOWED_TYPES") { builder = builder.set_override("evidence_allowed_types", v)?; }
        if let Some(v) = read_env("EVIDENCE_STORAGE_PATH") { builder = builder.set_override("evidence_storage_path", v)?; }

        // Numeric overrides
        if let Some(v) = read_env("MAX_EVIDENCE_BYTES").and_then(|s| s.parse::<u64>().ok()) { builder = builder.set_override("max_evidence_bytes", v)?; }
        if let Some(v) = read_env("HTTP_TIMEOUT_SECONDS").and_then(|s| s.parse::<f64>().ok()) { builder = builder.set_override("http_timeout_seconds", v)?; }
        if let Some(v) = read_env("TLS_TIMEOUT_SECONDS").and_then(|s| s.parse::<f64>().ok()) { builder = builder.set_override("tls_timeout_seconds", v)?; }
        if let Some(v) = read_env("DNS_CONCURRENCY").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("dns_concurrency", v)?; }
        if let Some(v) = read_env("RDNS_CONCURRENCY").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("rdns_concurrency", v)?; }
        if let Some(v) = read_env("TCP_SCAN_TIMEOUT").and_then(|s| s.parse::<f64>().ok()) { builder = builder.set_override("tcp_scan_timeout", v)?; }
        if let Some(v) = read_env("TCP_SCAN_CONCURRENCY").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("tcp_scan_concurrency", v)?; }
        if let Some(v) = read_env("MAX_CIDR_HOSTS").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("max_cidr_hosts", v)?; }
        if let Some(v) = read_env("MAX_DISCOVERY_DEPTH").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("max_discovery_depth", v)?; }
        if let Some(v) = read_env("SUBDOMAIN_ENUM_TIMEOUT").and_then(|s| s.parse::<f64>().ok()) { builder = builder.set_override("subdomain_enum_timeout", v)?; }
        if let Some(v) = read_env("RELATED_ASSET_CONFIDENCE_DEFAULT").and_then(|s| s.parse::<f64>().ok()) { builder = builder.set_override("related_asset_confidence_default", v)?; }
        if let Some(v) = read_env("RATE_LIMIT_REQUESTS").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("rate_limit_requests", v)?; }
        if let Some(v) = read_env("RATE_LIMIT_WINDOW_SECONDS").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("rate_limit_window_seconds", v)?; }
        if let Some(v) = read_env("MAX_CONCURRENT_SCANS").and_then(|s| s.parse::<u32>().ok()) { builder = builder.set_override("max_concurrent_scans", v)?; }
        if let Some(v) = read_env("SCAN_QUEUE_CHECK_INTERVAL").and_then(|s| s.parse::<f64>().ok()) { builder = builder.set_override("scan_queue_check_interval", v)?; }

        // Boolean overrides
        if let Some(v) = parse_bool_env("ENABLE_WAYBACK") { builder = builder.set_override("enable_wayback", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_URLSCAN") { builder = builder.set_override("enable_urlscan", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_OTX") { builder = builder.set_override("enable_otx", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_DNS_RECORD_EXPANSION") { builder = builder.set_override("enable_dns_record_expansion", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_WEB_CRAWL") { builder = builder.set_override("enable_web_crawl", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_CLOUD_STORAGE_DISCOVERY") { builder = builder.set_override("enable_cloud_storage_discovery", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_WIKIDATA") { builder = builder.set_override("enable_wikidata", v)?; }
        if let Some(v) = parse_bool_env("ENABLE_OPENCORPORATES") { builder = builder.set_override("enable_opencorporates", v)?; }
        if let Some(v) = parse_bool_env("RATE_LIMIT_ENABLED") { builder = builder.set_override("rate_limit_enabled", v)?; }

        let settings = builder.build()?;

        let config: Settings = settings.try_deserialize()?;
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }
    

    
    /// Validate configuration values
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate log format
        if !matches!(self.log_format.as_str(), "json" | "plain") {
            return Err(ConfigError::Validation(
                "log_format must be 'json' or 'plain'".to_string()
            ));
        }
        
        // Validate positive numeric values
        if self.max_evidence_bytes == 0 {
            return Err(ConfigError::Validation(
                "max_evidence_bytes must be greater than 0".to_string()
            ));
        }
        
        if self.http_timeout_seconds <= 0.0 {
            return Err(ConfigError::Validation(
                "http_timeout_seconds must be greater than 0".to_string()
            ));
        }
        
        if self.tls_timeout_seconds <= 0.0 {
            return Err(ConfigError::Validation(
                "tls_timeout_seconds must be greater than 0".to_string()
            ));
        }
        
        if self.tcp_scan_timeout <= 0.0 {
            return Err(ConfigError::Validation(
                "tcp_scan_timeout must be greater than 0".to_string()
            ));
        }
        
        if self.subdomain_enum_timeout <= 0.0 {
            return Err(ConfigError::Validation(
                "subdomain_enum_timeout must be greater than 0".to_string()
            ));
        }
        
        if self.scan_queue_check_interval <= 0.0 {
            return Err(ConfigError::Validation(
                "scan_queue_check_interval must be greater than 0".to_string()
            ));
        }
        
        // Validate concurrency limits
        if self.dns_concurrency == 0 {
            return Err(ConfigError::Validation(
                "dns_concurrency must be greater than 0".to_string()
            ));
        }
        
        if self.rdns_concurrency == 0 {
            return Err(ConfigError::Validation(
                "rdns_concurrency must be greater than 0".to_string()
            ));
        }
        
        if self.tcp_scan_concurrency == 0 {
            return Err(ConfigError::Validation(
                "tcp_scan_concurrency must be greater than 0".to_string()
            ));
        }
        
        if self.max_concurrent_scans == 0 {
            return Err(ConfigError::Validation(
                "max_concurrent_scans must be greater than 0".to_string()
            ));
        }
        
        if self.rate_limit_requests == 0 {
            return Err(ConfigError::Validation(
                "rate_limit_requests must be greater than 0".to_string()
            ));
        }
        
        if self.rate_limit_window_seconds == 0 {
            return Err(ConfigError::Validation(
                "rate_limit_window_seconds must be greater than 0".to_string()
            ));
        }
        
        // Validate ranges
        if self.max_cidr_hosts == 0 || self.max_cidr_hosts > 20000 {
            return Err(ConfigError::Validation(
                "max_cidr_hosts must be between 1 and 20000".to_string()
            ));
        }
        
        if self.max_discovery_depth == 0 || self.max_discovery_depth > 10 {
            return Err(ConfigError::Validation(
                "max_discovery_depth must be between 1 and 10".to_string()
            ));
        }
        
        if !(0.0..=1.0).contains(&self.related_asset_confidence_default) {
            return Err(ConfigError::Validation(
                "related_asset_confidence_default must be between 0.0 and 1.0".to_string()
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
    SETTINGS.get_or_init(|| {
        Settings::new().expect("Failed to initialize settings")
    })
}

/// Common ports for scanning (matches Python backend)
pub const COMMON_PORTS: &[u16] = &[
    80, 443, 22, 25, 53, 110, 143, 587, 993, 995,
    3306, 5432, 6379, 8080, 8443, 3389, 5900
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
    "www", "mail", "mx", "smtp", "imap", "pop", "vpn", "dev", "staging", "api",
    "app", "portal", "intranet", "test", "beta", "cdn", "assets", "static", "gw",
    "gateway", "sso", "auth", "admin", "docs", "blog", "status", "shop", "store",
    "pay", "files", "download", "downloads", "jira", "confluence", "git", "gitlab",
    "grafana", "kibana", "log", "logs", "monitor", "monitoring", "ns1", "ns2",
    "ns", "devops", "prod", "production", "stage", "ci", "cd", "build", "jenkins",
    "backup", "db", "database", "mysql", "postgres", "redis", "cache", "queue",
    "ftp", "sftp", "ssh", "remote", "rdp", "webmail", "cpanel", "whm", "plesk"
];

#[cfg(test)]
mod tests;
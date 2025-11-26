use axum::{
    extract::{Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{context::UserContext, rbac::Role},
    config::ManagedSettings,
    error::ApiError,
    AppState,
};

#[derive(Debug, Deserialize, Default)]
pub struct SettingsQuery {
    #[serde(default)]
    pub reveal_secrets: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct SettingsUpdateRequest {
    // Google OIDC
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_discovery_url: Option<String>,
    pub google_redirect_uri: Option<String>,
    pub google_allowed_domains: Option<Vec<String>>,

    // Keycloak
    pub keycloak_client_id: Option<String>,
    pub keycloak_client_secret: Option<String>,
    pub keycloak_discovery_url: Option<String>,
    pub keycloak_redirect_uri: Option<String>,
    pub keycloak_realm: Option<String>,

    // External API Keys
    pub certspotter_api_token: Option<String>,
    pub virustotal_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    pub urlscan_api_key: Option<String>,
    pub otx_api_key: Option<String>,
    pub clearbit_api_key: Option<String>,
    pub opencorporates_api_token: Option<String>,

    // CORS
    pub cors_allow_origins: Option<Vec<String>>,

    // Logging
    pub log_level: Option<String>,
    pub log_format: Option<String>,

    // Rate limiting
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_requests: Option<u32>,
    pub rate_limit_window_seconds: Option<u32>,

    // Performance
    pub http_timeout_seconds: Option<f64>,
    pub tls_timeout_seconds: Option<f64>,
    pub dns_concurrency: Option<u32>,
    pub rdns_concurrency: Option<u32>,
    pub max_concurrent_scans: Option<u32>,

    // Evidence storage
    pub max_evidence_bytes: Option<u64>,
    pub evidence_allowed_types: Option<Vec<String>>,

    // Discovery
    pub max_cidr_hosts: Option<u32>,
    pub max_discovery_depth: Option<u32>,
    pub subdomain_enum_timeout: Option<f64>,

    // OSINT toggles
    pub enable_wayback: Option<bool>,
    pub enable_urlscan: Option<bool>,
    pub enable_otx: Option<bool>,
    pub enable_dns_record_expansion: Option<bool>,
    pub enable_web_crawl: Option<bool>,
    pub enable_cloud_storage_discovery: Option<bool>,
    pub enable_wikidata: Option<bool>,
    pub enable_opencorporates: Option<bool>,

    // Recursive discovery
    pub max_assets_per_discovery: Option<u32>,
    pub min_pivot_confidence: Option<f64>,
    pub max_orgs_per_domain: Option<u32>,
    pub max_domains_per_org: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SecretField {
    pub is_set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SettingsView {
    // Google OIDC
    pub google_client_id: Option<String>,
    pub google_client_secret: SecretField,
    pub google_discovery_url: Option<String>,
    pub google_redirect_uri: Option<String>,
    pub google_allowed_domains: Vec<String>,

    // Keycloak
    pub keycloak_client_id: Option<String>,
    pub keycloak_client_secret: SecretField,
    pub keycloak_discovery_url: Option<String>,
    pub keycloak_redirect_uri: Option<String>,
    pub keycloak_realm: Option<String>,

    // External API Keys
    pub certspotter_api_token: SecretField,
    pub virustotal_api_key: SecretField,
    pub shodan_api_key: SecretField,
    pub urlscan_api_key: SecretField,
    pub otx_api_key: SecretField,
    pub clearbit_api_key: SecretField,
    pub opencorporates_api_token: SecretField,

    // CORS
    pub cors_allow_origins: Vec<String>,

    // Logging
    pub log_level: String,
    pub log_format: String,

    // Rate limiting
    pub rate_limit_enabled: bool,
    pub rate_limit_requests: u32,
    pub rate_limit_window_seconds: u32,

    // Performance
    pub http_timeout_seconds: f64,
    pub tls_timeout_seconds: f64,
    pub dns_concurrency: u32,
    pub rdns_concurrency: u32,
    pub max_concurrent_scans: u32,

    // Evidence storage
    pub max_evidence_bytes: u64,
    pub evidence_allowed_types: Vec<String>,

    // Discovery
    pub max_cidr_hosts: u32,
    pub max_discovery_depth: u32,
    pub subdomain_enum_timeout: f64,

    // OSINT toggles
    pub enable_wayback: bool,
    pub enable_urlscan: bool,
    pub enable_otx: bool,
    pub enable_dns_record_expansion: bool,
    pub enable_web_crawl: bool,
    pub enable_cloud_storage_discovery: bool,
    pub enable_wikidata: bool,
    pub enable_opencorporates: bool,

    // Recursive discovery
    pub max_assets_per_discovery: u32,
    pub min_pivot_confidence: f64,
    pub max_orgs_per_domain: u32,
    pub max_domains_per_org: u32,
}

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    pub settings: SettingsView,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

pub async fn get_settings(
    Extension(user): Extension<UserContext>,
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
) -> Result<Json<SettingsResponse>, ApiError> {
    require_admin(&user)?;

    let record = state.settings_service.get_managed().await?;
    let view = to_view(&record.managed, query.reveal_secrets);

    Ok(Json(SettingsResponse {
        settings: view,
        updated_at: record.updated_at,
        updated_by: record.updated_by,
    }))
}

pub async fn update_settings(
    Extension(user): Extension<UserContext>,
    State(state): State<AppState>,
    Query(query): Query<SettingsQuery>,
    Json(update): Json<SettingsUpdateRequest>,
) -> Result<Json<SettingsResponse>, ApiError> {
    require_admin(&user)?;

    let current = state.settings_service.get_managed().await?;
    let merged = merge_settings(current.managed, update);
    state
        .settings_service
        .update_managed(merged, user.user_id)
        .await?;

    let updated = state.settings_service.get_managed().await?;
    let view = to_view(&updated.managed, query.reveal_secrets);

    Ok(Json(SettingsResponse {
        settings: view,
        updated_at: updated.updated_at,
        updated_by: updated.updated_by,
    }))
}

fn require_admin(user: &UserContext) -> Result<(), ApiError> {
    if user.has_role(Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Authorization("Admin role required".to_string()))
    }
}

fn to_view(settings: &ManagedSettings, reveal_secrets: bool) -> SettingsView {
    SettingsView {
        google_client_id: settings.google_client_id.clone(),
        google_client_secret: secret_field(&settings.google_client_secret, reveal_secrets),
        google_discovery_url: settings.google_discovery_url.clone(),
        google_redirect_uri: settings.google_redirect_uri.clone(),
        google_allowed_domains: settings.google_allowed_domains.clone(),
        keycloak_client_id: settings.keycloak_client_id.clone(),
        keycloak_client_secret: secret_field(&settings.keycloak_client_secret, reveal_secrets),
        keycloak_discovery_url: settings.keycloak_discovery_url.clone(),
        keycloak_redirect_uri: settings.keycloak_redirect_uri.clone(),
        keycloak_realm: settings.keycloak_realm.clone(),
        certspotter_api_token: secret_field(&settings.certspotter_api_token, reveal_secrets),
        virustotal_api_key: secret_field(&settings.virustotal_api_key, reveal_secrets),
        shodan_api_key: secret_field(&settings.shodan_api_key, reveal_secrets),
        urlscan_api_key: secret_field(&settings.urlscan_api_key, reveal_secrets),
        otx_api_key: secret_field(&settings.otx_api_key, reveal_secrets),
        clearbit_api_key: secret_field(&settings.clearbit_api_key, reveal_secrets),
        opencorporates_api_token: secret_field(&settings.opencorporates_api_token, reveal_secrets),
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

fn secret_field(value: &Option<String>, reveal: bool) -> SecretField {
    SecretField {
        is_set: value.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
        value: if reveal { value.clone() } else { None },
    }
}

fn merge_settings(mut current: ManagedSettings, update: SettingsUpdateRequest) -> ManagedSettings {
    // SSO
    if let Some(v) = update.google_client_id {
        current.google_client_id = normalize_string(v);
    }
    if let Some(v) = update.google_client_secret {
        current.google_client_secret = normalize_string(v);
    }
    if let Some(v) = update.google_discovery_url {
        current.google_discovery_url = normalize_string(v);
    }
    if let Some(v) = update.google_redirect_uri {
        current.google_redirect_uri = normalize_string(v);
    }
    if let Some(v) = update.google_allowed_domains {
        current.google_allowed_domains = normalize_vec(v);
    }

    if let Some(v) = update.keycloak_client_id {
        current.keycloak_client_id = normalize_string(v);
    }
    if let Some(v) = update.keycloak_client_secret {
        current.keycloak_client_secret = normalize_string(v);
    }
    if let Some(v) = update.keycloak_discovery_url {
        current.keycloak_discovery_url = normalize_string(v);
    }
    if let Some(v) = update.keycloak_redirect_uri {
        current.keycloak_redirect_uri = normalize_string(v);
    }
    if let Some(v) = update.keycloak_realm {
        current.keycloak_realm = normalize_string(v);
    }

    // API keys
    if let Some(v) = update.certspotter_api_token {
        current.certspotter_api_token = normalize_string(v);
    }
    if let Some(v) = update.virustotal_api_key {
        current.virustotal_api_key = normalize_string(v);
    }
    if let Some(v) = update.shodan_api_key {
        current.shodan_api_key = normalize_string(v);
    }
    if let Some(v) = update.urlscan_api_key {
        current.urlscan_api_key = normalize_string(v);
    }
    if let Some(v) = update.otx_api_key {
        current.otx_api_key = normalize_string(v);
    }
    if let Some(v) = update.clearbit_api_key {
        current.clearbit_api_key = normalize_string(v);
    }
    if let Some(v) = update.opencorporates_api_token {
        current.opencorporates_api_token = normalize_string(v);
    }

    // CORS
    if let Some(v) = update.cors_allow_origins {
        current.cors_allow_origins = normalize_vec(v);
    }

    // Logging
    if let Some(v) = update.log_level {
        current.log_level = v;
    }
    if let Some(v) = update.log_format {
        current.log_format = v;
    }

    // Rate limiting
    if let Some(v) = update.rate_limit_enabled {
        current.rate_limit_enabled = v;
    }
    if let Some(v) = update.rate_limit_requests {
        current.rate_limit_requests = v;
    }
    if let Some(v) = update.rate_limit_window_seconds {
        current.rate_limit_window_seconds = v;
    }

    // Performance
    if let Some(v) = update.http_timeout_seconds {
        current.http_timeout_seconds = v;
    }
    if let Some(v) = update.tls_timeout_seconds {
        current.tls_timeout_seconds = v;
    }
    if let Some(v) = update.dns_concurrency {
        current.dns_concurrency = v;
    }
    if let Some(v) = update.rdns_concurrency {
        current.rdns_concurrency = v;
    }
    if let Some(v) = update.max_concurrent_scans {
        current.max_concurrent_scans = v;
    }

    // Evidence
    if let Some(v) = update.max_evidence_bytes {
        current.max_evidence_bytes = v;
    }
    if let Some(v) = update.evidence_allowed_types {
        current.evidence_allowed_types = normalize_vec(v);
    }

    // Discovery + OSINT
    if let Some(v) = update.max_cidr_hosts {
        current.max_cidr_hosts = v;
    }
    if let Some(v) = update.max_discovery_depth {
        current.max_discovery_depth = v;
    }
    if let Some(v) = update.subdomain_enum_timeout {
        current.subdomain_enum_timeout = v;
    }
    if let Some(v) = update.enable_wayback {
        current.enable_wayback = v;
    }
    if let Some(v) = update.enable_urlscan {
        current.enable_urlscan = v;
    }
    if let Some(v) = update.enable_otx {
        current.enable_otx = v;
    }
    if let Some(v) = update.enable_dns_record_expansion {
        current.enable_dns_record_expansion = v;
    }
    if let Some(v) = update.enable_web_crawl {
        current.enable_web_crawl = v;
    }
    if let Some(v) = update.enable_cloud_storage_discovery {
        current.enable_cloud_storage_discovery = v;
    }
    if let Some(v) = update.enable_wikidata {
        current.enable_wikidata = v;
    }
    if let Some(v) = update.enable_opencorporates {
        current.enable_opencorporates = v;
    }

    // Recursive discovery
    if let Some(v) = update.max_assets_per_discovery {
        current.max_assets_per_discovery = v;
    }
    if let Some(v) = update.min_pivot_confidence {
        current.min_pivot_confidence = v;
    }
    if let Some(v) = update.max_orgs_per_domain {
        current.max_orgs_per_domain = v;
    }
    if let Some(v) = update.max_domains_per_org {
        current.max_domains_per_org = v;
    }

    current.normalized()
}

fn normalize_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::context::UserContext, config::ManagedSettings, error::ApiError, AppState};

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
    pub securitytrails_api_key: Option<String>,
    pub censys_api_key: Option<String>,
    pub censys_org_id: Option<String>,
    pub chaos_api_key: Option<String>,
    pub leakix_api_key: Option<String>,
    pub fullhunt_api_key: Option<String>,
    pub binaryedge_api_key: Option<String>,
    pub netlas_api_key: Option<String>,

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
    pub max_active_scans_per_user: Option<u32>,
    pub max_active_discovery_per_user: Option<u32>,
    pub block_internal_ip_scans: Option<bool>,

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

    pub skip_unresolved_domains: Option<bool>,

    // Passive OSINT fan-out
    pub osint_source_concurrency: Option<u32>,
    pub osint_source_timeout_seconds: Option<f64>,
    pub osint_max_results_per_source: Option<u32>,

    // Active DNS discovery
    pub enable_dns_bruteforce: Option<bool>,
    pub enable_dns_permutations: Option<bool>,
    pub enable_nsec_walk: Option<bool>,
    pub enable_srv_probe: Option<bool>,
    pub dns_bruteforce_wordlist_path: Option<String>,
    pub dns_bruteforce_max_words: Option<u32>,
    pub dns_permutation_max_candidates: Option<u32>,
    pub dns_permutation_max_seeds: Option<u32>,
    pub active_dns_concurrency: Option<u32>,

    // Infrastructure attribution
    pub enable_asn_discovery: Option<bool>,
    pub enable_rdap_lookup: Option<bool>,
    pub enable_saas_tenant_discovery: Option<bool>,
    pub enable_cname_chain_analysis: Option<bool>,
    pub asn_max_prefixes: Option<u32>,
    pub reverse_dns_sweep_max_hosts: Option<u32>,

    // Search
    pub reindex_min_interval_seconds: Option<u32>,
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
    pub securitytrails_api_key: SecretField,
    pub censys_api_key: SecretField,
    /// Not a secret: Censys pairs the personal access token with a plain
    /// organisation identifier, which is useless on its own.
    pub censys_org_id: Option<String>,
    pub chaos_api_key: SecretField,
    pub leakix_api_key: SecretField,
    pub fullhunt_api_key: SecretField,
    pub binaryedge_api_key: SecretField,
    pub netlas_api_key: SecretField,

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
    pub max_active_scans_per_user: u32,
    pub max_active_discovery_per_user: u32,
    pub block_internal_ip_scans: bool,

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

    pub skip_unresolved_domains: bool,

    // Passive OSINT fan-out
    pub osint_source_concurrency: u32,
    pub osint_source_timeout_seconds: f64,
    pub osint_max_results_per_source: u32,

    // Active DNS discovery
    pub enable_dns_bruteforce: bool,
    pub enable_dns_permutations: bool,
    pub enable_nsec_walk: bool,
    pub enable_srv_probe: bool,
    pub dns_bruteforce_wordlist_path: Option<String>,
    pub dns_bruteforce_max_words: u32,
    pub dns_permutation_max_candidates: u32,
    pub dns_permutation_max_seeds: u32,
    pub active_dns_concurrency: u32,

    // Infrastructure attribution
    pub enable_asn_discovery: bool,
    pub enable_rdap_lookup: bool,
    pub enable_saas_tenant_discovery: bool,
    pub enable_cname_chain_analysis: bool,
    pub asn_max_prefixes: u32,
    pub reverse_dns_sweep_max_hosts: u32,

    // Search
    pub reindex_min_interval_seconds: u32,
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
    headers: HeaderMap,
) -> Result<Json<SettingsResponse>, ApiError> {
    require_global_admin(&user)?;

    let record = state.settings_service.get_managed().await?;
    let reveal = resolve_break_glass(&user, &state, &headers, query.reveal_secrets)?;
    if reveal {
        tracing::warn!(
            user_id = ?user.user_id,
            "Break-glass secret reveal via settings API"
        );
    }
    let view = to_view(&record.managed, reveal);

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
    headers: HeaderMap,
    Json(update): Json<SettingsUpdateRequest>,
) -> Result<Json<SettingsResponse>, ApiError> {
    require_global_admin(&user)?;

    let reveal = resolve_break_glass(&user, &state, &headers, query.reveal_secrets)?;

    let current = state.settings_service.get_managed().await?;
    let current_managed = current.managed.clone();
    let merged = merge_settings(current_managed.clone(), update);
    state
        .settings_service
        .update_managed(merged, user.user_id)
        .await?;

    let updated = state.settings_service.get_managed().await?;
    if reveal {
        tracing::warn!(
            user_id = ?user.user_id,
            "Break-glass secret reveal via settings API"
        );
    }
    if has_secret_changes(&updated.managed, &current_managed) {
        tracing::warn!(
            user_id = ?user.user_id,
            "Settings secrets updated"
        );
    }
    let view = to_view(&updated.managed, reveal);

    Ok(Json(SettingsResponse {
        settings: view,
        updated_at: updated.updated_at,
        updated_by: updated.updated_by,
    }))
}

/// These settings are deployment-wide — identity providers, external API keys,
/// CORS, rate limits, scan budgets — not company-scoped, so the gate is the
/// global role and not `has_role(Role::Admin)`, which the active company's
/// membership role now also satisfies. This matches the Settings UI, which
/// shows Integrations only to a global admin.
fn require_global_admin(user: &UserContext) -> Result<(), ApiError> {
    if user.is_global_admin() {
        Ok(())
    } else {
        Err(ApiError::Authorization(
            "Global admin role required".to_string(),
        ))
    }
}

fn resolve_break_glass(
    user: &UserContext,
    state: &AppState,
    headers: &HeaderMap,
    requested: bool,
) -> Result<bool, ApiError> {
    if !requested {
        return Ok(false);
    }

    if user.is_api_key {
        return Err(ApiError::Authorization(
            "Secret reveal requires session-based authentication".to_string(),
        ));
    }

    let expected = state
        .config
        .load()
        .break_glass_token
        .clone()
        .ok_or_else(|| ApiError::Authorization("Break-glass token not configured".to_string()))?;

    let provided = headers
        .get("x-break-glass-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided != expected {
        return Err(ApiError::Authorization(
            "Invalid break-glass token".to_string(),
        ));
    }

    Ok(true)
}

fn has_secret_changes(updated: &ManagedSettings, current: &ManagedSettings) -> bool {
    updated.google_client_secret != current.google_client_secret
        || updated.keycloak_client_secret != current.keycloak_client_secret
        || updated.certspotter_api_token != current.certspotter_api_token
        || updated.virustotal_api_key != current.virustotal_api_key
        || updated.shodan_api_key != current.shodan_api_key
        || updated.urlscan_api_key != current.urlscan_api_key
        || updated.otx_api_key != current.otx_api_key
        || updated.clearbit_api_key != current.clearbit_api_key
        || updated.opencorporates_api_token != current.opencorporates_api_token
        || updated.securitytrails_api_key != current.securitytrails_api_key
        || updated.censys_api_key != current.censys_api_key
        || updated.chaos_api_key != current.chaos_api_key
        || updated.leakix_api_key != current.leakix_api_key
        || updated.fullhunt_api_key != current.fullhunt_api_key
        || updated.binaryedge_api_key != current.binaryedge_api_key
        || updated.netlas_api_key != current.netlas_api_key
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
        securitytrails_api_key: secret_field(&settings.securitytrails_api_key, reveal_secrets),
        censys_api_key: secret_field(&settings.censys_api_key, reveal_secrets),
        censys_org_id: settings.censys_org_id.clone(),
        chaos_api_key: secret_field(&settings.chaos_api_key, reveal_secrets),
        leakix_api_key: secret_field(&settings.leakix_api_key, reveal_secrets),
        fullhunt_api_key: secret_field(&settings.fullhunt_api_key, reveal_secrets),
        binaryedge_api_key: secret_field(&settings.binaryedge_api_key, reveal_secrets),
        netlas_api_key: secret_field(&settings.netlas_api_key, reveal_secrets),
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
        max_active_scans_per_user: settings.max_active_scans_per_user,
        max_active_discovery_per_user: settings.max_active_discovery_per_user,
        block_internal_ip_scans: settings.block_internal_ip_scans,
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
        skip_unresolved_domains: settings.skip_unresolved_domains,
        osint_source_concurrency: settings.osint_source_concurrency,
        osint_source_timeout_seconds: settings.osint_source_timeout_seconds,
        osint_max_results_per_source: settings.osint_max_results_per_source,
        enable_dns_bruteforce: settings.enable_dns_bruteforce,
        enable_dns_permutations: settings.enable_dns_permutations,
        enable_nsec_walk: settings.enable_nsec_walk,
        enable_srv_probe: settings.enable_srv_probe,
        dns_bruteforce_wordlist_path: settings.dns_bruteforce_wordlist_path.clone(),
        dns_bruteforce_max_words: settings.dns_bruteforce_max_words,
        dns_permutation_max_candidates: settings.dns_permutation_max_candidates,
        dns_permutation_max_seeds: settings.dns_permutation_max_seeds,
        active_dns_concurrency: settings.active_dns_concurrency,
        enable_asn_discovery: settings.enable_asn_discovery,
        enable_rdap_lookup: settings.enable_rdap_lookup,
        enable_saas_tenant_discovery: settings.enable_saas_tenant_discovery,
        enable_cname_chain_analysis: settings.enable_cname_chain_analysis,
        asn_max_prefixes: settings.asn_max_prefixes,
        reverse_dns_sweep_max_hosts: settings.reverse_dns_sweep_max_hosts,
        reindex_min_interval_seconds: settings.reindex_min_interval_seconds,
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
    if let Some(v) = update.securitytrails_api_key {
        current.securitytrails_api_key = normalize_string(v);
    }
    if let Some(v) = update.censys_api_key {
        current.censys_api_key = normalize_string(v);
    }
    if let Some(v) = update.censys_org_id {
        current.censys_org_id = normalize_string(v);
    }
    if let Some(v) = update.chaos_api_key {
        current.chaos_api_key = normalize_string(v);
    }
    if let Some(v) = update.leakix_api_key {
        current.leakix_api_key = normalize_string(v);
    }
    if let Some(v) = update.fullhunt_api_key {
        current.fullhunt_api_key = normalize_string(v);
    }
    if let Some(v) = update.binaryedge_api_key {
        current.binaryedge_api_key = normalize_string(v);
    }
    if let Some(v) = update.netlas_api_key {
        current.netlas_api_key = normalize_string(v);
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
    if let Some(v) = update.max_active_scans_per_user {
        current.max_active_scans_per_user = v;
    }
    if let Some(v) = update.max_active_discovery_per_user {
        current.max_active_discovery_per_user = v;
    }
    if let Some(v) = update.block_internal_ip_scans {
        current.block_internal_ip_scans = v;
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

    if let Some(v) = update.skip_unresolved_domains {
        current.skip_unresolved_domains = v;
    }

    // Passive OSINT fan-out
    if let Some(v) = update.osint_source_concurrency {
        current.osint_source_concurrency = v;
    }
    if let Some(v) = update.osint_source_timeout_seconds {
        current.osint_source_timeout_seconds = v;
    }
    if let Some(v) = update.osint_max_results_per_source {
        current.osint_max_results_per_source = v;
    }

    // Active DNS discovery
    if let Some(v) = update.enable_dns_bruteforce {
        current.enable_dns_bruteforce = v;
    }
    if let Some(v) = update.enable_dns_permutations {
        current.enable_dns_permutations = v;
    }
    if let Some(v) = update.enable_nsec_walk {
        current.enable_nsec_walk = v;
    }
    if let Some(v) = update.enable_srv_probe {
        current.enable_srv_probe = v;
    }
    if let Some(v) = update.dns_bruteforce_wordlist_path {
        current.dns_bruteforce_wordlist_path = normalize_string(v);
    }
    if let Some(v) = update.dns_bruteforce_max_words {
        current.dns_bruteforce_max_words = v;
    }
    if let Some(v) = update.dns_permutation_max_candidates {
        current.dns_permutation_max_candidates = v;
    }
    if let Some(v) = update.dns_permutation_max_seeds {
        current.dns_permutation_max_seeds = v;
    }
    if let Some(v) = update.active_dns_concurrency {
        current.active_dns_concurrency = v;
    }

    // Infrastructure attribution
    if let Some(v) = update.enable_asn_discovery {
        current.enable_asn_discovery = v;
    }
    if let Some(v) = update.enable_rdap_lookup {
        current.enable_rdap_lookup = v;
    }
    if let Some(v) = update.enable_saas_tenant_discovery {
        current.enable_saas_tenant_discovery = v;
    }
    if let Some(v) = update.enable_cname_chain_analysis {
        current.enable_cname_chain_analysis = v;
    }
    if let Some(v) = update.asn_max_prefixes {
        current.asn_max_prefixes = v;
    }
    if let Some(v) = update.reverse_dns_sweep_max_hosts {
        current.reverse_dns_sweep_max_hosts = v;
    }

    if let Some(v) = update.reindex_min_interval_seconds {
        current.reindex_min_interval_seconds = v;
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

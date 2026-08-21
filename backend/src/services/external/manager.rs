use super::passive_sources::{
    self, OsintCredentials, PassiveContext, PassiveSourceOutcome, SourceStatus,
};
use super::{
    CertSpotterCertificate, CertSpotterClient, CrtShClient, ShodanClient, ShodanExtractedAssets,
    ShodanHostInfo, ShodanResult, VirusTotalClient,
};
use crate::config::Settings;
use crate::config::SharedSettings;
use crate::error::ApiError;
use crate::models::SourceType;
use futures::future::BoxFuture;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};

/// External services manager that coordinates all API integrations
pub struct ExternalServicesManager {
    settings: SharedSettings,
    crtsh_client: CrtShClient,
    /// One client shared by every registry source, across every domain in a
    /// run. `reqwest::Client` is an `Arc` internally, so cloning it shares the
    /// connection pool rather than rebuilding it per domain.
    osint_http: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct SubdomainEnumerationResult {
    pub subdomains: Vec<String>,
    pub sources: HashMap<String, Vec<String>>, // source -> domains found
    pub hostname_sources: HashMap<String, Vec<SourceType>>, // hostname -> ordered sources
    pub source_execution: Vec<SourceExecutionStatus>,
    /// IP -> owner hint from the existing Shodan domain query (if available).
    pub shodan_ip_owners: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct SourceExecutionStatus {
    pub source: SourceType,
    pub status: String, // queried | skipped | failed
    pub message: Option<String>,
    pub hostnames_found: usize,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelligenceResult {
    pub is_malicious: bool,
    pub reputation_score: Option<i32>,
    pub threat_sources: Vec<String>,
    pub additional_info: HashMap<String, String>,
}

const DISCOVERY_SOURCE_PRIORITY: [SourceType; 4] = [
    SourceType::Shodan,
    SourceType::Virustotal,
    SourceType::Crtsh,
    SourceType::Certspotter,
];

/// One source's contribution to an enumeration, before scoping and merging.
///
/// Every source — stateful client or registry entry — funnels through this
/// shape so the fold that follows has one case to handle instead of two.
struct SourceRun {
    source: SourceType,
    status: SourceStatus,
    message: Option<String>,
    hostnames: Vec<String>,
    /// Only Shodan populates this: IP -> owner, reused downstream to classify
    /// cloud and WAF addresses without a second round of queries.
    ip_owners: HashMap<String, String>,
}

impl SourceRun {
    fn queried(source: SourceType, hostnames: Vec<String>) -> Self {
        Self {
            source,
            status: SourceStatus::Queried,
            message: None,
            hostnames,
            ip_owners: HashMap::new(),
        }
    }

    fn skipped(source: SourceType, reason: &str) -> Self {
        Self {
            source,
            status: SourceStatus::Skipped,
            message: Some(reason.to_string()),
            hostnames: Vec::new(),
            ip_owners: HashMap::new(),
        }
    }

    fn failed(source: SourceType, message: String) -> Self {
        Self {
            source,
            status: SourceStatus::Failed,
            message: Some(message),
            hostnames: Vec::new(),
            ip_owners: HashMap::new(),
        }
    }

    fn with_ip_owners(mut self, ip_owners: HashMap<String, String>) -> Self {
        self.ip_owners = ip_owners;
        self
    }
}

impl From<PassiveSourceOutcome> for SourceRun {
    fn from(outcome: PassiveSourceOutcome) -> Self {
        Self {
            source: outcome.source,
            status: outcome.status,
            message: outcome.message,
            hostnames: outcome.hostnames,
            ip_owners: HashMap::new(),
        }
    }
}

/// Why a source is switched off in the settings, if it is.
fn disabled_reason(source: &SourceType, settings: &Settings) -> Option<&'static str> {
    match source {
        SourceType::Wayback if !settings.enable_wayback => {
            Some("Wayback Machine disabled in settings")
        }
        SourceType::UrlScan if !settings.enable_urlscan => Some("urlscan.io disabled in settings"),
        SourceType::Otx if !settings.enable_otx => Some("AlienVault OTX disabled in settings"),
        _ => None,
    }
}

/// Collect the keyed-source credentials out of the live settings.
fn credentials_from_settings(settings: &Settings) -> OsintCredentials {
    // Blank strings arrive from the settings UI whenever a field is cleared;
    // treating one as a key makes a source fail every run instead of skipping.
    fn present(value: &Option<String>) -> Option<String> {
        value
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    }

    OsintCredentials {
        securitytrails: present(&settings.securitytrails_api_key),
        censys_pat: present(&settings.censys_api_key),
        censys_org_id: present(&settings.censys_org_id),
        chaos: present(&settings.chaos_api_key),
        leakix: present(&settings.leakix_api_key),
        fullhunt: present(&settings.fullhunt_api_key),
        binaryedge: present(&settings.binaryedge_api_key),
        netlas: present(&settings.netlas_api_key),
        urlscan: present(&settings.urlscan_api_key),
        otx: present(&settings.otx_api_key),
    }
}

/// Stable key for the per-source hostname map exposed to the API.
///
/// Every enumerating source needs its own key: collapsing unknown sources onto
/// one bucket would make the per-source breakdown lie about who found what.
fn source_key(source: &SourceType) -> &'static str {
    match source {
        SourceType::Shodan => "shodan",
        SourceType::Virustotal => "virustotal",
        SourceType::Crtsh => "crtsh",
        SourceType::Certspotter => "certspotter",
        SourceType::Otx => "otx",
        SourceType::HackerTarget => "hackertarget",
        SourceType::RapidDns => "rapiddns",
        SourceType::AnubisDb => "anubisdb",
        SourceType::UrlScan => "urlscan",
        SourceType::Wayback => "wayback",
        SourceType::Columbus => "columbus",
        SourceType::Digitorus => "digitorus",
        SourceType::SecurityTrails => "securitytrails",
        SourceType::Censys => "censys",
        SourceType::Chaos => "chaos",
        SourceType::LeakIx => "leakix",
        SourceType::FullHunt => "fullhunt",
        SourceType::BinaryEdge => "binaryedge",
        SourceType::Netlas => "netlas",
        _ => "user_input",
    }
}

fn normalize_hostname(hostname: &str) -> Option<String> {
    let mut normalized = hostname.trim().trim_end_matches('.').to_lowercase();
    if normalized.starts_with("*.") {
        normalized = normalized.trim_start_matches("*.").to_string();
    }
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains(char::is_whitespace)
        || normalized.contains('/')
    {
        return None;
    }

    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.is_empty() {
        return None;
    }

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }

    Some(normalized)
}

fn is_related_hostname(hostname: &str, base_domain: &str) -> bool {
    hostname == base_domain || hostname.ends_with(&format!(".{}", base_domain))
}

fn add_hostnames_for_source(
    hostname_sources: &mut HashMap<String, Vec<SourceType>>,
    source_hostnames: &mut HashMap<String, Vec<String>>,
    source: SourceType,
    base_domain: &str,
    hostnames: Vec<String>,
) -> usize {
    let mut accepted_for_source: Vec<String> = Vec::new();
    let mut seen_for_source: HashSet<String> = HashSet::new();

    for hostname in hostnames {
        let Some(canonical) = normalize_hostname(&hostname) else {
            continue;
        };
        if !is_related_hostname(&canonical, base_domain) {
            continue;
        }
        if !seen_for_source.insert(canonical.clone()) {
            continue;
        }

        let entry = hostname_sources.entry(canonical.clone()).or_default();
        if !entry.contains(&source) {
            entry.push(source.clone());
        }
        accepted_for_source.push(canonical);
    }

    accepted_for_source.sort();
    source_hostnames.insert(source_key(&source).to_string(), accepted_for_source.clone());
    accepted_for_source.len()
}

impl ExternalServicesManager {
    /// Create a new external services manager with configured API clients
    pub fn new(settings: SharedSettings) -> Result<Self, ApiError> {
        let crtsh_client = CrtShClient::new()?;
        let osint_http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                settings.load().osint_source_timeout_seconds.max(1.0) as u64,
            ))
            .user_agent("EASM-Rust-Backend/1.0")
            .pool_max_idle_per_host(4)
            .build()?;

        Ok(Self {
            settings,
            crtsh_client,
            osint_http,
        })
    }

    /// Perform comprehensive subdomain enumeration using all available sources
    /// Queries Shodan first as primary source, then always queries other sources for comprehensive coverage
    /// Returns a SubdomainEnumerationResult plus extracted Shodan assets for recursive discovery
    /// Enumerate every hostname under `domain` that any configured OSINT
    /// corpus knows about.
    ///
    /// Sources are queried **concurrently**, not in sequence. That matters more
    /// than it sounds: enumeration latency used to be the sum of every source's
    /// response time, so one slow aggregator delayed the whole run and adding a
    /// source made discovery strictly slower. Fanning out makes the cost the
    /// *slowest* source rather than the sum, which is what makes it reasonable
    /// to ask nineteen corpora instead of four.
    ///
    /// Failure is per-source and never fatal. A dead endpoint, an expired key
    /// or a rate limit yields a `failed` execution record and the union of
    /// everything else; a source with no credential yields `skipped`.
    pub async fn enumerate_subdomains(
        &self,
        domain: &str,
    ) -> Result<SubdomainEnumerationResult, ApiError> {
        let canonical_domain = normalize_hostname(domain)
            .ok_or_else(|| ApiError::Validation("Domain cannot be empty".to_string()))?;

        let settings = self.settings.load();
        let concurrency = settings.osint_source_concurrency.max(1) as usize;
        let per_source_timeout =
            std::time::Duration::from_secs_f64(settings.osint_source_timeout_seconds.max(1.0));
        let max_results_per_source = settings.osint_max_results_per_source as usize;

        // --- Sources with their own stateful clients ---
        let shodan_client = self.shodan_client_for(&settings)?;
        let virustotal_client = self.virustotal_client_for(&settings)?;
        let certspotter_client = self.certspotter_client_for(&settings)?;

        let mut shodan_ip_owners: HashMap<String, String> = HashMap::new();

        // Every source, stateful client or registry entry, becomes one future
        // in a single vector. Building one homogeneous set of futures — rather
        // than combining two differently-typed streams — keeps the resulting
        // future `Send`, which the task manager requires in order to spawn it.
        let domain_ref: &str = canonical_domain.as_str();

        // Declared before `tasks`: values drop in reverse declaration order, and
        // the futures in `tasks` borrow both, so they must outlive it.
        let context = PassiveContext::with_client(
            self.osint_http.clone(),
            credentials_from_settings(&settings),
            max_results_per_source,
            per_source_timeout,
        );
        let registry = passive_sources::default_sources();

        let mut tasks: Vec<BoxFuture<'_, SourceRun>> = Vec::new();

        tasks.push(Box::pin(async move {
            let Some(client) = shodan_client.as_ref() else {
                return SourceRun::skipped(SourceType::Shodan, "Shodan API not configured");
            };
            match client.search_domain_comprehensive(domain_ref).await {
                Ok(extracted) => {
                    let ShodanExtractedAssets {
                        domains, ip_owners, ..
                    } = extracted;
                    SourceRun::queried(SourceType::Shodan, domains.into_iter().collect())
                        .with_ip_owners(ip_owners)
                }
                Err(e) => SourceRun::failed(SourceType::Shodan, e.to_string()),
            }
        }));

        tasks.push(Box::pin(async move {
            let Some(client) = virustotal_client.as_ref() else {
                return SourceRun::skipped(SourceType::Virustotal, "VirusTotal API not configured");
            };
            match client.get_subdomains(domain_ref).await {
                Ok(domains) => SourceRun::queried(SourceType::Virustotal, domains),
                Err(e) => SourceRun::failed(SourceType::Virustotal, e.to_string()),
            }
        }));

        let crtsh_client = &self.crtsh_client;
        tasks.push(Box::pin(async move {
            match crtsh_client.search_domain(domain_ref).await {
                Ok(domains) => SourceRun::queried(SourceType::Crtsh, domains),
                Err(e) => SourceRun::failed(SourceType::Crtsh, e.to_string()),
            }
        }));

        tasks.push(Box::pin(async move {
            let Some(client) = certspotter_client.as_ref() else {
                return SourceRun::skipped(
                    SourceType::Certspotter,
                    "CertSpotter API not configured",
                );
            };
            match client.get_subdomains(domain_ref).await {
                Ok(domains) => SourceRun::queried(SourceType::Certspotter, domains),
                Err(e) => SourceRun::failed(SourceType::Certspotter, e.to_string()),
            }
        }));

        // --- Registry-driven sources (plain HTTP, no client state) ---
        let context_ref = &context;
        for source in &registry {
            let source = source.as_ref();
            let source_type = source.source_type();

            // Three of these have had an operator-facing toggle since long
            // before they were implemented. Honour it: a source switched off in
            // the settings must report `skipped`, not quietly run anyway.
            if let Some(reason) = disabled_reason(&source_type, &settings) {
                tasks.push(Box::pin(
                    async move { SourceRun::skipped(source_type, reason) },
                ));
                continue;
            }

            tasks.push(Box::pin(async move {
                SourceRun::from(passive_sources::run_source(source, context_ref, domain_ref).await)
            }));
        }

        let started = std::time::Instant::now();
        let mut source_results: Vec<SourceRun> = stream::iter(tasks)
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // --- Fold every source's answer into one scoped, deduplicated set ---
        let mut hostname_sources: HashMap<String, Vec<SourceType>> = HashMap::new();
        let mut sources: HashMap<String, Vec<String>> = HashMap::new();
        let mut source_execution: Vec<SourceExecutionStatus> = Vec::new();

        // Sort so the execution report and per-source hostname map are stable
        // across runs regardless of which source happened to answer first.
        source_results.sort_by_key(|run| Self::source_report_order(&run.source));

        for run in source_results {
            let SourceRun {
                source,
                status,
                message,
                hostnames,
                ip_owners,
            } = run;

            shodan_ip_owners.extend(ip_owners);

            let hostnames_found = match status {
                SourceStatus::Queried => add_hostnames_for_source(
                    &mut hostname_sources,
                    &mut sources,
                    source.clone(),
                    &canonical_domain,
                    hostnames,
                ),
                _ => {
                    sources.entry(source_key(&source).to_string()).or_default();
                    0
                }
            };

            if status == SourceStatus::Failed {
                tracing::warn!(
                    "{} enumeration failed for {}: {}",
                    source,
                    canonical_domain,
                    message.as_deref().unwrap_or("unknown error")
                );
            }

            source_execution.push(SourceExecutionStatus {
                source,
                status: status.as_str().to_string(),
                message,
                hostnames_found,
            });
        }

        let mut final_subdomains: Vec<String> = hostname_sources.keys().cloned().collect();
        final_subdomains.sort();

        let queried = source_execution
            .iter()
            .filter(|execution| execution.status == "queried")
            .count();
        tracing::info!(
            "Subdomain enumeration for {}: {} unique hostnames from {}/{} sources in {:.1}s",
            canonical_domain,
            final_subdomains.len(),
            queried,
            source_execution.len(),
            started.elapsed().as_secs_f64()
        );

        Ok(SubdomainEnumerationResult {
            subdomains: final_subdomains,
            sources,
            hostname_sources,
            source_execution,
            shodan_ip_owners,
        })
    }

    /// Stable ordering for the per-source execution report: the four historical
    /// sources first, in their long-standing priority order, then the rest
    /// alphabetically so a new source does not reshuffle the report.
    fn source_report_order(source: &SourceType) -> (usize, String) {
        let priority = DISCOVERY_SOURCE_PRIORITY
            .iter()
            .position(|known| known == source)
            .unwrap_or(DISCOVERY_SOURCE_PRIORITY.len());
        (priority, source.to_string())
    }

    /// Get comprehensive Shodan data for a domain (for use in recursive discovery)
    /// Returns all asset types extracted from Shodan
    pub async fn get_shodan_comprehensive_data(
        &self,
        domain: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_domain_comprehensive(domain).await,
            None => Ok(ShodanExtractedAssets::default()),
        }
    }

    /// Search crt.sh for domains by organization name
    pub async fn search_crtsh_by_organization(
        &self,
        organization: &str,
    ) -> Result<Vec<String>, ApiError> {
        self.crtsh_client.search_organization(organization).await
    }

    /// Get threat intelligence for a domain
    pub async fn get_domain_threat_intel(
        &self,
        domain: &str,
    ) -> Result<ThreatIntelligenceResult, ApiError> {
        let mut is_malicious = false;
        let mut reputation_score = None;
        let mut threat_sources = Vec::new();
        let mut additional_info = HashMap::new();

        // VirusTotal threat intelligence
        let settings = self.settings.load();
        if let Some(client) = self.virustotal_client_for(&settings)? {
            match client.get_domain_report(domain).await {
                Ok(report) => {
                    if client.is_malicious_domain(&report) {
                        is_malicious = true;
                        threat_sources.push("virustotal".to_string());
                    }

                    if let Some(rep) = client.get_domain_reputation(&report) {
                        reputation_score = Some(rep);
                    }

                    if let Some(stats) = &report.attributes.last_analysis_stats {
                        additional_info.insert(
                            "virustotal_malicious_count".to_string(),
                            stats.malicious.to_string(),
                        );
                        additional_info.insert(
                            "virustotal_suspicious_count".to_string(),
                            stats.suspicious.to_string(),
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("VirusTotal threat intel failed for {}: {}", domain, e);
                }
            }
        }

        Ok(ThreatIntelligenceResult {
            is_malicious,
            reputation_score,
            threat_sources,
            additional_info,
        })
    }

    /// Get threat intelligence for an IP address
    pub async fn get_ip_threat_intel(
        &self,
        ip: &str,
    ) -> Result<ThreatIntelligenceResult, ApiError> {
        let mut is_malicious = false;
        let mut reputation_score = None;
        let mut threat_sources = Vec::new();
        let mut additional_info = HashMap::new();

        // VirusTotal threat intelligence
        let settings = self.settings.load();
        if let Some(client) = self.virustotal_client_for(&settings)? {
            match client.get_ip_report(ip).await {
                Ok(report) => {
                    if client.is_malicious_ip(&report) {
                        is_malicious = true;
                        threat_sources.push("virustotal".to_string());
                    }

                    if let Some(rep) = client.get_ip_reputation(&report) {
                        reputation_score = Some(rep);
                    }

                    if let Some(stats) = &report.attributes.last_analysis_stats {
                        additional_info.insert(
                            "virustotal_malicious_count".to_string(),
                            stats.malicious.to_string(),
                        );
                    }

                    if let Some(asn) = &report.attributes.asn {
                        additional_info.insert("asn".to_string(), asn.to_string());
                    }

                    if let Some(country) = &report.attributes.country {
                        additional_info.insert("country".to_string(), country.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!("VirusTotal IP threat intel failed for {}: {}", ip, e);
                }
            }
        }

        Ok(ThreatIntelligenceResult {
            is_malicious,
            reputation_score,
            threat_sources,
            additional_info,
        })
    }

    /// Search for hosts using Shodan
    pub async fn search_shodan(&self, query: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search(query).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Search for hosts by organization using Shodan
    pub async fn search_shodan_by_org(&self, org: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_by_org(org).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Search for hosts by ASN using Shodan
    pub async fn search_shodan_by_asn(&self, asn: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_by_asn(asn).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Get Shodan host information for a specific IP.
    /// Returns `Ok(None)` when Shodan is not configured.
    pub async fn get_shodan_host_info(&self, ip: &str) -> Result<Option<ShodanHostInfo>, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.get_host(ip).await.map(Some),
            None => Ok(None),
        }
    }

    /// Get certificate information from CertSpotter
    pub async fn get_certificate_info(
        &self,
        cert_id: &str,
    ) -> Result<CertSpotterCertificate, ApiError> {
        let settings = self.settings.load();
        match self.certspotter_client_for(&settings)? {
            Some(client) => client.get_certificate(cert_id).await,
            None => Err(ApiError::ExternalService(
                "CertSpotter API not configured".to_string(),
            )),
        }
    }

    /// Get service availability status
    pub fn get_service_status(&self) -> HashMap<String, bool> {
        let settings = self.settings.load();
        let shodan_configured = has_value(&settings.shodan_api_key);
        let virustotal_configured = has_value(&settings.virustotal_api_key);
        let certspotter_configured = has_value(&settings.certspotter_api_token);
        let mut status = HashMap::new();

        status.insert("crt.sh".to_string(), true); // Always available
        status.insert("shodan".to_string(), shodan_configured);
        status.insert("virustotal".to_string(), virustotal_configured);
        status.insert("certspotter".to_string(), certspotter_configured);

        status
    }

    /// Get configured API services count
    pub fn get_configured_services_count(&self) -> usize {
        let settings = self.settings.load();
        let mut count = 1; // crt.sh is always available

        if has_value(&settings.shodan_api_key) {
            count += 1;
        }
        if has_value(&settings.virustotal_api_key) {
            count += 1;
        }
        if has_value(&settings.certspotter_api_token) {
            count += 1;
        }

        count
    }

    /// Validate that at least basic services are available
    pub fn validate_configuration(&self) -> Result<(), ApiError> {
        let configured_count = self.get_configured_services_count();

        if configured_count < 2 {
            tracing::warn!(
                "Only {} external services configured. Consider adding API keys for better coverage.",
                configured_count
            );
        }

        tracing::info!(
            "External services manager initialized with {} services",
            configured_count
        );
        Ok(())
    }

    /// Comprehensive Shodan search that extracts ALL asset types (IPs, domains, ASNs, orgs, certs)
    pub async fn search_shodan_comprehensive(
        &self,
        query: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_comprehensive(query).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Comprehensive domain search on Shodan - extracts all related assets
    pub async fn search_shodan_domain_comprehensive(
        &self,
        domain: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_domain_comprehensive(domain).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Comprehensive organization search on Shodan - extracts all related assets
    pub async fn search_shodan_org_comprehensive(
        &self,
        org: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_org_comprehensive(org).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Comprehensive ASN search on Shodan - extracts all related assets
    pub async fn search_shodan_asn_comprehensive(
        &self,
        asn: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_asn_comprehensive(asn).await,
            None => Err(ApiError::ExternalService(
                "Shodan API not configured".to_string(),
            )),
        }
    }

    /// Lateral OSINT pivot — find apex domains that serve the same favicon as the seed.
    /// Returns an empty extraction (no error) when Shodan is unconfigured, the count
    /// exceeds `max_results`, or no matches exist. Cost: 1 Shodan query credit max
    /// (the count pre-check is free).
    pub async fn shodan_favicon_pivot(
        &self,
        hash: i32,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_by_favicon_hash(hash, max_results).await,
            None => Ok(ShodanExtractedAssets::default()),
        }
    }

    /// Read the JARM fingerprint Shodan recorded for an address.
    ///
    /// The fingerprint is taken from Shodan rather than computed locally on
    /// purpose — see [`super::shodan::ShodanSsl::jarm`]. Returns the fingerprint
    /// from the first TLS banner that has one, preferring 443.
    pub async fn shodan_jarm_for_ip(&self, ip: &str) -> Result<Option<String>, ApiError> {
        let settings = self.settings.load();
        let Some(client) = self.shodan_client_for(&settings)? else {
            return Ok(None);
        };

        let host = client.get_host(ip).await?;
        let mut banners: Vec<_> = host.data.iter().collect();
        // 443 first: a JARM from an unrelated service on the same host is a much
        // weaker signal about the web property being pivoted from.
        banners.sort_by_key(|banner| if banner.port == 443 { 0 } else { 1 });

        Ok(banners
            .into_iter()
            .filter_map(|banner| banner.ssl.as_ref())
            .filter_map(|ssl| ssl.jarm.as_deref())
            .map(|jarm| jarm.trim().to_string())
            // Shodan reports an all-zero JARM when the probe found no TLS.
            .find(|jarm| !jarm.is_empty() && jarm.chars().any(|c| c != '0')))
    }

    /// Lateral OSINT pivot — find apex domains whose TLS stack matches the seed's JARM.
    pub async fn shodan_jarm_pivot(
        &self,
        jarm: &str,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_by_jarm(jarm, max_results).await,
            None => Ok(ShodanExtractedAssets::default()),
        }
    }

    /// Lateral OSINT pivot — find apex domains whose HTML body contains the given
    /// fingerprint (analytics ID, tag-manager ID, pixel token, ...).
    pub async fn shodan_html_pivot(
        &self,
        needle: &str,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let settings = self.settings.load();
        match self.shodan_client_for(&settings)? {
            Some(client) => client.search_by_html(needle, max_results).await,
            None => Ok(ShodanExtractedAssets::default()),
        }
    }

    fn shodan_client_for(&self, settings: &Settings) -> Result<Option<ShodanClient>, ApiError> {
        if has_value(&settings.shodan_api_key) {
            Ok(Some(ShodanClient::new(settings.shodan_api_key.clone())?))
        } else {
            Ok(None)
        }
    }

    fn virustotal_client_for(
        &self,
        settings: &Settings,
    ) -> Result<Option<VirusTotalClient>, ApiError> {
        if has_value(&settings.virustotal_api_key) {
            Ok(Some(VirusTotalClient::new(
                settings.virustotal_api_key.clone(),
            )?))
        } else {
            Ok(None)
        }
    }

    fn certspotter_client_for(
        &self,
        settings: &Settings,
    ) -> Result<Option<CertSpotterClient>, ApiError> {
        if has_value(&settings.certspotter_api_token) {
            Ok(Some(CertSpotterClient::new(
                settings.certspotter_api_token.clone(),
            )?))
        } else {
            Ok(None)
        }
    }
}

fn has_value(opt: &Option<String>) -> bool {
    opt.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::models::SourceType;
    use arc_swap::ArcSwap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_external_services_manager_creation() {
        let settings = Settings::new_with_env_file(false).unwrap();
        let shared = Arc::new(ArcSwap::from_pointee(settings));
        let manager = ExternalServicesManager::new(shared).unwrap();

        let status = manager.get_service_status();
        assert!(status.get("crt.sh").unwrap_or(&false));

        let count = manager.get_configured_services_count();
        assert!(count >= 1); // At least crt.sh should be available
    }

    #[tokio::test]
    async fn test_service_validation() {
        let settings = Settings::new_with_env_file(false).unwrap();
        let shared = Arc::new(ArcSwap::from_pointee(settings));
        let manager = ExternalServicesManager::new(shared).unwrap();

        // Should not fail even with minimal configuration
        assert!(manager.validate_configuration().is_ok());
    }

    #[tokio::test]
    async fn test_threat_intel_no_apis() {
        let settings = Settings::new_with_env_file(false).unwrap();
        let shared = Arc::new(ArcSwap::from_pointee(settings));
        let manager = ExternalServicesManager::new(shared).unwrap();

        // Should return non-malicious result when no threat intel APIs are configured
        let result = manager
            .get_domain_threat_intel("example.com")
            .await
            .unwrap();
        assert!(!result.is_malicious);
        assert!(result.threat_sources.is_empty());
    }

    #[test]
    fn test_normalize_hostname_canonicalization() {
        assert_eq!(
            normalize_hostname(" WWW.Example.com. "),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            normalize_hostname("*.Api.Example.com"),
            Some("api.example.com".to_string())
        );
        assert_eq!(normalize_hostname(""), None);
        assert_eq!(normalize_hostname("bad host"), None);
    }

    #[test]
    fn test_add_hostnames_for_source_deduplicates_and_tracks_sources() {
        let mut hostname_sources: HashMap<String, Vec<SourceType>> = HashMap::new();
        let mut source_hostnames: HashMap<String, Vec<String>> = HashMap::new();

        let shodan_count = add_hostnames_for_source(
            &mut hostname_sources,
            &mut source_hostnames,
            SourceType::Shodan,
            "example.com",
            vec![
                "WWW.Example.com.".to_string(),
                "api.example.com".to_string(),
                "irrelevant.org".to_string(),
            ],
        );
        assert_eq!(shodan_count, 2);

        let vt_count = add_hostnames_for_source(
            &mut hostname_sources,
            &mut source_hostnames,
            SourceType::Virustotal,
            "example.com",
            vec![
                "www.example.com".to_string(),
                "mail.example.com".to_string(),
                "mail.example.com".to_string(),
            ],
        );
        assert_eq!(vt_count, 2);

        let www_sources = hostname_sources
            .get("www.example.com")
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            www_sources,
            vec![SourceType::Shodan, SourceType::Virustotal]
        );
        assert!(hostname_sources.contains_key("api.example.com"));
        assert!(hostname_sources.contains_key("mail.example.com"));
        assert!(!hostname_sources.contains_key("irrelevant.org"));

        let shodan_hosts = source_hostnames.get("shodan").cloned().unwrap_or_default();
        let vt_hosts = source_hostnames
            .get("virustotal")
            .cloned()
            .unwrap_or_default();
        assert_eq!(shodan_hosts, vec!["api.example.com", "www.example.com"]);
        assert_eq!(vt_hosts, vec!["mail.example.com", "www.example.com"]);
    }

    #[test]
    fn test_source_priority_order_is_fixed() {
        assert_eq!(
            DISCOVERY_SOURCE_PRIORITY,
            [
                SourceType::Shodan,
                SourceType::Virustotal,
                SourceType::Crtsh,
                SourceType::Certspotter
            ]
        );
    }
}

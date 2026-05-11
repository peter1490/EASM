use super::{
    CertSpotterCertificate, CertSpotterClient, CrtShClient, ShodanClient, ShodanExtractedAssets,
    ShodanHostInfo, ShodanResult, VirusTotalClient,
};
use crate::config::Settings;
use crate::config::SharedSettings;
use crate::error::ApiError;
use crate::models::SourceType;
use std::collections::{HashMap, HashSet};

/// External services manager that coordinates all API integrations
pub struct ExternalServicesManager {
    settings: SharedSettings,
    crtsh_client: CrtShClient,
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

fn source_key(source: &SourceType) -> &'static str {
    match source {
        SourceType::Shodan => "shodan",
        SourceType::Virustotal => "virustotal",
        SourceType::Crtsh => "crtsh",
        SourceType::Certspotter => "certspotter",
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

        Ok(Self {
            settings,
            crtsh_client,
        })
    }

    /// Perform comprehensive subdomain enumeration using all available sources
    /// Queries Shodan first as primary source, then always queries other sources for comprehensive coverage
    /// Returns a SubdomainEnumerationResult plus extracted Shodan assets for recursive discovery
    pub async fn enumerate_subdomains(
        &self,
        domain: &str,
    ) -> Result<SubdomainEnumerationResult, ApiError> {
        let canonical_domain = normalize_hostname(domain)
            .ok_or_else(|| ApiError::Validation("Domain cannot be empty".to_string()))?;
        let mut hostname_sources: HashMap<String, Vec<SourceType>> = HashMap::new();
        let mut sources: HashMap<String, Vec<String>> = HashMap::new();
        let mut source_execution: Vec<SourceExecutionStatus> = Vec::new();
        let mut shodan_ip_owners = HashMap::new();

        let settings = self.settings.load();
        let shodan_client = self.shodan_client_for(&settings)?;
        let virustotal_client = self.virustotal_client_for(&settings)?;
        let certspotter_client = self.certspotter_client_for(&settings)?;

        for source in DISCOVERY_SOURCE_PRIORITY {
            match source {
                SourceType::Shodan => {
                    if let Some(ref client) = shodan_client {
                        tracing::info!(
                            "Enumerating subdomains for {} using Shodan (priority 1)",
                            canonical_domain
                        );
                        match client.search_domain_comprehensive(&canonical_domain).await {
                            Ok(extracted) => {
                                let ShodanExtractedAssets {
                                    domains, ip_owners, ..
                                } = extracted;
                                let domains: Vec<String> = domains.into_iter().collect();
                                let discovered = add_hostnames_for_source(
                                    &mut hostname_sources,
                                    &mut sources,
                                    SourceType::Shodan,
                                    &canonical_domain,
                                    domains,
                                );
                                shodan_ip_owners.extend(ip_owners);
                                source_execution.push(SourceExecutionStatus {
                                    source: SourceType::Shodan,
                                    status: "queried".to_string(),
                                    message: None,
                                    hostnames_found: discovered,
                                });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Shodan comprehensive enumeration failed for {}: {}",
                                    canonical_domain,
                                    e
                                );
                                sources
                                    .entry(source_key(&SourceType::Shodan).to_string())
                                    .or_default();
                                source_execution.push(SourceExecutionStatus {
                                    source: SourceType::Shodan,
                                    status: "failed".to_string(),
                                    message: Some(e.to_string()),
                                    hostnames_found: 0,
                                });
                            }
                        }
                    } else {
                        sources.insert(source_key(&SourceType::Shodan).to_string(), Vec::new());
                        source_execution.push(SourceExecutionStatus {
                            source: SourceType::Shodan,
                            status: "skipped".to_string(),
                            message: Some("Shodan API not configured".to_string()),
                            hostnames_found: 0,
                        });
                    }
                }
                SourceType::Virustotal => {
                    if let Some(ref client) = virustotal_client {
                        tracing::info!(
                            "Enumerating subdomains for {} using VirusTotal (priority 2)",
                            canonical_domain
                        );
                        match client.get_subdomains(&canonical_domain).await {
                            Ok(domains) => {
                                let discovered = add_hostnames_for_source(
                                    &mut hostname_sources,
                                    &mut sources,
                                    SourceType::Virustotal,
                                    &canonical_domain,
                                    domains,
                                );
                                source_execution.push(SourceExecutionStatus {
                                    source: SourceType::Virustotal,
                                    status: "queried".to_string(),
                                    message: None,
                                    hostnames_found: discovered,
                                });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "VirusTotal enumeration failed for {}: {}",
                                    canonical_domain,
                                    e
                                );
                                sources
                                    .entry(source_key(&SourceType::Virustotal).to_string())
                                    .or_default();
                                source_execution.push(SourceExecutionStatus {
                                    source: SourceType::Virustotal,
                                    status: "failed".to_string(),
                                    message: Some(e.to_string()),
                                    hostnames_found: 0,
                                });
                            }
                        }
                    } else {
                        sources.insert(source_key(&SourceType::Virustotal).to_string(), Vec::new());
                        source_execution.push(SourceExecutionStatus {
                            source: SourceType::Virustotal,
                            status: "skipped".to_string(),
                            message: Some("VirusTotal API not configured".to_string()),
                            hostnames_found: 0,
                        });
                    }
                }
                SourceType::Crtsh => {
                    tracing::info!(
                        "Enumerating subdomains for {} using crt.sh (priority 3)",
                        canonical_domain
                    );
                    match self.crtsh_client.search_domain(&canonical_domain).await {
                        Ok(domains) => {
                            let discovered = add_hostnames_for_source(
                                &mut hostname_sources,
                                &mut sources,
                                SourceType::Crtsh,
                                &canonical_domain,
                                domains,
                            );
                            source_execution.push(SourceExecutionStatus {
                                source: SourceType::Crtsh,
                                status: "queried".to_string(),
                                message: None,
                                hostnames_found: discovered,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                "crt.sh enumeration failed for {}: {}",
                                canonical_domain,
                                e
                            );
                            sources
                                .entry(source_key(&SourceType::Crtsh).to_string())
                                .or_default();
                            source_execution.push(SourceExecutionStatus {
                                source: SourceType::Crtsh,
                                status: "failed".to_string(),
                                message: Some(e.to_string()),
                                hostnames_found: 0,
                            });
                        }
                    }
                }
                SourceType::Certspotter => {
                    if let Some(ref client) = certspotter_client {
                        tracing::info!(
                            "Enumerating subdomains for {} using CertSpotter (priority 4)",
                            canonical_domain
                        );
                        match client.get_subdomains(&canonical_domain).await {
                            Ok(domains) => {
                                let discovered = add_hostnames_for_source(
                                    &mut hostname_sources,
                                    &mut sources,
                                    SourceType::Certspotter,
                                    &canonical_domain,
                                    domains,
                                );
                                source_execution.push(SourceExecutionStatus {
                                    source: SourceType::Certspotter,
                                    status: "queried".to_string(),
                                    message: None,
                                    hostnames_found: discovered,
                                });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "CertSpotter enumeration failed for {}: {}",
                                    canonical_domain,
                                    e
                                );
                                sources
                                    .entry(source_key(&SourceType::Certspotter).to_string())
                                    .or_default();
                                source_execution.push(SourceExecutionStatus {
                                    source: SourceType::Certspotter,
                                    status: "failed".to_string(),
                                    message: Some(e.to_string()),
                                    hostnames_found: 0,
                                });
                            }
                        }
                    } else {
                        sources
                            .insert(source_key(&SourceType::Certspotter).to_string(), Vec::new());
                        source_execution.push(SourceExecutionStatus {
                            source: SourceType::Certspotter,
                            status: "skipped".to_string(),
                            message: Some("CertSpotter API not configured".to_string()),
                            hostnames_found: 0,
                        });
                    }
                }
                _ => {}
            }
        }

        let mut final_subdomains: Vec<String> = hostname_sources.keys().cloned().collect();
        final_subdomains.sort();

        tracing::info!(
            "Subdomain enumeration complete for {}: {} unique domains from {} sources",
            canonical_domain,
            final_subdomains.len(),
            sources.len()
        );

        Ok(SubdomainEnumerationResult {
            subdomains: final_subdomains,
            sources,
            hostname_sources,
            source_execution,
            shodan_ip_owners,
        })
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

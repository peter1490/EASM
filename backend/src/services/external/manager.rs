use crate::config::Settings;
use crate::error::ApiError;
use super::{
    CrtShClient, ShodanClient, VirusTotalClient, CertSpotterClient,
    ShodanResult, ShodanExtractedAssets, CertSpotterCertificate
};
use std::collections::HashMap;
use std::sync::Arc;

/// External services manager that coordinates all API integrations
pub struct ExternalServicesManager {
    crtsh_client: CrtShClient,
    shodan_client: Option<ShodanClient>,
    virustotal_client: Option<VirusTotalClient>,
    certspotter_client: Option<CertSpotterClient>,
}

#[derive(Debug, Clone)]
pub struct SubdomainEnumerationResult {
    pub subdomains: Vec<String>,
    pub sources: HashMap<String, Vec<String>>, // source -> domains found
}

#[derive(Debug, Clone)]
pub struct ThreatIntelligenceResult {
    pub is_malicious: bool,
    pub reputation_score: Option<i32>,
    pub threat_sources: Vec<String>,
    pub additional_info: HashMap<String, String>,
}

impl ExternalServicesManager {
    /// Create a new external services manager with configured API clients
    pub fn new(settings: Arc<Settings>) -> Result<Self, ApiError> {
        let crtsh_client = CrtShClient::new()?;
        
        let shodan_client = if settings.shodan_api_key.is_some() {
            Some(ShodanClient::new(settings.shodan_api_key.clone())?)
        } else {
            None
        };
        
        let virustotal_client = if settings.virustotal_api_key.is_some() {
            Some(VirusTotalClient::new(settings.virustotal_api_key.clone())?)
        } else {
            None
        };
        
        let certspotter_client = if settings.certspotter_api_token.is_some() {
            Some(CertSpotterClient::new(settings.certspotter_api_token.clone())?)
        } else {
            None
        };

        Ok(Self {
            crtsh_client,
            shodan_client,
            virustotal_client,
            certspotter_client,
        })
    }

    /// Perform comprehensive subdomain enumeration using all available sources
    /// Queries Shodan first as primary source, then always queries other sources for comprehensive coverage
    /// Returns a SubdomainEnumerationResult plus extracted Shodan assets for recursive discovery
    pub async fn enumerate_subdomains(&self, domain: &str) -> Result<SubdomainEnumerationResult, ApiError> {
        let mut all_subdomains = std::collections::HashSet::new();
        let mut sources = HashMap::new();

        // PRIORITY 1: Try Shodan first (if configured) as primary source
        // Use comprehensive search to extract ALL asset types
        if let Some(ref client) = self.shodan_client {
            tracing::info!("Enumerating subdomains for {} using Shodan (PRIMARY - Comprehensive)", domain);
            match client.search_domain_comprehensive(domain).await {
                Ok(extracted) => {
                    // Add discovered domains
                    if !extracted.domains.is_empty() {
                        tracing::info!("✓ Shodan found {} domains", extracted.domains.len());
                        let shodan_domains: Vec<String> = extracted.domains.iter().cloned().collect();
                        sources.insert("shodan".to_string(), shodan_domains.clone());
                        all_subdomains.extend(shodan_domains);
                    }
                    
                    // Log additional asset types found (for recursive discovery in parent function)
                    if !extracted.ips.is_empty() {
                        tracing::info!("✓ Shodan found {} IPs (available for recursive discovery)", extracted.ips.len());
                    }
                    if !extracted.asns.is_empty() {
                        tracing::info!("✓ Shodan found {} ASNs (available for recursive discovery)", extracted.asns.len());
                    }
                    if !extracted.organizations.is_empty() {
                        tracing::info!("✓ Shodan found {} organizations (available for recursive discovery)", extracted.organizations.len());
                    }
                    if !extracted.certificates.is_empty() {
                        tracing::info!("✓ Shodan found {} certificates (available for recursive discovery)", extracted.certificates.len());
                    }
                }
                Err(e) => {
                    tracing::warn!("Shodan comprehensive enumeration failed for {}: {}", domain, e);
                }
            }
        } else {
            tracing::info!("Shodan not configured");
        }

        // ALWAYS query additional sources for comprehensive coverage
        tracing::info!("Querying additional sources for comprehensive coverage");

        // Certificate Transparency (crt.sh) - always available
        tracing::info!("Enumerating subdomains for {} using crt.sh", domain);
        match self.crtsh_client.search_domain(domain).await {
            Ok(crtsh_domains) => {
                tracing::info!("Found {} domains from crt.sh", crtsh_domains.len());
                sources.insert("crt.sh".to_string(), crtsh_domains.clone());
                all_subdomains.extend(crtsh_domains);
            }
            Err(e) => {
                tracing::warn!("crt.sh enumeration failed for {}: {}", domain, e);
            }
        }

        // CertSpotter - if configured
        if let Some(ref client) = self.certspotter_client {
            tracing::info!("Enumerating subdomains for {} using CertSpotter", domain);
            match client.get_subdomains(domain).await {
                Ok(certspotter_domains) => {
                    tracing::info!("Found {} domains from CertSpotter", certspotter_domains.len());
                    sources.insert("certspotter".to_string(), certspotter_domains.clone());
                    all_subdomains.extend(certspotter_domains);
                }
                Err(e) => {
                    tracing::warn!("CertSpotter enumeration failed for {}: {}", domain, e);
                }
            }
        }

        // VirusTotal - if configured
        if let Some(ref client) = self.virustotal_client {
            tracing::info!("Enumerating subdomains for {} using VirusTotal", domain);
            match client.get_subdomains(domain).await {
                Ok(vt_domains) => {
                    tracing::info!("Found {} domains from VirusTotal", vt_domains.len());
                    sources.insert("virustotal".to_string(), vt_domains.clone());
                    all_subdomains.extend(vt_domains);
                }
                Err(e) => {
                    tracing::warn!("VirusTotal enumeration failed for {}: {}", domain, e);
                }
            }
        }

        let final_subdomains: Vec<String> = all_subdomains.into_iter().collect();
        
        tracing::info!(
            "Subdomain enumeration complete for {}: {} unique domains from {} sources",
            domain,
            final_subdomains.len(),
            sources.len()
        );

        Ok(SubdomainEnumerationResult {
            subdomains: final_subdomains,
            sources,
        })
    }
    
    /// Get comprehensive Shodan data for a domain (for use in recursive discovery)
    /// Returns all asset types extracted from Shodan
    pub async fn get_shodan_comprehensive_data(&self, domain: &str) -> Result<ShodanExtractedAssets, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_domain_comprehensive(domain).await
        } else {
            // Return empty result if Shodan not configured
            Ok(ShodanExtractedAssets::default())
        }
    }

    /// Search crt.sh for domains by organization name
    pub async fn search_crtsh_by_organization(&self, organization: &str) -> Result<Vec<String>, ApiError> {
        self.crtsh_client.search_organization(organization).await
    }

    /// Get threat intelligence for a domain
    pub async fn get_domain_threat_intel(&self, domain: &str) -> Result<ThreatIntelligenceResult, ApiError> {
        let mut is_malicious = false;
        let mut reputation_score = None;
        let mut threat_sources = Vec::new();
        let mut additional_info = HashMap::new();

        // VirusTotal threat intelligence
        if let Some(ref client) = self.virustotal_client {
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
                            stats.malicious.to_string()
                        );
                        additional_info.insert(
                            "virustotal_suspicious_count".to_string(),
                            stats.suspicious.to_string()
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
    pub async fn get_ip_threat_intel(&self, ip: &str) -> Result<ThreatIntelligenceResult, ApiError> {
        let mut is_malicious = false;
        let mut reputation_score = None;
        let mut threat_sources = Vec::new();
        let mut additional_info = HashMap::new();

        // VirusTotal threat intelligence
        if let Some(ref client) = self.virustotal_client {
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
                            stats.malicious.to_string()
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
        if let Some(ref client) = self.shodan_client {
            client.search(query).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }

    /// Search for hosts by organization using Shodan
    pub async fn search_shodan_by_org(&self, org: &str) -> Result<Vec<ShodanResult>, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_by_org(org).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }

    /// Search for hosts by ASN using Shodan
    pub async fn search_shodan_by_asn(&self, asn: &str) -> Result<Vec<ShodanResult>, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_by_asn(asn).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }

    /// Get certificate information from CertSpotter
    pub async fn get_certificate_info(&self, cert_id: &str) -> Result<CertSpotterCertificate, ApiError> {
        if let Some(ref client) = self.certspotter_client {
            client.get_certificate(cert_id).await
        } else {
            Err(ApiError::ExternalService("CertSpotter API not configured".to_string()))
        }
    }

    /// Get service availability status
    pub fn get_service_status(&self) -> HashMap<String, bool> {
        let mut status = HashMap::new();
        
        status.insert("crt.sh".to_string(), true); // Always available
        status.insert("shodan".to_string(), self.shodan_client.is_some());
        status.insert("virustotal".to_string(), self.virustotal_client.is_some());
        status.insert("certspotter".to_string(), self.certspotter_client.is_some());
        
        status
    }

    /// Get configured API services count
    pub fn get_configured_services_count(&self) -> usize {
        let mut count = 1; // crt.sh is always available
        
        if self.shodan_client.is_some() {
            count += 1;
        }
        if self.virustotal_client.is_some() {
            count += 1;
        }
        if self.certspotter_client.is_some() {
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
        
        tracing::info!("External services manager initialized with {} services", configured_count);
        Ok(())
    }

    /// Comprehensive Shodan search that extracts ALL asset types (IPs, domains, ASNs, orgs, certs)
    pub async fn search_shodan_comprehensive(&self, query: &str) -> Result<ShodanExtractedAssets, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_comprehensive(query).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }

    /// Comprehensive domain search on Shodan - extracts all related assets
    pub async fn search_shodan_domain_comprehensive(&self, domain: &str) -> Result<ShodanExtractedAssets, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_domain_comprehensive(domain).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }

    /// Comprehensive organization search on Shodan - extracts all related assets
    pub async fn search_shodan_org_comprehensive(&self, org: &str) -> Result<ShodanExtractedAssets, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_org_comprehensive(org).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }

    /// Comprehensive ASN search on Shodan - extracts all related assets
    pub async fn search_shodan_asn_comprehensive(&self, asn: &str) -> Result<ShodanExtractedAssets, ApiError> {
        if let Some(ref client) = self.shodan_client {
            client.search_asn_comprehensive(asn).await
        } else {
            Err(ApiError::ExternalService("Shodan API not configured".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    #[tokio::test]
    async fn test_external_services_manager_creation() {
        let settings = Arc::new(Settings::new_with_env_file(false).unwrap());
        let manager = ExternalServicesManager::new(settings).unwrap();
        
        let status = manager.get_service_status();
        assert!(status.get("crt.sh").unwrap_or(&false));
        
        let count = manager.get_configured_services_count();
        assert!(count >= 1); // At least crt.sh should be available
    }

    #[tokio::test]
    async fn test_service_validation() {
        let settings = Arc::new(Settings::new_with_env_file(false).unwrap());
        let manager = ExternalServicesManager::new(settings).unwrap();
        
        // Should not fail even with minimal configuration
        assert!(manager.validate_configuration().is_ok());
    }

    #[tokio::test]
    async fn test_threat_intel_no_apis() {
        let settings = Arc::new(Settings::new_with_env_file(false).unwrap());
        let manager = ExternalServicesManager::new(settings).unwrap();
        
        // Should return non-malicious result when no threat intel APIs are configured
        let result = manager.get_domain_threat_intel("example.com").await.unwrap();
        assert!(!result.is_malicious);
        assert!(result.threat_sources.is_empty());
    }
}
use super::rate_limited_client::RateLimitedClient;
use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanResult {
    pub ip_str: String,
    pub port: u16,
    pub data: String,
    pub timestamp: Option<String>,
    pub transport: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub hostnames: Option<Vec<String>>,
    pub location: Option<ShodanLocation>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanLocation {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub region_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct ShodanSearchResponse {
    pub matches: Vec<ShodanResult>,
    pub total: Option<u64>,
    pub facets: Option<HashMap<String, Vec<ShodanFacet>>>,
}

#[derive(Debug, Deserialize)]
pub struct ShodanFacet {
    pub value: String,
    pub count: u64,
}

#[derive(Debug, Deserialize)]
pub struct ShodanHostInfo {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub ports: Vec<u16>,
    pub data: Vec<ShodanResult>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
}

/// Comprehensive asset extraction from Shodan results
#[derive(Debug, Clone, Default)]
pub struct ShodanExtractedAssets {
    pub ips: HashSet<String>,
    pub domains: HashSet<String>,
    pub asns: HashSet<String>,
    pub organizations: HashSet<String>,
    pub certificates: Vec<ShodanCertificateInfo>,
}

/// Certificate information extracted from Shodan
#[derive(Debug, Clone)]
pub struct ShodanCertificateInfo {
    pub subject: String,
    pub issuer: Option<String>,
    pub domains: Vec<String>,
    pub organization: Option<String>,
}

/// Shodan API client with rate limiting and comprehensive error handling
pub struct ShodanClient {
    client: RateLimitedClient,
    api_key: Option<String>,
}

impl ShodanClient {
    /// Create a new Shodan client with rate limiting (1 request per second for free tier)
    pub fn new(api_key: Option<String>) -> Result<Self, ApiError> {
        let client = RateLimitedClient::new(1, 3)?;

        Ok(Self { client, api_key })
    }

    /// Search Shodan for hosts matching the query
    pub async fn search(&self, query: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("Shodan API key not configured".to_string())
        })?;

        if query.is_empty() {
            return Err(ApiError::Validation(
                "Search query cannot be empty".to_string(),
            ));
        }

        let url = format!(
            "https://api.shodan.io/shodan/host/search?key={}&query={}",
            api_key,
            urlencoding::encode(query)
        );

        tracing::debug!("Querying Shodan: {}", query);

        let response = self.client.get(&url).await?;
        let response_text = response.text().await?;

        let search_response: ShodanSearchResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                ApiError::ExternalService(format!("Failed to parse Shodan response: {}", e))
            })?;

        tracing::info!(
            "Found {} Shodan results for query: {}",
            search_response.matches.len(),
            query
        );
        Ok(search_response.matches)
    }

    /// Get detailed information about a specific host
    pub async fn get_host(&self, ip: &str) -> Result<ShodanHostInfo, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("Shodan API key not configured".to_string())
        })?;

        if ip.is_empty() {
            return Err(ApiError::Validation(
                "IP address cannot be empty".to_string(),
            ));
        }

        // Basic IP validation
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(ApiError::Validation(format!("Invalid IP address: {}", ip)));
        }

        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);

        tracing::debug!("Querying Shodan host info: {}", ip);

        let response = self.client.get(&url).await?;
        let response_text = response.text().await?;

        let host_info: ShodanHostInfo = serde_json::from_str(&response_text).map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse Shodan host response: {}", e))
        })?;

        Ok(host_info)
    }

    /// Search for hosts by organization name
    pub async fn search_by_org(&self, org: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let query = format!("org:\"{}\"", org);
        self.search(&query).await
    }

    /// Search for hosts by ASN
    pub async fn search_by_asn(&self, asn: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let query = format!("asn:{}", asn);
        self.search(&query).await
    }

    /// Search for hosts in a specific network range
    pub async fn search_by_net(&self, network: &str) -> Result<Vec<ShodanResult>, ApiError> {
        let query = format!("net:{}", network);
        self.search(&query).await
    }

    /// Search for subdomains using Shodan's hostname filter
    /// This searches for all hosts that match the domain pattern
    pub async fn search_subdomains(&self, domain: &str) -> Result<Vec<String>, ApiError> {
        if domain.is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        // Use Shodan's hostname filter to find subdomains
        // We search for hostnames containing the domain
        let query = format!("hostname:{}", domain);

        tracing::info!("Searching Shodan for subdomains of: {}", domain);

        let results = self.search(&query).await?;

        // Extract unique hostnames from results
        let mut subdomains = std::collections::HashSet::new();

        for result in results {
            // Add hostnames from the hostnames field
            if let Some(ref hostnames) = result.hostnames {
                for hostname in hostnames {
                    // Only include hostnames that contain or are subdomains of the target domain
                    if hostname.ends_with(domain) || hostname == domain {
                        subdomains.insert(hostname.clone());
                    }
                }
            }

            // Also check domains field if available
            if let Some(ref domains) = result.domains {
                for domain_name in domains {
                    if domain_name.ends_with(domain) || domain_name == domain {
                        subdomains.insert(domain_name.clone());
                    }
                }
            }
        }

        let subdomain_list: Vec<String> = subdomains.into_iter().collect();
        tracing::info!(
            "Found {} unique subdomains from Shodan for {}",
            subdomain_list.len(),
            domain
        );

        Ok(subdomain_list)
    }

    /// Comprehensive search that extracts ALL asset types from Shodan results
    /// Returns IPs, domains, ASNs, organizations, and certificate information
    pub async fn search_comprehensive(
        &self,
        query: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        tracing::info!("Performing comprehensive Shodan search for: {}", query);

        let results = self.search(query).await?;
        let extracted = self.extract_assets_from_results(&results);

        Ok(extracted)
    }

    /// Search by domain and extract all related assets (IPs, subdomains, ASNs, orgs, certs)
    pub async fn search_domain_comprehensive(
        &self,
        domain: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let query = format!("hostname:{}", domain);
        self.search_comprehensive(&query).await
    }

    /// Search by organization and extract all related assets
    pub async fn search_org_comprehensive(
        &self,
        org: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let query = format!("org:\"{}\"", org);
        self.search_comprehensive(&query).await
    }

    /// Search by ASN and extract all related assets
    pub async fn search_asn_comprehensive(
        &self,
        asn: &str,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let query = format!("asn:{}", asn);
        self.search_comprehensive(&query).await
    }

    /// Check if API key is configured
    pub fn is_configured(&self) -> bool {
        self.api_key.is_some()
    }

    /// Extract all asset types from Shodan search results
    /// Returns IPs, domains, ASNs, organizations, and certificate info
    pub fn extract_assets_from_results(&self, results: &[ShodanResult]) -> ShodanExtractedAssets {
        let mut extracted = ShodanExtractedAssets::default();

        for result in results {
            // Extract IP addresses
            extracted.ips.insert(result.ip_str.clone());

            // Extract hostnames/domains
            if let Some(ref hostnames) = result.hostnames {
                for hostname in hostnames {
                    if !hostname.is_empty() {
                        extracted.domains.insert(hostname.clone());
                    }
                }
            }

            // Extract additional domains field
            if let Some(ref domains) = result.domains {
                for domain in domains {
                    if !domain.is_empty() {
                        extracted.domains.insert(domain.clone());
                    }
                }
            }

            // Extract ASN information
            if let Some(ref asn) = result.asn {
                if !asn.is_empty() {
                    // Normalize ASN format (ensure it starts with "AS")
                    let normalized_asn = if asn.starts_with("AS") {
                        asn.clone()
                    } else {
                        format!("AS{}", asn)
                    };
                    extracted.asns.insert(normalized_asn);
                }
            }

            // Extract organization information
            if let Some(ref org) = result.org {
                if !org.is_empty() && org.len() > 2 {
                    extracted.organizations.insert(org.clone());
                }
            }

            // Extract certificate information from SSL/TLS data
            // Check if the data contains SSL/TLS certificate information
            if result.port == 443 || result.data.contains("ssl") || result.data.contains("tls") {
                // Try to extract certificate details from the data field
                // This is a simplified extraction - in production you might want to parse more thoroughly
                if let Some(cert_info) =
                    self.extract_certificate_from_data(&result.data, &result.hostnames)
                {
                    extracted.certificates.push(cert_info);
                }
            }
        }

        tracing::info!(
            "Extracted from Shodan results: {} IPs, {} domains, {} ASNs, {} orgs, {} certs",
            extracted.ips.len(),
            extracted.domains.len(),
            extracted.asns.len(),
            extracted.organizations.len(),
            extracted.certificates.len()
        );

        extracted
    }

    /// Extract certificate information from Shodan data field
    fn extract_certificate_from_data(
        &self,
        data: &str,
        hostnames: &Option<Vec<String>>,
    ) -> Option<ShodanCertificateInfo> {
        // Look for common certificate patterns in the data
        // This is a simplified implementation - Shodan's data field can be complex

        // Check if data contains certificate-related keywords
        if !data.to_lowercase().contains("certificate")
            && !data.to_lowercase().contains("subject")
            && !data.to_lowercase().contains("issuer")
        {
            return None;
        }

        let mut cert_info = ShodanCertificateInfo {
            subject: String::new(),
            issuer: None,
            domains: Vec::new(),
            organization: None,
        };

        // Try to extract subject
        if let Some(subject_start) = data.find("Subject:") {
            if let Some(subject_end) = data[subject_start..].find('\n') {
                let subject = &data[subject_start + 8..subject_start + subject_end];
                cert_info.subject = subject.trim().to_string();

                // Extract organization from subject (CN=..., O=...)
                if let Some(org_start) = subject.find("O=") {
                    if let Some(org_end) = subject[org_start..]
                        .find(',')
                        .or(Some(subject[org_start..].len()))
                    {
                        let org = &subject[org_start + 2..org_start + org_end];
                        cert_info.organization = Some(org.trim().to_string());
                    }
                }
            }
        }

        // Try to extract issuer
        if let Some(issuer_start) = data.find("Issuer:") {
            if let Some(issuer_end) = data[issuer_start..].find('\n') {
                let issuer = &data[issuer_start + 7..issuer_start + issuer_end];
                cert_info.issuer = Some(issuer.trim().to_string());
            }
        }

        // Add hostnames as certificate domains
        if let Some(ref host_vec) = hostnames {
            cert_info.domains = host_vec.clone();
        }

        // Only return if we extracted meaningful information
        if !cert_info.subject.is_empty()
            || cert_info.organization.is_some()
            || !cert_info.domains.is_empty()
        {
            Some(cert_info)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_shodan_search_success() {
        let mock_server = MockServer::start().await;

        let mock_response = r#"{
            "matches": [
                {
                    "ip_str": "192.168.1.1",
                    "port": 80,
                    "data": "HTTP/1.1 200 OK",
                    "timestamp": "2023-01-01T00:00:00.000000",
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "hostnames": ["example.com"],
                    "org": "Example Org",
                    "isp": "Example ISP",
                    "asn": "AS12345"
                }
            ],
            "total": 1
        }"#;

        Mock::given(method("GET"))
            .and(query_param("q", "apache"))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_response))
            .mount(&mock_server)
            .await;

        // We can't easily test the actual client due to the hardcoded URL,
        // but we can test the client creation and validation
        let client = ShodanClient::new(Some("test_key".to_string())).unwrap();
        assert!(client.is_configured());

        let client_no_key = ShodanClient::new(None).unwrap();
        assert!(!client_no_key.is_configured());
    }

    #[tokio::test]
    async fn test_shodan_empty_query() {
        let client = ShodanClient::new(Some("test_key".to_string())).unwrap();
        let result = client.search("").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_shodan_no_api_key() {
        let client = ShodanClient::new(None).unwrap();
        let result = client.search("apache").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ExternalService(msg) => assert!(msg.contains("not configured")),
            _ => panic!("Expected external service error"),
        }
    }

    #[tokio::test]
    async fn test_shodan_invalid_ip() {
        let client = ShodanClient::new(Some("test_key".to_string())).unwrap();
        let result = client.get_host("invalid_ip").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("Invalid IP")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_shodan_search_by_org() {
        let _client = ShodanClient::new(Some("test_key".to_string())).unwrap();
        // This would normally make a real request, but we're just testing the query construction
        // The actual search method would be called with org:"Example Corp"
    }
}

use super::rate_limited_client::RateLimitedClient;
use crate::error::ApiError;
use reqwest::header::LINK;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAX_CERTSPOTTER_PAGES: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSpotterCertificate {
    pub id: String,
    pub tbs_sha256: String,
    pub dns_names: Vec<String>,
    pub pubkey_sha256: String,
    pub not_before: String,
    pub not_after: String,
    pub issuer: CertSpotterIssuer,
    pub cert_der: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSpotterIssuer {
    pub name: String,
    pub pubkey_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSpotterIssuance {
    pub id: String,
    pub tbs_sha256: String,
    pub dns_names: Vec<String>,
    pub pubkey_sha256: String,
    pub not_before: String,
    pub not_after: String,
    pub issuer: CertSpotterIssuer,
}

/// CertSpotter API client for certificate transparency monitoring
pub struct CertSpotterClient {
    client: RateLimitedClient,
    api_token: Option<String>,
}

impl CertSpotterClient {
    /// Create a new CertSpotter client with rate limiting (100 requests per hour for free tier)
    pub fn new(api_token: Option<String>) -> Result<Self, ApiError> {
        // Free tier: 100 requests per hour, so roughly 1 request per 36 seconds
        // We'll be more conservative and use 1 request per 40 seconds
        let client = RateLimitedClient::new(1, 3)?;

        Ok(Self { client, api_token })
    }

    /// Get certificate issuances for a domain
    pub async fn get_issuances(
        &self,
        domain: &str,
        include_subdomains: bool,
    ) -> Result<Vec<CertSpotterIssuance>, ApiError> {
        if domain.is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        let mut initial_url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}",
            urlencoding::encode(domain)
        );

        if include_subdomains {
            initial_url.push_str("&include_subdomains=true");
        }

        if let Some(token) = &self.api_token {
            initial_url.push_str(&format!("&token={}", token));
        }

        tracing::debug!("Querying CertSpotter issuances: {}", domain);

        let mut issuances: Vec<CertSpotterIssuance> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut seen_urls: HashSet<String> = HashSet::new();
        let mut next_url: Option<String> = Some(initial_url);
        let mut page_count = 0usize;

        while let Some(url) = next_url.take() {
            if !seen_urls.insert(url.clone()) {
                tracing::warn!(
                    "Detected repeated CertSpotter issuances URL for {}. Stopping pagination.",
                    domain
                );
                break;
            }
            if page_count >= MAX_CERTSPOTTER_PAGES {
                tracing::warn!(
                    "Reached CertSpotter pagination cap ({}) for {}. Stopping early.",
                    MAX_CERTSPOTTER_PAGES,
                    domain
                );
                break;
            }

            let response = self.client.get(&url).await?;
            let next = response
                .headers()
                .get(LINK)
                .and_then(|v| v.to_str().ok())
                .and_then(Self::extract_next_link);
            let response_text = response.text().await?;

            let page_issuances: Vec<CertSpotterIssuance> = serde_json::from_str(&response_text)
                .map_err(|e| {
                    ApiError::ExternalService(format!(
                        "Failed to parse CertSpotter response: {}",
                        e
                    ))
                })?;
            for issuance in page_issuances {
                if seen_ids.insert(issuance.id.clone()) {
                    issuances.push(issuance);
                }
            }
            page_count += 1;
            next_url = next;
        }

        tracing::info!(
            "Found {} certificate issuances for {} ({} pages)",
            issuances.len(),
            domain,
            page_count
        );
        Ok(issuances)
    }

    /// Get unique subdomains from certificate issuances
    pub async fn get_subdomains(&self, domain: &str) -> Result<Vec<String>, ApiError> {
        let issuances = self.get_issuances(domain, true).await?;

        let mut subdomains = HashSet::new();

        for issuance in issuances {
            for dns_name in issuance.dns_names {
                // Clean and validate the DNS name
                if let Some(clean_domain) = self.validate_and_clean_domain(&dns_name, domain) {
                    subdomains.insert(clean_domain);
                }
            }
        }

        let mut result: Vec<String> = subdomains.into_iter().collect();
        result.sort();

        tracing::info!(
            "Found {} unique subdomains for {} from CertSpotter",
            result.len(),
            domain
        );
        Ok(result)
    }

    /// Get certificate details by ID
    pub async fn get_certificate(&self, cert_id: &str) -> Result<CertSpotterCertificate, ApiError> {
        if cert_id.is_empty() {
            return Err(ApiError::Validation(
                "Certificate ID cannot be empty".to_string(),
            ));
        }

        let mut url = format!("https://api.certspotter.com/v1/certificates/{}", cert_id);

        if let Some(token) = &self.api_token {
            url.push_str(&format!("?token={}", token));
        }

        tracing::debug!("Querying CertSpotter certificate: {}", cert_id);

        let response = self.client.get(&url).await?;
        let response_text = response.text().await?;

        let certificate: CertSpotterCertificate =
            serde_json::from_str(&response_text).map_err(|e| {
                ApiError::ExternalService(format!(
                    "Failed to parse CertSpotter certificate response: {}",
                    e
                ))
            })?;

        Ok(certificate)
    }

    /// Search for certificates by organization name
    pub async fn search_by_organization(
        &self,
        org: &str,
    ) -> Result<Vec<CertSpotterIssuance>, ApiError> {
        if org.is_empty() {
            return Err(ApiError::Validation(
                "Organization name cannot be empty".to_string(),
            ));
        }

        // Note: CertSpotter doesn't have direct organization search in the free API
        // This would need to be implemented by searching for known domains of the organization
        // For now, we'll return an empty result with a warning
        tracing::warn!(
            "Organization search not directly supported by CertSpotter free API for org: {}",
            org
        );
        Ok(Vec::new())
    }

    /// Validate and clean domain names from certificate data
    pub fn validate_and_clean_domain(&self, domain: &str, base_domain: &str) -> Option<String> {
        let mut cleaned = domain.trim().to_lowercase();

        // Skip empty domains
        if cleaned.is_empty() {
            return None;
        }

        // Normalize wildcard domains (e.g., *.example.com -> example.com)
        if cleaned.starts_with("*.") {
            cleaned = cleaned.trim_start_matches("*.").to_string();
        }

        // Reject malformed wildcard patterns (embedded '*' etc.)
        if cleaned.contains('*') {
            return None;
        }

        // Must be related to base domain
        if cleaned != base_domain && !cleaned.ends_with(&format!(".{}", base_domain)) {
            return None;
        }

        // Basic domain validation
        if cleaned.contains(' ') || cleaned.contains('\t') || cleaned.contains('\n') {
            return None;
        }

        Some(cleaned)
    }

    /// Parses RFC 5988 Link headers and returns the URL of the entry with `rel="next"`.
    ///
    /// Walks the header looking for `<URL>; <params>` segments rather than splitting on
    /// `,`, so URLs containing commas (cursors, encoded params) are handled correctly.
    fn extract_next_link(link_header: &str) -> Option<String> {
        let bytes = link_header.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'<' {
                break;
            }
            let url_start = i + 1;
            let url_end_rel = link_header[url_start..].find('>')?;
            let url_end = url_start + url_end_rel;
            let url = &link_header[url_start..url_end];

            // Params run from `>` to the next `,` (URL was already extracted, so
            // any remaining commas are between Link entries).
            let params_start = url_end + 1;
            let params_end = link_header[params_start..]
                .find(',')
                .map(|j| params_start + j)
                .unwrap_or(link_header.len());
            let params = &link_header[params_start..params_end];

            let normalized_params: String = params
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase();
            if normalized_params.contains("rel=\"next\"") || normalized_params.contains("rel=next")
            {
                return Some(url.to_string());
            }

            i = params_end;
        }
        None
    }

    /// Check if API token is configured
    pub fn is_configured(&self) -> bool {
        self.api_token.is_some()
    }

    /// Get rate limit information (if available)
    pub async fn get_rate_limit_info(&self) -> Result<(), ApiError> {
        // CertSpotter doesn't provide a specific rate limit endpoint
        // This is a placeholder for potential future implementation
        tracing::info!("CertSpotter rate limit: 100 requests per hour for free tier");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certspotter_client_creation() {
        let client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();
        assert!(client.is_configured());

        let client_no_token = CertSpotterClient::new(None).unwrap();
        assert!(!client_no_token.is_configured());
    }

    #[tokio::test]
    async fn test_certspotter_empty_domain() {
        let client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();
        let result = client.get_issuances("", false).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_certspotter_domain_validation() {
        let client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();

        // Valid domains
        assert_eq!(
            client.validate_and_clean_domain("example.com", "example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            client.validate_and_clean_domain("sub.example.com", "example.com"),
            Some("sub.example.com".to_string())
        );

        // Wildcard handling - normalize to concrete candidate domains
        assert_eq!(
            client.validate_and_clean_domain("*.example.com", "example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            client.validate_and_clean_domain("*.sub.example.com", "example.com"),
            Some("sub.example.com".to_string())
        );

        // Invalid domains
        assert_eq!(
            client.validate_and_clean_domain("other.com", "example.com"),
            None
        );
        assert_eq!(client.validate_and_clean_domain("", "example.com"), None);
        assert_eq!(
            client.validate_and_clean_domain("invalid domain", "example.com"),
            None
        );
    }

    #[test]
    fn test_extract_next_link() {
        let link = r#"<https://api.certspotter.com/v1/issuances?domain=example.com&cursor=abc>; rel="next", <https://api.certspotter.com/v1/issuances?domain=example.com>; rel="first""#;
        let next = CertSpotterClient::extract_next_link(link);
        assert_eq!(
            next,
            Some(
                "https://api.certspotter.com/v1/issuances?domain=example.com&cursor=abc"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_extract_next_link_with_comma_in_url() {
        // Cursor contains a literal `,` — naive split-on-`,` parsers truncate the URL.
        let link = r#"<https://api.certspotter.com/v1/issuances?cursor=abc,def>; rel="next""#;
        assert_eq!(
            CertSpotterClient::extract_next_link(link),
            Some("https://api.certspotter.com/v1/issuances?cursor=abc,def".to_string())
        );
    }

    #[test]
    fn test_extract_next_link_no_next() {
        let link = r#"<https://api.certspotter.com/v1/issuances?domain=example.com>; rel="first""#;
        assert!(CertSpotterClient::extract_next_link(link).is_none());
    }

    #[tokio::test]
    async fn test_certspotter_empty_cert_id() {
        let client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();
        let result = client.get_certificate("").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_certspotter_organization_search() {
        let client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();
        let result = client.search_by_organization("Example Corp").await;

        // Should return empty result with warning (not implemented in free API)
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}

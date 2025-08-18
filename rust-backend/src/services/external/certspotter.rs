use crate::error::ApiError;
use super::rate_limited_client::RateLimitedClient;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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
        
        Ok(Self {
            client,
            api_token,
        })
    }

    /// Get certificate issuances for a domain
    pub async fn get_issuances(&self, domain: &str, include_subdomains: bool) -> Result<Vec<CertSpotterIssuance>, ApiError> {
        if domain.is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        let mut url = format!("https://api.certspotter.com/v1/issuances?domain={}", urlencoding::encode(domain));
        
        if include_subdomains {
            url.push_str("&include_subdomains=true");
        }
        
        if let Some(token) = &self.api_token {
            url.push_str(&format!("&token={}", token));
        }

        tracing::debug!("Querying CertSpotter issuances: {}", domain);
        
        let response = self.client.get(&url).await?;
        let response_text = response.text().await?;
        
        let issuances: Vec<CertSpotterIssuance> = serde_json::from_str(&response_text)
            .map_err(|e| ApiError::ExternalService(format!("Failed to parse CertSpotter response: {}", e)))?;

        tracing::info!("Found {} certificate issuances for {}", issuances.len(), domain);
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
        
        tracing::info!("Found {} unique subdomains for {} from CertSpotter", result.len(), domain);
        Ok(result)
    }

    /// Get certificate details by ID
    pub async fn get_certificate(&self, cert_id: &str) -> Result<CertSpotterCertificate, ApiError> {
        if cert_id.is_empty() {
            return Err(ApiError::Validation("Certificate ID cannot be empty".to_string()));
        }

        let mut url = format!("https://api.certspotter.com/v1/certificates/{}", cert_id);
        
        if let Some(token) = &self.api_token {
            url.push_str(&format!("?token={}", token));
        }

        tracing::debug!("Querying CertSpotter certificate: {}", cert_id);
        
        let response = self.client.get(&url).await?;
        let response_text = response.text().await?;
        
        let certificate: CertSpotterCertificate = serde_json::from_str(&response_text)
            .map_err(|e| ApiError::ExternalService(format!("Failed to parse CertSpotter certificate response: {}", e)))?;

        Ok(certificate)
    }

    /// Search for certificates by organization name
    pub async fn search_by_organization(&self, org: &str) -> Result<Vec<CertSpotterIssuance>, ApiError> {
        if org.is_empty() {
            return Err(ApiError::Validation("Organization name cannot be empty".to_string()));
        }

        // Note: CertSpotter doesn't have direct organization search in the free API
        // This would need to be implemented by searching for known domains of the organization
        // For now, we'll return an empty result with a warning
        tracing::warn!("Organization search not directly supported by CertSpotter free API for org: {}", org);
        Ok(Vec::new())
    }

    /// Validate and clean domain names from certificate data
    pub fn validate_and_clean_domain(&self, domain: &str, base_domain: &str) -> Option<String> {
        let cleaned = domain.trim().to_lowercase();
        
        // Skip empty domains
        if cleaned.is_empty() {
            return None;
        }
        
        // Skip wildcards to match crt.sh behavior
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
    use wiremock::{matchers::{method, query_param}, Mock, MockServer, ResponseTemplate};

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
        
        // Wildcard handling - now skipped to match crt.sh behavior
        assert_eq!(
            client.validate_and_clean_domain("*.example.com", "example.com"),
            None
        );
        assert_eq!(
            client.validate_and_clean_domain("*.sub.example.com", "example.com"),
            None
        );
        
        // Invalid domains
        assert_eq!(
            client.validate_and_clean_domain("other.com", "example.com"),
            None
        );
        assert_eq!(
            client.validate_and_clean_domain("", "example.com"),
            None
        );
        assert_eq!(
            client.validate_and_clean_domain("invalid domain", "example.com"),
            None
        );
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
use super::rate_limited_client::RateLimitedClient;
use crate::error::ApiError;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
pub struct CrtShEntry {
    pub name_value: String,
    pub common_name: Option<String>,
    pub issuer_name: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// Certificate Transparency log client for subdomain enumeration
pub struct CrtShClient {
    client: RateLimitedClient,
    domain_regex: Regex,
}

impl CrtShClient {
    /// Create a new CRT.sh client with rate limiting (2 requests per second)
    pub fn new() -> Result<Self, ApiError> {
        let client = RateLimitedClient::new(2, 3)?;
        let domain_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
            .map_err(|e| ApiError::Internal(format!("Failed to compile domain regex: {}", e)))?;

        Ok(Self {
            client,
            domain_regex,
        })
    }

    /// Search for subdomains using certificate transparency logs
    pub async fn search_domain(&self, domain: &str) -> Result<Vec<String>, ApiError> {
        if domain.is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        // Search for exact domain and wildcard subdomains
        let mut all_domains = HashSet::new();

        // Search for exact domain
        let exact_domains = self.search_crt_sh(&format!("{}", domain)).await?;
        all_domains.extend(exact_domains);

        // Search for wildcard subdomains
        let wildcard_domains = self.search_crt_sh(&format!("%.{}", domain)).await?;
        all_domains.extend(wildcard_domains);

        // Filter and validate domains
        let mut valid_domains: Vec<String> = all_domains
            .into_iter()
            .filter_map(|d| self.validate_and_clean_domain(&d, domain))
            .collect();

        valid_domains.sort();
        valid_domains.dedup();

        tracing::info!(
            "Found {} unique subdomains for {}",
            valid_domains.len(),
            domain
        );
        Ok(valid_domains)
    }

    /// Search for domains associated with an organization using certificate transparency logs
    pub async fn search_organization(&self, organization: &str) -> Result<Vec<String>, ApiError> {
        if organization.trim().is_empty() {
            return Err(ApiError::Validation(
                "Organization cannot be empty".to_string(),
            ));
        }

        // Use crt.sh advanced query syntax to filter by organization (O=)
        // This queries certificates where the Subject's Organization matches the provided value
        //let query = format!("O={}", organization.trim());
        let url = format!(
            "https://crt.sh/?O={}&output=json",
            urlencoding::encode(organization.trim())
        );

        tracing::debug!("Querying crt.sh (org search): {}", url);

        let response = self.client.get(&url).await?;
        let text = response.text().await?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }

        // only print the response if the parsing fails
        let entries: Vec<CrtShEntry> = serde_json::from_str(&text).map_err(|e| {
            tracing::debug!("crt.sh ORG response: {}", text);
            ApiError::ExternalService(format!("Failed to parse crt.sh response: {}", e))
        })?;

        // Extract, clean, validate, and deduplicate domains
        let mut all_domains = HashSet::new();
        for entry in entries {
            let preferred = entry.common_name.or_else(|| Some(entry.name_value));
            if let Some(domain_like) = preferred {
                for d in domain_like.split('\n') {
                    let mut candidate = d.trim().to_lowercase();
                    if candidate.starts_with("*.") {
                        candidate = candidate.trim_start_matches("*.").to_string();
                    }

                    if candidate.is_empty() {
                        continue;
                    }

                    // Skip obvious invalids
                    if candidate.contains(' ') || candidate.contains('\t') {
                        continue;
                    }

                    if self.domain_regex.is_match(&candidate) {
                        all_domains.insert(candidate);
                    }
                }
            }
        }

        let mut domains: Vec<String> = all_domains.into_iter().collect();
        domains.sort();
        Ok(domains)
    }

    /// Internal method to query crt.sh API
    async fn search_crt_sh(&self, query: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://crt.sh/?Identity={}&output=json",
            urlencoding::encode(query)
        );

        tracing::debug!("Querying crt.sh: {}", url);

        let response = self.client.get(&url).await?;

        // Handle empty responses (no certificates found)
        let text = response.text().await?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let entries: Vec<CrtShEntry> = serde_json::from_str(&text).map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse crt.sh response: {}", e))
        })?;

        let domains: Vec<String> = entries.into_iter().map(|entry| entry.name_value).collect();

        Ok(domains)
    }

    /// Validate and clean domain names from certificate data
    pub fn validate_and_clean_domain(&self, domain: &str, base_domain: &str) -> Option<String> {
        // Clean up the domain string
        let cleaned = domain.trim().to_lowercase();

        // Skip empty domains
        if cleaned.is_empty() {
            return None;
        }

        // Handle multiple domains in one field (separated by newlines)
        let domains: Vec<&str> = cleaned.split('\n').collect();
        for d in domains {
            let d = d.trim();

            // Skip wildcards and invalid characters
            if d.contains('*') || d.contains(' ') || d.contains('\t') {
                continue;
            }

            // Must be related to base domain
            if !d.ends_with(base_domain) && d != base_domain {
                continue;
            }

            // Validate domain format
            if self.domain_regex.is_match(d) {
                return Some(d.to_string());
            }
        }

        None
    }
}

impl Default for CrtShClient {
    fn default() -> Self {
        Self::new().expect("Failed to create CrtShClient")
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
    async fn test_crtsh_search_domain() {
        let mock_server = MockServer::start().await;

        let mock_response = r#"[
            {"name_value": "example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"}
        ]"#;

        Mock::given(method("GET"))
            .and(query_param("output", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(mock_response))
            .mount(&mock_server)
            .await;

        // We can't easily test the actual client due to the hardcoded URL,
        // but we can test the validation logic
        let client = CrtShClient::new().unwrap();

        // Test domain validation
        assert_eq!(
            client.validate_and_clean_domain("www.example.com", "example.com"),
            Some("www.example.com".to_string())
        );

        assert_eq!(
            client.validate_and_clean_domain("*.example.com", "example.com"),
            None
        );

        assert_eq!(
            client.validate_and_clean_domain("unrelated.com", "example.com"),
            None
        );
    }

    #[tokio::test]
    async fn test_crtsh_domain_validation() {
        let client = CrtShClient::new().unwrap();

        // Valid domains
        assert!(client
            .validate_and_clean_domain("example.com", "example.com")
            .is_some());
        assert!(client
            .validate_and_clean_domain("sub.example.com", "example.com")
            .is_some());

        // Invalid domains
        assert!(client
            .validate_and_clean_domain("*.example.com", "example.com")
            .is_none());
        assert!(client
            .validate_and_clean_domain("", "example.com")
            .is_none());
        assert!(client
            .validate_and_clean_domain("invalid domain", "example.com")
            .is_none());
        assert!(client
            .validate_and_clean_domain("other.com", "example.com")
            .is_none());
    }

    #[tokio::test]
    async fn test_crtsh_empty_domain() {
        let client = CrtShClient::new().unwrap();
        let result = client.search_domain("").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected validation error"),
        }
    }
}

use super::rate_limited_client::RateLimitedClient;
use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalDomainReport {
    pub id: String,
    pub attributes: VirusTotalDomainAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalDomainAttributes {
    pub last_analysis_stats: Option<VirusTotalAnalysisStats>,
    pub last_analysis_results: Option<HashMap<String, VirusTotalEngineResult>>,
    pub reputation: Option<i32>,
    pub whois: Option<String>,
    pub categories: Option<HashMap<String, String>>,
    pub last_dns_records: Option<Vec<VirusTotalDnsRecord>>,
    pub subdomains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalAnalysisStats {
    pub harmless: u32,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub timeout: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalEngineResult {
    pub category: String,
    pub result: Option<String>,
    pub method: String,
    pub engine_name: String,
    pub engine_version: Option<String>,
    pub engine_update: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalDnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalIpReport {
    pub id: String,
    pub attributes: VirusTotalIpAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalIpAttributes {
    pub last_analysis_stats: Option<VirusTotalAnalysisStats>,
    pub last_analysis_results: Option<HashMap<String, VirusTotalEngineResult>>,
    pub reputation: Option<i32>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_owner: Option<String>,
    pub network: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VirusTotalResponse<T> {
    pub data: T,
}

#[derive(Debug, Deserialize)]
pub struct VirusTotalListResponse<T> {
    pub data: Vec<T>,
    pub links: Option<VirusTotalLinks>,
    pub meta: Option<VirusTotalMeta>,
}

#[derive(Debug, Deserialize)]
pub struct VirusTotalLinks {
    #[serde(rename = "self")]
    pub self_link: Option<String>,
    pub next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VirusTotalMeta {
    pub count: Option<u32>,
}

/// VirusTotal API client with rate limiting and comprehensive error handling
pub struct VirusTotalClient {
    client: RateLimitedClient,
    api_key: Option<String>,
}

impl VirusTotalClient {
    /// Create a new VirusTotal client with rate limiting (4 requests per minute for free tier)
    pub fn new(api_key: Option<String>) -> Result<Self, ApiError> {
        // Free tier: 4 requests per minute, so roughly 1 request per 15 seconds
        let client = RateLimitedClient::new(1, 3)?;

        Ok(Self { client, api_key })
    }

    /// Get domain report from VirusTotal
    pub async fn get_domain_report(
        &self,
        domain: &str,
    ) -> Result<VirusTotalDomainReport, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("VirusTotal API key not configured".to_string())
        })?;

        if domain.is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        let url = format!("https://www.virustotal.com/api/v3/domains/{}", domain);

        tracing::debug!("Querying VirusTotal domain: {}", domain);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-apikey",
            reqwest::header::HeaderValue::from_str(api_key)
                .map_err(|e| ApiError::Validation(format!("Invalid API key format: {}", e)))?,
        );

        let response = self.client.get_with_headers(&url, headers).await?;
        let response_text = response.text().await?;

        let vt_response: VirusTotalResponse<VirusTotalDomainReport> =
            serde_json::from_str(&response_text).map_err(|e| {
                ApiError::ExternalService(format!("Failed to parse VirusTotal response: {}", e))
            })?;

        Ok(vt_response.data)
    }

    /// Get IP address report from VirusTotal
    pub async fn get_ip_report(&self, ip: &str) -> Result<VirusTotalIpReport, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("VirusTotal API key not configured".to_string())
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

        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);

        tracing::debug!("Querying VirusTotal IP: {}", ip);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-apikey",
            reqwest::header::HeaderValue::from_str(api_key)
                .map_err(|e| ApiError::Validation(format!("Invalid API key format: {}", e)))?,
        );

        let response = self.client.get_with_headers(&url, headers).await?;
        let response_text = response.text().await?;

        let vt_response: VirusTotalResponse<VirusTotalIpReport> =
            serde_json::from_str(&response_text).map_err(|e| {
                ApiError::ExternalService(format!("Failed to parse VirusTotal response: {}", e))
            })?;

        Ok(vt_response.data)
    }

    /// Get subdomains for a domain from VirusTotal
    pub async fn get_subdomains(&self, domain: &str) -> Result<Vec<String>, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("VirusTotal API key not configured".to_string())
        })?;

        if domain.is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        let url = format!(
            "https://www.virustotal.com/api/v3/domains/{}/subdomains",
            domain
        );

        tracing::debug!("Querying VirusTotal subdomains: {}", domain);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-apikey",
            reqwest::header::HeaderValue::from_str(api_key)
                .map_err(|e| ApiError::Validation(format!("Invalid API key format: {}", e)))?,
        );

        let response = self.client.get_with_headers(&url, headers).await?;
        let response_text = response.text().await?;

        let vt_response: VirusTotalListResponse<VirusTotalDomainReport> =
            serde_json::from_str(&response_text).map_err(|e| {
                ApiError::ExternalService(format!(
                    "Failed to parse VirusTotal subdomains response: {}",
                    e
                ))
            })?;

        let subdomains: Vec<String> = vt_response
            .data
            .into_iter()
            .map(|report| report.id)
            .collect();

        tracing::info!(
            "Found {} subdomains for {} from VirusTotal",
            subdomains.len(),
            domain
        );
        Ok(subdomains)
    }

    /// Check if a domain is considered malicious by VirusTotal
    pub fn is_malicious_domain(&self, report: &VirusTotalDomainReport) -> bool {
        if let Some(stats) = &report.attributes.last_analysis_stats {
            stats.malicious > 0 || stats.suspicious > 2
        } else {
            false
        }
    }

    /// Check if an IP is considered malicious by VirusTotal
    pub fn is_malicious_ip(&self, report: &VirusTotalIpReport) -> bool {
        if let Some(stats) = &report.attributes.last_analysis_stats {
            stats.malicious > 0 || stats.suspicious > 2
        } else {
            false
        }
    }

    /// Get reputation score for a domain (-100 to 100, negative is bad)
    pub fn get_domain_reputation(&self, report: &VirusTotalDomainReport) -> Option<i32> {
        report.attributes.reputation
    }

    /// Get reputation score for an IP (-100 to 100, negative is bad)
    pub fn get_ip_reputation(&self, report: &VirusTotalIpReport) -> Option<i32> {
        report.attributes.reputation
    }

    /// Check if API key is configured
    pub fn is_configured(&self) -> bool {
        self.api_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_virustotal_client_creation() {
        let client = VirusTotalClient::new(Some("test_key".to_string())).unwrap();
        assert!(client.is_configured());

        let client_no_key = VirusTotalClient::new(None).unwrap();
        assert!(!client_no_key.is_configured());
    }

    #[tokio::test]
    async fn test_virustotal_empty_domain() {
        let client = VirusTotalClient::new(Some("test_key".to_string())).unwrap();
        let result = client.get_domain_report("").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_virustotal_invalid_ip() {
        let client = VirusTotalClient::new(Some("test_key".to_string())).unwrap();
        let result = client.get_ip_report("invalid_ip").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Validation(msg) => assert!(msg.contains("Invalid IP")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_virustotal_no_api_key() {
        let client = VirusTotalClient::new(None).unwrap();
        let result = client.get_domain_report("example.com").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ExternalService(msg) => assert!(msg.contains("not configured")),
            _ => panic!("Expected external service error"),
        }
    }

    #[tokio::test]
    async fn test_virustotal_reputation_analysis() {
        let client = VirusTotalClient::new(Some("test_key".to_string())).unwrap();

        // Test malicious domain detection
        let malicious_report = VirusTotalDomainReport {
            id: "malicious.com".to_string(),
            attributes: VirusTotalDomainAttributes {
                last_analysis_stats: Some(VirusTotalAnalysisStats {
                    harmless: 10,
                    malicious: 5,
                    suspicious: 2,
                    undetected: 3,
                    timeout: 0,
                }),
                last_analysis_results: None,
                reputation: Some(-50),
                whois: None,
                categories: None,
                last_dns_records: None,
                subdomains: None,
            },
        };

        assert!(client.is_malicious_domain(&malicious_report));
        assert_eq!(client.get_domain_reputation(&malicious_report), Some(-50));

        // Test clean domain
        let clean_report = VirusTotalDomainReport {
            id: "clean.com".to_string(),
            attributes: VirusTotalDomainAttributes {
                last_analysis_stats: Some(VirusTotalAnalysisStats {
                    harmless: 15,
                    malicious: 0,
                    suspicious: 1,
                    undetected: 4,
                    timeout: 0,
                }),
                last_analysis_results: None,
                reputation: Some(80),
                whois: None,
                categories: None,
                last_dns_records: None,
                subdomains: None,
            },
        };

        assert!(!client.is_malicious_domain(&clean_report));
        assert_eq!(client.get_domain_reputation(&clean_report), Some(80));
    }
}

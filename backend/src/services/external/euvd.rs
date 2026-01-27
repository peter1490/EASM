//! EUVD (European Union Vulnerability Database) API Client
//!
//! Integrates with ENISA's EUVD API to fetch vulnerability information.
//! API Documentation: https://euvd.enisa.europa.eu/apidoc

use crate::error::ApiError;
use crate::utils::version_rs;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const EUVD_API_BASE: &str = "https://euvdservices.enisa.europa.eu/api";
const EUVD_WEB_BASE: &str = "https://euvd.enisa.europa.eu/vulnerability";

/// EUVD API Client
pub struct EuvdClient {
    client: Client,
}

/// Vulnerability record from EUVD API
/// All fields are optional and unknown fields are captured in `extra`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EuvdVulnerability {
    /// ENISA unique identifier (e.g., "EUVD-2024-45012")
    pub id: Option<String>,
    /// ENISA UUID
    #[serde(rename = "enisaUuid")]
    pub enisa_uuid: Option<String>,
    /// Vulnerability description
    pub description: Option<String>,
    /// Publication date (format: "Dec 2, 2020, 4:20:12 PM")
    #[serde(rename = "datePublished")]
    pub date_published: Option<String>,
    /// Last update date
    #[serde(rename = "dateUpdated")]
    pub date_updated: Option<String>,
    /// Base CVSS score (0-10)
    #[serde(rename = "baseScore")]
    pub base_score: Option<f64>,
    /// CVSS version (e.g., "3.1")
    #[serde(rename = "baseScoreVersion")]
    pub base_score_version: Option<String>,
    /// CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")
    #[serde(rename = "baseScoreVector")]
    pub base_score_vector: Option<String>,
    /// Base severity (e.g., "MEDIUM", "HIGH")
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    /// EPSS score (probability of exploitation, 0-100)
    pub epss: Option<f64>,
    /// EPSS percentile
    #[serde(rename = "epssPercentile")]
    pub epss_percentile: Option<f64>,
    /// Whether this vulnerability is actively exploited (KEV)
    pub exploited: Option<bool>,
    /// Alternative identifiers (CVE IDs, etc.)
    pub aliases: Option<Vec<String>>,
    /// Affected products
    pub product: Option<String>,
    /// Affected products list
    pub products: Option<Vec<String>>,
    /// Vendor
    pub vendor: Option<String>,
    /// Vendors list
    pub vendors: Option<Vec<String>>,
    /// References and links - can be either strings or objects
    #[serde(default, deserialize_with = "deserialize_references")]
    pub references: Vec<String>,
    /// Assigner (e.g., "mitre", "redhat")
    pub assigner: Option<String>,
    /// CWE IDs
    pub cwe: Option<Vec<String>>,
    /// Affected products detailed information
    #[serde(rename = "enisaIdProduct")]
    pub affected_products: Option<Vec<EnisaAffectedProduct>>,
    /// Catch-all for any other fields
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Custom deserializer for references that can be either strings or objects
fn deserialize_references<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};

    struct ReferencesVisitor;

    impl<'de> Visitor<'de> for ReferencesVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of strings or reference objects")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut refs = Vec::new();

            while let Some(value) = seq.next_element::<serde_json::Value>()? {
                match value {
                    serde_json::Value::String(s) => refs.push(s),
                    serde_json::Value::Object(obj) => {
                        // Try to extract URL from object
                        if let Some(serde_json::Value::String(url)) = obj.get("url") {
                            refs.push(url.clone());
                        }
                    }
                    _ => {}
                }
            }

            Ok(refs)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(ReferencesVisitor)
}

/// Reference link from EUVD (kept for backwards compatibility)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EuvdReference {
    pub url: Option<String>,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub ref_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnisaProduct {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnisaAffectedProduct {
    pub id: Option<String>,
    pub product: EnisaProduct,
    #[serde(rename = "product_version")]
    pub product_version: String,
}

/// Search response from EUVD API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuvdSearchResponse {
    pub items: Option<Vec<EuvdVulnerability>>,
    pub total: Option<i64>,
    pub page: Option<i32>,
    pub size: Option<i32>,
}

/// Search parameters for EUVD API
#[derive(Debug, Default)]
pub struct EuvdSearchParams {
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub text: Option<String>,
    pub from_score: Option<f64>,
    pub to_score: Option<f64>,
    pub exploited: Option<bool>,
    pub page: Option<i32>,
    pub size: Option<i32>,
}

impl EuvdClient {
    /// Create a new EUVD client
    pub fn new() -> Result<Self, ApiError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("EASM-Scanner/1.0")
            .build()
            .map_err(|e| ApiError::HttpClient(e))?;

        Ok(Self { client })
    }

    /// Generate EUVD web URL for a CVE
    pub fn get_vulnerability_url(cve_id: &str) -> String {
        format!("{}/{}", EUVD_WEB_BASE, cve_id)
    }

    /// Parse a vulnerability from a JSON value (manual parsing for robustness)
    fn parse_vulnerability(item: &serde_json::Value) -> Option<EuvdVulnerability> {
        // Helper to extract optional string
        let get_str = |key: &str| -> Option<String> {
            item.get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };

        // Helper to extract optional f64
        let get_f64 = |key: &str| -> Option<f64> { item.get(key).and_then(|v| v.as_f64()) };

        // Helper to extract optional bool
        let get_bool = |key: &str| -> Option<bool> { item.get(key).and_then(|v| v.as_bool()) };

        // Extract aliases (array of strings)
        let aliases = item.get("aliases").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

        // Extract references (can be strings or objects with url field)
        let references = item
            .get("references")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        if let Some(s) = v.as_str() {
                            Some(s.to_string())
                        } else if let Some(url) = v.get("url").and_then(|u| u.as_str()) {
                            Some(url.to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Extract products (can be string or array)
        let products = if let Some(arr) = item.get("products").and_then(|v| v.as_array()) {
            Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
            )
        } else {
            None
        };

        // Extract vendors (can be string or array)
        let vendors = if let Some(arr) = item.get("vendors").and_then(|v| v.as_array()) {
            Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
            )
        } else {
            None
        };

        // Extract CWE (array of strings)
        let cwe = item.get("cwe").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

        // Extract all enisaIdProduct
        let affected_products =
            if let Some(arr) = item.get("enisaIdProduct").and_then(|v| v.as_array()) {
                serde_json::from_value(serde_json::Value::Array(arr.clone())).ok()
            } else {
                None
            };

        Some(EuvdVulnerability {
            id: get_str("id"),
            enisa_uuid: get_str("enisaUuid"),
            description: get_str("description"),
            date_published: get_str("datePublished"),
            date_updated: get_str("dateUpdated"),
            base_score: get_f64("baseScore"),
            base_score_version: get_str("baseScoreVersion"),
            base_score_vector: get_str("baseScoreVector"),
            base_severity: get_str("baseSeverity"),
            epss: get_f64("epss"),
            epss_percentile: get_f64("epssPercentile"),
            exploited: get_bool("exploited"),
            aliases,
            product: get_str("product"),
            products,
            vendor: get_str("vendor"),
            vendors,
            references,
            assigner: get_str("assigner"),
            cwe,
            affected_products,
            extra: std::collections::HashMap::new(),
        })
    }

    /// Check if a specific version is affected by a vulnerability
    pub fn is_version_affected(
        vuln: &EuvdVulnerability,
        product_name: &str,
        version: &str,
    ) -> bool {
        // If no detailed product info, fallback to assuming it might be affected (false positive usage)
        // However, the goal is to be precise, so if we have details, we use them.
        // tracing affected products
        let affected_products = match &vuln.affected_products {
            Some(products) => products,
            None => return true, // Fallback if no detailed info is available
        };

        let normalized_product = product_name.to_lowercase();
        let normalized_version = version.trim();

        for affected in affected_products {
            // Check if product name matches (if needed, though usually we search by product)
            // The search query might have returned this vuln for this product.
            // But let's be safe and check if the affected product name matches what we are checking.
            // Fuzzy match or contains? EUVD names might be "NGINX Open Source" vs just "nginx"
            // Let's assume broad matching if the vulnerability was found for this product.
            if affected.product.name.to_lowercase() == normalized_product {
                // Split the product version into multiple ranges (ex: "1.36.0, < 2.2.0")
                for range in affected.product_version.split(',') {
                    let range = range.trim();
                    // Core logic: check version range
                    if Self::check_version_range(&range, normalized_version) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if a version string matches an EUVD version range
    fn check_version_range(range_str: &str, version_str: &str) -> bool {
        // Examples of ranges:
        // "1.11.4 <*" (start 1.11.4, unbounded end)
        // "n/a ≤1.8.3" (unbounded start, end <= 1.8.3)
        // "5.3.0 <5.3.1"
        // "<*" (all versions?)
        // "0 ≤1.11.4"

        // Parse version for comparison
        let service_version = match version_rs::Version::from(version_str) {
            Some(v) => v,
            None => return true, // If we can't parse our version, assume affected to be safe
        };

        // Split range string by space?
        // Usually formats are "Start <End" or "Start <=End" with an operator?
        // Based on user input: "1.11.4 <*"
        // "n/a ≤1.8.3"
        // "5.3.0 <5.3.1"
        // It seems to be "StartRange [Operator]EndRange"?
        // Or "StartRange Operator EndRange"?
        // Let's look closely at "1.11.4 <*".
        // It seems to be "LOWER_BOUND UPPER_BOUND_WITH_OP"?
        // Or "LOWER_BOUND < UPPER_BOUND"?

        // Let's try to parse based on common patterns seen in EUVD.
        // Pattern 1: "VERSION < VERSION" or "VERSION <= VERSION"
        // Note the space.

        let parts: Vec<&str> = range_str.split_whitespace().collect();
        if parts.len() != 2 {
            if parts.len() == 3 && parts[1] == "-" {
                let start_range_ver = match version_rs::Version::from(parts[0]) {
                    Some(v) => v,
                    None => return true, // If we can't parse our version, assume affected to be safe
                };

                let end_range_ver = match version_rs::Version::from(parts[2]) {
                    Some(v) => v,
                    None => return true, // If we can't parse our version, assume affected to be safe
                };
                println!("Checking range: {} - {}", parts[0], parts[2]);
                if start_range_ver <= service_version && service_version <= end_range_ver {
                    return true;
                }
            } else if parts.len() == 1 {
                // Unexpected format, maybe single version?
                let range_version = match version_rs::Version::from(range_str) {
                    Some(v) => v,
                    None => return true, // If we can't parse our version, assume affected to be safe
                };

                if range_version == service_version {
                    return true;
                }
            }
            return false;
        }

        let start_str = parts[0];
        let end_part = parts[1];

        // if start is special cases and end is version with comparator
        // exemple "n/a ≤1.8.3"
        if matches!(start_str, "n/a" | "*" | "0" | "through") {
            // Unbounded start
            // Now check end part
            let (operator, end_ver_str) = if end_part.starts_with("≤") {
                ("≤", &end_part["≤".len()..])
            } else if end_part.starts_with("<=") {
                ("<=", &end_part["<=".len()..])
            } else if end_part.starts_with("<") {
                ("<", &end_part["<".len()..])
            } else {
                ("", end_part)
            };

            if let Some(end_ver) = version_rs::Version::from(end_ver_str) {
                return match operator {
                    "≤" | "<=" => service_version <= end_ver,
                    "<" => service_version < end_ver,
                    _ => true, // Unknown operator
                };
            }
            return true;
        }

        // if end as comparator and can parse start as version
        // exemple "1.11.4 <*" or "5.3.0 <5.3.1"
        if let Some(bound_ver) = version_rs::Version::from(start_str) {
            return match end_part {
                ">" | ">*" => bound_ver > service_version,
                ">=" | "≥" => bound_ver >= service_version,
                "<" | "<*" => bound_ver < service_version,
                "<=" | "≤" => bound_ver <= service_version,
                _ => {
                    let (operator, end_ver_str) = if end_part.starts_with("≤") {
                        ("≤", &end_part["≤".len()..])
                    } else if end_part.starts_with("<=") {
                        ("<=", &end_part["<=".len()..])
                    } else if end_part.starts_with("<") {
                        ("<", &end_part["<".len()..])
                    } else {
                        ("", end_part)
                    };
                    if let Some(end_ver) = version_rs::Version::from(end_ver_str) {
                        return match operator {
                            "≤" | "<=" => {
                                bound_ver <= service_version && service_version <= end_ver
                            }
                            "<" => bound_ver < service_version && service_version < end_ver,
                            _ => true, // Unknown operator
                        };
                    }
                    true
                }
            };
        }
        false
    }

    /// Search vulnerabilities by product and optionally version
    pub async fn search_by_product(
        &self,
        product: &str,
        vendor: Option<&str>,
    ) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let mut params = EuvdSearchParams {
            product: Some(product.to_string()),
            size: Some(100), // Max allowed
            ..Default::default()
        };

        if let Some(v) = vendor {
            params.vendor = Some(v.to_string());
        }

        self.search(params).await
    }

    /// Search vulnerabilities by text query
    pub async fn search_by_text(&self, query: &str) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let params = EuvdSearchParams {
            text: Some(query.to_string()),
            size: Some(100),
            ..Default::default()
        };

        self.search(params).await
    }

    /// Search for actively exploited vulnerabilities
    pub async fn search_exploited(&self) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let params = EuvdSearchParams {
            exploited: Some(true),
            size: Some(100),
            ..Default::default()
        };

        self.search(params).await
    }

    /// Search vulnerabilities with custom parameters
    pub async fn search(
        &self,
        params: EuvdSearchParams,
    ) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let mut url = format!("{}/search?", EUVD_API_BASE);
        let mut query_parts = Vec::new();

        if let Some(product) = &params.product {
            query_parts.push(format!("product={}", urlencoding::encode(product)));
        }
        if let Some(vendor) = &params.vendor {
            query_parts.push(format!("vendor={}", urlencoding::encode(vendor)));
        }
        if let Some(text) = &params.text {
            query_parts.push(format!("text={}", urlencoding::encode(text)));
        }
        if let Some(from_score) = params.from_score {
            query_parts.push(format!("fromScore={}", from_score));
        }
        if let Some(to_score) = params.to_score {
            query_parts.push(format!("toScore={}", to_score));
        }
        if let Some(exploited) = params.exploited {
            query_parts.push(format!("exploited={}", exploited));
        }
        if let Some(page) = params.page {
            query_parts.push(format!("page={}", page));
        }
        if let Some(size) = params.size {
            query_parts.push(format!("size={}", size));
        }

        url.push_str(&query_parts.join("&"));

        tracing::info!("EUVD API request: {}", url);

        let response =
            self.client.get(&url).send().await.map_err(|e| {
                ApiError::ExternalService(format!("EUVD API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::ExternalService(format!(
                "EUVD API returned {}: {}",
                status, body
            )));
        }

        // Parse response as raw JSON first for maximum flexibility
        let text = response.text().await.map_err(|e| {
            ApiError::ExternalService(format!("Failed to read EUVD response: {}", e))
        })?;

        // Parse as generic JSON value
        let json: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to parse EUVD response as JSON: {}", e);
                return Ok(Vec::new());
            }
        };

        // Extract items array (either from root or from "items" field)
        let items = if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
            items.clone()
        } else if let Some(arr) = json.as_array() {
            arr.clone()
        } else {
            tracing::warn!("EUVD response has unexpected structure");
            return Ok(Vec::new());
        };

        // Manually convert each item to EuvdVulnerability
        let vulns: Vec<EuvdVulnerability> = items
            .into_iter()
            .filter_map(|item| Self::parse_vulnerability(&item))
            .collect();

        Ok(vulns)
    }

    /// Get the latest vulnerabilities
    pub async fn get_latest_vulnerabilities(&self) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let url = format!("{}/lastvulnerabilities", EUVD_API_BASE);

        let response =
            self.client.get(&url).send().await.map_err(|e| {
                ApiError::ExternalService(format!("EUVD API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(ApiError::ExternalService(format!(
                "EUVD API returned {}",
                response.status()
            )));
        }

        let vulns: Vec<EuvdVulnerability> = response.json().await.map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse EUVD response: {}", e))
        })?;

        Ok(vulns)
    }

    /// Get actively exploited vulnerabilities
    pub async fn get_exploited_vulnerabilities(&self) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let url = format!("{}/exploitedvulnerabilities", EUVD_API_BASE);

        let response =
            self.client.get(&url).send().await.map_err(|e| {
                ApiError::ExternalService(format!("EUVD API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(ApiError::ExternalService(format!(
                "EUVD API returned {}",
                response.status()
            )));
        }

        let vulns: Vec<EuvdVulnerability> = response.json().await.map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse EUVD response: {}", e))
        })?;

        Ok(vulns)
    }

    /// Get critical vulnerabilities
    pub async fn get_critical_vulnerabilities(&self) -> Result<Vec<EuvdVulnerability>, ApiError> {
        let url = format!("{}/criticalvulnerabilities", EUVD_API_BASE);

        let response =
            self.client.get(&url).send().await.map_err(|e| {
                ApiError::ExternalService(format!("EUVD API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(ApiError::ExternalService(format!(
                "EUVD API returned {}",
                response.status()
            )));
        }

        let vulns: Vec<EuvdVulnerability> = response.json().await.map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse EUVD response: {}", e))
        })?;

        Ok(vulns)
    }

    /// Get vulnerability by EUVD ID (e.g., "EUVD-2024-45012")
    pub async fn get_by_euvd_id(
        &self,
        euvd_id: &str,
    ) -> Result<Option<EuvdVulnerability>, ApiError> {
        let url = format!(
            "{}/enisaid?id={}",
            EUVD_API_BASE,
            urlencoding::encode(euvd_id)
        );

        let response =
            self.client.get(&url).send().await.map_err(|e| {
                ApiError::ExternalService(format!("EUVD API request failed: {}", e))
            })?;

        if response.status().is_client_error() {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(ApiError::ExternalService(format!(
                "EUVD API returned {}",
                response.status()
            )));
        }

        let vuln: EuvdVulnerability = response.json().await.map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse EUVD response: {}", e))
        })?;

        Ok(Some(vuln))
    }

    /// Search for a specific CVE by its ID
    /// Note: CVE IDs are stored in the `aliases` field
    pub async fn search_by_cve(&self, cve_id: &str) -> Result<Option<EuvdVulnerability>, ApiError> {
        // Search using the CVE ID as text
        let params = EuvdSearchParams {
            text: Some(cve_id.to_string()),
            size: Some(10),
            ..Default::default()
        };

        let mut results = self.search(params).await?;

        // Find the one that has this CVE in aliases
        for vuln in &results {
            if let Some(aliases) = &vuln.aliases {
                if aliases.iter().any(|a| a.eq_ignore_ascii_case(cve_id)) {
                    return Ok(Some(vuln.clone()));
                }
            }
        }

        Ok(results.pop())
    }
}

impl Default for EuvdClient {
    fn default() -> Self {
        Self::new().expect("Failed to create EUVD client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_url() {
        let url = EuvdClient::get_vulnerability_url("CVE-2021-44228");
        assert_eq!(
            url,
            "https://euvd.enisa.europa.eu/vulnerability/CVE-2021-44228"
        );
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_search_by_product() {
        let client = EuvdClient::new().unwrap();
        let results = client.search_by_product("openssh", None).await;
        assert!(results.is_ok());
    }
    #[test]
    fn test_check_version_range() {
        // Test basic comparisons
        assert!(EuvdClient::check_version_range("1.11.4 <*", "1.12.0"));
        assert!(EuvdClient::check_version_range("1.11.4 <*", "1.11.4"));
        assert!(!EuvdClient::check_version_range("1.11.4 <*", "1.11.3"));

        // Test n/a start
        assert!(EuvdClient::check_version_range("n/a ≤1.8.3", "1.8.3"));
        assert!(EuvdClient::check_version_range("n/a ≤1.8.3", "1.0.0"));
        assert!(!EuvdClient::check_version_range("n/a ≤1.8.3", "1.8.4"));

        // Test range
        assert!(EuvdClient::check_version_range("5.3.0 <5.3.1", "5.3.0"));
        assert!(EuvdClient::check_version_range("5.3.0 <5.3.1", "5.3.0.5"));
        assert!(!EuvdClient::check_version_range("5.3.0 <5.3.1", "5.3.1"));
        assert!(!EuvdClient::check_version_range("5.3.0 <5.3.1", "5.2.9"));

        // Test exact
        assert!(EuvdClient::check_version_range("1.2.3", "1.2.3"));
    }
}

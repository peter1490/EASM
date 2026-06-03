//! NVD (NIST National Vulnerability Database) API Client
//!
//! Integrates with NIST's NVD 2.0 CVE API to fetch vulnerability information.
//! Unlike the EUVD API, NVD exposes structured CPE version ranges
//! (`versionStartIncluding`/`versionEndExcluding`/…) for every affected product,
//! which lets us perform precise version matching client-side.
//!
//! API Documentation: https://nvd.nist.gov/developers/vulnerabilities
//!
//! An optional API key (read from the `NVD_API_KEY` environment variable) raises
//! the rate limit from 5 to 50 requests per rolling 30-second window. Without a
//! key NVD throttles aggressively, so requests are retried with backoff on 403/429/503.

use crate::error::ApiError;
use crate::utils::version_rs::Version;
use reqwest::Client;
use std::time::Duration;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_WEB_BASE: &str = "https://nvd.nist.gov/vuln/detail";
/// Retry attempts on rate-limit / transient errors before giving up.
const MAX_RETRIES: u32 = 2;
/// Base backoff between retries; NVD recommends ~6s spacing without an API key.
const RETRY_BACKOFF: Duration = Duration::from_secs(6);

/// NVD API Client
pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
}

/// A normalized vulnerability record distilled from an NVD 2.0 CVE object.
#[derive(Debug, Clone, Default)]
pub struct NvdVulnerability {
    /// CVE identifier (e.g., "CVE-2021-23017")
    pub id: String,
    /// English description, if present
    pub description: Option<String>,
    /// Best available CVSS base score (prefers v3.1 > v3.0 > v4.0 > v2)
    pub base_score: Option<f64>,
    /// Base severity label (e.g., "HIGH")
    pub base_severity: Option<String>,
    /// CVSS vector string
    pub base_score_vector: Option<String>,
    /// CVSS version (e.g., "3.1")
    pub base_score_version: Option<String>,
    /// CWE identifiers
    pub cwe: Vec<String>,
    /// Reference URLs
    pub references: Vec<String>,
    /// Whether NVD flags this CVE as a CISA Known Exploited Vulnerability
    pub exploited: bool,
    /// Flattened list of vulnerable CPE matches across all configurations
    pub cpe_matches: Vec<NvdCpeMatch>,
}

/// A single vulnerable CPE match with its optional version range bounds.
#[derive(Debug, Clone, Default)]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    /// CPE 2.3 criteria string (e.g., "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")
    pub criteria: String,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

impl NvdCpeMatch {
    fn has_version_bounds(&self) -> bool {
        self.version_start_including.is_some()
            || self.version_start_excluding.is_some()
            || self.version_end_including.is_some()
            || self.version_end_excluding.is_some()
    }

    /// (vendor, product, version) parsed from the CPE 2.3 criteria string.
    fn cpe_parts(&self) -> (String, String, String) {
        // cpe:2.3:part:vendor:product:version:update:edition:...
        let parts: Vec<&str> = self.criteria.split(':').collect();
        let get = |i: usize| parts.get(i).map(|s| s.to_string()).unwrap_or_default();
        (get(3), get(4), get(5))
    }

    /// Human-readable affected-version range derived from this match.
    fn format_range(&self) -> String {
        let mut lower = None;
        if let Some(v) = &self.version_start_including {
            lower = Some(format!(">= {}", v));
        } else if let Some(v) = &self.version_start_excluding {
            lower = Some(format!("> {}", v));
        }

        let mut upper = None;
        if let Some(v) = &self.version_end_including {
            upper = Some(format!("<= {}", v));
        } else if let Some(v) = &self.version_end_excluding {
            upper = Some(format!("< {}", v));
        }

        match (lower, upper) {
            (Some(l), Some(u)) => format!("{}, {}", l, u),
            (Some(l), None) => l,
            (None, Some(u)) => u,
            (None, None) => {
                // No range bounds: fall back to the CPE version component.
                let (_, _, version) = self.cpe_parts();
                match version.as_str() {
                    "*" | "-" | "" => "all versions".to_string(),
                    v => v.to_string(),
                }
            }
        }
    }
}

impl NvdClient {
    /// Create a new NVD client. Picks up an optional API key from `NVD_API_KEY`.
    pub fn new() -> Result<Self, ApiError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("EASM-Scanner/1.0")
            .build()
            .map_err(ApiError::HttpClient)?;

        let api_key = std::env::var("NVD_API_KEY")
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());

        Ok(Self { client, api_key })
    }

    /// Generate the NVD web URL for a CVE.
    pub fn vulnerability_url(cve_id: &str) -> String {
        format!("{}/{}", NVD_WEB_BASE, cve_id)
    }

    /// Normalize a product/vendor token for fuzzy comparison: lowercase and drop
    /// any non-alphanumeric characters (so "next.js" == "nextjs", "http_server"
    /// == "httpserver").
    fn normalize_token(s: &str) -> String {
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    }

    /// Does the searched product name plausibly refer to this CPE's vendor/product?
    fn product_matches(norm_product: &str, cpe_vendor: &str, cpe_product: &str) -> bool {
        if norm_product.is_empty() {
            return false;
        }
        let vendor = Self::normalize_token(cpe_vendor);
        let product = Self::normalize_token(cpe_product);

        if product == norm_product || vendor == norm_product {
            return true;
        }
        // Fuzzy containment, but only for tokens long enough to be meaningful
        // (avoids "go"/"vi"-style substrings matching everything).
        if norm_product.len() >= 3 {
            if product.contains(norm_product) || vendor.contains(norm_product) {
                return true;
            }
        }
        false
    }

    /// Evaluate whether `service_version` falls inside a single CPE match's range.
    fn version_in_match(
        cpe_match: &NvdCpeMatch,
        service_version: Option<&Version>,
        version_str: &str,
    ) -> bool {
        if cpe_match.has_version_bounds() {
            // Without a parseable service version we can't compare ranges; assume
            // affected to stay on the safe side.
            let sv = match service_version {
                Some(v) => v,
                None => return true,
            };
            if let Some(b) = cpe_match
                .version_start_including
                .as_deref()
                .and_then(Version::from)
            {
                if *sv < b {
                    return false;
                }
            }
            if let Some(b) = cpe_match
                .version_start_excluding
                .as_deref()
                .and_then(Version::from)
            {
                if *sv <= b {
                    return false;
                }
            }
            if let Some(b) = cpe_match
                .version_end_including
                .as_deref()
                .and_then(Version::from)
            {
                if *sv > b {
                    return false;
                }
            }
            if let Some(b) = cpe_match
                .version_end_excluding
                .as_deref()
                .and_then(Version::from)
            {
                if *sv >= b {
                    return false;
                }
            }
            true
        } else {
            // No explicit bounds: rely on the CPE version component itself.
            let (_, _, cpe_version) = cpe_match.cpe_parts();
            match cpe_version.as_str() {
                "*" | "-" | "" => true, // applies to all versions
                specific => match (service_version, Version::from(specific)) {
                    (Some(a), Some(b)) => *a == b,
                    _ => specific.eq_ignore_ascii_case(version_str),
                },
            }
        }
    }

    /// Check whether a specific `(product, version)` is affected by this CVE,
    /// using NVD's structured CPE version ranges.
    pub fn is_version_affected(vuln: &NvdVulnerability, product: &str, version: &str) -> bool {
        let norm_product = Self::normalize_token(product);
        let service_version = Version::from(version);

        for cpe_match in &vuln.cpe_matches {
            if !cpe_match.vulnerable {
                continue;
            }
            let (vendor, cpe_product, _) = cpe_match.cpe_parts();
            if !Self::product_matches(&norm_product, &vendor, &cpe_product) {
                continue;
            }
            if Self::version_in_match(cpe_match, service_version.as_ref(), version) {
                return true;
            }
        }
        false
    }

    /// Collect human-readable affected-version ranges to display for a finding:
    /// the range(s) of the vulnerable CPE matches that (a) belong to the searched
    /// product and (b) actually contain the detected version.
    pub fn affected_version_ranges(
        vuln: &NvdVulnerability,
        product: &str,
        version: &str,
    ) -> Vec<String> {
        let candidates: Vec<String> = Self::cpe_product_candidates(product)
            .iter()
            .map(|c| Self::normalize_token(c))
            .collect();
        let service_version = Version::from(version);
        let mut ranges: Vec<String> = Vec::new();

        for cpe_match in &vuln.cpe_matches {
            if !cpe_match.vulnerable {
                continue;
            }
            let (_, cpe_product, _) = cpe_match.cpe_parts();
            if !candidates.contains(&Self::normalize_token(&cpe_product)) {
                continue;
            }
            if !Self::version_in_match(cpe_match, service_version.as_ref(), version) {
                continue;
            }
            let range = cpe_match.format_range();
            if !ranges.contains(&range) {
                ranges.push(range);
            }
        }
        ranges
    }

    /// Candidate CPE product tokens for a detected product name. Most products'
    /// CPE product equals their lowercased name, but some Server-header / banner
    /// names differ from their CPE product (e.g. "Apache" → `http_server`), so we
    /// map those explicitly. Returns tokens to try in priority order.
    fn cpe_product_candidates(product: &str) -> Vec<String> {
        let norm = product.trim().to_lowercase();

        // Curated aliases: displayed/banner name -> CPE product component.
        let aliased: Option<&str> = match norm.as_str() {
            "apache" | "apache httpd" | "apache http server" | "httpd" => Some("http_server"),
            "microsoft iis" | "microsoft-iis" | "ms iis" | "iis" => {
                Some("internet_information_services")
            }
            "apache tomcat" | "tomcat" => Some("tomcat"),
            "microsoft exchange" | "microsoft exchange server" | "exchange" => {
                Some("exchange_server")
            }
            "eclipse jetty" | "jetty" => Some("jetty"),
            "litespeed" => Some("litespeed_web_server"),
            "dropbear ssh" | "dropbear" => Some("dropbear_ssh"),
            "filezilla server" | "filezilla" => Some("filezilla_server"),
            _ => None,
        };
        if let Some(a) = aliased {
            return vec![a.to_string()];
        }

        // Default: CPE products replace spaces with underscores. Also try the
        // bare last word for multi-word names whose CPE product is just that word.
        let underscored: String = norm.split_whitespace().collect::<Vec<_>>().join("_");
        let mut out = vec![underscored.clone()];
        if let Some(last) = norm.split_whitespace().last() {
            if last != underscored {
                out.push(last.to_string());
            }
        }
        out
    }

    /// Extract a CPE-safe version token from a detected version string
    /// (e.g. "8.0.32-log" → "8.0.32", "1.21.0 (Ubuntu)" → "1.21.0", "v2.4" → "2.4").
    fn cpe_version_token(version: &str) -> Option<String> {
        let v = version.trim().trim_start_matches(['v', 'V']);
        let core: String = v
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
            .collect();
        let core = core.trim_matches('.').to_string();
        if core.is_empty() {
            None
        } else {
            Some(core)
        }
    }

    /// Search NVD for CVEs affecting a specific `(product, version)`.
    ///
    /// Uses NVD's server-side, version-range-aware CPE matching via
    /// `virtualMatchString` with a wildcard vendor, so we don't need to know the
    /// vendor and NVD itself filters by the detected version (handling CVEs whose
    /// affected set is expressed as a version range). Returns the matching CVEs.
    pub async fn search_affecting(
        &self,
        product: &str,
        version: &str,
    ) -> Result<Vec<NvdVulnerability>, ApiError> {
        let version_token = match Self::cpe_version_token(version) {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };

        // Try each product-token candidate; return the first non-empty match set.
        for product_token in Self::cpe_product_candidates(product) {
            let match_string = format!(
                "cpe:2.3:a:*:{}:{}:*:*:*:*:*:*:*",
                product_token, version_token
            );
            let url = format!(
                "{}?virtualMatchString={}",
                NVD_API_BASE,
                urlencoding::encode(&match_string)
            );

            tracing::info!("NVD API request: {}", url);

            let text = self.get_with_retry(&url).await?;

            let json: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Failed to parse NVD response as JSON: {}", e);
                    continue;
                }
            };

            let items = match json.get("vulnerabilities").and_then(|v| v.as_array()) {
                Some(arr) => arr,
                None => {
                    tracing::warn!("NVD response has unexpected structure");
                    continue;
                }
            };

            if items.is_empty() {
                continue;
            }

            let vulns: Vec<NvdVulnerability> = items
                .iter()
                .filter_map(|item| item.get("cve").map(Self::parse_cve))
                .collect();
            return Ok(vulns);
        }

        Ok(Vec::new())
    }

    /// Parse a single NVD `cve` object into our normalized representation.
    fn parse_cve(cve: &serde_json::Value) -> NvdVulnerability {
        let id = cve
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // Description: prefer the English entry.
        let description = cve.get("descriptions").and_then(|v| v.as_array()).map(|arr| {
            let en = arr.iter().find(|d| {
                d.get("lang").and_then(|l| l.as_str()) == Some("en")
            });
            en.or_else(|| arr.first())
                .and_then(|d| d.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        });

        // CVSS metrics: prefer v3.1, then v3.0, then v4.0, then v2.
        let metrics = cve.get("metrics");
        let (base_score, base_severity, base_score_vector, base_score_version) =
            Self::best_cvss(metrics);

        // CWE identifiers.
        let cwe = cve
            .get("weaknesses")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| w.get("description").and_then(|d| d.as_array()))
                    .flatten()
                    .filter_map(|d| d.get("value").and_then(|v| v.as_str()))
                    .filter(|s| s.starts_with("CWE-"))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        // Reference URLs.
        let references = cve
            .get("references")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // CISA Known Exploited Vulnerability flag.
        let exploited = cve.get("cisaExploitAdd").is_some();

        // Flatten vulnerable CPE matches across all configurations/nodes.
        let cpe_matches = Self::parse_cpe_matches(cve);

        NvdVulnerability {
            id,
            description,
            base_score,
            base_severity,
            base_score_vector,
            base_score_version,
            cwe,
            references,
            exploited,
            cpe_matches,
        }
    }

    /// Pick the best available CVSS metric, returning
    /// (score, severity, vector, version).
    fn best_cvss(
        metrics: Option<&serde_json::Value>,
    ) -> (Option<f64>, Option<String>, Option<String>, Option<String>) {
        let metrics = match metrics {
            Some(m) => m,
            None => return (None, None, None, None),
        };

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"] {
            if let Some(first) = metrics.get(key).and_then(|v| v.as_array()).and_then(|a| a.first()) {
                let data = first.get("cvssData");
                let score = data
                    .and_then(|d| d.get("baseScore"))
                    .and_then(|v| v.as_f64());
                let vector = data
                    .and_then(|d| d.get("vectorString"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let version = data
                    .and_then(|d| d.get("version"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                // v3.x/v4.0 carry baseSeverity inside cvssData; v2 carries it on
                // the metric object itself.
                let severity = data
                    .and_then(|d| d.get("baseSeverity"))
                    .or_else(|| first.get("baseSeverity"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                if score.is_some() {
                    return (score, severity, vector, version);
                }
            }
        }
        (None, None, None, None)
    }

    /// Flatten all vulnerable `cpeMatch` entries from a CVE's configurations.
    fn parse_cpe_matches(cve: &serde_json::Value) -> Vec<NvdCpeMatch> {
        let mut matches = Vec::new();
        let configurations = match cve.get("configurations").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => return matches,
        };

        for config in configurations {
            let nodes = match config.get("nodes").and_then(|v| v.as_array()) {
                Some(n) => n,
                None => continue,
            };
            for node in nodes {
                let cpe_match = match node.get("cpeMatch").and_then(|v| v.as_array()) {
                    Some(m) => m,
                    None => continue,
                };
                for m in cpe_match {
                    let get_str = |key: &str| {
                        m.get(key)
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    };
                    matches.push(NvdCpeMatch {
                        vulnerable: m
                            .get("vulnerable")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        criteria: get_str("criteria").unwrap_or_default(),
                        version_start_including: get_str("versionStartIncluding"),
                        version_start_excluding: get_str("versionStartExcluding"),
                        version_end_including: get_str("versionEndIncluding"),
                        version_end_excluding: get_str("versionEndExcluding"),
                    });
                }
            }
        }
        matches
    }

    /// Issue a GET request, retrying with backoff on rate-limit / transient errors.
    /// Returns the response body text.
    async fn get_with_retry(&self, url: &str) -> Result<String, ApiError> {
        let mut attempt = 0;
        loop {
            let mut req = self.client.get(url);
            if let Some(key) = &self.api_key {
                req = req.header("apiKey", key);
            }

            let response = req.send().await.map_err(|e| {
                ApiError::ExternalService(format!("NVD API request failed: {}", e))
            })?;

            let status = response.status();
            if status.is_success() {
                return response.text().await.map_err(|e| {
                    ApiError::ExternalService(format!("Failed to read NVD response: {}", e))
                });
            }

            let retryable = matches!(status.as_u16(), 403 | 429 | 503);
            if retryable && attempt < MAX_RETRIES {
                attempt += 1;
                let backoff = RETRY_BACKOFF * attempt;
                tracing::warn!(
                    "NVD API returned {} (attempt {}/{}), backing off {:?}",
                    status,
                    attempt,
                    MAX_RETRIES,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(ApiError::ExternalService(format!(
                "NVD API returned {}: {}",
                status, body
            )));
        }
    }
}

impl Default for NvdClient {
    fn default() -> Self {
        Self::new().expect("Failed to create NVD client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpe(criteria: &str) -> NvdCpeMatch {
        NvdCpeMatch {
            vulnerable: true,
            criteria: criteria.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_vulnerability_url() {
        assert_eq!(
            NvdClient::vulnerability_url("CVE-2021-44228"),
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        );
    }

    #[test]
    fn test_product_matches() {
        // exact product / vendor
        assert!(NvdClient::product_matches("nginx", "f5", "nginx"));
        assert!(NvdClient::product_matches("apache", "apache", "http_server"));
        assert!(NvdClient::product_matches("openssh", "openbsd", "openssh"));
        // separator-insensitive
        assert!(NvdClient::product_matches("nextjs", "vercel", "next.js"));
        // non-match
        assert!(!NvdClient::product_matches("nginx", "apache", "http_server"));
        assert!(!NvdClient::product_matches("", "apache", "http_server"));
    }

    #[test]
    fn test_version_range_inclusive_exclusive() {
        let mut m = cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*");
        m.version_start_including = Some("0.6.18".to_string());
        m.version_end_excluding = Some("1.20.1".to_string());
        let vuln = NvdVulnerability {
            cpe_matches: vec![m],
            ..Default::default()
        };

        assert!(NvdClient::is_version_affected(&vuln, "nginx", "1.19.0"));
        assert!(NvdClient::is_version_affected(&vuln, "nginx", "0.6.18")); // lower inclusive
        assert!(!NvdClient::is_version_affected(&vuln, "nginx", "1.20.1")); // upper exclusive
        assert!(!NvdClient::is_version_affected(&vuln, "nginx", "0.6.17")); // below range
        // product mismatch -> not affected even if version is in range
        assert!(!NvdClient::is_version_affected(&vuln, "apache", "1.19.0"));
    }

    #[test]
    fn test_version_end_including_and_start_excluding() {
        let mut m = cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*");
        m.version_start_excluding = Some("7.0".to_string());
        m.version_end_including = Some("8.3".to_string());
        let vuln = NvdVulnerability {
            cpe_matches: vec![m],
            ..Default::default()
        };

        assert!(!NvdClient::is_version_affected(&vuln, "openssh", "7.0")); // lower exclusive
        assert!(NvdClient::is_version_affected(&vuln, "openssh", "7.1"));
        assert!(NvdClient::is_version_affected(&vuln, "openssh", "8.3")); // upper inclusive
        assert!(!NvdClient::is_version_affected(&vuln, "openssh", "8.4"));
    }

    #[test]
    fn test_specific_cpe_version_no_bounds() {
        let vuln = NvdVulnerability {
            cpe_matches: vec![cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")],
            ..Default::default()
        };
        assert!(NvdClient::is_version_affected(&vuln, "apache", "2.4.49"));
        assert!(!NvdClient::is_version_affected(&vuln, "apache", "2.4.50"));
    }

    #[test]
    fn test_wildcard_cpe_version_matches_all() {
        let vuln = NvdVulnerability {
            cpe_matches: vec![cpe("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")],
            ..Default::default()
        };
        assert!(NvdClient::is_version_affected(&vuln, "product", "1.0.0"));
        assert!(NvdClient::is_version_affected(&vuln, "product", "99.9"));
    }

    #[test]
    fn test_affected_version_ranges_display() {
        let mut m = cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*");
        m.version_start_including = Some("0.6.18".to_string());
        m.version_end_excluding = Some("1.20.1".to_string());
        let vuln = NvdVulnerability {
            cpe_matches: vec![m],
            ..Default::default()
        };
        // Detected version 1.0.0 falls in [0.6.18, 1.20.1) -> that range is shown.
        let ranges = NvdClient::affected_version_ranges(&vuln, "nginx", "1.0.0");
        assert_eq!(ranges, vec![">= 0.6.18, < 1.20.1".to_string()]);
        // A version outside every affected range yields no displayed range.
        assert!(NvdClient::affected_version_ranges(&vuln, "nginx", "2.0.0").is_empty());
    }

    #[test]
    fn test_cpe_product_candidates() {
        // Server-header names that differ from their CPE product.
        assert_eq!(
            NvdClient::cpe_product_candidates("Apache HTTP Server"),
            vec!["http_server".to_string()]
        );
        assert_eq!(
            NvdClient::cpe_product_candidates("Microsoft IIS"),
            vec!["internet_information_services".to_string()]
        );
        // Direct matches.
        assert_eq!(NvdClient::cpe_product_candidates("nginx"), vec!["nginx"]);
        assert_eq!(NvdClient::cpe_product_candidates("OpenSSH"), vec!["openssh"]);
        assert_eq!(NvdClient::cpe_product_candidates("next.js"), vec!["next.js"]);
        // Unknown multi-word: underscored form + bare last word.
        assert_eq!(
            NvdClient::cpe_product_candidates("Acme Web Server"),
            vec!["acme_web_server".to_string(), "server".to_string()]
        );
    }

    #[test]
    fn test_cpe_version_token() {
        assert_eq!(NvdClient::cpe_version_token("2.4.49").as_deref(), Some("2.4.49"));
        assert_eq!(NvdClient::cpe_version_token("8.0.32-log").as_deref(), Some("8.0.32"));
        assert_eq!(NvdClient::cpe_version_token("1.21.0 (Ubuntu)").as_deref(), Some("1.21.0"));
        assert_eq!(NvdClient::cpe_version_token("v2.4").as_deref(), Some("2.4"));
        assert_eq!(NvdClient::cpe_version_token("1.0.2k").as_deref(), Some("1.0.2k"));
        assert_eq!(NvdClient::cpe_version_token("-").as_deref(), None);
    }

    #[test]
    fn test_parse_cve_full() {
        let json = serde_json::json!({
            "id": "CVE-2021-23017",
            "descriptions": [
                { "lang": "es", "value": "descripcion" },
                { "lang": "en", "value": "A security issue in nginx resolver." }
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
                        "baseScore": 7.7,
                        "baseSeverity": "HIGH"
                    }
                }]
            },
            "weaknesses": [
                { "description": [{ "lang": "en", "value": "CWE-193" }] }
            ],
            "references": [
                { "url": "https://example.com/advisory" }
            ],
            "cisaExploitAdd": "2021-11-03",
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "0.6.18",
                        "versionEndExcluding": "1.20.1"
                    }]
                }]
            }]
        });

        let vuln = NvdClient::parse_cve(&json);
        assert_eq!(vuln.id, "CVE-2021-23017");
        assert_eq!(
            vuln.description.as_deref(),
            Some("A security issue in nginx resolver.")
        );
        assert_eq!(vuln.base_score, Some(7.7));
        assert_eq!(vuln.base_severity.as_deref(), Some("HIGH"));
        assert_eq!(vuln.base_score_version.as_deref(), Some("3.1"));
        assert_eq!(vuln.cwe, vec!["CWE-193".to_string()]);
        assert_eq!(vuln.references, vec!["https://example.com/advisory".to_string()]);
        assert!(vuln.exploited);
        assert_eq!(vuln.cpe_matches.len(), 1);
        assert!(NvdClient::is_version_affected(&vuln, "nginx", "1.19.0"));
    }

    #[test]
    fn test_parse_cve_cvss_v2_fallback() {
        let json = serde_json::json!({
            "id": "CVE-2018-0001",
            "descriptions": [{ "lang": "en", "value": "old vuln" }],
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "baseScore": 7.5
                    },
                    "baseSeverity": "HIGH"
                }]
            }
        });
        let vuln = NvdClient::parse_cve(&json);
        assert_eq!(vuln.base_score, Some(7.5));
        assert_eq!(vuln.base_severity.as_deref(), Some("HIGH"));
        assert_eq!(vuln.base_score_version.as_deref(), Some("2.0"));
        assert!(!vuln.exploited);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_search_affecting() {
        let client = NvdClient::new().unwrap();
        // nginx 1.18.0 has a known, bounded set of CVEs in NVD.
        let results = client.search_affecting("nginx", "1.18.0").await;
        assert!(results.is_ok());
        let vulns = results.unwrap();
        assert!(
            !vulns.is_empty(),
            "expected NVD to return CVEs affecting nginx 1.18.0"
        );
        assert!(
            vulns.iter().any(|v| v.id == "CVE-2021-23017"),
            "expected CVE-2021-23017 in results, got: {:?}",
            vulns.iter().map(|v| &v.id).collect::<Vec<_>>()
        );
    }
}

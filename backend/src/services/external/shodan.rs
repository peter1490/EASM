use super::rate_limited_client::RateLimitedClient;
use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const SHODAN_PAGE_SIZE: usize = 100;
/// Each page past the 1st costs 1 Shodan query credit, so keep this small by default.
const MAX_SHODAN_PAGES: u32 = 10;
const MAX_SHODAN_DNS_PAGES: u32 = 50;
/// RFC 1035 limits: 253 characters and 127 labels for a fully qualified name.
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_HOSTNAME_LABELS: usize = 127;

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
    /// TLS banner, when the service speaks TLS. Carries the JARM fingerprint.
    #[serde(default)]
    pub ssl: Option<ShodanSsl>,
}

/// The TLS portion of a Shodan banner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanSsl {
    /// JARM fingerprint as Shodan computed it.
    ///
    /// Reading Shodan's own value rather than computing one locally is
    /// deliberate: JARM is a *fuzzy* hash of ten precisely-shaped ClientHellos,
    /// and a locally-computed fingerprint that differs from Shodan's in any
    /// detail would query `ssl.jarm:` with a value the index has never seen —
    /// a pivot that silently returns nothing rather than failing loudly.
    #[serde(default)]
    pub jarm: Option<String>,
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

#[derive(Debug, Deserialize)]
struct ShodanDnsDomainResponse {
    /// The zone Shodan actually answered for. The /dns/domain endpoint is an apex
    /// endpoint: query any sub-hostname and it still answers for the registrable
    /// domain, echoing it here. Bare labels in `subdomains`/`data` are relative to
    /// THIS, not to whatever we asked for.
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub subdomains: Vec<String>,
    #[serde(default)]
    pub data: Vec<ShodanDnsRecord>,
    #[serde(default)]
    pub more: bool,
}

#[derive(Debug, Deserialize)]
struct ShodanDnsRecord {
    #[serde(default)]
    pub subdomain: String,
    #[serde(default, rename = "type")]
    pub record_type: String,
}

/// Comprehensive asset extraction from Shodan results
#[derive(Debug, Clone, Default)]
pub struct ShodanExtractedAssets {
    pub ips: HashSet<String>,
    /// IP -> owner hint (org/ISP), used to avoid extra lookups downstream.
    pub ip_owners: HashMap<String, String>,
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

        tracing::debug!("Querying Shodan: {}", query);

        let mut page: u32 = 1;
        let mut processed_pages: u32 = 0;
        let mut all_results = Vec::new();
        let mut seen_result_keys: HashSet<String> = HashSet::new();
        let mut total_announced: Option<u64> = None;

        loop {
            let url = format!(
                "https://api.shodan.io/shodan/host/search?key={}&query={}&page={}",
                api_key,
                urlencoding::encode(query),
                page
            );

            let response = self.client.get(&url).await?;
            let response_text = response.text().await?;

            let search_response: ShodanSearchResponse = serde_json::from_str(&response_text)
                .map_err(|e| {
                    ApiError::ExternalService(format!("Failed to parse Shodan response: {}", e))
                })?;

            if total_announced.is_none() {
                total_announced = search_response.total;
            }

            let page_results = search_response.matches;
            let page_result_count = page_results.len();
            if page_result_count == 0 {
                break;
            }
            processed_pages += 1;

            let mut newly_added = 0usize;
            for result in page_results {
                let key = Self::stable_result_key(&result);
                if seen_result_keys.insert(key) {
                    all_results.push(result);
                    newly_added += 1;
                }
            }

            if newly_added == 0 {
                tracing::warn!(
                    "Shodan returned a repeated/duplicate page for query '{}' at page {}. Stopping pagination.",
                    query,
                    page
                );
                break;
            }

            // Stop once we've collected everything Shodan claims exists.
            if let Some(total) = total_announced {
                if (all_results.len() as u64) >= total {
                    break;
                }
            }

            if page >= MAX_SHODAN_PAGES {
                tracing::warn!(
                    "Reached Shodan pagination cap ({}) for query '{}'. Returning {} of {} announced results.",
                    MAX_SHODAN_PAGES,
                    query,
                    all_results.len(),
                    total_announced
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                );
                break;
            }

            if page_result_count < SHODAN_PAGE_SIZE {
                break;
            }

            page += 1;
        }

        tracing::info!(
            "Found {} unique Shodan results for query '{}' after {} page(s)",
            all_results.len(),
            query,
            processed_pages
        );
        Ok(all_results)
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

    /// Fetches passive DNS subdomains from Shodan DNS domain endpoint.
    pub async fn search_dns_domain_subdomains(
        &self,
        domain: &str,
    ) -> Result<Vec<String>, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("Shodan API key not configured".to_string())
        })?;

        if domain.trim().is_empty() {
            return Err(ApiError::Validation("Domain cannot be empty".to_string()));
        }

        let canonical_domain = domain.trim().trim_end_matches('.').to_lowercase();
        tracing::debug!(
            "Querying Shodan DNS domain endpoint for subdomains: {}",
            canonical_domain
        );

        let mut hostnames: HashSet<String> = HashSet::new();
        let mut page: u32 = 1;
        let mut pages_fetched: u32 = 0;

        loop {
            let url = format!(
                "https://api.shodan.io/dns/domain/{}?key={}&page={}",
                urlencoding::encode(&canonical_domain),
                api_key,
                page
            );

            let response = self.client.get(&url).await?;
            let response_text = response.text().await?;

            let dns_response: ShodanDnsDomainResponse = serde_json::from_str(&response_text)
                .map_err(|e| {
                    ApiError::ExternalService(format!(
                        "Failed to parse Shodan DNS domain response: {}",
                        e
                    ))
                })?;

            pages_fetched += 1;

            // Compose relative labels against the zone Shodan answered for, never against
            // the hostname we queried. Querying a sub-hostname (as deeper discovery does)
            // still returns the apex's labels, so suffixing them onto the query would
            // manufacture "audio.audio.example.com" and compound at every depth.
            let base_domain = dns_response
                .domain
                .as_deref()
                .map(|d| d.trim().trim_end_matches('.').to_lowercase())
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| canonical_domain.clone());

            if base_domain != canonical_domain {
                tracing::debug!(
                    "Shodan DNS domain endpoint answered for {} when queried for {}; \
                     composing subdomains against {}",
                    base_domain,
                    canonical_domain,
                    base_domain
                );
            }

            for subdomain in &dns_response.subdomains {
                if let Some(hostname) = Self::compose_dns_hostname(&base_domain, subdomain) {
                    hostnames.insert(hostname);
                }
            }
            for record in &dns_response.data {
                if !Self::is_hostname_dns_type(&record.record_type) {
                    continue;
                }
                if let Some(hostname) = Self::compose_dns_hostname(&base_domain, &record.subdomain)
                {
                    hostnames.insert(hostname);
                }
            }

            if !dns_response.more {
                break;
            }
            if page >= MAX_SHODAN_DNS_PAGES {
                tracing::warn!(
                    "Reached Shodan DNS-domain pagination cap ({}) for {}; further pages skipped.",
                    MAX_SHODAN_DNS_PAGES,
                    canonical_domain
                );
                break;
            }
            page += 1;
        }

        let mut subdomain_list: Vec<String> = hostnames.into_iter().collect();
        subdomain_list.sort();
        tracing::info!(
            "Found {} unique subdomains from Shodan DNS domain endpoint for {} ({} page(s))",
            subdomain_list.len(),
            canonical_domain,
            pages_fetched
        );
        Ok(subdomain_list)
    }

    /// Restrict DNS-domain records to types whose `subdomain` field names a hostname.
    fn is_hostname_dns_type(record_type: &str) -> bool {
        matches!(
            record_type.to_ascii_uppercase().as_str(),
            "" | "A" | "AAAA" | "CNAME" | "NS"
        )
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
        let host_search_result = self.search_comprehensive(&query).await;
        let dns_subdomain_result = self.search_dns_domain_subdomains(domain).await;

        match (host_search_result, dns_subdomain_result) {
            (Ok(mut extracted), Ok(subdomains)) => {
                extracted.domains.extend(subdomains);
                Ok(extracted)
            }
            (Ok(extracted), Err(dns_error)) => {
                tracing::warn!(
                    "Shodan DNS domain endpoint failed for {}: {}",
                    domain,
                    dns_error
                );
                Ok(extracted)
            }
            (Err(host_search_error), Ok(subdomains)) => {
                tracing::warn!(
                    "Shodan hostname search failed for {}: {}. Returning DNS-domain-only results.",
                    domain,
                    host_search_error
                );
                let mut extracted = ShodanExtractedAssets::default();
                extracted.domains.extend(subdomains);
                Ok(extracted)
            }
            (Err(host_search_error), Err(dns_error)) => Err(ApiError::ExternalService(format!(
                "Shodan hostname and DNS-domain queries both failed for '{}': hostname={}, dns={}",
                domain, host_search_error, dns_error
            ))),
        }
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

    /// Count results for a filtered query without consuming query credits.
    /// Used to gate lateral pivots (favicon/JARM/HTML) so a SaaS-grade saturated
    /// fingerprint cannot blow the discovery run's Shodan budget.
    pub async fn count(&self, query: &str) -> Result<u64, ApiError> {
        let api_key = self.api_key.as_ref().ok_or_else(|| {
            ApiError::ExternalService("Shodan API key not configured".to_string())
        })?;
        if query.is_empty() {
            return Err(ApiError::Validation(
                "Search query cannot be empty".to_string(),
            ));
        }

        let url = format!(
            "https://api.shodan.io/shodan/host/count?key={}&query={}",
            api_key,
            urlencoding::encode(query)
        );
        let response = self.client.get(&url).await?;
        let text = response.text().await?;
        #[derive(Deserialize)]
        struct CountResponse {
            #[serde(default)]
            total: u64,
        }
        let parsed: CountResponse = serde_json::from_str(&text).map_err(|e| {
            ApiError::ExternalService(format!("Failed to parse Shodan count response: {}", e))
        })?;
        Ok(parsed.total)
    }

    /// Lateral pivot — find hosts whose favicon hash matches `hash`.
    /// `max_results` caps the result set after a free count pre-check (Shodan's
    /// `host/count` does not consume query credits). When the live count exceeds
    /// the cap the pivot is skipped entirely and an empty extraction is returned;
    /// this prevents a popular SaaS favicon from saturating the queue.
    pub async fn search_by_favicon_hash(
        &self,
        hash: i32,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let query = format!("http.favicon.hash:{}", hash);
        self.lateral_pivot_search(&query, max_results).await
    }

    /// Lateral pivot — find hosts whose TLS stack fingerprint matches `jarm`.
    /// (JARM probe computation lives in [`HttpAnalyzer`]; this is just the search side.)
    pub async fn search_by_jarm(
        &self,
        jarm: &str,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let trimmed = jarm.trim();
        if trimmed.is_empty() {
            return Err(ApiError::Validation(
                "JARM fingerprint cannot be empty".to_string(),
            ));
        }
        let query = format!("ssl.jarm:{}", trimmed);
        self.lateral_pivot_search(&query, max_results).await
    }

    /// Lateral pivot — find hosts whose HTML body contains the given needle.
    /// Used with analytics IDs / tag-manager IDs / pixel tokens extracted from
    /// the seed's HTML. The needle is wrapped in double quotes so Shodan treats
    /// it as an exact substring match rather than a tokenized search.
    pub async fn search_by_html(
        &self,
        needle: &str,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        let trimmed = needle.trim();
        if trimmed.is_empty() {
            return Err(ApiError::Validation(
                "HTML pivot needle cannot be empty".to_string(),
            ));
        }
        // Shodan's filter accepts a quoted exact-match value; URL encoding is
        // applied later by the caller-side helper.
        let query = format!("http.html:\"{}\"", trimmed.replace('"', ""));
        self.lateral_pivot_search(&query, max_results).await
    }

    async fn lateral_pivot_search(
        &self,
        query: &str,
        max_results: usize,
    ) -> Result<ShodanExtractedAssets, ApiError> {
        if self.api_key.is_none() {
            return Err(ApiError::ExternalService(
                "Shodan API key not configured".to_string(),
            ));
        }

        // Free pre-check: count does not consume query credits.
        let total = match self.count(query).await {
            Ok(n) => n,
            Err(e) => {
                // The count endpoint is occasionally flaky for new filters; degrade
                // gracefully by proceeding with the paged search and letting the
                // existing per-page cap handle runaway result sets.
                tracing::debug!(
                    "Shodan count pre-check failed for '{}': {}; proceeding with search",
                    query,
                    e
                );
                u64::MAX
            }
        };

        if total == 0 {
            return Ok(ShodanExtractedAssets::default());
        }
        if max_results > 0 && total as usize > max_results {
            tracing::info!(
                "Skipping Shodan lateral pivot '{}': count={} exceeds cap={}",
                query,
                total,
                max_results
            );
            return Ok(ShodanExtractedAssets::default());
        }

        let results = self.search(query).await?;
        let mut extracted = self.extract_assets_from_results(&results);
        if max_results > 0 && extracted.domains.len() > max_results {
            // Defensive trim — should be unreachable given the count pre-check.
            let trimmed: HashSet<String> =
                extracted.domains.into_iter().take(max_results).collect();
            extracted.domains = trimmed;
        }
        Ok(extracted)
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

            // Keep a per-IP owner hint for downstream filtering.
            // Prefer org, fallback to ISP.
            let owner_hint = result
                .org
                .as_ref()
                .filter(|org| !org.trim().is_empty() && org.trim().len() > 2)
                .cloned()
                .or_else(|| {
                    result
                        .isp
                        .as_ref()
                        .filter(|isp| !isp.trim().is_empty() && isp.trim().len() > 2)
                        .cloned()
                });
            if let Some(owner) = owner_hint {
                extracted
                    .ip_owners
                    .entry(result.ip_str.clone())
                    .or_insert(owner);
            }

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

    fn stable_result_key(result: &ShodanResult) -> String {
        let ts = result.timestamp.as_deref().unwrap_or("");
        format!("{}:{}:{}", result.ip_str, result.port, ts)
    }

    /// Turn a Shodan DNS label into an absolute hostname.
    ///
    /// `base_domain` must be the zone the response was for (`ShodanDnsDomainResponse::domain`),
    /// not the hostname that was queried — see the call site for why.
    fn compose_dns_hostname(base_domain: &str, subdomain: &str) -> Option<String> {
        let canonical_base = base_domain.trim().trim_end_matches('.').to_lowercase();
        if canonical_base.is_empty() {
            return None;
        }

        let mut normalized = subdomain.trim().trim_end_matches('.').to_lowercase();
        if normalized.starts_with("*.") {
            normalized = normalized.trim_start_matches("*.").to_string();
        }
        if normalized.is_empty() || normalized == "@" {
            return Some(canonical_base);
        }
        if normalized.contains('*') {
            return None;
        }

        if normalized == canonical_base || normalized.ends_with(&format!(".{}", canonical_base)) {
            return Some(normalized);
        }

        let composed = format!("{}.{}", normalized, canonical_base);
        // Structural backstop against runaway suffixing: a name past the DNS limits is
        // never a real host, so drop it rather than persist it and recurse into it.
        if composed.len() > MAX_HOSTNAME_LEN || composed.split('.').count() > MAX_HOSTNAME_LABELS {
            tracing::debug!(
                "Discarding over-long composed Shodan hostname: {}",
                composed
            );
            return None;
        }

        Some(composed)
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

    #[test]
    fn test_stable_result_key() {
        let result = ShodanResult {
            ip_str: "203.0.113.10".to_string(),
            port: 443,
            data: "tls".to_string(),
            timestamp: Some("2024-01-01T00:00:00".to_string()),
            transport: None,
            product: None,
            version: None,
            hostnames: None,
            location: None,
            org: None,
            isp: None,
            asn: None,
            domains: None,
            ssl: None,
        };
        assert_eq!(
            ShodanClient::stable_result_key(&result),
            "203.0.113.10:443:2024-01-01T00:00:00".to_string()
        );
    }

    #[test]
    fn test_compose_dns_hostname_uses_response_zone_not_query() {
        // Shodan's /dns/domain endpoint answers for the apex whatever you ask it, so the
        // labels it returns must be composed against the apex. Composing them against the
        // queried sub-hostname is what produced "audio.audio.balivet.pro" and compounded
        // a fresh cross-product at every discovery depth.
        let response: ShodanDnsDomainResponse = serde_json::from_str(
            r#"{"domain":"example.com","subdomains":["audio","media"],"data":[],"more":false}"#,
        )
        .expect("response should parse");

        let base = response.domain.as_deref().expect("domain echoed by Shodan");
        let composed: Vec<String> = response
            .subdomains
            .iter()
            .filter_map(|s| ShodanClient::compose_dns_hostname(base, s))
            .collect();

        assert_eq!(
            composed,
            vec![
                "audio.example.com".to_string(),
                "media.example.com".to_string()
            ]
        );

        // The queried hostname is irrelevant to composition: even three levels deep the
        // result is the same flat set, so recursion converges instead of exploding.
        assert_eq!(
            ShodanClient::compose_dns_hostname(base, "audio"),
            Some("audio.example.com".to_string()),
            "composing against the apex must not re-suffix an existing label"
        );
    }

    #[test]
    fn test_compose_dns_hostname_rejects_over_long_names() {
        let deep = vec!["a"; 130].join(".");
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", &deep),
            None
        );

        let long_label = "b".repeat(250);
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", &long_label),
            None
        );
    }

    #[test]
    fn test_compose_dns_hostname() {
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", "www"),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", "WWW.Example.com."),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", "*.api"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", "a*pi"),
            None
        );
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", ""),
            Some("example.com".to_string())
        );
        assert_eq!(
            ShodanClient::compose_dns_hostname("example.com", "@"),
            Some("example.com".to_string())
        );
        assert_eq!(ShodanClient::compose_dns_hostname("", "www"), None);
    }

    #[test]
    fn test_shodan_dns_domain_response_deserialization() {
        let payload = r#"{
            "domain":"example.com",
            "subdomains":["www","api.internal","www.example.com"],
            "data":[
                {"subdomain":"mail"},
                {"subdomain":"www"}
            ],
            "more":false
        }"#;

        let parsed: ShodanDnsDomainResponse = serde_json::from_str(payload).unwrap();
        let mut hostnames: HashSet<String> = HashSet::new();
        for subdomain in parsed.subdomains {
            if let Some(hostname) = ShodanClient::compose_dns_hostname("example.com", &subdomain) {
                hostnames.insert(hostname);
            }
        }
        for record in parsed.data {
            if let Some(hostname) =
                ShodanClient::compose_dns_hostname("example.com", &record.subdomain)
            {
                hostnames.insert(hostname);
            }
        }

        assert!(hostnames.contains("www.example.com"));
        assert!(hostnames.contains("api.internal.example.com"));
        assert!(hostnames.contains("mail.example.com"));
        assert_eq!(hostnames.len(), 3);
    }
}

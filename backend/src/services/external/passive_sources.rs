//! Passive OSINT source registry.
//!
//! Subdomain enumeration is only as good as the number of *independent* corpora
//! you ask. `subfinder`, `amass` and `bbot` all win the same way: they fan out
//! across dozens of aggregators concurrently and union the answers, because no
//! single corpus sees the whole zone. Certificate transparency misses names that
//! never got a certificate; passive DNS misses names nobody ever resolved from a
//! monitored resolver; scan data misses anything that was never listening.
//!
//! This module holds every source that is *just an HTTP call returning
//! hostnames*. Sources with real client state — Shodan, VirusTotal, CertSpotter,
//! crt.sh — keep their own modules and are folded into the same fan-out by
//! [`super::manager::ExternalServicesManager`].
//!
//! Every source is annotated with the credential it needs. Sources needing none
//! run always; the rest report `skipped` rather than failing, so a deployment
//! with no API keys at all still gets eight independent corpora instead of one.

use crate::error::ApiError;
use crate::models::SourceType;
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// Credentials for the keyed passive sources.
///
/// Every field is optional: a source whose key is absent is skipped, never
/// failed. Discovery is expected to run usefully with an empty set.
#[derive(Debug, Clone, Default)]
pub struct OsintCredentials {
    pub securitytrails: Option<String>,
    pub censys_pat: Option<String>,
    pub censys_org_id: Option<String>,
    pub chaos: Option<String>,
    pub leakix: Option<String>,
    pub fullhunt: Option<String>,
    pub binaryedge: Option<String>,
    pub netlas: Option<String>,
    pub urlscan: Option<String>,
    pub otx: Option<String>,
}

/// Why a source did not run, or how it finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceStatus {
    Queried,
    Skipped,
    Failed,
}

impl SourceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceStatus::Queried => "queried",
            SourceStatus::Skipped => "skipped",
            SourceStatus::Failed => "failed",
        }
    }
}

/// What one source returned.
#[derive(Debug, Clone)]
pub struct PassiveSourceOutcome {
    pub source: SourceType,
    pub status: SourceStatus,
    pub message: Option<String>,
    pub hostnames: Vec<String>,
}

impl PassiveSourceOutcome {
    fn skipped(source: SourceType, reason: &str) -> Self {
        Self {
            source,
            status: SourceStatus::Skipped,
            message: Some(reason.to_string()),
            hostnames: Vec::new(),
        }
    }
}

/// Shared state handed to every source: one HTTP client, the credentials, and
/// the per-source result cap.
pub struct PassiveContext {
    client: reqwest::Client,
    credentials: OsintCredentials,
    /// Hard ceiling on hostnames accepted from a single source. A misbehaving
    /// aggregator that returns the whole internet must not be able to blow up a
    /// discovery run's asset budget on its own.
    pub max_results_per_source: usize,
    /// Per-source wall-clock budget. A slow source must not hold up the union.
    pub per_source_timeout: Duration,
}

impl PassiveContext {
    pub fn new(
        credentials: OsintCredentials,
        max_results_per_source: usize,
        per_source_timeout: Duration,
        user_agent: &str,
    ) -> Result<Self, ApiError> {
        let client = reqwest::Client::builder()
            .timeout(per_source_timeout)
            .user_agent(user_agent)
            // Aggregators answer with large JSON bodies; keeping connections warm
            // across the fan-out measurably cuts total enumeration time.
            .pool_max_idle_per_host(4)
            .build()?;

        Ok(Self::with_client(
            client,
            credentials,
            max_results_per_source,
            per_source_timeout,
        ))
    }

    /// Build a context around an existing client.
    ///
    /// Enumeration runs once per domain, and a discovery run walks many
    /// domains. Building a fresh client each time would throw away the
    /// connection pool between them — every source would pay a new TLS
    /// handshake on every domain. `reqwest::Client` is an `Arc` internally, so
    /// cloning one shares its pool.
    ///
    /// The per-source deadline is enforced by [`run_source`] regardless of the
    /// client's own timeout, so a client built with a stale timeout is still
    /// bounded correctly.
    pub fn with_client(
        client: reqwest::Client,
        credentials: OsintCredentials,
        max_results_per_source: usize,
        per_source_timeout: Duration,
    ) -> Self {
        Self {
            client,
            credentials,
            max_results_per_source,
            per_source_timeout,
        }
    }

    pub fn credentials(&self) -> &OsintCredentials {
        &self.credentials
    }

    /// GET returning the body as text, with the status surfaced as an error so
    /// a 401/429 is reported as a source failure rather than as "no results".
    async fn get_text(&self, url: &str, headers: &[(&str, &str)]) -> Result<String, ApiError> {
        let mut request = self.client.get(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError::ExternalService(format!(
                "{} returned HTTP {}",
                url, status
            )));
        }
        Ok(response.text().await?)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<T, ApiError> {
        let body = self.get_text(url, headers).await?;
        serde_json::from_str(&body).map_err(|e| {
            ApiError::ExternalService(format!("{} returned unparseable JSON: {}", url, e))
        })
    }

    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: serde_json::Value,
    ) -> Result<T, ApiError> {
        let mut request = self.client.post(url).json(&body);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError::ExternalService(format!(
                "{} returned HTTP {}",
                url, status
            )));
        }
        let text = response.text().await?;
        serde_json::from_str(&text).map_err(|e| {
            ApiError::ExternalService(format!("{} returned unparseable JSON: {}", url, e))
        })
    }
}

/// One passive OSINT corpus.
#[async_trait]
pub trait PassiveSource: Send + Sync {
    fn source_type(&self) -> SourceType;

    /// The credential this source needs, if any. `None` means it always runs.
    fn required_credential(&self) -> Option<&'static str> {
        None
    }

    /// Whether the credentials at hand are sufficient to run this source.
    fn is_available(&self, _credentials: &OsintCredentials) -> bool {
        true
    }

    /// Return every hostname this corpus associates with `domain`.
    ///
    /// Implementations return raw strings; normalisation, scoping to the base
    /// domain and deduplication all happen once, centrally, in the manager.
    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError>;
}

/// Run one source under its timeout, converting every failure mode into an
/// outcome rather than an error — one dead aggregator must never abort the run.
pub async fn run_source(
    source: &dyn PassiveSource,
    ctx: &PassiveContext,
    domain: &str,
) -> PassiveSourceOutcome {
    let source_type = source.source_type();

    if !source.is_available(ctx.credentials()) {
        let reason = match source.required_credential() {
            Some(cred) => format!("{} not configured", cred),
            None => "source unavailable".to_string(),
        };
        return PassiveSourceOutcome::skipped(source_type, &reason);
    }

    match tokio::time::timeout(ctx.per_source_timeout, source.enumerate(ctx, domain)).await {
        Ok(Ok(mut hostnames)) => {
            hostnames.truncate(ctx.max_results_per_source);
            PassiveSourceOutcome {
                source: source_type,
                status: SourceStatus::Queried,
                message: None,
                hostnames,
            }
        }
        Ok(Err(e)) => PassiveSourceOutcome {
            source: source_type,
            status: SourceStatus::Failed,
            message: Some(e.to_string()),
            hostnames: Vec::new(),
        },
        Err(_) => PassiveSourceOutcome {
            source: source_type,
            status: SourceStatus::Failed,
            message: Some(format!(
                "timed out after {}s",
                ctx.per_source_timeout.as_secs()
            )),
            hostnames: Vec::new(),
        },
    }
}

/// Every passive source in this module, keyed or not.
///
/// Order is irrelevant — the manager runs them concurrently — but it is kept
/// free-first so a log of skipped sources reads sensibly.
pub fn default_sources() -> Vec<Arc<dyn PassiveSource>> {
    vec![
        // No credential required.
        Arc::new(AlienVaultOtx),
        Arc::new(HackerTarget),
        Arc::new(RapidDns),
        Arc::new(AnubisDb),
        Arc::new(UrlScan),
        Arc::new(WaybackArchive),
        Arc::new(Columbus),
        Arc::new(Digitorus),
        // Credential required.
        Arc::new(SecurityTrails),
        Arc::new(Censys),
        Arc::new(Chaos),
        Arc::new(LeakIx),
        Arc::new(FullHunt),
        Arc::new(BinaryEdge),
        Arc::new(Netlas),
    ]
}

// ============================================================================
// Shared extraction helpers
// ============================================================================

/// Pull every hostname under `domain` out of arbitrary text.
///
/// Used for the sources that return HTML or a URL list rather than JSON. The
/// pattern is anchored on the base domain so a page full of unrelated links
/// cannot inject noise.
fn extract_hostnames_from_text(text: &str, domain: &str) -> Vec<String> {
    let escaped = regex::escape(domain);
    // A hostname is a run of labels ending in the base domain. The leading
    // boundary keeps `notexample.com` from matching a search for `example.com`.
    let pattern = format!(
        r"(?i)(?:^|[^A-Za-z0-9_.-])((?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{{0,61}}[A-Za-z0-9_])?\.)+{})",
        escaped
    );
    let Ok(regex) = Regex::new(&pattern) else {
        return Vec::new();
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for capture in regex.captures_iter(text) {
        if let Some(matched) = capture.get(1) {
            let hostname = matched.as_str().trim_end_matches('.').to_lowercase();
            if seen.insert(hostname.clone()) {
                out.push(hostname);
            }
        }
    }
    out
}

/// Pull the host out of a URL string without a full URL parse.
///
/// Web archives return millions of URLs; `url::Url::parse` on each is a
/// measurable cost for a value we can take with a couple of splits.
fn host_from_url(raw: &str) -> Option<String> {
    let without_scheme = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // Strip userinfo and port.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host.trim_end_matches('.').to_lowercase())
    }
}

// ============================================================================
// Free sources — no credential required
// ============================================================================

/// AlienVault OTX passive DNS.
///
/// OTX records every hostname its sensors and community pulses ever resolved
/// for a domain, including names that were retired before any scanner saw them.
pub struct AlienVaultOtx;

#[derive(Debug, Deserialize)]
struct OtxResponse {
    #[serde(default)]
    passive_dns: Vec<OtxPassiveDnsEntry>,
}

#[derive(Debug, Deserialize)]
struct OtxPassiveDnsEntry {
    #[serde(default)]
    hostname: Option<String>,
}

#[async_trait]
impl PassiveSource for AlienVaultOtx {
    fn source_type(&self) -> SourceType {
        SourceType::Otx
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            urlencoding::encode(domain)
        );
        // The API key is optional here: OTX serves passive DNS anonymously and
        // simply raises the rate limit for authenticated callers.
        let headers: Vec<(&str, &str)> = match ctx.credentials().otx.as_deref() {
            Some(key) => vec![("X-OTX-API-KEY", key)],
            None => Vec::new(),
        };

        let response: OtxResponse = ctx.get_json(&url, &headers).await?;
        Ok(response
            .passive_dns
            .into_iter()
            .filter_map(|entry| entry.hostname)
            .collect())
    }
}

/// HackerTarget's `hostsearch` — a free, unauthenticated passive DNS view.
///
/// Returns `hostname,ip` CSV. The IP half is discarded here: the discovery
/// service resolves names itself so it records who resolved what, and when.
pub struct HackerTarget;

#[async_trait]
impl PassiveSource for HackerTarget {
    fn source_type(&self) -> SourceType {
        SourceType::HackerTarget
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://api.hackertarget.com/hostsearch/?q={}",
            urlencoding::encode(domain)
        );
        let body = ctx.get_text(&url, &[]).await?;

        // The free tier answers a quota breach with a 200 and a prose body.
        if body.contains("API count exceeded") || body.contains("error check your search") {
            return Err(ApiError::RateLimit(
                "HackerTarget free-tier quota exhausted".to_string(),
            ));
        }

        Ok(body
            .lines()
            .filter_map(|line| line.split(',').next())
            .map(|host| host.trim().to_lowercase())
            .filter(|host| !host.is_empty())
            .collect())
    }
}

/// RapidDNS scraped subdomain index.
///
/// HTML only — there is no API — so the hostnames are extracted from the page
/// body. Paging is bounded because the site paginates in 100-row chunks and a
/// large zone would otherwise cost dozens of requests.
pub struct RapidDns;

const RAPIDDNS_MAX_PAGES: u32 = 5;

#[async_trait]
impl PassiveSource for RapidDns {
    fn source_type(&self) -> SourceType {
        SourceType::RapidDns
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let mut hostnames: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for page in 1..=RAPIDDNS_MAX_PAGES {
            let url = format!(
                "https://rapiddns.io/subdomain/{}?page={}&full=1",
                urlencoding::encode(domain),
                page
            );
            let body = match ctx.get_text(&url, &[]).await {
                Ok(body) => body,
                // A failure on page 2+ still leaves page 1's results usable.
                Err(e) if page > 1 => {
                    tracing::debug!("RapidDNS page {} failed for {}: {}", page, domain, e);
                    break;
                }
                Err(e) => return Err(e),
            };

            let before = hostnames.len();
            for hostname in extract_hostnames_from_text(&body, domain) {
                if seen.insert(hostname.clone()) {
                    hostnames.push(hostname);
                }
            }

            // No new names on this page means the index is exhausted.
            if hostnames.len() == before || hostnames.len() >= ctx.max_results_per_source {
                break;
            }
        }

        Ok(hostnames)
    }
}

/// AnubisDB (jonluca's Anubis) — a community-curated subdomain index.
pub struct AnubisDb;

#[async_trait]
impl PassiveSource for AnubisDb {
    fn source_type(&self) -> SourceType {
        SourceType::AnubisDb
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://jldc.me/anubis/subdomains/{}",
            urlencoding::encode(domain)
        );
        let hostnames: Vec<String> = ctx.get_json(&url, &[]).await?;
        Ok(hostnames)
    }
}

/// urlscan.io search over submitted scans.
///
/// Works without a key at a lower rate limit, which is why it is in the free
/// group; supplying `urlscan_api_key` simply raises the ceiling.
pub struct UrlScan;

#[derive(Debug, Deserialize)]
struct UrlScanResponse {
    #[serde(default)]
    results: Vec<UrlScanResult>,
}

#[derive(Debug, Deserialize)]
struct UrlScanResult {
    #[serde(default)]
    task: Option<UrlScanTarget>,
    #[serde(default)]
    page: Option<UrlScanTarget>,
}

#[derive(Debug, Deserialize)]
struct UrlScanTarget {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[async_trait]
impl PassiveSource for UrlScan {
    fn source_type(&self) -> SourceType {
        SourceType::UrlScan
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://urlscan.io/api/v1/search/?q=domain:{}&size=100",
            urlencoding::encode(domain)
        );
        let headers: Vec<(&str, &str)> = match ctx.credentials().urlscan.as_deref() {
            Some(key) => vec![("API-Key", key)],
            None => Vec::new(),
        };

        let response: UrlScanResponse = ctx.get_json(&url, &headers).await?;
        let mut hostnames = Vec::new();
        for result in response.results {
            for target in [result.task, result.page].into_iter().flatten() {
                if let Some(domain) = target.domain {
                    hostnames.push(domain);
                }
                // The scanned URL frequently names a host the `domain` field
                // does not, because urlscan reports the *final* landing domain.
                if let Some(host) = target.url.as_deref().and_then(host_from_url) {
                    hostnames.push(host);
                }
            }
        }
        Ok(hostnames)
    }
}

/// Wayback Machine CDX index.
///
/// Archives are the only corpus that reliably surfaces *decommissioned* hosts —
/// exactly the ones that still have a dangling DNS record pointing at a
/// reclaimable cloud tenant. Confidence is scored low to match: a name in the
/// archive proves it once existed, not that it exists now.
pub struct WaybackArchive;

#[async_trait]
impl PassiveSource for WaybackArchive {
    fn source_type(&self) -> SourceType {
        SourceType::Wayback
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        // `collapse=urlkey` deduplicates server-side; `limit` caps a response
        // that is otherwise unbounded for a large site.
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey&limit={}",
            urlencoding::encode(domain),
            // Ask for more rows than we keep: many rows collapse to the same host.
            ctx.max_results_per_source.saturating_mul(20).min(100_000)
        );
        let body = ctx.get_text(&url, &[]).await?;

        let mut seen: HashSet<String> = HashSet::new();
        let mut hostnames = Vec::new();
        for line in body.lines() {
            let Some(host) = host_from_url(line.trim()) else {
                continue;
            };
            if seen.insert(host.clone()) {
                hostnames.push(host);
            }
        }
        Ok(hostnames)
    }
}

/// Columbus Project (elmasy) subdomain index.
///
/// Returns bare labels rather than FQDNs — `["www", "mail"]` — so the base
/// domain is appended here.
pub struct Columbus;

#[async_trait]
impl PassiveSource for Columbus {
    fn source_type(&self) -> SourceType {
        SourceType::Columbus
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://columbus.elmasy.com/api/lookup/{}",
            urlencoding::encode(domain)
        );
        let labels: Vec<String> = ctx
            .get_json(&url, &[("accept", "application/json")])
            .await?;

        Ok(labels
            .into_iter()
            .map(|label| {
                let label = label.trim().trim_end_matches('.');
                if label.is_empty() {
                    domain.to_string()
                } else {
                    format!("{}.{}", label, domain)
                }
            })
            .collect())
    }
}

/// Digitorus certificatedetails.com — a certificate transparency front end.
pub struct Digitorus;

#[async_trait]
impl PassiveSource for Digitorus {
    fn source_type(&self) -> SourceType {
        SourceType::Digitorus
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let url = format!(
            "https://certificatedetails.com/{}",
            urlencoding::encode(domain)
        );
        let body = ctx.get_text(&url, &[]).await?;
        Ok(extract_hostnames_from_text(&body, domain))
    }
}

// ============================================================================
// Keyed sources
// ============================================================================

/// SecurityTrails historical DNS.
///
/// Returns bare labels under `subdomains`, so the base domain is appended.
pub struct SecurityTrails;

#[derive(Debug, Deserialize)]
struct SecurityTrailsResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[async_trait]
impl PassiveSource for SecurityTrails {
    fn source_type(&self) -> SourceType {
        SourceType::SecurityTrails
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("securitytrails_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.securitytrails.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let key = ctx
            .credentials()
            .securitytrails
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("SecurityTrails key missing".to_string()))?;

        let url = format!(
            "https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false&include_inactive=true",
            urlencoding::encode(domain)
        );
        let response: SecurityTrailsResponse = ctx.get_json(&url, &[("APIKEY", key)]).await?;

        Ok(response
            .subdomains
            .into_iter()
            .filter(|label| !label.trim().is_empty())
            .map(|label| format!("{}.{}", label.trim().trim_end_matches('.'), domain))
            .collect())
    }
}

/// Censys Platform global search over certificate names.
pub struct Censys;

#[derive(Debug, Deserialize)]
struct CensysResponse {
    #[serde(default)]
    result: Option<CensysResult>,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    #[serde(default)]
    hits: Vec<CensysHit>,
}

#[derive(Debug, Deserialize)]
struct CensysHit {
    #[serde(default)]
    certificate_v1: Option<CensysCertificate>,
}

#[derive(Debug, Deserialize)]
struct CensysCertificate {
    #[serde(default)]
    resource: Option<CensysResource>,
}

#[derive(Debug, Deserialize)]
struct CensysResource {
    #[serde(default)]
    names: Vec<String>,
}

#[async_trait]
impl PassiveSource for Censys {
    fn source_type(&self) -> SourceType {
        SourceType::Censys
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("censys_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.censys_pat.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let pat = ctx
            .credentials()
            .censys_pat
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("Censys token missing".to_string()))?;
        let authorization = format!("Bearer {}", pat);

        let mut headers: Vec<(&str, &str)> = vec![
            ("Authorization", authorization.as_str()),
            ("Content-Type", "application/json"),
        ];
        if let Some(org_id) = ctx.credentials().censys_org_id.as_deref() {
            headers.push(("X-Organization-ID", org_id));
        }

        let body = serde_json::json!({
            "query": format!("cert.names: {}", domain),
            "page_size": 100,
        });

        let response: CensysResponse = ctx
            .post_json(
                "https://api.platform.censys.io/v3/global/search/query",
                &headers,
                body,
            )
            .await?;

        Ok(response
            .result
            .into_iter()
            .flat_map(|result| result.hits)
            .filter_map(|hit| hit.certificate_v1)
            .filter_map(|certificate| certificate.resource)
            .flat_map(|resource| resource.names)
            .collect())
    }
}

/// ProjectDiscovery Chaos — the precomputed bug-bounty subdomain dataset.
pub struct Chaos;

#[derive(Debug, Deserialize)]
struct ChaosResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[async_trait]
impl PassiveSource for Chaos {
    fn source_type(&self) -> SourceType {
        SourceType::Chaos
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("chaos_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.chaos.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let key = ctx
            .credentials()
            .chaos
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("Chaos key missing".to_string()))?;

        let url = format!(
            "https://dns.projectdiscovery.io/dns/{}/subdomains",
            urlencoding::encode(domain)
        );
        let response: ChaosResponse = ctx.get_json(&url, &[("Authorization", key)]).await?;

        Ok(response
            .subdomains
            .into_iter()
            .filter(|label| !label.trim().is_empty())
            .map(|label| {
                let label = label.trim().trim_end_matches('.');
                // Chaos stores bare labels, but wildcard entries arrive as `*`.
                if label == "*" {
                    domain.to_string()
                } else {
                    format!("{}.{}", label, domain)
                }
            })
            .collect())
    }
}

/// LeakIX subdomain index. Answers unauthenticated at a reduced rate, so the
/// key is optional — but supplying one is what makes it worth querying.
pub struct LeakIx;

#[derive(Debug, Deserialize)]
struct LeakIxEntry {
    #[serde(default)]
    subdomain: Option<String>,
}

#[async_trait]
impl PassiveSource for LeakIx {
    fn source_type(&self) -> SourceType {
        SourceType::LeakIx
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("leakix_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.leakix.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let key = ctx
            .credentials()
            .leakix
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("LeakIX key missing".to_string()))?;

        let url = format!(
            "https://leakix.net/api/subdomains/{}",
            urlencoding::encode(domain)
        );
        let entries: Vec<LeakIxEntry> = ctx
            .get_json(&url, &[("accept", "application/json"), ("api-key", key)])
            .await?;

        Ok(entries.into_iter().filter_map(|e| e.subdomain).collect())
    }
}

/// FullHunt attack-surface dataset.
pub struct FullHunt;

#[derive(Debug, Deserialize)]
struct FullHuntResponse {
    #[serde(default)]
    hosts: Vec<String>,
}

#[async_trait]
impl PassiveSource for FullHunt {
    fn source_type(&self) -> SourceType {
        SourceType::FullHunt
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("fullhunt_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.fullhunt.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let key = ctx
            .credentials()
            .fullhunt
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("FullHunt key missing".to_string()))?;

        let url = format!(
            "https://fullhunt.io/api/v1/domain/{}/subdomains",
            urlencoding::encode(domain)
        );
        let response: FullHuntResponse = ctx.get_json(&url, &[("X-API-KEY", key)]).await?;
        Ok(response.hosts)
    }
}

/// BinaryEdge internet-scan dataset.
pub struct BinaryEdge;

#[derive(Debug, Deserialize)]
struct BinaryEdgeResponse {
    #[serde(default)]
    events: Vec<String>,
}

#[async_trait]
impl PassiveSource for BinaryEdge {
    fn source_type(&self) -> SourceType {
        SourceType::BinaryEdge
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("binaryedge_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.binaryedge.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let key = ctx
            .credentials()
            .binaryedge
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("BinaryEdge key missing".to_string()))?;

        let url = format!(
            "https://api.binaryedge.io/v2/query/domains/subdomain/{}",
            urlencoding::encode(domain)
        );
        let response: BinaryEdgeResponse = ctx.get_json(&url, &[("X-Key", key)]).await?;
        Ok(response.events)
    }
}

/// Netlas DNS dataset.
pub struct Netlas;

#[derive(Debug, Deserialize)]
struct NetlasItem {
    #[serde(default)]
    data: Option<NetlasData>,
}

#[derive(Debug, Deserialize)]
struct NetlasData {
    #[serde(default)]
    domain: Option<String>,
}

#[async_trait]
impl PassiveSource for Netlas {
    fn source_type(&self) -> SourceType {
        SourceType::Netlas
    }

    fn required_credential(&self) -> Option<&'static str> {
        Some("netlas_api_key")
    }

    fn is_available(&self, credentials: &OsintCredentials) -> bool {
        credentials.netlas.is_some()
    }

    async fn enumerate(&self, ctx: &PassiveContext, domain: &str) -> Result<Vec<String>, ApiError> {
        let key = ctx
            .credentials()
            .netlas
            .as_deref()
            .ok_or_else(|| ApiError::Configuration("Netlas key missing".to_string()))?;

        let body = serde_json::json!({
            "q": format!("domain:(domain:*.{0} OR domain:{0})", domain),
            "fields": ["domain"],
            "source_type": "include",
            // Netlas caps a download at 1000 rows per request; taking the first
            // page is enough for an EASM inventory and keeps the cost fixed.
            "size": 1000,
        });

        let items: Vec<NetlasItem> = ctx
            .post_json(
                "https://app.netlas.io/api/domains/download/",
                &[("X-API-Key", key), ("Content-Type", "application/json")],
                body,
            )
            .await?;

        Ok(items
            .into_iter()
            .filter_map(|item| item.data)
            .filter_map(|data| data.domain)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hostnames_is_anchored_on_the_base_domain() {
        let html = r#"
            <a href="https://mail.example.com/inbox">mail</a>
            <td>dev.api.example.com</td>
            notexample.com should not match
            <a href="https://example.com.evil.net/">phish</a>
        "#;
        let found = extract_hostnames_from_text(html, "example.com");
        assert!(found.contains(&"mail.example.com".to_string()));
        assert!(found.contains(&"dev.api.example.com".to_string()));
        assert!(!found.contains(&"notexample.com".to_string()));
        // `example.com.evil.net` does not *end* in example.com, so the anchored
        // pattern must not report it as ours.
        assert!(!found.iter().any(|h| h.ends_with("evil.net")));
    }

    #[test]
    fn extract_hostnames_deduplicates_case_insensitively() {
        let text = "WWW.Example.COM www.example.com www.example.com";
        let found = extract_hostnames_from_text(text, "example.com");
        assert_eq!(found, vec!["www.example.com".to_string()]);
    }

    #[test]
    fn host_from_url_handles_ports_userinfo_and_paths() {
        assert_eq!(
            host_from_url("https://user:pw@Www.Example.com:8443/a/b?c=d#e"),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            host_from_url("http://api.example.com/"),
            Some("api.example.com".to_string())
        );
        // CDX rows are bare host/path pairs with no scheme.
        assert_eq!(
            host_from_url("cdn.example.com/assets/app.js"),
            Some("cdn.example.com".to_string())
        );
        assert_eq!(host_from_url(""), None);
    }

    #[test]
    fn keyed_sources_report_the_credential_they_need() {
        let empty = OsintCredentials::default();
        for source in default_sources() {
            match source.required_credential() {
                Some(name) => {
                    assert!(
                        !source.is_available(&empty),
                        "{} claims to need {} but runs without it",
                        source.source_type(),
                        name
                    );
                }
                None => assert!(
                    source.is_available(&empty),
                    "{} needs no credential but reports unavailable",
                    source.source_type()
                ),
            }
        }
    }

    #[tokio::test]
    async fn an_unavailable_source_is_skipped_not_failed() {
        let ctx = PassiveContext::new(
            OsintCredentials::default(),
            100,
            Duration::from_secs(1),
            "EASM-test",
        )
        .expect("context builds");

        let outcome = run_source(&SecurityTrails, &ctx, "example.com").await;
        assert_eq!(outcome.status, SourceStatus::Skipped);
        assert!(outcome.hostnames.is_empty());
        assert!(outcome
            .message
            .unwrap_or_default()
            .contains("securitytrails_api_key"));
    }
}

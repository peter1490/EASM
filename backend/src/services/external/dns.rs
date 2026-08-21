use crate::error::ApiError;
use futures::future::join_all;
use governor::{
    clock::DefaultClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use trust_dns_resolver::proto::rr::{RData, Record, RecordType};
use trust_dns_resolver::TokioAsyncResolver;

/// DNS resolution configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Timeout for individual DNS queries
    pub query_timeout: Duration,
    /// Maximum concurrent DNS queries
    pub max_concurrent: usize,
    /// Rate limit for DNS queries (queries per second)
    pub rate_limit: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(5),
            max_concurrent: 50,
            rate_limit: 100,
        }
    }
}

/// DNS resolution result
#[derive(Debug, Clone)]
pub struct DnsResult {
    pub hostname: String,
    pub ips: Vec<IpAddr>,
    pub error: Option<String>,
}

/// Reverse DNS lookup result
#[derive(Debug, Clone)]
pub struct ReverseDnsResult {
    pub ip: IpAddr,
    pub hostnames: Vec<String>,
    pub error: Option<String>,
}

/// Parsed SPF directives that name another DNS hostname (and thus expand the
/// attack surface). Mechanisms that do not name a hostname (`ip4:`, `ip6:`,
/// `all`, qualifiers) are deliberately discarded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpfDirectives {
    /// `include:domain` and `redirect=domain` — the other SPF policies this
    /// record delegates to. Highest-yield SPF pivot: routinely names sibling
    /// apex domains used for transactional mail.
    pub includes: Vec<String>,
    /// `a:domain` / `mx:domain` — explicit hostnames that authorize mail.
    pub hosts: Vec<String>,
    /// `exists:domain` — DNS-time existence check; sometimes names internal hosts.
    pub exists: Vec<String>,
}

/// Parse SPF mechanisms from a single TXT record that begins with `v=spf1`.
/// Returns an empty `SpfDirectives` for non-SPF records.
pub fn parse_spf(record: &str) -> SpfDirectives {
    let trimmed = record.trim();
    // Some resolvers concatenate `"v=spf1 ..." "..."` into raw quoted strings —
    // strip stray quotes defensively.
    let cleaned: String = trimmed.chars().filter(|c| *c != '"').collect();
    if !cleaned.to_ascii_lowercase().starts_with("v=spf1") {
        return SpfDirectives::default();
    }
    let mut out = SpfDirectives::default();
    for raw_token in cleaned.split_whitespace().skip(1) {
        // Strip leading qualifier (+, -, ~, ?) so "+include:foo" matches.
        let token = raw_token.trim_start_matches(['+', '-', '~', '?']);
        let lower = token.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("include:") {
            if !value.is_empty() {
                out.includes.push(value.to_string());
            }
        } else if let Some(value) = lower.strip_prefix("redirect=") {
            if !value.is_empty() {
                out.includes.push(value.to_string());
            }
        } else if let Some(value) = lower.strip_prefix("a:") {
            if !value.is_empty() {
                out.hosts.push(value.to_string());
            }
        } else if let Some(value) = lower.strip_prefix("mx:") {
            if !value.is_empty() {
                out.hosts.push(value.to_string());
            }
        } else if let Some(value) = lower.strip_prefix("exists:") {
            if !value.is_empty() {
                out.exists.push(value.to_string());
            }
        }
    }
    out.includes.sort();
    out.includes.dedup();
    out.hosts.sort();
    out.hosts.dedup();
    out.exists.sort();
    out.exists.dedup();
    out
}

/// Parsed DMARC report mailboxes — the domain portions of `rua=mailto:` and
/// `ruf=mailto:` tags. These mailboxes are usually hosted on the org's own
/// monitoring infrastructure and frequently leak sibling domain names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DmarcReportDomains {
    pub aggregate: Vec<String>,
    pub forensic: Vec<String>,
}

/// Parse the `rua=` and `ruf=` tags from a DMARC TXT record.
pub fn parse_dmarc(record: &str) -> DmarcReportDomains {
    let cleaned: String = record.chars().filter(|c| *c != '"').collect();
    if !cleaned.to_ascii_lowercase().contains("v=dmarc1") {
        return DmarcReportDomains::default();
    }
    let mut out = DmarcReportDomains::default();
    for tag in cleaned.split(';') {
        let tag = tag.trim();
        let lower = tag.to_ascii_lowercase();
        let push_to: &mut Vec<String> = if let Some(rest) = lower.strip_prefix("rua=") {
            let _ = rest;
            &mut out.aggregate
        } else if let Some(rest) = lower.strip_prefix("ruf=") {
            let _ = rest;
            &mut out.forensic
        } else {
            continue;
        };
        // Use the original-case tag value to preserve mailbox capitalisation
        // before we lowercase the host below.
        let value = tag.splitn(2, '=').nth(1).unwrap_or("");
        for mailbox in value.split(',') {
            let cleaned = mailbox
                .trim()
                .trim_start_matches("mailto:")
                .trim_start_matches("MAILTO:");
            // Drop any size suffix (`!10m`).
            let cleaned = cleaned.split('!').next().unwrap_or("");
            if let Some(domain) = cleaned.split('@').nth(1) {
                let host = domain.trim().to_ascii_lowercase();
                if !host.is_empty() {
                    push_to.push(host);
                }
            }
        }
    }
    out.aggregate.sort();
    out.aggregate.dedup();
    out.forensic.sort();
    out.forensic.dedup();
    out
}

/// A SaaS tenancy proven by a DNS verification token.
///
/// To onboard a domain, most SaaS vendors make the customer publish a token in
/// a TXT record at the apex. Those records never expire on their own, so the
/// apex of a mature organisation is a near-complete inventory of the vendors it
/// has ever onboarded — including the ones nobody remembers procuring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaasTenancy {
    /// Vendor name, e.g. `Google Workspace`.
    pub vendor: &'static str,
    /// The token prefix that identified it.
    pub token_prefix: &'static str,
    /// The full record, kept as evidence.
    pub record: String,
    /// Hostname the record implies is worth adding to the inventory, when the
    /// vendor's tenancy is reachable at a predictable name.
    pub implied_hostname: Option<String>,
}

/// Verification-token prefixes and the vendor each identifies.
///
/// Prefix matching, not substring: a token is defined by how the record
/// *starts*, and matching anywhere in the string would let an unrelated SPF
/// record claim a vendor.
static SAAS_VERIFICATION_TOKENS: &[(&str, &str)] = &[
    (
        "google-site-verification=",
        "Google Workspace / Search Console",
    ),
    ("MS=", "Microsoft 365"),
    ("ms-domain-verification=", "Microsoft"),
    ("atlassian-domain-verification=", "Atlassian"),
    ("atlassian-sending-domain-verification=", "Atlassian"),
    ("adobe-idp-site-verification=", "Adobe"),
    ("adobe-sign-verification=", "Adobe Sign"),
    ("docusign=", "DocuSign"),
    ("dropbox-domain-verification=", "Dropbox"),
    ("facebook-domain-verification=", "Meta"),
    ("slack-domain-verification=", "Slack"),
    ("zoom-domain-verification=", "Zoom"),
    ("zoom_verify_", "Zoom"),
    ("stripe-verification=", "Stripe"),
    ("shopify-verification=", "Shopify"),
    ("apple-domain-verification=", "Apple Business"),
    ("citrix-verification-code=", "Citrix"),
    ("cisco-ci-domain-verification=", "Cisco"),
    ("miro-verification=", "Miro"),
    ("mongodb-site-verification=", "MongoDB Atlas"),
    ("openai-domain-verification=", "OpenAI"),
    ("asana-domain-verification=", "Asana"),
    ("notion-domain-verification=", "Notion"),
    ("canva-site-verification=", "Canva"),
    ("box-domain-verification=", "Box"),
    ("smartsheet-site-validation=", "Smartsheet"),
    ("workplace-domain-verification=", "Workplace"),
    ("logmein-verification-code=", "LogMeIn / GoTo"),
    ("mailru-verification:", "Mail.ru"),
    ("yandex-verification:", "Yandex"),
    ("globalsign-domain-verification=", "GlobalSign"),
    ("pardot", "Salesforce Pardot"),
    ("sendinblue-code:", "Brevo"),
    ("brevo-code:", "Brevo"),
    ("mailgun-verification=", "Mailgun"),
    ("postman-domain-verification=", "Postman"),
    ("segment-site-verification=", "Segment"),
    ("intercom-domain-verification=", "Intercom"),
    ("zendesk_verification=", "Zendesk"),
    ("freshdesk-verification=", "Freshworks"),
    ("statuspage-domain-verification=", "Atlassian Statuspage"),
    ("cloudhealth=", "VMware CloudHealth"),
    ("wrike-verification=", "Wrike"),
    ("webexdomainverification", "Cisco Webex"),
    ("_globalsign-domain-verification=", "GlobalSign"),
    ("have-i-been-pwned-verification=", "Have I Been Pwned"),
    ("onetrust-domain-verification=", "OneTrust"),
    ("knowbe4-site-verification=", "KnowBe4"),
    ("dynatrace-site-verification=", "Dynatrace"),
    ("detectify-verification=", "Detectify"),
    ("loaderio=", "loader.io"),
    ("status-page-domain-verification=", "Statuspage"),
    ("h1-domain-verification=", "HackerOne"),
    ("bugcrowd-verification=", "Bugcrowd"),
];

/// Hostnames a tenancy implies, keyed by vendor.
///
/// A Zendesk tenant is reachable at `support.<domain>` far more often than not,
/// and `autodiscover.<domain>` is a Microsoft 365 constant. These are *implied*
/// candidates, verified by resolution downstream like any other guess.
static SAAS_IMPLIED_HOSTNAMES: &[(&str, &str)] = &[
    ("Microsoft 365", "autodiscover"),
    ("Zendesk", "support"),
    ("Atlassian", "jira"),
    ("Atlassian Statuspage", "status"),
    ("Statuspage", "status"),
    ("Freshworks", "support"),
    ("Salesforce Pardot", "go"),
    ("Shopify", "shop"),
];

/// Identify the SaaS tenancies proven by a set of apex TXT records.
pub fn parse_saas_verifications(records: &[String], domain: &str) -> Vec<SaasTenancy> {
    let mut found: Vec<SaasTenancy> = Vec::new();

    for record in records {
        let trimmed = record.trim().trim_matches('"');
        let lowered = trimmed.to_lowercase();

        // SPF and DMARC are handled by their own parsers and would otherwise
        // match the loose prefixes below.
        if lowered.starts_with("v=spf1") || lowered.starts_with("v=dmarc1") {
            continue;
        }

        for (prefix, vendor) in SAAS_VERIFICATION_TOKENS {
            if !lowered.starts_with(&prefix.to_lowercase()) {
                continue;
            }
            // One record proves one tenancy; a vendor already seen is not
            // re-reported just because it published two tokens.
            if found.iter().any(|tenancy| tenancy.vendor == *vendor) {
                break;
            }

            let implied_hostname = SAAS_IMPLIED_HOSTNAMES
                .iter()
                .find(|(implied_vendor, _)| implied_vendor == vendor)
                .map(|(_, label)| format!("{}.{}", label, domain));

            found.push(SaasTenancy {
                vendor,
                token_prefix: prefix,
                record: trimmed.to_string(),
                implied_hostname,
            });
            break;
        }
    }

    found
}

/// Async DNS resolver with timeout handling and concurrency limits
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    config: DnsConfig,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl DnsResolver {
    /// Create a new DNS resolver with default configuration
    pub async fn new() -> Result<Self, ApiError> {
        Self::with_config(DnsConfig::default()).await
    }

    /// Create a new DNS resolver with custom configuration
    pub async fn with_config(config: DnsConfig) -> Result<Self, ApiError> {
        let (resolver_config, mut resolver_opts) =
            trust_dns_resolver::system_conf::read_system_conf().map_err(|e| {
                ApiError::ExternalService(format!("Failed to read system DNS configuration: {}", e))
            })?;
        resolver_opts.timeout = config.query_timeout;
        resolver_opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

        // Create rate limiter
        let quota = Quota::per_second(std::num::NonZeroU32::new(config.rate_limit).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Self {
            resolver,
            config,
            rate_limiter,
        })
    }

    /// Resolve a single hostname to IP addresses with timeout
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let hostname_owned = hostname.to_string();
        let hostname_for_error = hostname_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.lookup_ip(&hostname_owned).await.map_err(|e| {
                ApiError::ExternalService(format!(
                    "DNS resolution failed for {}: {}",
                    hostname_owned, e
                ))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("DNS query timeout for {}", hostname_for_error))
        })?;

        match result {
            Ok(response) => {
                let ips: Vec<IpAddr> = response.iter().collect();
                Ok(ips)
            }
            Err(e) => Err(e),
        }
    }

    /// Perform reverse DNS lookup for an IP address
    pub async fn reverse_lookup(&self, ip: &IpAddr) -> Result<Vec<String>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let ip_addr = *ip;
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.reverse_lookup(ip_addr).await.map_err(|e| {
                ApiError::ExternalService(format!(
                    "Reverse DNS lookup failed for {}: {}",
                    ip_addr, e
                ))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("Reverse DNS query timeout for {}", ip_addr))
        })?;

        match result {
            Ok(response) => {
                let hostnames: Vec<String> = response.iter().map(|name| name.to_string()).collect();
                Ok(hostnames)
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve multiple hostnames concurrently with configurable limits
    pub async fn resolve_hostnames_concurrent(&self, hostnames: Vec<String>) -> Vec<DnsResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrent));
        let resolver_clone = self.resolver.clone();
        let rate_limiter_clone = self.rate_limiter.clone();
        let query_timeout = self.config.query_timeout;

        let tasks: Vec<_> = hostnames
            .into_iter()
            .map(|hostname| {
                let semaphore = semaphore.clone();
                let resolver = resolver_clone.clone();
                let rate_limiter = rate_limiter_clone.clone();

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    // Apply rate limiting
                    rate_limiter.until_ready().await;

                    let result = timeout(query_timeout, async {
                        resolver.lookup_ip(&hostname).await.map_err(|e| {
                            ApiError::ExternalService(format!(
                                "DNS resolution failed for {}: {}",
                                hostname, e
                            ))
                        })
                    })
                    .await
                    .map_err(|_| {
                        ApiError::ExternalService(format!("DNS query timeout for {}", hostname))
                    });

                    match result {
                        Ok(Ok(response)) => {
                            let ips: Vec<IpAddr> = response.iter().collect();
                            DnsResult {
                                hostname: hostname.clone(),
                                ips,
                                error: None,
                            }
                        }
                        Ok(Err(e)) | Err(e) => DnsResult {
                            hostname: hostname.clone(),
                            ips: vec![],
                            error: Some(e.to_string()),
                        },
                    }
                })
            })
            .collect();

        let results = join_all(tasks).await;
        results.into_iter().filter_map(|r| r.ok()).collect()
    }

    /// Perform reverse DNS lookups for multiple IP addresses concurrently
    pub async fn reverse_lookup_concurrent(&self, ips: Vec<IpAddr>) -> Vec<ReverseDnsResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrent));
        let resolver_clone = self.resolver.clone();
        let rate_limiter_clone = self.rate_limiter.clone();
        let query_timeout = self.config.query_timeout;

        let tasks: Vec<_> = ips
            .into_iter()
            .map(|ip| {
                let semaphore = semaphore.clone();
                let resolver = resolver_clone.clone();
                let rate_limiter = rate_limiter_clone.clone();

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    // Apply rate limiting
                    rate_limiter.until_ready().await;

                    let result = timeout(query_timeout, async {
                        resolver.reverse_lookup(ip).await.map_err(|e| {
                            ApiError::ExternalService(format!(
                                "Reverse DNS lookup failed for {}: {}",
                                ip, e
                            ))
                        })
                    })
                    .await
                    .map_err(|_| {
                        ApiError::ExternalService(format!("Reverse DNS query timeout for {}", ip))
                    });

                    match result {
                        Ok(Ok(response)) => {
                            let hostnames: Vec<String> =
                                response.iter().map(|name| name.to_string()).collect();
                            ReverseDnsResult {
                                ip,
                                hostnames,
                                error: None,
                            }
                        }
                        Ok(Err(e)) | Err(e) => ReverseDnsResult {
                            ip,
                            hostnames: vec![],
                            error: Some(e.to_string()),
                        },
                    }
                })
            })
            .collect();

        let results = join_all(tasks).await;
        results.into_iter().filter_map(|r| r.ok()).collect()
    }

    /// Check if a hostname resolves to any IP address
    pub async fn hostname_exists(&self, hostname: &str) -> bool {
        match self.resolve_hostname(hostname).await {
            Ok(ips) => !ips.is_empty(),
            Err(_) => false,
        }
    }

    /// Get the configuration used by this resolver
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Lookup TXT records for a hostname
    pub async fn lookup_txt(&self, hostname: &str) -> Result<Vec<String>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let hostname_owned = hostname.to_string();
        let hostname_for_error = hostname_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.txt_lookup(&hostname_owned).await.map_err(|e| {
                ApiError::ExternalService(format!(
                    "TXT lookup failed for {}: {}",
                    hostname_owned, e
                ))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("TXT query timeout for {}", hostname_for_error))
        })?;

        match result {
            Ok(response) => {
                let records: Vec<String> = response
                    .iter()
                    .map(|txt| {
                        txt.txt_data()
                            .iter()
                            .map(|data| String::from_utf8_lossy(data).to_string())
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => Err(e),
        }
    }

    /// Lookup NS records for a domain
    pub async fn lookup_ns(&self, domain: &str) -> Result<Vec<String>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let domain_owned = format!("{}.", domain.trim_end_matches('.'));
        let domain_for_error = domain_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.ns_lookup(&domain_owned).await.map_err(|e| {
                ApiError::ExternalService(format!("NS lookup failed for {}: {}", domain_owned, e))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("NS query timeout for {}", domain_for_error))
        })?;

        match result {
            Ok(response) => {
                let nameservers: Vec<String> = response
                    .iter()
                    .map(|ns| ns.to_string().trim_end_matches('.').to_string())
                    .collect();
                Ok(nameservers)
            }
            Err(e) => Err(e),
        }
    }

    /// Lookup CAA records for a domain
    pub async fn lookup_caa(&self, domain: &str) -> Result<Vec<String>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let domain_owned = format!("{}.", domain.trim_end_matches('.'));
        let domain_for_error = domain_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            use trust_dns_resolver::proto::rr::RecordType;

            resolver
                .lookup(&domain_owned, RecordType::CAA)
                .await
                .map_err(|e| {
                    ApiError::ExternalService(format!(
                        "CAA lookup failed for {}: {}",
                        domain_owned, e
                    ))
                })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("CAA query timeout for {}", domain_for_error))
        })?;

        match result {
            Ok(response) => {
                let records: Vec<String> = response
                    .iter()
                    .filter_map(|record| {
                        // Try to extract CAA data from the record
                        // The format is: flags tag value
                        let rdata_str = format!("{:?}", record);
                        if rdata_str.contains("CAA") {
                            Some(rdata_str)
                        } else {
                            None
                        }
                    })
                    .collect();
                Ok(records)
            }
            Err(e) => Err(e),
        }
    }

    /// Lookup DMARC record at `_dmarc.{domain}` and return parsed report mailboxes.
    /// Returns an empty `DmarcReportDomains` when no DMARC record exists or the
    /// query fails — DMARC lookup failure is non-fatal for discovery.
    pub async fn lookup_dmarc(&self, domain: &str) -> Result<DmarcReportDomains, ApiError> {
        let name = format!("_dmarc.{}", domain.trim_end_matches('.'));
        let records = self.lookup_txt(&name).await?;
        let mut merged = DmarcReportDomains::default();
        for record in records {
            let parsed = parse_dmarc(&record);
            merged.aggregate.extend(parsed.aggregate);
            merged.forensic.extend(parsed.forensic);
        }
        merged.aggregate.sort();
        merged.aggregate.dedup();
        merged.forensic.sort();
        merged.forensic.dedup();
        Ok(merged)
    }

    /// Lookup SPF — the v=spf1 record in the domain's own TXT records — and
    /// return parsed mechanisms that name other hostnames.
    pub async fn lookup_spf(&self, domain: &str) -> Result<SpfDirectives, ApiError> {
        let records = self.lookup_txt(domain).await?;
        let mut merged = SpfDirectives::default();
        for record in records {
            let parsed = parse_spf(&record);
            merged.includes.extend(parsed.includes);
            merged.hosts.extend(parsed.hosts);
            merged.exists.extend(parsed.exists);
        }
        merged.includes.sort();
        merged.includes.dedup();
        merged.hosts.sort();
        merged.hosts.dedup();
        merged.exists.sort();
        merged.exists.dedup();
        Ok(merged)
    }

    /// Look up records of an arbitrary type, returning them unparsed.
    ///
    /// The typed helpers above cover the handful of record types discovery needs.
    /// A security scan needs the rest — SOA, SRV, DNSKEY, DS, TLSA, HTTPS — and
    /// enumerating a helper per type would be a hundred lines of the same code,
    /// so this hands the caller the records and lets it match on what it asked for.
    /// Identify SaaS tenancies from the apex TXT records.
    ///
    /// A verification token is proof the organisation once completed an
    /// ownership challenge for that vendor — which makes the apex TXT set a
    /// better vendor inventory than most procurement systems hold.
    pub async fn lookup_saas_tenancies(&self, domain: &str) -> Result<Vec<SaasTenancy>, ApiError> {
        let records = self.lookup_txt(domain).await?;
        Ok(parse_saas_verifications(&records, domain))
    }

    /// Follow a hostname's CNAME chain.
    ///
    /// The chain is the takeover surface: a CNAME pointing at a deprovisioned
    /// cloud tenant is the classic dangling-record finding, and the
    /// intermediate targets frequently name infrastructure the organisation
    /// owns but never published.
    ///
    /// The hop limit stops a deliberately looping chain from spinning.
    pub async fn lookup_cname_chain(
        &self,
        hostname: &str,
        max_hops: usize,
    ) -> Result<Vec<String>, ApiError> {
        let mut chain: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut current = hostname.trim_end_matches('.').to_lowercase();
        seen.insert(current.clone());

        for _ in 0..max_hops {
            let records = match self.lookup_records(&current, RecordType::CNAME).await {
                Ok(records) => records,
                // No CNAME is the common case and ends the walk cleanly.
                Err(_) => break,
            };

            let Some(target) = records
                .iter()
                .filter_map(|record| match record.data() {
                    Some(RData::CNAME(name)) => {
                        Some(name.to_utf8().trim_end_matches('.').to_lowercase())
                    }
                    _ => None,
                })
                .find(|target| !target.is_empty())
            else {
                break;
            };

            if !seen.insert(target.clone()) {
                tracing::debug!("CNAME chain for {} loops at {}", hostname, target);
                break;
            }
            chain.push(target.clone());
            current = target;
        }

        Ok(chain)
    }

    pub async fn lookup_records(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ApiError> {
        self.rate_limiter.until_ready().await;

        let name_owned = format!("{}.", name.trim_end_matches('.'));
        let name_for_error = name_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver
                .lookup(&name_owned, record_type)
                .await
                .map_err(|e| {
                    ApiError::ExternalService(format!(
                        "{} lookup failed for {}: {}",
                        record_type, name_owned, e
                    ))
                })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!(
                "{} query timeout for {}",
                record_type, name_for_error
            ))
        })?;

        result.map(|lookup| lookup.record_iter().cloned().collect())
    }

    /// Whether any record of this type exists. Distinguishes "no such record"
    /// from "the query failed", which matters for DNSSEC: treating a SERVFAIL as
    /// "unsigned" would report a broken chain of trust as an absent one.
    pub async fn record_exists(&self, name: &str, record_type: RecordType) -> Option<bool> {
        match self.lookup_records(name, record_type).await {
            Ok(records) => Some(!records.is_empty()),
            Err(e) => {
                let message = e.to_string();
                // trust-dns reports an empty authoritative answer as "no records
                // found", which is a definite negative rather than a failure.
                if message.contains("no record") || message.contains("No records") {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }

    /// Query one specific nameserver rather than the system resolver. Needed to
    /// tell a lame delegation from a working one, and to compare what each
    /// nameserver in a set actually serves.
    pub async fn lookup_at_nameserver(
        &self,
        nameserver: IpAddr,
        name: &str,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ApiError> {
        use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

        let group = NameServerConfigGroup::from_ips_clear(&[nameserver], 53, true);
        let config = ResolverConfig::from_parts(None, Vec::new(), group);
        let mut opts = ResolverOpts::default();
        opts.timeout = self.config.query_timeout;
        opts.attempts = 1;
        // The point is to see this server's own answer, not a cached one, and to
        // learn whether it answers for the zone at all.
        opts.use_hosts_file = false;
        opts.cache_size = 0;

        let resolver = TokioAsyncResolver::tokio(config, opts);
        let name_owned = format!("{}.", name.trim_end_matches('.'));
        let query_timeout = self.config.query_timeout;

        timeout(query_timeout, async move {
            resolver
                .lookup(&name_owned, record_type)
                .await
                .map(|lookup| lookup.record_iter().cloned().collect::<Vec<_>>())
                .map_err(|e| {
                    ApiError::ExternalService(format!(
                        "{} lookup at {} failed: {}",
                        record_type, nameserver, e
                    ))
                })
        })
        .await
        .map_err(|_| ApiError::ExternalService(format!("query to {} timed out", nameserver)))?
    }

    /// Lookup MX records for a domain
    pub async fn lookup_mx(&self, domain: &str) -> Result<Vec<(u16, String)>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let domain_owned = format!("{}.", domain.trim_end_matches('.'));
        let domain_for_error = domain_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.mx_lookup(&domain_owned).await.map_err(|e| {
                ApiError::ExternalService(format!("MX lookup failed for {}: {}", domain_owned, e))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("MX query timeout for {}", domain_for_error))
        })?;

        match result {
            Ok(response) => {
                let mut mx_records: Vec<(u16, String)> = response
                    .iter()
                    .map(|mx| {
                        (
                            mx.preference(),
                            mx.exchange().to_string().trim_end_matches('.').to_string(),
                        )
                    })
                    .collect();
                mx_records.sort_by_key(|(pref, _)| *pref);
                Ok(mx_records)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_dns_resolver_creation() {
        let resolver = DnsResolver::new().await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_dns_resolver_with_custom_config() {
        let config = DnsConfig {
            query_timeout: Duration::from_secs(3),
            max_concurrent: 25,
            rate_limit: 50,
        };

        let resolver = DnsResolver::with_config(config.clone()).await;
        assert!(resolver.is_ok());

        let resolver = resolver.unwrap();
        assert_eq!(resolver.config().query_timeout, config.query_timeout);
        assert_eq!(resolver.config().max_concurrent, config.max_concurrent);
        assert_eq!(resolver.config().rate_limit, config.rate_limit);
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let resolver = DnsResolver::new().await.unwrap();
        let result = resolver.resolve_hostname("localhost").await;

        // localhost should resolve to something (usually 127.0.0.1 or ::1)
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_invalid_hostname() {
        let resolver = DnsResolver::new().await.unwrap();
        let result = resolver
            .resolve_hostname("this-domain-should-not-exist-12345.invalid")
            .await;

        // Should fail for invalid domain
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reverse_lookup_localhost() {
        let resolver = DnsResolver::new().await.unwrap();
        let localhost_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = resolver.reverse_lookup(&localhost_ip).await;

        // Reverse lookup might succeed or fail depending on system configuration
        // We just test that it doesn't panic
        match result {
            Ok(hostnames) => {
                println!("Reverse lookup successful: {:?}", hostnames);
            }
            Err(e) => {
                println!("Reverse lookup failed (expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_resolution() {
        let resolver = DnsResolver::new().await.unwrap();
        let hostnames = vec![
            "localhost".to_string(),
            "example.com".to_string(),
            "invalid-domain-12345.test".to_string(),
        ];

        let results = resolver.resolve_hostnames_concurrent(hostnames).await;

        // Should have results for all hostnames (some may have errors)
        assert_eq!(results.len(), 3);

        // Check that localhost resolved successfully
        let localhost_result = results.iter().find(|r| r.hostname == "localhost");
        assert!(localhost_result.is_some());
        let localhost_result = localhost_result.unwrap();
        assert!(localhost_result.error.is_none());
        assert!(!localhost_result.ips.is_empty());

        // Check that invalid domain has an error
        let invalid_result = results
            .iter()
            .find(|r| r.hostname == "invalid-domain-12345.test");
        assert!(invalid_result.is_some());
        let invalid_result = invalid_result.unwrap();
        assert!(invalid_result.error.is_some());
        assert!(invalid_result.ips.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_reverse_lookup() {
        let resolver = DnsResolver::new().await.unwrap();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];

        let results = resolver.reverse_lookup_concurrent(ips).await;

        // Should have results for all IPs (some may have errors)
        assert_eq!(results.len(), 3);

        // Results should contain the IPs we queried
        let result_ips: Vec<IpAddr> = results.iter().map(|r| r.ip).collect();
        assert!(result_ips.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(result_ips.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(result_ips.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[tokio::test]
    async fn test_hostname_exists() {
        let resolver = DnsResolver::new().await.unwrap();

        // localhost should exist
        assert!(resolver.hostname_exists("localhost").await);

        // Invalid domain should not exist
        assert!(
            !resolver
                .hostname_exists("this-domain-should-not-exist-12345.invalid")
                .await
        );
    }

    #[test]
    fn test_parse_spf_includes_and_redirect() {
        let spf = parse_spf("v=spf1 include:_spf.google.com include:amazonses.com ip4:1.2.3.4 a:mail.example.org mx:mx.example.com exists:%{i}._spf.example.net -all");
        assert_eq!(
            spf.includes,
            vec!["_spf.google.com".to_string(), "amazonses.com".to_string()]
        );
        assert_eq!(
            spf.hosts,
            vec!["mail.example.org".to_string(), "mx.example.com".to_string()]
        );
        assert_eq!(spf.exists, vec!["%{i}._spf.example.net".to_string()]);
    }

    #[test]
    fn test_parse_spf_redirect() {
        let spf = parse_spf("v=spf1 redirect=_spf.example.com");
        assert_eq!(spf.includes, vec!["_spf.example.com".to_string()]);
    }

    #[test]
    fn test_parse_spf_ignores_non_spf() {
        // Other TXT records (Google site verification, DKIM, etc.) must not produce hits.
        let spf = parse_spf("google-site-verification=abc123");
        assert!(spf.includes.is_empty());
        assert!(spf.hosts.is_empty());
    }

    #[test]
    fn test_parse_spf_handles_qualifiers_and_quotes() {
        let spf = parse_spf("\"v=spf1 +include:foo.example.com ?include:bar.example.com ~all\"");
        assert_eq!(
            spf.includes,
            vec!["bar.example.com".to_string(), "foo.example.com".to_string()]
        );
    }

    #[test]
    fn test_parse_dmarc_extracts_report_domains() {
        let rec = "v=DMARC1; p=reject; rua=mailto:dmarc-agg@reports.example.org, mailto:other@watchdog.example.net!10m; ruf=mailto:forensic@reports.example.org; fo=1";
        let parsed = parse_dmarc(rec);
        assert_eq!(
            parsed.aggregate,
            vec![
                "reports.example.org".to_string(),
                "watchdog.example.net".to_string(),
            ]
        );
        assert_eq!(parsed.forensic, vec!["reports.example.org".to_string()]);
    }

    #[test]
    fn test_parse_dmarc_ignores_non_dmarc() {
        let parsed = parse_dmarc("v=spf1 -all");
        assert!(parsed.aggregate.is_empty());
        assert!(parsed.forensic.is_empty());
    }

    #[test]
    fn saas_verification_tokens_identify_the_vendor() {
        let records = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "google-site-verification=AbCdEf123".to_string(),
            "MS=ms12345678".to_string(),
            "atlassian-domain-verification=xyz".to_string(),
            "some unrelated free text".to_string(),
        ];
        let found = parse_saas_verifications(&records, "example.com");
        let vendors: Vec<&str> = found.iter().map(|t| t.vendor).collect();

        assert!(vendors.contains(&"Google Workspace / Search Console"));
        assert!(vendors.contains(&"Microsoft 365"));
        assert!(vendors.contains(&"Atlassian"));
        assert_eq!(found.len(), 3, "free text and SPF must not match");
    }

    #[test]
    fn spf_and_dmarc_records_are_not_mistaken_for_verification_tokens() {
        let records = vec![
            "v=spf1 -all".to_string(),
            "v=DMARC1; p=reject; rua=mailto:d@example.com".to_string(),
        ];
        assert!(parse_saas_verifications(&records, "example.com").is_empty());
    }

    #[test]
    fn a_token_matches_only_as_a_prefix() {
        // A record that merely mentions a token elsewhere is not proof of tenancy.
        let records = vec!["note: we removed the google-site-verification= record".to_string()];
        assert!(parse_saas_verifications(&records, "example.com").is_empty());
    }

    #[test]
    fn a_vendor_with_two_tokens_is_reported_once() {
        let records = vec![
            "google-site-verification=first".to_string(),
            "google-site-verification=second".to_string(),
        ];
        assert_eq!(parse_saas_verifications(&records, "example.com").len(), 1);
    }

    #[test]
    fn tenancies_imply_predictable_hostnames_only_where_they_exist() {
        let found = parse_saas_verifications(
            &[
                "MS=ms1".to_string(),
                "zendesk_verification=abc".to_string(),
                "stripe-verification=xyz".to_string(),
            ],
            "example.com",
        );

        let implied: Vec<Option<String>> = found
            .iter()
            .map(|tenancy| tenancy.implied_hostname.clone())
            .collect();

        assert!(implied.contains(&Some("autodiscover.example.com".to_string())));
        assert!(implied.contains(&Some("support.example.com".to_string())));
        // Stripe has no predictable tenant hostname, so none is invented.
        assert!(implied.contains(&None));
    }

    #[test]
    fn quoted_txt_records_are_unwrapped_before_matching() {
        let records = vec!["\"google-site-verification=quoted\"".to_string()];
        let found = parse_saas_verifications(&records, "example.com");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].record, "google-site-verification=quoted");
    }

    #[tokio::test]
    async fn test_timeout_configuration() {
        let config = DnsConfig {
            query_timeout: Duration::from_millis(1), // Very short timeout
            max_concurrent: 10,
            rate_limit: 100,
        };

        let resolver = DnsResolver::with_config(config).await.unwrap();

        // This should timeout quickly
        let start = std::time::Instant::now();
        let result = resolver.resolve_hostname("example.com").await;
        let elapsed = start.elapsed();

        // Should fail due to timeout and complete quickly
        assert!(result.is_err());
        assert!(elapsed < Duration::from_millis(100)); // Should be much faster than normal DNS query
    }
}

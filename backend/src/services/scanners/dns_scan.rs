//! Deep DNS assessment of a domain.
//!
//! Covers what `dig`, `dnsrecon`, MXToolbox, Hardenize and internet.nl cover
//! between them:
//!
//! * a full record sweep (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, DNSKEY, DS)
//! * DNSSEC: is the zone signed, and is the delegation signed with it
//! * AXFR against every authoritative nameserver
//! * SPF to RFC 7208 including the ten-lookup processing limit, DMARC to RFC 7489,
//!   DKIM selector probing, MTA-STS, TLS-RPT, BIMI, DANE/TLSA
//! * CAA parsing, not `format!("{:?}")` of the record
//! * nameserver count, diversity and lame delegation (RFC 2182)
//! * SOA timer sanity (RFC 1912 §2.2, RFC 2308)
//! * wildcard DNS, CNAME at the apex, RFC 1918 addresses in public DNS
//! * dangling CNAMEs against the subdomain-takeover signature set

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use trust_dns_resolver::proto::rr::{RData, RecordType};

use crate::models::FindingSeverity;
use crate::services::external::DnsResolver;

use super::dns_wire::{self, ZoneTransferOutcome};
use super::email_auth::{
    self, DmarcAnalysis, MtaStsAnalysis, SimpleRecordCheck, SpfAnalysis, COMMON_DKIM_SELECTORS,
};
use super::takeover::{self, TakeoverSignature};
use super::ScanFinding;

/// Recursion depth for SPF `include:` chains. RFC 7208 caps the *lookups* at 10;
/// this bounds the shape of the walk so a cyclic policy cannot spin.
const SPF_MAX_DEPTH: u8 = 10;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsRecordInventory {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub cname: Vec<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub caa: Vec<CaaRecord>,
    pub srv: Vec<String>,
    pub soa: Option<SoaRecord>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaRecord {
    pub primary_ns: String,
    pub responsible: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnssecResult {
    /// DNSKEY records exist at the zone apex: the zone is signed.
    pub zone_signed: bool,
    /// A DS record exists in the parent zone: the signature is anchored.
    pub delegation_signed: bool,
    pub dnskey_count: usize,
    pub ds_count: usize,
    /// Signed but not anchored — validators treat it as unsigned, so the
    /// signatures buy nothing. Hardenize calls this an "island of security".
    pub island_of_security: bool,
    pub checked: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NameserverResult {
    pub nameservers: Vec<NameserverInfo>,
    pub count: usize,
    /// Distinct parent zones among the nameserver names — a proxy for "would one
    /// provider outage take the domain off the internet".
    pub distinct_providers: usize,
    /// Distinct /24 (or /48) networks among the nameserver addresses.
    pub distinct_networks: usize,
    pub ipv6_capable: bool,
    pub issues: Vec<NameserverIssue>,
}

/// A delegation problem and how bad it is.
///
/// The severity travels with the issue rather than being recovered later by
/// matching substrings of its own message — which is how the worst case (no
/// nameserver answers at all) ended up graded as the mildest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameserverIssue {
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameserverInfo {
    pub hostname: String,
    pub addresses: Vec<String>,
    pub resolvable: bool,
    /// The nameserver answered for the zone it is delegated for.
    pub answers_for_zone: bool,
    pub zone_transfer: String,
    pub zone_transfer_records: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailSecurityResult {
    pub has_mx: bool,
    pub mx_hosts: Vec<String>,
    pub spf: SpfAnalysis,
    pub dmarc: DmarcAnalysis,
    pub dkim_selectors_found: Vec<String>,
    pub dkim_probed: usize,
    pub mta_sts: MtaStsAnalysis,
    pub tls_rpt: SimpleRecordCheck,
    pub bimi: SimpleRecordCheck,
    /// DANE/TLSA records on the MX hosts (RFC 7672).
    pub dane_hosts: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub dangling: bool,
    pub cname_target: Option<String>,
    pub service: Option<String>,
    pub evidence: Option<String>,
    pub claimable: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WildcardResult {
    pub enabled: bool,
    pub resolved_to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsScanResult {
    pub domain: String,
    /// Whether this name is a zone apex, decided by whether it serves its own
    /// SOA. Delegation, DNSSEC, CAA and email policy are all properties of a
    /// *zone*; a subdomain inherits them and has none of its own, so reporting
    /// them as missing there is noise — and an asset inventory is mostly
    /// subdomains.
    pub is_zone_apex: bool,
    pub records: DnsRecordInventory,
    pub email: EmailSecurityResult,
    pub dnssec: DnssecResult,
    pub nameservers: NameserverResult,
    pub caa_present: bool,
    pub zone_transfer_possible: bool,
    pub takeover: TakeoverResult,
    pub wildcard: WildcardResult,
    pub internal_addresses: Vec<String>,
    pub cname_at_apex: bool,
    /// 0–100 hygiene score, and the letter it maps to.
    pub score: u8,
    pub grade: String,
    pub errors: Vec<String>,
    pub scan_duration_ms: i64,
}

/// Every finding type this scanner can emit.
///
/// `security_scan_service::finding_types_for_scan` uses these lists to decide
/// which findings a fresh scan is allowed to auto-resolve. A type emitted here
/// but absent there stays open forever after it is fixed, so the two are kept in
/// step by a test rather than by memory.
pub const EMITTED_FINDING_TYPES: &[&str] = &[
    "zone_transfer_allowed",
    "dangling_dns",
    "missing_spf",
    "weak_spf_policy",
    "spf_lookup_limit_exceeded",
    "multiple_spf_records",
    "missing_dmarc",
    "weak_dmarc_policy",
    "missing_dkim",
    "missing_mta_sts",
    "mta_sts_misconfigured",
    "missing_tls_rpt",
    "missing_dnssec",
    "dnssec_misconfigured",
    "missing_caa",
    "caa_incomplete",
    "nameserver_misconfigured",
    "soa_misconfigured",
    "dns_misconfiguration",
    "information_disclosure",
];

/// Everything the scan produced: the structured result for the UI, and the
/// findings for the database.
pub struct DnsScanOutcome {
    pub result: DnsScanResult,
    pub findings: Vec<ScanFinding>,
}

fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()
                || v4.octets()[0] == 0
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local, fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The network an address belongs to, for the diversity check: a /24 for IPv4 and
/// a /48 for IPv6, which is the granularity at which routing actually differs.
fn network_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// The registrable-ish parent of a nameserver hostname, used to tell
/// `ns1.example-dns.com` and `ns2.example-dns.com` apart from a genuinely
/// independent second provider.
fn provider_key(hostname: &str) -> String {
    let host = hostname.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host;
    }
    labels[labels.len() - 2..].join(".")
}

async fn resolve_txt(resolver: &DnsResolver, name: &str) -> Vec<String> {
    resolver.lookup_txt(name).await.unwrap_or_default()
}

/// Walk `include:` and `redirect=` to get the real RFC 7208 lookup count.
///
/// A record whose own terms cost three lookups can still blow the limit of ten
/// through the providers it includes; counting only the top level — which is what
/// a naive check does — reports a broken policy as healthy.
///
/// `on_path` is the current include chain, not a global visited set. RFC 7208
/// counts DNS *queries*, and a provider reached down two sibling branches is
/// queried twice, so it costs twice. Deduplicating globally would undercount
/// exactly the diamond-shaped include graphs that push a policy over the limit:
/// `include:a include:b` where both include the same 5-lookup provider really
/// costs 14, and a global set would report 9 — healthy, and wrong. Removing the
/// domain on the way out keeps the cycle guard while allowing the re-traversal.
fn count_spf_lookups<'a>(
    resolver: &'a DnsResolver,
    domain: String,
    depth: u8,
    on_path: &'a mut BTreeSet<String>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = u32> + Send + 'a>> {
    Box::pin(async move {
        if depth >= SPF_MAX_DEPTH || !on_path.insert(domain.clone()) {
            return 0;
        }
        let records = resolve_txt(resolver, &domain).await;
        let Some(record) = records
            .iter()
            .find(|r| r.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
        else {
            return 0;
        };
        let analysis = email_auth::parse_spf_record(record);
        let mut total = analysis.dns_lookups;
        let mut nested: Vec<String> = analysis.includes.clone();
        if let Some(redirect) = &analysis.redirect {
            nested.push(redirect.clone());
        }
        for target in nested {
            total += count_spf_lookups(resolver, target, depth + 1, on_path).await;
        }
        on_path.remove(&domain);
        total
    })
}

/// Run the full DNS assessment.
pub async fn scan(
    resolver: &Arc<DnsResolver>,
    http: &reqwest::Client,
    domain: &str,
    timeout: Duration,
    deep: bool,
) -> DnsScanOutcome {
    let started = std::time::Instant::now();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut errors = Vec::new();
    let mut records = DnsRecordInventory::default();

    // ---- Record sweep -----------------------------------------------------
    let (a_records, aaaa_records, cname_records, txt_records, ns_records, mx_records) = tokio::join!(
        resolver.lookup_records(&domain, RecordType::A),
        resolver.lookup_records(&domain, RecordType::AAAA),
        resolver.lookup_records(&domain, RecordType::CNAME),
        resolver.lookup_txt(&domain),
        resolver.lookup_ns(&domain),
        resolver.lookup_mx(&domain),
    );

    let mut internal_addresses = Vec::new();
    for record in a_records.into_iter().flatten() {
        if let Some(RData::A(ip)) = record.data() {
            let addr = IpAddr::V4(ip.0);
            if is_internal(addr) {
                internal_addresses.push(addr.to_string());
            }
            records.a.push(addr.to_string());
        }
    }
    for record in aaaa_records.into_iter().flatten() {
        if let Some(RData::AAAA(ip)) = record.data() {
            let addr = IpAddr::V6(ip.0);
            if is_internal(addr) {
                internal_addresses.push(addr.to_string());
            }
            records.aaaa.push(addr.to_string());
        }
    }
    for record in cname_records.into_iter().flatten() {
        if let Some(RData::CNAME(name)) = record.data() {
            records
                .cname
                .push(name.to_string().trim_end_matches('.').to_string());
        }
    }
    // Every lookup below distinguishes "answered with nothing" from "did not
    // answer". `unwrap_or_default` on its own silently turns the second into the
    // first, which is how a resolver hiccup becomes a high-severity finding about
    // somebody's delegation.
    if let Err(e) = &txt_records {
        errors.push(format!("TXT lookup for {} failed: {}", domain, e));
    }
    if let Err(e) = &ns_records {
        errors.push(format!("NS lookup for {} failed: {}", domain, e));
    }
    if let Err(e) = &mx_records {
        tracing::debug!("MX lookup for {} failed: {}", domain, e);
    }
    let ns_lookup_succeeded = ns_records.is_ok();
    records.txt = txt_records.unwrap_or_default();
    records.ns = ns_records.unwrap_or_default();
    let mx = mx_records.unwrap_or_default();
    records.mx = mx
        .iter()
        .map(|(pref, host)| format!("{} {}", pref, host))
        .collect();

    // CAA, parsed properly. The pre-existing resolver helper returned
    // `format!("{:?}", record)` of the whole record, so "does this domain
    // restrict certificate issuance, and to whom" was unanswerable from it.
    match resolver.lookup_records(&domain, RecordType::CAA).await {
        Ok(found) => {
            for record in found {
                if let Some(RData::CAA(caa)) = record.data() {
                    let value = match caa.value() {
                        trust_dns_resolver::proto::rr::rdata::caa::Value::Issuer(name, _) => name
                            .as_ref()
                            .map(|n| n.to_string().trim_end_matches('.').to_string())
                            .unwrap_or_else(|| ";".to_string()),
                        trust_dns_resolver::proto::rr::rdata::caa::Value::Url(url) => {
                            url.to_string()
                        }
                        trust_dns_resolver::proto::rr::rdata::caa::Value::Unknown(bytes) => {
                            String::from_utf8_lossy(bytes).to_string()
                        }
                    };
                    records.caa.push(CaaRecord {
                        flags: u8::from(caa.issuer_critical()),
                        tag: caa.tag().as_str().to_string(),
                        value,
                    });
                }
            }
        }
        Err(e) => tracing::debug!("CAA lookup for {} failed: {}", domain, e),
    }

    if let Ok(found) = resolver.lookup_records(&domain, RecordType::SOA).await {
        for record in found {
            if let Some(RData::SOA(soa)) = record.data() {
                records.soa = Some(build_soa(soa));
            }
        }
    }

    records.total = records.a.len()
        + records.aaaa.len()
        + records.cname.len()
        + records.mx.len()
        + records.ns.len()
        + records.txt.len()
        + records.caa.len()
        + usize::from(records.soa.is_some());

    // RFC 1034 §3.6.2 forbids a CNAME alongside any other record. At a zone apex
    // that is always a violation, because the apex necessarily carries SOA and NS.
    // Below the apex a CNAME is ordinary and correct — every CDN-fronted `www` is
    // one — so the SOA is what distinguishes the two. Without that check every
    // aliased subdomain in the inventory would be reported as misconfigured.
    let cname_at_apex = !records.cname.is_empty() && records.soa.is_some();

    // ---- Email authentication --------------------------------------------
    let email = analyze_email(resolver, http, &domain, &records, &mx, deep).await;

    // ---- DNSSEC -----------------------------------------------------------
    // Only a zone has a DNSKEY set; below the apex there is nothing to ask for.
    let dnssec = if records.soa.is_some() {
        analyze_dnssec(&domain, timeout).await
    } else {
        DnssecResult::default()
    };

    // ---- Nameservers and zone transfer ------------------------------------
    let nameservers = analyze_nameservers(
        resolver,
        &domain,
        &records.ns,
        ns_lookup_succeeded,
        timeout,
        deep,
    )
    .await;
    let zone_transfer_possible = nameservers
        .nameservers
        .iter()
        .any(|ns| ns.zone_transfer == "transferred");

    // ---- Wildcard and takeover --------------------------------------------
    let wildcard = detect_wildcard(resolver, &domain).await;
    let takeover = detect_takeover(resolver, http, &records.cname, timeout).await;

    let caa_present = !records.caa.is_empty();

    let is_zone_apex = records.soa.is_some();
    let mut result = DnsScanResult {
        domain: domain.clone(),
        is_zone_apex,
        records,
        email,
        dnssec,
        nameservers,
        caa_present,
        zone_transfer_possible,
        takeover,
        wildcard,
        internal_addresses,
        cname_at_apex,
        score: 100,
        grade: "A".to_string(),
        errors,
        scan_duration_ms: 0,
    };

    let findings = build_findings(&result);
    let (score, grade) = score_dns(&result, &findings);
    result.score = score;
    result.grade = grade;
    result.scan_duration_ms = started.elapsed().as_millis() as i64;

    DnsScanOutcome { result, findings }
}

fn build_soa(soa: &trust_dns_resolver::proto::rr::rdata::SOA) -> SoaRecord {
    let mut issues = Vec::new();
    let refresh = soa.refresh();
    let retry = soa.retry();
    let expire = soa.expire();
    let minimum = soa.minimum();

    // RFC 1912 §2.2 and RFC 2308 §5 give the ranges below. Outside them, a zone
    // survives a primary outage badly: too short and the secondaries hammer the
    // primary, too long and a change takes days to propagate.
    if !(1_200..=43_200).contains(&refresh) {
        issues.push(format!(
            "SOA refresh is {}s; RFC 1912 §2.2 suggests 20 minutes to 12 hours (1200–43200).",
            refresh
        ));
    }
    if !(120..=7_200).contains(&retry) || retry >= refresh {
        issues.push(format!(
            "SOA retry is {}s; it should be 2 minutes to 2 hours and below the refresh interval.",
            retry
        ));
    }
    if !(1_209_600..=2_419_200).contains(&expire) {
        issues.push(format!(
            "SOA expire is {}s; RFC 1912 §2.2 suggests 2 to 4 weeks (1209600–2419200). Too short \
             and the zone goes dark during a primary outage.",
            expire
        ));
    }
    if !(300..=86_400).contains(&minimum) {
        issues.push(format!(
            "SOA minimum (negative-cache TTL) is {}s; RFC 2308 §5 suggests 5 minutes to 1 day.",
            minimum
        ));
    }

    SoaRecord {
        primary_ns: soa.mname().to_string().trim_end_matches('.').to_string(),
        responsible: soa.rname().to_string().trim_end_matches('.').to_string(),
        serial: soa.serial(),
        refresh,
        retry,
        expire,
        minimum,
        issues,
    }
}

async fn analyze_email(
    resolver: &Arc<DnsResolver>,
    http: &reqwest::Client,
    domain: &str,
    records: &DnsRecordInventory,
    mx: &[(u16, String)],
    deep: bool,
) -> EmailSecurityResult {
    let mut email = EmailSecurityResult {
        has_mx: !mx.is_empty(),
        mx_hosts: mx.iter().map(|(_, host)| host.clone()).collect(),
        ..Default::default()
    };

    // ---- SPF --------------------------------------------------------------
    let spf_records: Vec<&String> = records
        .txt
        .iter()
        .filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    if let Some(record) = spf_records.first() {
        let mut analysis = email_auth::parse_spf_record(record);
        analysis.multiple_records = spf_records.len() > 1;
        let mut on_path = BTreeSet::new();
        on_path.insert(domain.to_string());
        let mut total = analysis.dns_lookups;
        let mut nested = analysis.includes.clone();
        if let Some(redirect) = &analysis.redirect {
            nested.push(redirect.clone());
        }
        for target in nested {
            total += count_spf_lookups(resolver, target, 1, &mut on_path).await;
        }
        email_auth::evaluate_spf(&mut analysis, total);
        email.spf = analysis;
    }

    // ---- DMARC ------------------------------------------------------------
    let dmarc_records = resolve_txt(resolver, &format!("_dmarc.{}", domain)).await;
    let dmarc_hits: Vec<&String> = dmarc_records
        .iter()
        .filter(|r| r.to_ascii_lowercase().contains("v=dmarc1"))
        .collect();
    if let Some(record) = dmarc_hits.first() {
        let mut analysis = email_auth::parse_dmarc_record(record);
        analysis.multiple_records = dmarc_hits.len() > 1;
        email_auth::evaluate_dmarc(&mut analysis);
        email.dmarc = analysis;
    }

    // ---- DKIM -------------------------------------------------------------
    // Selectors cannot be enumerated from DNS, only guessed; the report says so
    // rather than presenting an empty result as "no DKIM".
    let selectors: &[&str] = if deep {
        COMMON_DKIM_SELECTORS
    } else {
        &COMMON_DKIM_SELECTORS[..12]
    };
    email.dkim_probed = selectors.len();
    let probes = selectors.iter().map(|selector| {
        let resolver = Arc::clone(resolver);
        let name = format!("{}._domainkey.{}", selector, domain);
        let selector = selector.to_string();
        async move {
            let records = resolver.lookup_txt(&name).await.unwrap_or_default();
            records
                .iter()
                .any(|r| {
                    let lower = r.to_ascii_lowercase();
                    lower.contains("v=dkim1") || lower.contains("p=")
                })
                .then_some(selector)
        }
    });
    email.dkim_selectors_found = futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .collect();

    // ---- MTA-STS, TLS-RPT, BIMI -------------------------------------------
    let mta_sts_txt = resolve_txt(resolver, &format!("_mta-sts.{}", domain)).await;
    let mut mta_sts = MtaStsAnalysis::default();
    for record in &mta_sts_txt {
        if let Some(id) = email_auth::parse_mta_sts_txt(record) {
            mta_sts.dns_record_present = true;
            mta_sts.policy_id = Some(id);
            break;
        }
    }
    if mta_sts.dns_record_present {
        let url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
        match http.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await.unwrap_or_default();
                email_auth::parse_mta_sts_policy(&body, &mut mta_sts);
            }
            _ => email_auth::parse_mta_sts_policy("", &mut mta_sts),
        }
    }
    email.mta_sts = mta_sts;

    email.tls_rpt = email_auth::parse_tls_rpt(
        &resolve_txt(resolver, &format!("_smtp._tls.{}", domain)).await,
    );
    email.bimi =
        email_auth::parse_bimi(&resolve_txt(resolver, &format!("default._bimi.{}", domain)).await);

    // ---- DANE / TLSA on the MX hosts --------------------------------------
    for (_, host) in mx.iter().take(5) {
        let name = format!("_25._tcp.{}", host);
        // TLSA is another type the stub resolver cannot decode; ask over the wire.
        if let Ok(records) =
            dns_wire::query_system(&name, dns_wire::TYPE_TLSA, Duration::from_secs(5)).await
        {
            if records.iter().any(|r| r.record_type == "TLSA") {
                email.dane_hosts.push(host.clone());
            }
        }
    }

    email
}

async fn analyze_dnssec(domain: &str, timeout: Duration) -> DnssecResult {
    // Asked over the wire rather than through the stub resolver: built without
    // its `dnssec` feature, `trust-dns-proto` decodes DNSKEY and DS as `Unknown`
    // and trips a `debug_assert!` doing it, so every signed zone would read as
    // unsigned (and every debug build would panic). See `dns_wire`.
    let (dnskey, ds) = tokio::join!(
        dns_wire::query_system(domain, dns_wire::TYPE_DNSKEY, timeout),
        dns_wire::query_system(domain, dns_wire::TYPE_DS, timeout),
    );

    // A query error is not the same as an empty answer: reporting a SERVFAIL as
    // "unsigned" would turn a broken chain of trust into a missing one.
    // A query that failed says nothing about whether the record exists, and every
    // verdict below is gated on the query it depends on having actually answered.
    // Both must succeed before any conclusion is drawn: with only one, a signed
    // and correctly anchored zone whose large DNSKEY answer timed out would be
    // reported as a *broken chain of trust* at high severity — a false alarm
    // manufactured out of a network problem.
    let dnskey_count = dnskey
        .as_ref()
        .ok()
        .map(|records| records.iter().filter(|r| r.record_type == "DNSKEY").count());
    let ds_count = ds
        .as_ref()
        .ok()
        .map(|records| records.iter().filter(|r| r.record_type == "DS").count());

    let mut result = DnssecResult {
        zone_signed: dnskey_count.is_some_and(|count| count > 0),
        delegation_signed: ds_count.is_some_and(|count| count > 0),
        dnskey_count: dnskey_count.unwrap_or(0),
        ds_count: ds_count.unwrap_or(0),
        island_of_security: false,
        checked: dnskey_count.is_some() && ds_count.is_some(),
        issues: Vec::new(),
    };
    // Only meaningful once both queries have answered.
    result.island_of_security = result.checked && result.zone_signed && !result.delegation_signed;

    if !result.checked {
        let mut unanswered = Vec::new();
        if let Err(e) = &dnskey {
            unanswered.push(format!("DNSKEY ({})", e));
        }
        if let Err(e) = &ds {
            unanswered.push(format!("DS ({})", e));
        }
        result.issues.push(format!(
            "DNSSEC status could not be determined: {} did not answer. This is reported as \
             unknown rather than as unsigned.",
            unanswered.join(" and ")
        ));
        return result;
    }

    if result.island_of_security {
        result.issues.push(
            "The zone publishes DNSKEY records but the parent zone has no DS record, so no \
             validating resolver can anchor the signatures. The zone is signed but unvalidated."
                .to_string(),
        );
    }
    if result.delegation_signed && !result.zone_signed {
        result.issues.push(
            "The parent zone publishes a DS record but the zone itself has no DNSKEY. Validating \
             resolvers will fail every lookup for this domain (SERVFAIL)."
                .to_string(),
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn analyze_nameservers(
    resolver: &Arc<DnsResolver>,
    domain: &str,
    ns_names: &[String],
    ns_lookup_succeeded: bool,
    timeout: Duration,
    deep: bool,
) -> NameserverResult {
    let mut result = NameserverResult {
        count: ns_names.len(),
        ..Default::default()
    };

    let mut providers: BTreeSet<String> = BTreeSet::new();
    let mut networks: BTreeSet<String> = BTreeSet::new();

    for hostname in ns_names {
        providers.insert(provider_key(hostname));
        let addresses = resolver.resolve_hostname(hostname).await.unwrap_or_default();
        for ip in &addresses {
            networks.insert(network_key(*ip));
            if ip.is_ipv6() {
                result.ipv6_capable = true;
            }
        }

        // A delegated nameserver that will not answer for the zone is a lame
        // delegation: every query that lands on it is a timeout for somebody.
        let answers_for_zone = match addresses.first() {
            Some(ip) => resolver
                .lookup_at_nameserver(*ip, domain, RecordType::SOA)
                .await
                .map(|records| !records.is_empty())
                .unwrap_or(false),
            None => false,
        };

        let (transfer_state, transfer_records) = if deep {
            match addresses.first() {
                Some(ip) => {
                    let outcome =
                        dns_wire::attempt_transfer(domain, SocketAddr::new(*ip, 53), timeout).await;
                    match outcome {
                        ZoneTransferOutcome::Transferred { record_count, .. } => {
                            ("transferred".to_string(), Some(record_count))
                        }
                        ZoneTransferOutcome::Refused(_) => ("refused".to_string(), None),
                        ZoneTransferOutcome::Unavailable(_) => ("unavailable".to_string(), None),
                    }
                }
                None => ("unavailable".to_string(), None),
            }
        } else {
            ("not tested".to_string(), None)
        };

        result.nameservers.push(NameserverInfo {
            hostname: hostname.clone(),
            resolvable: !addresses.is_empty(),
            addresses: addresses.iter().map(|ip| ip.to_string()).collect(),
            answers_for_zone,
            zone_transfer: transfer_state,
            zone_transfer_records: transfer_records,
        });
    }

    result.distinct_providers = providers.len();
    result.distinct_networks = networks.len();

    if result.count == 0 {
        // Only a real answer of "no NS records" is a finding. A lookup that
        // failed says nothing, and reporting it as a missing delegation turns a
        // transient resolver problem into a high-severity alarm.
        if ns_lookup_succeeded {
            result.issues.push(NameserverIssue {
                severity: "high".to_string(),
                message: "No NS records were returned for the zone.".to_string(),
            });
        } else {
            result.issues.push(NameserverIssue {
                severity: "info".to_string(),
                message: "The NS lookup did not answer, so the delegation could not be checked."
                    .to_string(),
            });
        }
    } else if result.count == 1 {
        result.issues.push(NameserverIssue {
            severity: "low".to_string(),
            message: "Only one nameserver is delegated. RFC 2182 §5 requires at least two, on \
                      separate networks, so a single failure does not take the domain off the \
                      internet."
                .to_string(),
        });
    } else if result.distinct_networks == 1 {
        result.issues.push(NameserverIssue {
            severity: "low".to_string(),
            message: "Every nameserver is in the same /24. RFC 2182 §3.1 asks for topological \
                      diversity: one routing failure currently removes all of them."
                .to_string(),
        });
    }

    let lame: Vec<&NameserverInfo> = result
        .nameservers
        .iter()
        .filter(|ns| !ns.answers_for_zone)
        .collect();
    if !lame.is_empty() {
        let names = lame
            .iter()
            .map(|ns| ns.hostname.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        // Every nameserver failing is the worst case, not a case to skip. It is
        // also the one that can be the scanner's own egress rather than the
        // zone's problem, so it says so instead of asserting a verdict.
        if lame.len() == result.count {
            result.issues.push(NameserverIssue {
                severity: "medium".to_string(),
                message: format!(
                "None of the {} delegated nameservers answered authoritatively for the zone \
                 ({}). Either the delegation is entirely lame — in which case the domain \
                 resolves only from cache — or this scanner cannot reach port 53 on them. \
                 Confirm with `dig @{} SOA {}` from a host that can.",
                result.count,
                names,
                result
                    .nameservers
                    .first()
                    .map(|ns| ns.hostname.as_str())
                    .unwrap_or("ns"),
                    domain
                ),
            });
        } else {
            result.issues.push(NameserverIssue {
                severity: "medium".to_string(),
                message: format!(
                    "{} of {} delegated nameservers do not answer authoritatively for the zone \
                     (lame delegation): {}",
                    lame.len(),
                    result.count,
                    names
                ),
            });
        }
    }

    result
}

async fn detect_wildcard(resolver: &Arc<DnsResolver>, domain: &str) -> WildcardResult {
    // A label no one would register. If it resolves, the zone answers for
    // everything, which makes subdomain enumeration meaningless and can mask a
    // typo-squatting or takeover problem.
    let probe = format!("zzq7x2n4-easm-wildcard-probe.{}", domain);
    match resolver.resolve_hostname(&probe).await {
        Ok(ips) if !ips.is_empty() => WildcardResult {
            enabled: true,
            resolved_to: ips.iter().map(|ip| ip.to_string()).collect(),
        },
        _ => WildcardResult::default(),
    }
}

async fn detect_takeover(
    resolver: &Arc<DnsResolver>,
    http: &reqwest::Client,
    cnames: &[String],
    _timeout: Duration,
) -> TakeoverResult {
    for target in cnames {
        let Some(signature) = takeover::match_service(target) else {
            continue;
        };
        // Step 1: does the CNAME target resolve at all?
        let resolves = resolver
            .resolve_hostname(target)
            .await
            .map(|ips| !ips.is_empty())
            .unwrap_or(false);

        if !resolves && signature.nxdomain_is_takeover {
            return TakeoverResult {
                dangling: true,
                cname_target: Some(target.clone()),
                service: Some(signature.service.to_string()),
                evidence: Some(format!(
                    "The CNAME points at {} but the target does not resolve, and {} releases the \
                     name for re-registration.",
                    target, signature.service
                )),
                claimable: signature.claimable,
            };
        }

        // Step 2: it resolves — does the provider serve its "unclaimed" page?
        if resolves {
            if let Some(evidence) = fetch_takeover_evidence(http, target, signature).await {
                return TakeoverResult {
                    dangling: true,
                    cname_target: Some(target.clone()),
                    service: Some(signature.service.to_string()),
                    evidence: Some(evidence),
                    claimable: signature.claimable,
                };
            }
        }
    }
    TakeoverResult::default()
}

async fn fetch_takeover_evidence(
    http: &reqwest::Client,
    target: &str,
    signature: &TakeoverSignature,
) -> Option<String> {
    if signature.fingerprints.is_empty() {
        return None;
    }
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, target);
        let Ok(response) = http.get(&url).send().await else {
            continue;
        };
        let status = response.status();
        let Ok(body) = response.text().await else {
            continue;
        };
        // Only look at the head of the body: these are static error pages.
        let head: String = body.chars().take(8192).collect();
        if takeover::body_matches_fingerprint(signature, &head) {
            return Some(format!(
                "{} returned HTTP {} carrying {}'s unclaimed-tenant page.",
                url, status, signature.service
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

fn finding(
    finding_type: &str,
    severity: FindingSeverity,
    title: &str,
    description: String,
    remediation: &str,
    data: serde_json::Value,
) -> ScanFinding {
    ScanFinding::new(finding_type, severity, title, description, remediation, data)
}

/// Turn the assessment into findings. Pure over the result, so every rule below
/// is unit-testable without touching the network.
pub fn build_findings(result: &DnsScanResult) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let domain = &result.domain;

    // Checks below that are marked apex-only are skipped for a name that is not
    // a zone of its own. `www.example.com` has no NS records, no DNSKEY and no
    // CAA because `example.com` has them on its behalf; asserting otherwise would
    // put a "missing DNSSEC" finding on every subdomain in the inventory.
    let apex = result.is_zone_apex;

    // ---- Zone transfer: the highest-value DNS misconfiguration there is ----
    for ns in &result.nameservers.nameservers {
        if ns.zone_transfer == "transferred" {
            findings.push(finding(
                "zone_transfer_allowed",
                FindingSeverity::High,
                "DNS Zone Transfer Allowed (AXFR)",
                format!(
                    "{} handed over the complete zone for {} to an unauthenticated client{}. The \
                     transfer discloses every hostname in the zone — internal services, staging \
                     environments, and the full address layout — which removes the reconnaissance \
                     step from any attack on this domain.",
                    ns.hostname,
                    domain,
                    ns.zone_transfer_records
                        .map(|n| format!(", {} records", n))
                        .unwrap_or_default()
                ),
                "Restrict AXFR to the IP addresses of your secondary nameservers only \
                 (`allow-transfer` in BIND, `provide-xfr` in NSD), and prefer TSIG authentication.",
                json!({
                    "domain": domain,
                    "nameserver": ns.hostname,
                    "addresses": ns.addresses,
                    "record_count": ns.zone_transfer_records,
                }),
            ));
        }
    }

    // ---- Subdomain takeover ------------------------------------------------
    if result.takeover.dangling {
        findings.push(finding(
            "dangling_dns",
            if result.takeover.claimable {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            "Dangling DNS Record (Subdomain Takeover)",
            format!(
                "{} still points at {}, a {} resource that is no longer claimed. {} {}",
                domain,
                result.takeover.cname_target.as_deref().unwrap_or("a third-party service"),
                result.takeover.service.as_deref().unwrap_or("third-party"),
                result.takeover.evidence.as_deref().unwrap_or(""),
                if result.takeover.claimable {
                    "Anyone can register that resource and then serve content — and obtain a valid \
                     certificate — on this hostname."
                } else {
                    "The provider is documented as blocking re-registration, so the record is a \
                     defect rather than an immediate takeover, but it should still be removed."
                },
            ),
            "Remove the DNS record, or re-claim the resource at the provider before someone else \
             does. Retire DNS entries as part of decommissioning, not after it.",
            json!({
                "domain": domain,
                "cname_target": result.takeover.cname_target,
                "service": result.takeover.service,
                "evidence": result.takeover.evidence,
                "claimable": result.takeover.claimable,
            }),
        ));
    }

    // ---- Zone-level checks -------------------------------------------------
    //
    // Email authentication, DNSSEC, CAA and the delegation are all properties
    // of a zone. A subdomain inherits them and publishes none of its own, so
    // every one of these would be reported as missing on every `www.` in the
    // inventory. Gating the whole section — rather than each condition —
    // keeps the `else` branches (a weak DMARC policy, an incomplete CAA set)
    // inside the guard too.
    if apex {
        // ---- Email authentication ---------------------------------------------
        let email = &result.email;
        // A domain with MX is actively receiving mail, so a spoofed message is far
        // more likely to be believed. A parked domain still needs SPF/DMARC, but the
        // exposure is smaller.
        let mail_severity = |with_mx: FindingSeverity, without: FindingSeverity| {
            if email.has_mx {
                with_mx
            } else {
                without
            }
        };

        if !email.spf.present {
            findings.push(finding(
                "missing_spf",
                mail_severity(FindingSeverity::Medium, FindingSeverity::Low),
                "Missing SPF Record",
                format!(
                    "{} publishes no SPF record, so no receiving mail server can tell an authorised \
                     sender from a forged one. Any host on the internet can send mail claiming to be \
                     from this domain.{}",
                    domain,
                    if email.has_mx {
                        " The domain has MX records, so it is actively used for mail."
                    } else {
                        " The domain has no MX records, but it can still be forged in the From: header."
                    }
                ),
                "Publish a TXT record at the apex: `v=spf1 include:<your provider> -all`. A domain \
                 that never sends mail should publish `v=spf1 -all`.",
                json!({ "domain": domain, "has_mx": email.has_mx }),
            ));
        } else {
            if !email.spf.valid && email.spf.all_qualifier == Some(email_auth::SpfQualifier::Pass) {
                findings.push(finding(
                    "weak_spf_policy",
                    FindingSeverity::High,
                    "SPF Record Authorises Every Sender",
                    format!(
                        "The SPF record for {} ends in `+all`, which tells receivers that every host \
                         on the internet is an authorised sender. This is strictly worse than having \
                         no SPF record, because it turns a neutral result into an explicit pass.",
                        domain
                    ),
                    "Replace `+all` with `-all` and list the authorised senders explicitly.",
                    json!({ "domain": domain, "record": email.spf.record }),
                ));
            }
            if email.spf.exceeds_lookup_limit {
                findings.push(finding(
                    "spf_lookup_limit_exceeded",
                    FindingSeverity::Medium,
                    "SPF Record Exceeds the DNS Lookup Limit",
                    format!(
                        "Evaluating the SPF policy for {} needs {} DNS lookups, above the limit of {} \
                         in RFC 7208 §4.6.4. Receivers stop evaluating and return `permerror`, which \
                         most treat as no policy at all — so the SPF record silently does nothing.",
                        domain, email.spf.dns_lookups, email_auth::SPF_MAX_DNS_LOOKUPS
                    ),
                    "Flatten or consolidate `include:` chains, drop providers no longer used, or move \
                     to a provider that publishes a single-lookup include.",
                    json!({
                        "domain": domain,
                        "dns_lookups": email.spf.dns_lookups,
                        "limit": email_auth::SPF_MAX_DNS_LOOKUPS,
                        "includes": email.spf.includes,
                        "record": email.spf.record,
                    }),
                ));
            }
            if email.spf.multiple_records {
                findings.push(finding(
                    "multiple_spf_records",
                    FindingSeverity::Medium,
                    "Multiple SPF Records Published",
                    format!(
                        "{} publishes more than one `v=spf1` record. RFC 7208 §4.5 makes this a \
                         permanent error, and receivers discard the policy entirely.",
                        domain
                    ),
                    "Merge the records into a single TXT record at the apex.",
                    json!({ "domain": domain }),
                ));
            }
            if matches!(
                email.spf.all_qualifier,
                Some(email_auth::SpfQualifier::SoftFail) | Some(email_auth::SpfQualifier::Neutral)
            ) {
                findings.push(finding(
                    "weak_spf_policy",
                    FindingSeverity::Low,
                    "SPF Policy Is Not Enforcing",
                    format!(
                        "The SPF record for {} ends in `{}`, so mail from unauthorised hosts is still \
                         delivered. The policy documents the authorised senders without acting on \
                         them.",
                        domain,
                        email
                            .spf
                            .all_qualifier
                            .map(|q| q.label())
                            .unwrap_or("?all (neutral)")
                    ),
                    "Move to `-all` once DMARC aggregate reports confirm every legitimate source is \
                     covered.",
                    json!({ "domain": domain, "record": email.spf.record, "issues": email.spf.issues }),
                ));
            }
        }

        if !email.dmarc.present {
            findings.push(finding(
                "missing_dmarc",
                mail_severity(FindingSeverity::Medium, FindingSeverity::Low),
                "Missing DMARC Record",
                format!(
                    "{} publishes no DMARC record. Without one, SPF and DKIM results are advisory: \
                     receivers have no instruction about what to do with mail that fails them, and no \
                     reports come back showing who is sending as this domain.",
                    domain
                ),
                "Publish `v=DMARC1; p=none; rua=mailto:dmarc@<domain>` at `_dmarc.<domain>`, then \
                 tighten to `p=quarantine` and `p=reject` once the reports are clean.",
                json!({ "domain": domain, "has_mx": email.has_mx }),
            ));
        } else if !email.dmarc.enforced {
            let severity = match email.dmarc.policy.as_deref() {
                Some("quarantine") => FindingSeverity::Low,
                _ => FindingSeverity::Medium,
            };
            findings.push(finding(
                "weak_dmarc_policy",
                severity,
                "DMARC Policy Is Not Enforcing",
                format!(
                    "The DMARC policy for {} is `p={}`{}. {}",
                    domain,
                    email.dmarc.policy.as_deref().unwrap_or("none"),
                    if email.dmarc.percentage < 100 {
                        format!(" applied to {}% of mail", email.dmarc.percentage)
                    } else {
                        String::new()
                    },
                    email.dmarc.issues.join(" ")
                ),
                "Move to `p=reject; pct=100` once aggregate reports show every legitimate source \
                 passing SPF or DKIM with alignment.",
                json!({
                    "domain": domain,
                    "policy": email.dmarc.policy,
                    "subdomain_policy": email.dmarc.subdomain_policy,
                    "percentage": email.dmarc.percentage,
                    "issues": email.dmarc.issues,
                    "record": email.dmarc.record,
                }),
            ));
        }

        if email.has_mx && email.dkim_selectors_found.is_empty() {
            findings.push(finding(
                "missing_dkim",
                FindingSeverity::Low,
                "No DKIM Selector Found",
                format!(
                    "None of the {} common DKIM selectors probed returned a key for {}. DKIM \
                     selectors cannot be enumerated from DNS — they are only visible in a signed \
                     message — so this is not proof that DKIM is absent, only that no default \
                     selector answered.",
                    email.dkim_probed, domain
                ),
                "Confirm from a signed message's `DKIM-Signature: s=` tag which selector is in use. \
                 If none is, enable DKIM signing at the mail provider.",
                json!({
                    "domain": domain,
                    "selectors_probed": email.dkim_probed,
                    "selectors_found": email.dkim_selectors_found,
                    "inconclusive": true,
                }),
            ));
        }

        if email.has_mx && !email.mta_sts.dns_record_present {
            findings.push(finding(
                "missing_mta_sts",
                FindingSeverity::Low,
                "Missing MTA-STS Policy",
                format!(
                    "{} receives mail but publishes no MTA-STS policy. SMTP's STARTTLS is \
                     opportunistic: an attacker on the path can strip it and the sending server will \
                     deliver in cleartext without warning. MTA-STS is what makes TLS mandatory.",
                    domain
                ),
                "Publish `v=STSv1; id=<timestamp>` at `_mta-sts.<domain>` and serve a policy in \
                 `enforce` mode at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.",
                json!({ "domain": domain }),
            ));
        } else if !email.mta_sts.issues.is_empty() {
            findings.push(finding(
                "mta_sts_misconfigured",
                FindingSeverity::Low,
                "MTA-STS Policy Is Not Enforcing",
                format!(
                    "The MTA-STS policy for {} is published but not effective: {}",
                    domain,
                    email.mta_sts.issues.join(" ")
                ),
                "Set `mode: enforce` in the policy file and `max_age` to at least 604800.",
                json!({
                    "domain": domain,
                    "mode": email.mta_sts.mode,
                    "max_age": email.mta_sts.max_age,
                    "issues": email.mta_sts.issues,
                }),
            ));
        }

        if email.has_mx && !email.tls_rpt.present {
            findings.push(finding(
                "missing_tls_rpt",
                FindingSeverity::Info,
                "Missing SMTP TLS Reporting",
                format!(
                    "{} publishes no TLS-RPT record, so no reports arrive when a sending server fails \
                     to establish TLS with its mail servers. A downgrade attack in progress would be \
                     invisible.",
                    domain
                ),
                "Publish `v=TLSRPTv1; rua=mailto:tlsrpt@<domain>` at `_smtp._tls.<domain>`.",
                json!({ "domain": domain }),
            ));
        }

        // ---- DNSSEC ------------------------------------------------------------
        if result.dnssec.checked && !result.dnssec.zone_signed {
            findings.push(finding(
                "missing_dnssec",
                FindingSeverity::Low,
                "DNSSEC Not Enabled",
                format!(
                    "{} is not signed with DNSSEC, so answers for this domain carry no origin \
                     authentication. A resolver that is poisoned, or an on-path attacker, can \
                     substitute any address without detection.",
                    domain
                ),
                "Enable DNSSEC at the DNS provider and publish the resulting DS record through the \
                 registrar so the delegation is signed too.",
                json!({ "domain": domain }),
            ));
        }
        if result.dnssec.island_of_security {
            findings.push(finding(
                "dnssec_misconfigured",
                FindingSeverity::Medium,
                "DNSSEC Signed but Not Anchored",
                format!(
                    "{} publishes {} DNSKEY record(s) but the parent zone has no DS record. Validating \
                     resolvers cannot anchor the signatures, so the zone is signed at cost and \
                     validated by nobody.",
                    domain, result.dnssec.dnskey_count
                ),
                "Publish the DS record at the registrar to complete the chain of trust.",
                json!({
                    "domain": domain,
                    "dnskey_count": result.dnssec.dnskey_count,
                    "ds_count": result.dnssec.ds_count,
                }),
            ));
        }
        if result.dnssec.delegation_signed && !result.dnssec.zone_signed {
            findings.push(finding(
                "dnssec_misconfigured",
                FindingSeverity::High,
                "Broken DNSSEC Chain of Trust",
                format!(
                    "The parent zone publishes a DS record for {} but the zone itself serves no \
                     DNSKEY. Every validating resolver — which today includes most large public \
                     resolvers — returns SERVFAIL, so the domain is unreachable for a large share of \
                     users.",
                    domain
                ),
                "Either restore the zone's DNSKEY records or remove the DS record at the registrar.",
                json!({ "domain": domain, "ds_count": result.dnssec.ds_count }),
            ));
        }

        // ---- CAA ---------------------------------------------------------------
        if !result.caa_present {
            findings.push(finding(
                "missing_caa",
                FindingSeverity::Low,
                "Missing CAA Records",
                format!(
                    "{} publishes no CAA records, so every public certificate authority is permitted \
                     to issue for it. CAA is the only DNS-level control over misissuance.",
                    domain
                ),
                "Publish CAA records naming the CAs you use, e.g. `0 issue \"letsencrypt.org\"`, plus \
                 `0 iodef \"mailto:security@<domain>\"` to be notified of blocked attempts.",
                json!({ "domain": domain }),
            ));
        } else {
            let has_iodef = result.records.caa.iter().any(|c| c.tag == "iodef");
            let has_issuewild = result.records.caa.iter().any(|c| c.tag == "issuewild");
            if !has_iodef || !has_issuewild {
                let mut gaps = Vec::new();
                if !has_issuewild {
                    gaps.push(
                        "no `issuewild` record, so wildcard issuance falls back to the `issue` policy",
                    );
                }
                if !has_iodef {
                    gaps.push("no `iodef` record, so blocked issuance attempts are never reported");
                }
                findings.push(finding(
                    "caa_incomplete",
                    FindingSeverity::Info,
                    "CAA Policy Is Incomplete",
                    format!("{} restricts issuance but {}.", domain, gaps.join(", and ")),
                    "Add `issuewild` and `iodef` records to complete the policy.",
                    json!({ "domain": domain, "caa_records": result.records.caa }),
                ));
            }
        }
        if !result.nameservers.issues.is_empty() {
            let issues = &result.nameservers.issues;
            // The worst issue sets the finding's severity.
            let severity = issues
                .iter()
                .map(|issue| FindingSeverity::from(issue.severity.as_str()))
                .max_by_key(|severity| match severity {
                    FindingSeverity::Critical => 5,
                    FindingSeverity::High => 4,
                    FindingSeverity::Medium => 3,
                    FindingSeverity::Low => 2,
                    FindingSeverity::Info => 1,
                })
                .unwrap_or(FindingSeverity::Low);
            findings.push(finding(
                "nameserver_misconfigured",
                severity,
                "Nameserver Configuration Weakness",
                format!(
                    "{} {}",
                    domain,
                    issues
                        .iter()
                        .map(|issue| issue.message.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                "Delegate at least two nameservers, hosted on separate networks, each answering \
                 authoritatively for the zone.",
                json!({
                    "domain": domain,
                    "issues": issues,
                    "nameservers": result.nameservers.nameservers,
                    "distinct_networks": result.nameservers.distinct_networks,
                    "distinct_providers": result.nameservers.distinct_providers,
                }),
            ));
        }
    }

    // ---- Zone structure ----------------------------------------------------
    // One finding carrying every issue, rather than one per issue.
    //
    // Findings are deduplicated on `(asset_id, finding_type, title)`, and the
    // update path does not rewrite the description — so several findings sharing
    // the title "Nameserver Configuration Weakness" would collapse into one row
    // that keeps the first issue's text and the last one's severity, silently
    // losing the rest.
    if let Some(soa) = &result.records.soa {
        if !soa.issues.is_empty() {
            findings.push(finding(
                "soa_misconfigured",
                FindingSeverity::Info,
                "SOA Timers Outside Recommended Ranges",
                format!(
                    "The SOA record for {} uses timers outside the ranges in RFC 1912 §2.2 and RFC \
                     2308: {}",
                    domain,
                    soa.issues.join(" ")
                ),
                "Adjust the SOA refresh, retry, expire and minimum values to the recommended \
                 ranges.",
                json!({ "domain": domain, "soa": soa }),
            ));
        }
    }

    if result.cname_at_apex {
        findings.push(finding(
            "dns_misconfiguration",
            FindingSeverity::Low,
            "CNAME Record at the Zone Apex",
            format!(
                "{} serves a CNAME at the apex alongside its SOA and NS records. RFC 1034 §3.6.2 \
                 forbids this, and resolvers handle it inconsistently — some ignore the other \
                 records, which can break mail delivery.",
                domain
            ),
            "Replace the apex CNAME with A/AAAA records, or use the provider's ALIAS/ANAME \
             equivalent, which resolves server-side.",
            json!({ "domain": domain, "cname": result.records.cname }),
        ));
    }

    if !result.internal_addresses.is_empty() {
        findings.push(finding(
            "information_disclosure",
            FindingSeverity::Low,
            "Internal IP Addresses in Public DNS",
            format!(
                "Public DNS for {} returns {} address(es) from private or reserved ranges: {}. \
                 This publishes the internal addressing plan to anyone who asks, which is \
                 reconnaissance an attacker would otherwise have to work for.",
                domain,
                result.internal_addresses.len(),
                result.internal_addresses.join(", ")
            ),
            "Serve internal addresses from a split-horizon or internal-only zone.",
            json!({ "domain": domain, "addresses": result.internal_addresses }),
        ));
    }

    if result.wildcard.enabled {
        findings.push(finding(
            "dns_misconfiguration",
            FindingSeverity::Info,
            "Wildcard DNS Record",
            format!(
                "Every name under {} resolves, including ones that were never configured — a \
                 probe for a random label returned {}. Wildcards mask typos and decommissioned \
                 hosts, and they make it impossible to tell a real subdomain from an invented one.",
                domain,
                result.wildcard.resolved_to.join(", ")
            ),
            "Replace the wildcard with explicit records where possible, so that an unconfigured \
             name fails as it should.",
            json!({ "domain": domain, "resolved_to": result.wildcard.resolved_to }),
        ));
    }

    findings
}

/// A 0–100 hygiene score and its letter, using the same deduction shape as the
/// rest of the product: start clean, subtract for what is actually wrong.
fn score_dns(result: &DnsScanResult, findings: &[ScanFinding]) -> (u8, String) {
    let mut score: i32 = 100;
    for finding in findings {
        score -= match finding.severity {
            FindingSeverity::Critical => 40,
            FindingSeverity::High => 25,
            FindingSeverity::Medium => 12,
            FindingSeverity::Low => 5,
            FindingSeverity::Info => 1,
        };
    }
    // Credit for the controls that are genuinely hard to deploy and rarely are.
    if result.dnssec.zone_signed && result.dnssec.delegation_signed {
        score += 5;
    }
    if result.email.dmarc.enforced {
        score += 5;
    }
    if result.email.mta_sts.mode.as_deref() == Some("enforce") {
        score += 3;
    }

    let score = score.clamp(0, 100) as u8;
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        55..=69 => "D",
        40..=54 => "E",
        _ => "F",
    };
    (score, grade.to_string())
}

/// Group findings by type, for the summary the UI shows.
pub fn findings_by_type(findings: &[ScanFinding]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for finding in findings {
        *counts.entry(finding.finding_type.clone()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::scanners::email_auth::SpfQualifier;

    fn clean_result() -> DnsScanResult {
        let mut spf = email_auth::parse_spf_record("v=spf1 include:_spf.example.com -all");
        email_auth::evaluate_spf(&mut spf, 3);
        let mut dmarc =
            email_auth::parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:d@example.com");
        email_auth::evaluate_dmarc(&mut dmarc);

        DnsScanResult {
            domain: "example.com".into(),
            is_zone_apex: true,
            records: DnsRecordInventory {
                caa: vec![
                    CaaRecord { flags: 0, tag: "issue".into(), value: "letsencrypt.org".into() },
                    CaaRecord { flags: 0, tag: "issuewild".into(), value: ";".into() },
                    CaaRecord { flags: 0, tag: "iodef".into(), value: "mailto:s@example.com".into() },
                ],
                ..Default::default()
            },
            email: EmailSecurityResult {
                has_mx: true,
                mx_hosts: vec!["mail.example.com".into()],
                spf,
                dmarc,
                dkim_selectors_found: vec!["default".into()],
                dkim_probed: 12,
                mta_sts: MtaStsAnalysis {
                    dns_record_present: true,
                    mode: Some("enforce".into()),
                    max_age: Some(604_800),
                    policy_fetched: true,
                    ..Default::default()
                },
                tls_rpt: SimpleRecordCheck { present: true, ..Default::default() },
                bimi: SimpleRecordCheck::default(),
                dane_hosts: vec![],
            },
            dnssec: DnssecResult {
                zone_signed: true,
                delegation_signed: true,
                dnskey_count: 2,
                ds_count: 1,
                island_of_security: false,
                checked: true,
                issues: vec![],
            },
            nameservers: NameserverResult {
                count: 2,
                distinct_providers: 2,
                distinct_networks: 2,
                ipv6_capable: true,
                nameservers: vec![],
                issues: vec![],
            },
            caa_present: true,
            zone_transfer_possible: false,
            takeover: TakeoverResult::default(),
            wildcard: WildcardResult::default(),
            internal_addresses: vec![],
            cname_at_apex: false,
            score: 100,
            grade: "A".into(),
            errors: vec![],
            scan_duration_ms: 0,
        }
    }

    fn types(findings: &[ScanFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.finding_type.as_str()).collect()
    }

    #[test]
    fn a_well_configured_domain_produces_no_findings() {
        let findings = build_findings(&clean_result());
        assert!(findings.is_empty(), "unexpected findings: {:?}", types(&findings));
        let (score, grade) = score_dns(&clean_result(), &findings);
        assert_eq!(score, 100);
        assert_eq!(grade, "A");
    }

    #[test]
    fn every_emitted_type_is_declared() {
        // Drive the builder through the states that produce each rule, and check
        // nothing escapes the declared set.
        let mut result = clean_result();
        result.email.spf = SpfAnalysis::default();
        result.email.dmarc = DmarcAnalysis::default();
        result.email.dkim_selectors_found.clear();
        result.email.mta_sts = MtaStsAnalysis::default();
        result.email.tls_rpt = SimpleRecordCheck::default();
        result.caa_present = false;
        result.records.caa.clear();
        result.dnssec = DnssecResult { checked: true, island_of_security: true, zone_signed: true, ..Default::default() };
        result.takeover = TakeoverResult { dangling: true, claimable: true, ..Default::default() };
        result.wildcard = WildcardResult { enabled: true, resolved_to: vec!["192.0.2.1".into()] };
        result.internal_addresses = vec!["10.0.0.1".into()];
        result.cname_at_apex = true;
        result.nameservers.issues = vec![NameserverIssue {
            severity: "low".into(),
            message: "Only one nameserver is delegated.".into(),
        }];
        result.records.soa = Some(SoaRecord {
            primary_ns: "ns1.example.com".into(),
            responsible: "hostmaster.example.com".into(),
            serial: 1,
            refresh: 60,
            retry: 30,
            expire: 100,
            minimum: 10,
            issues: vec!["SOA refresh is 60s".into()],
        });
        result.nameservers.nameservers = vec![NameserverInfo {
            hostname: "ns1.example.com".into(),
            addresses: vec!["192.0.2.1".into()],
            resolvable: true,
            answers_for_zone: true,
            zone_transfer: "transferred".into(),
            zone_transfer_records: Some(10),
        }];

        let findings = build_findings(&result);
        assert!(findings.len() >= 12, "expected broad coverage, got {}", findings.len());
        for finding in &findings {
            assert!(
                EMITTED_FINDING_TYPES.contains(&finding.finding_type.as_str()),
                "undeclared finding type {}",
                finding.finding_type
            );
        }
    }

    #[test]
    fn zone_transfer_is_reported_per_nameserver() {
        let mut result = clean_result();
        result.nameservers.nameservers = vec![
            NameserverInfo {
                hostname: "ns1.example.com".into(),
                addresses: vec!["192.0.2.1".into()],
                resolvable: true,
                answers_for_zone: true,
                zone_transfer: "transferred".into(),
                zone_transfer_records: Some(412),
            },
            NameserverInfo {
                hostname: "ns2.example.com".into(),
                addresses: vec!["198.51.100.1".into()],
                resolvable: true,
                answers_for_zone: true,
                zone_transfer: "refused".into(),
                zone_transfer_records: None,
            },
        ];
        let findings = build_findings(&result);
        let transfers: Vec<&ScanFinding> = findings
            .iter()
            .filter(|f| f.finding_type == "zone_transfer_allowed")
            .collect();
        assert_eq!(transfers.len(), 1, "only the permissive nameserver is reported");
        assert_eq!(transfers[0].severity, FindingSeverity::High);
        assert!(transfers[0].description.contains("412 records"));
    }

    #[test]
    fn missing_spf_severity_depends_on_whether_mail_is_received() {
        let mut with_mx = clean_result();
        with_mx.email.spf = SpfAnalysis::default();
        let findings = build_findings(&with_mx);
        let spf = findings.iter().find(|f| f.finding_type == "missing_spf").unwrap();
        assert_eq!(spf.severity, FindingSeverity::Medium);

        let mut without_mx = with_mx.clone();
        without_mx.email.has_mx = false;
        let findings = build_findings(&without_mx);
        let spf = findings.iter().find(|f| f.finding_type == "missing_spf").unwrap();
        assert_eq!(spf.severity, FindingSeverity::Low);
    }

    #[test]
    fn a_permissive_spf_is_high_severity() {
        let mut result = clean_result();
        let mut spf = email_auth::parse_spf_record("v=spf1 +all");
        email_auth::evaluate_spf(&mut spf, 0);
        result.email.spf = spf;
        let findings = build_findings(&result);
        let weak = findings.iter().find(|f| f.finding_type == "weak_spf_policy").unwrap();
        assert_eq!(weak.severity, FindingSeverity::High);
        assert_eq!(result.email.spf.all_qualifier, Some(SpfQualifier::Pass));
    }

    #[test]
    fn the_spf_lookup_limit_is_its_own_finding() {
        let mut result = clean_result();
        let mut spf = email_auth::parse_spf_record("v=spf1 include:a.example -all");
        email_auth::evaluate_spf(&mut spf, 14);
        result.email.spf = spf;
        let findings = build_findings(&result);
        let limit = findings
            .iter()
            .find(|f| f.finding_type == "spf_lookup_limit_exceeded")
            .unwrap();
        assert_eq!(limit.severity, FindingSeverity::Medium);
        assert!(limit.description.contains("14 DNS lookups"));
    }

    #[test]
    fn a_broken_dnssec_chain_outranks_a_missing_one() {
        let mut broken = clean_result();
        broken.dnssec = DnssecResult {
            zone_signed: false,
            delegation_signed: true,
            ds_count: 1,
            checked: true,
            ..Default::default()
        };
        let findings = build_findings(&broken);
        let dnssec = findings
            .iter()
            .find(|f| f.finding_type == "dnssec_misconfigured")
            .unwrap();
        assert_eq!(dnssec.severity, FindingSeverity::High);
        assert!(dnssec.description.contains("SERVFAIL"));

        let mut island = clean_result();
        island.dnssec = DnssecResult {
            zone_signed: true,
            delegation_signed: false,
            dnskey_count: 2,
            island_of_security: true,
            checked: true,
            ..Default::default()
        };
        let findings = build_findings(&island);
        let dnssec = findings
            .iter()
            .find(|f| f.finding_type == "dnssec_misconfigured")
            .unwrap();
        assert_eq!(dnssec.severity, FindingSeverity::Medium);
    }

    #[test]
    fn zone_level_checks_do_not_fire_on_a_subdomain() {
        // An asset inventory is mostly subdomains. `www.example.com` has no NS,
        // no DNSKEY, no CAA and no SPF of its own because the zone holds them —
        // reporting each as missing would bury the real findings.
        let mut subdomain = clean_result();
        subdomain.domain = "www.example.com".into();
        subdomain.is_zone_apex = false;
        subdomain.email.spf = SpfAnalysis::default();
        subdomain.email.dmarc = DmarcAnalysis::default();
        subdomain.email.mta_sts = MtaStsAnalysis::default();
        subdomain.email.tls_rpt = SimpleRecordCheck::default();
        subdomain.caa_present = false;
        subdomain.records.caa.clear();
        subdomain.dnssec = DnssecResult { checked: true, ..Default::default() };
        subdomain.nameservers.count = 0;
        subdomain.nameservers.issues = vec![NameserverIssue {
            severity: "high".into(),
            message: "No NS records were returned for the zone.".into(),
        }];

        let findings = build_findings(&subdomain);
        for zone_only in [
            "missing_spf",
            "missing_dmarc",
            "missing_caa",
            "missing_dnssec",
            "missing_mta_sts",
            "missing_tls_rpt",
            "nameserver_misconfigured",
            // The `else` branches of the same checks, which per-condition gating
            // had missed.
            "weak_spf_policy",
            "weak_dmarc_policy",
            "caa_incomplete",
            "dnssec_misconfigured",
            "missing_dkim",
            "mta_sts_misconfigured",
        ] {
            assert!(
                !types(&findings).contains(&zone_only),
                "{} must not be reported on a subdomain; got {:?}",
                zone_only,
                types(&findings)
            );
        }

        // The same state at an apex does produce them.
        let mut apex = subdomain.clone();
        apex.domain = "example.com".into();
        apex.is_zone_apex = true;
        let findings = build_findings(&apex);
        assert!(types(&findings).contains(&"missing_spf"));
        assert!(types(&findings).contains(&"missing_dnssec"));
        assert!(types(&findings).contains(&"nameserver_misconfigured"));

        // A weak-but-present policy is an `else` branch; it must be gated the
        // same way.
        let mut weak_subdomain = clean_result();
        weak_subdomain.is_zone_apex = false;
        weak_subdomain.records.caa = vec![CaaRecord {
            flags: 0,
            tag: "issue".into(),
            value: "letsencrypt.org".into(),
        }];
        let mut dmarc = email_auth::parse_dmarc_record("v=DMARC1; p=none; rua=mailto:d@e.com");
        email_auth::evaluate_dmarc(&mut dmarc);
        weak_subdomain.email.dmarc = dmarc;
        let findings = build_findings(&weak_subdomain);
        assert!(!types(&findings).contains(&"weak_dmarc_policy"));
        assert!(!types(&findings).contains(&"caa_incomplete"));
    }

    #[test]
    fn subdomain_takeover_is_still_checked_below_the_apex() {
        // Takeover is a property of the record, not the zone, and subdomains are
        // where it actually happens — so it must survive the apex gate.
        let mut subdomain = clean_result();
        subdomain.is_zone_apex = false;
        subdomain.takeover = TakeoverResult {
            dangling: true,
            cname_target: Some("gone.herokuapp.com".into()),
            service: Some("Heroku".into()),
            evidence: Some("no-such-app page".into()),
            claimable: true,
        };
        subdomain.internal_addresses = vec!["10.0.0.1".into()];
        let findings = build_findings(&subdomain);
        assert!(types(&findings).contains(&"dangling_dns"));
        assert!(types(&findings).contains(&"information_disclosure"));
    }

    #[test]
    fn an_apex_cname_needs_an_apex() {
        // A CNAME on a subdomain is ordinary; only one alongside a SOA is the
        // RFC 1034 violation.
        let mut subdomain = clean_result();
        subdomain.cname_at_apex = false;
        assert!(!types(&build_findings(&subdomain)).contains(&"dns_misconfiguration"));

        let mut apex = clean_result();
        apex.cname_at_apex = true;
        let findings = build_findings(&apex);
        let cname = findings
            .iter()
            .find(|f| f.title.contains("Zone Apex"))
            .expect("an apex CNAME is a finding");
        assert_eq!(cname.severity, FindingSeverity::Low);
    }

    #[test]
    fn a_totally_lame_delegation_is_reported_not_skipped() {
        // The worst case — no nameserver answers — used to fall through the
        // `lame.len() < count` guard and produce nothing at all.
        let mut result = clean_result();
        result.nameservers.issues = vec![NameserverIssue {
            severity: "medium".into(),
            message: "None of the 2 delegated nameservers answered authoritatively for the zone."
                .into(),
        }];
        let findings = build_findings(&result);
        let ns = findings
            .iter()
            .find(|f| f.finding_type == "nameserver_misconfigured")
            .expect("an entirely lame delegation must be reported");
        assert_eq!(ns.severity, FindingSeverity::Medium);
    }

    #[test]
    fn nameserver_issues_become_one_finding_not_several() {
        // Findings dedupe on (asset, type, title); several sharing a title would
        // collapse into one row and lose all but the first description.
        let mut result = clean_result();
        result.nameservers.issues = vec![
            NameserverIssue {
                severity: "low".into(),
                message: "Only one nameserver is delegated.".into(),
            },
            NameserverIssue {
                severity: "medium".into(),
                message: "1 of 1 delegated nameservers do not answer authoritatively for the \
                          zone (lame delegation): ns1.example.com"
                    .into(),
            },
        ];
        let findings = build_findings(&result);
        let ns: Vec<&ScanFinding> = findings
            .iter()
            .filter(|f| f.finding_type == "nameserver_misconfigured")
            .collect();
        assert_eq!(ns.len(), 1, "one row, carrying every issue");
        assert!(ns[0].description.contains("Only one nameserver"));
        assert!(ns[0].description.contains("lame delegation"));
        // The worst issue sets the severity.
        assert_eq!(ns[0].severity, FindingSeverity::Medium);
    }

    #[test]
    fn a_failed_ns_lookup_is_not_a_missing_delegation() {
        let mut result = clean_result();
        result.nameservers.count = 0;
        result.nameservers.issues = vec![NameserverIssue {
            severity: "info".into(),
            message: "The NS lookup did not answer, so the delegation could not be checked."
                .into(),
        }];
        let findings = build_findings(&result);
        let ns = findings
            .iter()
            .find(|f| f.finding_type == "nameserver_misconfigured")
            .unwrap();
        // Not High: nothing was established about the delegation.
        assert_eq!(ns.severity, FindingSeverity::Info);

        // A real empty answer still is.
        result.nameservers.issues = vec![NameserverIssue {
            severity: "high".into(),
            message: "No NS records were returned for the zone.".into(),
        }];
        let findings = build_findings(&result);
        let ns = findings
            .iter()
            .find(|f| f.finding_type == "nameserver_misconfigured")
            .unwrap();
        assert_eq!(ns.severity, FindingSeverity::High);
    }

    #[test]
    fn an_unchecked_dnssec_state_reports_nothing() {
        // A query failure must not be rendered as "DNSSEC is off".
        let mut result = clean_result();
        result.dnssec = DnssecResult { checked: false, ..Default::default() };
        let findings = build_findings(&result);
        assert!(!types(&findings).contains(&"missing_dnssec"));
    }

    #[test]
    fn takeover_severity_follows_claimability() {
        let mut result = clean_result();
        result.takeover = TakeoverResult {
            dangling: true,
            cname_target: Some("gone.herokuapp.com".into()),
            service: Some("Heroku".into()),
            evidence: Some("served the no-such-app page".into()),
            claimable: true,
        };
        let findings = build_findings(&result);
        let takeover = findings.iter().find(|f| f.finding_type == "dangling_dns").unwrap();
        assert_eq!(takeover.severity, FindingSeverity::High);

        result.takeover.claimable = false;
        let findings = build_findings(&result);
        let takeover = findings.iter().find(|f| f.finding_type == "dangling_dns").unwrap();
        assert_eq!(takeover.severity, FindingSeverity::Medium);
    }

    #[test]
    fn dkim_absence_is_reported_as_inconclusive() {
        let mut result = clean_result();
        result.email.dkim_selectors_found.clear();
        let findings = build_findings(&result);
        let dkim = findings.iter().find(|f| f.finding_type == "missing_dkim").unwrap();
        assert_eq!(dkim.severity, FindingSeverity::Low);
        assert!(dkim.description.contains("not proof"));
        assert_eq!(dkim.data["inconclusive"], serde_json::json!(true));
    }

    #[test]
    fn private_addresses_in_public_dns_are_reported() {
        let mut result = clean_result();
        result.internal_addresses = vec!["10.0.0.5".into(), "192.168.1.1".into()];
        let findings = build_findings(&result);
        assert!(types(&findings).contains(&"information_disclosure"));
    }

    #[test]
    fn internal_ranges_are_classified_correctly() {
        for private in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"] {
            assert!(is_internal(private.parse().unwrap()), "{} should be internal", private);
        }
        for public in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1"] {
            assert!(!is_internal(public.parse().unwrap()), "{} should be public", public);
        }
        assert!(is_internal("fd00::1".parse().unwrap()));
        assert!(is_internal("fe80::1".parse().unwrap()));
        assert!(!is_internal("2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn nameserver_diversity_uses_networks_not_addresses() {
        assert_eq!(network_key("192.0.2.10".parse().unwrap()), "192.0.2.0/24");
        assert_eq!(network_key("192.0.2.200".parse().unwrap()), "192.0.2.0/24");
        assert_ne!(
            network_key("192.0.2.1".parse().unwrap()),
            network_key("198.51.100.1".parse().unwrap())
        );
        assert_eq!(provider_key("ns1.example-dns.com"), "example-dns.com");
        assert_eq!(provider_key("ns2.example-dns.com"), "example-dns.com");
        assert_ne!(provider_key("ns1.a-dns.com"), provider_key("ns1.b-dns.net"));
    }

    #[test]
    fn score_deducts_by_severity_and_credits_hard_controls() {
        let clean = clean_result();
        let (score, _) = score_dns(&clean, &[]);
        // 100 capped, despite +13 of credits.
        assert_eq!(score, 100);

        let mut broken = clean_result();
        broken.zone_transfer_possible = true;
        broken.nameservers.nameservers = vec![NameserverInfo {
            hostname: "ns1.example.com".into(),
            addresses: vec!["192.0.2.1".into()],
            resolvable: true,
            answers_for_zone: true,
            zone_transfer: "transferred".into(),
            zone_transfer_records: Some(10),
        }];
        let findings = build_findings(&broken);
        let (score, grade) = score_dns(&broken, &findings);
        assert!(score < 100, "a zone transfer must cost points");
        assert_ne!(grade, "A");
    }

    #[test]
    fn caa_completeness_is_only_informational() {
        let mut result = clean_result();
        result.records.caa = vec![CaaRecord {
            flags: 0,
            tag: "issue".into(),
            value: "letsencrypt.org".into(),
        }];
        let findings = build_findings(&result);
        let caa = findings.iter().find(|f| f.finding_type == "caa_incomplete").unwrap();
        assert_eq!(caa.severity, FindingSeverity::Info);
        assert!(caa.description.contains("issuewild"));
        assert!(caa.description.contains("iodef"));
    }
}

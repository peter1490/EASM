//! Exploitation threat intelligence: CISA KEV and FIRST EPSS.
//!
//! A CVSS base score says how bad a vulnerability would be if exploited. It
//! says nothing about whether anyone is exploiting it, and on its own it is not
//! a prioritisation: "CVSS >= 7" selects roughly half of every CVE ever
//! published. Two public feeds close that gap, and both are free and
//! unauthenticated:
//!
//! * **CISA KEV** — the Known Exploited Vulnerabilities catalogue. Membership
//!   is evidence of *observed* exploitation, and for US federal agencies it
//!   carries a legally binding remediation deadline. It is a small, curated
//!   list (a few thousand CVEs), so it is high-precision and low-recall.
//! * **FIRST EPSS** — a daily-updated probability that a CVE will be exploited
//!   in the next 30 days. High-recall, and the right tie-breaker among the
//!   thousands of CVEs that are not in KEV.
//!
//! Neither replaces the other, and neither may be used to *suppress* a finding:
//! EPSS is trained on observed exploitation volume, so a freshly disclosed
//! high-impact bug scores low precisely when it matters most. They only ever
//! promote.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// CISA's published JSON feed of the KEV catalogue.
const KEV_FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// FIRST's EPSS query API.
const EPSS_API_BASE: &str = "https://api.first.org/data/v1/epss";

/// CISA revises the catalogue at most a couple of times a day.
const KEV_TTL: Duration = Duration::from_secs(6 * 60 * 60);
/// EPSS republishes once a day.
const EPSS_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// The EPSS API accepts a comma-separated list; keep requests to a sane size.
const EPSS_BATCH: usize = 100;
/// Both feeds are optional enrichment — never let them stall a scan.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A CVE's entry in the CISA Known Exploited Vulnerabilities catalogue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KevEntry {
    /// Date CISA added the CVE to the catalogue (ISO-8601 date).
    pub date_added: String,
    /// Federal remediation deadline CISA set for it.
    pub due_date: Option<String>,
    /// Whether CISA has linked the CVE to a known ransomware campaign.
    pub known_ransomware_campaign_use: bool,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
}

/// A CVE's EPSS scores.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct EpssScore {
    /// Probability of exploitation in the next 30 days, 0.0–1.0.
    pub probability: f64,
    /// Rank of that probability among all scored CVEs, 0.0–1.0.
    pub percentile: f64,
}

/// Everything the threat feeds know about one CVE.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatContext {
    pub kev: Option<KevEntry>,
    pub epss: Option<EpssScore>,
}

impl ThreatContext {
    /// True when there is direct evidence of real-world exploitation.
    pub fn is_known_exploited(&self) -> bool {
        self.kev.is_some()
    }

    /// The threat term of the priority score, 0.0–5.0.
    ///
    /// Observed exploitation saturates it: once a CVE is in KEV, no probability
    /// estimate adds information. Otherwise the EPSS probability is mapped
    /// through a log scale, because the EPSS distribution is extremely
    /// right-skewed — a probability of 0.1 already sits around the 88th
    /// percentile, so a linear mapping would flatten almost every CVE to zero.
    /// Each tenfold increase in probability adds 1.25 points.
    pub fn threat_score(&self) -> f64 {
        if self.is_known_exploited() {
            return 5.0;
        }
        match self.epss {
            Some(EpssScore { probability, .. }) if probability > 0.0 => {
                let scaled = (probability.log10() + 4.0) / 4.0;
                5.0 * scaled.clamp(0.0, 1.0)
            }
            _ => 0.0,
        }
    }

    /// Combined 0–10 priority for a CVE with the given CVSS base score.
    ///
    /// Half the range comes from severity and half from exploitation evidence,
    /// so a critical-but-unexploited bug and a medium-but-actively-exploited
    /// one land in the same neighbourhood rather than one dominating.
    pub fn priority_score(&self, cvss_base: Option<f64>) -> f64 {
        let severity = cvss_base.unwrap_or(5.0).clamp(0.0, 10.0) / 2.0;
        (severity + self.threat_score()).clamp(0.0, 10.0)
    }
}

lazy_static! {
    static ref KEV_CACHE: RwLock<Option<(Instant, Arc<HashMap<String, KevEntry>>)>> =
        RwLock::new(None);
    static ref EPSS_CACHE: RwLock<HashMap<String, (Instant, Option<EpssScore>)>> =
        RwLock::new(HashMap::new());
}

/// Client for the CISA KEV and FIRST EPSS feeds.
pub struct ThreatIntelClient {
    client: Client,
}

impl ThreatIntelClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent("EASM-Scanner/1.0")
            .build()
            .unwrap_or_default();
        ThreatIntelClient { client }
    }

    /// Look up threat context for a batch of CVE ids.
    ///
    /// Both lookups are best-effort: if a feed is unreachable the corresponding
    /// field stays `None` and the caller falls back to CVSS alone, rather than
    /// the scan failing over enrichment it can live without.
    pub async fn context_for(&self, cve_ids: &[String]) -> HashMap<String, ThreatContext> {
        let mut out: HashMap<String, ThreatContext> = cve_ids
            .iter()
            .map(|id| (id.to_uppercase(), ThreatContext::default()))
            .collect();

        if let Some(kev) = self.kev_catalog().await {
            for (id, ctx) in out.iter_mut() {
                ctx.kev = kev.get(id).cloned();
            }
        }

        for (id, score) in self.epss_scores(cve_ids).await {
            if let Some(ctx) = out.get_mut(&id) {
                ctx.epss = score;
            }
        }

        out
    }

    /// The KEV catalogue as a CVE-id map, fetched at most once per TTL.
    async fn kev_catalog(&self) -> Option<Arc<HashMap<String, KevEntry>>> {
        if let Ok(guard) = KEV_CACHE.read() {
            if let Some((fetched_at, catalog)) = guard.as_ref() {
                if fetched_at.elapsed() <= KEV_TTL {
                    return Some(Arc::clone(catalog));
                }
            }
        }

        let text = match self.client.get(KEV_FEED_URL).send().await {
            Ok(resp) if resp.status().is_success() => resp.text().await.ok()?,
            Ok(resp) => {
                tracing::warn!("CISA KEV feed returned {}", resp.status());
                return None;
            }
            Err(e) => {
                tracing::warn!("CISA KEV feed unreachable: {}", e);
                return None;
            }
        };

        let catalog = Arc::new(parse_kev_feed(&text)?);
        tracing::info!("Loaded {} CISA KEV entries", catalog.len());
        if let Ok(mut guard) = KEV_CACHE.write() {
            *guard = Some((Instant::now(), Arc::clone(&catalog)));
        }
        Some(catalog)
    }

    /// EPSS scores for the given CVEs, served from cache where possible.
    async fn epss_scores(&self, cve_ids: &[String]) -> HashMap<String, Option<EpssScore>> {
        let mut out: HashMap<String, Option<EpssScore>> = HashMap::new();
        let mut missing: Vec<String> = Vec::new();

        {
            let cache = EPSS_CACHE.read().ok();
            for id in cve_ids {
                let key = id.to_uppercase();
                let hit = cache.as_ref().and_then(|c| c.get(&key)).and_then(|(at, v)| {
                    if at.elapsed() <= EPSS_TTL {
                        Some(*v)
                    } else {
                        None
                    }
                });
                match hit {
                    Some(v) => {
                        out.insert(key, v);
                    }
                    None => missing.push(key),
                }
            }
        }

        for chunk in missing.chunks(EPSS_BATCH) {
            let url = format!("{}?cve={}", EPSS_API_BASE, chunk.join(","));
            let text = match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!("EPSS response unreadable: {}", e);
                        continue;
                    }
                },
                Ok(resp) => {
                    tracing::warn!("EPSS API returned {}", resp.status());
                    continue;
                }
                Err(e) => {
                    tracing::warn!("EPSS API unreachable: {}", e);
                    continue;
                }
            };

            let scores = parse_epss_response(&text);
            if let Ok(mut cache) = EPSS_CACHE.write() {
                for id in chunk {
                    // Cache the absence too: a CVE too new to be scored would
                    // otherwise be re-queried on every scan.
                    let score = scores.get(id).copied();
                    cache.insert(id.clone(), (Instant::now(), score));
                    out.insert(id.clone(), score);
                }
            } else {
                for id in chunk {
                    out.insert(id.clone(), scores.get(id).copied());
                }
            }
        }

        out
    }
}

impl Default for ThreatIntelClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse CISA's KEV feed into a CVE-id map.
fn parse_kev_feed(text: &str) -> Option<HashMap<String, KevEntry>> {
    let json: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| tracing::warn!("Malformed CISA KEV feed: {}", e))
        .ok()?;
    let items = json.get("vulnerabilities")?.as_array()?;

    let mut map = HashMap::with_capacity(items.len());
    for item in items {
        let Some(cve_id) = item.get("cveID").and_then(|v| v.as_str()) else {
            continue;
        };
        let str_field = |k: &str| {
            item.get(k)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        };
        map.insert(
            cve_id.to_uppercase(),
            KevEntry {
                date_added: str_field("dateAdded").unwrap_or_default(),
                due_date: str_field("dueDate"),
                // CISA writes this as the strings "Known"/"Unknown", not a bool.
                known_ransomware_campaign_use: item
                    .get("knownRansomwareCampaignUse")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("known")),
                vendor_project: str_field("vendorProject"),
                product: str_field("product"),
            },
        );
    }
    Some(map)
}

/// Parse a FIRST EPSS API response into a CVE-id map.
fn parse_epss_response(text: &str) -> HashMap<String, EpssScore> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        tracing::warn!("Malformed EPSS response");
        return HashMap::new();
    };
    let Some(items) = json.get("data").and_then(|v| v.as_array()) else {
        return HashMap::new();
    };

    let mut map = HashMap::with_capacity(items.len());
    for item in items {
        let Some(cve) = item.get("cve").and_then(|v| v.as_str()) else {
            continue;
        };
        // The API returns the numbers as JSON strings.
        let num = |k: &str| -> Option<f64> {
            item.get(k).and_then(|v| match v {
                serde_json::Value::String(s) => s.parse().ok(),
                serde_json::Value::Number(n) => n.as_f64(),
                _ => None,
            })
        };
        if let (Some(probability), Some(percentile)) = (num("epss"), num("percentile")) {
            map.insert(
                cve.to_uppercase(),
                EpssScore {
                    probability,
                    percentile,
                },
            );
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_cisa_kev_feed_shape() {
        let feed = r#"{
          "title": "CISA Catalog of Known Exploited Vulnerabilities",
          "count": 2,
          "vulnerabilities": [
            {"cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler ADC",
             "vulnerabilityName": "Citrix NetScaler Buffer Overflow",
             "dateAdded": "2023-10-18", "dueDate": "2023-11-08",
             "knownRansomwareCampaignUse": "Known"},
            {"cveID": "cve-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
             "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
             "knownRansomwareCampaignUse": "Unknown"}
          ]}"#;
        let map = parse_kev_feed(feed).expect("parsed");
        assert_eq!(map.len(), 2);

        let citrix = map.get("CVE-2023-4966").expect("Citrix entry");
        assert_eq!(citrix.date_added, "2023-10-18");
        assert_eq!(citrix.due_date.as_deref(), Some("2023-11-08"));
        assert!(citrix.known_ransomware_campaign_use);
        assert_eq!(citrix.product.as_deref(), Some("NetScaler ADC"));

        // Ids are normalised, so a lowercase feed entry is still findable.
        let log4j = map.get("CVE-2021-44228").expect("Log4Shell entry");
        assert!(!log4j.known_ransomware_campaign_use);
    }

    #[test]
    fn kev_parse_is_tolerant_of_missing_fields() {
        let feed = r#"{"vulnerabilities":[{"cveID":"CVE-2020-0001"},{"noCveHere":true}]}"#;
        let map = parse_kev_feed(feed).expect("parsed");
        assert_eq!(map.len(), 1);
        let e = map.get("CVE-2020-0001").unwrap();
        assert_eq!(e.date_added, "");
        assert_eq!(e.due_date, None);
        assert!(!e.known_ransomware_campaign_use);
    }

    #[test]
    fn kev_parse_rejects_junk() {
        assert!(parse_kev_feed("not json").is_none());
        assert!(parse_kev_feed(r#"{"unexpected": 1}"#).is_none());
    }

    #[test]
    fn parses_the_epss_api_shape() {
        // FIRST returns the numbers as strings.
        let body = r#"{"status":"OK","data":[
            {"cve":"CVE-2021-44228","epss":"0.944200000","percentile":"0.999950000","date":"2026-08-19"},
            {"cve":"CVE-2019-0001","epss":"0.00042","percentile":"0.10"}
        ]}"#;
        let map = parse_epss_response(body);
        assert_eq!(map.len(), 2);
        let log4j = map.get("CVE-2021-44228").unwrap();
        assert!((log4j.probability - 0.9442).abs() < 1e-9);
        assert!((log4j.percentile - 0.99995).abs() < 1e-9);
    }

    #[test]
    fn epss_parse_is_tolerant_of_junk_and_numeric_forms() {
        assert!(parse_epss_response("not json").is_empty());
        assert!(parse_epss_response(r#"{"status":"OK"}"#).is_empty());
        let numeric = r#"{"data":[{"cve":"CVE-2020-1","epss":0.5,"percentile":0.9}]}"#;
        assert_eq!(parse_epss_response(numeric).len(), 1);
        // An entry missing percentile is dropped rather than half-populated.
        let partial = r#"{"data":[{"cve":"CVE-2020-2","epss":"0.5"}]}"#;
        assert!(parse_epss_response(partial).is_empty());
    }

    fn epss(p: f64) -> ThreatContext {
        ThreatContext {
            kev: None,
            epss: Some(EpssScore {
                probability: p,
                percentile: 0.0,
            }),
        }
    }

    #[test]
    fn kev_membership_saturates_the_threat_term() {
        let kev = ThreatContext {
            kev: Some(KevEntry {
                date_added: "2023-10-18".into(),
                due_date: None,
                known_ransomware_campaign_use: true,
                vendor_project: None,
                product: None,
            }),
            epss: Some(EpssScore {
                probability: 0.0001,
                percentile: 0.1,
            }),
        };
        // Observed exploitation outranks any probability estimate, including a
        // low one — the estimate adds nothing once it has actually happened.
        assert_eq!(kev.threat_score(), 5.0);
        assert!(kev.is_known_exploited());
    }

    #[test]
    fn epss_maps_through_a_log_scale() {
        // Each tenfold increase in probability is worth 1.25 points.
        assert!((epss(1.0).threat_score() - 5.0).abs() < 1e-9);
        assert!((epss(0.1).threat_score() - 3.75).abs() < 1e-9);
        assert!((epss(0.01).threat_score() - 2.5).abs() < 1e-9);
        assert!((epss(0.001).threat_score() - 1.25).abs() < 1e-9);
        // The floor clamps rather than going negative.
        assert_eq!(epss(0.00001).threat_score(), 0.0);
        assert_eq!(epss(0.0).threat_score(), 0.0);
        assert_eq!(ThreatContext::default().threat_score(), 0.0);
    }

    #[test]
    fn epss_ordering_is_monotonic() {
        let mut previous = -1.0;
        for p in [0.0001, 0.001, 0.01, 0.05, 0.1, 0.5, 0.9, 1.0] {
            let score = epss(p).threat_score();
            assert!(score >= previous, "threat score must not decrease with p={p}");
            previous = score;
        }
    }

    #[test]
    fn priority_balances_severity_against_exploitation() {
        let unexploited_critical = ThreatContext::default().priority_score(Some(9.8));
        let exploited_medium = ThreatContext {
            kev: Some(KevEntry {
                date_added: "2024-01-01".into(),
                due_date: None,
                known_ransomware_campaign_use: false,
                vendor_project: None,
                product: None,
            }),
            epss: None,
        }
        .priority_score(Some(5.0));

        assert!((unexploited_critical - 4.9).abs() < 1e-9);
        assert!((exploited_medium - 7.5).abs() < 1e-9);
        assert!(
            exploited_medium > unexploited_critical,
            "a medium bug being exploited today outranks a critical one that is not"
        );
    }

    #[test]
    fn priority_is_bounded_and_defaults_sanely() {
        let kev_critical = ThreatContext {
            kev: Some(KevEntry {
                date_added: "2024-01-01".into(),
                due_date: None,
                known_ransomware_campaign_use: true,
                vendor_project: None,
                product: None,
            }),
            epss: None,
        };
        assert_eq!(kev_critical.priority_score(Some(10.0)), 10.0);
        assert_eq!(kev_critical.priority_score(Some(99.0)), 10.0);
        // A CVE with no CVSS score at all is treated as medium, not as zero.
        assert!((ThreatContext::default().priority_score(None) - 2.5).abs() < 1e-9);
    }
}

//! Technology Fingerprinting Engine
//!
//! A lightweight, Wappalyzer-style technology detector. Given the headers,
//! cookies, body (HTML), and final URL of an HTTP response, it matches a
//! curated, embedded ruleset of technology signatures and returns the detected
//! products (with versions where they can be extracted).
//!
//! The detections are consumed by the security scan service, which:
//!   1. feeds versioned detections into the existing EUVD CVE lookup, and
//!   2. records the full technology stack as an inventory finding.
//!
//! The signature ruleset (`signatures.json`) uses our own / permissively
//! sourced patterns — it intentionally does NOT bundle Wappalyzer's
//! (re-licensed) dataset. It is schema-compatible so it can grow over time.

use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;

/// Maximum number of body characters scanned, to bound regex work / memory.
const MAX_BODY_CHARS: usize = 1_000_000;
/// Maximum length of stored evidence snippets.
const MAX_EVIDENCE_CHARS: usize = 160;

/// A single technology detected on a target.
#[derive(Debug, Clone)]
pub struct TechDetection {
    /// CVE-lookup vocabulary (lowercase, e.g. "wordpress", "nginx", "jquery").
    pub product: String,
    /// Human-friendly name (e.g. "WordPress").
    pub display_name: String,
    /// Extracted version, if any source exposed it.
    pub version: Option<String>,
    /// High-level categories (e.g. "cms", "javascript-library").
    pub categories: Vec<String>,
    /// CPE 2.3 base string, if known (vendor:product), without version.
    pub cpe: Option<String>,
    /// Detection confidence 0-100.
    pub confidence: u8,
    /// Where the match came from (e.g. "header:server", "html", "meta", "script", "cookie", "url", "implied").
    pub source: String,
    /// Truncated matched evidence.
    pub evidence: String,
}

impl TechDetection {
    /// True when this detection was sourced from an HTTP response header.
    /// Versionless header detections are treated as information disclosure;
    /// versionless body detections are inventory-only.
    pub fn is_header_source(&self) -> bool {
        self.source.starts_with("header:")
    }
}

// ---------------------------------------------------------------------------
// Raw (JSON) ruleset shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawSignature {
    name: String,
    product: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    implies: Vec<String>,
    #[serde(default)]
    headers: Vec<RawHeaderPattern>,
    #[serde(default)]
    cookies: Vec<String>,
    #[serde(default)]
    html: Vec<String>,
    #[serde(default)]
    meta: Vec<String>,
    #[serde(default)]
    scripts: Vec<String>,
    #[serde(default)]
    url: Vec<String>,
    #[serde(default = "default_confidence")]
    confidence: u8,
}

#[derive(Debug, Deserialize)]
struct RawHeaderPattern {
    name: String,
    /// Optional regex. When absent, the mere presence of the header matches.
    #[serde(default)]
    pattern: Option<String>,
}

fn default_confidence() -> u8 {
    80
}

// ---------------------------------------------------------------------------
// Compiled ruleset
// ---------------------------------------------------------------------------

struct HeaderMatcher {
    name: String,
    pattern: Option<Regex>,
}

struct Signature {
    name: String,
    product: String,
    categories: Vec<String>,
    cpe: Option<String>,
    implies: Vec<String>,
    confidence: u8,
    headers: Vec<HeaderMatcher>,
    cookies: Vec<Regex>,
    html: Vec<Regex>,
    meta: Vec<Regex>,
    scripts: Vec<Regex>,
    url: Vec<Regex>,
}

/// The compiled, ready-to-query fingerprint engine.
pub struct FingerprintEngine {
    signatures: Vec<Signature>,
    /// product -> (display_name, categories, cpe) for enriching `implies`.
    index: HashMap<String, (String, Vec<String>, Option<String>)>,
}

const RAW_SIGNATURES: &str = include_str!("signatures.json");

lazy_static! {
    static ref ENGINE: FingerprintEngine = FingerprintEngine::load(RAW_SIGNATURES);
}

/// Returns the process-wide compiled fingerprint engine.
pub fn engine() -> &'static FingerprintEngine {
    &ENGINE
}

fn compile(pattern: &str, ctx: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(re) => Some(re),
        Err(e) => {
            tracing::warn!("fingerprint: invalid regex in {}: {} ({})", ctx, pattern, e);
            None
        }
    }
}

impl FingerprintEngine {
    fn load(raw: &str) -> Self {
        let parsed: Vec<RawSignature> = serde_json::from_str(raw).unwrap_or_else(|e| {
            tracing::error!("fingerprint: failed to parse signatures.json: {}", e);
            Vec::new()
        });

        let mut signatures = Vec::with_capacity(parsed.len());
        let mut index = HashMap::new();

        for sig in parsed {
            let sig_name = sig.name.clone();
            index.insert(
                sig.product.to_ascii_lowercase(),
                (sig.name.clone(), sig.categories.clone(), sig.cpe.clone()),
            );

            let headers = sig
                .headers
                .into_iter()
                .map(|h| HeaderMatcher {
                    name: h.name.to_ascii_lowercase(),
                    pattern: h
                        .pattern
                        .as_deref()
                        .and_then(|p| compile(p, &format!("{} header", sig_name))),
                })
                .collect();

            let compile_all = |pats: Vec<String>, kind: &str| -> Vec<Regex> {
                pats.iter()
                    .filter_map(|p| compile(p, &format!("{} {}", sig_name, kind)))
                    .collect()
            };

            signatures.push(Signature {
                name: sig.name,
                product: sig.product.to_ascii_lowercase(),
                categories: sig.categories,
                cpe: sig.cpe,
                implies: sig
                    .implies
                    .into_iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                confidence: sig.confidence,
                headers,
                cookies: compile_all(sig.cookies, "cookie"),
                html: compile_all(sig.html, "html"),
                meta: compile_all(sig.meta, "meta"),
                scripts: compile_all(sig.scripts, "script"),
                url: compile_all(sig.url, "url"),
            });
        }

        tracing::info!("fingerprint: loaded {} technology signatures", signatures.len());
        FingerprintEngine { signatures, index }
    }

    /// Detect technologies from an HTTP response.
    ///
    /// `headers` keys must be lowercased. `set_cookies` are the raw values of
    /// any `Set-Cookie` response headers. `body` is the (HTML) response body.
    pub fn detect(
        &self,
        headers: &HashMap<String, String>,
        set_cookies: &[String],
        body: &str,
        url: &str,
    ) -> Vec<TechDetection> {
        let body_trunc: String = if body.len() > MAX_BODY_CHARS {
            body.chars().take(MAX_BODY_CHARS).collect()
        } else {
            body.to_string()
        };
        let body_ref = body_trunc.as_str();

        // product -> detection (accumulates the best version/confidence)
        let mut found: HashMap<String, TechDetection> = HashMap::new();

        for sig in &self.signatures {
            // hit = (version, source, evidence); upgraded toward a versioned match.
            let mut hit: Option<(Option<String>, String, String)> = None;

            // Headers
            for hm in &sig.headers {
                if let Some(val) = headers.get(&hm.name) {
                    match &hm.pattern {
                        Some(re) => {
                            if let Some(caps) = re.captures(val) {
                                consider(
                                    &mut hit,
                                    version_from(&caps),
                                    format!("header:{}", hm.name),
                                    val,
                                );
                            }
                        }
                        None => {
                            consider(&mut hit, None, format!("header:{}", hm.name), val);
                        }
                    }
                }
            }

            // Cookies (matched against each raw Set-Cookie value)
            for re in &sig.cookies {
                for cookie in set_cookies {
                    if let Some(caps) = re.captures(cookie) {
                        consider(&mut hit, version_from(&caps), "cookie".to_string(), cookie);
                        break;
                    }
                }
            }

            // Body-derived sources (html / meta / script) + url
            for (label, regexes, haystack) in [
                ("html", &sig.html, body_ref),
                ("meta", &sig.meta, body_ref),
                ("script", &sig.scripts, body_ref),
                ("url", &sig.url, url),
            ] {
                for re in regexes {
                    if let Some(caps) = re.captures(haystack) {
                        let evidence = caps.get(0).map(|m| m.as_str()).unwrap_or(haystack);
                        consider(&mut hit, version_from(&caps), label.to_string(), evidence);
                        break;
                    }
                }
            }

            if let Some((version, source, evidence)) = hit {
                upsert(
                    &mut found,
                    &sig.product,
                    &sig.name,
                    version,
                    &sig.categories,
                    &sig.cpe,
                    sig.confidence,
                    source,
                    &evidence,
                );

                // Expand implied technologies (versionless, lower confidence).
                for implied in &sig.implies {
                    let (display, cats, cpe) = self
                        .index
                        .get(implied)
                        .cloned()
                        .unwrap_or_else(|| (implied.clone(), Vec::new(), None));
                    upsert(
                        &mut found,
                        implied,
                        &display,
                        None,
                        &cats,
                        &cpe,
                        sig.confidence.min(50),
                        "implied".to_string(),
                        &format!("implied by {}", sig.name),
                    );
                }
            }
        }

        let mut detections: Vec<TechDetection> = found.into_values().collect();
        detections.sort_by(|a, b| a.product.cmp(&b.product));
        detections
    }
}

/// Update `hit` toward the most informative match: prefer one that carries a
/// version. The first match wins for presence; a later versioned match upgrades.
fn consider(
    hit: &mut Option<(Option<String>, String, String)>,
    version: Option<String>,
    source: String,
    evidence: &str,
) {
    let evidence = truncate_evidence(evidence);
    match hit {
        None => *hit = Some((version, source, evidence)),
        Some((existing_version, existing_source, existing_evidence)) => {
            if existing_version.is_none() && version.is_some() {
                *existing_version = version;
                *existing_source = source;
                *existing_evidence = evidence;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn upsert(
    found: &mut HashMap<String, TechDetection>,
    product: &str,
    display_name: &str,
    version: Option<String>,
    categories: &[String],
    cpe: &Option<String>,
    confidence: u8,
    source: String,
    evidence: &str,
) {
    let key = product.to_ascii_lowercase();
    match found.get_mut(&key) {
        None => {
            found.insert(
                key.clone(),
                TechDetection {
                    product: key,
                    display_name: display_name.to_string(),
                    version,
                    categories: categories.to_vec(),
                    cpe: cpe.clone(),
                    confidence,
                    source,
                    evidence: truncate_evidence(evidence),
                },
            );
        }
        Some(existing) => {
            if existing.version.is_none() && version.is_some() {
                existing.version = version;
                existing.source = source;
                existing.evidence = truncate_evidence(evidence);
            }
            if confidence > existing.confidence {
                existing.confidence = confidence;
            }
            if existing.categories.is_empty() && !categories.is_empty() {
                existing.categories = categories.to_vec();
            }
            if existing.cpe.is_none() {
                existing.cpe = cpe.clone();
            }
        }
    }
}

/// Extract and normalize a version from capture group 1, if present and plausible.
fn version_from(caps: &regex::Captures) -> Option<String> {
    let raw = caps.get(1)?.as_str();
    let normalized = raw.trim().trim_start_matches(['v', 'V']).trim();
    if normalized.is_empty() || normalized.len() > 24 {
        return None;
    }
    // Must start with a digit to be a plausible version.
    if !normalized.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some(normalized.to_string())
}

fn truncate_evidence(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() > MAX_EVIDENCE_CHARS {
        let truncated: String = trimmed.chars().take(MAX_EVIDENCE_CHARS).collect();
        format!("{}…", truncated)
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect()
    }

    fn find<'a>(dets: &'a [TechDetection], product: &str) -> Option<&'a TechDetection> {
        dets.iter().find(|d| d.product == product)
    }

    #[test]
    fn ruleset_compiles_and_is_non_empty() {
        // Forces lazy load; panics surfaced here if JSON is malformed.
        assert!(
            !engine().signatures.is_empty(),
            "expected signatures to load"
        );
    }

    #[test]
    fn detects_nginx_version_from_server_header() {
        let h = headers(&[("server", "nginx/1.18.0")]);
        let dets = engine().detect(&h, &[], "", "https://x");
        let nginx = find(&dets, "nginx").expect("nginx detected");
        assert_eq!(nginx.version.as_deref(), Some("1.18.0"));
        assert!(nginx.is_header_source());
    }

    #[test]
    fn detects_php_version_from_x_powered_by() {
        let h = headers(&[("x-powered-by", "PHP/8.1.2")]);
        let dets = engine().detect(&h, &[], "", "https://x");
        assert_eq!(
            find(&dets, "php").and_then(|d| d.version.clone()).as_deref(),
            Some("8.1.2")
        );
    }

    #[test]
    fn detects_wordpress_and_version_from_meta_generator() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        let wp = find(&dets, "wordpress").expect("wordpress detected");
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
    }

    #[test]
    fn detects_jquery_version_from_script_src() {
        let body = r#"<script src="/assets/jquery-3.5.1.min.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert_eq!(
            find(&dets, "jquery")
                .and_then(|d| d.version.clone())
                .as_deref(),
            Some("3.5.1")
        );
    }

    #[test]
    fn cookie_signature_matches() {
        let dets = engine().detect(
            &HashMap::new(),
            &["laravel_session=abc; path=/".to_string()],
            "",
            "https://x",
        );
        assert!(find(&dets, "laravel").is_some());
    }

    #[test]
    fn woocommerce_implies_wordpress() {
        let body = r#"<div class="woocommerce">cart</div>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert!(find(&dets, "woocommerce").is_some());
        assert!(
            find(&dets, "wordpress").is_some(),
            "woocommerce should imply wordpress"
        );
    }

    #[test]
    fn no_false_positive_on_empty_response() {
        let dets = engine().detect(&HashMap::new(), &[], "", "https://x");
        assert!(dets.is_empty(), "expected no detections, got {:?}", dets);
    }

    #[test]
    fn versionless_presence_still_detected() {
        let h = headers(&[("x-powered-by", "Express")]);
        let dets = engine().detect(&h, &[], "", "https://x");
        let express = find(&dets, "express").expect("express detected");
        assert!(express.version.is_none());
    }
}

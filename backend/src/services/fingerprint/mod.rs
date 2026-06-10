//! Technology Fingerprinting Engine
//!
//! A lightweight, Wappalyzer-style technology detector. Given the headers,
//! cookies, body (HTML), and final URL of an HTTP response, it matches a
//! curated, embedded ruleset of technology signatures and returns the detected
//! products (with versions where they can be extracted).
//!
//! The detections are consumed by the security scan service, which:
//!   1. feeds versioned detections into the NVD CVE lookup, and
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
    /// Regexes applied to *fetched* JS/CSS asset contents to recover a version
    /// banner (e.g. "/*! jQuery v3.6.0" or `.fn.jquery="3.6.0"`). Capture group 1
    /// is the version.
    #[serde(default)]
    js_content: Vec<String>,
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
    js_content: Vec<Regex>,
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
                js_content: compile_all(sig.js_content, "js_content"),
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

    /// True if this engine can recover a version for `product` from the contents
    /// of a fetched asset (i.e. the signature defines content-banner patterns).
    /// Used to decide whether fetching a referenced script is worthwhile.
    pub fn supports_asset_version(&self, product: &str) -> bool {
        self.signatures
            .iter()
            .any(|s| s.product == product && !s.js_content.is_empty())
    }

    /// Recover a version for `product` from the body of a fetched asset
    /// (e.g. a minified `jquery.min.js`), using the signature's content-banner
    /// patterns — plus, as a bonus, any version-capturing HTML banner patterns
    /// (a JS banner comment is the same text as the HTML one).
    pub fn version_from_asset(&self, product: &str, content: &str) -> Option<String> {
        let sig = self.signatures.iter().find(|s| s.product == product)?;

        // Banners live near the top; scan a bounded prefix to cap regex work.
        let truncated: String;
        let scan: &str = if content.len() > MAX_BODY_CHARS {
            truncated = content.chars().take(MAX_BODY_CHARS).collect();
            truncated.as_str()
        } else {
            content
        };

        for re in sig.js_content.iter().chain(sig.html.iter()) {
            if let Some(caps) = re.captures(scan) {
                if let Some(v) = version_from(&caps) {
                    return Some(v);
                }
            }
        }
        None
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
    fn detects_versionless_jquery_min_js() {
        // Bare, unversioned filename (as served by mutantstage.lafayetteanticipations.com):
        // technology must still be detected (inventory), just without a version.
        let body = r#"<script src="js/lib/jquery.min.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        let jq = find(&dets, "jquery").expect("jquery detected without version");
        assert_eq!(jq.version, None);
    }

    #[test]
    fn detects_jquery_version_from_query_string() {
        // CMS-style cache-busting query param (Drupal/WordPress): version is in ?v=/?ver=.
        for body in [
            r#"<script src="/core/assets/vendor/jquery/jquery.min.js?v=3.7.1"></script>"#,
            r#"<script src="/wp-includes/js/jquery/jquery.js?ver=3.6.0"></script>"#,
        ] {
            let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
            let jq = find(&dets, "jquery").expect("jquery detected");
            assert!(
                jq.version.is_some(),
                "expected a version from query string in {body}"
            );
        }
    }

    #[test]
    fn does_not_misdetect_jquery_plugin_as_jquery() {
        // A jQuery *plugin* filename alone should not be reported as jQuery core.
        let body = r#"<script src="js/jquery.waypoints.min.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert!(find(&dets, "jquery").is_none());
    }

    #[test]
    fn supports_asset_version_only_for_banner_libs() {
        assert!(engine().supports_asset_version("jquery"));
        assert!(engine().supports_asset_version("bootstrap"));
        assert!(engine().supports_asset_version("vue"));
        assert!(!engine().supports_asset_version("nginx"));
        assert!(!engine().supports_asset_version("wordpress"));
    }

    #[test]
    fn recovers_jquery_version_from_banner_comment() {
        let content = "/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors */\n!function(){}";
        assert_eq!(
            engine().version_from_asset("jquery", content).as_deref(),
            Some("3.6.0")
        );
        // Older "jQuery JavaScript Library v1.12.4" banner form.
        let legacy = "/*!\n * jQuery JavaScript Library v1.12.4\n */";
        assert_eq!(
            engine().version_from_asset("jquery", legacy).as_deref(),
            Some("1.12.4")
        );
    }

    #[test]
    fn recovers_jquery_version_from_fn_property() {
        // Minified body without a leading banner; version is in `.fn.jquery`.
        let content = r#"a.fn.jquery="3.5.1",a.extend({})"#;
        assert_eq!(
            engine().version_from_asset("jquery", content).as_deref(),
            Some("3.5.1")
        );
    }

    #[test]
    fn recovers_bootstrap_and_vue_versions_from_banner() {
        assert_eq!(
            engine()
                .version_from_asset("bootstrap", "/*! Bootstrap v5.3.2 (https://getbootstrap.com/) */")
                .as_deref(),
            Some("5.3.2")
        );
        assert_eq!(
            engine()
                .version_from_asset("vue", "/*!\n * vue v3.3.4\n * (c) 2014-2023 */")
                .as_deref(),
            Some("3.3.4")
        );
    }

    #[test]
    fn version_from_asset_none_when_absent() {
        assert_eq!(engine().version_from_asset("jquery", "no version here"), None);
        // Unknown product yields nothing.
        assert_eq!(engine().version_from_asset("nginx", "nginx 1.2.3"), None);
    }

    #[test]
    fn detects_new_js_libraries_versionless_and_versioned() {
        // Versionless presence (bare minified filenames).
        for (src, product) in [
            ("/js/lodash.min.js", "lodash"),
            ("/vendor/moment.min.js", "moment"),
            ("/lib/angular.min.js", "angularjs"),
            ("/js/underscore.min.js", "underscore"),
            ("/js/modernizr.custom.min.js", "modernizr"),
        ] {
            let body = format!(r#"<script src="{src}"></script>"#);
            let dets = engine().detect(&HashMap::new(), &[], &body, "https://x");
            let d = find(&dets, product).unwrap_or_else(|| panic!("{product} not detected from {src}"));
            assert_eq!(d.version, None, "{product} should be versionless from {src}");
        }
    }

    #[test]
    fn detects_versioned_libs_from_filename_and_cdn_path() {
        // version in filename
        let b1 = r#"<script src="/lib/angular-1.7.9.min.js"></script>"#;
        assert_eq!(
            find(&engine().detect(&HashMap::new(), &[], b1, "https://x"), "angularjs")
                .and_then(|d| d.version.clone()).as_deref(),
            Some("1.7.9")
        );
        // version in cdnjs-style path
        let b2 = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>"#;
        assert_eq!(
            find(&engine().detect(&HashMap::new(), &[], b2, "https://x"), "lodash")
                .and_then(|d| d.version.clone()).as_deref(),
            Some("4.17.21")
        );
    }

    #[test]
    fn recovers_new_lib_versions_from_banners() {
        assert_eq!(engine().version_from_asset("lodash", r#"var x;t.VERSION="4.17.21";"#).as_deref(), Some("4.17.21"));
        assert_eq!(engine().version_from_asset("moment", r#"e.version="2.29.4",e.fn"#).as_deref(), Some("2.29.4"));
        assert_eq!(engine().version_from_asset("angularjs", "/*! AngularJS v1.8.2 */").as_deref(), Some("1.8.2"));
        assert_eq!(engine().version_from_asset("underscore", "//     Underscore.js 1.13.6").as_deref(), Some("1.13.6"));
        assert_eq!(engine().version_from_asset("axios", "// axios v1.6.2").as_deref(), Some("1.6.2"));
        assert_eq!(engine().version_from_asset("three.js", "const REVISION = '158';").as_deref(), Some("158"));
        assert_eq!(engine().version_from_asset("chart.js", "/*! Chart.js v4.4.1 */").as_deref(), Some("4.4.1"));
    }

    #[test]
    fn detects_jquery_version_from_cdnjs_path() {
        // Real-world case (www.groupegalerieslafayette.com): jQuery loaded from a
        // cdnjs URL where the version is a path segment, not in the filename.
        let body = r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert_eq!(
            find(&dets, "jquery").and_then(|d| d.version.clone()).as_deref(),
            Some("3.2.1")
        );
    }

    #[test]
    fn detects_cdnjs_path_versions_for_core_libs() {
        for (body, product, ver) in [
            (r#"<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css">"#, "bootstrap", "5.3.2"),
            (r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>"#, "react", "18.2.0"),
            (r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.3.4/vue.global.prod.min.js"></script>"#, "vue", "3.3.4"),
        ] {
            let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
            assert_eq!(
                find(&dets, product).and_then(|d| d.version.clone()).as_deref(),
                Some(ver),
                "{product} cdnjs path version"
            );
        }
    }

    #[test]
    fn detects_bootstrap_from_versionless_stylesheet() {
        let body = r#"<link rel="stylesheet" href="/css/bootstrap.min.css">"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        let bs = find(&dets, "bootstrap").expect("bootstrap detected from css");
        assert_eq!(bs.version, None);
    }

    #[test]
    fn detects_server_side_tech_from_cookies() {
        let php = engine().detect(&HashMap::new(), &["PHPSESSID=abc123; path=/".to_string()], "", "https://x");
        assert!(find(&php, "php").is_some(), "PHP from PHPSESSID cookie");

        let aspnet = engine().detect(&HashMap::new(), &["ASP.NET_SessionId=xyz".to_string()], "", "https://x");
        assert!(find(&aspnet, "asp.net").is_some(), "ASP.NET from session cookie");
    }

    #[test]
    fn cms_implies_php() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert!(find(&dets, "wordpress").is_some());
        // WordPress is PHP-based -> php inventoried (versionless).
        let php = find(&dets, "php").expect("php implied by wordpress");
        assert_eq!(php.version, None);
    }

    #[test]
    fn detects_typo3_from_path_markers() {
        let body = r#"<link href="/typo3conf/ext/theme/style.css"><script src="/typo3temp/assets/app.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert!(find(&dets, "typo3").is_some());
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

    #[test]
    fn detects_webpack_from_runtime_chunk() {
        let body = r#"<script src="/static/js/runtime.8f3a9c2b1d.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        let w = find(&dets, "webpack").expect("webpack detected from runtime chunk");
        // Bundled-asset detection is presence-only; the bundle does not expose a version.
        assert_eq!(w.version, None);
    }

    #[test]
    fn detects_webpack_from_inline_marker() {
        let body = r#"<script>window.webpackChunk_app=[];__webpack_require__(0);</script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert!(find(&dets, "webpack").is_some());
    }

    #[test]
    fn does_not_flag_webpack_on_plain_main_js() {
        // A generic, unhashed main.js with no webpack runtime marker must not trip
        // the bundled-SPA heuristic.
        let body = r#"<script src="/js/main.js"></script>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://x");
        assert!(find(&dets, "webpack").is_none());
    }

    #[test]
    fn detects_new_libs_versionless_from_bare_filenames() {
        for (src, product) in [
            ("/js/chart.umd.js", "chart.js"),
            ("/vendor/d3.min.js", "d3"),
            ("/js/gsap.min.js", "gsap"),
            ("/js/select2.full.min.js", "select2"),
            ("/js/axios.min.js", "axios"),
            ("/js/three.module.js", "three.js"),
        ] {
            let body = format!(r#"<script src="{}"></script>"#, src);
            let dets = engine().detect(&HashMap::new(), &[], &body, "https://x");
            let d = find(&dets, product)
                .unwrap_or_else(|| panic!("{} not detected from {}", product, src));
            assert_eq!(d.version, None, "{} should be versionless from {}", product, src);
        }
    }

    #[test]
    fn detects_new_libs_versioned_from_filename_and_cdn() {
        let b1 = r#"<script src="/lib/axios-1.6.2.min.js"></script>"#;
        assert_eq!(
            find(&engine().detect(&HashMap::new(), &[], b1, "https://x"), "axios")
                .and_then(|d| d.version.clone())
                .as_deref(),
            Some("1.6.2")
        );
        let b2 =
            r#"<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>"#;
        assert_eq!(
            find(&engine().detect(&HashMap::new(), &[], b2, "https://x"), "d3")
                .and_then(|d| d.version.clone())
                .as_deref(),
            Some("7.8.5")
        );
    }
}

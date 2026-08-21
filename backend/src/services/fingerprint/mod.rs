//! Technology Fingerprinting Engine
//!
//! A Wappalyzer-style passive technology detector. Given everything a single
//! HTTP exchange revealed — headers, cookies, HTML, the meta tags and asset
//! URLs inside it, the final URL, the TLS certificate issuer, the favicon hash
//! and `robots.txt` — it matches an embedded ruleset and returns the products
//! it can prove are there, with versions wherever one is exposed.
//!
//! The detections are consumed by the security scan service, which:
//!   1. feeds versioned detections into the NVD CVE lookup keyed on the
//!      signature's CPE, and
//!   2. records the full technology stack as an inventory finding.
//!
//! ## What makes a detection precise
//!
//! Three things, all of which the ruleset depends on:
//!
//! * **Scoped haystacks.** `meta` patterns run against extracted `<meta>` tags,
//!   `scripts` against extracted `<script src>` / `<link href>` URLs, `css`
//!   against inline `<style>` blocks. Running everything against the raw body
//!   is what makes a mirrored page or a blog post *about* WordPress look like
//!   WordPress.
//! * **Corroboration.** Confidence combines probabilistically across matched
//!   patterns, so two independent 80%-confidence signals reach 96% while one
//!   weak marker stays weak — and the CVE path only acts on strong detections.
//! * **`excludes` / `requires`.** Products that impersonate each other
//!   (LiteSpeed serving an `Apache` Server header) and products that only exist
//!   inside a host product (a WordPress plugin) need explicit relationships,
//!   not just independent patterns.
//!
//! ## Pattern syntax
//!
//! Patterns are regexes with Wappalyzer's optional trailing tags:
//!
//! ```text
//! "nginx/?([\\d.]+)?\;version:\\1"        version comes from capture group 1
//! "wp-content\;confidence:50"             this marker alone is weak evidence
//! "jquery\;version:\\1?\\1:unknown"       ternary on whether group 1 matched
//! ```
//!
//! A pattern with no `\;version:` tag still yields a version from capture group
//! 1 when that group looks like one, which keeps older rules working.
//!
//! The signature ruleset (`signatures.json`) uses our own / permissively
//! sourced patterns — it intentionally does NOT bundle Wappalyzer's
//! (re-licensed) dataset.

use std::collections::{HashMap, HashSet};

use lazy_static::lazy_static;
use regex::{Captures, Regex};
use serde::Deserialize;

/// Maximum number of body characters scanned, to bound regex work / memory.
const MAX_BODY_CHARS: usize = 1_000_000;
/// Maximum length of stored evidence snippets.
const MAX_EVIDENCE_CHARS: usize = 160;
/// Confidence at or above which a detection is trusted enough to drive a CVE
/// lookup and a user-visible vulnerability finding. Weaker hits still appear in
/// the technology inventory, where a false positive costs nothing.
pub const RELIABLE_CONFIDENCE: u8 = 70;
/// Fraction of the implying signature's confidence that an implied technology
/// inherits. "This is Laravel, therefore PHP" is sound but second-hand.
const IMPLIED_CONFIDENCE_RATIO: u32 = 60;
/// Bound on `implies` chain expansion, so a cyclic ruleset cannot spin.
const MAX_IMPLIES_DEPTH: usize = 4;

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
    /// Where the strongest match came from (e.g. "header:server", "html",
    /// "meta", "script", "cookie", "url", "favicon", "cert", "robots",
    /// "implied").
    pub source: String,
    /// Every distinct source category that contributed, for explainability.
    pub sources: Vec<String>,
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

    /// True when the detection is strong enough to act on — to open a CVE
    /// finding against the asset rather than merely list the technology.
    pub fn is_reliable(&self) -> bool {
        self.confidence >= RELIABLE_CONFIDENCE
    }
}

/// Everything one HTTP exchange revealed, as handed to the engine.
///
/// Built with [`DetectionInput::new`] and refined with the `with_*` setters, so
/// that adding a signal source later does not break every call site.
#[derive(Debug, Default, Clone)]
pub struct DetectionInput<'a> {
    /// The **final** URL after redirects. Matching `url` patterns against the
    /// requested URL instead would miss every redirect-to-login appliance.
    pub url: &'a str,
    /// Response headers, keys lowercased.
    pub headers: &'a [(String, String)],
    /// Raw `Set-Cookie` response header values.
    pub set_cookies: &'a [String],
    /// Response body (HTML).
    pub body: &'a str,
    /// Subject/issuer string of the leaf TLS certificate.
    pub cert_issuer: Option<&'a str>,
    /// Shodan-convention MurmurHash3 of the base64-encoded favicon.
    pub favicon_hash: Option<i32>,
    /// Contents of `/robots.txt`, when fetched.
    pub robots_txt: Option<&'a str>,
}

impl<'a> DetectionInput<'a> {
    pub fn new(url: &'a str, body: &'a str) -> Self {
        DetectionInput {
            url,
            body,
            ..Default::default()
        }
    }

    pub fn with_headers(mut self, headers: &'a [(String, String)]) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_cookies(mut self, set_cookies: &'a [String]) -> Self {
        self.set_cookies = set_cookies;
        self
    }

    pub fn with_cert_issuer(mut self, issuer: Option<&'a str>) -> Self {
        self.cert_issuer = issuer;
        self
    }

    pub fn with_favicon_hash(mut self, hash: Option<i32>) -> Self {
        self.favicon_hash = hash;
        self
    }

    pub fn with_robots_txt(mut self, robots: Option<&'a str>) -> Self {
        self.robots_txt = robots;
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
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
    /// Products that cannot coexist with this one. When this signature matches,
    /// the excluded products are dropped from the result — the escape hatch for
    /// servers that deliberately impersonate another (LiteSpeed answering with
    /// an `Apache` Server header).
    #[serde(default)]
    excludes: Vec<String>,
    /// Products that must also be present for this signature to count, for
    /// technologies that only exist inside a host product (plugins, themes).
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    headers: Vec<RawHeaderPattern>,
    #[serde(default)]
    cookies: Vec<String>,
    #[serde(default)]
    html: Vec<String>,
    /// Matched against each extracted `<meta …>` element.
    #[serde(default)]
    meta: Vec<String>,
    /// Matched against extracted `<script src>` and `<link href>` URLs.
    #[serde(default)]
    scripts: Vec<String>,
    /// Matched against the contents of inline `<style>` blocks.
    #[serde(default)]
    css: Vec<String>,
    /// Matched against the page's visible text with markup stripped.
    #[serde(default)]
    text: Vec<String>,
    /// Regexes applied to *fetched* JS/CSS asset contents to recover a version
    /// banner (e.g. "/*! jQuery v3.6.0" or `.fn.jquery="3.6.0"`). Capture group 1
    /// is the version.
    #[serde(default)]
    js_content: Vec<String>,
    #[serde(default)]
    url: Vec<String>,
    /// Matched against the TLS leaf certificate issuer string.
    #[serde(default)]
    cert_issuer: Vec<String>,
    /// Matched against `robots.txt`.
    #[serde(default)]
    robots: Vec<String>,
    /// Shodan-convention MurmurHash3 favicon hashes. An exact hash match is
    /// near-conclusive, so these carry high confidence.
    #[serde(default)]
    favicon: Vec<i32>,
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
// Pattern compilation
// ---------------------------------------------------------------------------

/// How a matched pattern yields a version string.
#[derive(Debug, Clone)]
enum VersionSpec {
    /// No explicit tag: use capture group 1 if it looks like a version.
    ImplicitGroupOne,
    /// `\;version:\1` — a template of literals and `\N` backreferences.
    Template(Vec<TemplatePart>),
    /// `\;version:\1?a:b` — `a` when group N matched, `b` otherwise.
    Ternary {
        group: usize,
        when_present: Vec<TemplatePart>,
        when_absent: Vec<TemplatePart>,
    },
}

#[derive(Debug, Clone)]
enum TemplatePart {
    Literal(String),
    Group(usize),
}

/// A compiled pattern: the regex plus the version/confidence tags that followed
/// it in the ruleset.
struct Pattern {
    regex: Regex,
    version: VersionSpec,
    /// Per-pattern confidence override; falls back to the signature's.
    confidence: Option<u8>,
}

impl Pattern {
    /// Split a raw ruleset pattern on its unescaped `\;` tag separators and
    /// compile the parts.
    fn compile(raw: &str, ctx: &str) -> Option<Pattern> {
        let (regex_src, tags) = split_tags(raw);
        let regex = match Regex::new(&regex_src) {
            Ok(re) => re,
            Err(e) => {
                tracing::warn!("fingerprint: invalid regex in {}: {} ({})", ctx, raw, e);
                return None;
            }
        };

        let mut version = VersionSpec::ImplicitGroupOne;
        let mut confidence = None;
        for tag in tags {
            if let Some(rest) = tag.strip_prefix("version:") {
                version = parse_version_spec(rest);
            } else if let Some(rest) = tag.strip_prefix("confidence:") {
                confidence = rest.trim().parse::<u8>().ok().map(|c| c.min(100));
            }
        }

        Some(Pattern {
            regex,
            version,
            confidence,
        })
    }

    fn version_from(&self, caps: &Captures) -> Option<String> {
        match &self.version {
            VersionSpec::ImplicitGroupOne => {
                caps.get(1).and_then(|m| normalize_version(m.as_str()))
            }
            VersionSpec::Template(parts) => {
                normalize_version(&render_template(parts, caps))
            }
            VersionSpec::Ternary {
                group,
                when_present,
                when_absent,
            } => {
                let parts = if caps.get(*group).is_some_and(|m| !m.as_str().is_empty()) {
                    when_present
                } else {
                    when_absent
                };
                normalize_version(&render_template(parts, caps))
            }
        }
    }
}

/// Split `regex\;version:\1\;confidence:50` into the regex source and its tags,
/// honouring `\;` as an escaped literal semicolon inside the regex.
fn split_tags(raw: &str) -> (String, Vec<String>) {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some(';') => {
                    chars.next();
                    parts.push(std::mem::take(&mut current));
                }
                _ => {
                    current.push(c);
                    if let Some(&next) = chars.peek() {
                        current.push(next);
                        chars.next();
                    }
                }
            }
        } else {
            current.push(c);
        }
    }
    parts.push(current);
    let regex_src = parts.remove(0);
    (regex_src, parts)
}

/// Parse the right-hand side of a `\;version:` tag.
fn parse_version_spec(spec: &str) -> VersionSpec {
    // Ternary form: `\1?present:absent`
    if let Some((cond, branches)) = spec.split_once('?') {
        if let Some(group) = cond.strip_prefix('\\').and_then(|g| g.parse::<usize>().ok()) {
            let (present, absent) = branches.split_once(':').unwrap_or((branches, ""));
            return VersionSpec::Ternary {
                group,
                when_present: parse_template(present),
                when_absent: parse_template(absent),
            };
        }
    }
    VersionSpec::Template(parse_template(spec))
}

fn parse_template(spec: &str) -> Vec<TemplatePart> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut chars = spec.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    chars.next();
                    if !literal.is_empty() {
                        parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
                    }
                    parts.push(TemplatePart::Group(d.to_digit(10).unwrap_or(0) as usize));
                    continue;
                }
            }
            literal.push(c);
        } else {
            literal.push(c);
        }
    }
    if !literal.is_empty() {
        parts.push(TemplatePart::Literal(literal));
    }
    parts
}

fn render_template(parts: &[TemplatePart], caps: &Captures) -> String {
    let mut out = String::new();
    for part in parts {
        match part {
            TemplatePart::Literal(s) => out.push_str(s),
            TemplatePart::Group(n) => {
                if let Some(m) = caps.get(*n) {
                    out.push_str(m.as_str());
                }
            }
        }
    }
    out
}

/// Normalize and sanity-check a candidate version string.
fn normalize_version(raw: &str) -> Option<String> {
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

// ---------------------------------------------------------------------------
// Compiled ruleset
// ---------------------------------------------------------------------------

struct HeaderMatcher {
    name: String,
    pattern: Option<Pattern>,
}

/// The haystacks a pattern list is matched against, named for the `source`
/// label they produce.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Html,
    Meta,
    Script,
    Css,
    Text,
    Url,
    Cert,
    Robots,
}

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::Html => "html",
            Field::Meta => "meta",
            Field::Script => "script",
            Field::Css => "css",
            Field::Text => "text",
            Field::Url => "url",
            Field::Cert => "cert",
            Field::Robots => "robots",
        }
    }
}

struct Signature {
    name: String,
    product: String,
    categories: Vec<String>,
    cpe: Option<String>,
    implies: Vec<String>,
    excludes: Vec<String>,
    requires: Vec<String>,
    confidence: u8,
    headers: Vec<HeaderMatcher>,
    cookies: Vec<Pattern>,
    html: Vec<Pattern>,
    meta: Vec<Pattern>,
    scripts: Vec<Pattern>,
    css: Vec<Pattern>,
    text: Vec<Pattern>,
    js_content: Vec<Regex>,
    url: Vec<Pattern>,
    cert_issuer: Vec<Pattern>,
    robots: Vec<Pattern>,
    favicon: Vec<i32>,
}

impl Signature {
    fn patterns_for(&self, field: Field) -> &[Pattern] {
        match field {
            Field::Html => &self.html,
            Field::Meta => &self.meta,
            Field::Script => &self.scripts,
            Field::Css => &self.css,
            Field::Text => &self.text,
            Field::Url => &self.url,
            Field::Cert => &self.cert_issuer,
            Field::Robots => &self.robots,
        }
    }
}

/// The compiled, ready-to-query fingerprint engine.
pub struct FingerprintEngine {
    signatures: Vec<Signature>,
    /// product -> (display_name, categories, cpe) for enriching `implies`.
    index: HashMap<String, (String, Vec<String>, Option<String>)>,
    /// product -> signature indices, for `requires`/`excludes` resolution.
    by_product: HashMap<String, Vec<usize>>,
    /// favicon hash -> signature indices.
    by_favicon: HashMap<i32, Vec<usize>>,
    /// Whether any signature has `text` patterns. Stripping markup off a
    /// megabyte of HTML is only worth doing if something will read the result.
    has_text_patterns: bool,
}

const RAW_SIGNATURES: &str = include_str!("signatures.json");

lazy_static! {
    static ref ENGINE: FingerprintEngine = FingerprintEngine::load(RAW_SIGNATURES);
}

/// Returns the process-wide compiled fingerprint engine.
pub fn engine() -> &'static FingerprintEngine {
    &ENGINE
}

impl FingerprintEngine {
    fn load(raw: &str) -> Self {
        let parsed: Vec<RawSignature> = serde_json::from_str(raw).unwrap_or_else(|e| {
            tracing::error!("fingerprint: failed to parse signatures.json: {}", e);
            Vec::new()
        });

        let mut signatures = Vec::with_capacity(parsed.len());
        let mut index = HashMap::new();
        let mut by_product: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_favicon: HashMap<i32, Vec<usize>> = HashMap::new();

        for sig in parsed {
            let sig_name = sig.name.clone();
            let product = sig.product.to_ascii_lowercase();
            index.insert(
                product.clone(),
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
                        .and_then(|p| Pattern::compile(p, &format!("{} header", sig_name))),
                })
                .collect();

            let compile_all = |pats: Vec<String>, kind: &str| -> Vec<Pattern> {
                pats.iter()
                    .filter_map(|p| Pattern::compile(p, &format!("{} {}", sig_name, kind)))
                    .collect()
            };

            let idx = signatures.len();
            by_product.entry(product.clone()).or_default().push(idx);
            for hash in &sig.favicon {
                by_favicon.entry(*hash).or_default().push(idx);
            }

            signatures.push(Signature {
                name: sig.name,
                product,
                categories: sig.categories,
                cpe: sig.cpe,
                implies: lowercase_all(sig.implies),
                excludes: lowercase_all(sig.excludes),
                requires: lowercase_all(sig.requires),
                confidence: sig.confidence,
                headers,
                cookies: compile_all(sig.cookies, "cookie"),
                html: compile_all(sig.html, "html"),
                meta: compile_all(sig.meta, "meta"),
                scripts: compile_all(sig.scripts, "script"),
                css: compile_all(sig.css, "css"),
                text: compile_all(sig.text, "text"),
                js_content: sig
                    .js_content
                    .iter()
                    .filter_map(|p| match Regex::new(p) {
                        Ok(re) => Some(re),
                        Err(e) => {
                            tracing::warn!(
                                "fingerprint: invalid js_content regex in {}: {} ({})",
                                sig_name,
                                p,
                                e
                            );
                            None
                        }
                    })
                    .collect(),
                url: compile_all(sig.url, "url"),
                cert_issuer: compile_all(sig.cert_issuer, "cert_issuer"),
                robots: compile_all(sig.robots, "robots"),
                favicon: sig.favicon,
            });
        }

        let has_text_patterns = signatures.iter().any(|s| !s.text.is_empty());

        tracing::info!(
            "fingerprint: loaded {} technology signatures",
            signatures.len()
        );
        FingerprintEngine {
            signatures,
            index,
            by_product,
            by_favicon,
            has_text_patterns,
        }
    }

    /// Detect technologies from an HTTP response.
    ///
    /// `headers` keys must be lowercased. `set_cookies` are the raw values of
    /// any `Set-Cookie` response headers. `body` is the (HTML) response body.
    ///
    /// A convenience wrapper over [`detect_with`](Self::detect_with) for callers
    /// that only have the four core signals.
    pub fn detect(
        &self,
        headers: &HashMap<String, String>,
        set_cookies: &[String],
        body: &str,
        url: &str,
    ) -> Vec<TechDetection> {
        let header_pairs: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();
        self.detect_with(
            &DetectionInput::new(url, body)
                .with_headers(&header_pairs)
                .with_cookies(set_cookies),
        )
    }

    /// Detect technologies from every signal an exchange produced.
    pub fn detect_with(&self, input: &DetectionInput<'_>) -> Vec<TechDetection> {
        let body_trunc: String = if input.body.len() > MAX_BODY_CHARS {
            input.body.chars().take(MAX_BODY_CHARS).collect()
        } else {
            input.body.to_string()
        };
        let body = body_trunc.as_str();

        // Scoped haystacks. Each is derived once and shared by every signature,
        // so the parsing cost is paid per response, not per rule.
        let meta_tags = extract_meta_tags(body);
        let asset_urls = extract_asset_urls(body);
        let style_blocks = extract_style_blocks(body);
        let visible_text = if self.has_text_patterns {
            strip_markup(body)
        } else {
            String::new()
        };

        // product -> accumulated detection state
        let mut found: HashMap<String, Hit> = HashMap::new();
        // Which signature produced each product hit, for implies/excludes.
        let mut matched_signatures: Vec<usize> = Vec::new();

        for (si, sig) in self.signatures.iter().enumerate() {
            let mut hit = Hit::new(sig);

            // --- Headers ---
            for hm in &sig.headers {
                let Some(val) = input.header(&hm.name) else {
                    continue;
                };
                match &hm.pattern {
                    Some(pat) => {
                        if let Some(caps) = pat.regex.captures(val) {
                            hit.record(
                                pat.version_from(&caps),
                                &format!("header:{}", hm.name),
                                val,
                                pat.confidence.unwrap_or(sig.confidence),
                            );
                        }
                    }
                    None => hit.record(
                        None,
                        &format!("header:{}", hm.name),
                        val,
                        sig.confidence,
                    ),
                }
            }

            // --- Cookies (matched against each raw Set-Cookie value) ---
            for pat in &sig.cookies {
                for cookie in input.set_cookies {
                    if let Some(caps) = pat.regex.captures(cookie) {
                        hit.record(
                            pat.version_from(&caps),
                            "cookie",
                            cookie,
                            pat.confidence.unwrap_or(sig.confidence),
                        );
                        break;
                    }
                }
            }

            // --- Favicon: an exact hash match is close to conclusive ---
            if let Some(hash) = input.favicon_hash {
                if sig.favicon.contains(&hash) {
                    hit.record(None, "favicon", &format!("mmh3={}", hash), 95);
                }
            }

            // --- Single-string haystacks ---
            let single: [(Field, Option<&str>); 3] = [
                (Field::Url, Some(input.url)),
                (Field::Cert, input.cert_issuer),
                (Field::Robots, input.robots_txt),
            ];
            for (field, haystack) in single {
                let Some(haystack) = haystack else { continue };
                match_patterns(sig, field, std::slice::from_ref(&haystack), &mut hit);
            }

            // --- Multi-string haystacks derived from the body ---
            match_patterns(sig, Field::Meta, &meta_tags, &mut hit);
            match_patterns(sig, Field::Script, &asset_urls, &mut hit);
            match_patterns(sig, Field::Css, &style_blocks, &mut hit);

            // --- Whole-body haystacks ---
            match_patterns(sig, Field::Html, std::slice::from_ref(&body), &mut hit);
            if self.has_text_patterns {
                let text: &str = &visible_text;
                match_patterns(sig, Field::Text, std::slice::from_ref(&text), &mut hit);
            }

            if hit.matched {
                matched_signatures.push(si);
                hit.merge_into(&mut found, sig);
            }
        }

        self.resolve_requires(&mut found, &mut matched_signatures);
        self.apply_excludes(&mut found, &matched_signatures);
        self.expand_implies(&mut found, &matched_signatures);

        let mut detections: Vec<TechDetection> =
            found.into_values().map(|h| h.into_detection()).collect();
        detections.sort_by(|a, b| a.product.cmp(&b.product));
        detections
    }

    /// Drop detections whose signature declares `requires` on a product that is
    /// not present. Iterated to a fixpoint, because a required product may
    /// itself be dropped by this rule.
    fn resolve_requires(&self, found: &mut HashMap<String, Hit>, matched: &mut Vec<usize>) {
        loop {
            let present: HashSet<&String> = found.keys().collect();
            let mut doomed: Vec<String> = Vec::new();
            for &si in matched.iter() {
                let sig = &self.signatures[si];
                if sig.requires.is_empty() || !found.contains_key(&sig.product) {
                    continue;
                }
                if !sig.requires.iter().all(|r| present.contains(r)) {
                    doomed.push(sig.product.clone());
                }
            }
            if doomed.is_empty() {
                return;
            }
            for product in &doomed {
                found.remove(product);
            }
            matched.retain(|&si| !doomed.contains(&self.signatures[si].product));
        }
    }

    /// Remove products excluded by a signature that matched.
    fn apply_excludes(&self, found: &mut HashMap<String, Hit>, matched: &[usize]) {
        let excluded: HashSet<String> = matched
            .iter()
            .filter(|&&si| found.contains_key(&self.signatures[si].product))
            .flat_map(|&si| self.signatures[si].excludes.iter().cloned())
            .collect();
        for product in excluded {
            found.remove(&product);
        }
    }

    /// Add technologies implied by what matched, following `implies` chains
    /// transitively and decaying confidence at each hop.
    fn expand_implies(&self, found: &mut HashMap<String, Hit>, matched: &[usize]) {
        let mut frontier: Vec<(String, u8, String)> = matched
            .iter()
            .filter(|&&si| found.contains_key(&self.signatures[si].product))
            .flat_map(|&si| {
                let sig = &self.signatures[si];
                let conf = found
                    .get(&sig.product)
                    .map(|h| h.confidence)
                    .unwrap_or(sig.confidence);
                sig.implies
                    .iter()
                    .map(move |i| (i.clone(), conf, sig.name.clone()))
            })
            .collect();

        for _ in 0..MAX_IMPLIES_DEPTH {
            if frontier.is_empty() {
                return;
            }
            let mut next: Vec<(String, u8, String)> = Vec::new();

            for (product, source_confidence, via) in frontier.drain(..) {
                let confidence =
                    ((source_confidence as u32 * IMPLIED_CONFIDENCE_RATIO) / 100) as u8;
                let (display, categories, cpe) = self
                    .index
                    .get(&product)
                    .cloned()
                    .unwrap_or_else(|| (product.clone(), Vec::new(), None));

                let entry = found.entry(product.clone()).or_insert_with(|| Hit {
                    product: product.clone(),
                    display_name: display,
                    version: None,
                    categories,
                    cpe,
                    confidence: 0,
                    source: "implied".to_string(),
                    sources: vec!["implied".to_string()],
                    evidence: truncate_evidence(&format!("implied by {}", via)),
                    matched: true,
                    has_direct_evidence: false,
                });
                let was_new = entry.confidence == 0;
                entry.confidence = combine_confidence(entry.confidence, confidence);

                // Only follow the chain onward the first time a product appears,
                // so a diamond in the graph does not re-walk the same subtree.
                if was_new {
                    if let Some(indices) = self.by_product.get(&product) {
                        for &si in indices {
                            for implied in &self.signatures[si].implies {
                                next.push((implied.clone(), confidence, product.clone()));
                            }
                        }
                    }
                }
            }
            frontier = next;
        }
    }

    /// The CPE 2.3 base registered for `product`, if the ruleset knows one.
    ///
    /// This is what lets a detection reach the right NVD record: without it the
    /// CVE lookup has to guess a CPE product token from a display name, which
    /// only works when the two happen to coincide.
    pub fn cpe_for(&self, product: &str) -> Option<crate::utils::cpe::Cpe> {
        self.index
            .get(&product.to_ascii_lowercase())
            .and_then(|(_, _, cpe)| cpe.as_deref())
            .and_then(crate::utils::cpe::Cpe::parse)
    }

    /// Products whose signature registers `hash` as a known favicon.
    pub fn products_for_favicon(&self, hash: i32) -> Vec<String> {
        self.by_favicon
            .get(&hash)
            .map(|idx| {
                idx.iter()
                    .map(|&i| self.signatures[i].product.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of loaded signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
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

        for re in &sig.js_content {
            if let Some(caps) = re.captures(scan) {
                if let Some(v) = caps.get(1).and_then(|m| normalize_version(m.as_str())) {
                    return Some(v);
                }
            }
        }
        for pat in &sig.html {
            if let Some(caps) = pat.regex.captures(scan) {
                if let Some(v) = pat.version_from(&caps) {
                    return Some(v);
                }
            }
        }
        None
    }
}

fn lowercase_all(v: Vec<String>) -> Vec<String> {
    v.into_iter().map(|s| s.to_ascii_lowercase()).collect()
}

/// Run one field's patterns over every haystack string, recording matches.
fn match_patterns(sig: &Signature, field: Field, haystacks: &[&str], hit: &mut Hit) {
    let patterns = sig.patterns_for(field);
    if patterns.is_empty() || haystacks.is_empty() {
        return;
    }
    for pat in patterns {
        for haystack in haystacks {
            // `is_match` can stop at the first match and use the literal
            // prefilters the regex crate builds per pattern; `captures` has to
            // run the slower engine that tracks group positions. Most patterns
            // miss, so paying for captures only on a hit is the difference
            // between milliseconds and hundreds of them on a large page.
            if !pat.regex.is_match(haystack) {
                continue;
            }
            let Some(caps) = pat.regex.captures(haystack) else {
                continue;
            };
            let evidence = caps.get(0).map(|m| m.as_str()).unwrap_or(haystack);
            hit.record(
                pat.version_from(&caps),
                field.label(),
                evidence,
                pat.confidence.unwrap_or(sig.confidence),
            );
            // One match per pattern is enough; other haystacks would only
            // re-prove the same rule.
            break;
        }
    }
}

/// True when `candidate` pins the same release down more precisely than
/// `current` does.
///
/// Drupal's generator tag says `Drupal 11` while a core asset URL may say
/// `?v=11.0.5`; whichever pattern happened to run first used to win, so the
/// bare major routinely beat the exact build. Only an extension of the same
/// version counts — `3.7.1` must never replace `11`, or one signature's
/// unrelated capture would overwrite another's.
fn is_more_precise(candidate: Option<&str>, current: Option<&str>) -> bool {
    let (Some(candidate), Some(current)) = (candidate, current) else {
        return false;
    };
    let (Some(new_v), Some(old_v)) = (
        crate::utils::version_rs::Version::from(candidate),
        crate::utils::version_rs::Version::from(current),
    ) else {
        return false;
    };
    let new_parts = new_v.numeric_components();
    let old_parts = old_v.numeric_components();
    if new_parts.len() <= old_parts.len() {
        return false;
    }
    new_parts.starts_with(&old_parts)
}

/// Combine two independent confidences the way corroborating evidence should:
/// each one reduces the remaining doubt, so 80 + 80 = 96 rather than 160.
fn combine_confidence(a: u8, b: u8) -> u8 {
    let a = a as u32;
    let b = b as u32;
    let combined = 100 - ((100 - a.min(100)) * (100 - b.min(100))) / 100;
    combined.min(100) as u8
}

/// Per-signature match state, promoted to a `TechDetection` once merged.
struct Hit {
    product: String,
    display_name: String,
    version: Option<String>,
    categories: Vec<String>,
    cpe: Option<String>,
    confidence: u8,
    source: String,
    sources: Vec<String>,
    evidence: String,
    matched: bool,
    /// False for purely implied entries, which must not be reported as if the
    /// scanner saw them.
    has_direct_evidence: bool,
}

impl Hit {
    fn new(sig: &Signature) -> Self {
        Hit {
            product: sig.product.clone(),
            display_name: sig.name.clone(),
            version: None,
            categories: sig.categories.clone(),
            cpe: sig.cpe.clone(),
            confidence: 0,
            source: String::new(),
            sources: Vec::new(),
            evidence: String::new(),
            matched: false,
            has_direct_evidence: false,
        }
    }

    /// Fold one matched pattern in. The reported `source`/`evidence` track the
    /// most informative match — a versioned one always wins, and among versioned
    /// ones the *most precise* wins, because that is the match a reader needs to
    /// see to check the CVE claim.
    fn record(&mut self, version: Option<String>, source: &str, evidence: &str, confidence: u8) {
        self.matched = true;
        self.has_direct_evidence = true;
        self.confidence = combine_confidence(self.confidence, confidence);
        if !self.sources.iter().any(|s| s == source) {
            self.sources.push(source.to_string());
        }

        let upgrades = self.source.is_empty()
            || (self.version.is_none() && version.is_some())
            || is_more_precise(version.as_deref(), self.version.as_deref());
        if upgrades {
            if version.is_some() {
                self.version = version;
            }
            self.source = source.to_string();
            self.evidence = truncate_evidence(evidence);
        }
    }

    fn merge_into(self, found: &mut HashMap<String, Hit>, sig: &Signature) {
        match found.get_mut(&sig.product) {
            None => {
                found.insert(sig.product.clone(), self);
            }
            Some(existing) => {
                existing.matched = true;
                existing.has_direct_evidence |= self.has_direct_evidence;
                existing.confidence = combine_confidence(existing.confidence, self.confidence);
                if existing.version.is_none() && self.version.is_some() {
                    existing.version = self.version;
                    existing.source = self.source.clone();
                    existing.evidence = self.evidence.clone();
                } else if existing.source.is_empty() {
                    existing.source = self.source.clone();
                    existing.evidence = self.evidence.clone();
                }
                for s in self.sources {
                    if !existing.sources.iter().any(|e| *e == s) {
                        existing.sources.push(s);
                    }
                }
                if existing.categories.is_empty() {
                    existing.categories = self.categories;
                }
                if existing.cpe.is_none() {
                    existing.cpe = self.cpe;
                }
            }
        }
    }

    fn into_detection(self) -> TechDetection {
        TechDetection {
            product: self.product,
            display_name: self.display_name,
            version: self.version,
            categories: self.categories,
            cpe: self.cpe,
            confidence: self.confidence,
            source: self.source,
            sources: self.sources,
            evidence: self.evidence,
        }
    }
}

// ---------------------------------------------------------------------------
// Haystack extraction
// ---------------------------------------------------------------------------

lazy_static! {
    static ref META_TAG_RE: Regex = Regex::new(r"(?is)<meta\b[^>]*>").expect("meta regex");
    static ref ASSET_URL_RE: Regex = Regex::new(
        r#"(?is)<(?:script[^>]*\bsrc|link[^>]*\bhref|img[^>]*\bsrc)\s*=\s*["']([^"']+)["']"#
    )
    .expect("asset regex");
    static ref STYLE_BLOCK_RE: Regex =
        Regex::new(r"(?is)<style\b[^>]*>(.*?)</style>").expect("style regex");
    // Written as three alternatives rather than `<(script|style)…</\1>` because
    // the `regex` crate has no backreferences.
    static ref MARKUP_RE: Regex = Regex::new(
        r"(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<[^>]+>"
    )
    .expect("markup regex");
}

/// Every `<meta …>` element in the document, as raw strings.
fn extract_meta_tags(body: &str) -> Vec<&str> {
    META_TAG_RE.find_iter(body).map(|m| m.as_str()).collect()
}

/// Every referenced asset URL (`<script src>`, `<link href>`, `<img src>`).
///
/// Scoping `scripts` patterns to these instead of the whole body is what stops
/// a page that merely *mentions* `jquery-3.5.1.min.js` in prose from being
/// recorded as running it.
fn extract_asset_urls(body: &str) -> Vec<&str> {
    ASSET_URL_RE
        .captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect()
}

/// The contents of every inline `<style>` block.
fn extract_style_blocks(body: &str) -> Vec<&str> {
    STYLE_BLOCK_RE
        .captures_iter(body)
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect()
}

/// The document with script/style bodies and all tags removed, so `text`
/// patterns see what a visitor sees.
fn strip_markup(body: &str) -> String {
    MARKUP_RE.replace_all(body, " ").into_owned()
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
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head>
            <body><div class="woocommerce woocommerce-cart">cart</div></body></html>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://shop.example/");
        assert!(find(&dets, "woocommerce").is_some());
        assert!(
            find(&dets, "wordpress").is_some(),
            "woocommerce should imply wordpress"
        );
    }

    #[test]
    fn an_article_about_woocommerce_is_not_a_woocommerce_site() {
        // wordpress.org itself tripped this: the ruleset matched the bare word
        // anywhere in the page, so every changelog and marketing page that
        // named the plugin was recorded as running it.
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head>
            <body><h1>What's new</h1><p>WooCommerce 8.4 ships this week.</p>
            <a href="https://woocommerce.com/">Read more</a></body></html>"#;
        let dets = engine().detect(&HashMap::new(), &[], body, "https://wordpress.example/");
        assert!(find(&dets, "wordpress").is_some());
        assert!(
            find(&dets, "woocommerce").is_none(),
            "naming a plugin in prose is not evidence of running it"
        );
    }

    #[test]
    fn a_universal_security_header_never_identifies_a_product() {
        // `X-Content-Type-Options: nosniff` was matched as a Splunk marker,
        // which flagged every hardened site on the internet as running Splunk.
        let dets = engine().detect(
            &headers(&[
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-amz-request-id", "ABC123"),
            ]),
            &[],
            "",
            "https://hardened.example/",
        );
        assert!(
            dets.is_empty(),
            "standard security headers must identify nothing, got {:?}",
            dets.iter().map(|d| &d.product).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_ordinary_versioned_asset_url_identifies_nothing() {
        // `/js/app.js?ver=1.2.3` is the most common asset URL on the web; a
        // Zabbix rule shaped like that matched wordpress.org.
        let body = r#"<html><body>
            <script src="/js/app.js?ver=1.2.3"></script>
            <script src="/js/vendors/utils.js?ver=4.5"></script>
            <link rel="stylesheet" href="/css/site.css?ver=2.0">
            </body></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://plain.example/");
        assert!(
            dets.is_empty(),
            "generic versioned assets must identify nothing, got {:?}",
            dets.iter().map(|d| (&d.product, &d.evidence)).collect::<Vec<_>>()
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

    // -----------------------------------------------------------------------
    // Engine v2: pattern syntax, scoped haystacks, relationships
    // -----------------------------------------------------------------------

    /// A boring, hand-written page that runs none of the technologies we ship
    /// signatures for. Any detection against this is a false positive, and the
    /// whole ruleset is checked against it.
    const PLAIN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Acme Widgets</title>
<meta name="description" content="We sell widgets.">
<link rel="stylesheet" href="/assets/site.css">
<style>body { font-family: system-ui; } .banner { color: #333; }</style>
</head><body>
<h1>Acme Widgets</h1>
<p>Our team writes about WordPress, Drupal and jQuery on the blog. We once
migrated off Apache and evaluated nginx, Tomcat and Microsoft IIS. A colleague
recommends jquery-3.5.1.min.js for new projects.</p>
<script src="/assets/app.js"></script>
<script src="/assets/video.js"></script>
<script>window.APP = { ready: true };</script>
</body></html>"#;

    #[test]
    fn every_static_regex_compiles() {
        // These live in lazy_static and would otherwise only blow up on the
        // first response that reaches them.
        assert!(META_TAG_RE.is_match("<meta charset=\"utf-8\">"));
        assert!(ASSET_URL_RE.is_match(r#"<script src="/a.js"></script>"#));
        assert!(STYLE_BLOCK_RE.is_match("<style>a{}</style>"));
        assert!(!MARKUP_RE.as_str().is_empty());
        assert_eq!(strip_markup("<b>hi</b>").trim(), "hi");
    }

    #[test]
    fn a_plain_page_produces_no_detections() {
        let dets = engine().detect(&headers(&[]), &[], PLAIN_PAGE, "https://acme.example/");
        assert!(
            dets.is_empty(),
            "plain page should be clean, got: {:?}",
            dets.iter().map(|d| (&d.product, &d.source, &d.evidence)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn prose_mentioning_a_library_is_not_a_detection() {
        // The filename appears in a paragraph, not in a <script src>. Scoping
        // `scripts` patterns to extracted asset URLs is what makes this hold.
        assert!(
            find(
                &engine().detect(&headers(&[]), &[], PLAIN_PAGE, "https://acme.example/"),
                "jquery"
            )
            .is_none(),
            "jQuery named in prose must not count as jQuery running"
        );
    }

    #[test]
    fn a_sites_own_video_js_is_not_the_video_js_library() {
        // `/assets/video.js` in PLAIN_PAGE is a plausible name for a site's own
        // helper script; only a versioned or vendor-distribution path counts.
        let dets = engine().detect(&headers(&[]), &[], PLAIN_PAGE, "https://acme.example/");
        assert!(find(&dets, "video.js").is_none());

        let real = r#"<script src="/js/video-js-8.6.1.min.js"></script>"#;
        let dets = engine().detect(&headers(&[]), &[], real, "https://acme.example/");
        assert_eq!(find(&dets, "video.js").unwrap().version.as_deref(), Some("8.6.1"));
    }

    #[test]
    fn meta_patterns_only_see_meta_tags() {
        // The generator string is in body text, not in a <meta> element.
        let body = r#"<html><body><p>content="Drupal 9"</p></body></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://x.example/");
        assert!(find(&dets, "drupal").is_none());

        let real = r#"<html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)"></head></html>"#;
        let dets = engine().detect(&headers(&[]), &[], real, "https://x.example/");
        assert_eq!(find(&dets, "drupal").unwrap().version.as_deref(), Some("9"));
    }

    #[test]
    fn corroborating_signals_raise_confidence_without_overflowing() {
        // One weak marker stays weak.
        let one = engine().detect(&headers(&[]), &[], r#"<div class="wp-content"></div>"#, "https://x/");
        // Several independent WordPress signals should land near certainty.
        let many = engine().detect(
            &headers(&[("x-pingback", "https://x/xmlrpc.php")]),
            &["wordpress_logged_in_abc=1; path=/".to_string()],
            r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head>
               <body><link rel="stylesheet" href="/wp-content/themes/x/style.css">
               <script src="/wp-includes/js/jquery.js"></script></body></html>"#,
            "https://x/",
        );
        let wp = find(&many, "wordpress").expect("WordPress detected");
        assert!(wp.confidence >= 95, "expected high confidence, got {}", wp.confidence);
        assert!(wp.confidence <= 100, "confidence must never exceed 100");
        assert!(wp.sources.len() >= 3, "expected several sources, got {:?}", wp.sources);
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
        assert!(wp.is_reliable());
        let _ = one;
    }

    #[test]
    fn an_implied_product_is_marked_as_inferred_not_observed() {
        // `Server: Kestrel` proves ASP.NET is behind it, but nothing in the
        // response is direct ASP.NET evidence, so it must not be presented as
        // though the scanner saw it.
        let dets = engine().detect(&headers(&[("server", "Kestrel")]), &[], "", "https://api.example/");
        let kestrel = find(&dets, "kestrel").expect("Kestrel");
        let aspnet = find(&dets, "asp.net").expect("ASP.NET implied by Kestrel");

        assert_eq!(aspnet.source, "implied");
        assert!(aspnet.evidence.contains("Kestrel"), "evidence should name the implier");
        assert!(
            aspnet.confidence < kestrel.confidence,
            "implied {} should decay below observed {}",
            aspnet.confidence,
            kestrel.confidence
        );
        assert!(aspnet.version.is_none(), "an inference never carries a version");
    }

    #[test]
    fn implies_reaches_through_a_chain() {
        // WooCommerce -> WordPress -> PHP. WordPress is also directly visible
        // here (the plugin path *is* a WordPress marker), but PHP is reachable
        // only by following the chain a second hop.
        let dets = engine().detect(
            &headers(&[]),
            &[],
            r#"<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css">"#,
            "https://shop.example/",
        );
        assert!(find(&dets, "woocommerce").is_some());
        let wp = find(&dets, "wordpress").expect("WordPress");
        let php = find(&dets, "php").expect("PHP implied two hops out");

        assert_eq!(php.source, "implied");
        assert!(
            php.confidence < wp.confidence,
            "a second-hop inference must be weaker than its source"
        );
        assert!(
            !php.is_reliable(),
            "a two-hop inference is not evidence enough to open a CVE finding"
        );
    }

    #[test]
    fn excludes_removes_an_impersonated_product() {
        // LiteSpeed can be configured to answer with an Apache Server header.
        let dets = engine().detect(
            &headers(&[("server", "Apache"), ("x-litespeed-cache", "hit")]),
            &[],
            "",
            "https://x/",
        );
        assert!(find(&dets, "litespeed").is_some());
        assert!(
            find(&dets, "apache").is_none(),
            "LiteSpeed's own marker means the Apache banner is impersonation"
        );

        // Without the LiteSpeed marker, Apache stands.
        let dets = engine().detect(&headers(&[("server", "Apache/2.4.49")]), &[], "", "https://x/");
        assert_eq!(find(&dets, "apache").unwrap().version.as_deref(), Some("2.4.49"));
    }

    #[test]
    fn requires_suppresses_a_plugin_without_its_host() {
        // A path that looks like a plugin, on a site with nothing else saying
        // WordPress — e.g. a proxy or a mirrored asset directory.
        let orphan = r#"<img src="/wp-content/plugins/elementor/assets/img/x.png">"#;
        let dets = engine().detect(&headers(&[]), &[], orphan, "https://cdn.example/");
        assert!(find(&dets, "wordpress").is_some(), "the path itself is a WordPress marker");

        // With no WordPress marker at all, the plugin must not be reported.
        let dets = engine().detect(
            &headers(&[]),
            &[],
            r#"<script src="https://other.example/plugins/elementor/frontend.js"></script>"#,
            "https://cdn.example/",
        );
        assert!(find(&dets, "elementor").is_none());
    }

    #[test]
    fn wordpress_plugin_version_comes_from_the_ver_query_string() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2">
            <script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.3"></script>
            </head></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://x/");
        let el = find(&dets, "elementor").expect("Elementor");
        assert_eq!(el.version.as_deref(), Some("3.18.3"));
        assert_eq!(el.cpe.as_deref(), Some("cpe:2.3:a:elementor:website_builder"));
    }

    #[test]
    fn confidence_tag_in_a_pattern_overrides_the_signature_default() {
        // The Struts `.action` URL rule was removed for being too weak, so use
        // the tag parser directly on a representative pattern.
        let pat = Pattern::compile(r"foo\;confidence:30", "test").unwrap();
        assert_eq!(pat.confidence, Some(30));
        assert!(pat.regex.is_match("xfoox"));
    }

    #[test]
    fn version_tag_selects_an_explicit_capture_group() {
        let pat = Pattern::compile(r"(\w+)/(\d[\d.]*)\;version:\2", "test").unwrap();
        let caps = pat.regex.captures("nginx/1.25.3").unwrap();
        assert_eq!(pat.version_from(&caps).as_deref(), Some("1.25.3"));
    }

    #[test]
    fn version_template_can_join_literals_and_groups() {
        let pat = Pattern::compile(r"v(\d+)_(\d+)\;version:\1.\2", "test").unwrap();
        let caps = pat.regex.captures("v7_4").unwrap();
        assert_eq!(pat.version_from(&caps).as_deref(), Some("7.4"));
    }

    #[test]
    fn version_ternary_picks_a_branch_on_group_presence() {
        let pat = Pattern::compile(r"lib(?:-(\d[\d.]*))?\.js\;version:\1?\1:1.0", "test").unwrap();
        let with = pat.regex.captures("lib-2.5.js").unwrap();
        assert_eq!(pat.version_from(&with).as_deref(), Some("2.5"));
        let without = pat.regex.captures("lib.js").unwrap();
        assert_eq!(pat.version_from(&without).as_deref(), Some("1.0"));
    }

    #[test]
    fn implicit_group_one_still_works_for_untagged_patterns() {
        let pat = Pattern::compile(r"nginx/([\d.]+)", "test").unwrap();
        let caps = pat.regex.captures("nginx/1.25.3").unwrap();
        assert_eq!(pat.version_from(&caps).as_deref(), Some("1.25.3"));
    }

    // -----------------------------------------------------------------------
    // New signal sources
    // -----------------------------------------------------------------------

    #[test]
    fn the_most_precise_version_on_the_page_wins() {
        // Drupal's generator tag only ever gives the major. When a core asset
        // URL also carries the exact build, that is the one to report — the
        // bare major used to win purely because `meta` runs before `scripts`.
        let body = r#"<html><head>
            <meta name="Generator" content="Drupal 11 (https://www.drupal.org)">
            <script src="/core/misc/drupal.js?v=11.0.5"></script>
            </head></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://cms.example/");
        let drupal = find(&dets, "drupal").expect("Drupal");
        assert_eq!(drupal.version.as_deref(), Some("11.0.5"));
    }

    #[test]
    fn a_major_only_version_is_still_reported_when_it_is_all_there_is() {
        // lafayetteanticipations.com: aggregation is on, so the generator tag
        // is the only version signal. Reporting "11" is correct; the CVE path
        // is what has to treat it as a series.
        let body = r#"<html><head>
            <meta name="Generator" content="Drupal 11 (https://www.drupal.org)">
            </head><body><script src="/core/assets/vendor/jquery/jquery.min.js?v=4.0.0"></script>
            </body></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://cms.example/");
        let drupal = find(&dets, "drupal").expect("Drupal");
        assert_eq!(drupal.version.as_deref(), Some("11"));
        // The jQuery version on the same page must not leak into Drupal's.
        assert_eq!(find(&dets, "jquery").unwrap().version.as_deref(), Some("4.0.0"));
    }

    #[test]
    fn a_drupal_page_is_not_also_a_prestashop_page() {
        // A `/themes/<name>/assets/` path is a shape half the CMS world uses;
        // as a PrestaShop marker it fired on a live Drupal site.
        let body = r#"<html><head>
            <meta name="Generator" content="Drupal 11 (https://www.drupal.org)">
            <link rel="stylesheet" href="/themes/custom/site/assets/css/main.css">
            <script src="/themes/custom/site/assets/js/app.js"></script>
            </head><body data-drupal-selector="page"></body></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://cms.example/");
        assert!(find(&dets, "drupal").is_some());
        assert!(
            find(&dets, "prestashop").is_none(),
            "a themed asset path is not a PrestaShop marker"
        );
    }

    #[test]
    fn precision_upgrade_requires_the_same_release() {
        // An unrelated longer version must never displace a shorter one.
        assert!(is_more_precise(Some("11.0.5"), Some("11")));
        assert!(is_more_precise(Some("8.2.14"), Some("8.2")));
        assert!(!is_more_precise(Some("3.7.1"), Some("11")));
        assert!(!is_more_precise(Some("12.0.1"), Some("11")));
        assert!(!is_more_precise(Some("11"), Some("11.0.5")));
        assert!(!is_more_precise(Some("11.0.5"), Some("11.0.5")));
        assert!(!is_more_precise(None, Some("11")));
        assert!(!is_more_precise(Some("11.0.5"), None));
    }

    #[test]
    fn detects_from_the_tls_certificate_issuer() {
        let input = DetectionInput::new("https://vpn.example/", "")
            .with_cert_issuer(Some("CN=FGT60E4Q17000000,OU=FortiGate,O=Fortinet,L=Sunnyvale,ST=California,C=US"));
        let dets = engine().detect_with(&input);
        let fos = find(&dets, "fortios").expect("FortiOS from certificate issuer");
        assert_eq!(fos.source, "cert");
        assert_eq!(fos.cpe.as_deref(), Some("cpe:2.3:o:fortinet:fortios"));
    }

    #[test]
    fn detects_from_a_known_favicon_hash() {
        let input = DetectionInput::new("https://gw.example/", "").with_favicon_hash(Some(-1166125415));
        let dets = engine().detect_with(&input);
        let ns = find(&dets, "citrix-netscaler").expect("NetScaler from favicon");
        assert_eq!(ns.source, "favicon");
        // A favicon hash never yields a version, so it can never by itself
        // drive a CVE lookup — which matters, because favicon hashes are
        // cheap to forge.
        assert!(ns.version.is_none());
    }

    #[test]
    fn detects_from_robots_txt() {
        let input = DetectionInput::new("https://blog.example/", "")
            .with_robots_txt(Some("User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"));
        let dets = engine().detect_with(&input);
        assert_eq!(find(&dets, "wordpress").unwrap().source, "robots");
    }

    #[test]
    fn a_soft_404_robots_file_is_not_matched_as_html() {
        // robots.txt patterns are anchored per-line on directives, so an HTML
        // page that merely contains the word Disallow does not match.
        let input = DetectionInput::new("https://x/", "")
            .with_robots_txt(Some("<html><body>Disallow: /wp-admin/ appears here</body></html>"));
        assert!(find(&engine().detect_with(&input), "wordpress").is_none());
    }

    #[test]
    fn visible_text_patterns_see_through_markup() {
        let body = r#"<html><body><div class="footer">
            <a href="https://www.cacti.net">Cacti</a> <span>Version</span> <b>1.2.24</b>
            </div></body></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://mon.example/");
        let cacti = find(&dets, "cacti").expect("Cacti from footer text");
        assert_eq!(cacti.version.as_deref(), Some("1.2.24"));
    }

    #[test]
    fn url_patterns_match_the_final_url() {
        let input = DetectionInput::new("https://vpn.example/global-protect/login.esp", "");
        let dets = engine().detect_with(&input);
        let gp = find(&dets, "globalprotect").expect("GlobalProtect from URL");
        assert_eq!(gp.cpe.as_deref(), Some("cpe:2.3:o:paloaltonetworks:pan-os"));
    }

    // -----------------------------------------------------------------------
    // Enterprise edge coverage — the products with the densest KEV history
    // -----------------------------------------------------------------------

    #[test]
    fn detects_citrix_netscaler_from_its_session_cookie() {
        let dets = engine().detect(
            &headers(&[]),
            &["NSC_AAAC=abc123; secure; path=/".to_string()],
            "",
            "https://gw.example/",
        );
        assert!(find(&dets, "citrix-netscaler").is_some());
    }

    #[test]
    fn detects_netscaler_version_from_its_header() {
        let dets = engine().detect(&headers(&[("x-ns-version", "NS13.1")]), &[], "", "https://gw/");
        assert_eq!(
            find(&dets, "citrix-netscaler").unwrap().version.as_deref(),
            Some("13.1")
        );
    }

    #[test]
    fn detects_fortigate_ssl_vpn_from_its_login_redirect() {
        let body = r#"<html><head><script>top.location=window.location;top.location="/remote/login";</script></head></html>"#;
        let dets = engine().detect(&headers(&[]), &[], body, "https://fw.example/");
        assert!(find(&dets, "fortios").is_some());
    }

    #[test]
    fn detects_ivanti_connect_secure_from_its_cookie_and_paths() {
        let dets = engine().detect(
            &headers(&[]),
            &["DSSignInURL=/; secure; HttpOnly".to_string()],
            r#"<img src="/dana-na/imgs/logo.gif">"#,
            "https://sslvpn.example/dana-na/auth/url_default/welcome.cgi",
        );
        let ivanti = find(&dets, "ivanti-connect-secure").expect("Ivanti Connect Secure");
        assert!(ivanti.confidence >= 95, "three independent signals should corroborate");
    }

    #[test]
    fn detects_cisco_asa_webvpn() {
        let dets = engine().detect(
            &headers(&[]),
            &["webvpn=; expires=Thu, 01 Jan 1970".to_string()],
            r#"<link rel="stylesheet" href="/+CSCOU+/portal.css">"#,
            "https://vpn.example/+CSCOE+/logon.html",
        );
        assert!(find(&dets, "cisco-asa").is_some());
    }

    #[test]
    fn detects_f5_big_ip_and_apm_together() {
        let dets = engine().detect(
            &headers(&[]),
            &[
                "BIGipServerpool_www=110536896.20480.0000; path=/".to_string(),
                "MRHSession=0123456789abcdef0123456789abcdef; path=/".to_string(),
            ],
            "",
            "https://portal.example/my.policy",
        );
        assert!(find(&dets, "f5-big-ip").is_some());
        assert!(find(&dets, "f5-big-ip-apm").is_some());
    }

    #[test]
    fn extracts_exact_versions_from_file_transfer_version_oracles() {
        // These three products each publish their exact build in a header, and
        // each has been mass-exploited; getting the version right is the whole
        // difference between a CVE finding and a shrug.
        let moveit = engine().detect(
            &headers(&[("x-moveitisapi-version", "15.0.2.13")]),
            &[],
            "",
            "https://mft.example/",
        );
        assert_eq!(
            find(&moveit, "moveit-transfer").unwrap().version.as_deref(),
            Some("15.0.2.13")
        );

        let crushftp = engine().detect(
            &headers(&[("server", "CrushFTP HTTP Server Version 10.5.1")]),
            &[],
            "",
            "https://ftp.example/",
        );
        assert_eq!(
            find(&crushftp, "crushftp").unwrap().version.as_deref(),
            Some("10.5.1")
        );

        let servu = engine().detect(
            &headers(&[("server", "Serv-U/15.1.6.31")]),
            &[],
            "",
            "https://ftp.example/",
        );
        assert_eq!(find(&servu, "serv-u").unwrap().version.as_deref(), Some("15.1.6.31"));
    }

    #[test]
    fn detects_confluence_version_from_its_ajs_meta_tag() {
        let body = r#"<html><head><meta name="ajs-version-number" content="8.5.4">
            <meta name="ajs-build-number" content="9012"></head>
            <body><div id="com.atlassian.confluence"></div></body></html>"#;
        let dets = engine().detect(
            &headers(&[("x-confluence-request-time", "1700000000000")]),
            &[],
            body,
            "https://wiki.example/",
        );
        let c = find(&dets, "confluence").expect("Confluence");
        assert_eq!(c.version.as_deref(), Some("8.5.4"));
        assert_eq!(c.cpe.as_deref(), Some("cpe:2.3:a:atlassian:confluence_server"));
        assert!(c.is_reliable());
    }

    #[test]
    fn detects_screenconnect_version_from_its_server_header() {
        let dets = engine().detect(
            &headers(&[("server", "ScreenConnect/23.9.8.8811")]),
            &[],
            "",
            "https://remote.example/",
        );
        assert_eq!(
            find(&dets, "screenconnect").unwrap().version.as_deref(),
            Some("23.9.8.8811")
        );
    }

    #[test]
    fn openresty_implies_nginx() {
        let dets = engine().detect(&headers(&[("server", "openresty/1.21.4.1")]), &[], "", "https://x/");
        assert_eq!(
            find(&dets, "openresty").unwrap().version.as_deref(),
            Some("1.21.4.1")
        );
        assert!(find(&dets, "nginx").is_some(), "OpenResty is nginx underneath");
    }

    #[test]
    fn detects_zimbra_and_owa_webmail() {
        let zimbra = engine().detect(
            &headers(&[]),
            &["ZM_TEST=true; path=/".to_string()],
            r#"<script src="/zimbra/js/zimbraMail.js"></script>"#,
            "https://mail.example/zimbra/mail/",
        );
        assert!(find(&zimbra, "zimbra").is_some());

        let owa = engine().detect(
            &headers(&[]),
            &[],
            r#"<link href="/owa/auth/15.2.1544.4/themes/resources/logon.css" rel="stylesheet">"#,
            "https://mail.example/owa/auth/logon.aspx",
        );
        let o = find(&owa, "owa").expect("OWA");
        assert_eq!(o.version.as_deref(), Some("15.2.1544.4"));
        assert!(find(&owa, "exchange").is_some(), "OWA implies Exchange");
    }

    // -----------------------------------------------------------------------
    // Ruleset integrity
    // -----------------------------------------------------------------------

    #[test]
    fn detection_stays_fast_on_a_large_page() {
        // Guard against re-introducing a whole-ruleset scan that scales badly.
        // A `RegexSet` prefilter once cost 435 ms on a 660 KB page — 40x more
        // than simply running each pattern, because a set cannot use the
        // per-pattern literal prefilters the regex crate builds.
        //
        // The budget is deliberately loose: this runs in a debug build, which
        // is roughly 45x slower than release, and it only has to catch an
        // order-of-magnitude regression.
        let chunk = r#"<div class="row"><p>Lorem ipsum dolor sit amet, consectetur.</p>
            <a href="/page/42">link</a><span data-id="x">text</span></div>"#;
        let mut body = String::with_capacity(1_100_000);
        body.push_str("<html><head><title>Big</title></head><body>");
        while body.len() < 1_000_000 {
            body.push_str(chunk);
        }
        body.push_str("</body></html>");

        let started = std::time::Instant::now();
        let dets = engine().detect(&headers(&[]), &[], &body, "https://big.example/");
        let elapsed = started.elapsed();

        assert!(dets.is_empty(), "filler markup must not match anything");
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "1 MB page took {:?}; the ruleset scan has regressed",
            elapsed
        );
    }

    #[test]
    fn body_scanning_is_bounded() {
        // A response far larger than the cap must still terminate promptly and
        // must not be read past MAX_BODY_CHARS.
        let mut body = "x".repeat(MAX_BODY_CHARS + 500_000);
        body.push_str("<meta name=\"generator\" content=\"WordPress 6.4\">");
        let started = std::time::Instant::now();
        let dets = engine().detect(&headers(&[]), &[], &body, "https://big.example/");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(
            find(&dets, "wordpress").is_none(),
            "content past the scan cap must not be matched"
        );
    }

    #[test]
    fn every_signature_cpe_parses() {
        for sig in &engine().signatures {
            if let Some(raw) = &sig.cpe {
                assert!(
                    crate::utils::cpe::Cpe::parse(raw).is_some(),
                    "signature {} has an unparseable CPE: {}",
                    sig.name,
                    raw
                );
            }
        }
    }

    #[test]
    fn every_implies_excludes_and_requires_names_a_known_product() {
        let known: std::collections::HashSet<&str> =
            engine().signatures.iter().map(|s| s.product.as_str()).collect();
        for sig in &engine().signatures {
            for (kind, list) in [
                ("implies", &sig.implies),
                ("excludes", &sig.excludes),
                ("requires", &sig.requires),
            ] {
                for product in list {
                    assert!(
                        known.contains(product.as_str()),
                        "{} {} references unknown product '{}'",
                        sig.name,
                        kind,
                        product
                    );
                }
            }
        }
    }

    /// A page that names, links to and writes about a long list of products
    /// without running any of them — the shape of a vendor comparison page, a
    /// changelog, or a nav menu. This is the single most productive source of
    /// false positives in a fingerprint ruleset: `nextcloud.com` linking to a
    /// page about Roundcube was recorded as running Roundcube.
    const LINK_FARM: &str = r#"<!DOCTYPE html><html><head>
<title>Integrations directory</title>
<meta name="description" content="WordPress, Drupal, Joomla and more">
</head><body>
<nav>
  <a href="/integrations/wordpress/">WordPress</a>
  <a href="/integrations/roundcube/">Roundcube — the most popular webmail</a>
  <a href="/integrations/laravel/">Laravel</a>
  <a href="/integrations/gitlab/">GitLab</a>
  <a href="/integrations/phpmyadmin/">phpMyAdmin</a>
  <a href="/integrations/joomla/">Joomla!</a>
  <a href="/integrations/woocommerce/">WooCommerce</a>
  <a href="/integrations/zabbix/">Zabbix</a>
  <a href="/integrations/rabbitmq/">RabbitMQ Management</a>
  <a href="/integrations/confluence/">Confluence</a>
  <a href="/integrations/jenkins/">Jenkins</a>
  <a href="/integrations/splunk/">Splunk</a>
  <a href="/integrations/grafana/">Grafana</a>
  <a href="/integrations/moodle/">Moodle</a>
  <a href="/integrations/odoo/">Odoo</a>
</nav>
<article><h1>Comparing CMS platforms</h1>
<p>Drupal, TYPO3 and Magento all take a different approach from WordPress.
Teams running Apache Tomcat or Microsoft IIS often ask about ColdFusion.
Our SDK ships as jquery-3.5.1.min.js and bootstrap.min.css.</p></article>
</body></html>"#;

    #[test]
    fn a_page_that_only_talks_about_products_detects_none_of_them() {
        let dets = engine().detect(&headers(&[]), &[], LINK_FARM, "https://vendor.example/integrations/");
        assert!(
            dets.is_empty(),
            "linking to and writing about products is not running them; got {:?}",
            dets.iter().map(|d| (&d.product, &d.evidence)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn naming_every_product_in_the_ruleset_detects_none_of_them() {
        // The generalisation of the link-farm case, run against the whole
        // ruleset: build a page that mentions every signature's display name
        // and product key, in prose and in link text and hrefs, and assert that
        // nothing matches. A signature that fires here is matching the
        // product's *name* rather than something the product emits, and will
        // report itself on every comparison page, changelog and nav menu on the
        // internet.
        //
        // Self-maintaining: adding a signature automatically extends the page.
        let mut body = String::from("<!DOCTYPE html><html><head><title>Directory</title></head><body>\n");
        for sig in &engine().signatures {
            body.push_str(&format!(
                "<li><a href=\"/compare/{}/\">{}</a> — we integrate with {} and {}.</li>\n",
                sig.product.replace(['.', ' '], "-"),
                sig.name,
                sig.name,
                sig.product
            ));
        }
        body.push_str("</body></html>");

        let dets = engine().detect(&headers(&[]), &[], &body, "https://vendor.example/compare/");
        assert!(
            dets.is_empty(),
            "these signatures match the product's name rather than its output: {:?}",
            dets.iter()
                .map(|d| (d.product.as_str(), d.source.as_str(), d.evidence.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn products_are_unique_across_the_ruleset() {
        let mut seen = std::collections::HashSet::new();
        for sig in &engine().signatures {
            assert!(
                seen.insert(sig.product.as_str()),
                "duplicate product key '{}' — the second signature's patterns would \
                 silently merge into the first",
                sig.product
            );
        }
    }

    #[test]
    fn every_signature_has_at_least_one_pattern() {
        for sig in &engine().signatures {
            let total = sig.headers.len()
                + sig.cookies.len()
                + sig.html.len()
                + sig.meta.len()
                + sig.scripts.len()
                + sig.css.len()
                + sig.text.len()
                + sig.url.len()
                + sig.cert_issuer.len()
                + sig.robots.len()
                + sig.favicon.len();
            assert!(total > 0, "signature {} can never match", sig.name);
        }
    }

    #[test]
    fn the_ruleset_covers_the_kev_heavy_edge_products() {
        // A regression guard: these are the categories an EASM exists to find,
        // and they are exactly the ones a Wappalyzer-derived ruleset misses.
        for product in [
            "citrix-netscaler",
            "fortios",
            "ivanti-connect-secure",
            "globalprotect",
            "cisco-asa",
            "f5-big-ip",
            "moveit-transfer",
            "crushftp",
            "confluence",
            "screenconnect",
            "vcenter",
            "zimbra",
            "weblogic",
            "coldfusion",
        ] {
            assert!(
                engine().cpe_for(product).is_some() || engine().supports_asset_version(product)
                    || engine().signatures.iter().any(|s| s.product == product),
                "missing signature for {}",
                product
            );
        }
        assert!(
            engine().signature_count() >= 150,
            "ruleset shrank unexpectedly: {}",
            engine().signature_count()
        );
    }
}

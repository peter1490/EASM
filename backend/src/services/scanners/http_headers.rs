//! HTTP security header and cookie analysis, with Mozilla Observatory scoring.
//!
//! Split from the HTTP I/O so every grading rule is a pure function over parsed
//! headers. The score modifiers are the published Mozilla HTTP Observatory ones
//! (baseline 100, letter chart from A+ down to F), which is what makes a grade
//! here comparable to what securityheaders.com or `observatory.mozilla.org`
//! would report for the same response.
//!
//! The header checks themselves go further than a lookup table: a `Content-
//! Security-Policy` that is present but contains `'unsafe-inline'` in
//! `script-src` provides no XSS protection at all, and grading it as "present"
//! is the single most common way a header scanner misleads its reader.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Mozilla Observatory's baseline. Everything is a deduction or a bonus from here.
pub const OBSERVATORY_BASELINE: i32 = 100;

/// One graded check, carrying the Observatory test name so a result can be
/// compared against the reference implementation directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderCheck {
    /// The Observatory test name, e.g. `csp-implemented-with-unsafe-inline`.
    pub name: String,
    pub category: String,
    pub passed: bool,
    pub score_modifier: i32,
    pub description: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAnalysis {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    /// `__Host-` and `__Secure-` are enforced by the browser, not just advisory.
    pub prefix: Option<String>,
    /// Heuristic: a cookie whose name suggests it carries a session or token.
    pub session_like: bool,
    pub issues: Vec<String>,
}

/// A parsed `Content-Security-Policy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CspAnalysis {
    pub present: bool,
    pub report_only: bool,
    pub directives: BTreeMap<String, Vec<String>>,
    pub unsafe_inline_script: bool,
    pub unsafe_inline_style: bool,
    pub unsafe_eval: bool,
    /// A wildcard or bare scheme (`https:`, `data:`) in a fetch directive is as
    /// permissive as no policy for that resource type.
    pub wildcard_sources: Vec<String>,
    pub insecure_scheme: bool,
    pub has_default_src_none: bool,
    pub has_frame_ancestors: bool,
    pub has_object_src: bool,
    pub has_base_uri: bool,
    pub has_form_action: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HstsAnalysis {
    pub present: bool,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
    pub valid: bool,
    pub issues: Vec<String>,
}

/// Six months, the threshold Observatory and the HSTS preload list both use.
pub const HSTS_MIN_MAX_AGE: u64 = 15_768_000;

pub fn parse_hsts(value: Option<&str>) -> HstsAnalysis {
    let Some(value) = value else {
        return HstsAnalysis::default();
    };
    let mut analysis = HstsAnalysis {
        present: true,
        valid: true,
        ..Default::default()
    };
    for token in value.split(';') {
        let token = token.trim();
        let lower = token.to_ascii_lowercase();
        if let Some(age) = lower.strip_prefix("max-age=") {
            analysis.max_age = age.trim_matches('"').parse().ok();
        } else if lower == "includesubdomains" {
            analysis.include_subdomains = true;
        } else if lower == "preload" {
            analysis.preload = true;
        }
    }

    match analysis.max_age {
        None => {
            analysis.valid = false;
            analysis.issues.push(
                "The header has no max-age directive, so browsers ignore it entirely."
                    .to_string(),
            );
        }
        Some(0) => {
            analysis.valid = false;
            analysis.issues.push(
                "max-age is 0, which instructs browsers to forget the HSTS policy — the header \
                 is actively disabling protection."
                    .to_string(),
            );
        }
        Some(age) if age < HSTS_MIN_MAX_AGE => analysis.issues.push(format!(
            "max-age is {} seconds ({} days). Six months (15768000) is the minimum for the \
             preload list and for an A+ grade.",
            age,
            age / 86_400
        )),
        Some(_) => {}
    }
    if !analysis.include_subdomains {
        analysis.issues.push(
            "includeSubDomains is not set, so a subdomain served over plain HTTP can still be \
             used to set cookies for the parent domain."
                .to_string(),
        );
    }
    analysis
}

/// Directives whose sources are fetched and executed, where a wildcard matters.
const FETCH_DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "script-src-elem",
    "object-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "frame-src",
    "worker-src",
];

pub fn parse_csp(value: Option<&str>, report_only_value: Option<&str>) -> CspAnalysis {
    let (raw, report_only) = match (value, report_only_value) {
        (Some(v), _) => (v, false),
        (None, Some(v)) => (v, true),
        (None, None) => return CspAnalysis::default(),
    };

    let mut analysis = CspAnalysis {
        present: true,
        report_only,
        ..Default::default()
    };

    for directive in raw.split(';') {
        let mut parts = directive.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let name = name.to_ascii_lowercase();
        let sources: Vec<String> = parts.map(|s| s.to_ascii_lowercase()).collect();
        analysis.directives.insert(name.clone(), sources.clone());
    }

    // `default-src` supplies the fallback for any fetch directive not named.
    let default_src = analysis.directives.get("default-src").cloned().unwrap_or_default();
    let effective = |name: &str| -> Vec<String> {
        analysis
            .directives
            .get(name)
            .cloned()
            .unwrap_or_else(|| default_src.clone())
    };

    let script_src = effective("script-src");
    let style_src = effective("style-src");

    analysis.unsafe_inline_script = script_src.iter().any(|s| s == "'unsafe-inline'");
    analysis.unsafe_inline_style = style_src.iter().any(|s| s == "'unsafe-inline'");
    analysis.unsafe_eval = script_src.iter().any(|s| s == "'unsafe-eval'");
    analysis.has_default_src_none = default_src.iter().any(|s| s == "'none'");
    analysis.has_frame_ancestors = analysis.directives.contains_key("frame-ancestors");
    analysis.has_object_src = analysis.directives.contains_key("object-src")
        || analysis.directives.contains_key("default-src");
    analysis.has_base_uri = analysis.directives.contains_key("base-uri");
    analysis.has_form_action = analysis.directives.contains_key("form-action");

    for directive in FETCH_DIRECTIVES {
        let sources = effective(directive);
        for source in &sources {
            // A bare scheme or `*` lets any host on the internet supply this
            // resource type, which for script-src is the whole policy defeated.
            if source == "*" || source == "https:" || source == "http:" || source == "data:" {
                analysis
                    .wildcard_sources
                    .push(format!("{} {}", directive, source));
            }
            if source.starts_with("http://") {
                analysis.insecure_scheme = true;
            }
        }
    }

    // A nonce or hash makes 'unsafe-inline' inert in CSP3 browsers, but CSP2
    // browsers still honour it — so it is a weakening, not a neutral.
    let has_nonce_or_hash = script_src
        .iter()
        .any(|s| s.starts_with("'nonce-") || s.starts_with("'sha256-") || s.starts_with("'sha384-") || s.starts_with("'sha512-"));

    if analysis.unsafe_inline_script {
        analysis.issues.push(if has_nonce_or_hash {
            "script-src allows 'unsafe-inline' alongside a nonce or hash. CSP3 browsers ignore \
             the keyword, but CSP2 browsers honour it, so older clients get no XSS protection."
                .to_string()
        } else {
            "script-src allows 'unsafe-inline', which permits any injected <script> block to \
             run. The policy provides no XSS protection."
                .to_string()
        });
    }
    if analysis.unsafe_eval {
        analysis.issues.push(
            "script-src allows 'unsafe-eval', so eval() and its relatives stay available to \
             injected code."
                .to_string(),
        );
    }
    if !analysis.wildcard_sources.is_empty() {
        analysis.issues.push(format!(
            "Overly broad sources permit content from anywhere: {}.",
            analysis.wildcard_sources.join(", ")
        ));
    }
    if analysis.insecure_scheme {
        analysis.issues.push(
            "The policy permits resources over http://, which allows an on-path attacker to \
             substitute them."
                .to_string(),
        );
    }
    if !analysis.has_object_src {
        analysis.issues.push(
            "Neither object-src nor default-src is set, so Flash and other plugin content is \
             unrestricted."
                .to_string(),
        );
    }
    if !analysis.has_base_uri {
        analysis.issues.push(
            "base-uri is not set, so an injected <base> tag can redirect every relative URL on \
             the page."
                .to_string(),
        );
    }
    if !analysis.has_form_action {
        analysis.issues.push(
            "form-action is not set, so an injected form can post credentials to any origin."
                .to_string(),
        );
    }
    if report_only {
        analysis.issues.push(
            "The policy is sent as Content-Security-Policy-Report-Only, so violations are \
             reported but nothing is blocked."
                .to_string(),
        );
    }

    analysis
}

/// Cookie names that indicate a session or authentication token, where a missing
/// `HttpOnly` or `Secure` flag is a real finding rather than a nit.
const SESSION_COOKIE_MARKERS: &[&str] = &[
    "sess", "session", "sid", "auth", "token", "jwt", "login", "user", "account", "remember",
    "csrf", "xsrf", "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid", "_rails",
];

pub fn analyze_cookie(set_cookie: &str) -> Option<CookieAnalysis> {
    let mut parts = set_cookie.split(';');
    let first = parts.next()?.trim();
    let name = first.split('=').next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut analysis = CookieAnalysis {
        session_like: {
            let lower = name.to_ascii_lowercase();
            SESSION_COOKIE_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        },
        prefix: if name.starts_with("__Host-") {
            Some("__Host-".to_string())
        } else if name.starts_with("__Secure-") {
            Some("__Secure-".to_string())
        } else {
            None
        },
        name,
        secure: false,
        http_only: false,
        same_site: None,
        issues: Vec::new(),
    };

    for attribute in parts {
        let attribute = attribute.trim();
        let lower = attribute.to_ascii_lowercase();
        if lower == "secure" {
            analysis.secure = true;
        } else if lower == "httponly" {
            analysis.http_only = true;
        } else if let Some(value) = lower.strip_prefix("samesite=") {
            analysis.same_site = Some(value.trim().to_string());
        }
    }

    if !analysis.secure {
        analysis.issues.push(
            "No Secure flag: the cookie is sent over plain HTTP, where anyone on the path can \
             read it."
                .to_string(),
        );
    }
    if !analysis.http_only && analysis.session_like {
        analysis.issues.push(
            "No HttpOnly flag on a session cookie: any XSS on the site can read it directly."
                .to_string(),
        );
    }
    match analysis.same_site.as_deref() {
        None => analysis.issues.push(
            "No SameSite attribute. Browsers default to Lax, but stating it explicitly is what \
             makes the CSRF posture reviewable."
                .to_string(),
        ),
        Some("none") if !analysis.secure => analysis.issues.push(
            "SameSite=None without Secure. Browsers reject this combination outright, so the \
             cookie is dropped."
                .to_string(),
        ),
        Some("none") | Some("lax") | Some("strict") => {}
        Some(other) => analysis
            .issues
            .push(format!("SameSite={} is not a valid value.", other)),
    }
    // The prefixes are browser-enforced: __Secure- requires Secure, __Host-
    // additionally requires Path=/ and no Domain.
    if analysis.prefix.is_some() && !analysis.secure {
        analysis.issues.push(
            "The cookie name uses a __Secure-/__Host- prefix without the Secure flag, so the \
             browser rejects it."
                .to_string(),
        );
    }

    Some(analysis)
}

// ---------------------------------------------------------------------------
// Observatory scoring
// ---------------------------------------------------------------------------

fn check(
    name: &str,
    category: &str,
    passed: bool,
    modifier: i32,
    description: &str,
    value: Option<String>,
) -> HeaderCheck {
    HeaderCheck {
        name: name.to_string(),
        category: category.to_string(),
        passed,
        score_modifier: modifier,
        description: description.to_string(),
        value,
    }
}

/// The inputs the scorer needs, gathered by whoever made the requests.
pub struct ScoringInput<'a> {
    pub is_https: bool,
    pub headers: &'a BTreeMap<String, String>,
    pub csp: &'a CspAnalysis,
    pub hsts: &'a HstsAnalysis,
    pub cookies: &'a [CookieAnalysis],
    /// Result of requesting the http:// origin: did it end on https, on the same
    /// host, and via an https first hop?
    pub redirects_to_https: Option<bool>,
    pub redirect_first_hop_https: bool,
    pub redirect_same_host: bool,
    /// `Access-Control-Allow-Origin` on the main response.
    pub cors_allow_origin: Option<&'a str>,
    pub cors_allow_credentials: bool,
    /// External `<script src>` origins, and how many carry an `integrity` attribute.
    pub external_scripts: usize,
    pub external_scripts_with_sri: usize,
    pub external_scripts_over_http: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservatoryScore {
    pub score: i32,
    pub grade: String,
    pub checks: Vec<HeaderCheck>,
}

/// Mozilla's published letter chart.
pub fn observatory_grade(score: i32) -> &'static str {
    match score {
        100..=i32::MAX => "A+",
        90..=99 => "A",
        85..=89 => "A-",
        80..=84 => "B+",
        70..=79 => "B",
        65..=69 => "B-",
        60..=64 => "C+",
        50..=59 => "C",
        45..=49 => "C-",
        40..=44 => "D+",
        30..=39 => "D",
        25..=29 => "D-",
        _ => "F",
    }
}

pub fn score(input: &ScoringInput) -> ObservatoryScore {
    let mut checks = Vec::new();
    let header = |name: &str| input.headers.get(name).map(|s| s.as_str());

    // ---- Content Security Policy ------------------------------------------
    checks.push(if !input.csp.present {
        check(
            "csp-not-implemented",
            "csp",
            false,
            -25,
            "Content Security Policy header not implemented",
            None,
        )
    } else if input.csp.unsafe_inline_script
        || input
            .csp
            .wildcard_sources
            .iter()
            .any(|s| s.starts_with("script-src") || s.starts_with("object-src") || s.starts_with("default-src"))
    {
        check(
            "csp-implemented-with-unsafe-inline",
            "csp",
            false,
            -20,
            "CSP implemented unsafely: 'unsafe-inline' or an overly broad source in script-src \
             or object-src",
            header("content-security-policy").map(str::to_string),
        )
    } else if input.csp.insecure_scheme {
        check(
            "csp-implemented-with-insecure-scheme",
            "csp",
            false,
            -20,
            "CSP implemented, but the secure site allows resources to be loaded over http",
            None,
        )
    } else if input.csp.unsafe_eval {
        check(
            "csp-implemented-with-unsafe-eval",
            "csp",
            false,
            -10,
            "CSP implemented, but allows 'unsafe-eval'",
            None,
        )
    } else if input.csp.unsafe_inline_style {
        check(
            "csp-implemented-with-unsafe-inline-in-style-src-only",
            "csp",
            true,
            0,
            "CSP implemented with unsafe directives inside style-src only",
            None,
        )
    } else if input.csp.has_default_src_none {
        check(
            "csp-implemented-with-no-unsafe-default-src-none",
            "csp",
            true,
            10,
            "CSP implemented with default-src 'none' and without 'unsafe-inline' or 'unsafe-eval'",
            None,
        )
    } else {
        check(
            "csp-implemented-with-no-unsafe",
            "csp",
            true,
            5,
            "CSP implemented without 'unsafe-inline' or 'unsafe-eval'",
            None,
        )
    });

    // ---- HSTS --------------------------------------------------------------
    checks.push(if !input.is_https {
        check(
            "hsts-not-implemented-no-https",
            "hsts",
            false,
            -20,
            "HSTS cannot be set for sites not available over https",
            None,
        )
    } else if !input.hsts.present {
        check(
            "hsts-not-implemented",
            "hsts",
            false,
            -20,
            "HTTP Strict Transport Security header not implemented",
            None,
        )
    } else if !input.hsts.valid {
        check(
            "hsts-header-invalid",
            "hsts",
            false,
            -20,
            "HTTP Strict Transport Security header cannot be recognised",
            header("strict-transport-security").map(str::to_string),
        )
    } else if input.hsts.preload && input.hsts.include_subdomains {
        check(
            "hsts-preloaded",
            "hsts",
            true,
            5,
            "Preloaded via the HTTP Strict Transport Security preloading process",
            header("strict-transport-security").map(str::to_string),
        )
    } else if input.hsts.max_age.unwrap_or(0) >= HSTS_MIN_MAX_AGE {
        check(
            "hsts-implemented-max-age-at-least-six-months",
            "hsts",
            true,
            0,
            "HSTS header set to a minimum of six months (15768000)",
            header("strict-transport-security").map(str::to_string),
        )
    } else {
        check(
            "hsts-implemented-max-age-less-than-six-months",
            "hsts",
            false,
            -10,
            "HSTS header set to less than six months (15768000)",
            header("strict-transport-security").map(str::to_string),
        )
    });

    // ---- X-Frame-Options ---------------------------------------------------
    let xfo = header("x-frame-options").map(|v| v.to_ascii_lowercase());
    checks.push(if input.csp.has_frame_ancestors {
        check(
            "x-frame-options-implemented-via-csp",
            "x-frame-options",
            true,
            5,
            "X-Frame-Options implemented via the CSP frame-ancestors directive",
            None,
        )
    } else {
        match xfo.as_deref() {
            Some(v) if v.contains("deny") || v.contains("sameorigin") => check(
                "x-frame-options-sameorigin-or-deny",
                "x-frame-options",
                true,
                0,
                "X-Frame-Options header set to SAMEORIGIN or DENY",
                xfo.clone(),
            ),
            Some(_) => check(
                "x-frame-options-header-invalid",
                "x-frame-options",
                false,
                -20,
                "X-Frame-Options header cannot be recognised",
                xfo.clone(),
            ),
            None => check(
                "x-frame-options-not-implemented",
                "x-frame-options",
                false,
                -20,
                "X-Frame-Options header not implemented",
                None,
            ),
        }
    });

    // ---- X-Content-Type-Options --------------------------------------------
    checks.push(match header("x-content-type-options") {
        Some(v) if v.trim().eq_ignore_ascii_case("nosniff") => check(
            "x-content-type-options-nosniff",
            "x-content-type-options",
            true,
            0,
            "X-Content-Type-Options header set to nosniff",
            Some(v.to_string()),
        ),
        Some(v) => check(
            "x-content-type-options-header-invalid",
            "x-content-type-options",
            false,
            -5,
            "X-Content-Type-Options header cannot be recognised",
            Some(v.to_string()),
        ),
        None => check(
            "x-content-type-options-not-implemented",
            "x-content-type-options",
            false,
            -5,
            "X-Content-Type-Options header not implemented",
            None,
        ),
    });

    // ---- Referrer-Policy ---------------------------------------------------
    let referrer = header("referrer-policy").map(|v| v.to_ascii_lowercase());
    checks.push(match referrer.as_deref() {
        None => check(
            "referrer-policy-not-implemented",
            "referrer-policy",
            true,
            0,
            "Referrer-Policy header not implemented",
            None,
        ),
        Some(v)
            if ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]
                .iter()
                .any(|safe| v.split(',').any(|part| part.trim() == *safe)) =>
        {
            check(
                "referrer-policy-private",
                "referrer-policy",
                true,
                5,
                "Referrer-Policy set to a value that does not leak URLs cross-origin",
                referrer.clone(),
            )
        }
        Some(v) if v.contains("no-referrer-when-downgrade") => check(
            "referrer-policy-no-referrer-when-downgrade",
            "referrer-policy",
            true,
            0,
            "Referrer-Policy header set to no-referrer-when-downgrade",
            referrer.clone(),
        ),
        Some(v)
            if v.contains("unsafe-url")
                || v.contains("origin-when-cross-origin")
                || v.trim() == "origin" =>
        {
            check(
                "referrer-policy-unsafe",
                "referrer-policy",
                false,
                -5,
                "Referrer-Policy unsafely set to origin, origin-when-cross-origin or unsafe-url",
                referrer.clone(),
            )
        }
        Some(_) => check(
            "referrer-policy-header-invalid",
            "referrer-policy",
            false,
            -5,
            "Referrer-Policy header cannot be recognised",
            referrer.clone(),
        ),
    });

    // ---- Cookies -----------------------------------------------------------
    checks.push(cookie_check(input));

    // ---- Redirection -------------------------------------------------------
    checks.push(match input.redirects_to_https {
        None => check(
            "redirection-not-needed-no-http",
            "redirection",
            true,
            0,
            "Not able to connect via http, so no redirection necessary",
            None,
        ),
        Some(false) => check(
            "redirection-missing",
            "redirection",
            false,
            -20,
            "Does not redirect to an https site",
            None,
        ),
        Some(true) if !input.redirect_first_hop_https => check(
            "redirection-not-to-https-on-initial-redirection",
            "redirection",
            false,
            -10,
            "Redirects to https eventually, but the initial redirection is to another http URL",
            None,
        ),
        Some(true) if !input.redirect_same_host => check(
            "redirection-off-host-from-http",
            "redirection",
            false,
            -5,
            "Initial redirection from http to https is to a different host, preventing HSTS",
            None,
        ),
        Some(true) => check(
            "redirection-to-https",
            "redirection",
            true,
            0,
            "Initial redirection is to https on the same host, final destination is https",
            None,
        ),
    });

    // ---- CORS --------------------------------------------------------------
    checks.push(match input.cors_allow_origin {
        Some("*") => check(
            "cross-origin-resource-sharing-implemented-with-universal-access",
            "cors",
            false,
            -50,
            "Content is visible via cross-origin resource sharing to any origin",
            Some("*".to_string()),
        ),
        Some(origin) => check(
            "cross-origin-resource-sharing-implemented-with-restricted-access",
            "cors",
            true,
            0,
            "Content is visible via CORS but restricted to specific domains",
            Some(origin.to_string()),
        ),
        None => check(
            "cross-origin-resource-sharing-not-implemented",
            "cors",
            true,
            0,
            "Content is not visible via cross-origin resource sharing",
            None,
        ),
    });

    // ---- Subresource Integrity ---------------------------------------------
    checks.push(if input.external_scripts == 0 {
        check(
            "sri-not-implemented-but-no-scripts-loaded",
            "sri",
            true,
            0,
            "SRI is not needed since the page loads no external scripts",
            None,
        )
    } else if input.external_scripts_over_http > 0 && input.external_scripts_with_sri == 0 {
        check(
            "sri-not-implemented-and-external-scripts-not-loaded-securely",
            "sri",
            false,
            -50,
            "SRI is not implemented and external scripts are not loaded over https",
            None,
        )
    } else if input.external_scripts_with_sri >= input.external_scripts {
        check(
            "sri-implemented-and-external-scripts-loaded-securely",
            "sri",
            true,
            5,
            "Subresource Integrity is implemented and all scripts are loaded securely",
            None,
        )
    } else {
        check(
            "sri-not-implemented-but-external-scripts-loaded-securely",
            "sri",
            false,
            -5,
            "SRI not implemented, but all external scripts are loaded over https",
            None,
        )
    });

    let total: i32 = OBSERVATORY_BASELINE + checks.iter().map(|c| c.score_modifier).sum::<i32>();
    let total = total.max(0);
    ObservatoryScore {
        score: total,
        grade: observatory_grade(total).to_string(),
        checks,
    }
}

fn cookie_check(input: &ScoringInput) -> HeaderCheck {
    if input.cookies.is_empty() {
        return check("cookies-not-found", "cookies", true, 0, "No cookies detected", None);
    }
    let session = |c: &&CookieAnalysis| c.session_like;
    let sessions: Vec<&CookieAnalysis> = input.cookies.iter().filter(session).collect();

    if let Some(bad) = sessions.iter().find(|c| !c.secure) {
        return check(
            "cookies-session-without-secure-flag",
            "cookies",
            false,
            -40,
            "Session cookie set without using the Secure flag or set over http",
            Some(bad.name.clone()),
        );
    }
    if let Some(bad) = sessions.iter().find(|c| !c.http_only) {
        return check(
            "cookies-session-without-httponly-flag",
            "cookies",
            false,
            -30,
            "Session cookie set without using the HttpOnly flag",
            Some(bad.name.clone()),
        );
    }
    if let Some(bad) = input.cookies.iter().find(|c| {
        c.same_site
            .as_deref()
            .is_some_and(|v| !matches!(v, "strict" | "lax" | "none"))
    }) {
        return check(
            "cookies-samesite-flag-invalid",
            "cookies",
            false,
            -20,
            "Cookies use the SameSite flag, but set to something other than Strict, Lax or None",
            Some(bad.name.clone()),
        );
    }
    if let Some(bad) = input.cookies.iter().find(|c| !c.secure) {
        return check(
            "cookies-without-secure-flag",
            "cookies",
            false,
            -20,
            "Cookies set without using the Secure flag or set over http",
            Some(bad.name.clone()),
        );
    }
    if input.cookies.iter().all(|c| c.same_site.is_some()) {
        return check(
            "cookies-secure-with-httponly-sessions-and-samesite",
            "cookies",
            true,
            5,
            "All cookies use Secure, session cookies use HttpOnly, and SameSite is set",
            None,
        );
    }
    check(
        "cookies-secure-with-httponly-sessions",
        "cookies",
        true,
        0,
        "All cookies use the Secure flag and all session cookies use the HttpOnly flag",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn base_input<'a>(
        map: &'a BTreeMap<String, String>,
        csp: &'a CspAnalysis,
        hsts: &'a HstsAnalysis,
        cookies: &'a [CookieAnalysis],
    ) -> ScoringInput<'a> {
        ScoringInput {
            is_https: true,
            headers: map,
            csp,
            hsts,
            cookies,
            redirects_to_https: Some(true),
            redirect_first_hop_https: true,
            redirect_same_host: true,
            cors_allow_origin: None,
            cors_allow_credentials: false,
            external_scripts: 0,
            external_scripts_with_sri: 0,
            external_scripts_over_http: 0,
        }
    }

    #[test]
    fn hsts_directives_are_parsed_and_graded() {
        let hsts = parse_hsts(Some("max-age=31536000; includeSubDomains; preload"));
        assert_eq!(hsts.max_age, Some(31_536_000));
        assert!(hsts.include_subdomains && hsts.preload && hsts.valid);
        assert!(hsts.issues.is_empty());

        let short = parse_hsts(Some("max-age=300"));
        assert!(short.valid);
        assert!(short.issues.iter().any(|i| i.contains("Six months")));
        assert!(short.issues.iter().any(|i| i.contains("includeSubDomains")));

        // max-age=0 tells the browser to forget the policy — worse than absent.
        let disabled = parse_hsts(Some("max-age=0"));
        assert!(!disabled.valid);
        assert!(disabled.issues.iter().any(|i| i.contains("forget")));

        assert!(!parse_hsts(None).present);
        assert!(!parse_hsts(Some("includeSubDomains")).valid);
    }

    #[test]
    fn csp_unsafe_inline_is_detected_through_default_src_fallback() {
        // script-src is absent, so it falls back to default-src.
        let csp = parse_csp(Some("default-src 'self' 'unsafe-inline'"), None);
        assert!(csp.unsafe_inline_script);
        assert!(csp.issues.iter().any(|i| i.contains("no XSS protection")));

        // An explicit script-src overrides default-src and is clean.
        let csp = parse_csp(Some("default-src 'unsafe-inline'; script-src 'self'"), None);
        assert!(!csp.unsafe_inline_script);
        assert!(csp.unsafe_inline_style, "style-src still falls back");
    }

    #[test]
    fn csp_wildcards_are_found_in_fetch_directives() {
        let csp = parse_csp(Some("default-src 'self'; script-src https:; img-src *"), None);
        assert!(csp.wildcard_sources.iter().any(|s| s == "script-src https:"));
        assert!(csp.wildcard_sources.iter().any(|s| s == "img-src *"));
    }

    #[test]
    fn a_nonce_alongside_unsafe_inline_is_reported_differently() {
        let strict = parse_csp(Some("script-src 'unsafe-inline'"), None);
        assert!(strict.issues.iter().any(|i| i.contains("no XSS protection")));

        let with_nonce = parse_csp(Some("script-src 'nonce-abc123' 'unsafe-inline'"), None);
        assert!(with_nonce.unsafe_inline_script);
        assert!(with_nonce.issues.iter().any(|i| i.contains("CSP2 browsers")));
    }

    #[test]
    fn report_only_policies_are_marked_as_not_enforcing() {
        let csp = parse_csp(None, Some("default-src 'none'"));
        assert!(csp.present && csp.report_only);
        assert!(csp.issues.iter().any(|i| i.contains("nothing is blocked")));
    }

    #[test]
    fn missing_base_uri_and_form_action_are_reported() {
        let csp = parse_csp(Some("default-src 'none'"), None);
        assert!(csp.issues.iter().any(|i| i.contains("base-uri")));
        assert!(csp.issues.iter().any(|i| i.contains("form-action")));

        let complete = parse_csp(
            Some("default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
            None,
        );
        assert!(complete.issues.is_empty(), "{:?}", complete.issues);
        assert!(complete.has_frame_ancestors);
    }

    #[test]
    fn cookie_flags_and_prefixes_are_parsed() {
        let cookie = analyze_cookie("__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
            .unwrap();
        assert_eq!(cookie.name, "__Host-session");
        assert_eq!(cookie.prefix.as_deref(), Some("__Host-"));
        assert!(cookie.secure && cookie.http_only && cookie.session_like);
        assert_eq!(cookie.same_site.as_deref(), Some("strict"));
        assert!(cookie.issues.is_empty());
    }

    #[test]
    fn an_insecure_session_cookie_reports_every_problem() {
        let cookie = analyze_cookie("PHPSESSID=xyz; Path=/").unwrap();
        assert!(cookie.session_like);
        assert!(cookie.issues.iter().any(|i| i.contains("Secure flag")));
        assert!(cookie.issues.iter().any(|i| i.contains("HttpOnly")));
        assert!(cookie.issues.iter().any(|i| i.contains("SameSite")));
    }

    #[test]
    fn samesite_none_without_secure_is_rejected_by_browsers() {
        let cookie = analyze_cookie("tracking=1; SameSite=None").unwrap();
        assert!(cookie.issues.iter().any(|i| i.contains("reject this combination")));
    }

    #[test]
    fn a_non_session_cookie_is_not_faulted_for_httponly() {
        let cookie = analyze_cookie("theme=dark; Secure; SameSite=Lax").unwrap();
        assert!(!cookie.session_like);
        assert!(!cookie.http_only);
        assert!(cookie.issues.is_empty(), "{:?}", cookie.issues);
    }

    #[test]
    fn observatory_letter_chart_matches_the_published_one() {
        assert_eq!(observatory_grade(135), "A+");
        assert_eq!(observatory_grade(100), "A+");
        assert_eq!(observatory_grade(99), "A");
        assert_eq!(observatory_grade(90), "A");
        assert_eq!(observatory_grade(89), "A-");
        assert_eq!(observatory_grade(85), "A-");
        assert_eq!(observatory_grade(84), "B+");
        assert_eq!(observatory_grade(70), "B");
        assert_eq!(observatory_grade(65), "B-");
        assert_eq!(observatory_grade(60), "C+");
        assert_eq!(observatory_grade(50), "C");
        assert_eq!(observatory_grade(45), "C-");
        assert_eq!(observatory_grade(40), "D+");
        assert_eq!(observatory_grade(30), "D");
        assert_eq!(observatory_grade(25), "D-");
        assert_eq!(observatory_grade(24), "F");
        assert_eq!(observatory_grade(0), "F");
    }

    #[test]
    fn a_bare_site_scores_the_sum_of_the_published_deductions() {
        let map = headers(&[]);
        let csp = parse_csp(None, None);
        let hsts = parse_hsts(None);
        let result = score(&base_input(&map, &csp, &hsts, &[]));
        // csp -25, hsts -20, xfo -20, xcto -5. Referrer, cookies, redirect,
        // CORS and SRI are all zero here.
        assert_eq!(result.score, 100 - 25 - 20 - 20 - 5);
        assert_eq!(result.grade, "D");
    }

    #[test]
    fn a_hardened_site_reaches_a_plus() {
        let map = headers(&[
            ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
        ]);
        let csp = parse_csp(
            Some("default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
            None,
        );
        let hsts = parse_hsts(map.get("strict-transport-security").map(String::as_str));
        let cookies = vec![analyze_cookie("__Host-sid=a; Secure; HttpOnly; SameSite=Strict").unwrap()];
        let result = score(&base_input(&map, &csp, &hsts, &cookies));
        // +10 csp, +5 hsts preload, +5 xfo via CSP, 0 xcto, +5 referrer,
        // +5 cookies, 0 redirect, 0 cors, 0 sri.
        assert_eq!(result.score, 130);
        assert_eq!(result.grade, "A+");
    }

    #[test]
    fn wildcard_cors_is_the_single_largest_deduction() {
        let map = headers(&[]);
        let csp = parse_csp(None, None);
        let hsts = parse_hsts(None);
        let mut input = base_input(&map, &csp, &hsts, &[]);
        input.cors_allow_origin = Some("*");
        let result = score(&input);
        let cors = result.checks.iter().find(|c| c.category == "cors").unwrap();
        assert_eq!(cors.score_modifier, -50);
        assert_eq!(cors.name, "cross-origin-resource-sharing-implemented-with-universal-access");
    }

    #[test]
    fn a_plain_http_site_cannot_score_hsts() {
        let map = headers(&[]);
        let csp = parse_csp(None, None);
        let hsts = parse_hsts(None);
        let mut input = base_input(&map, &csp, &hsts, &[]);
        input.is_https = false;
        input.redirects_to_https = Some(false);
        let result = score(&input);
        let hsts_check = result.checks.iter().find(|c| c.category == "hsts").unwrap();
        assert_eq!(hsts_check.name, "hsts-not-implemented-no-https");
        let redirect = result.checks.iter().find(|c| c.category == "redirection").unwrap();
        assert_eq!(redirect.score_modifier, -20);
    }

    #[test]
    fn score_never_goes_below_zero() {
        let map = headers(&[("x-frame-options", "nonsense")]);
        let csp = parse_csp(None, None);
        let hsts = parse_hsts(None);
        let cookies = vec![analyze_cookie("sessionid=a").unwrap()];
        let mut input = base_input(&map, &csp, &hsts, &cookies);
        input.cors_allow_origin = Some("*");
        input.redirects_to_https = Some(false);
        input.external_scripts = 3;
        input.external_scripts_over_http = 2;
        let result = score(&input);
        assert_eq!(result.score, 0);
        assert_eq!(result.grade, "F");
    }

    #[test]
    fn csp_frame_ancestors_substitutes_for_x_frame_options() {
        let map = headers(&[]);
        let csp = parse_csp(Some("frame-ancestors 'none'"), None);
        let hsts = parse_hsts(None);
        let result = score(&base_input(&map, &csp, &hsts, &[]));
        let xfo = result
            .checks
            .iter()
            .find(|c| c.category == "x-frame-options")
            .unwrap();
        assert_eq!(xfo.score_modifier, 5);
    }
}

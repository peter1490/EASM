//! Deep HTTP assessment of a web endpoint.
//!
//! Covers what Mozilla Observatory, securityheaders.com, `nikto` and `nuclei`'s
//! exposure templates cover between them:
//!
//! * the http→https redirect chain, hop by hop
//! * every security header, graded on its *value* rather than its presence, and
//!   scored with the published Observatory modifiers
//! * cookie flags, including the browser-enforced `__Host-`/`__Secure-` prefixes
//! * CORS misconfiguration, including origin reflection with credentials — which
//!   a header table cannot see, because it only appears when you send an `Origin`
//! * dangerous HTTP methods (TRACE, PUT, DELETE) confirmed by response, not by
//!   what `Allow:` claims
//! * exposed files and endpoints: `.git`, `.env`, actuator, phpinfo, backups
//! * `security.txt`, directory listing, stack traces, mixed content
//!
//! Every path probe is validated against expected *content*, never against a
//! status code alone. A server that answers 200 with an SPA shell for every URL —
//! which is most of them — otherwise produces a page of invented findings.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::models::FindingSeverity;

use super::http_headers::{
    self, CookieAnalysis, CspAnalysis, HeaderCheck, HstsAnalysis, ObservatoryScore, ScoringInput,
};
use super::ScanFinding;

/// Bodies are read only far enough to fingerprint them.
const MAX_BODY_BYTES: usize = 512 * 1024;
/// Path and method probes need only enough to match a signature. Kept small
/// because several probed endpoints return very large bodies by design.
const MAX_PROBE_BYTES: usize = 64 * 1024;
/// Cap on redirect hops we follow by hand, so a redirect loop cannot spin.
const MAX_REDIRECT_HOPS: usize = 8;
/// Origin used to test whether CORS reflects whatever it is sent.
const CORS_PROBE_ORIGIN: &str = "https://easm-cors-probe.example";

/// A path worth asking for, and the evidence that proves the answer is real.
#[derive(Debug, Clone, Copy)]
pub struct SensitivePath {
    pub path: &'static str,
    /// What the finding is called.
    pub label: &'static str,
    pub finding_type: &'static str,
    pub severity: FindingSeverity,
    /// Body substrings that confirm the real thing was served. A hit on none of
    /// these means the 200 was a catch-all page, not an exposure.
    pub signatures: &'static [&'static str],
    pub description: &'static str,
    pub remediation: &'static str,
}

macro_rules! path {
    ($path:expr, $label:expr, $ftype:expr, $sev:ident, $sigs:expr, $desc:expr, $rem:expr) => {
        SensitivePath {
            path: $path,
            label: $label,
            finding_type: $ftype,
            severity: FindingSeverity::$sev,
            signatures: &$sigs,
            description: $desc,
            remediation: $rem,
        }
    };
}

/// The probe set. Deliberately small and high-signal: each entry is something
/// that, when genuinely exposed, is worth waking somebody for.
pub const SENSITIVE_PATHS: &[SensitivePath] = &[
    path!(
        "/.git/config", "Git repository exposed", "sensitive_data_exposed", High,
        ["[core]", "repositoryformatversion"],
        "The .git directory is served over HTTP. The full repository — source, history, and any \
         credential ever committed — can be reconstructed with a directory-walking tool.",
        "Block access to dotfile directories at the web server, and deploy from a build artefact \
         rather than a working copy."
    ),
    path!(
        "/.env", "Environment file exposed", "sensitive_data_exposed", Critical,
        ["DB_PASSWORD", "APP_KEY=", "SECRET_KEY", "AWS_SECRET", "DATABASE_URL", "API_KEY="],
        "A .env file is served over HTTP. These files hold database credentials, application \
         secrets and API keys in plaintext.",
        "Remove the file from the web root, rotate every credential it contains, and serve \
         configuration from the environment rather than a file under the document root."
    ),
    path!(
        "/.svn/entries", "Subversion metadata exposed", "sensitive_data_exposed", Medium,
        ["dir", "svn:"],
        "Subversion metadata is served over HTTP, disclosing the repository layout and often \
         allowing source recovery.",
        "Block .svn from the web server and deploy from an export."
    ),
    path!(
        "/server-status", "Apache server-status exposed", "debug_endpoint_exposed", Medium,
        ["Apache Server Status", "Server uptime"],
        "Apache's mod_status page is public. It lists every request in flight with its client IP \
         and URL, which leaks both internal endpoints and user activity.",
        "Restrict <Location /server-status> to localhost, or disable mod_status."
    ),
    path!(
        "/server-info", "Apache server-info exposed", "debug_endpoint_exposed", Medium,
        ["Apache Server Information", "Server Settings"],
        "Apache's mod_info page is public, disclosing the full module list and configuration.",
        "Restrict <Location /server-info> to localhost, or disable mod_info."
    ),
    path!(
        "/actuator/env", "Spring Boot Actuator env exposed", "debug_endpoint_exposed", Critical,
        ["\"propertySources\"", "systemEnvironment"],
        "Spring Boot's /actuator/env endpoint is public. It dumps the entire environment, \
         including datasource passwords and cloud credentials.",
        "Set management.endpoints.web.exposure.include to health only, and put the actuator \
         behind authentication on a separate port."
    ),
    path!(
        "/actuator/heapdump", "Spring Boot heap dump exposed", "sensitive_data_exposed", Critical,
        ["HPROF", "JAVA PROFILE"],
        "Spring Boot's heap dump endpoint is public. The dump contains live memory: session \
         tokens, passwords in flight, and decrypted configuration.",
        "Disable the heapdump endpoint and put the actuator behind authentication."
    ),
    path!(
        "/actuator", "Spring Boot Actuator exposed", "debug_endpoint_exposed", Medium,
        ["\"_links\"", "\"self\""],
        "The Spring Boot Actuator index is public, listing the management endpoints available on \
         this application.",
        "Restrict management endpoint exposure and require authentication."
    ),
    path!(
        "/phpinfo.php", "phpinfo() exposed", "information_disclosure", Medium,
        ["phpinfo()", "PHP Version", "Loaded Configuration File"],
        "A phpinfo() page is public. It discloses the PHP version, every loaded module, absolute \
         filesystem paths, and often environment variables.",
        "Delete the file. It has no purpose on a production host."
    ),
    path!(
        "/.aws/credentials", "AWS credentials file exposed", "sensitive_data_exposed", Critical,
        ["aws_access_key_id", "aws_secret_access_key"],
        "An AWS credentials file is served over HTTP, exposing long-lived access keys.",
        "Remove the file, revoke the keys immediately, and move to instance roles."
    ),
    path!(
        "/web.config", "IIS web.config exposed", "sensitive_data_exposed", High,
        ["<configuration>", "<system.webServer>"],
        "The IIS configuration file is served as text, disclosing connection strings, machine \
         keys and the application's internal structure.",
        "Ensure the request filtering module blocks web.config, and rotate any secret it contains."
    ),
    path!(
        "/.well-known/security.txt", "security.txt", "security_txt_missing", Info,
        ["Contact:"],
        "RFC 9116 security.txt tells a researcher who to report a vulnerability to.",
        "Publish /.well-known/security.txt with at least a Contact: and Expires: field."
    ),
    path!(
        "/.DS_Store", "macOS .DS_Store exposed", "information_disclosure", Low,
        ["Bud1"],
        "A .DS_Store file is served, which discloses the names of every file in the directory it \
         was created in — including ones not otherwise linked.",
        "Remove .DS_Store files from the deployment and block the name at the web server."
    ),
    path!(
        "/trace.axd", "ASP.NET trace viewer exposed", "debug_endpoint_exposed", High,
        ["Application Trace", "Request Details"],
        "The ASP.NET trace viewer is public, replaying recent requests with their full headers, \
         cookies and session state.",
        "Set <trace enabled=\"false\" /> in web.config."
    ),
    path!(
        "/.git/HEAD", "Git HEAD exposed", "sensitive_data_exposed", High,
        ["ref: refs/"],
        "The .git directory is served over HTTP, which is enough to reconstruct the repository.",
        "Block dotfile directories at the web server."
    ),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorsAnalysis {
    pub allow_origin: Option<String>,
    pub allow_credentials: bool,
    /// The server echoed back whatever `Origin` it was sent — every site an
    /// attacker controls can then read authenticated responses.
    pub reflects_origin: bool,
    pub allows_null_origin: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MethodAnalysis {
    /// What `Allow:`/`Access-Control-Allow-Methods` claimed.
    pub advertised: Vec<String>,
    /// What actually answered without a 4xx/5xx.
    pub enabled: Vec<String>,
    pub trace_enabled: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedPath {
    pub path: String,
    pub url: String,
    pub status: u16,
    pub label: String,
    pub content_length: usize,
    pub matched_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpScanResult {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub is_https: bool,
    pub http_version: String,
    pub supports_http2: bool,
    pub supports_http3: bool,
    pub server: Option<String>,
    pub headers_present: Vec<String>,
    pub headers_missing: Vec<String>,
    pub redirect_chain: Vec<RedirectHop>,
    pub redirects_to_https: Option<bool>,
    pub csp: CspAnalysis,
    pub hsts: HstsAnalysis,
    pub cookies: Vec<CookieAnalysis>,
    pub cors: CorsAnalysis,
    pub methods: MethodAnalysis,
    pub exposed_paths: Vec<ExposedPath>,
    /// `None` when path probing did not run, so a shallow scan does not report
    /// a file it never asked for as absent.
    pub security_txt: Option<bool>,
    pub directory_listing: bool,
    pub mixed_content: Vec<String>,
    /// Total found, which may exceed the length of the list above.
    pub mixed_content_total: usize,
    pub external_scripts: usize,
    pub external_scripts_with_sri: usize,
    pub stack_trace_disclosed: Option<String>,
    /// Why an `https://` attempt failed, when the scan fell back to plain HTTP.
    /// Present means the HTTPS verdict is about a connection that never happened.
    pub https_error: Option<String>,
    pub observatory: ObservatoryScore,
    pub checks: Vec<HeaderCheck>,
    pub errors: Vec<String>,
    pub scan_duration_ms: i64,
}

pub struct HttpScanOutcome {
    pub result: HttpScanResult,
    pub findings: Vec<ScanFinding>,
}

/// Headers reported on individually, beyond the ones Observatory scores.
const REPORTED_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
];

struct Fetched {
    url: String,
    status: u16,
    version: String,
    headers: BTreeMap<String, String>,
    set_cookies: Vec<String>,
    body: String,
}

async fn fetch(client: &reqwest::Client, url: &str) -> Result<Fetched, String> {
    let response = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let version = format!("{:?}", response.version());
    let final_url = response.url().to_string();

    let mut headers = BTreeMap::new();
    let mut set_cookies = Vec::new();
    for (name, value) in response.headers() {
        let Ok(value) = value.to_str() else { continue };
        let name = name.as_str().to_ascii_lowercase();
        if name == "set-cookie" {
            set_cookies.push(value.to_string());
        } else {
            // Repeated headers are joined the way a browser would see them.
            headers
                .entry(name)
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(value);
                })
                .or_insert_with(|| value.to_string());
        }
    }

    let body = read_body_capped(response, MAX_BODY_BYTES).await;
    Ok(Fetched {
        url: final_url,
        status,
        version,
        headers,
        set_cookies,
        body,
    })
}

/// Read at most `cap` bytes of a response body, stopping the transfer there.
///
/// `response.bytes()` buffers the whole body before anything can cap it. That is
/// not acceptable for a scanner whose probe list deliberately includes
/// `/actuator/heapdump` — an endpoint whose entire purpose is to return a
/// multi-hundred-megabyte JVM heap dump. The signature that identifies each probe
/// is in the first few kilobytes, so nothing is lost by stopping early.
async fn read_body_capped(mut response: reqwest::Response, cap: usize) -> String {
    let mut collected: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024));
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = cap.saturating_sub(collected.len());
                if room == 0 {
                    break;
                }
                collected.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if collected.len() >= cap {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("truncated body read: {}", e);
                break;
            }
        }
    }
    String::from_utf8_lossy(&collected).into_owned()
}

/// The outcome of walking the plain-HTTP origin's redirect chain.
enum RedirectTrace {
    /// The chain terminated in a non-redirect response at this URL.
    Settled(String),
    /// A hop could not be fetched, or the hop limit was reached, so where the
    /// chain would have ended is unknown. Distinct from `Settled` because
    /// "we could not follow it" is not "it does not redirect to HTTPS".
    Interrupted,
    /// Nothing answered on plain HTTP at all.
    NoHttp,
}

/// Walk the redirect chain by hand so each hop can be inspected. `reqwest`'s
/// automatic following hides exactly what Observatory grades: whether the *first*
/// hop went to https, and whether it stayed on the same host.
async fn trace_redirects(
    client: &reqwest::Client,
    start: &str,
) -> (Vec<RedirectHop>, RedirectTrace) {
    let mut hops = Vec::new();
    let mut current = start.to_string();

    for _ in 0..MAX_REDIRECT_HOPS {
        let Ok(response) = client.get(&current).send().await else {
            // Nothing answered the very first request: there is no plain-HTTP
            // origin. Further along the chain it means we lost the trail, which
            // must not be graded as "does not redirect to HTTPS".
            return if hops.is_empty() {
                (hops, RedirectTrace::NoHttp)
            } else {
                (hops, RedirectTrace::Interrupted)
            };
        };
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        hops.push(RedirectHop {
            url: current.clone(),
            status,
            location: location.clone(),
        });

        if !(300..400).contains(&status) {
            return (hops, RedirectTrace::Settled(current));
        }
        let Some(location) = location else {
            // A 3xx with no Location goes nowhere.
            return (hops, RedirectTrace::Settled(current));
        };
        let Ok(next) = url::Url::parse(&current).and_then(|base| base.join(&location)) else {
            return (hops, RedirectTrace::Interrupted);
        };
        current = next.to_string();
    }
    // Out of hops with the chain still redirecting: we never saw where it ends.
    (hops, RedirectTrace::Interrupted)
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Run the assessment. `target` may be a bare host or a full URL.
pub async fn scan(
    client: &reqwest::Client,
    plain_client: &reqwest::Client,
    target: &str,
    timeout: Duration,
    deep: bool,
) -> HttpScanOutcome {
    let started = std::time::Instant::now();
    let mut errors = Vec::new();

    // Derive the scheme from an explicit port where there is one. Building
    // `https://host:8080` and waiting for it to fail before trying HTTP wastes a
    // connection and, worse, records an `https_error` that makes a plain-HTTP
    // port look like an unreachable HTTPS one.
    let url = if target.contains("://") {
        target.to_string()
    } else {
        let port = target
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok());
        match port {
            Some(80) | Some(8080) | Some(8000) | Some(8888) => format!("http://{}", target),
            _ => format!("https://{}", target),
        }
    };

    // ---- Primary fetch, with a scheme fallback ----------------------------
    //
    // The fallback is load-bearing for correctness, not just coverage: if an
    // https:// attempt fails for a *local* reason — an egress proxy that will not
    // open the tunnel, a DNS hiccup — and we quietly scan the http:// origin
    // instead, the result reads "this site is HTTP-only" and produces an
    // https_not_enforced finding about a site that serves HTTPS perfectly well.
    // So the reason is captured and travels with the finding as evidence.
    let mut https_error: Option<String> = None;
    let page = match fetch(client, &url).await {
        Ok(page) => Ok(page),
        Err(reason) => {
            let alternate = if url.starts_with("https://") {
                https_error = Some(reason.clone());
                url.replacen("https://", "http://", 1)
            } else {
                url.replacen("http://", "https://", 1)
            };
            errors.push(format!(
                "{} did not answer ({}); retried over {}",
                url, reason, alternate
            ));
            fetch(client, &alternate).await
        }
    };

    let Ok(page) = page else {
        let csp = http_headers::parse_csp(None, None);
        let hsts = http_headers::parse_hsts(None);
        let headers = BTreeMap::new();
        let observatory = http_headers::score(&ScoringInput {
            is_https: false,
            headers: &headers,
            csp: &csp,
            hsts: &hsts,
            cookies: &[],
            redirects_to_https: None,
            redirect_first_hop_https: false,
            redirect_same_host: false,
            cors_allow_origin: None,
            cors_allow_credentials: false,
            external_scripts: 0,
            external_scripts_with_sri: 0,
            external_scripts_over_http: 0,
        });
        errors.push(format!("No HTTP response from {} over either scheme", target));
        return HttpScanOutcome {
            result: HttpScanResult {
                url: url.clone(),
                final_url: url,
                status: 0,
                is_https: false,
                http_version: String::new(),
                supports_http2: false,
                supports_http3: false,
                server: None,
                headers_present: vec![],
                headers_missing: REPORTED_HEADERS.iter().map(|h| h.to_string()).collect(),
                redirect_chain: vec![],
                redirects_to_https: None,
                csp,
                hsts,
                cookies: vec![],
                cors: CorsAnalysis::default(),
                methods: MethodAnalysis::default(),
                exposed_paths: vec![],
                security_txt: None,
                directory_listing: false,
                mixed_content: vec![],
                mixed_content_total: 0,
                external_scripts: 0,
                external_scripts_with_sri: 0,
                stack_trace_disclosed: None,
                https_error,
                checks: observatory.checks.clone(),
                observatory,
                errors,
                scan_duration_ms: started.elapsed().as_millis() as i64,
            },
            findings: vec![],
        };
    };

    let is_https = page.url.starts_with("https://");
    let csp = http_headers::parse_csp(
        page.headers.get("content-security-policy").map(String::as_str),
        page.headers
            .get("content-security-policy-report-only")
            .map(String::as_str),
    );
    let hsts = http_headers::parse_hsts(
        page.headers
            .get("strict-transport-security")
            .map(String::as_str),
    );
    let cookies: Vec<CookieAnalysis> = page
        .set_cookies
        .iter()
        .filter_map(|c| http_headers::analyze_cookie(c))
        .collect();

    // ---- Redirect chain from the plain-HTTP origin ------------------------
    let host = host_of(&page.url).unwrap_or_else(|| target.to_string());
    let (redirect_chain, redirect_trace) =
        trace_redirects(plain_client, &format!("http://{}/", host)).await;
    // `None` means "no verdict": either nothing answers on plain HTTP (so no
    // redirect is needed) or the chain could not be followed to its end. Only a
    // chain we actually watched terminate can be graded.
    let redirects_to_https = match &redirect_trace {
        RedirectTrace::Settled(url) => Some(url.starts_with("https://")),
        RedirectTrace::NoHttp => None,
        RedirectTrace::Interrupted => {
            errors.push(format!(
                "The redirect chain from http://{}/ could not be followed to its end; HTTPS \
                 redirection was not graded.",
                host
            ));
            None
        }
    };
    // The chain being traced starts at `http://`, so a relative Location resolves
    // against an http:// base and stays on http — regardless of what scheme the
    // primary fetch used. Reading the primary's scheme here would let a site that
    // redirects `http://x/` to `/en/` look as though its first hop reached HTTPS.
    let redirect_first_hop_https = redirect_chain
        .first()
        .and_then(|hop| hop.location.as_deref())
        .map(|location| location.starts_with("https://"))
        .unwrap_or(false);
    let redirect_same_host = redirect_chain
        .first()
        .and_then(|hop| hop.location.as_deref())
        .map(|location| match host_of(location) {
            Some(target_host) => target_host == host,
            // A relative Location stays on the same host by definition.
            None => true,
        })
        .unwrap_or(true);

    // ---- CORS, methods, body analysis -------------------------------------
    let cors = probe_cors(client, &page.url, &page.headers).await;
    let methods = if deep {
        probe_methods(client, &page.url, timeout).await
    } else {
        MethodAnalysis::default()
    };

    let body_analysis = analyze_body(&page.body, is_https);
    let stack_trace_disclosed = detect_stack_trace(&page.body);
    let directory_listing = detect_directory_listing(&page.body);

    // ---- Path probing ------------------------------------------------------
    let (exposed_paths, security_txt) = if deep {
        let (paths, found) = probe_paths(client, &page.url, timeout).await;
        (paths, Some(found))
    } else {
        (Vec::new(), None)
    };

    let observatory = http_headers::score(&ScoringInput {
        is_https,
        headers: &page.headers,
        csp: &csp,
        hsts: &hsts,
        cookies: &cookies,
        redirects_to_https,
        redirect_first_hop_https,
        redirect_same_host,
        cors_allow_origin: cors.allow_origin.as_deref(),
        cors_allow_credentials: cors.allow_credentials,
        external_scripts: body_analysis.external_scripts,
        external_scripts_with_sri: body_analysis.external_scripts_with_sri,
        external_scripts_over_http: body_analysis.external_scripts_over_http,
    });

    let headers_present: Vec<String> = REPORTED_HEADERS
        .iter()
        .filter(|h| page.headers.contains_key(**h))
        .map(|h| h.to_string())
        .collect();
    let headers_missing: Vec<String> = REPORTED_HEADERS
        .iter()
        .filter(|h| !page.headers.contains_key(**h))
        .map(|h| h.to_string())
        .collect();

    let result = HttpScanResult {
        url,
        status: page.status,
        supports_http2: page.version.contains("HTTP/2") || page.version.contains("HTTP/3"),
        supports_http3: page
            .headers
            .get("alt-svc")
            .is_some_and(|v| v.contains("h3")),
        http_version: page.version.clone(),
        server: page.headers.get("server").cloned(),
        final_url: page.url.clone(),
        is_https,
        headers_present,
        headers_missing,
        redirect_chain,
        redirects_to_https,
        csp,
        hsts,
        cookies,
        cors,
        methods,
        exposed_paths,
        security_txt,
        directory_listing,
        mixed_content_total: body_analysis.mixed_content_total,
        mixed_content: body_analysis.mixed_content,
        external_scripts: body_analysis.external_scripts,
        external_scripts_with_sri: body_analysis.external_scripts_with_sri,
        stack_trace_disclosed,
        https_error,
        checks: observatory.checks.clone(),
        observatory,
        errors,
        scan_duration_ms: started.elapsed().as_millis() as i64,
    };

    let findings = build_findings(&result);
    HttpScanOutcome { result, findings }
}

async fn probe_cors(
    client: &reqwest::Client,
    url: &str,
    headers: &BTreeMap<String, String>,
) -> CorsAnalysis {
    let mut analysis = CorsAnalysis {
        allow_origin: headers.get("access-control-allow-origin").cloned(),
        allow_credentials: headers
            .get("access-control-allow-credentials")
            .is_some_and(|v| v.eq_ignore_ascii_case("true")),
        ..Default::default()
    };

    // Origin reflection only shows up when an Origin is actually sent, which is
    // why reading the plain response headers is not enough.
    if let Ok(response) = client.get(url).header("Origin", CORS_PROBE_ORIGIN).send().await {
        let allow = response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let credentials = response
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if allow.as_deref() == Some(CORS_PROBE_ORIGIN) {
            analysis.reflects_origin = true;
            analysis.allow_credentials |= credentials;
        }
        if analysis.allow_origin.is_none() {
            analysis.allow_origin = allow;
        }
    }

    if let Ok(response) = client.get(url).header("Origin", "null").send().await {
        analysis.allows_null_origin = response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "null");
    }

    if analysis.reflects_origin && analysis.allow_credentials {
        analysis.issues.push(
            "The server reflects any Origin it is sent and sets \
             Access-Control-Allow-Credentials: true. Any site a victim visits can read \
             authenticated responses from this origin — the browser's same-origin policy is \
             fully disabled for it."
                .to_string(),
        );
    } else if analysis.reflects_origin {
        analysis.issues.push(
            "The server reflects any Origin it is sent. Without credentials this exposes only \
             unauthenticated content, but it removes the origin restriction on every response."
                .to_string(),
        );
    }
    if analysis.allow_origin.as_deref() == Some("*") && analysis.allow_credentials {
        analysis.issues.push(
            "Access-Control-Allow-Origin is '*' alongside Allow-Credentials. Browsers reject the \
             combination, so cross-origin requests fail — the configuration does not do what it \
             appears to."
                .to_string(),
        );
    }
    if analysis.allows_null_origin {
        analysis.issues.push(
            "Access-Control-Allow-Origin: null is returned. A sandboxed iframe or a data: URL \
             sends Origin: null, so any page can obtain that origin and read the response."
                .to_string(),
        );
    }
    analysis
}

/// Which methods actually work, rather than which the `Allow` header claims.
async fn probe_methods(client: &reqwest::Client, url: &str, timeout: Duration) -> MethodAnalysis {
    let mut analysis = MethodAnalysis::default();

    if let Ok(response) = client
        .request(reqwest::Method::OPTIONS, url)
        .timeout(timeout)
        .send()
        .await
    {
        for header in ["allow", "access-control-allow-methods"] {
            if let Some(value) = response.headers().get(header).and_then(|v| v.to_str().ok()) {
                for method in value.split(',') {
                    let method = method.trim().to_ascii_uppercase();
                    if !method.is_empty() && !analysis.advertised.contains(&method) {
                        analysis.advertised.push(method);
                    }
                }
            }
        }
    }

    // TRACE is the one worth an active request: it reflects the request back,
    // which is Cross-Site Tracing (CVE-2005-3398 and friends).
    if let Ok(response) = client
        .request(reqwest::Method::TRACE, url)
        .timeout(timeout)
        .send()
        .await
    {
        let status = response.status().as_u16();
        let body = read_body_capped(response, MAX_PROBE_BYTES).await;
        // A real TRACE echoes the request line; a 200 with an HTML page does not.
        if status == 200 && (body.contains("TRACE /") || body.contains("TRACE http")) {
            analysis.trace_enabled = true;
            analysis.enabled.push("TRACE".to_string());
            analysis.issues.push(
                "TRACE is enabled and echoes the request. Combined with a scripting flaw this \
                 discloses headers a script cannot otherwise read, including HttpOnly cookies \
                 (Cross-Site Tracing)."
                    .to_string(),
            );
        }
    }

    for method in ["PUT", "DELETE"] {
        if analysis.advertised.iter().any(|m| m == method) {
            analysis.issues.push(format!(
                "{} is advertised in the Allow header. Confirm it is authenticated — an \
                 unauthenticated {} on a static path allows content to be replaced.",
                method, method
            ));
        }
    }
    analysis
}

struct BodyAnalysis {
    external_scripts: usize,
    external_scripts_with_sri: usize,
    /// Scripts specifically — the Observatory SRI check grades executable code,
    /// and counting an `<img>` over HTTP as one turns a −5 into a −50.
    external_scripts_over_http: usize,
    mixed_content: Vec<String>,
    /// How many there were before the display list was capped.
    mixed_content_total: usize,
}

fn analyze_body(body: &str, is_https: bool) -> BodyAnalysis {
    let mut external_scripts = 0;
    let mut external_scripts_with_sri = 0;
    let mut external_scripts_over_http = 0;
    let mut mixed_content = Vec::new();

    // Crude but adequate: split on <script and read the tag up to its '>'.
    for fragment in body.split("<script").skip(1) {
        let Some(end) = fragment.find('>') else { continue };
        let tag = &fragment[..end];
        let Some(src_start) = tag.find("src=") else {
            continue;
        };
        let rest = &tag[src_start + 4..];
        let quote = rest.chars().next().unwrap_or(' ');
        let src = if quote == '"' || quote == '\'' {
            rest[1..].split(quote).next().unwrap_or("")
        } else {
            rest.split_whitespace().next().unwrap_or("")
        };
        if src.starts_with("http://") || src.starts_with("https://") || src.starts_with("//") {
            external_scripts += 1;
            if tag.contains("integrity=") {
                external_scripts_with_sri += 1;
            }
        }
        if is_https && src.starts_with("http://") {
            external_scripts_over_http += 1;
            mixed_content.push(src.to_string());
        }
    }

    if is_https {
        for tag in ["<link", "<img", "<iframe"] {
            for fragment in body.split(tag).skip(1).take(80) {
                let Some(end) = fragment.find('>') else { continue };
                let attributes = &fragment[..end];
                if let Some(pos) = attributes.find("http://") {
                    let value: String = attributes[pos..]
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != '>')
                        .collect();
                    if !mixed_content.contains(&value) {
                        mixed_content.push(value);
                    }
                }
            }
        }
    }

    // The list is capped for display; the count is not, so the finding does not
    // understate how much of the page is affected.
    let mixed_content_total = mixed_content.len();
    mixed_content.truncate(20);
    BodyAnalysis {
        external_scripts,
        external_scripts_with_sri,
        external_scripts_over_http,
        mixed_content,
        mixed_content_total,
    }
}

/// Framework error pages that leak file paths, SQL and internal structure.
const STACK_TRACE_SIGNATURES: &[(&str, &str)] = &[
    ("Traceback (most recent call last)", "Python traceback"),
    ("java.lang.NullPointerException", "Java stack trace"),
    ("at org.springframework", "Spring stack trace"),
    ("Warning: mysqli", "PHP MySQL error"),
    ("Fatal error: Uncaught", "PHP fatal error"),
    ("<b>Warning</b>:  include", "PHP include warning"),
    ("System.NullReferenceException", ".NET exception"),
    ("Server Error in '/' Application", "ASP.NET error page"),
    ("ActiveRecord::", "Rails ActiveRecord error"),
    ("Whitelabel Error Page", "Spring Boot default error page"),
    ("Werkzeug Debugger", "Flask debugger enabled"),
    ("DEBUG = True", "Django debug mode"),
    ("You're seeing this error because you have", "Django debug page"),
];

fn detect_stack_trace(body: &str) -> Option<String> {
    STACK_TRACE_SIGNATURES
        .iter()
        .find(|(needle, _)| body.contains(needle))
        .map(|(_, label)| label.to_string())
}

fn detect_directory_listing(body: &str) -> bool {
    // Every common server's auto-index page carries one of these titles.
    const MARKERS: &[&str] = &[
        "<title>Index of /",
        "Directory Listing For",
        "[To Parent Directory]",
        "<h1>Index of /",
    ];
    MARKERS.iter().any(|marker| body.contains(marker))
}

async fn probe_paths(
    client: &reqwest::Client,
    base_url: &str,
    timeout: Duration,
) -> (Vec<ExposedPath>, bool) {
    let Ok(base) = url::Url::parse(base_url) else {
        return (Vec::new(), false);
    };
    let mut exposed = Vec::new();
    let mut security_txt = false;

    for probe in SENSITIVE_PATHS {
        let Ok(url) = base.join(probe.path) else {
            continue;
        };
        let Ok(response) = client.get(url.clone()).timeout(timeout).send().await else {
            continue;
        };
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            continue;
        }
        let body = read_body_capped(response, MAX_PROBE_BYTES).await;
        let head: String = body.chars().take(16_384).collect();

        // Content, not status. A 200 with the site's SPA shell is not an exposure,
        // and treating it as one is how path scanners generate pages of noise.
        let Some(signature) = probe
            .signatures
            .iter()
            .find(|needle| head.contains(**needle))
        else {
            continue;
        };

        if probe.finding_type == "security_txt_missing" {
            security_txt = true;
            continue;
        }

        exposed.push(ExposedPath {
            path: probe.path.to_string(),
            url: url.to_string(),
            status,
            label: probe.label.to_string(),
            content_length: body.len(),
            matched_signature: (*signature).to_string(),
        });
    }
    (exposed, security_txt)
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// Every finding type this scanner can emit. See `dns_scan` for why this exists.
pub const EMITTED_FINDING_TYPES: &[&str] = &[
    "https_not_enforced",
    "missing_security_header",
    "weak_security_header",
    "insecure_cookies",
    "cors_misconfiguration",
    "dangerous_http_method",
    "information_disclosure",
    "directory_listing",
    "mixed_content",
    "missing_sri",
    "server_version_exposed",
    "security_txt_missing",
    "sensitive_data_exposed",
    "debug_endpoint_exposed",
];

/// Turn the assessment into findings. Pure over the result, so every rule is
/// unit-testable without touching the network.
pub fn build_findings(result: &HttpScanResult) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    if result.status == 0 {
        return findings;
    }
    let url = &result.final_url;

    // ---- Exposed files and endpoints ---------------------------------------
    for exposed in &result.exposed_paths {
        let Some(probe) = SENSITIVE_PATHS.iter().find(|p| p.path == exposed.path) else {
            continue;
        };
        findings.push(ScanFinding::new(
            probe.finding_type,
            probe.severity,
            probe.label,
            format!(
                "{} Confirmed by fetching {} (HTTP {}), whose body contains `{}`.",
                probe.description, exposed.url, exposed.status, exposed.matched_signature
            ),
            probe.remediation,
            json!({
                "url": exposed.url,
                "path": exposed.path,
                "status": exposed.status,
                "matched_signature": exposed.matched_signature,
                "content_length": exposed.content_length,
            }),
        ));
    }

    // ---- Transport ---------------------------------------------------------
    if !result.is_https {
        // A failed HTTPS attempt is only evidence about the target if the failure
        // came from the target. Downgrading the severity and naming the error
        // keeps a scanner-side network problem from being filed as a defect in
        // somebody's web server.
        let (severity, detail) = match &result.https_error {
            Some(reason) => (
                FindingSeverity::Low,
                format!(
                    " The scan reached this conclusion after an https:// attempt failed with \"{}\", so confirm the error is the server's and not the scanner's network path before acting on it.",
                    reason
                ),
            ),
            None => (FindingSeverity::Medium, String::new()),
        };
        findings.push(ScanFinding::new(
            "https_not_enforced",
            severity,
            "HTTPS Not Enforced",
            format!(
                "{} is served over plain HTTP. Every request and response — including any \
                 credential or session cookie — travels in cleartext and can be read or modified \
                 by anyone on the network path.{}",
                url, detail
            ),
            "Serve the site over HTTPS, redirect HTTP to HTTPS on the same host, and add HSTS.",
            json!({
                "url": url,
                "redirect_chain": result.redirect_chain,
                "https_error": result.https_error,
            }),
        ));
    } else if result.redirects_to_https == Some(false) {
        findings.push(ScanFinding::new(
            "https_not_enforced",
            FindingSeverity::Medium,
            "HTTP Does Not Redirect to HTTPS",
            "The site answers over HTTPS, but the plain-HTTP origin does not redirect to it. A \
             visitor who types the bare hostname stays on HTTP, where the session can be hijacked \
             before HSTS ever applies.",
            "Redirect every plain-HTTP request to the same URL over HTTPS with a 301.",
            json!({ "url": url, "redirect_chain": result.redirect_chain }),
        ));
    }

    if result.is_https && !result.hsts.present {
        findings.push(ScanFinding::new(
            "missing_security_header",
            FindingSeverity::Medium,
            "Missing Security Header: Strict-Transport-Security",
            format!(
                "{} does not send HSTS. A visitor's first request of the day still goes out over \
                 plain HTTP, which is the window an on-path attacker needs to strip TLS entirely.",
                url
            ),
            "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
            json!({ "url": url, "header": "Strict-Transport-Security" }),
        ));
    } else if !result.hsts.issues.is_empty() {
        findings.push(ScanFinding::new(
            "weak_security_header",
            FindingSeverity::Low,
            "Weak HSTS Policy",
            format!(
                "The HSTS policy on {} is weaker than it should be: {}",
                url,
                result.hsts.issues.join(" ")
            ),
            "Set max-age to at least 15768000 (six months) and add includeSubDomains.",
            json!({
                "url": url,
                "max_age": result.hsts.max_age,
                "include_subdomains": result.hsts.include_subdomains,
                "preload": result.hsts.preload,
                "issues": result.hsts.issues,
            }),
        ));
    }

    // ---- CSP ---------------------------------------------------------------
    if !result.csp.present {
        findings.push(ScanFinding::new(
            "missing_security_header",
            FindingSeverity::Medium,
            "Missing Security Header: Content-Security-Policy",
            format!(
                "{} sends no Content-Security-Policy. Any HTML-injection flaw on the site \
                 escalates directly to script execution, with nothing to constrain where the \
                 injected script may load from or send data to.",
                url
            ),
            "Start with `default-src 'self'; object-src 'none'; base-uri 'none'` in \
             report-only mode, review the reports, then enforce.",
            json!({ "url": url, "header": "Content-Security-Policy" }),
        ));
    } else if !result.csp.issues.is_empty() {
        // A CSP that permits 'unsafe-inline' — or a bare `https:` in script-src,
        // which lets any host on the internet supply code — provides no XSS
        // protection at all, so reporting it as "header present" would mislead.
        // These are the same conditions Observatory scores at -20.
        let script_wildcard = result.csp.wildcard_sources.iter().any(|source| {
            source.starts_with("script-src") || source.starts_with("default-src")
                || source.starts_with("object-src")
        });
        let severity = if result.csp.unsafe_inline_script || script_wildcard || result.csp.report_only
        {
            FindingSeverity::Medium
        } else {
            FindingSeverity::Low
        };
        findings.push(ScanFinding::new(
            "weak_security_header",
            severity,
            "Weak Content-Security-Policy",
            format!(
                "{} sends a Content-Security-Policy, but it does not provide the protection its \
                 presence implies: {}",
                url,
                result.csp.issues.join(" ")
            ),
            "Remove 'unsafe-inline' and 'unsafe-eval' from script-src, replace broad sources with \
             explicit origins or nonces, and set object-src, base-uri and form-action.",
            json!({
                "url": url,
                "report_only": result.csp.report_only,
                "unsafe_inline_script": result.csp.unsafe_inline_script,
                "unsafe_eval": result.csp.unsafe_eval,
                "wildcard_sources": result.csp.wildcard_sources,
                "issues": result.csp.issues,
            }),
        ));
    }

    // ---- Remaining headers -------------------------------------------------
    for check in &result.checks {
        if check.passed || check.score_modifier >= 0 {
            continue;
        }
        // CSP, HSTS, cookies, CORS and redirects each have a richer finding above
        // or below; this covers the rest without duplicating them.
        if matches!(
            check.category.as_str(),
            "csp" | "hsts" | "cookies" | "cors" | "redirection" | "sri"
        ) {
            continue;
        }
        let severity = match check.score_modifier {
            m if m <= -20 => FindingSeverity::Medium,
            m if m <= -10 => FindingSeverity::Low,
            _ => FindingSeverity::Info,
        };
        findings.push(ScanFinding::new(
            "missing_security_header",
            severity,
            format!("Missing Security Header: {}", pretty_header(&check.category)),
            format!("{} ({}).", check.description, check.name),
            recommend_header(&check.category),
            json!({
                "url": url,
                "header": pretty_header(&check.category),
                "observatory_test": check.name,
                "score_modifier": check.score_modifier,
            }),
        ));
    }

    // ---- Cookies -----------------------------------------------------------
    let bad_cookies: Vec<&CookieAnalysis> =
        result.cookies.iter().filter(|c| !c.issues.is_empty()).collect();
    if !bad_cookies.is_empty() {
        let has_session_problem = bad_cookies
            .iter()
            .any(|c| c.session_like && (!c.secure || !c.http_only));
        findings.push(ScanFinding::new(
            "insecure_cookies",
            if has_session_problem {
                FindingSeverity::Medium
            } else {
                FindingSeverity::Low
            },
            "Insecure Cookie Attributes",
            format!(
                "{} of {} cookies set by {} are missing protective attributes: {}",
                bad_cookies.len(),
                result.cookies.len(),
                url,
                bad_cookies
                    .iter()
                    .map(|c| format!("{} ({})", c.name, c.issues.join("; ")))
                    .collect::<Vec<_>>()
                    .join(" · ")
            ),
            "Set Secure and SameSite on every cookie, HttpOnly on every session cookie, and use \
             the __Host- prefix where the cookie is origin-scoped.",
            json!({ "url": url, "cookies": bad_cookies }),
        ));
    }

    // ---- CORS --------------------------------------------------------------
    if !result.cors.issues.is_empty() {
        let severity = if result.cors.reflects_origin && result.cors.allow_credentials {
            FindingSeverity::High
        } else if result.cors.reflects_origin || result.cors.allows_null_origin {
            FindingSeverity::Medium
        } else {
            FindingSeverity::Low
        };
        findings.push(ScanFinding::new(
            "cors_misconfiguration",
            severity,
            "CORS Misconfiguration",
            format!("{} {}", url, result.cors.issues.join(" ")),
            "Validate the Origin header against an allowlist and echo only matching origins. \
             Never combine a reflected or wildcard origin with Allow-Credentials.",
            json!({
                "url": url,
                "allow_origin": result.cors.allow_origin,
                "allow_credentials": result.cors.allow_credentials,
                "reflects_origin": result.cors.reflects_origin,
                "allows_null_origin": result.cors.allows_null_origin,
                "issues": result.cors.issues,
            }),
        ));
    }

    // ---- Methods -----------------------------------------------------------
    if result.methods.trace_enabled {
        findings.push(ScanFinding::new(
            "dangerous_http_method",
            FindingSeverity::Medium,
            "HTTP TRACE Method Enabled",
            format!(
                "{} answers TRACE by echoing the request back. Combined with a scripting flaw \
                 this reveals headers script cannot otherwise read, including HttpOnly cookies \
                 and Authorization values (Cross-Site Tracing).",
                url
            ),
            "Disable TRACE (`TraceEnable Off` in Apache, and reject the method at any proxy).",
            json!({ "url": url, "methods_advertised": result.methods.advertised }),
        ));
    } else if !result.methods.issues.is_empty() {
        findings.push(ScanFinding::new(
            "dangerous_http_method",
            FindingSeverity::Low,
            "Write Methods Advertised",
            format!("{} {}", url, result.methods.issues.join(" ")),
            "Restrict write methods to authenticated routes and reject them elsewhere.",
            json!({ "url": url, "advertised": result.methods.advertised }),
        ));
    }

    // ---- Content-derived disclosures ---------------------------------------
    if let Some(kind) = &result.stack_trace_disclosed {
        findings.push(ScanFinding::new(
            "information_disclosure",
            FindingSeverity::Medium,
            "Application Error Details Disclosed",
            format!(
                "The response from {} contains a {}. These pages disclose file paths, framework \
                 versions, and often SQL or configuration values — a map of the application's \
                 internals handed to whoever asks.",
                url, kind
            ),
            "Turn off debug mode in production and serve a generic error page; log the detail \
             server-side instead.",
            json!({ "url": url, "detected": kind }),
        ));
    }

    if result.directory_listing {
        findings.push(ScanFinding::new(
            "directory_listing",
            FindingSeverity::Low,
            "Directory Listing Enabled",
            format!(
                "{} returns an automatic directory index. Every file in the directory is \
                 enumerable, including ones that are not linked from anywhere.",
                url
            ),
            "Disable auto-indexing (`Options -Indexes` in Apache, `autoindex off` in nginx).",
            json!({ "url": url }),
        ));
    }

    if !result.mixed_content.is_empty() {
        findings.push(ScanFinding::new(
            "mixed_content",
            FindingSeverity::Low,
            "Mixed Content on an HTTPS Page",
            format!(
                "{} is served over HTTPS but references {} resource(s) over plain HTTP: {}{}. \
                 Browsers block active mixed content and warn on passive, and any of it is \
                 modifiable in transit.",
                url,
                result.mixed_content_total.max(result.mixed_content.len()),
                result.mixed_content.join(", "),
                if result.mixed_content_total > result.mixed_content.len() {
                    format!(" and {} more", result.mixed_content_total - result.mixed_content.len())
                } else {
                    String::new()
                }
            ),
            "Serve every subresource over HTTPS, and add `upgrade-insecure-requests` to the CSP.",
            json!({ "url": url, "resources": result.mixed_content }),
        ));
    }

    if result.external_scripts > 0 && result.external_scripts_with_sri < result.external_scripts {
        findings.push(ScanFinding::new(
            "missing_sri",
            FindingSeverity::Low,
            "Third-Party Scripts Without Subresource Integrity",
            format!(
                "{} of {} externally-hosted scripts on {} carry no `integrity` attribute. If the \
                 third-party host is compromised, the modified script executes with full access \
                 to this origin.",
                result.external_scripts - result.external_scripts_with_sri,
                result.external_scripts,
                url
            ),
            "Add `integrity` and `crossorigin` attributes to every external <script>, or serve \
             the file from your own origin.",
            json!({
                "url": url,
                "external_scripts": result.external_scripts,
                "with_sri": result.external_scripts_with_sri,
            }),
        ));
    }

    if let Some(server) = &result.server {
        // A version number is the disclosure; a bare product name is not.
        if server.contains('/') && server.chars().any(|c| c.is_ascii_digit()) {
            findings.push(ScanFinding::new(
                "server_version_exposed",
                FindingSeverity::Info,
                "Server Version Disclosed",
                format!(
                    "The Server header on {} reads `{}`, naming the exact software version. That \
                     lets an attacker match published CVEs to this host without probing for them.",
                    url, server
                ),
                "Suppress the version (`ServerTokens Prod` in Apache, `server_tokens off` in \
                 nginx).",
                json!({ "url": url, "header": "Server", "value": server }),
            ));
        }
    }

    // Only when it was actually looked for.
    if result.security_txt == Some(false) {
        findings.push(ScanFinding::new(
            "security_txt_missing",
            FindingSeverity::Info,
            "No security.txt Published",
            format!(
                "{} does not publish /.well-known/security.txt. A researcher who finds a \
                 vulnerability has no documented way to report it, which is how findings end up \
                 public instead of in your inbox.",
                url
            ),
            "Publish /.well-known/security.txt with Contact: and Expires: fields (RFC 9116).",
            json!({ "url": url }),
        ));
    }

    findings
}

fn pretty_header(category: &str) -> String {
    category
        .split('-')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn recommend_header(category: &str) -> &'static str {
    match category {
        "x-frame-options" => {
            "Send `X-Frame-Options: DENY`, or better, `frame-ancestors 'none'` in the CSP."
        }
        "x-content-type-options" => "Send `X-Content-Type-Options: nosniff`.",
        "referrer-policy" => "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
        _ => "Add the header with a restrictive value.",
    }
}

/// The distinct header names reported as missing, for the summary panel.
pub fn missing_header_names(result: &HttpScanResult) -> BTreeSet<String> {
    result.headers_missing.iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::scanners::http_headers;

    fn result_with(headers: &[(&str, &str)]) -> HttpScanResult {
        let map: BTreeMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let csp = http_headers::parse_csp(
            map.get("content-security-policy").map(String::as_str),
            None,
        );
        let hsts = http_headers::parse_hsts(
            map.get("strict-transport-security").map(String::as_str),
        );
        let observatory = http_headers::score(&ScoringInput {
            is_https: true,
            headers: &map,
            csp: &csp,
            hsts: &hsts,
            cookies: &[],
            redirects_to_https: Some(true),
            redirect_first_hop_https: true,
            redirect_same_host: true,
            cors_allow_origin: None,
            cors_allow_credentials: false,
            external_scripts: 0,
            external_scripts_with_sri: 0,
            external_scripts_over_http: 0,
        });
        HttpScanResult {
            url: "https://example.com/".into(),
            final_url: "https://example.com/".into(),
            status: 200,
            is_https: true,
            http_version: "HTTP/2.0".into(),
            supports_http2: true,
            supports_http3: false,
            server: map.get("server").cloned(),
            headers_present: vec![],
            headers_missing: vec![],
            redirect_chain: vec![],
            redirects_to_https: Some(true),
            csp,
            hsts,
            cookies: vec![],
            cors: CorsAnalysis::default(),
            methods: MethodAnalysis::default(),
            exposed_paths: vec![],
            security_txt: Some(true),
            directory_listing: false,
            mixed_content: vec![],
            mixed_content_total: 0,
            external_scripts: 0,
            external_scripts_with_sri: 0,
            stack_trace_disclosed: None,
            https_error: None,
            checks: observatory.checks.clone(),
            observatory,
            errors: vec![],
            scan_duration_ms: 0,
        }
    }

    fn types(findings: &[ScanFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.finding_type.as_str()).collect()
    }

    #[test]
    fn an_unreachable_target_produces_no_findings() {
        let mut result = result_with(&[]);
        result.status = 0;
        assert!(build_findings(&result).is_empty());
    }

    #[test]
    fn a_hardened_response_produces_no_findings() {
        let result = result_with(&[
            ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
            ("content-security-policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
        ]);
        let findings = build_findings(&result);
        assert!(findings.is_empty(), "unexpected: {:?}", types(&findings));
        assert_eq!(result.observatory.grade, "A+");
    }

    #[test]
    fn a_present_but_useless_csp_is_still_a_finding() {
        // The whole point: "header present" is not the same as "protected".
        let result = result_with(&[
            ("strict-transport-security", "max-age=63072000; includeSubDomains"),
            ("content-security-policy", "default-src 'self' 'unsafe-inline'"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
        ]);
        let findings = build_findings(&result);
        let csp = findings
            .iter()
            .find(|f| f.title == "Weak Content-Security-Policy")
            .expect("weak CSP should be reported");
        assert_eq!(csp.severity, FindingSeverity::Medium);
        assert_eq!(csp.finding_type, "weak_security_header");
        // And it must not also be reported as missing.
        assert!(!findings
            .iter()
            .any(|f| f.title.contains("Missing Security Header: Content-Security-Policy")));
    }

    #[test]
    fn a_wildcard_script_src_is_as_serious_as_unsafe_inline() {
        // `script-src https:` lets any host on the internet supply executable
        // code; grading it below 'unsafe-inline' would be arbitrary.
        let result = result_with(&[
            ("strict-transport-security", "max-age=63072000; includeSubDomains"),
            ("content-security-policy", "default-src 'self'; script-src https:; base-uri 'none'; form-action 'self'"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
        ]);
        let findings = build_findings(&result);
        let csp = findings
            .iter()
            .find(|f| f.title == "Weak Content-Security-Policy")
            .unwrap();
        assert_eq!(csp.severity, FindingSeverity::Medium);

        // A policy whose only fault is style-src stays low.
        let result = result_with(&[
            ("strict-transport-security", "max-age=63072000; includeSubDomains"),
            ("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
        ]);
        let findings = build_findings(&result);
        if let Some(csp) = findings.iter().find(|f| f.title == "Weak Content-Security-Policy") {
            assert_eq!(csp.severity, FindingSeverity::Low);
        }
    }

    #[test]
    fn missing_headers_are_reported_once_each() {
        let result = result_with(&[]);
        let findings = build_findings(&result);
        let missing: Vec<&String> = findings
            .iter()
            .filter(|f| f.finding_type == "missing_security_header")
            .map(|f| &f.title)
            .collect();
        let unique: BTreeSet<&&String> = missing.iter().collect();
        assert_eq!(missing.len(), unique.len(), "duplicate header findings: {:?}", missing);
        assert!(missing.iter().any(|t| t.contains("Content-Security-Policy")));
        assert!(missing.iter().any(|t| t.contains("Strict-Transport-Security")));
        assert!(missing.iter().any(|t| t.contains("X-Frame-Options")));
    }

    #[test]
    fn every_emitted_type_is_declared() {
        let mut result = result_with(&[("server", "nginx/1.2.3")]);
        result.is_https = false;
        result.security_txt = Some(false);
        result.directory_listing = true;
        result.stack_trace_disclosed = Some("Python traceback".into());
        result.mixed_content = vec!["http://a/b.js".into()];
        result.external_scripts = 2;
        result.external_scripts_with_sri = 0;
        result.cookies = vec![http_headers::analyze_cookie("PHPSESSID=a").unwrap()];
        result.cors = CorsAnalysis {
            reflects_origin: true,
            allow_credentials: true,
            issues: vec!["reflects".into()],
            ..Default::default()
        };
        result.methods = MethodAnalysis {
            trace_enabled: true,
            ..Default::default()
        };
        result.exposed_paths = SENSITIVE_PATHS
            .iter()
            .filter(|p| p.finding_type != "security_txt_missing")
            .map(|p| ExposedPath {
                path: p.path.into(),
                url: format!("https://example.com{}", p.path),
                status: 200,
                label: p.label.into(),
                content_length: 10,
                matched_signature: p.signatures[0].into(),
            })
            .collect();

        let findings = build_findings(&result);
        assert!(findings.len() >= 15, "expected broad coverage, got {}", findings.len());
        for finding in &findings {
            assert!(
                EMITTED_FINDING_TYPES.contains(&finding.finding_type.as_str()),
                "undeclared finding type {}",
                finding.finding_type
            );
        }
    }

    #[test]
    fn cors_severity_escalates_with_credentials() {
        let mut result = result_with(&[]);
        result.cors = CorsAnalysis {
            reflects_origin: true,
            allow_credentials: true,
            issues: vec!["reflects origin with credentials".into()],
            ..Default::default()
        };
        let findings = build_findings(&result);
        let cors = findings.iter().find(|f| f.finding_type == "cors_misconfiguration").unwrap();
        assert_eq!(cors.severity, FindingSeverity::High);

        result.cors.allow_credentials = false;
        let findings = build_findings(&result);
        let cors = findings.iter().find(|f| f.finding_type == "cors_misconfiguration").unwrap();
        assert_eq!(cors.severity, FindingSeverity::Medium);
    }

    #[test]
    fn exposed_paths_carry_their_matched_signature() {
        let mut result = result_with(&[]);
        result.exposed_paths = vec![ExposedPath {
            path: "/.env".into(),
            url: "https://example.com/.env".into(),
            status: 200,
            label: "Environment file exposed".into(),
            content_length: 420,
            matched_signature: "DB_PASSWORD".into(),
        }];
        let findings = build_findings(&result);
        let env = findings
            .iter()
            .find(|f| f.title == "Environment file exposed")
            .unwrap();
        assert_eq!(env.severity, FindingSeverity::Critical);
        assert_eq!(env.finding_type, "sensitive_data_exposed");
        assert!(env.description.contains("DB_PASSWORD"));
    }

    #[test]
    fn session_cookie_problems_outrank_ordinary_ones() {
        let mut result = result_with(&[]);
        result.cookies = vec![http_headers::analyze_cookie("theme=dark").unwrap()];
        let findings = build_findings(&result);
        let cookies = findings.iter().find(|f| f.finding_type == "insecure_cookies").unwrap();
        assert_eq!(cookies.severity, FindingSeverity::Low);

        result.cookies = vec![http_headers::analyze_cookie("PHPSESSID=abc").unwrap()];
        let findings = build_findings(&result);
        let cookies = findings.iter().find(|f| f.finding_type == "insecure_cookies").unwrap();
        assert_eq!(cookies.severity, FindingSeverity::Medium);
    }

    #[test]
    fn plain_http_and_a_missing_redirect_are_distinct_findings() {
        let mut result = result_with(&[]);
        result.is_https = false;
        let findings = build_findings(&result);
        let https = findings.iter().find(|f| f.finding_type == "https_not_enforced").unwrap();
        assert!(https.title.contains("HTTPS Not Enforced"));

        let mut result = result_with(&[]);
        result.redirects_to_https = Some(false);
        let findings = build_findings(&result);
        let redirect = findings.iter().find(|f| f.finding_type == "https_not_enforced").unwrap();
        assert!(redirect.title.contains("Does Not Redirect"));
    }

    #[test]
    fn the_scheme_follows_an_explicit_plain_http_port() {
        // Only the URL derivation is under test here, so it is asserted through
        // the same rule the scanner uses.
        let scheme_for = |target: &str| -> String {
            if target.contains("://") {
                return target.to_string();
            }
            let port = target
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok());
            match port {
                Some(80) | Some(8080) | Some(8000) | Some(8888) => format!("http://{}", target),
                _ => format!("https://{}", target),
            }
        };
        assert_eq!(scheme_for("example.com"), "https://example.com");
        assert_eq!(scheme_for("example.com:443"), "https://example.com:443");
        assert_eq!(scheme_for("example.com:8443"), "https://example.com:8443");
        assert_eq!(scheme_for("127.0.0.1:8080"), "http://127.0.0.1:8080");
        assert_eq!(scheme_for("127.0.0.1:80"), "http://127.0.0.1:80");
        // An explicit scheme always wins.
        assert_eq!(scheme_for("http://example.com/"), "http://example.com/");
    }

    #[test]
    fn security_txt_is_only_reported_missing_when_it_was_probed() {
        let mut result = result_with(&[]);
        result.security_txt = Some(false);
        assert!(types(&build_findings(&result)).contains(&"security_txt_missing"));

        // A shallow scan never asks for the path, so it must not report it absent.
        result.security_txt = None;
        assert!(!types(&build_findings(&result)).contains(&"security_txt_missing"));

        result.security_txt = Some(true);
        assert!(!types(&build_findings(&result)).contains(&"security_txt_missing"));
    }

    #[test]
    fn mixed_content_does_not_count_as_scripts_over_http() {
        // An <img> over HTTP is mixed content but not an unprotected script, and
        // grading it as one costs 45 Observatory points — an A becomes an F.
        let body = concat!(
            r#"<script src="https://cdn.example.com/a.js"></script>"#,
            r#"<img src="http://tracker.example/pixel.gif">"#,
        );
        let analysis = analyze_body(body, true);
        assert_eq!(analysis.external_scripts, 1);
        assert_eq!(analysis.external_scripts_over_http, 0, "the img is not a script");
        assert_eq!(analysis.mixed_content.len(), 1);

        // A script actually loaded over HTTP does count.
        let body = r#"<script src="http://cdn.example.com/a.js"></script>"#;
        let analysis = analyze_body(body, true);
        assert_eq!(analysis.external_scripts_over_http, 1);
    }

    #[test]
    fn the_mixed_content_count_is_not_capped_by_the_display_list() {
        let body: String = (0..30)
            .map(|i| format!(r#"<img src="http://host{}.example/p.gif">"#, i))
            .collect();
        let analysis = analyze_body(&body, true);
        assert_eq!(analysis.mixed_content.len(), 20, "the list is capped");
        assert_eq!(analysis.mixed_content_total, 30, "the count is not");
    }

    #[test]
    fn a_failed_https_attempt_downgrades_the_http_finding() {
        // A scanner-side connection failure must not be filed as "this server has
        // no HTTPS" at the same severity as a server that genuinely has none.
        let mut result = result_with(&[]);
        result.is_https = false;
        result.https_error = Some("error trying to connect: unsuccessful tunnel".into());
        let findings = build_findings(&result);
        let https = findings
            .iter()
            .find(|f| f.finding_type == "https_not_enforced")
            .unwrap();
        assert_eq!(https.severity, FindingSeverity::Low);
        assert!(https.description.contains("unsuccessful tunnel"));
        assert!(https.description.contains("not the scanner's"));

        // With no error recorded, HTTP-only is a real medium finding.
        result.https_error = None;
        let findings = build_findings(&result);
        let https = findings
            .iter()
            .find(|f| f.finding_type == "https_not_enforced")
            .unwrap();
        assert_eq!(https.severity, FindingSeverity::Medium);
        assert!(!https.description.contains("confirm the error"));
    }

    #[test]
    fn server_version_is_reported_only_when_a_version_is_present() {
        let result = result_with(&[("server", "nginx/1.18.0")]);
        assert!(types(&build_findings(&result)).contains(&"server_version_exposed"));

        let result = result_with(&[("server", "cloudflare")]);
        assert!(!types(&build_findings(&result)).contains(&"server_version_exposed"));
    }

    #[test]
    fn stack_traces_are_recognised_per_framework() {
        assert_eq!(
            detect_stack_trace("Traceback (most recent call last):\n  File ..."),
            Some("Python traceback".into())
        );
        assert_eq!(
            detect_stack_trace("<h1>Whitelabel Error Page</h1>"),
            Some("Spring Boot default error page".into())
        );
        assert_eq!(detect_stack_trace("<html>Hello</html>"), None);
    }

    #[test]
    fn directory_listing_markers_are_matched() {
        assert!(detect_directory_listing("<title>Index of /uploads</title>"));
        assert!(detect_directory_listing("[To Parent Directory]"));
        assert!(!detect_directory_listing("<title>Index of our services</title>"));
    }

    #[test]
    fn body_analysis_counts_external_scripts_and_mixed_content() {
        let body = r#"
            <script src="https://cdn.example.com/a.js" integrity="sha384-abc"></script>
            <script src="https://cdn.example.com/b.js"></script>
            <script src="/local.js"></script>
            <script>inline()</script>
            <img src="http://insecure.example.com/pixel.gif">
        "#;
        let analysis = analyze_body(body, true);
        assert_eq!(analysis.external_scripts, 2, "local and inline do not count");
        assert_eq!(analysis.external_scripts_with_sri, 1);
        assert!(analysis
            .mixed_content
            .iter()
            .any(|r| r.contains("insecure.example.com")));
    }

    #[test]
    fn mixed_content_is_not_reported_on_an_http_page() {
        let body = r#"<img src="http://example.com/a.gif">"#;
        let analysis = analyze_body(body, false);
        assert!(analysis.mixed_content.is_empty());
    }

    #[test]
    fn every_probe_has_a_signature_so_a_catch_all_200_cannot_match() {
        for probe in SENSITIVE_PATHS {
            assert!(
                !probe.signatures.is_empty(),
                "{} would match any 200 response",
                probe.path
            );
            assert!(!probe.remediation.is_empty(), "{} has no remediation", probe.path);
        }
    }

    #[test]
    fn header_names_render_readably() {
        assert_eq!(pretty_header("x-frame-options"), "X-Frame-Options");
        assert_eq!(pretty_header("referrer-policy"), "Referrer-Policy");
    }
}

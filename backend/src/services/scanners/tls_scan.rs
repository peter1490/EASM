//! Full TLS/SSL assessment of one endpoint.
//!
//! Drives [`tls_probe`] and [`cert_analysis`] to produce what `sslscan`,
//! `sslyze`, `testssl.sh` and SSL Labs produce: every protocol version the server
//! speaks, every cipher suite it will accept on each, whose preference order
//! wins, the key-exchange strength actually negotiated, the certificate chain
//! judged against a browser's trust store, the vulnerability set implied by all
//! of that, and a letter grade computed by the published SSL Labs rating guide
//! rather than invented here.
//!
//! Detection is separated into two confidences and they are never conflated.
//! *Confirmed* means the scanner observed the condition — SSLv2 answered, DEFLATE
//! was negotiated, the heartbeat overread came back. *Potential* means the
//! configuration is a precondition for the attack but proving it needs an oracle
//! test this scanner deliberately does not run (ROBOT, LUCKY13). Reporting the
//! second as the first is how a scanner loses its reader.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use serde_json::json;

use crate::models::FindingSeverity;

use super::cert_analysis::{
    self, ChainAnalysis, ParsedCertificate, TrustStatus, MAX_CERTIFICATE_LIFETIME_DAYS,
};
use super::cipher_suites::{self, CipherSuite, Encryption, KeyExchange};
use super::tls_probe::{
    self, ecc_equivalent_dh_bits, HeartbleedVerdict, KeyExchangeInfo, TlsVersion,
};
use super::ScanFinding;

/// How many enumeration rounds one protocol version gets. Each round is a full
/// TCP+handshake, so this is the main cost control: 48 covers every suite in the
/// table with room to spare, and a server offering more than that is unusual
/// enough that truncation is reported rather than hidden.
const MAX_CIPHER_ROUNDS: usize = 48;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSupport {
    pub version: String,
    pub supported: bool,
    pub deprecated: bool,
    /// The suite the server picks when offered everything — its own preference.
    pub preferred_cipher: Option<String>,
    pub cipher_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherReport {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub key_exchange: String,
    pub encryption: String,
    pub bits: u16,
    pub forward_secrecy: bool,
    pub aead: bool,
    pub strength: String,
    pub curve: Option<String>,
    pub dh_bits: Option<u32>,
}

/// Whether the scanner saw the problem or merely saw the conditions for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Potential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsVulnerability {
    pub id: String,
    pub name: String,
    pub cve: Option<String>,
    pub severity: String,
    pub confidence: Confidence,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

/// Protocol features that are not vulnerabilities but decide the grade or the
/// remediation advice.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsFeatures {
    pub alpn_protocols: Vec<String>,
    pub http2: bool,
    /// `None` when only TLS 1.3 is available: the CertificateStatus message that
    /// proves stapling is encrypted there, so the scanner cannot see it.
    pub ocsp_stapling: Option<bool>,
    pub session_tickets: bool,
    pub extended_master_secret: bool,
    pub encrypt_then_mac: bool,
    pub secure_renegotiation: bool,
    pub fallback_scsv: Option<bool>,
    pub compression: Option<bool>,
    pub server_cipher_preference: bool,
    pub forward_secrecy_only: bool,
    pub aead_only: bool,
    pub named_curves: Vec<String>,
    pub min_dh_bits: Option<u32>,
}

/// The SSL Labs rating, with the arithmetic kept visible so a reader can see why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsGrade {
    pub grade: String,
    pub score: u32,
    pub protocol_score: u32,
    pub key_exchange_score: u32,
    pub cipher_score: u32,
    /// Conditions that held the grade below what the score alone would give.
    pub caps: Vec<String>,
    /// Conditions that cost the `+`, in SSL Labs terms.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsScanResult {
    pub host: String,
    pub port: u16,
    pub protocols: Vec<ProtocolSupport>,
    pub supported_protocols: Vec<String>,
    pub highest_protocol: Option<String>,
    pub lowest_protocol: Option<String>,
    pub ciphers: Vec<CipherReport>,
    pub weak_ciphers: Vec<String>,
    pub certificate: Option<ParsedCertificate>,
    pub chain: ChainAnalysis,
    pub features: TlsFeatures,
    pub vulnerabilities: Vec<TlsVulnerability>,
    pub grade: TlsGrade,
    /// A public second opinion for whoever reads the finding.
    pub ssl_labs_url: Option<String>,
    pub crt_sh_url: Option<String>,
    pub errors: Vec<String>,
    pub scan_duration_ms: i64,
}

impl TlsScanResult {
    pub fn reachable(&self) -> bool {
        !self.supported_protocols.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SSL Labs rating
// ---------------------------------------------------------------------------

/// Protocol support score: the average of the best and worst version offered
/// (SSL Labs Rating Guide §3.1).
fn protocol_score(supported: &[TlsVersion]) -> u32 {
    if supported.is_empty() {
        return 0;
    }
    let best = supported.iter().map(|v| v.rating()).max().unwrap_or(0);
    let worst = supported.iter().map(|v| v.rating()).min().unwrap_or(0);
    (best + worst) / 2
}

/// Key exchange score, taken from the *weakest* key exchange on offer (§3.2).
/// Certificate key strength and ephemeral parameter strength are graded on the
/// same scale, so an RSA-2048 certificate in front of a 1024-bit DH group scores
/// as the 1024-bit group.
fn key_exchange_score(effective_bits: u32, anonymous: bool, export: bool) -> u32 {
    if anonymous {
        return 0;
    }
    if export {
        return 40;
    }
    match effective_bits {
        0..=511 => 20,
        512..=1023 => 40,
        1024..=2047 => 80,
        2048..=4095 => 90,
        _ => 100,
    }
}

/// Cipher strength score: the average of the strongest and weakest suite (§3.3).
fn cipher_score(bits: &[u16]) -> u32 {
    if bits.is_empty() {
        return 0;
    }
    let band = |b: u16| -> u32 {
        match b {
            0 => 0,
            1..=127 => 20,
            128..=255 => 80,
            _ => 100,
        }
    };
    let best = bits.iter().copied().map(band).max().unwrap_or(0);
    let worst = bits.iter().copied().map(band).min().unwrap_or(0);
    (best + worst) / 2
}

fn letter_for_score(score: u32) -> &'static str {
    match score {
        80..=u32::MAX => "A",
        65..=79 => "B",
        50..=64 => "C",
        35..=49 => "D",
        20..=34 => "E",
        _ => "F",
    }
}

/// Order used to apply caps: a cap can only ever lower a grade.
fn grade_rank(grade: &str) -> u8 {
    match grade {
        "A+" => 8,
        "A" => 7,
        "A-" => 6,
        "B" => 5,
        "C" => 4,
        "D" => 3,
        "E" => 2,
        "F" => 1,
        _ => 0, // T and M sit outside the scale
    }
}

fn cap_grade(current: &mut String, cap: &str, caps: &mut Vec<String>, reason: &str) {
    if grade_rank(cap) < grade_rank(current) {
        *current = cap.to_string();
    }
    caps.push(reason.to_string());
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

/// Run the full assessment. `host` is used for SNI and hostname validation;
/// `addr` is the endpoint actually connected to, so an IP asset with a known
/// virtual host still gets a correct certificate verdict.
pub async fn scan(
    host: &str,
    addr: SocketAddr,
    port: u16,
    timeout: Duration,
    deep: bool,
) -> TlsScanResult {
    let started = std::time::Instant::now();
    let mut errors = Vec::new();
    let sni = if host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host)
    };

    // ---- Protocol enumeration -------------------------------------------
    // Sequential rather than concurrent: a scanner that opens six sockets at
    // once to the same endpoint looks like a SYN flood to any IPS in the path,
    // and some servers rate-limit handshakes per source.
    let mut protocols = Vec::new();
    let mut supported = Vec::new();
    let mut der_chain: Vec<Vec<u8>> = Vec::new();
    let mut features = TlsFeatures::default();
    let mut ocsp_seen_on_legacy = false;
    let mut legacy_reachable = false;

    for version in TlsVersion::all() {
        // A peer that answered with something that is not TLS will do so for
        // every version; probing the remaining five just burns the timeout.
        let attempt = tls_probe::handshake(
            addr,
            &tls_probe::HelloOptions::new(version, sni.map(str::to_string)),
            timeout,
        )
        .await;
        if attempt.as_ref().is_some_and(|result| result.not_tls) {
            errors.push(format!(
                "{}:{} answered with something that is not TLS; the remaining protocol probes \
                 were skipped",
                host, port
            ));
            protocols.push(ProtocolSupport {
                version: version.label().to_string(),
                supported: false,
                deprecated: version.is_deprecated(),
                preferred_cipher: None,
                cipher_count: 0,
            });
            break;
        }

        match attempt.filter(|result| result.succeeded()) {
            Some(result) => {
                supported.push(version);
                // Only TLS 1.2 and below expose the extensions read below; TLS 1.3
                // moved them into the encrypted flight, so a 1.3-only endpoint
                // must report "not determined" rather than "not enabled".
                if version <= TlsVersion::Tls12 && version != TlsVersion::Ssl2 {
                    legacy_reachable = true;
                }
                if der_chain.is_empty() && !result.certificates.is_empty() {
                    der_chain = result.certificates.clone();
                }
                if let Some(alpn) = &result.alpn {
                    if !features.alpn_protocols.contains(alpn) {
                        features.alpn_protocols.push(alpn.clone());
                    }
                }
                // These extensions only appear in a TLS 1.2-and-below ServerHello;
                // in TLS 1.3 they moved into the encrypted flight.
                if version <= TlsVersion::Tls12 {
                    if result.ocsp_stapled {
                        ocsp_seen_on_legacy = true;
                    }
                    features.session_tickets |= result.has_extension(35);
                    features.extended_master_secret |= result.has_extension(23);
                    features.encrypt_then_mac |= result.has_extension(22);
                    features.secure_renegotiation |= result.has_extension(0xff01);
                }
                protocols.push(ProtocolSupport {
                    version: version.label().to_string(),
                    supported: true,
                    deprecated: version.is_deprecated(),
                    preferred_cipher: result.cipher_id.map(cipher_suites::name_for),
                    cipher_count: 0,
                });
            }
            None => protocols.push(ProtocolSupport {
                version: version.label().to_string(),
                supported: false,
                deprecated: version.is_deprecated(),
                preferred_cipher: None,
                cipher_count: 0,
            }),
        }
    }

    if supported.is_empty() {
        errors.push(format!(
            "No TLS handshake completed against {}:{} — the endpoint may not speak TLS",
            host, port
        ));
    }

    features.http2 = features.alpn_protocols.iter().any(|p| p == "h2");
    features.ocsp_stapling = if legacy_reachable {
        Some(ocsp_seen_on_legacy)
    } else {
        // TLS 1.3 only: CertificateStatus is encrypted, so we genuinely cannot say.
        None
    };

    // ---- Cipher enumeration ----------------------------------------------
    let mut ciphers: Vec<CipherReport> = Vec::new();
    let mut curves: BTreeSet<String> = BTreeSet::new();
    let mut min_dh_bits: Option<u32> = None;
    let mut any_server_preference = false;

    for version in supported.iter().copied() {
        if version == TlsVersion::Ssl2 {
            continue;
        }
        let rounds = if deep { MAX_CIPHER_ROUNDS } else { 12 };
        let enumeration =
            tls_probe::enumerate_ciphers(addr, version, sni, timeout, rounds).await;
        any_server_preference |= enumeration.server_has_preference;

        if let Some(entry) = protocols
            .iter_mut()
            .find(|p| p.version == version.label() && p.supported)
        {
            entry.cipher_count = enumeration.accepted.len();
        }
        if enumeration.accepted.len() >= rounds {
            errors.push(format!(
                "{} cipher enumeration stopped at the {}-round cap; the list may be incomplete",
                version.label(),
                rounds
            ));
        }

        for (id, kx) in enumeration.accepted {
            if let Some(curve) = &kx.curve_name {
                curves.insert(curve.clone());
            }
            if let Some(bits) = kx.dh_bits {
                min_dh_bits = Some(min_dh_bits.map_or(bits, |m: u32| m.min(bits)));
            }
            ciphers.push(build_cipher_report(id, version, &kx));
        }
    }

    features.server_cipher_preference = any_server_preference;
    features.named_curves = curves.into_iter().collect();
    features.min_dh_bits = min_dh_bits;
    features.forward_secrecy_only = !ciphers.is_empty() && ciphers.iter().all(|c| c.forward_secrecy);
    features.aead_only = !ciphers.is_empty() && ciphers.iter().all(|c| c.aead);

    // ---- Targeted probes --------------------------------------------------
    let highest = supported.iter().copied().max();
    if let Some(highest) = highest {
        if highest >= TlsVersion::Tls11 {
            features.fallback_scsv =
                tls_probe::supports_fallback_scsv(addr, highest, sni, timeout).await;
        }
        let compression_version = supported
            .iter()
            .copied()
            .filter(|v| *v != TlsVersion::Ssl2 && *v <= TlsVersion::Tls12)
            .max();
        if let Some(version) = compression_version {
            features.compression =
                tls_probe::supports_compression(addr, version, sni, timeout).await;
        }
    }

    let heartbleed = if deep && supported.contains(&TlsVersion::Tls12) {
        tls_probe::check_heartbleed(addr, sni, timeout).await
    } else {
        HeartbleedVerdict::Inconclusive
    };

    // ---- Certificate ------------------------------------------------------
    let chain = cert_analysis::analyze_chain(&der_chain, host);
    if chain.chain.is_empty() && !supported.is_empty() {
        errors.push(
            "The certificate chain was not captured: the endpoint negotiated TLS 1.3, where the \
             Certificate message is encrypted. Enable TLS 1.2 to allow chain inspection, or read \
             the leaf from the CT log link."
                .to_string(),
        );
    }
    let certificate = chain.chain.first().cloned();

    // ---- Vulnerabilities and grade ---------------------------------------
    let vulnerabilities = derive_vulnerabilities(
        &supported,
        &ciphers,
        &features,
        &chain,
        heartbleed,
        min_dh_bits,
    );
    let grade = compute_grade(
        &supported,
        &ciphers,
        &features,
        &chain,
        certificate.as_ref(),
        &vulnerabilities,
        min_dh_bits,
    );

    let weak_ciphers = ciphers
        .iter()
        .filter(|c| c.strength == "weak" || c.strength == "insecure")
        .map(|c| c.name.clone())
        .collect();

    let is_domain = host.parse::<std::net::IpAddr>().is_err();
    TlsScanResult {
        host: host.to_string(),
        port,
        supported_protocols: supported.iter().map(|v| v.label().to_string()).collect(),
        highest_protocol: supported.iter().max().map(|v| v.label().to_string()),
        lowest_protocol: supported.iter().min().map(|v| v.label().to_string()),
        protocols,
        ciphers,
        weak_ciphers,
        certificate,
        chain,
        features,
        vulnerabilities,
        grade,
        ssl_labs_url: is_domain.then(|| {
            format!(
                "https://www.ssllabs.com/ssltest/analyze.html?d={}&hideResults=on",
                host
            )
        }),
        crt_sh_url: is_domain.then(|| format!("https://crt.sh/?q={}", host)),
        errors,
        scan_duration_ms: started.elapsed().as_millis() as i64,
    }
}

/// A result carrying only the certificate analysis.
///
/// For the case where `rustls` completed a handshake but the raw prober did not,
/// so the chain is known and the protocol/cipher configuration is not. The
/// protocol and cipher lists stay empty and the grade is reported as unevaluated,
/// because those genuinely were not measured — a grade computed from no
/// observations would be worse than no grade.
pub fn certificate_only_result(host: &str, port: u16, chain_der: &[Vec<u8>]) -> TlsScanResult {
    let chain = cert_analysis::analyze_chain(chain_der, host);
    let certificate = chain.chain.first().cloned();
    let is_domain = host.parse::<std::net::IpAddr>().is_err();

    let vulnerabilities = if chain.trust == TrustStatus::Revoked {
        vec![vuln(
            "revoked_certificate",
            "Revoked certificate",
            None,
            "critical",
            Confidence::Confirmed,
            "The certificate has been revoked by its issuer.",
            chain.trust_detail.clone().unwrap_or_default(),
            "Install a newly issued certificate.",
        )]
    } else {
        Vec::new()
    };

    TlsScanResult {
        host: host.to_string(),
        port,
        protocols: Vec::new(),
        // Non-empty so `reachable()` is true and the certificate findings are
        // not discarded, but honest about what was established.
        supported_protocols: vec!["unknown".to_string()],
        highest_protocol: None,
        lowest_protocol: None,
        ciphers: Vec::new(),
        weak_ciphers: Vec::new(),
        certificate,
        chain,
        features: TlsFeatures::default(),
        vulnerabilities,
        grade: TlsGrade {
            grade: "?".to_string(),
            score: 0,
            protocol_score: 0,
            key_exchange_score: 0,
            cipher_score: 0,
            caps: Vec::new(),
            warnings: vec![
                "Protocol and cipher configuration was not measured: the endpoint did not answer \
                 the scanner's handshake, so only the certificate could be assessed."
                    .to_string(),
            ],
        },
        ssl_labs_url: is_domain.then(|| {
            format!(
                "https://www.ssllabs.com/ssltest/analyze.html?d={}&hideResults=on",
                host
            )
        }),
        crt_sh_url: is_domain.then(|| format!("https://crt.sh/?q={}", host)),
        errors: vec![
            "The TLS handshake this scanner builds was not answered; the certificate was read \
             through the standard client instead. Protocol versions, cipher suites and the grade \
             are therefore not reported."
                .to_string(),
        ],
        scan_duration_ms: 0,
    }
}

fn build_cipher_report(id: u16, version: TlsVersion, kx: &KeyExchangeInfo) -> CipherReport {
    let suite = cipher_suites::lookup(id);
    let strength = match suite {
        Some(s) if s.is_insecure() => "insecure",
        Some(s) if s.is_weak() => "weak",
        Some(s) if s.bits >= 256 && s.enc.is_aead() => "strong",
        Some(_) => "acceptable",
        None => "unknown",
    };
    CipherReport {
        id: format!("0x{:04X}", id),
        name: cipher_suites::name_for(id),
        protocol: version.label().to_string(),
        key_exchange: suite.map_or_else(
            || "unknown".to_string(),
            |s| {
                if s.kx == KeyExchange::Tls13 {
                    // TLS 1.3 always uses an ephemeral (EC)DHE exchange; the group
                    // is what was actually agreed.
                    kx.curve_name.clone().unwrap_or_else(|| "ECDHE".to_string())
                } else {
                    s.kx.label().to_string()
                }
            },
        ),
        encryption: suite.map_or_else(|| "unknown".to_string(), |s| s.enc.label().to_string()),
        bits: suite.map_or(0, |s| s.bits),
        forward_secrecy: suite.is_some_and(|s| s.kx.forward_secret()),
        aead: suite.is_some_and(|s| s.enc.is_aead()),
        strength: strength.to_string(),
        curve: kx.curve_name.clone(),
        dh_bits: kx.dh_bits,
    }
}

fn suites_of(ciphers: &[CipherReport]) -> Vec<&'static CipherSuite> {
    ciphers
        .iter()
        .filter_map(|c| {
            u16::from_str_radix(c.id.trim_start_matches("0x"), 16)
                .ok()
                .and_then(cipher_suites::lookup)
        })
        .collect()
}

/// Construct a vulnerability entry. Wide on purpose: every field is part of the
/// report, and packing them into a struct just to unpack them at each call site
/// would make the twelve call sites below harder to read, not easier.
#[allow(clippy::too_many_arguments)]
fn vuln(
    id: &str,
    name: &str,
    cve: Option<&str>,
    severity: &str,
    confidence: Confidence,
    description: &str,
    evidence: String,
    remediation: &str,
) -> TlsVulnerability {
    TlsVulnerability {
        id: id.to_string(),
        name: name.to_string(),
        cve: cve.map(str::to_string),
        severity: severity.to_string(),
        confidence,
        description: description.to_string(),
        evidence,
        remediation: remediation.to_string(),
    }
}

fn derive_vulnerabilities(
    supported: &[TlsVersion],
    ciphers: &[CipherReport],
    features: &TlsFeatures,
    chain: &ChainAnalysis,
    heartbleed: HeartbleedVerdict,
    min_dh_bits: Option<u32>,
) -> Vec<TlsVulnerability> {
    let mut out = Vec::new();
    let suites = suites_of(ciphers);
    let names = |predicate: &dyn Fn(&CipherSuite) -> bool| -> String {
        let matched: Vec<&str> = suites
            .iter()
            .filter(|s| predicate(s))
            .map(|s| s.name)
            .collect();
        matched.join(", ")
    };

    if supported.contains(&TlsVersion::Ssl2) {
        out.push(vuln(
            "drown", "DROWN", Some("CVE-2016-0800"), "critical", Confidence::Confirmed,
            "The server speaks SSLv2. An attacker can use it as a decryption oracle against TLS \
             sessions that share the same RSA key, even ones negotiated on a modern protocol.",
            "SSLv2 handshake accepted".to_string(),
            "Disable SSLv2 entirely. It has no legitimate use and no client requires it.",
        ));
    }

    if supported.contains(&TlsVersion::Ssl3) {
        let cbc = names(&|s| s.enc.is_cbc());
        out.push(vuln(
            "poodle_sslv3", "POODLE", Some("CVE-2014-3566"), "high", Confidence::Confirmed,
            "SSLv3 is enabled. Its CBC padding is not covered by the MAC, so an attacker who can \
             trigger repeated requests recovers plaintext a byte at a time.",
            if cbc.is_empty() { "SSLv3 handshake accepted".to_string() } else { format!("SSLv3 with CBC suites: {}", cbc) },
            "Disable SSLv3. Every current client negotiates TLS 1.2 or better.",
        ));
    }

    if supported.contains(&TlsVersion::Tls10) && suites.iter().any(|s| s.enc.is_cbc()) {
        out.push(vuln(
            "beast", "BEAST", Some("CVE-2011-3389"), "low", Confidence::Potential,
            "TLS 1.0 with CBC suites uses predictable IVs. Client-side mitigations (1/n-1 record \
             splitting) have shipped in every browser since 2012, so exploitation now requires an \
             unpatched client as well as this server.",
            format!("TLS 1.0 offered with CBC suites: {}", names(&|s| s.enc.is_cbc())),
            "Disable TLS 1.0 (RFC 8996). If it must stay, prefer AEAD suites and RC4-free ordering.",
        ));
    }

    if suites.iter().any(|s| s.enc.is_64bit_block()) {
        out.push(vuln(
            "sweet32", "SWEET32", Some("CVE-2016-2183"), "medium", Confidence::Confirmed,
            "64-bit block ciphers (3DES, IDEA, RC2) hit their birthday bound after ~32 GB on one \
             connection, letting an attacker recover repeated plaintext such as a session cookie.",
            format!("64-bit block suites offered: {}", names(&|s| s.enc.is_64bit_block())),
            "Remove 3DES, IDEA and RC2 from the cipher list.",
        ));
    }

    if suites.iter().any(|s| s.enc == Encryption::Rc4) {
        out.push(vuln(
            "rc4", "RC4 enabled", Some("CVE-2015-2808"), "medium", Confidence::Confirmed,
            "RC4's keystream is measurably biased. RFC 7465 prohibits it in TLS outright.",
            format!("RC4 suites offered: {}", names(&|s| s.enc == Encryption::Rc4)),
            "Remove all RC4 suites.",
        ));
    }

    if suites.iter().any(|s| s.kx == KeyExchange::Export && s.enc != Encryption::DesCbc40) {
        out.push(vuln(
            "freak", "FREAK", Some("CVE-2015-0204"), "high", Confidence::Confirmed,
            "Export-grade RSA suites are offered. A man in the middle can force a 512-bit RSA key \
             exchange and factor it within hours.",
            format!("Export suites offered: {}", names(&|s| s.kx == KeyExchange::Export)),
            "Remove every EXPORT suite from the cipher list.",
        ));
    }

    let weak_dh = min_dh_bits.is_some_and(|b| b < 2048);
    if suites.iter().any(|s| s.kx == KeyExchange::Export) || min_dh_bits.is_some_and(|b| b <= 1024) {
        out.push(vuln(
            "logjam", "LOGJAM", Some("CVE-2015-4000"), "high", Confidence::Confirmed,
            "The server accepts a Diffie-Hellman group small enough to precompute against. A \
             state-level attacker who has done the precomputation reads every session using it.",
            match min_dh_bits {
                Some(bits) => format!("smallest DH group offered: {} bits", bits),
                None => "export-grade DHE suites offered".to_string(),
            },
            "Use a 2048-bit or larger DH group, or prefer ECDHE and drop finite-field DHE entirely.",
        ));
    } else if weak_dh {
        out.push(vuln(
            "weak_dh", "Undersized DH group", None, "medium", Confidence::Confirmed,
            "The Diffie-Hellman group is below the 2048-bit floor recommended by NIST SP 800-57 \
             and required for an A grade.",
            format!("smallest DH group offered: {} bits", min_dh_bits.unwrap_or(0)),
            "Generate a 2048-bit or larger DH group, or switch to ECDHE.",
        ));
    }

    if features.compression == Some(true) {
        out.push(vuln(
            "crime", "CRIME", Some("CVE-2012-4929"), "high", Confidence::Confirmed,
            "TLS-level compression is enabled. Because compressed length leaks how much of the \
             plaintext an attacker guessed correctly, secrets in the request are recoverable.",
            "server negotiated DEFLATE compression".to_string(),
            "Disable TLS compression. No modern stack enables it by default.",
        ));
    }

    match heartbleed {
        HeartbleedVerdict::Vulnerable => out.push(vuln(
            "heartbleed", "Heartbleed", Some("CVE-2014-0160"), "critical", Confidence::Confirmed,
            "The server returned more heartbeat payload than it was sent, so arbitrary process \
             memory — private keys, session cookies, credentials — is readable by any client.",
            "heartbeat response exceeded the requested payload length".to_string(),
            "Patch OpenSSL immediately, then reissue and revoke the certificate and rotate every \
             secret the process held.",
        )),
        HeartbleedVerdict::NotVulnerable | HeartbleedVerdict::HeartbeatDisabled | HeartbleedVerdict::Inconclusive => {}
    }

    if !features.secure_renegotiation && supported.iter().any(|v| *v <= TlsVersion::Tls12) {
        out.push(vuln(
            "insecure_renegotiation", "Insecure renegotiation", Some("CVE-2009-3555"), "medium",
            Confidence::Confirmed,
            "The server did not advertise RFC 5746 secure renegotiation, so a man in the middle \
             can prefix chosen plaintext to a client's request.",
            "no renegotiation_info extension or SCSV in the ServerHello".to_string(),
            "Upgrade the TLS stack, or disable renegotiation.",
        ));
    }

    if features.fallback_scsv == Some(false) && supported.len() > 1 {
        out.push(vuln(
            "no_fallback_scsv", "No downgrade protection", None, "low", Confidence::Confirmed,
            "TLS_FALLBACK_SCSV (RFC 7507) is not honoured, so an attacker who breaks a handshake \
             can silently push the client down to the weakest protocol the server still accepts.",
            "downgrade handshake carrying the SCSV was accepted".to_string(),
            "Enable TLS_FALLBACK_SCSV, and remove the older protocols there is nothing to fall back to.",
        ));
    }

    if suites.iter().any(|s| s.kx == KeyExchange::Rsa) {
        out.push(vuln(
            "robot", "ROBOT (Bleichenbacher oracle)", Some("CVE-2017-13099"), "medium",
            Confidence::Potential,
            "RSA key exchange is offered. Whether this server leaks a padding oracle needs an \
             active Bleichenbacher test, which this scanner does not run — but the exposure only \
             exists because RSA key exchange is enabled at all.",
            format!("RSA key-exchange suites offered: {}", names(&|s| s.kx == KeyExchange::Rsa)),
            "Disable static RSA key exchange and offer only ECDHE/DHE suites. This also restores \
             forward secrecy.",
        ));
    }

    if suites.iter().any(|s| s.enc.is_cbc()) && supported.iter().any(|v| *v <= TlsVersion::Tls12) {
        out.push(vuln(
            "lucky13", "LUCKY13 / padding oracle family", Some("CVE-2013-0169"), "low",
            Confidence::Potential,
            "CBC suites are offered on TLS 1.2 or below. The MAC-then-encrypt construction has \
             produced a decade of timing and padding oracles (LUCKY13, Zombie POODLE, \
             GOLDENDOODLE); confirming this instance needs a timing test.",
            format!("CBC suites offered: {}", names(&|s| s.enc.is_cbc())),
            "Offer only AEAD suites (AES-GCM, ChaCha20-Poly1305), which have no padding to attack.",
        ));
    }

    if suites.iter().any(|s| s.kx == KeyExchange::Anonymous) {
        out.push(vuln(
            "anonymous_kx", "Anonymous key exchange", None, "critical", Confidence::Confirmed,
            "Anonymous suites are offered. They authenticate nobody, so any man in the middle can \
             terminate the connection transparently.",
            format!("anonymous suites offered: {}", names(&|s| s.kx == KeyExchange::Anonymous)),
            "Remove every aNULL suite.",
        ));
    }

    if suites.iter().any(|s| s.enc == Encryption::Null) {
        out.push(vuln(
            "null_cipher", "NULL encryption offered", None, "critical", Confidence::Confirmed,
            "Suites with no encryption at all are offered; records would travel in cleartext.",
            format!("NULL suites offered: {}", names(&|s| s.enc == Encryption::Null)),
            "Remove every eNULL suite.",
        ));
    }

    // A revoked certificate is a TLS failure, not a certificate nicety.
    if chain.trust == TrustStatus::Revoked {
        out.push(vuln(
            "revoked_certificate", "Revoked certificate", None, "critical", Confidence::Confirmed,
            "The certificate has been revoked by its issuer. Clients that check revocation will \
             refuse the connection outright.",
            chain.trust_detail.clone().unwrap_or_default(),
            "Install a newly issued certificate.",
        ));
    }

    out
}

#[allow(clippy::too_many_arguments)]
fn compute_grade(
    supported: &[TlsVersion],
    ciphers: &[CipherReport],
    features: &TlsFeatures,
    chain: &ChainAnalysis,
    certificate: Option<&ParsedCertificate>,
    vulnerabilities: &[TlsVulnerability],
    min_dh_bits: Option<u32>,
) -> TlsGrade {
    let mut caps = Vec::new();
    let mut warnings = Vec::new();

    if supported.is_empty() {
        return TlsGrade {
            grade: "F".to_string(),
            score: 0,
            protocol_score: 0,
            key_exchange_score: 0,
            cipher_score: 0,
            caps: vec!["No TLS protocol version could be negotiated".to_string()],
            warnings,
        };
    }

    let suites = suites_of(ciphers);
    let protocol = protocol_score(supported);

    // Effective key-exchange strength: the weakest of the certificate key and any
    // ephemeral parameter, all expressed in equivalent finite-field bits.
    let cert_bits = certificate
        .and_then(|c| c.public_key_bits.map(|bits| (c.public_key_type.clone(), bits)))
        .map(|(kind, bits)| match kind.as_deref() {
            Some("ecdsa") | Some("ed25519") | Some("ed448") => ecc_equivalent_dh_bits(bits),
            _ => bits,
        })
        .unwrap_or(2048);
    let curve_bits = ciphers
        .iter()
        .filter_map(|c| c.curve.as_deref())
        .filter_map(|name| match name {
            "x25519" => Some(253),
            "x448" => Some(448),
            "secp256r1" => Some(256),
            "secp384r1" => Some(384),
            "secp521r1" => Some(521),
            _ => None,
        })
        .map(ecc_equivalent_dh_bits)
        .min();
    let effective_bits = [Some(cert_bits), min_dh_bits, curve_bits]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(cert_bits);

    let anonymous = suites.iter().any(|s| s.kx == KeyExchange::Anonymous);
    let export = suites.iter().any(|s| s.kx == KeyExchange::Export);
    let key_exchange = key_exchange_score(effective_bits, anonymous, export);

    let bits: Vec<u16> = suites.iter().map(|s| s.bits).collect();
    let cipher = cipher_score(&bits);

    let score = ((protocol as f64) * 0.30 + (key_exchange as f64) * 0.30 + (cipher as f64) * 0.40)
        .round() as u32;
    let mut grade = letter_for_score(score).to_string();

    // ---- Certificate problems outrank the numeric score entirely ----------
    // SSL Labs uses M for a name mismatch and T for any other trust failure, and
    // neither is a point on the A–F scale.
    match &chain.trust {
        TrustStatus::Trusted => {}
        TrustStatus::NameMismatch => {
            caps.push("Certificate does not match the hostname".to_string());
            return TlsGrade {
                grade: "M".to_string(),
                score,
                protocol_score: protocol,
                key_exchange_score: key_exchange,
                cipher_score: cipher,
                caps,
                warnings,
            };
        }
        TrustStatus::Unknown => {
            warnings.push("Certificate trust could not be evaluated".to_string());
        }
        other => {
            caps.push(format!("Certificate is {}", other.label()));
            return TlsGrade {
                grade: "T".to_string(),
                score,
                protocol_score: protocol,
                key_exchange_score: key_exchange,
                cipher_score: cipher,
                caps,
                warnings,
            };
        }
    }
    if chain.trust.is_trusted() && !chain.hostname_matches {
        caps.push("Certificate does not cover the requested hostname".to_string());
        return TlsGrade {
            grade: "M".to_string(),
            score,
            protocol_score: protocol,
            key_exchange_score: key_exchange,
            cipher_score: cipher,
            caps,
            warnings,
        };
    }

    // ---- Automatic F ------------------------------------------------------
    for vulnerability in vulnerabilities {
        if vulnerability.confidence == Confidence::Confirmed
            && matches!(
                vulnerability.id.as_str(),
                "drown" | "heartbleed" | "crime" | "freak" | "logjam" | "anonymous_kx" | "null_cipher"
            )
        {
            cap_grade(
                &mut grade,
                "F",
                &mut caps,
                &format!("Vulnerable to {}", vulnerability.name),
            );
        }
    }
    if supported.iter().max() == Some(&TlsVersion::Ssl3) {
        cap_grade(&mut grade, "F", &mut caps, "SSLv3 is the best protocol offered");
    }

    // ---- Cap to C ---------------------------------------------------------
    if supported.contains(&TlsVersion::Ssl3) {
        cap_grade(&mut grade, "C", &mut caps, "SSLv3 is supported (POODLE)");
    }
    if !supported.contains(&TlsVersion::Tls12) && !supported.contains(&TlsVersion::Tls13) {
        cap_grade(&mut grade, "C", &mut caps, "TLS 1.2 is not supported");
    }
    let modern_only = supported
        .iter()
        .all(|v| *v >= TlsVersion::Tls11);
    if modern_only && suites.iter().any(|s| s.enc == Encryption::Rc4) {
        cap_grade(&mut grade, "C", &mut caps, "RC4 is offered on TLS 1.1 or better");
    }
    if modern_only && suites.iter().any(|s| s.enc == Encryption::TripleDes) {
        cap_grade(&mut grade, "C", &mut caps, "3DES is offered on TLS 1.1 or better");
    }

    // ---- Cap to B ---------------------------------------------------------
    if supported.contains(&TlsVersion::Tls10) || supported.contains(&TlsVersion::Tls11) {
        cap_grade(&mut grade, "B", &mut caps, "TLS 1.0 or TLS 1.1 is still enabled");
    }
    if suites.iter().any(|s| s.enc == Encryption::Rc4) {
        cap_grade(&mut grade, "B", &mut caps, "RC4 is offered");
    }
    if min_dh_bits.is_some_and(|b| b < 2048) {
        cap_grade(&mut grade, "B", &mut caps, "Diffie-Hellman group is below 2048 bits");
    }
    if chain.chain_incomplete {
        cap_grade(&mut grade, "B", &mut caps, "Certificate chain is incomplete");
    }
    if !features.forward_secrecy_only && !ciphers.is_empty() {
        cap_grade(&mut grade, "B", &mut caps, "Some suites do not provide forward secrecy");
    }
    if !features.aead_only && !ciphers.is_empty() {
        cap_grade(&mut grade, "B", &mut caps, "Non-AEAD cipher suites are offered");
    }

    // ---- Warnings: enough to lose the '+' and take an A down to A- ---------
    if !supported.contains(&TlsVersion::Tls13) {
        warnings.push("TLS 1.3 is not supported".to_string());
    }
    if let Some(cert) = certificate {
        if cert_analysis::is_weak_signature_algorithm(&cert.signature_algorithm) {
            cap_grade(
                &mut grade,
                "T",
                &mut caps,
                "Certificate uses a deprecated signature algorithm",
            );
        }
        if cert.days_until_expiry < 0 {
            cap_grade(&mut grade, "T", &mut caps, "Certificate has expired");
        }
        if cert.validity_days > MAX_CERTIFICATE_LIFETIME_DAYS {
            warnings.push(format!(
                "Certificate lifetime is {} days, above the {}-day CA/Browser Forum maximum",
                cert.validity_days, MAX_CERTIFICATE_LIFETIME_DAYS
            ));
        }
        if cert.sct_count == 0 {
            warnings.push("No embedded Certificate Transparency SCTs".to_string());
        }
    }
    if features.ocsp_stapling == Some(false) {
        warnings.push("OCSP stapling is not enabled".to_string());
    }
    if !features.server_cipher_preference && ciphers.len() > 1 {
        warnings.push("Server does not enforce its own cipher preference order".to_string());
    }

    // SSL Labs awards A+ only for a clean A with a six-month HSTS policy. HSTS is
    // an HTTP header, so the TLS scan can reach A but never A+ on its own; the
    // HTTP scan is what supplies the missing half.
    if grade == "A" && !warnings.is_empty() {
        grade = "A-".to_string();
    }

    TlsGrade {
        grade,
        score,
        protocol_score: protocol,
        key_exchange_score: key_exchange,
        cipher_score: cipher,
        caps,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// Every finding type this scanner can emit. See `dns_scan` for why this exists.
pub const EMITTED_FINDING_TYPES: &[&str] = &[
    "weak_tls_version",
    "weak_cipher_suite",
    "no_forward_secrecy",
    "tls_vulnerability",
    "tls_misconfiguration",
    "expired_certificate",
    "certificate_expiring_soon",
    "certificate_not_yet_valid",
    "self_signed_certificate",
    "certificate_untrusted",
    "certificate_hostname_mismatch",
    "certificate_chain_incomplete",
    "certificate_missing_san",
    "certificate_lifetime_excessive",
    "certificate_transparency_missing",
    "weak_signature_algorithm",
    "weak_key_strength",
    "missing_ocsp_stapling",
];

fn tls_finding(
    finding_type: &str,
    severity: FindingSeverity,
    title: impl Into<String>,
    description: String,
    remediation: impl Into<String>,
    data: serde_json::Value,
) -> ScanFinding {
    ScanFinding::new(finding_type, severity, title, description, remediation, data)
}

fn severity_from_label(label: &str) -> FindingSeverity {
    match label {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Info,
    }
}

/// Turn the assessment into findings. Pure over the result, so every rule here
/// is unit-testable without opening a socket.
pub fn build_findings(result: &TlsScanResult) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    if !result.reachable() {
        return findings;
    }
    let endpoint = format!("{}:{}", result.host, result.port);
    let source = json!({
        "host": result.host,
        "port": result.port,
        "source_url": result.ssl_labs_url,
        "source_name": result.ssl_labs_url.as_ref().map(|_| "SSL Labs"),
    });

    // ---- Protocol versions -------------------------------------------------
    let deprecated: Vec<&ProtocolSupport> = result
        .protocols
        .iter()
        .filter(|p| p.supported && p.deprecated)
        .collect();
    if !deprecated.is_empty() {
        let names: Vec<&str> = deprecated.iter().map(|p| p.version.as_str()).collect();
        // SSLv2/SSLv3 are broken outright; TLS 1.0/1.1 are deprecated by RFC 8996
        // and out of PCI DSS compliance, which is a different order of problem.
        let broken = names.iter().any(|n| n.starts_with("SSL"));
        findings.push(tls_finding(
            "weak_tls_version",
            if broken { FindingSeverity::High } else { FindingSeverity::Medium },
            format!("Deprecated TLS Protocol Enabled: {}", names.join(", ")),
            format!(
                "{} still accepts {}. {} Any client that can be induced to downgrade — by an \
                 attacker breaking the first handshake — negotiates it.",
                endpoint,
                names.join(" and "),
                if broken {
                    "SSL 2.0 and 3.0 are cryptographically broken and have been for a decade."
                } else {
                    "RFC 8996 deprecates TLS 1.0 and 1.1 outright, and PCI DSS has required their \
                     removal since 2018."
                }
            ),
            "Disable every protocol below TLS 1.2 and enable TLS 1.3.",
            json!({
                "host": result.host,
                "port": result.port,
                "deprecated_protocols": names,
                "supported_protocols": result.supported_protocols,
                "source_url": result.ssl_labs_url,
                "source_name": "SSL Labs",
            }),
        ));
    }

    // ---- Cipher suites -----------------------------------------------------
    let insecure: Vec<&CipherReport> = result
        .ciphers
        .iter()
        .filter(|c| c.strength == "insecure")
        .collect();
    let weak: Vec<&CipherReport> = result
        .ciphers
        .iter()
        .filter(|c| c.strength == "weak")
        .collect();
    if !insecure.is_empty() || !weak.is_empty() {
        let all: Vec<&str> = insecure
            .iter()
            .chain(weak.iter())
            .map(|c| c.name.as_str())
            .collect();
        findings.push(tls_finding(
            "weak_cipher_suite",
            if insecure.is_empty() { FindingSeverity::Medium } else { FindingSeverity::High },
            format!("Weak Cipher Suites Offered ({})", all.len()),
            format!(
                "{} accepts {} cipher suite(s) that should no longer be negotiated: {}. {}",
                endpoint,
                all.len(),
                all.join(", "),
                if insecure.is_empty() {
                    "These are below current strength recommendations or use constructions with \
                     known attacks."
                } else {
                    "Some offer no encryption, no authentication, or export-grade key sizes that \
                     are breakable on commodity hardware."
                }
            ),
            "Restrict the cipher list to AEAD suites with forward secrecy (ECDHE with AES-GCM or \
             ChaCha20-Poly1305) and remove everything else.",
            json!({
                "host": result.host,
                "port": result.port,
                "insecure": insecure.iter().map(|c| &c.name).collect::<Vec<_>>(),
                "weak": weak.iter().map(|c| &c.name).collect::<Vec<_>>(),
                "source_url": result.ssl_labs_url,
                "source_name": "SSL Labs",
            }),
        ));
    }

    if !result.ciphers.is_empty() && !result.features.forward_secrecy_only {
        let without: Vec<&str> = result
            .ciphers
            .iter()
            .filter(|c| !c.forward_secrecy)
            .map(|c| c.name.as_str())
            .collect();
        findings.push(tls_finding(
            "no_forward_secrecy",
            FindingSeverity::Low,
            "Cipher Suites Without Forward Secrecy",
            format!(
                "{} offers {} suite(s) that do not provide forward secrecy: {}. Traffic \
                 negotiated with them can be decrypted retroactively by anyone who later obtains \
                 the server's private key — from a backup, a subpoena, or a future compromise.",
                endpoint,
                without.len(),
                without.join(", ")
            ),
            "Offer only ECDHE or DHE key exchange, and remove static RSA suites.",
            json!({
                "host": result.host,
                "port": result.port,
                "suites_without_forward_secrecy": without,
            }),
        ));
    }

    // ---- Vulnerabilities ---------------------------------------------------
    for vulnerability in &result.vulnerabilities {
        // A configuration-implied exposure is filed a step below a confirmed one,
        // and says so in its own text. Reporting "vulnerable to ROBOT" off the
        // mere presence of RSA key exchange is how a scanner loses its reader.
        let severity = match vulnerability.confidence {
            Confidence::Confirmed => severity_from_label(&vulnerability.severity),
            Confidence::Potential => match severity_from_label(&vulnerability.severity) {
                FindingSeverity::Critical => FindingSeverity::High,
                FindingSeverity::High => FindingSeverity::Medium,
                FindingSeverity::Medium => FindingSeverity::Low,
                other => other,
            },
        };
        let qualifier = match vulnerability.confidence {
            Confidence::Confirmed => "",
            Confidence::Potential => " (potential — requires active verification)",
        };
        findings.push(tls_finding(
            "tls_vulnerability",
            severity,
            format!("{}{}", vulnerability.name, qualifier),
            format!(
                "{} — {} Evidence: {}.",
                endpoint, vulnerability.description, vulnerability.evidence
            ),
            vulnerability.remediation.clone(),
            json!({
                "host": result.host,
                "port": result.port,
                "vulnerability": vulnerability.id,
                "cve": vulnerability.cve,
                "confidence": vulnerability.confidence,
                "evidence": vulnerability.evidence,
                "source_url": result.ssl_labs_url,
                "source_name": "SSL Labs",
            }),
        ));
    }

    // ---- Certificate -------------------------------------------------------
    if let Some(cert) = &result.certificate {
        let cert_data = |extra: serde_json::Value| -> serde_json::Value {
            let mut data = source.clone();
            data["subject"] = json!(cert.subject);
            data["issuer"] = json!(cert.issuer);
            data["not_after"] = json!(cert.not_after);
            data["sha256_fingerprint"] = json!(cert.sha256_fingerprint);
            if let Some(url) = &result.crt_sh_url {
                data["crt_sh_url"] = json!(url);
            }
            if let serde_json::Value::Object(extra) = extra {
                for (key, value) in extra {
                    data[key] = value;
                }
            }
            data
        };

        if cert.days_until_expiry < 0 {
            findings.push(tls_finding(
                "expired_certificate",
                FindingSeverity::Critical,
                "Expired TLS Certificate",
                format!(
                    "The certificate for {} expired {} day(s) ago, on {}. Every browser refuses \
                     the connection with an interstitial the user must click through.",
                    endpoint, -cert.days_until_expiry, cert.not_after
                ),
                "Renew the certificate now, and automate renewal so this cannot recur.",
                cert_data(json!({ "days_expired": -cert.days_until_expiry })),
            ));
        } else if cert.days_until_expiry < 30 {
            findings.push(tls_finding(
                "certificate_expiring_soon",
                FindingSeverity::High,
                "Certificate Expiring Within 30 Days",
                format!(
                    "The certificate for {} expires in {} day(s), on {}.",
                    endpoint, cert.days_until_expiry, cert.not_after
                ),
                "Renew the certificate and verify automated renewal is working.",
                cert_data(json!({ "days_remaining": cert.days_until_expiry })),
            ));
        } else if cert.days_until_expiry < 90 {
            findings.push(tls_finding(
                "certificate_expiring_soon",
                FindingSeverity::Low,
                "Certificate Expiring Within 90 Days",
                format!(
                    "The certificate for {} expires in {} day(s), on {}.",
                    endpoint, cert.days_until_expiry, cert.not_after
                ),
                "Confirm automated renewal is configured.",
                cert_data(json!({ "days_remaining": cert.days_until_expiry })),
            ));
        }

        if cert.not_before > chrono::Utc::now().to_rfc3339() {
            findings.push(tls_finding(
                "certificate_not_yet_valid",
                FindingSeverity::Medium,
                "Certificate Not Yet Valid",
                format!(
                    "The certificate for {} does not become valid until {}. Clients reject it \
                     until then, so this is usually a clock skew or a premature deployment.",
                    endpoint, cert.not_before
                ),
                "Check the server clock, or wait for the validity period to begin.",
                cert_data(json!({ "not_before": cert.not_before })),
            ));
        }

        match &result.chain.trust {
            TrustStatus::Trusted => {}
            TrustStatus::SelfSigned => findings.push(tls_finding(
                "self_signed_certificate",
                FindingSeverity::Medium,
                "Self-Signed Certificate",
                format!(
                    "The certificate for {} is self-signed, so no browser trusts it. Users are \
                     shown a warning, and any attacker on the path can substitute their own \
                     self-signed certificate without the substitution being detectable.",
                    endpoint
                ),
                "Install a certificate from a publicly trusted CA.",
                cert_data(json!({ "trust": "self_signed" })),
            )),
            TrustStatus::Unknown => {}
            other => findings.push(tls_finding(
                "certificate_untrusted",
                FindingSeverity::High,
                format!("Untrusted Certificate ({})", other.label()),
                format!(
                    "The certificate chain for {} does not validate against the Mozilla root \
                     store: {}. Browsers will refuse or warn on this connection.{}",
                    endpoint,
                    result.chain.trust_detail.as_deref().unwrap_or(other.label()),
                    if result.chain.chain_incomplete {
                        " The server is not sending the intermediate certificates, which is the \
                         usual cause — it often works in a desktop browser that has cached them \
                         and fails everywhere else."
                    } else {
                        ""
                    }
                ),
                "Install the complete certificate chain, including every intermediate, and \
                 confirm the issuing CA is publicly trusted.",
                cert_data(json!({
                    "trust": other,
                    "detail": result.chain.trust_detail,
                    "chain_incomplete": result.chain.chain_incomplete,
                })),
            )),
        }

        if !result.chain.hostname_matches && result.chain.trust.is_trusted() {
            findings.push(tls_finding(
                "certificate_hostname_mismatch",
                FindingSeverity::High,
                "Certificate Hostname Mismatch",
                format!(
                    "The certificate served for {} does not cover that name. It is issued for \
                     {}. Browsers reject the connection.",
                    endpoint,
                    if cert.san_domains.is_empty() {
                        cert.common_name.clone().unwrap_or_else(|| "an unknown name".into())
                    } else {
                        cert.san_domains.join(", ")
                    }
                ),
                "Reissue the certificate with the correct hostname in its Subject Alternative \
                 Name list.",
                cert_data(json!({
                    "requested_host": result.host,
                    "san_domains": cert.san_domains,
                    "common_name": cert.common_name,
                })),
            ));
        }

        if result.chain.chain_incomplete && result.chain.trust.is_trusted() {
            findings.push(tls_finding(
                "certificate_chain_incomplete",
                FindingSeverity::Medium,
                "Incomplete Certificate Chain",
                format!(
                    "{} sends only {} certificate(s) and omits at least one intermediate. \
                     Desktop browsers often paper over this from cache; mobile clients, API \
                     clients and older stacks fail outright.",
                    endpoint,
                    result.chain.chain.len()
                ),
                "Configure the server to send the full chain, leaf first, up to but excluding \
                 the root.",
                cert_data(json!({ "chain_length": result.chain.chain.len() })),
            ));
        }

        if cert.san_domains.is_empty() && cert.san_ips.is_empty() {
            findings.push(tls_finding(
                "certificate_missing_san",
                FindingSeverity::Low,
                "Certificate Has No Subject Alternative Names",
                format!(
                    "The certificate for {} carries no SAN entries. Every current browser \
                     ignores the Common Name entirely (RFC 6125), so the certificate matches no \
                     hostname at all.",
                    endpoint
                ),
                "Reissue with the hostnames listed in the Subject Alternative Name extension.",
                cert_data(json!({})),
            ));
        }

        if cert_analysis::is_weak_signature_algorithm(&cert.signature_algorithm) {
            findings.push(tls_finding(
                "weak_signature_algorithm",
                FindingSeverity::High,
                "Certificate Uses a Deprecated Signature Algorithm",
                format!(
                    "The certificate for {} is signed with {}. SHA-1 collisions are practical \
                     and MD5 has been trivially forgeable for years; browsers have rejected both \
                     since 2017.",
                    endpoint, cert.signature_algorithm
                ),
                "Reissue the certificate with a SHA-256 or stronger signature.",
                cert_data(json!({ "signature_algorithm": cert.signature_algorithm })),
            ));
        }

        if let Some(bits) = cert.public_key_bits {
            let weak = match cert.public_key_type.as_deref() {
                Some("rsa") | Some("dsa") => bits < 2048,
                Some("ecdsa") => bits < 256,
                _ => false,
            };
            if weak {
                findings.push(tls_finding(
                    "weak_key_strength",
                    FindingSeverity::High,
                    "Certificate Key Below Minimum Strength",
                    format!(
                        "The certificate for {} uses a {}-bit {} key, below the CA/Browser Forum \
                         minimum (2048-bit RSA, 256-bit ECDSA).",
                        endpoint,
                        bits,
                        cert.public_key_type.as_deref().unwrap_or("unknown")
                    ),
                    "Reissue with a 2048-bit or larger RSA key, or a P-256 or larger EC key.",
                    cert_data(json!({ "key_bits": bits, "key_type": cert.public_key_type })),
                ));
            }
        }

        if cert.validity_days > MAX_CERTIFICATE_LIFETIME_DAYS {
            findings.push(tls_finding(
                "certificate_lifetime_excessive",
                FindingSeverity::Low,
                "Certificate Lifetime Exceeds the Browser Maximum",
                format!(
                    "The certificate for {} is valid for {} days. Since September 2020 the \
                     CA/Browser Forum caps publicly trusted TLS certificates at {} days, and \
                     Safari rejects longer ones outright.",
                    endpoint, cert.validity_days, MAX_CERTIFICATE_LIFETIME_DAYS
                ),
                "Reissue with a lifetime of 398 days or less, and automate renewal.",
                cert_data(json!({ "validity_days": cert.validity_days })),
            ));
        }

        if cert.sct_count == 0 && result.chain.trust.is_trusted() {
            findings.push(tls_finding(
                "certificate_transparency_missing",
                FindingSeverity::Low,
                "Certificate Not in Certificate Transparency",
                format!(
                    "The certificate for {} carries no embedded Signed Certificate Timestamps. \
                     Chrome requires CT for publicly trusted certificates, and without it a \
                     misissuance for this domain would never appear in a CT log where you could \
                     see it.",
                    endpoint
                ),
                "Obtain the certificate from a CA that submits to Certificate Transparency logs, \
                 and monitor crt.sh for issuance you did not request.",
                cert_data(json!({ "sct_count": 0 })),
            ));
        }
    }

    // ---- Protocol features -------------------------------------------------
    // `None` means the scan could not tell (TLS 1.3 encrypts the CertificateStatus
    // message), which is not the same as "off".
    if result.features.ocsp_stapling == Some(false) {
        findings.push(tls_finding(
            "missing_ocsp_stapling",
            FindingSeverity::Info,
            "OCSP Stapling Not Enabled",
            format!(
                "{} does not staple an OCSP response. Clients that check revocation must contact \
                 the CA themselves, which leaks the browsing to the CA and adds latency — so most \
                 clients skip the check, and a revoked certificate keeps working.",
                endpoint
            ),
            "Enable OCSP stapling (`ssl_stapling on` in nginx, `SSLUseStapling on` in Apache).",
            json!({ "host": result.host, "port": result.port }),
        ));
    }

    if let Some(cert) = &result.certificate {
        if cert.must_staple && result.features.ocsp_stapling == Some(false) {
            findings.push(tls_finding(
                "tls_misconfiguration",
                FindingSeverity::High,
                "OCSP Must-Staple Set Without Stapling",
                format!(
                    "The certificate for {} carries the OCSP Must-Staple extension, but the \
                     server sends no stapled response. Clients that honour the extension — \
                     Firefox does — refuse the connection outright.",
                    endpoint
                ),
                "Enable OCSP stapling immediately, or reissue without the Must-Staple extension.",
                json!({ "host": result.host, "port": result.port, "must_staple": true }),
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher(name: &str, id: u16, version: TlsVersion) -> CipherReport {
        build_cipher_report(id, version, &KeyExchangeInfo::default())
            .tap(|c| assert_eq!(c.name, name))
    }

    trait Tap: Sized {
        fn tap(self, f: impl FnOnce(&Self)) -> Self {
            f(&self);
            self
        }
    }
    impl Tap for CipherReport {}

    fn trusted_chain() -> ChainAnalysis {
        ChainAnalysis {
            chain: vec![],
            trust: TrustStatus::Trusted,
            trust_detail: None,
            hostname_matches: true,
            chain_incomplete: false,
            chain_has_extra_certs: false,
            chain_ordered: true,
        }
    }

    fn scan_result(protocols: Vec<TlsVersion>, ciphers: Vec<CipherReport>) -> TlsScanResult {
        let features = TlsFeatures {
            forward_secrecy_only: true,
            aead_only: true,
            secure_renegotiation: true,
            ocsp_stapling: Some(true),
            server_cipher_preference: true,
            ..Default::default()
        };
        TlsScanResult {
            host: "example.com".into(),
            port: 443,
            supported_protocols: protocols.iter().map(|v| v.label().to_string()).collect(),
            highest_protocol: protocols.iter().max().map(|v| v.label().to_string()),
            lowest_protocol: protocols.iter().min().map(|v| v.label().to_string()),
            protocols: protocols
                .iter()
                .map(|v| ProtocolSupport {
                    version: v.label().to_string(),
                    supported: true,
                    deprecated: v.is_deprecated(),
                    preferred_cipher: None,
                    cipher_count: 0,
                })
                .collect(),
            weak_ciphers: vec![],
            ciphers,
            certificate: None,
            chain: trusted_chain(),
            features,
            vulnerabilities: vec![],
            grade: TlsGrade {
                grade: "A".into(),
                score: 90,
                protocol_score: 100,
                key_exchange_score: 90,
                cipher_score: 90,
                caps: vec![],
                warnings: vec![],
            },
            ssl_labs_url: Some("https://ssllabs".into()),
            crt_sh_url: Some("https://crt.sh".into()),
            errors: vec![],
            scan_duration_ms: 0,
        }
    }

    fn finding_types(findings: &[ScanFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.finding_type.as_str()).collect()
    }

    #[test]
    fn an_unreachable_endpoint_produces_no_findings() {
        let result = scan_result(vec![], vec![]);
        assert!(!result.reachable());
        assert!(build_findings(&result).is_empty());
    }

    #[test]
    fn a_modern_endpoint_produces_no_findings() {
        let result = scan_result(
            vec![TlsVersion::Tls12, TlsVersion::Tls13],
            vec![cipher("TLS_AES_256_GCM_SHA384", 0x1302, TlsVersion::Tls13)],
        );
        let findings = build_findings(&result);
        assert!(findings.is_empty(), "unexpected: {:?}", finding_types(&findings));
    }

    #[test]
    fn every_emitted_type_is_declared() {
        let mut result = scan_result(
            vec![TlsVersion::Ssl3, TlsVersion::Tls10, TlsVersion::Tls12],
            vec![
                cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0003, TlsVersion::Tls10),
                cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000A, TlsVersion::Tls10),
            ],
        );
        result.features.forward_secrecy_only = false;
        result.features.ocsp_stapling = Some(false);
        let mut cert = expired_certificate();
        cert.must_staple = true;
        result.certificate = Some(cert);
        result.chain.trust = TrustStatus::UnknownIssuer;
        result.vulnerabilities = vec![
            vuln("drown", "DROWN", None, "critical", Confidence::Confirmed, "d", "e".into(), "r"),
            vuln("robot", "ROBOT", None, "medium", Confidence::Potential, "d", "e".into(), "r"),
        ];

        let findings = build_findings(&result);
        assert!(findings.len() >= 10, "expected broad coverage, got {}", findings.len());
        for finding in &findings {
            assert!(
                EMITTED_FINDING_TYPES.contains(&finding.finding_type.as_str()),
                "undeclared finding type {}",
                finding.finding_type
            );
        }
    }

    #[test]
    fn legacy_protocols_are_reported_with_severity_by_era() {
        // TLS 1.0/1.1 are deprecated; SSLv3 is broken. Those are different findings.
        let result = scan_result(
            vec![TlsVersion::Tls10, TlsVersion::Tls12],
            vec![cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030, TlsVersion::Tls12)],
        );
        let findings = build_findings(&result);
        let protocol = findings.iter().find(|f| f.finding_type == "weak_tls_version").unwrap();
        assert_eq!(protocol.severity, FindingSeverity::Medium);
        assert!(protocol.description.contains("RFC 8996"));

        let result = scan_result(
            vec![TlsVersion::Ssl3, TlsVersion::Tls12],
            vec![cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030, TlsVersion::Tls12)],
        );
        let findings = build_findings(&result);
        let protocol = findings.iter().find(|f| f.finding_type == "weak_tls_version").unwrap();
        assert_eq!(protocol.severity, FindingSeverity::High);
    }

    #[test]
    fn insecure_ciphers_outrank_merely_weak_ones() {
        let result = scan_result(
            vec![TlsVersion::Tls12],
            vec![cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000A, TlsVersion::Tls12)],
        );
        let findings = build_findings(&result);
        let ciphers = findings.iter().find(|f| f.finding_type == "weak_cipher_suite").unwrap();
        assert_eq!(ciphers.severity, FindingSeverity::Medium);

        let result = scan_result(
            vec![TlsVersion::Tls12],
            vec![cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0003, TlsVersion::Tls12)],
        );
        let findings = build_findings(&result);
        let ciphers = findings.iter().find(|f| f.finding_type == "weak_cipher_suite").unwrap();
        assert_eq!(ciphers.severity, FindingSeverity::High);
    }

    #[test]
    fn a_potential_vulnerability_is_filed_a_step_below_a_confirmed_one() {
        let mut result = scan_result(
            vec![TlsVersion::Tls12],
            vec![cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030, TlsVersion::Tls12)],
        );
        result.vulnerabilities = vec![
            vuln("drown", "DROWN", None, "critical", Confidence::Confirmed, "d", "e".into(), "r"),
            vuln("robot", "ROBOT", None, "critical", Confidence::Potential, "d", "e".into(), "r"),
        ];
        let findings = build_findings(&result);
        let confirmed = findings.iter().find(|f| f.title == "DROWN").unwrap();
        assert_eq!(confirmed.severity, FindingSeverity::Critical);

        let potential = findings
            .iter()
            .find(|f| f.title.starts_with("ROBOT"))
            .unwrap();
        assert_eq!(potential.severity, FindingSeverity::High, "one step down");
        assert!(potential.title.contains("potential"));
    }

    #[test]
    fn certificate_problems_map_to_their_own_finding_types() {
        let mut result = scan_result(
            vec![TlsVersion::Tls13],
            vec![cipher("TLS_AES_256_GCM_SHA384", 0x1302, TlsVersion::Tls13)],
        );
        result.certificate = Some(expired_certificate());
        result.chain.chain = vec![expired_certificate()];
        let findings = build_findings(&result);
        let types = finding_types(&findings);
        assert!(types.contains(&"expired_certificate"));
        assert!(types.contains(&"weak_signature_algorithm"));
        assert!(types.contains(&"weak_key_strength"));
        assert!(types.contains(&"certificate_missing_san"));
        assert!(types.contains(&"certificate_lifetime_excessive"));
        assert!(types.contains(&"certificate_transparency_missing"));
        // Not expiring soon *and* expired would be contradictory.
        assert!(!types.contains(&"certificate_expiring_soon"));
    }

    #[test]
    fn must_staple_without_stapling_is_a_hard_failure() {
        let mut result = scan_result(
            vec![TlsVersion::Tls13],
            vec![cipher("TLS_AES_256_GCM_SHA384", 0x1302, TlsVersion::Tls13)],
        );
        let mut cert = healthy_certificate();
        cert.must_staple = true;
        result.certificate = Some(cert);
        result.features.ocsp_stapling = Some(false);
        let findings = build_findings(&result);
        let must_staple = findings
            .iter()
            .find(|f| f.finding_type == "tls_misconfiguration")
            .unwrap();
        assert_eq!(must_staple.severity, FindingSeverity::High);
        assert!(must_staple.description.contains("refuse the connection"));
    }

    #[test]
    fn an_untrusted_chain_is_distinguished_from_a_self_signed_one() {
        let mut result = scan_result(
            vec![TlsVersion::Tls13],
            vec![cipher("TLS_AES_256_GCM_SHA384", 0x1302, TlsVersion::Tls13)],
        );
        result.certificate = Some(healthy_certificate());
        result.chain.trust = TrustStatus::SelfSigned;
        let findings = build_findings(&result);
        assert!(finding_types(&findings).contains(&"self_signed_certificate"));

        result.chain.trust = TrustStatus::UnknownIssuer;
        result.chain.chain_incomplete = true;
        let findings = build_findings(&result);
        let untrusted = findings
            .iter()
            .find(|f| f.finding_type == "certificate_untrusted")
            .unwrap();
        assert_eq!(untrusted.severity, FindingSeverity::High);
        assert!(untrusted.description.contains("intermediate"));
    }

    fn healthy_certificate() -> ParsedCertificate {
        ParsedCertificate {
            subject: "CN=example.com".into(),
            issuer: "CN=Real CA".into(),
            common_name: Some("example.com".into()),
            organization: None,
            issuer_common_name: Some("Real CA".into()),
            issuer_organization: None,
            san_domains: vec!["example.com".into()],
            san_ips: vec![],
            not_before: "2024-01-01T00:00:00+00:00".into(),
            not_after: "2099-01-01T00:00:00+00:00".into(),
            validity_days: 90,
            days_until_expiry: 300,
            serial_number: "01".into(),
            serial_bits: 64,
            signature_algorithm: "sha256WithRSAEncryption".into(),
            public_key_type: Some("rsa".into()),
            public_key_bits: Some(2048),
            is_ca: false,
            is_self_signed: false,
            is_wildcard: false,
            key_usage: vec![],
            extended_key_usage: vec![],
            ocsp_urls: vec![],
            ca_issuer_urls: vec![],
            crl_urls: vec![],
            must_staple: false,
            sct_count: 2,
            sha256_fingerprint: "aa:bb".into(),
        }
    }

    fn expired_certificate() -> ParsedCertificate {
        ParsedCertificate {
            san_domains: vec![],
            days_until_expiry: -5,
            validity_days: 800,
            signature_algorithm: "sha1WithRSAEncryption".into(),
            public_key_bits: Some(1024),
            sct_count: 0,
            not_after: "2020-01-01T00:00:00+00:00".into(),
            ..healthy_certificate()
        }
    }

    #[test]
    fn protocol_score_averages_best_and_worst() {
        // TLS 1.2 + 1.3 only: both rate 100.
        assert_eq!(protocol_score(&[TlsVersion::Tls12, TlsVersion::Tls13]), 100);
        // Adding TLS 1.0 (90) drags the average down.
        assert_eq!(
            protocol_score(&[TlsVersion::Tls10, TlsVersion::Tls12]),
            95
        );
        // SSLv2 rates 0, so the average halves.
        assert_eq!(protocol_score(&[TlsVersion::Ssl2, TlsVersion::Tls12]), 50);
        assert_eq!(protocol_score(&[]), 0);
    }

    #[test]
    fn key_exchange_score_follows_the_rating_guide_bands() {
        assert_eq!(key_exchange_score(4096, false, false), 100);
        assert_eq!(key_exchange_score(2048, false, false), 90);
        assert_eq!(key_exchange_score(1024, false, false), 80);
        assert_eq!(key_exchange_score(512, false, false), 40);
        assert_eq!(key_exchange_score(256, false, false), 20);
        assert_eq!(key_exchange_score(4096, false, true), 40, "export caps at 40");
        assert_eq!(key_exchange_score(4096, true, false), 0, "anon scores zero");
    }

    #[test]
    fn cipher_score_averages_the_bands() {
        assert_eq!(cipher_score(&[256, 256]), 100);
        assert_eq!(cipher_score(&[128, 256]), 90);
        assert_eq!(cipher_score(&[112, 256]), 60);
        assert_eq!(cipher_score(&[0, 256]), 50);
        assert_eq!(cipher_score(&[]), 0);
    }

    #[test]
    fn letter_thresholds_match_the_published_table() {
        assert_eq!(letter_for_score(100), "A");
        assert_eq!(letter_for_score(80), "A");
        assert_eq!(letter_for_score(79), "B");
        assert_eq!(letter_for_score(65), "B");
        assert_eq!(letter_for_score(64), "C");
        assert_eq!(letter_for_score(50), "C");
        assert_eq!(letter_for_score(49), "D");
        assert_eq!(letter_for_score(35), "D");
        assert_eq!(letter_for_score(34), "E");
        assert_eq!(letter_for_score(20), "E");
        assert_eq!(letter_for_score(19), "F");
    }

    #[test]
    fn a_modern_endpoint_grades_a() {
        let ciphers = vec![
            cipher("TLS_AES_256_GCM_SHA384", 0x1302, TlsVersion::Tls13),
            cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030, TlsVersion::Tls12),
        ];
        let features = TlsFeatures {
            forward_secrecy_only: true,
            aead_only: true,
            server_cipher_preference: true,
            ocsp_stapling: Some(true),
            secure_renegotiation: true,
            ..Default::default()
        };
        let grade = compute_grade(
            &[TlsVersion::Tls12, TlsVersion::Tls13],
            &ciphers,
            &features,
            &trusted_chain(),
            None,
            &[],
            None,
        );
        assert_eq!(grade.protocol_score, 100);
        assert_eq!(grade.grade, "A", "caps were {:?}, warnings {:?}", grade.caps, grade.warnings);
    }

    #[test]
    fn missing_tls13_costs_the_plus_and_lands_on_a_minus() {
        let ciphers = vec![cipher(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xC030,
            TlsVersion::Tls12,
        )];
        let features = TlsFeatures {
            forward_secrecy_only: true,
            aead_only: true,
            server_cipher_preference: true,
            ocsp_stapling: Some(true),
            secure_renegotiation: true,
            ..Default::default()
        };
        let grade = compute_grade(
            &[TlsVersion::Tls12],
            &ciphers,
            &features,
            &trusted_chain(),
            None,
            &[],
            None,
        );
        assert_eq!(grade.grade, "A-");
        assert!(grade.warnings.iter().any(|w| w.contains("TLS 1.3")));
    }

    #[test]
    fn legacy_protocols_cap_the_grade_at_b() {
        let ciphers = vec![cipher(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xC030,
            TlsVersion::Tls12,
        )];
        let features = TlsFeatures {
            forward_secrecy_only: true,
            aead_only: true,
            secure_renegotiation: true,
            ..Default::default()
        };
        let grade = compute_grade(
            &[TlsVersion::Tls10, TlsVersion::Tls12],
            &ciphers,
            &features,
            &trusted_chain(),
            None,
            &[],
            None,
        );
        assert_eq!(grade.grade, "B");
        assert!(grade.caps.iter().any(|c| c.contains("TLS 1.0")));
    }

    #[test]
    fn a_confirmed_critical_vulnerability_forces_f() {
        let ciphers = vec![cipher(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xC030,
            TlsVersion::Tls12,
        )];
        let vulnerabilities = vec![vuln(
            "heartbleed", "Heartbleed", Some("CVE-2014-0160"), "critical",
            Confidence::Confirmed, "", String::new(), "",
        )];
        let grade = compute_grade(
            &[TlsVersion::Tls12, TlsVersion::Tls13],
            &ciphers,
            &TlsFeatures { forward_secrecy_only: true, aead_only: true, secure_renegotiation: true, ..Default::default() },
            &trusted_chain(),
            None,
            &vulnerabilities,
            None,
        );
        assert_eq!(grade.grade, "F");
    }

    #[test]
    fn a_potential_finding_alone_never_forces_f() {
        let ciphers = vec![cipher(
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xC030,
            TlsVersion::Tls12,
        )];
        let vulnerabilities = vec![vuln(
            "robot", "ROBOT", None, "medium", Confidence::Potential, "", String::new(), "",
        )];
        let grade = compute_grade(
            &[TlsVersion::Tls12, TlsVersion::Tls13],
            &ciphers,
            &TlsFeatures { forward_secrecy_only: true, aead_only: true, secure_renegotiation: true, server_cipher_preference: true, ocsp_stapling: Some(true), ..Default::default() },
            &trusted_chain(),
            None,
            &vulnerabilities,
            None,
        );
        assert_eq!(grade.grade, "A");
    }

    #[test]
    fn hostname_mismatch_grades_m_and_trust_failure_grades_t() {
        let ciphers = vec![cipher("TLS_AES_256_GCM_SHA384", 0x1302, TlsVersion::Tls13)];
        let features = TlsFeatures::default();

        let mut chain = trusted_chain();
        chain.hostname_matches = false;
        let grade = compute_grade(&[TlsVersion::Tls13], &ciphers, &features, &chain, None, &[], None);
        assert_eq!(grade.grade, "M");

        let mut chain = trusted_chain();
        chain.trust = TrustStatus::SelfSigned;
        let grade = compute_grade(&[TlsVersion::Tls13], &ciphers, &features, &chain, None, &[], None);
        assert_eq!(grade.grade, "T");
    }

    #[test]
    fn no_protocol_at_all_grades_f() {
        let grade = compute_grade(&[], &[], &TlsFeatures::default(), &trusted_chain(), None, &[], None);
        assert_eq!(grade.grade, "F");
        assert_eq!(grade.score, 0);
    }

    #[test]
    fn vulnerabilities_are_derived_from_the_offered_configuration() {
        let ciphers = vec![
            cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000A, TlsVersion::Tls10),
            cipher("TLS_RSA_WITH_RC4_128_SHA", 0x0005, TlsVersion::Tls10),
        ];
        let found = derive_vulnerabilities(
            &[TlsVersion::Ssl3, TlsVersion::Tls10],
            &ciphers,
            &TlsFeatures::default(),
            &trusted_chain(),
            HeartbleedVerdict::NotVulnerable,
            None,
        );
        let ids: Vec<&str> = found.iter().map(|v| v.id.as_str()).collect();
        assert!(ids.contains(&"poodle_sslv3"));
        assert!(ids.contains(&"sweet32"));
        assert!(ids.contains(&"rc4"));
        assert!(ids.contains(&"beast"));
        assert!(ids.contains(&"robot"));
        assert!(ids.contains(&"insecure_renegotiation"));
        // Not offered, so must not be reported.
        assert!(!ids.contains(&"drown"));
        assert!(!ids.contains(&"heartbleed"));
        assert!(!ids.contains(&"crime"));

        // ROBOT and LUCKY13 are inferred, never confirmed.
        for v in &found {
            if v.id == "robot" || v.id == "lucky13" || v.id == "beast" {
                assert_eq!(v.confidence, Confidence::Potential, "{} must be potential", v.id);
            }
        }
    }

    #[test]
    fn heartbleed_is_only_reported_when_actually_observed() {
        let ciphers = vec![cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC030, TlsVersion::Tls12)];
        for verdict in [
            HeartbleedVerdict::NotVulnerable,
            HeartbleedVerdict::HeartbeatDisabled,
            HeartbleedVerdict::Inconclusive,
        ] {
            let found = derive_vulnerabilities(
                &[TlsVersion::Tls12],
                &ciphers,
                &TlsFeatures { secure_renegotiation: true, ..Default::default() },
                &trusted_chain(),
                verdict,
                None,
            );
            assert!(!found.iter().any(|v| v.id == "heartbleed"), "{:?}", verdict);
        }
        let found = derive_vulnerabilities(
            &[TlsVersion::Tls12],
            &ciphers,
            &TlsFeatures { secure_renegotiation: true, ..Default::default() },
            &trusted_chain(),
            HeartbleedVerdict::Vulnerable,
            None,
        );
        assert!(found.iter().any(|v| v.id == "heartbleed"));
    }

    #[test]
    fn small_dh_groups_produce_logjam_and_large_ones_do_not() {
        let ciphers = vec![cipher("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009E, TlsVersion::Tls12)];
        let features = TlsFeatures { secure_renegotiation: true, ..Default::default() };

        let found = derive_vulnerabilities(&[TlsVersion::Tls12], &ciphers, &features, &trusted_chain(), HeartbleedVerdict::Inconclusive, Some(1024));
        assert!(found.iter().any(|v| v.id == "logjam"));

        let found = derive_vulnerabilities(&[TlsVersion::Tls12], &ciphers, &features, &trusted_chain(), HeartbleedVerdict::Inconclusive, Some(1536));
        assert!(found.iter().any(|v| v.id == "weak_dh"));
        assert!(!found.iter().any(|v| v.id == "logjam"));

        let found = derive_vulnerabilities(&[TlsVersion::Tls12], &ciphers, &features, &trusted_chain(), HeartbleedVerdict::Inconclusive, Some(4096));
        assert!(!found.iter().any(|v| v.id == "logjam" || v.id == "weak_dh"));
    }
}

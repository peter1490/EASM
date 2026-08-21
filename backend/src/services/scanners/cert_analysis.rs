//! Deep X.509 analysis of a served certificate chain.
//!
//! The pre-existing certificate code answered five questions: subject, issuer,
//! validity window, SANs, key size. Everything a CA/Browser Forum baseline
//! requirement or an SSL Labs report actually turns on — is the chain trusted,
//! is it complete and in order, is it in Certificate Transparency, does it
//! demand a stapled OCSP response, is its lifetime legal, is its serial
//! guessable — was not asked at all.
//!
//! Trust is decided by `rustls` against the Mozilla root program (`webpki-roots`),
//! the same store a browser uses, so "untrusted" here means what it means in a
//! browser rather than "our parser was unhappy".

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

/// RFC 6962: the SCT list extension embedded in a certificate by the CA.
const OID_SCT: &str = "1.3.6.1.4.1.11129.2.4.2";
/// RFC 7633: the TLS Feature extension, which carries OCSP Must-Staple.
const OID_TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";

/// CA/Browser Forum Baseline Requirements: since 1 September 2020 a publicly
/// trusted TLS certificate may not be valid for more than 398 days.
pub const MAX_CERTIFICATE_LIFETIME_DAYS: i64 = 398;

/// Why a chain failed to validate, kept apart because SSL Labs grades them
/// differently: a name mismatch is `M`, anything else is `T`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Trusted,
    /// Chains to a root nobody ships — a private CA, or a missing intermediate.
    UnknownIssuer,
    SelfSigned,
    Expired,
    NotYetValid,
    Revoked,
    /// Chains fine, but not for the name we asked for.
    NameMismatch,
    BadSignature,
    /// The chain is valid but the leaf is not marked for server authentication.
    InvalidPurpose,
    Malformed,
    /// Not checked — no chain was captured.
    Unknown,
}

impl TrustStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustStatus::Trusted)
    }

    pub fn label(&self) -> &'static str {
        match self {
            TrustStatus::Trusted => "trusted",
            TrustStatus::UnknownIssuer => "unknown issuer",
            TrustStatus::SelfSigned => "self-signed",
            TrustStatus::Expired => "expired",
            TrustStatus::NotYetValid => "not yet valid",
            TrustStatus::Revoked => "revoked",
            TrustStatus::NameMismatch => "hostname mismatch",
            TrustStatus::BadSignature => "invalid signature",
            TrustStatus::InvalidPurpose => "not valid for server authentication",
            TrustStatus::Malformed => "malformed",
            TrustStatus::Unknown => "not evaluated",
        }
    }
}

/// One certificate in the served chain, parsed in full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub issuer_common_name: Option<String>,
    pub issuer_organization: Option<String>,
    pub san_domains: Vec<String>,
    pub san_ips: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub validity_days: i64,
    pub days_until_expiry: i64,
    pub serial_number: String,
    /// Entropy of the serial. The CA/B Forum requires at least 64 bits of CSPRNG
    /// output; less than that is what made the SHA-1 collision attacks practical.
    pub serial_bits: u32,
    pub signature_algorithm: String,
    pub public_key_type: Option<String>,
    pub public_key_bits: Option<u32>,
    pub is_ca: bool,
    pub is_self_signed: bool,
    pub is_wildcard: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub ca_issuer_urls: Vec<String>,
    pub crl_urls: Vec<String>,
    /// RFC 7633 OCSP Must-Staple: the server MUST present a stapled response.
    pub must_staple: bool,
    /// Embedded Certificate Transparency SCTs. Chrome requires at least two from
    /// independent logs for a publicly trusted certificate.
    pub sct_count: usize,
    pub sha256_fingerprint: String,
}

/// The verdict on the whole chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAnalysis {
    pub chain: Vec<ParsedCertificate>,
    pub trust: TrustStatus,
    pub trust_detail: Option<String>,
    pub hostname_matches: bool,
    /// The chain the server sent stops short of a trusted root, so a client has to
    /// find the intermediate itself (AIA chasing) or fail.
    pub chain_incomplete: bool,
    /// Certificates the server sent that are not part of the path to the leaf.
    pub chain_has_extra_certs: bool,
    /// Whether each certificate's issuer is the next one's subject.
    pub chain_ordered: bool,
}

fn oid_string(name: &X509Name, oid: &str) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type().to_id_string() == oid {
                if let Ok(value) = attr.as_str() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn format_name(name: &X509Name) -> String {
    let mut parts = Vec::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let Ok(value) = attr.as_str() else { continue };
            let field = match attr.attr_type().to_id_string().as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                _ => continue,
            };
            parts.push(format!("{}={}", field, value));
        }
    }
    parts.join(", ")
}

/// Human-readable signature algorithm. `x509-parser` exposes only the OID, and an
/// OID in a report tells the reader nothing about whether it is safe.
fn signature_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "rsassaPss",
        "1.2.840.10040.4.3" => "dsaWithSha1",
        "2.16.840.1.101.3.4.3.2" => "dsaWithSha256",
        "1.2.840.10045.4.1" => "ecdsaWithSHA1",
        "1.2.840.10045.4.3.2" => "ecdsaWithSHA256",
        "1.2.840.10045.4.3.3" => "ecdsaWithSHA384",
        "1.2.840.10045.4.3.4" => "ecdsaWithSHA512",
        "1.3.101.112" => "ed25519",
        "1.3.101.113" => "ed448",
        other => return other.to_string(),
    }
    .to_string()
}

/// Signature algorithms that must not appear on a publicly trusted certificate.
/// SHA-1 has been forbidden since 2017 and MD5/MD2 long before that.
pub fn is_weak_signature_algorithm(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("md2") || lower.contains("md5") || lower.contains("sha1") || lower.contains("sha-1")
}

fn asn1_to_rfc3339(time: &ASN1Time) -> String {
    Utc.timestamp_opt(time.timestamp(), 0)
        .single()
        .map(|dt: DateTime<Utc>| dt.to_rfc3339())
        .unwrap_or_default()
}

fn serial_bits(serial: &[u8]) -> u32 {
    for (i, byte) in serial.iter().enumerate() {
        if *byte != 0 {
            return ((serial.len() - i - 1) * 8) as u32 + (8 - byte.leading_zeros());
        }
    }
    0
}

fn key_usage_labels(ku: &KeyUsage) -> Vec<String> {
    let mut out = Vec::new();
    for (present, label) in [
        (ku.digital_signature(), "digitalSignature"),
        (ku.non_repudiation(), "nonRepudiation"),
        (ku.key_encipherment(), "keyEncipherment"),
        (ku.data_encipherment(), "dataEncipherment"),
        (ku.key_agreement(), "keyAgreement"),
        (ku.key_cert_sign(), "keyCertSign"),
        (ku.crl_sign(), "cRLSign"),
        (ku.encipher_only(), "encipherOnly"),
        (ku.decipher_only(), "decipherOnly"),
    ] {
        if present {
            out.push(label.to_string());
        }
    }
    out
}

fn extended_key_usage_labels(eku: &ExtendedKeyUsage) -> Vec<String> {
    let mut out = Vec::new();
    for (present, label) in [
        (eku.any, "any"),
        (eku.server_auth, "serverAuth"),
        (eku.client_auth, "clientAuth"),
        (eku.code_signing, "codeSigning"),
        (eku.email_protection, "emailProtection"),
        (eku.time_stamping, "timeStamping"),
        (eku.ocsp_signing, "OCSPSigning"),
    ] {
        if present {
            out.push(label.to_string());
        }
    }
    out
}

/// Parse a single DER certificate into everything a report needs.
pub fn parse_certificate(der: &[u8]) -> Option<ParsedCertificate> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject = format_name(cert.subject());
    let issuer = format_name(cert.issuer());
    let common_name = oid_string(cert.subject(), "2.5.4.3");
    let organization = oid_string(cert.subject(), "2.5.4.10");

    let mut san_domains = Vec::new();
    let mut san_ips = Vec::new();
    let mut ocsp_urls = Vec::new();
    let mut ca_issuer_urls = Vec::new();
    let mut crl_urls = Vec::new();
    let mut key_usage = Vec::new();
    let mut extended_key_usage = Vec::new();
    let mut is_ca = false;
    let mut must_staple = false;
    let mut sct_count = 0usize;

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => san_domains.push(dns.to_string()),
                        GeneralName::IPAddress(bytes) => {
                            let rendered = match bytes.len() {
                                4 => Some(
                                    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                                        .to_string(),
                                ),
                                16 => {
                                    let mut octets = [0u8; 16];
                                    octets.copy_from_slice(bytes);
                                    Some(std::net::Ipv6Addr::from(octets).to_string())
                                }
                                _ => None,
                            };
                            if let Some(ip) = rendered {
                                san_ips.push(ip);
                            }
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::BasicConstraints(bc) => is_ca = bc.ca,
            ParsedExtension::KeyUsage(ku) => key_usage = key_usage_labels(ku),
            ParsedExtension::ExtendedKeyUsage(eku) => {
                extended_key_usage = extended_key_usage_labels(eku)
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for desc in aia.iter() {
                    if let GeneralName::URI(uri) = desc.access_location {
                        match desc.access_method.to_id_string().as_str() {
                            // id-ad-ocsp / id-ad-caIssuers
                            "1.3.6.1.5.5.7.48.1" => ocsp_urls.push(uri.to_string()),
                            "1.3.6.1.5.5.7.48.2" => ca_issuer_urls.push(uri.to_string()),
                            _ => {}
                        }
                    }
                }
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                for point in points.iter() {
                    if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                crl_urls.push(uri.to_string());
                            }
                        }
                    }
                }
            }
            ParsedExtension::SCT(scts) => sct_count = scts.len(),
            _ => {}
        }

        let oid = ext.oid.to_id_string();
        if oid == OID_TLS_FEATURE {
            // TLSFeature ::= SEQUENCE OF INTEGER; feature 5 is status_request.
            must_staple = ext.value.windows(1).any(|w| w[0] == 5) && ext.value.len() >= 3;
        }
        // Some CAs emit the SCT list without x509-parser recognising the shape.
        if oid == OID_SCT && sct_count == 0 {
            sct_count = 1;
        }
    }

    let public_key = cert.public_key();
    let (public_key_type, public_key_bits) = match public_key.parsed() {
        Ok(PublicKey::RSA(rsa)) => (Some("rsa".to_string()), Some(rsa.key_size() as u32)),
        Ok(PublicKey::EC(ec)) => (Some("ecdsa".to_string()), Some(ec.key_size() as u32)),
        Ok(PublicKey::DSA(_)) => (
            Some("dsa".to_string()),
            Some(public_key.subject_public_key.data.len() as u32 * 8),
        ),
        Ok(PublicKey::Unknown(_)) | Err(_) => {
            // Ed25519 / Ed448 have no `PublicKey` variant; identify by OID.
            match public_key.algorithm.algorithm.to_id_string().as_str() {
                "1.3.101.112" => (Some("ed25519".to_string()), Some(256)),
                "1.3.101.113" => (Some("ed448".to_string()), Some(448)),
                _ => (None, None),
            }
        }
        Ok(_) => (None, None),
    };

    let not_before = cert.validity().not_before;
    let not_after = cert.validity().not_after;
    let validity_days = (not_after.timestamp() - not_before.timestamp()) / 86_400;
    let days_until_expiry = (not_after.timestamp() - Utc::now().timestamp()) / 86_400;

    let serial = cert.raw_serial();
    let is_wildcard = common_name.as_deref().is_some_and(|cn| cn.starts_with("*."))
        || san_domains.iter().any(|d| d.starts_with("*."));

    let mut hasher = Sha256::new();
    hasher.update(der);
    let sha256_fingerprint = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");

    Some(ParsedCertificate {
        is_self_signed: subject == issuer,
        subject,
        issuer_common_name: oid_string(cert.issuer(), "2.5.4.3"),
        issuer_organization: oid_string(cert.issuer(), "2.5.4.10"),
        issuer,
        common_name,
        organization,
        san_domains,
        san_ips,
        not_before: asn1_to_rfc3339(&not_before),
        not_after: asn1_to_rfc3339(&not_after),
        validity_days,
        days_until_expiry,
        serial_number: serial
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
        serial_bits: serial_bits(serial),
        signature_algorithm: signature_algorithm_name(
            &cert.signature_algorithm.algorithm.to_id_string(),
        ),
        public_key_type,
        public_key_bits,
        is_ca,
        is_wildcard,
        key_usage,
        extended_key_usage,
        ocsp_urls,
        ca_issuer_urls,
        crl_urls,
        must_staple,
        sct_count,
        sha256_fingerprint,
    })
}

/// RFC 6125 hostname matching: exact, or a wildcard that replaces exactly one
/// left-most label. `*.example.com` covers `a.example.com` and neither
/// `example.com` nor `a.b.example.com`.
pub fn hostname_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() || !suffix.contains('.') {
            return false;
        }
        return host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix);
    }
    host == pattern
}

pub fn certificate_covers_host(cert: &ParsedCertificate, host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return cert.san_ips.iter().any(|ip| ip == host);
    }
    // RFC 6125 §6.4.4: CN is only consulted when there is no dNSName SAN at all.
    if !cert.san_domains.is_empty() {
        return cert.san_domains.iter().any(|d| hostname_matches(host, d));
    }
    cert.common_name
        .as_deref()
        .is_some_and(|cn| hostname_matches(host, cn))
}

fn root_store() -> Arc<RootCertStore> {
    // Built once: parsing ~150 roots per scanned host is pure waste.
    static ROOTS: std::sync::OnceLock<Arc<RootCertStore>> = std::sync::OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(store)
        })
        .clone()
}

fn trust_status_from_error(error: &rustls::Error) -> (TrustStatus, String) {
    let detail = error.to_string();
    let status = match error {
        rustls::Error::InvalidCertificate(cert_error) => match cert_error {
            CertificateError::Expired => TrustStatus::Expired,
            CertificateError::NotValidYet => TrustStatus::NotYetValid,
            CertificateError::Revoked => TrustStatus::Revoked,
            CertificateError::NotValidForName => TrustStatus::NameMismatch,
            CertificateError::UnknownIssuer => TrustStatus::UnknownIssuer,
            CertificateError::BadSignature => TrustStatus::BadSignature,
            CertificateError::BadEncoding => TrustStatus::Malformed,
            CertificateError::InvalidPurpose => TrustStatus::InvalidPurpose,
            _ => TrustStatus::UnknownIssuer,
        },
        _ => TrustStatus::UnknownIssuer,
    };
    (status, detail)
}

/// Validate the served chain against the Mozilla root program, exactly as a
/// browser would, and describe the result.
pub fn analyze_chain(der_chain: &[Vec<u8>], host: &str) -> ChainAnalysis {
    let chain: Vec<ParsedCertificate> = der_chain
        .iter()
        .filter_map(|der| parse_certificate(der))
        .collect();

    if chain.is_empty() {
        return ChainAnalysis {
            chain,
            trust: TrustStatus::Unknown,
            trust_detail: Some("no certificate chain was captured".to_string()),
            hostname_matches: false,
            chain_incomplete: false,
            chain_has_extra_certs: false,
            chain_ordered: true,
        };
    }

    let leaf = &chain[0];
    let hostname_ok = certificate_covers_host(leaf, host);

    // Each certificate should be issued by the next one along.
    let chain_ordered = chain
        .windows(2)
        .all(|pair| pair[0].issuer == pair[1].subject);

    // A chain that terminates in a self-signed root is complete by construction;
    // otherwise the last certificate must itself be issued by a trusted root, and
    // only the verifier can say whether it is.
    let ends_at_root = chain.last().is_some_and(|c| c.is_self_signed);

    let (trust, trust_detail) = if leaf.is_self_signed {
        (
            TrustStatus::SelfSigned,
            Some("the leaf certificate is self-signed".to_string()),
        )
    } else {
        verify_with_webpki(der_chain, host)
    };

    // Missing intermediates surface as UnknownIssuer with only a leaf present;
    // that is the classic "works in Chrome, fails on Android" misconfiguration.
    let chain_incomplete = !ends_at_root
        && !leaf.is_self_signed
        && (chain.len() == 1 || trust == TrustStatus::UnknownIssuer);

    ChainAnalysis {
        chain_has_extra_certs: chain.iter().skip(1).any(|c| !c.is_ca),
        chain,
        trust,
        trust_detail,
        hostname_matches: hostname_ok,
        chain_incomplete,
        chain_ordered,
    }
}

fn verify_with_webpki(der_chain: &[Vec<u8>], host: &str) -> (TrustStatus, Option<String>) {
    let Ok(verifier) = WebPkiServerVerifier::builder(root_store()).build() else {
        return (
            TrustStatus::Unknown,
            Some("could not build the trust verifier".to_string()),
        );
    };

    let certs: Vec<CertificateDer<'static>> = der_chain
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let (leaf, intermediates) = certs.split_first().expect("chain is non-empty");

    // An IP-literal SNI is legal for verification even though we never send it in
    // a ClientHello.
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => {
            return (
                TrustStatus::Unknown,
                Some(format!("'{}' is not a valid server name", host)),
            )
        }
    };

    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        Utc::now().timestamp().max(0) as u64,
    ));

    match verifier.verify_server_cert(leaf, intermediates, &server_name, &[], now) {
        Ok(_) => (TrustStatus::Trusted, None),
        Err(error) => {
            let (status, detail) = trust_status_from_error(&error);
            (status, Some(detail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_replace_exactly_one_label() {
        assert!(hostname_matches("www.example.com", "*.example.com"));
        assert!(hostname_matches("WWW.Example.com", "*.example.com"));
        // A wildcard does not cover the bare domain...
        assert!(!hostname_matches("example.com", "*.example.com"));
        // ...nor a deeper label.
        assert!(!hostname_matches("a.b.example.com", "*.example.com"));
        // A wildcard directly on a TLD is never valid.
        assert!(!hostname_matches("example.com", "*.com"));
        assert!(hostname_matches("example.com", "example.com."));
    }

    #[test]
    fn cn_is_only_consulted_without_sans() {
        let mut cert = sample_certificate();
        cert.san_domains = vec!["other.example.com".to_string()];
        cert.common_name = Some("target.example.com".to_string());
        // RFC 6125: a dNSName SAN present means CN must be ignored entirely.
        assert!(!certificate_covers_host(&cert, "target.example.com"));

        cert.san_domains.clear();
        assert!(certificate_covers_host(&cert, "target.example.com"));
    }

    #[test]
    fn ip_hosts_match_only_ip_sans() {
        let mut cert = sample_certificate();
        cert.san_domains = vec!["*.example.com".to_string()];
        cert.san_ips = vec!["192.0.2.10".to_string()];
        assert!(certificate_covers_host(&cert, "192.0.2.10"));
        assert!(!certificate_covers_host(&cert, "192.0.2.11"));
    }

    #[test]
    fn serial_entropy_ignores_leading_zeros() {
        // A 64-bit serial padded to 9 bytes still has 64 bits of entropy at most.
        assert_eq!(serial_bits(&[0x00, 0xFF, 0, 0, 0, 0, 0, 0, 0]), 64);
        assert_eq!(serial_bits(&[0x01]), 1);
        assert_eq!(serial_bits(&[0x00]), 0);
    }

    #[test]
    fn deprecated_signature_algorithms_are_recognised() {
        assert!(is_weak_signature_algorithm("sha1WithRSAEncryption"));
        assert!(is_weak_signature_algorithm("md5WithRSAEncryption"));
        assert!(is_weak_signature_algorithm("ecdsaWithSHA1"));
        assert!(!is_weak_signature_algorithm("sha256WithRSAEncryption"));
        // SHA-512 contains no "sha1" substring by accident.
        assert!(!is_weak_signature_algorithm("sha512WithRSAEncryption"));
    }

    #[test]
    fn signature_oids_render_as_names() {
        assert_eq!(
            signature_algorithm_name("1.2.840.113549.1.1.11"),
            "sha256WithRSAEncryption"
        );
        // An unmapped OID is reported verbatim rather than guessed at.
        assert_eq!(signature_algorithm_name("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn empty_chain_is_reported_as_unevaluated_not_trusted() {
        let analysis = analyze_chain(&[], "example.com");
        assert_eq!(analysis.trust, TrustStatus::Unknown);
        assert!(!analysis.trust.is_trusted());
        assert!(!analysis.hostname_matches);
    }

    #[test]
    fn garbage_der_does_not_panic() {
        assert!(parse_certificate(&[0x00, 0x01, 0x02]).is_none());
        let analysis = analyze_chain(&[vec![0xde, 0xad, 0xbe, 0xef]], "example.com");
        assert_eq!(analysis.trust, TrustStatus::Unknown);
    }

    fn sample_certificate() -> ParsedCertificate {
        ParsedCertificate {
            subject: "CN=example.com".into(),
            issuer: "CN=Test CA".into(),
            common_name: Some("example.com".into()),
            organization: None,
            issuer_common_name: Some("Test CA".into()),
            issuer_organization: None,
            san_domains: vec![],
            san_ips: vec![],
            not_before: String::new(),
            not_after: String::new(),
            validity_days: 90,
            days_until_expiry: 60,
            serial_number: "01".into(),
            serial_bits: 8,
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
            sct_count: 0,
            sha256_fingerprint: String::new(),
        }
    }
}

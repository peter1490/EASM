//! A raw TLS handshake prober.
//!
//! `rustls` — the library the rest of this codebase uses — deliberately refuses to
//! speak SSLv3, TLS 1.0 or TLS 1.1, and will not negotiate RC4, 3DES, export or
//! anonymous suites. That is correct for a *client*, and useless for a *scanner*:
//! the whole job here is to find out whether a server still offers exactly those
//! things. `sslscan`, `sslyze` and `testssl.sh` all solve this the same way, by
//! writing the ClientHello bytes themselves, and so does this module.
//!
//! Everything below speaks the record and handshake layers directly over a
//! `TcpStream`. Nothing is ever decrypted: every message a scanner needs
//! (ServerHello, Certificate, ServerKeyExchange, CertificateStatus) is sent in the
//! clear in TLS 1.2 and below, and in TLS 1.3 the ServerHello alone carries the
//! negotiated version and suite.
//!
//! References: RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 6520 (heartbeat),
//! RFC 7507 (fallback SCSV), RFC 5746 (secure renegotiation), and the SSLv2 spec
//! for the DROWN probe.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::cipher_suites::{self, KeyExchange};

/// Protocol versions a scanner is expected to report on, oldest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsVersion {
    Ssl2,
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// The wire encoding. SSLv2 has none — it predates the version field's use in
    /// the record layer — so it is probed with a message of its own.
    pub fn wire(self) -> u16 {
        match self {
            TlsVersion::Ssl2 => 0x0002,
            TlsVersion::Ssl3 => 0x0300,
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
        }
    }

    pub fn from_wire(v: u16) -> Option<Self> {
        match v {
            0x0002 => Some(TlsVersion::Ssl2),
            0x0300 => Some(TlsVersion::Ssl3),
            0x0301 => Some(TlsVersion::Tls10),
            0x0302 => Some(TlsVersion::Tls11),
            0x0303 => Some(TlsVersion::Tls12),
            0x0304 => Some(TlsVersion::Tls13),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TlsVersion::Ssl2 => "SSLv2",
            TlsVersion::Ssl3 => "SSLv3",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
        }
    }

    /// Deprecated by RFC 8996 (TLS 1.0/1.1) or long since broken (SSLv2/v3).
    pub fn is_deprecated(self) -> bool {
        matches!(
            self,
            TlsVersion::Ssl2 | TlsVersion::Ssl3 | TlsVersion::Tls10 | TlsVersion::Tls11
        )
    }

    /// SSL Labs protocol-support score for this version, as a percentage.
    pub fn rating(self) -> u32 {
        match self {
            TlsVersion::Ssl2 => 0,
            TlsVersion::Ssl3 => 80,
            TlsVersion::Tls10 => 90,
            TlsVersion::Tls11 => 95,
            TlsVersion::Tls12 | TlsVersion::Tls13 => 100,
        }
    }

    pub fn all() -> [TlsVersion; 6] {
        [
            TlsVersion::Ssl2,
            TlsVersion::Ssl3,
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ]
    }
}

/// RFC 8446 §5.1: a record body is at most 2^14 bytes, plus up to 2048 bytes of
/// expansion for the ciphertext forms.
const MAX_TLS_RECORD_SIZE: usize = (1 << 14) + 2048;

// Record content types.
const CT_CHANGE_CIPHER_SPEC: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APPLICATION_DATA: u8 = 23;
const CT_HEARTBEAT: u8 = 24;

// Handshake message types.
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_SERVER_HELLO_DONE: u8 = 14;
const HS_CERTIFICATE_STATUS: u8 = 22;

// Extension types we send or look for.
const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_HEARTBEAT: u16 = 15;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_ENCRYPT_THEN_MAC: u16 = 22;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// RFC 7507: signals "this is a downgrade retry" so a patched server can refuse.
const TLS_FALLBACK_SCSV: u16 = 0x5600;
/// RFC 5746: the extension-free way to advertise secure renegotiation support.
const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00FF;

/// What to put in the ClientHello for one probe.
#[derive(Debug, Clone)]
pub struct HelloOptions {
    pub version: TlsVersion,
    pub cipher_ids: Vec<u16>,
    pub server_name: Option<String>,
    /// Offer DEFLATE as well as null compression — the CRIME precondition.
    pub offer_compression: bool,
    pub include_fallback_scsv: bool,
    pub include_heartbeat: bool,
    pub request_ocsp: bool,
    pub alpn: Vec<&'static str>,
}

impl HelloOptions {
    pub fn new(version: TlsVersion, server_name: Option<String>) -> Self {
        let cipher_ids = if version == TlsVersion::Tls13 {
            cipher_suites::tls13_suite_ids()
        } else {
            cipher_suites::legacy_suite_ids()
        };
        Self {
            version,
            cipher_ids,
            server_name,
            offer_compression: false,
            include_fallback_scsv: false,
            include_heartbeat: false,
            request_ocsp: true,
            alpn: vec!["h2", "http/1.1"],
        }
    }

    pub fn with_ciphers(mut self, cipher_ids: Vec<u16>) -> Self {
        self.cipher_ids = cipher_ids;
        self
    }
}

/// Key-exchange parameters recovered from ServerKeyExchange (TLS ≤ 1.2) or from
/// the ServerHello `key_share` (TLS 1.3).
#[derive(Debug, Clone, Default)]
pub struct KeyExchangeInfo {
    /// Finite-field DH prime size, in bits. Drives the LOGJAM / weak-DH checks.
    pub dh_bits: Option<u32>,
    pub named_curve: Option<u16>,
    pub curve_name: Option<String>,
    pub curve_bits: Option<u32>,
}

/// Everything one handshake attempt told us.
#[derive(Debug, Clone, Default)]
pub struct HandshakeResult {
    pub negotiated_version: Option<TlsVersion>,
    pub cipher_id: Option<u16>,
    pub compression_method: Option<u8>,
    pub server_extensions: Vec<u16>,
    pub alpn: Option<String>,
    pub ocsp_stapled: bool,
    /// DER-encoded chain, leaf first. Empty for TLS 1.3 (encrypted).
    pub certificates: Vec<Vec<u8>>,
    pub key_exchange: KeyExchangeInfo,
    /// `(level, description)` when the server rejected the hello.
    pub alert: Option<(u8, u8)>,
    /// Set when the peer answered with an SSLv2 SERVER-HELLO.
    pub ssl2_server_hello: bool,
    pub ssl2_cipher_specs: Vec<u32>,
    /// True once the server started sending encrypted records — TLS 1.3 reached
    /// the point where nothing more is readable, which is itself a success signal.
    pub saw_encrypted: bool,
    /// The peer answered with something that is not a TLS record at all. Lets a
    /// caller stop probing the remaining protocol versions instead of waiting out
    /// a timeout per version.
    pub not_tls: bool,
}

impl HandshakeResult {
    pub fn succeeded(&self) -> bool {
        self.negotiated_version.is_some() || self.ssl2_server_hello
    }

    pub fn has_extension(&self, ext: u16) -> bool {
        self.server_extensions.contains(&ext)
    }
}

/// An alert description worth naming in a report.
pub fn alert_description(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

fn curve_name(id: u16) -> (&'static str, u32) {
    match id {
        1 => ("sect163k1", 163),
        15 => ("secp160k1", 160),
        19 => ("secp192r1", 192),
        21 => ("secp224r1", 224),
        23 => ("secp256r1", 256),
        24 => ("secp384r1", 384),
        25 => ("secp521r1", 521),
        29 => ("x25519", 253),
        30 => ("x448", 448),
        256 => ("ffdhe2048", 2048),
        257 => ("ffdhe3072", 3072),
        258 => ("ffdhe4096", 4096),
        259 => ("ffdhe6144", 6144),
        260 => ("ffdhe8192", 8192),
        _ => ("unknown", 0),
    }
}

/// NIST SP 800-57 equivalence, the same table SSL Labs uses to score an ECDHE key
/// exchange on the same scale as a finite-field one.
pub fn ecc_equivalent_dh_bits(curve_bits: u32) -> u32 {
    match curve_bits {
        0..=159 => 512,
        160..=223 => 1024,
        224..=255 => 2048,
        256..=383 => 3072,
        384..=511 => 7680,
        _ => 15360,
    }
}

// ---------------------------------------------------------------------------
// ClientHello construction
// ---------------------------------------------------------------------------

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_vec16(out: &mut Vec<u8>, body: &[u8]) {
    push_u16(out, body.len() as u16);
    out.extend_from_slice(body);
}

fn extension(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    push_u16(out, ext_type);
    push_vec16(out, body);
}

/// A deterministic 32-byte "random". Real randomness buys nothing here — no key is
/// ever derived from it — and a fixed value makes a scan reproducible.
fn client_random(version: TlsVersion) -> [u8; 32] {
    let mut random = [0u8; 32];
    for (i, byte) in random.iter_mut().enumerate() {
        *byte = ((i as u8).wrapping_mul(37)) ^ (version.wire() as u8);
    }
    random
}

fn build_client_hello(opts: &HelloOptions) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);

    // TLS 1.3 keeps `legacy_version` pinned at 1.2 and moves the real version
    // into `supported_versions` (RFC 8446 §4.1.2).
    let legacy_version = if opts.version == TlsVersion::Tls13 {
        TlsVersion::Tls12.wire()
    } else {
        opts.version.wire()
    };
    push_u16(&mut body, legacy_version);
    body.extend_from_slice(&client_random(opts.version));

    // Non-empty legacy_session_id keeps middleboxes happy in TLS 1.3 compat mode.
    if opts.version == TlsVersion::Tls13 {
        body.push(32);
        body.extend_from_slice(&[0x5a; 32]);
    } else {
        body.push(0);
    }

    let mut suites = Vec::with_capacity(opts.cipher_ids.len() * 2 + 4);
    for id in &opts.cipher_ids {
        suites.extend_from_slice(&id.to_be_bytes());
    }
    // Advertising the renegotiation SCSV is how a server that supports RFC 5746
    // without the extension gets a chance to say so.
    suites.extend_from_slice(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV.to_be_bytes());
    if opts.include_fallback_scsv {
        suites.extend_from_slice(&TLS_FALLBACK_SCSV.to_be_bytes());
    }
    push_vec16(&mut body, &suites);

    if opts.offer_compression {
        body.extend_from_slice(&[2, 1, 0]); // DEFLATE then null
    } else {
        body.extend_from_slice(&[1, 0]); // null only
    }

    let mut exts = Vec::with_capacity(256);

    if let Some(name) = &opts.server_name {
        // SNI is only defined for DNS names; sending an IP literal is a protocol
        // violation that some stacks answer with a fatal alert.
        if name.parse::<std::net::IpAddr>().is_err() && !name.is_empty() {
            let mut sni = Vec::with_capacity(name.len() + 5);
            push_u16(&mut sni, (name.len() + 3) as u16);
            sni.push(0); // host_name
            push_vec16(&mut sni, name.as_bytes());
            extension(&mut exts, EXT_SERVER_NAME, &sni);
        }
    }

    if opts.request_ocsp {
        // status_request: OCSP, no responder ids, no request extensions.
        extension(&mut exts, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0]);
    }

    let groups: [u16; 8] = [29, 23, 24, 25, 30, 256, 257, 258];
    let mut groups_body = Vec::with_capacity(groups.len() * 2 + 2);
    push_u16(&mut groups_body, (groups.len() * 2) as u16);
    for g in groups {
        push_u16(&mut groups_body, g);
    }
    extension(&mut exts, EXT_SUPPORTED_GROUPS, &groups_body);
    extension(&mut exts, EXT_EC_POINT_FORMATS, &[1, 0]);

    // TLS 1.2 made signature_algorithms mandatory in practice; older versions
    // ignore it. The list is deliberately broad so a legacy server still matches.
    let sig_algs: [u16; 14] = [
        0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0201,
    ];
    let mut sig_body = Vec::with_capacity(sig_algs.len() * 2 + 2);
    push_u16(&mut sig_body, (sig_algs.len() * 2) as u16);
    for s in sig_algs {
        push_u16(&mut sig_body, s);
    }
    extension(&mut exts, EXT_SIGNATURE_ALGORITHMS, &sig_body);

    if !opts.alpn.is_empty() {
        let mut protocols = Vec::new();
        for p in &opts.alpn {
            protocols.push(p.len() as u8);
            protocols.extend_from_slice(p.as_bytes());
        }
        let mut alpn_body = Vec::with_capacity(protocols.len() + 2);
        push_u16(&mut alpn_body, protocols.len() as u16);
        alpn_body.extend_from_slice(&protocols);
        extension(&mut exts, EXT_ALPN, &alpn_body);
    }

    extension(&mut exts, EXT_SCT, &[]);
    extension(&mut exts, EXT_ENCRYPT_THEN_MAC, &[]);
    extension(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
    extension(&mut exts, EXT_SESSION_TICKET, &[]);
    extension(&mut exts, EXT_RENEGOTIATION_INFO, &[0]);

    if opts.include_heartbeat {
        extension(&mut exts, EXT_HEARTBEAT, &[1]); // peer_allowed_to_send
    }

    if opts.version == TlsVersion::Tls13 {
        extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
        extension(&mut exts, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1]);
        // A fixed X25519 "public key". Any 32 bytes is a well-formed one; the
        // handshake is abandoned right after ServerHello, so the shared secret
        // never matters.
        let mut key_share = Vec::with_capacity(40);
        push_u16(&mut key_share, 36); // client_shares length
        push_u16(&mut key_share, 29); // x25519
        push_vec16(&mut key_share, &[0x2a; 32]);
        extension(&mut exts, EXT_KEY_SHARE, &key_share);
    }

    // SSLv3 predates extensions entirely. Sending them provokes a decode_error
    // from strict stacks, which would read as "SSLv3 unsupported" and hide a real
    // finding, so an SSLv3 hello goes out bare.
    if opts.version != TlsVersion::Ssl3 {
        push_vec16(&mut body, &exts);
    }

    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(1); // client_hello
    let len = body.len();
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(CT_HANDSHAKE);
    // A record-layer version above 1.0 makes some ancient stacks hang up.
    push_u16(&mut record, TlsVersion::Tls10.wire().min(legacy_version));
    push_vec16(&mut record, &handshake);
    record
}

/// The SSLv2 CLIENT-HELLO, needed only to answer "is DROWN possible here".
fn build_ssl2_client_hello() -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    body.push(1); // MSG-CLIENT-HELLO
    body.extend_from_slice(&[0x00, 0x02]); // SSL 2.0
    let ciphers: Vec<u32> = cipher_suites::SSL2_CIPHERS.iter().map(|(id, _, _)| *id).collect();
    push_u16(&mut body, (ciphers.len() * 3) as u16); // cipher spec length
    push_u16(&mut body, 0); // session id length
    push_u16(&mut body, 16); // challenge length
    for c in &ciphers {
        body.push((c >> 16) as u8);
        body.push((c >> 8) as u8);
        body.push(*c as u8);
    }
    body.extend_from_slice(&[0x11; 16]); // challenge

    let mut record = Vec::with_capacity(body.len() + 2);
    let len = body.len() as u16 | 0x8000; // two-byte header form
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(&body);
    record
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let v = ((self.buf[self.pos] as u32) << 16)
            | ((self.buf[self.pos + 1] as u32) << 8)
            | self.buf[self.pos + 2] as u32;
        self.pos += 3;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }
}

/// Bit length of a big-endian integer, ignoring leading zero bytes/bits. A 2048-bit
/// prime is often serialised in 257 bytes with a leading zero, so `len * 8` alone
/// would report 2056 and miss the boundary tests.
fn big_int_bits(bytes: &[u8]) -> u32 {
    for (i, b) in bytes.iter().enumerate() {
        if *b != 0 {
            return ((bytes.len() - i - 1) * 8) as u32 + (8 - b.leading_zeros());
        }
    }
    0
}

fn parse_server_hello(body: &[u8], result: &mut HandshakeResult) {
    let mut r = Reader::new(body);
    let Some(legacy_version) = r.u16() else { return };
    if r.skip(32).is_none() {
        return;
    }
    let Some(session_len) = r.u8() else { return };
    if r.skip(session_len as usize).is_none() {
        return;
    }
    let Some(cipher) = r.u16() else { return };
    let Some(compression) = r.u8() else { return };

    result.cipher_id = Some(cipher);
    result.compression_method = Some(compression);
    result.negotiated_version = TlsVersion::from_wire(legacy_version);

    // Extensions are optional in a ServerHello from TLS 1.2 and below.
    let Some(ext_total) = r.u16() else { return };
    let Some(ext_bytes) = r.bytes(ext_total as usize) else {
        return;
    };
    let mut er = Reader::new(ext_bytes);
    while er.remaining() >= 4 {
        let Some(ext_type) = er.u16() else { break };
        let Some(ext_len) = er.u16() else { break };
        let Some(data) = er.bytes(ext_len as usize) else {
            break;
        };
        result.server_extensions.push(ext_type);
        match ext_type {
            // RFC 8446: the authoritative version lives here, not in legacy_version.
            EXT_SUPPORTED_VERSIONS if data.len() >= 2 => {
                let v = u16::from_be_bytes([data[0], data[1]]);
                if let Some(version) = TlsVersion::from_wire(v) {
                    result.negotiated_version = Some(version);
                }
            }
            EXT_ALPN if data.len() >= 3 => {
                // ProtocolNameList: list length (2), then length-prefixed names.
                // The server returns exactly one.
                let name_len = data[2] as usize;
                if data.len() >= 3 + name_len {
                    result.alpn = String::from_utf8(data[3..3 + name_len].to_vec()).ok();
                }
            }
            EXT_KEY_SHARE if data.len() >= 2 => {
                let group = u16::from_be_bytes([data[0], data[1]]);
                let (name, bits) = curve_name(group);
                result.key_exchange.named_curve = Some(group);
                result.key_exchange.curve_name = Some(name.to_string());
                result.key_exchange.curve_bits = Some(bits);
                if name.starts_with("ffdhe") {
                    result.key_exchange.dh_bits = Some(bits);
                }
            }
            _ => {}
        }
    }
}

fn parse_certificates(body: &[u8], result: &mut HandshakeResult) {
    let mut r = Reader::new(body);
    let Some(list_len) = r.u24() else { return };
    let Some(list) = r.bytes(list_len as usize) else {
        return;
    };
    let mut cr = Reader::new(list);
    while cr.remaining() >= 3 {
        let Some(cert_len) = cr.u24() else { break };
        let Some(der) = cr.bytes(cert_len as usize) else {
            break;
        };
        result.certificates.push(der.to_vec());
    }
}

fn parse_server_key_exchange(body: &[u8], result: &mut HandshakeResult) {
    let Some(cipher) = result.cipher_id else { return };
    let Some(suite) = cipher_suites::lookup(cipher) else {
        return;
    };
    let mut r = Reader::new(body);
    match suite.kx {
        KeyExchange::Dhe | KeyExchange::Dh => {
            // ServerDHParams: dh_p, dh_g, dh_Ys — each a 16-bit-length opaque.
            let Some(p_len) = r.u16() else { return };
            let Some(p) = r.bytes(p_len as usize) else {
                return;
            };
            result.key_exchange.dh_bits = Some(big_int_bits(p));
        }
        KeyExchange::Ecdhe | KeyExchange::Ecdh => {
            // ServerECDHParams: curve_type(1) then, for named_curve, the id.
            let Some(curve_type) = r.u8() else { return };
            if curve_type == 3 {
                let Some(group) = r.u16() else { return };
                let (name, bits) = curve_name(group);
                result.key_exchange.named_curve = Some(group);
                result.key_exchange.curve_name = Some(name.to_string());
                result.key_exchange.curve_bits = Some(bits);
            }
        }
        _ => {}
    }
}

/// Parse every *complete* handshake message in `buf`, returning how many bytes
/// were consumed.
///
/// The caller reads in chunks and re-invokes this as more arrives, so it must
/// resume where it stopped: parsing from zero each time appended the certificate
/// chain and the server's extension list once per read.
fn parse_handshake_messages(buf: &[u8], result: &mut HandshakeResult) -> usize {
    let mut r = Reader::new(buf);
    let mut consumed = 0usize;
    while r.remaining() >= 4 {
        let start = r.pos;
        let Some(msg_type) = r.u8() else { break };
        let Some(len) = r.u24() else { break };
        let Some(body) = r.bytes(len as usize) else {
            // A partial message: leave it for the next read.
            r.pos = start;
            break;
        };
        match msg_type {
            HS_SERVER_HELLO => parse_server_hello(body, result),
            HS_CERTIFICATE => parse_certificates(body, result),
            HS_SERVER_KEY_EXCHANGE => parse_server_key_exchange(body, result),
            HS_CERTIFICATE_STATUS => result.ocsp_stapled = true,
            _ => {}
        }
        consumed = r.pos;
    }
    consumed
}

async fn read_with_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    timeout: Duration,
) -> std::io::Result<usize> {
    match tokio::time::timeout(timeout, stream.read(buf)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TLS read timed out",
        )),
    }
}

/// Read the server's first flight and stop at the earliest conclusive point.
async fn read_server_flight(
    stream: &mut TcpStream,
    timeout: Duration,
    result: &mut HandshakeResult,
) {
    let mut pending = Vec::with_capacity(8192);
    let mut handshake = Vec::with_capacity(8192);
    let mut parsed = 0usize;
    let mut chunk = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let read = match read_with_timeout(stream, &mut chunk, deadline - now).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        pending.extend_from_slice(&chunk[..read]);

        // An SSLv2-style reply has the high bit set in its first length byte and
        // never a valid TLS content type, so it can only be checked up front.
        if result.negotiated_version.is_none()
            && pending.len() >= 3
            && pending[0] & 0x80 != 0
            && pending[2] == 4
        {
            result.ssl2_server_hello = true;
            parse_ssl2_server_hello(&pending, result);
            return;
        }

        let mut consumed = 0usize;
        let mut done = false;
        while pending.len() >= consumed + 5 {
            let content_type = pending[consumed];
            let len = u16::from_be_bytes([pending[consumed + 3], pending[consumed + 4]]) as usize;
            // A reply that is not TLS at all — an HTTP error page on 443, a
            // proxy banner, an SSH greeting — must be recognised here. Without
            // this the bytes are read as a record header: "HTTP/1.1 400" gives
            // content type 'H' and a length of 0x502F, and the loop then waits
            // the full timeout for 20527 bytes that never come. Six protocol
            // probes at eight seconds each turned every non-TLS port into a
            // 48-second stall.
            //
            // The two guards are the record layer's own limits: RFC 8446 §5.1
            // defines content types 20-24, and caps a record at 2^14 plus the
            // expansion allowance.
            if !(CT_CHANGE_CIPHER_SPEC..=CT_HEARTBEAT).contains(&content_type)
                || len > MAX_TLS_RECORD_SIZE
            {
                result.not_tls = true;
                done = true;
                break;
            }
            if pending.len() < consumed + 5 + len {
                break;
            }
            let payload = &pending[consumed + 5..consumed + 5 + len];
            match content_type {
                CT_HANDSHAKE => handshake.extend_from_slice(payload),
                CT_ALERT if payload.len() >= 2 => {
                    result.alert = Some((payload[0], payload[1]));
                    done = true;
                }
                CT_APPLICATION_DATA | CT_CHANGE_CIPHER_SPEC => {
                    // TLS 1.3 encrypts everything from here; there is nothing more
                    // to learn from this connection.
                    if content_type == CT_APPLICATION_DATA {
                        result.saw_encrypted = true;
                        done = true;
                    }
                }
                _ => {}
            }
            consumed += 5 + len;
            if done {
                break;
            }
        }
        pending.drain(..consumed);

        parsed += parse_handshake_messages(&handshake[parsed..], result);
        // ServerHelloDone means the flight is complete for TLS ≤ 1.2.
        if done || handshake_contains(&handshake, HS_SERVER_HELLO_DONE) {
            break;
        }
        // TLS 1.3 sends ServerHello then encrypted records; once we have the
        // ServerHello there is nothing further worth waiting for.
        if result.negotiated_version == Some(TlsVersion::Tls13) {
            break;
        }
    }

    parse_handshake_messages(&handshake[parsed.min(handshake.len())..], result);
}

fn handshake_contains(buf: &[u8], msg_type: u8) -> bool {
    let mut r = Reader::new(buf);
    while r.remaining() >= 4 {
        let Some(t) = r.u8() else { break };
        let Some(len) = r.u24() else { break };
        if t == msg_type {
            return true;
        }
        if r.skip(len as usize).is_none() {
            break;
        }
    }
    false
}

fn parse_ssl2_server_hello(buf: &[u8], result: &mut HandshakeResult) {
    // header(2) msg(1) session_id_hit(1) cert_type(1) version(2)
    // cert_len(2) cipher_len(2) conn_id_len(2)
    if buf.len() < 13 {
        return;
    }
    let cert_len = u16::from_be_bytes([buf[7], buf[8]]) as usize;
    let cipher_len = u16::from_be_bytes([buf[9], buf[10]]) as usize;
    let start = 13 + cert_len;
    if buf.len() < start + cipher_len {
        return;
    }
    for spec in buf[start..start + cipher_len].chunks_exact(3) {
        result
            .ssl2_cipher_specs
            .push(((spec[0] as u32) << 16) | ((spec[1] as u32) << 8) | spec[2] as u32);
    }
}

// ---------------------------------------------------------------------------
// Public probes
// ---------------------------------------------------------------------------

async fn connect(addr: SocketAddr, timeout: Duration) -> Option<TcpStream> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Some(stream)
        }
        _ => None,
    }
}

/// One handshake attempt. `None` means the TCP connection itself failed, which is
/// different from "the server refused this hello" — the caller must not read a
/// connection error as "protocol unsupported".
pub async fn handshake(
    addr: SocketAddr,
    opts: &HelloOptions,
    timeout: Duration,
) -> Option<HandshakeResult> {
    let mut stream = connect(addr, timeout).await?;
    let hello = if opts.version == TlsVersion::Ssl2 {
        build_ssl2_client_hello()
    } else {
        build_client_hello(opts)
    };
    if tokio::time::timeout(timeout, stream.write_all(&hello))
        .await
        .is_err()
    {
        return None;
    }
    let _ = stream.flush().await;

    let mut result = HandshakeResult::default();
    read_server_flight(&mut stream, timeout, &mut result).await;

    // A server that answers a TLS 1.0 hello with a TLS 1.2 ServerHello has *not*
    // told us TLS 1.0 is supported. Only an exact match counts.
    if opts.version != TlsVersion::Ssl2 {
        if let Some(negotiated) = result.negotiated_version {
            if negotiated != opts.version {
                result.negotiated_version = None;
                result.cipher_id = None;
            }
        }
    }
    Some(result)
}

/// Does the server speak this protocol version at all?
pub async fn supports_version(
    addr: SocketAddr,
    version: TlsVersion,
    server_name: Option<&str>,
    timeout: Duration,
) -> Option<HandshakeResult> {
    let opts = HelloOptions::new(version, server_name.map(str::to_string));
    let result = handshake(addr, &opts, timeout).await?;
    if result.succeeded() {
        Some(result)
    } else {
        None
    }
}

/// Enumerate the suites a server will accept for one protocol version.
///
/// The classic algorithm, shared by `sslscan` and `testssl.sh --each-cipher`:
/// offer everything, note what the server picks, drop it, repeat. The server's
/// first pick under an unmodified list also tells us whose preference order wins,
/// which is a finding of its own.
pub struct CipherEnumeration {
    pub accepted: Vec<(u16, KeyExchangeInfo)>,
    pub server_has_preference: bool,
    pub preferred: Option<u16>,
}

pub async fn enumerate_ciphers(
    addr: SocketAddr,
    version: TlsVersion,
    server_name: Option<&str>,
    timeout: Duration,
    max_rounds: usize,
) -> CipherEnumeration {
    let mut remaining: Vec<u16> = if version == TlsVersion::Tls13 {
        cipher_suites::tls13_suite_ids()
    } else {
        cipher_suites::legacy_suite_ids()
    };
    let mut accepted: Vec<(u16, KeyExchangeInfo)> = Vec::new();
    let mut preferred = None;

    for round in 0..max_rounds {
        if remaining.is_empty() {
            break;
        }
        let opts = HelloOptions::new(version, server_name.map(str::to_string))
            .with_ciphers(remaining.clone());
        let Some(result) = handshake(addr, &opts, timeout).await else {
            break;
        };
        let Some(cipher) = result.cipher_id else { break };
        if !result.succeeded() {
            break;
        }
        // A server that echoes a suite we did not offer is broken or is a
        // middlebox; stopping avoids an endless loop.
        if !remaining.contains(&cipher) {
            break;
        }
        if round == 0 {
            preferred = Some(cipher);
        }
        accepted.push((cipher, result.key_exchange.clone()));
        remaining.retain(|c| *c != cipher);
    }

    // Preference test: re-offer the accepted list reversed. A server that honours
    // its own order picks the same suite either way.
    let mut server_has_preference = false;
    if accepted.len() > 1 {
        let reversed: Vec<u16> = accepted.iter().rev().map(|(id, _)| *id).collect();
        let opts =
            HelloOptions::new(version, server_name.map(str::to_string)).with_ciphers(reversed);
        if let Some(result) = handshake(addr, &opts, timeout).await {
            if let (Some(first), Some(second)) = (preferred, result.cipher_id) {
                server_has_preference = first == second;
            }
        }
    }

    CipherEnumeration {
        accepted,
        server_has_preference,
        preferred,
    }
}

/// Does the server accept DEFLATE compression? That is the CRIME precondition
/// (CVE-2012-4929) — TLS-level compression leaks secrets through ciphertext length.
pub async fn supports_compression(
    addr: SocketAddr,
    version: TlsVersion,
    server_name: Option<&str>,
    timeout: Duration,
) -> Option<bool> {
    let mut opts = HelloOptions::new(version, server_name.map(str::to_string));
    opts.offer_compression = true;
    let result = handshake(addr, &opts, timeout).await?;
    result.compression_method.map(|method| method != 0)
}

/// RFC 7507 fallback protection: a server that implements it answers a downgrade
/// hello carrying the SCSV with `inappropriate_fallback` (alert 86).
pub async fn supports_fallback_scsv(
    addr: SocketAddr,
    highest: TlsVersion,
    server_name: Option<&str>,
    timeout: Duration,
) -> Option<bool> {
    // Only meaningful if there is a lower version to fall back *to*.
    let lower = match highest {
        TlsVersion::Tls13 => TlsVersion::Tls12,
        TlsVersion::Tls12 => TlsVersion::Tls11,
        TlsVersion::Tls11 => TlsVersion::Tls10,
        _ => return None,
    };
    let mut opts = HelloOptions::new(lower, server_name.map(str::to_string));
    opts.include_fallback_scsv = true;
    let result = handshake(addr, &opts, timeout).await?;
    match result.alert {
        Some((_, 86)) => Some(true),
        _ => Some(false),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbleedVerdict {
    /// The server returned more heartbeat payload than it was sent.
    Vulnerable,
    /// The heartbeat extension is on but the overread was refused.
    NotVulnerable,
    /// The extension was not negotiated, so CVE-2014-0160 cannot apply.
    HeartbeatDisabled,
    /// The handshake did not get far enough to say either way.
    Inconclusive,
}

/// CVE-2014-0160. The probe declares a 64-byte payload and sends none of it: a
/// patched server drops the malformed request, an unpatched one answers with 64
/// bytes of its own memory.
///
/// 64 bytes is the smallest overread that is unambiguous. The response is measured
/// and discarded — nothing leaked is parsed, logged or stored.
pub async fn check_heartbleed(
    addr: SocketAddr,
    server_name: Option<&str>,
    timeout: Duration,
) -> HeartbleedVerdict {
    const DECLARED_PAYLOAD: u16 = 64;

    let mut opts = HelloOptions::new(TlsVersion::Tls12, server_name.map(str::to_string));
    opts.include_heartbeat = true;
    opts.alpn.clear();

    let Some(mut stream) = connect(addr, timeout).await else {
        return HeartbleedVerdict::Inconclusive;
    };
    let hello = build_client_hello(&opts);
    if stream.write_all(&hello).await.is_err() {
        return HeartbleedVerdict::Inconclusive;
    }

    let mut result = HandshakeResult::default();
    read_server_flight(&mut stream, timeout, &mut result).await;
    if !result.succeeded() {
        return HeartbleedVerdict::Inconclusive;
    }
    if !result.has_extension(EXT_HEARTBEAT) {
        return HeartbleedVerdict::HeartbeatDisabled;
    }

    let version = result.negotiated_version.unwrap_or(TlsVersion::Tls12).wire();
    let mut payload = Vec::with_capacity(24);
    payload.push(1); // heartbeat_request
    payload.extend_from_slice(&DECLARED_PAYLOAD.to_be_bytes());
    payload.extend_from_slice(&[0x00; 16]); // padding only — no payload at all

    let mut record = Vec::with_capacity(payload.len() + 5);
    record.push(CT_HEARTBEAT);
    record.extend_from_slice(&version.to_be_bytes());
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);

    if stream.write_all(&record).await.is_err() {
        return HeartbleedVerdict::Inconclusive;
    }

    let mut buf = [0u8; 4096];
    let mut seen = Vec::with_capacity(128);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        match read_with_timeout(&mut stream, &mut buf, deadline - now).await {
            Ok(0) | Err(_) => break,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
        while seen.len() >= 5 {
            let content_type = seen[0];
            let len = u16::from_be_bytes([seen[3], seen[4]]) as usize;
            if seen.len() < 5 + len {
                break;
            }
            if content_type == CT_HEARTBEAT {
                // We sent 0 payload bytes; anything beyond the 3-byte header and
                // our 16 bytes of padding came out of the server's heap.
                return if len > 19 {
                    HeartbleedVerdict::Vulnerable
                } else {
                    HeartbleedVerdict::NotVulnerable
                };
            }
            if content_type == CT_ALERT {
                return HeartbleedVerdict::NotVulnerable;
            }
            seen.drain(..5 + len);
        }
    }
    // Silence is the patched behaviour: the malformed request is dropped.
    HeartbleedVerdict::NotVulnerable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_well_formed() {
        let opts = HelloOptions::new(TlsVersion::Tls12, Some("example.com".to_string()));
        let hello = build_client_hello(&opts);
        assert_eq!(hello[0], CT_HANDSHAKE);
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
        assert_eq!(hello[5], 1, "handshake type must be client_hello");
        let hs_len = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(record_len, hs_len + 4);
        // legacy_version for a TLS 1.2 hello is 1.2 itself.
        assert_eq!(u16::from_be_bytes([hello[9], hello[10]]), 0x0303);
    }

    #[test]
    fn tls13_hello_pins_legacy_version_and_sends_key_share() {
        let opts = HelloOptions::new(TlsVersion::Tls13, Some("example.com".to_string()));
        let hello = build_client_hello(&opts);
        assert_eq!(u16::from_be_bytes([hello[9], hello[10]]), 0x0303);
        // supported_versions (43) and key_share (51) must both be present.
        let body = &hello[5..];
        assert!(
            body.windows(2).any(|w| w == 43u16.to_be_bytes()),
            "supported_versions missing"
        );
        assert!(
            body.windows(2).any(|w| w == 51u16.to_be_bytes()),
            "key_share missing"
        );
    }

    #[test]
    fn sslv3_hello_carries_no_extensions() {
        let opts = HelloOptions::new(TlsVersion::Ssl3, Some("example.com".to_string()));
        let hello = build_client_hello(&opts);
        // Everything after compression_methods should be gone: 5 record + 4
        // handshake + 2 version + 32 random + 1 session + 2 len + suites + 2 comp.
        let suites_len = (opts.cipher_ids.len() + 1) * 2;
        let expected = 5 + 4 + 2 + 32 + 1 + 2 + suites_len + 2;
        assert_eq!(hello.len(), expected);
    }

    #[test]
    fn sni_is_omitted_for_ip_literals() {
        let opts = HelloOptions::new(TlsVersion::Tls12, Some("192.0.2.1".to_string()));
        let hello = build_client_hello(&opts);
        assert!(!hello.windows(9).any(|w| w == b"192.0.2.1"));
    }

    #[test]
    fn compression_offer_changes_the_methods_list() {
        let mut opts = HelloOptions::new(TlsVersion::Tls12, None);
        let without = build_client_hello(&opts);
        opts.offer_compression = true;
        let with = build_client_hello(&opts);
        assert_eq!(with.len(), without.len() + 1);
    }

    #[test]
    fn server_hello_parses_version_cipher_and_extensions() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0); // empty session id
        body.extend_from_slice(&0xC02Fu16.to_be_bytes());
        body.push(0); // null compression
        let mut exts = Vec::new();
        exts.extend_from_slice(&EXT_RENEGOTIATION_INFO.to_be_bytes());
        exts.extend_from_slice(&1u16.to_be_bytes());
        exts.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut result = HandshakeResult::default();
        parse_server_hello(&body, &mut result);
        assert_eq!(result.negotiated_version, Some(TlsVersion::Tls12));
        assert_eq!(result.cipher_id, Some(0xC02F));
        assert_eq!(result.compression_method, Some(0));
        assert!(result.has_extension(EXT_RENEGOTIATION_INFO));
    }

    #[test]
    fn tls13_version_comes_from_supported_versions_not_legacy() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        let mut exts = Vec::new();
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&0x0304u16.to_be_bytes());
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut result = HandshakeResult::default();
        parse_server_hello(&body, &mut result);
        assert_eq!(result.negotiated_version, Some(TlsVersion::Tls13));
    }

    #[test]
    fn dh_prime_bit_length_ignores_the_leading_zero_byte() {
        // A 2048-bit prime serialised in 257 bytes must not read as 2056.
        let mut p = vec![0u8; 257];
        p[1] = 0x80;
        assert_eq!(big_int_bits(&p), 2048);
        assert_eq!(big_int_bits(&[0x01]), 1);
        assert_eq!(big_int_bits(&[0x00, 0x00]), 0);
    }

    #[test]
    fn server_key_exchange_yields_dh_size() {
        // DHE_RSA_WITH_AES_128_GCM: the suite is what tells the parser the
        // ServerKeyExchange body carries finite-field DH parameters.
        let mut result = HandshakeResult {
            cipher_id: Some(0x009E),
            ..Default::default()
        };
        let mut body = Vec::new();
        let p = vec![0xFFu8; 128]; // 1024-bit prime
        body.extend_from_slice(&(p.len() as u16).to_be_bytes());
        body.extend_from_slice(&p);
        parse_server_key_exchange(&body, &mut result);
        assert_eq!(result.key_exchange.dh_bits, Some(1024));
    }

    #[test]
    fn server_key_exchange_yields_named_curve() {
        // ECDHE_RSA_WITH_AES_128_GCM: an EC key exchange, so the body is a
        // named-curve identifier rather than a DH prime.
        let mut result = HandshakeResult {
            cipher_id: Some(0xC02F),
            ..Default::default()
        };
        let body = vec![3, 0x00, 23]; // named_curve secp256r1
        parse_server_key_exchange(&body, &mut result);
        assert_eq!(result.key_exchange.curve_name.as_deref(), Some("secp256r1"));
        assert_eq!(result.key_exchange.curve_bits, Some(256));
    }

    #[test]
    fn handshake_messages_are_parsed_once_across_reads() {
        // A Certificate message delivered in two reads must yield one chain, not
        // two: the incremental cursor is what stops the duplication.
        let cert = vec![0x30, 0x82, 0x01, 0x02];
        let mut list = Vec::new();
        let len = cert.len();
        list.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        list.extend_from_slice(&cert);
        let mut body = Vec::new();
        let len = list.len();
        body.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        body.extend_from_slice(&list);
        let mut msg = vec![HS_CERTIFICATE];
        let len = body.len();
        msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        msg.extend_from_slice(&body);

        let mut result = HandshakeResult::default();
        let split = msg.len() - 2;
        // First read: the message is incomplete, so nothing is consumed.
        let mut parsed = parse_handshake_messages(&msg[..split], &mut result);
        assert_eq!(parsed, 0);
        assert!(result.certificates.is_empty());
        // Second read completes it.
        parsed += parse_handshake_messages(&msg[parsed..], &mut result);
        assert_eq!(parsed, msg.len());
        assert_eq!(result.certificates.len(), 1);
        // A final sweep over the already-parsed tail adds nothing.
        parse_handshake_messages(&msg[parsed..], &mut result);
        assert_eq!(result.certificates.len(), 1);
    }

    #[test]
    fn alpn_extension_yields_the_negotiated_protocol() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x01; 32]);
        body.push(0);
        body.extend_from_slice(&0xC02Fu16.to_be_bytes());
        body.push(0);
        let mut exts = Vec::new();
        exts.extend_from_slice(&EXT_ALPN.to_be_bytes());
        // ProtocolNameList { list_len = 3, name_len = 2, "h2" }
        exts.extend_from_slice(&5u16.to_be_bytes());
        exts.extend_from_slice(&[0x00, 0x03, 0x02, b'h', b'2']);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut result = HandshakeResult::default();
        parse_server_hello(&body, &mut result);
        assert_eq!(result.alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn certificate_message_splits_the_chain() {
        let leaf = vec![0x30, 0x82, 0x01];
        let inter = vec![0x30, 0x82, 0x02, 0x03];
        let mut list = Vec::new();
        for cert in [&leaf, &inter] {
            let len = cert.len();
            list.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
            list.extend_from_slice(cert);
        }
        let mut body = Vec::new();
        let len = list.len();
        body.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        body.extend_from_slice(&list);

        let mut result = HandshakeResult::default();
        parse_certificates(&body, &mut result);
        assert_eq!(result.certificates, vec![leaf, inter]);
    }

    #[test]
    fn ecc_equivalence_matches_nist_bands() {
        assert_eq!(ecc_equivalent_dh_bits(253), 2048);
        assert_eq!(ecc_equivalent_dh_bits(256), 3072);
        assert_eq!(ecc_equivalent_dh_bits(384), 7680);
        assert_eq!(ecc_equivalent_dh_bits(521), 15360);
    }

    #[test]
    fn truncated_input_never_panics() {
        let full = {
            let mut b = Vec::new();
            b.extend_from_slice(&0x0303u16.to_be_bytes());
            b.extend_from_slice(&[0xAB; 32]);
            b.push(0);
            b.extend_from_slice(&0xC02Fu16.to_be_bytes());
            b.push(0);
            b
        };
        for cut in 0..full.len() {
            let mut result = HandshakeResult::default();
            parse_server_hello(&full[..cut], &mut result);
            parse_certificates(&full[..cut], &mut result);
            parse_handshake_messages(&full[..cut], &mut result);
        }
    }

    #[test]
    fn a_non_tls_reply_is_recognised_rather_than_waited_out() {
        // Both guards must reject an HTTP response read as a record header.
        let http = b"HTTP/1.1 400 Bad Request\r\n";
        let content_type = http[0];
        let len = u16::from_be_bytes([http[3], http[4]]) as usize;
        assert!(
            !(CT_CHANGE_CIPHER_SPEC..=CT_HEARTBEAT).contains(&content_type),
            "'H' is not a TLS content type"
        );
        assert!(len > MAX_TLS_RECORD_SIZE, "and 0x{:04X} is not a legal record length", len);

        // A real handshake record passes both.
        let record = build_client_hello(&HelloOptions::new(TlsVersion::Tls12, None));
        let content_type = record[0];
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert!((CT_CHANGE_CIPHER_SPEC..=CT_HEARTBEAT).contains(&content_type));
        assert!(len <= MAX_TLS_RECORD_SIZE);
    }

    #[test]
    fn the_record_size_cap_is_reachable_by_a_u16() {
        // The previous bound was `1 << 16`, which a u16 length can never exceed,
        // so the guard was dead code.
        assert!(MAX_TLS_RECORD_SIZE < u16::MAX as usize);
    }

    #[test]
    fn ssl2_hello_uses_the_two_byte_header_form() {
        let hello = build_ssl2_client_hello();
        assert_eq!(hello[0] & 0x80, 0x80);
        let len = (u16::from_be_bytes([hello[0], hello[1]]) & 0x7fff) as usize;
        assert_eq!(hello.len(), 2 + len);
        assert_eq!(hello[2], 1, "MSG-CLIENT-HELLO");
    }
}

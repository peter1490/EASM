//! IANA TLS cipher suite registry, reduced to the properties a grader needs.
//!
//! `sslscan`, `testssl.sh` and SSL Labs all report a cipher by its IANA name plus
//! the four facts that decide whether it is safe: what does the key exchange, what
//! authenticates the server, what encrypts the record, and how the record is
//! integrity-protected. Everything this crate says about a cipher is derived from
//! this table, so a suite that is missing here is reported as unknown rather than
//! silently graded as fine.

/// How the session key is agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchange {
    /// TLS 1.3: key agreement is not part of the suite; it comes from `key_share`.
    Tls13,
    Rsa,
    Dhe,
    Ecdhe,
    /// Static (non-ephemeral) DH/ECDH — no forward secrecy.
    Dh,
    Ecdh,
    Psk,
    Srp,
    Krb5,
    /// No authentication of the peer at all.
    Anonymous,
    /// Deliberately weakened to comply with 1990s US export rules.
    Export,
    Null,
}

impl KeyExchange {
    /// Whether a compromise of the server's long-term key exposes past sessions.
    pub fn forward_secret(self) -> bool {
        matches!(self, KeyExchange::Tls13 | KeyExchange::Dhe | KeyExchange::Ecdhe)
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyExchange::Tls13 => "TLS 1.3",
            KeyExchange::Rsa => "RSA",
            KeyExchange::Dhe => "DHE",
            KeyExchange::Ecdhe => "ECDHE",
            KeyExchange::Dh => "DH",
            KeyExchange::Ecdh => "ECDH",
            KeyExchange::Psk => "PSK",
            KeyExchange::Srp => "SRP",
            KeyExchange::Krb5 => "KRB5",
            KeyExchange::Anonymous => "anon",
            KeyExchange::Export => "EXPORT",
            KeyExchange::Null => "NULL",
        }
    }
}

/// The bulk encryption algorithm, and the two facts that decide its fate:
/// block size (SWEET32) and whether it is authenticated (AEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    Null,
    Rc4,
    Rc2,
    Des,
    DesCbc40,
    TripleDes,
    Idea,
    Seed,
    AesCbc,
    AesGcm,
    AesCcm,
    Camellia,
    Aria,
    ChaCha20Poly1305,
}

impl Encryption {
    /// AEAD ciphers integrate authentication; everything else needs a MAC and is
    /// exposed to the padding-oracle family (LUCKY13, Zombie POODLE, …).
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Encryption::AesGcm | Encryption::AesCcm | Encryption::ChaCha20Poly1305
        )
    }

    pub fn is_cbc(self) -> bool {
        matches!(
            self,
            Encryption::AesCbc
                | Encryption::TripleDes
                | Encryption::Des
                | Encryption::DesCbc40
                | Encryption::Idea
                | Encryption::Seed
                | Encryption::Camellia
                | Encryption::Rc2
        )
    }

    /// 64-bit block ciphers are birthday-bound at ~32 GB of traffic — SWEET32
    /// (CVE-2016-2183).
    pub fn is_64bit_block(self) -> bool {
        matches!(
            self,
            Encryption::TripleDes | Encryption::Des | Encryption::DesCbc40 | Encryption::Idea | Encryption::Rc2
        )
    }

    pub fn is_stream(self) -> bool {
        matches!(self, Encryption::Rc4)
    }

    pub fn label(self) -> &'static str {
        match self {
            Encryption::Null => "NULL",
            Encryption::Rc4 => "RC4",
            Encryption::Rc2 => "RC2",
            Encryption::Des => "DES",
            Encryption::DesCbc40 => "DES40",
            Encryption::TripleDes => "3DES",
            Encryption::Idea => "IDEA",
            Encryption::Seed => "SEED",
            Encryption::AesCbc => "AES-CBC",
            Encryption::AesGcm => "AES-GCM",
            Encryption::AesCcm => "AES-CCM",
            Encryption::Camellia => "Camellia",
            Encryption::Aria => "ARIA",
            Encryption::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CipherSuite {
    pub id: u16,
    pub name: &'static str,
    pub kx: KeyExchange,
    pub enc: Encryption,
    /// Effective symmetric key size in bits. Export suites report their *real*
    /// strength (40/56), not the nominal one, which is what makes them score 20%
    /// in the SSL Labs cipher-strength band.
    pub bits: u16,
}

impl CipherSuite {
    /// Suites nobody should still be negotiating. Drives `weak_cipher_suite`.
    pub fn is_weak(&self) -> bool {
        self.bits < 128
            || matches!(self.enc, Encryption::Null | Encryption::Rc4 | Encryption::Rc2)
            || matches!(
                self.kx,
                KeyExchange::Anonymous | KeyExchange::Export | KeyExchange::Null
            )
            || self.enc.is_64bit_block()
    }

    /// A suite so broken that its presence alone caps the grade at F.
    pub fn is_insecure(&self) -> bool {
        matches!(self.enc, Encryption::Null)
            || matches!(
                self.kx,
                KeyExchange::Anonymous | KeyExchange::Export | KeyExchange::Null
            )
            || self.bits < 56
    }

    pub fn hex(&self) -> String {
        format!("0x{:04X}", self.id)
    }
}

macro_rules! suite {
    ($id:expr, $name:expr, $kx:ident, $enc:ident, $bits:expr) => {
        CipherSuite {
            id: $id,
            name: $name,
            kx: KeyExchange::$kx,
            enc: Encryption::$enc,
            bits: $bits,
        }
    };
}

/// The suites worth offering during enumeration, ordered strongest-first so a
/// server with its own preference still gets asked about the good ones.
///
/// This covers the whole of what OpenSSL, GnuTLS, NSS, Schannel and JSSE will
/// negotiate in practice, plus every historically-broken family a scanner is
/// expected to report on (EXPORT, anon, NULL, RC4, DES, 3DES, IDEA, SEED).
pub const CIPHER_SUITES: &[CipherSuite] = &[
    // ---- TLS 1.3 ----------------------------------------------------------
    suite!(0x1301, "TLS_AES_128_GCM_SHA256", Tls13, AesGcm, 128),
    suite!(0x1302, "TLS_AES_256_GCM_SHA384", Tls13, AesGcm, 256),
    suite!(0x1303, "TLS_CHACHA20_POLY1305_SHA256", Tls13, ChaCha20Poly1305, 256),
    suite!(0x1304, "TLS_AES_128_CCM_SHA256", Tls13, AesCcm, 128),
    suite!(0x1305, "TLS_AES_128_CCM_8_SHA256", Tls13, AesCcm, 128),
    // ---- ECDHE AEAD -------------------------------------------------------
    suite!(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Ecdhe, AesGcm, 128),
    suite!(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Ecdhe, AesGcm, 256),
    suite!(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Ecdhe, AesGcm, 128),
    suite!(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Ecdhe, AesGcm, 256),
    suite!(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Ecdhe, ChaCha20Poly1305, 256),
    suite!(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Ecdhe, ChaCha20Poly1305, 256),
    suite!(0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", Ecdhe, AesCcm, 128),
    suite!(0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", Ecdhe, AesCcm, 256),
    suite!(0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", Ecdhe, Aria, 128),
    suite!(0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", Ecdhe, Aria, 256),
    suite!(0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", Ecdhe, Aria, 128),
    suite!(0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", Ecdhe, Aria, 256),
    suite!(0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", Ecdhe, Camellia, 128),
    suite!(0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", Ecdhe, Camellia, 256),
    suite!(0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", Ecdhe, Camellia, 128),
    suite!(0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", Ecdhe, Camellia, 256),
    // ---- DHE AEAD ---------------------------------------------------------
    suite!(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", Dhe, AesGcm, 128),
    suite!(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", Dhe, AesGcm, 256),
    suite!(0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", Dhe, AesGcm, 128),
    suite!(0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", Dhe, AesGcm, 256),
    suite!(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Dhe, ChaCha20Poly1305, 256),
    suite!(0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM", Dhe, AesCcm, 128),
    suite!(0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM", Dhe, AesCcm, 256),
    // ---- ECDHE CBC (no AEAD; LUCKY13 family) -------------------------------
    suite!(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", Ecdhe, AesCbc, 128),
    suite!(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", Ecdhe, AesCbc, 256),
    suite!(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", Ecdhe, AesCbc, 128),
    suite!(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", Ecdhe, AesCbc, 256),
    suite!(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", Ecdhe, AesCbc, 128),
    suite!(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", Ecdhe, AesCbc, 256),
    suite!(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Ecdhe, AesCbc, 128),
    suite!(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", Ecdhe, AesCbc, 256),
    // ---- DHE CBC ----------------------------------------------------------
    suite!(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", Dhe, AesCbc, 128),
    suite!(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", Dhe, AesCbc, 256),
    suite!(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", Dhe, AesCbc, 128),
    suite!(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", Dhe, AesCbc, 256),
    suite!(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", Dhe, AesCbc, 128),
    suite!(0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", Dhe, AesCbc, 256),
    suite!(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", Dhe, AesCbc, 128),
    suite!(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", Dhe, AesCbc, 256),
    suite!(0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", Dhe, Camellia, 128),
    suite!(0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", Dhe, Camellia, 256),
    suite!(0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", Dhe, Seed, 128),
    // ---- Static RSA key exchange (no forward secrecy; ROBOT surface) --------
    suite!(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", Rsa, AesGcm, 128),
    suite!(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", Rsa, AesGcm, 256),
    suite!(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", Rsa, AesCbc, 128),
    suite!(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", Rsa, AesCbc, 256),
    suite!(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", Rsa, AesCbc, 128),
    suite!(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", Rsa, AesCbc, 256),
    suite!(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", Rsa, Camellia, 128),
    suite!(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", Rsa, Camellia, 256),
    suite!(0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", Rsa, Seed, 128),
    suite!(0xC09C, "TLS_RSA_WITH_AES_128_CCM", Rsa, AesCcm, 128),
    suite!(0xC09D, "TLS_RSA_WITH_AES_256_CCM", Rsa, AesCcm, 256),
    // ---- Static (non-ephemeral) DH/ECDH: no forward secrecy -----------------
    suite!(0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", Ecdh, AesCbc, 128),
    suite!(0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", Ecdh, AesCbc, 256),
    suite!(0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", Ecdh, AesCbc, 128),
    suite!(0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", Ecdh, AesCbc, 256),
    suite!(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", Dh, AesCbc, 128),
    suite!(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", Dh, AesCbc, 256),
    // ---- SWEET32: 64-bit block ciphers -------------------------------------
    suite!(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", Ecdhe, TripleDes, 112),
    suite!(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", Ecdhe, TripleDes, 112),
    suite!(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", Dhe, TripleDes, 112),
    suite!(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", Dhe, TripleDes, 112),
    suite!(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Rsa, TripleDes, 112),
    suite!(0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA", Rsa, Idea, 128),
    suite!(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", Rsa, Des, 56),
    suite!(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", Dhe, Des, 56),
    suite!(0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", Dhe, Des, 56),
    // ---- RC4 ---------------------------------------------------------------
    suite!(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", Ecdhe, Rc4, 128),
    suite!(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", Ecdhe, Rc4, 128),
    suite!(0x0005, "TLS_RSA_WITH_RC4_128_SHA", Rsa, Rc4, 128),
    suite!(0x0004, "TLS_RSA_WITH_RC4_128_MD5", Rsa, Rc4, 128),
    suite!(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", Anonymous, Rc4, 128),
    // ---- Anonymous (no server authentication at all) ------------------------
    suite!(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", Anonymous, AesCbc, 128),
    suite!(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA", Anonymous, AesCbc, 256),
    suite!(0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA", Anonymous, Rc4, 128),
    suite!(0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", Anonymous, TripleDes, 112),
    suite!(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", Anonymous, AesCbc, 128),
    suite!(0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", Anonymous, AesCbc, 256),
    suite!(0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", Anonymous, TripleDes, 112),
    // ---- EXPORT-grade: FREAK (RSA) and LOGJAM (DH) ---------------------------
    suite!(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Export, Rc4, 40),
    suite!(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", Export, Rc2, 40),
    suite!(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", Export, DesCbc40, 40),
    suite!(0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", Export, DesCbc40, 40),
    suite!(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", Export, DesCbc40, 40),
    suite!(0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", Export, Rc4, 40),
    suite!(0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", Export, DesCbc40, 40),
    suite!(0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", Export, Des, 56),
    suite!(0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", Export, Rc4, 56),
    // ---- NULL encryption: cleartext records ---------------------------------
    suite!(0x0001, "TLS_RSA_WITH_NULL_MD5", Rsa, Null, 0),
    suite!(0x0002, "TLS_RSA_WITH_NULL_SHA", Rsa, Null, 0),
    suite!(0x003B, "TLS_RSA_WITH_NULL_SHA256", Rsa, Null, 0),
    suite!(0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", Ecdhe, Null, 0),
    suite!(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA", Ecdhe, Null, 0),
];

pub fn lookup(id: u16) -> Option<&'static CipherSuite> {
    CIPHER_SUITES.iter().find(|c| c.id == id)
}

/// Name for a suite we offered but do not have in the table — reported as the raw
/// code point rather than guessed at.
pub fn name_for(id: u16) -> String {
    lookup(id)
        .map(|c| c.name.to_string())
        .unwrap_or_else(|| format!("UNKNOWN_CIPHER_0x{:04X}", id))
}

/// TLS 1.3 renegotiated the suite namespace: only the five `TLS_*_SHA*` suites are
/// valid there, and offering the TLS 1.2 list to a 1.3 server is what makes
/// enumeration report nonsense.
pub fn tls13_suite_ids() -> Vec<u16> {
    CIPHER_SUITES
        .iter()
        .filter(|c| c.kx == KeyExchange::Tls13)
        .map(|c| c.id)
        .collect()
}

pub fn legacy_suite_ids() -> Vec<u16> {
    CIPHER_SUITES
        .iter()
        .filter(|c| c.kx != KeyExchange::Tls13)
        .map(|c| c.id)
        .collect()
}

/// SSLv2 used three-byte cipher identifiers of its own. Only needed to build a
/// DROWN probe, so the list is the historical one in full.
pub const SSL2_CIPHERS: &[(u32, &str, u16)] = &[
    (0x010080, "SSL2_RC4_128_WITH_MD5", 128),
    (0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5", 40),
    (0x030080, "SSL2_RC2_128_CBC_WITH_MD5", 128),
    (0x040080, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5", 40),
    (0x050080, "SSL2_IDEA_128_CBC_WITH_MD5", 128),
    (0x060040, "SSL2_DES_64_CBC_WITH_MD5", 56),
    (0x0700C0, "SSL2_DES_192_EDE3_CBC_WITH_MD5", 112),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for suite in CIPHER_SUITES {
            assert!(seen.insert(suite.id), "duplicate suite id {:#06x}", suite.id);
        }
    }

    #[test]
    fn forward_secrecy_tracks_key_exchange() {
        assert!(lookup(0xC02F).unwrap().kx.forward_secret());
        assert!(lookup(0x1301).unwrap().kx.forward_secret());
        assert!(!lookup(0x009C).unwrap().kx.forward_secret());
        assert!(!lookup(0xC00E).unwrap().kx.forward_secret());
    }

    #[test]
    fn broken_families_are_flagged() {
        // EXPORT, anon and NULL are all "insecure", not merely "weak".
        assert!(lookup(0x0003).unwrap().is_insecure());
        assert!(lookup(0x0034).unwrap().is_insecure());
        assert!(lookup(0x0001).unwrap().is_insecure());
        // 3DES is weak (SWEET32) but not an automatic F.
        assert!(lookup(0x000A).unwrap().is_weak());
        assert!(!lookup(0x000A).unwrap().is_insecure());
        // A modern suite is neither.
        assert!(!lookup(0xC02F).unwrap().is_weak());
    }

    #[test]
    fn tls13_suites_are_separated_from_legacy() {
        assert_eq!(tls13_suite_ids().len(), 5);
        assert!(!legacy_suite_ids().contains(&0x1301));
    }
}

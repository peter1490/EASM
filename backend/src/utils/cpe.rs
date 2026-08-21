//! CPE 2.3 parsing and formatting.
//!
//! A CPE 2.3 *formatted string* names a product in NVD's vocabulary:
//!
//! ```text
//! cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//! cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
//! ```
//!
//! Our fingerprint signatures carry the *base* of that string —
//! `cpe:2.3:a:apache:http_server` — because a signature knows the vendor and
//! product but not the version until it matches something. This module turns
//! that base plus a detected version into the query string NVD expects, which
//! is the difference between asking NVD about the right product and guessing a
//! product token from a display name.
//!
//! Two component values are special and must not be quoted:
//! `*` (ANY) and `-` (NA).

use std::fmt;

/// Which kind of thing the CPE names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpePart {
    /// Application (`a`) — web servers, CMSes, libraries.
    Application,
    /// Operating system (`o`) — appliance firmware such as FortiOS or PAN-OS.
    OperatingSystem,
    /// Hardware (`h`).
    Hardware,
}

impl CpePart {
    fn as_char(self) -> char {
        match self {
            CpePart::Application => 'a',
            CpePart::OperatingSystem => 'o',
            CpePart::Hardware => 'h',
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "a" => Some(CpePart::Application),
            "o" => Some(CpePart::OperatingSystem),
            "h" => Some(CpePart::Hardware),
            _ => None,
        }
    }
}

impl fmt::Display for CpePart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

/// A parsed CPE 2.3 name. Only the components we actually query on are kept
/// individually; the rest are preserved verbatim so a round-trip is lossless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpe {
    pub part: CpePart,
    pub vendor: String,
    pub product: String,
    /// `None` when the source string was a version-less base.
    pub version: Option<String>,
    /// Components 6..12 (update, edition, language, sw_edition, target_sw,
    /// target_hw, other), defaulting to `*`.
    tail: [String; 7],
}

/// Characters that carry meaning in a CPE formatted string and therefore have
/// to be backslash-escaped inside a component value.
const MUST_ESCAPE: &[char] = &[
    ':', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '+', ',', '/', ';', '<', '=', '>', '@', '[',
    ']', '^', '`', '{', '|', '}', '~',
];

/// Quote a component value for the formatted-string binding.
/// `*` and `-` pass through untouched: they are the ANY and NA logical values.
pub fn quote_component(value: &str) -> String {
    if value == "*" || value == "-" {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if MUST_ESCAPE.contains(&c) || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Reverse `quote_component`.
fn unquote_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Split a CPE formatted string on unescaped `:` only, so that a component
/// containing `\:` is not torn in half.
fn split_unescaped(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            current.push('\\');
            current.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ':' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

impl Cpe {
    /// Parse a CPE 2.3 formatted string. Accepts both a full 13-field name and
    /// the abbreviated `cpe:2.3:a:vendor:product` base our signatures use.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts = split_unescaped(s);
        // ["cpe", "2.3", part, vendor, product, ...]
        if parts.len() < 5 {
            return None;
        }
        if !parts[0].eq_ignore_ascii_case("cpe") || parts[1] != "2.3" {
            return None;
        }
        let part = CpePart::from_str(&parts[2].to_ascii_lowercase())?;
        let vendor = unquote_component(&parts[3]);
        let product = unquote_component(&parts[4]);
        if vendor.is_empty() || product.is_empty() {
            return None;
        }

        let version = match parts.get(5).map(|v| unquote_component(v)) {
            Some(v) if v != "*" && !v.is_empty() => Some(v),
            _ => None,
        };

        let mut tail: [String; 7] = Default::default();
        for (i, slot) in tail.iter_mut().enumerate() {
            *slot = parts
                .get(6 + i)
                .map(|v| unquote_component(v))
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "*".to_string());
        }

        Some(Cpe {
            part,
            vendor,
            product,
            version,
            tail,
        })
    }

    /// Build an application CPE from a vendor and product directly.
    pub fn application(vendor: &str, product: &str) -> Self {
        Cpe {
            part: CpePart::Application,
            vendor: vendor.to_string(),
            product: product.to_string(),
            version: None,
            tail: std::array::from_fn(|_| "*".to_string()),
        }
    }

    /// This CPE with `version` substituted in. Used to turn a signature's
    /// version-less base into a concrete name once a version is detected.
    pub fn with_version(&self, version: &str) -> Self {
        Cpe {
            version: Some(version.to_string()),
            ..self.clone()
        }
    }

    /// The full 13-field CPE 2.3 formatted string.
    pub fn to_formatted_string(&self) -> String {
        let version = self.version.as_deref().unwrap_or("*");
        let mut out = format!(
            "cpe:2.3:{}:{}:{}:{}",
            self.part,
            quote_component(&self.vendor),
            quote_component(&self.product),
            quote_component(version),
        );
        for t in &self.tail {
            out.push(':');
            out.push_str(&quote_component(t));
        }
        out
    }

    /// The `vendor:product` pair, lowercased — the key we use to decide whether
    /// an NVD `cpeMatch` refers to the product we actually detected.
    pub fn vendor_product_key(&self) -> (String, String) {
        (self.vendor.to_lowercase(), self.product.to_lowercase())
    }

    /// True when this CPE names the same product as `other`, ignoring version.
    /// A `*` vendor on either side matches any vendor, which is what NVD
    /// returns for products whose vendor it has not pinned down.
    pub fn same_product_as(&self, other: &Cpe) -> bool {
        if self.part != other.part {
            return false;
        }
        if !self.product.eq_ignore_ascii_case(&other.product) {
            return false;
        }
        self.vendor == "*"
            || other.vendor == "*"
            || self.vendor.eq_ignore_ascii_case(&other.vendor)
    }
}

impl fmt::Display for Cpe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_formatted_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_abbreviated_base_our_signatures_use() {
        let cpe = Cpe::parse("cpe:2.3:a:apache:http_server").unwrap();
        assert_eq!(cpe.part, CpePart::Application);
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, None);
        assert_eq!(
            cpe.to_formatted_string(),
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn parses_a_full_name_and_round_trips_it() {
        let s = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";
        let cpe = Cpe::parse(s).unwrap();
        assert_eq!(cpe.version.as_deref(), Some("2.4.49"));
        assert_eq!(cpe.to_formatted_string(), s);
    }

    #[test]
    fn substitutes_a_detected_version() {
        let base = Cpe::parse("cpe:2.3:a:openssl:openssl").unwrap();
        assert_eq!(
            base.with_version("1.0.2k").to_formatted_string(),
            "cpe:2.3:a:openssl:openssl:1.0.2k:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn supports_os_and_hardware_parts() {
        // Appliance firmware lives under part `o`, which an `a`-only query
        // can never match — FortiOS, PAN-OS and NetScaler all sit here.
        let cpe = Cpe::parse("cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.part, CpePart::OperatingSystem);
        assert_eq!(cpe.product, "fortios");
        assert_eq!(
            Cpe::parse("cpe:2.3:h:cisco:asa_5500").unwrap().part,
            CpePart::Hardware
        );
    }

    #[test]
    fn escapes_and_unescapes_special_characters() {
        // Real dictionary entries contain escaped dots and colons, e.g.
        // cpe:2.3:a:vercel:next.js — the dot is legal unquoted, but a colon
        // inside a component must survive a parse/format round trip.
        let cpe = Cpe::parse(r"cpe:2.3:a:foo:bar\:baz:1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.product, "bar:baz");
        assert_eq!(
            cpe.to_formatted_string(),
            r"cpe:2.3:a:foo:bar\:baz:1.0:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn keeps_dots_in_product_names_unquoted() {
        let cpe = Cpe::parse("cpe:2.3:a:vercel:next.js").unwrap();
        assert_eq!(cpe.product, "next.js");
        assert!(cpe.to_formatted_string().contains(":next.js:"));
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(Cpe::parse("").is_none());
        assert!(Cpe::parse("nginx").is_none());
        assert!(Cpe::parse("cpe:2.3:a:apache").is_none()); // no product
        assert!(Cpe::parse("cpe:2.2:a:apache:http_server").is_none()); // wrong binding
        assert!(Cpe::parse("cpe:2.3:x:apache:http_server").is_none()); // bad part
    }

    #[test]
    fn product_identity_ignores_version_and_wildcard_vendors() {
        let detected = Cpe::parse("cpe:2.3:a:apache:http_server:2.4.49").unwrap();
        let from_nvd = Cpe::parse("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*").unwrap();
        assert!(detected.same_product_as(&from_nvd));

        let wildcard_vendor = Cpe::parse("cpe:2.3:a:*:http_server:*").unwrap();
        assert!(detected.same_product_as(&wildcard_vendor));

        let other = Cpe::parse("cpe:2.3:a:nginx:nginx:*").unwrap();
        assert!(!detected.same_product_as(&other));

        // Same product name, different part — an OS CPE is not an app CPE.
        let os = Cpe::parse("cpe:2.3:o:apache:http_server:*").unwrap();
        assert!(!detected.same_product_as(&os));
    }
}

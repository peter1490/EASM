//! SPF, DMARC, MTA-STS, TLS-RPT and BIMI record analysis.
//!
//! The parsing here is deliberately separate from the DNS I/O in [`super::dns_scan`]
//! so the RFC rules can be tested exhaustively without a resolver. What it checks
//! is what MXToolbox, dmarcian, internet.nl and Hardenize check, and the section
//! references are to the RFCs those tools are implementing:
//!
//! * SPF — RFC 7208. The two rules everyone gets wrong are the ten-DNS-lookup
//!   processing limit (§4.6.4), which is a hard `permerror` and silently breaks
//!   mail delivery, and `ptr` (§5.5), deprecated because it is slow and spoofable.
//! * DMARC — RFC 7489.
//! * MTA-STS — RFC 8461. TLS-RPT — RFC 8460. BIMI — draft-blank-ietf-bimi.

use serde::{Deserialize, Serialize};

/// The qualifier on an SPF mechanism, which is what decides what happens to
/// non-matching mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpfQualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl SpfQualifier {
    fn from_char(c: char) -> Self {
        match c {
            '-' => SpfQualifier::Fail,
            '~' => SpfQualifier::SoftFail,
            '?' => SpfQualifier::Neutral,
            _ => SpfQualifier::Pass,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SpfQualifier::Pass => "+all (pass)",
            SpfQualifier::Fail => "-all (hard fail)",
            SpfQualifier::SoftFail => "~all (soft fail)",
            SpfQualifier::Neutral => "?all (neutral)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfMechanism {
    pub qualifier: SpfQualifier,
    pub name: String,
    pub value: Option<String>,
    /// Whether evaluating this mechanism costs one of the ten permitted lookups.
    pub costs_lookup: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpfAnalysis {
    pub present: bool,
    pub record: Option<String>,
    /// More than one `v=spf1` record is a permanent error (RFC 7208 §4.5): a
    /// receiver must reject the whole policy, so the domain has *no* SPF.
    pub multiple_records: bool,
    pub mechanisms: Vec<SpfMechanism>,
    pub all_qualifier: Option<SpfQualifier>,
    pub redirect: Option<String>,
    /// DNS lookups consumed, counting recursively through `include:`/`redirect=`.
    pub dns_lookups: u32,
    pub exceeds_lookup_limit: bool,
    pub uses_ptr: bool,
    pub includes: Vec<String>,
    pub issues: Vec<String>,
    pub valid: bool,
}

/// RFC 7208 §4.6.4 — the number of DNS-querying terms a record may use.
pub const SPF_MAX_DNS_LOOKUPS: u32 = 10;

/// Parse one `v=spf1` record into its terms, without following includes.
pub fn parse_spf_record(record: &str) -> SpfAnalysis {
    let cleaned: String = record.chars().filter(|c| *c != '"').collect();
    let mut analysis = SpfAnalysis {
        present: true,
        record: Some(cleaned.trim().to_string()),
        valid: true,
        ..Default::default()
    };

    for raw in cleaned.split_whitespace().skip(1) {
        let (qualifier, term) = match raw.chars().next() {
            Some(c @ ('+' | '-' | '~' | '?')) => (SpfQualifier::from_char(c), &raw[1..]),
            _ => (SpfQualifier::Pass, raw),
        };
        if term.is_empty() {
            continue;
        }
        let lower = term.to_ascii_lowercase();

        // Modifiers use `=`; mechanisms use `:` or nothing.
        if let Some(target) = lower.strip_prefix("redirect=") {
            analysis.redirect = Some(target.to_string());
            analysis.dns_lookups += 1;
            analysis.mechanisms.push(SpfMechanism {
                qualifier,
                name: "redirect".into(),
                value: Some(target.to_string()),
                costs_lookup: true,
            });
            continue;
        }
        if lower.starts_with("exp=") {
            continue; // `exp` is only evaluated on failure and does not count.
        }

        let (name, value) = match lower.split_once(':') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => match lower.split_once('/') {
                // `a/24` and `mx/24` are the mechanism with a CIDR length.
                Some((n, _)) => (n.to_string(), None),
                None => (lower.clone(), None),
            },
        };

        let costs_lookup = matches!(name.as_str(), "include" | "a" | "mx" | "ptr" | "exists");
        if costs_lookup {
            analysis.dns_lookups += 1;
        }
        if name == "include" {
            if let Some(target) = &value {
                analysis.includes.push(target.split('/').next().unwrap_or(target).to_string());
            }
        }
        if name == "ptr" {
            analysis.uses_ptr = true;
        }
        if name == "all" {
            analysis.all_qualifier = Some(qualifier);
        }

        analysis.mechanisms.push(SpfMechanism {
            qualifier,
            name,
            value,
            costs_lookup,
        });
    }

    analysis
}

/// Grade a fully resolved SPF policy. `total_lookups` is the recursive count the
/// caller obtained by following every `include:` and `redirect=`.
pub fn evaluate_spf(analysis: &mut SpfAnalysis, total_lookups: u32) {
    analysis.dns_lookups = total_lookups;
    analysis.exceeds_lookup_limit = total_lookups > SPF_MAX_DNS_LOOKUPS;

    if analysis.multiple_records {
        analysis.valid = false;
        analysis.issues.push(
            "More than one v=spf1 record is published. RFC 7208 §4.5 makes this a permanent \
             error, so receivers treat the domain as having no SPF policy at all."
                .to_string(),
        );
    }

    if analysis.exceeds_lookup_limit {
        analysis.valid = false;
        analysis.issues.push(format!(
            "The policy needs {} DNS lookups, above the limit of {} (RFC 7208 §4.6.4). Receivers \
             return permerror and the policy stops being applied.",
            total_lookups, SPF_MAX_DNS_LOOKUPS
        ));
    } else if total_lookups >= SPF_MAX_DNS_LOOKUPS {
        analysis.issues.push(format!(
            "The policy uses {} of the {} permitted DNS lookups; adding one more provider will \
             break it.",
            total_lookups, SPF_MAX_DNS_LOOKUPS
        ));
    }

    match analysis.all_qualifier {
        Some(SpfQualifier::Pass) => {
            analysis.valid = false;
            analysis.issues.push(
                "The record ends in '+all', which authorises every host on the internet to send \
                 mail as this domain. It is equivalent to publishing no SPF record."
                    .to_string(),
            );
        }
        Some(SpfQualifier::Neutral) => analysis.issues.push(
            "The record ends in '?all' (neutral), which asserts nothing about unauthorised \
             senders. Use '-all' once the authorised list is complete."
                .to_string(),
        ),
        Some(SpfQualifier::SoftFail) => analysis.issues.push(
            "The record ends in '~all' (soft fail). Mail from unauthorised hosts is accepted and \
             merely marked. Move to '-all' once DMARC reports show no legitimate sources failing."
                .to_string(),
        ),
        Some(SpfQualifier::Fail) => {}
        None => {
            if analysis.redirect.is_none() {
                analysis.issues.push(
                    "The record has no 'all' mechanism and no 'redirect', so unmatched mail gets \
                     a neutral result — the same outcome as having no policy."
                        .to_string(),
                );
            }
        }
    }

    if analysis.uses_ptr {
        analysis.issues.push(
            "The record uses the 'ptr' mechanism, which RFC 7208 §5.5 deprecates: it is slow, \
             relies on reverse DNS an attacker may control, and some receivers ignore it."
                .to_string(),
        );
    }
}

// ---------------------------------------------------------------------------
// DMARC
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DmarcAnalysis {
    pub present: bool,
    pub record: Option<String>,
    pub multiple_records: bool,
    /// `p=` — none, quarantine or reject.
    pub policy: Option<String>,
    /// `sp=` — the policy for subdomains, defaulting to `p` when absent.
    pub subdomain_policy: Option<String>,
    /// `pct=` — the share of failing mail the policy is applied to.
    pub percentage: u8,
    pub aggregate_reports: Vec<String>,
    pub forensic_reports: Vec<String>,
    /// `adkim=` / `aspf=` — `r` (relaxed, default) or `s` (strict).
    pub dkim_alignment: String,
    pub spf_alignment: String,
    pub issues: Vec<String>,
    pub valid: bool,
    /// True only for `p=reject` at 100%, which is the point of deploying DMARC.
    pub enforced: bool,
}

pub fn parse_dmarc_record(record: &str) -> DmarcAnalysis {
    let cleaned: String = record.chars().filter(|c| *c != '"').collect();
    let mut analysis = DmarcAnalysis {
        present: true,
        record: Some(cleaned.trim().to_string()),
        percentage: 100,
        dkim_alignment: "r".to_string(),
        spf_alignment: "r".to_string(),
        valid: true,
        ..Default::default()
    };

    for tag in cleaned.split(';') {
        let tag = tag.trim();
        let Some((key, value)) = tag.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "p" => analysis.policy = Some(value.to_ascii_lowercase()),
            "sp" => analysis.subdomain_policy = Some(value.to_ascii_lowercase()),
            "pct" => {
                if let Ok(pct) = value.parse::<u8>() {
                    analysis.percentage = pct.min(100);
                }
            }
            "rua" => analysis.aggregate_reports = split_report_uris(value),
            "ruf" => analysis.forensic_reports = split_report_uris(value),
            "adkim" => analysis.dkim_alignment = value.to_ascii_lowercase(),
            "aspf" => analysis.spf_alignment = value.to_ascii_lowercase(),
            _ => {}
        }
    }
    analysis
}

fn split_report_uris(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|uri| uri.trim().split('!').next().unwrap_or("").trim().to_string())
        .filter(|uri| !uri.is_empty())
        .collect()
}

pub fn evaluate_dmarc(analysis: &mut DmarcAnalysis) {
    if analysis.multiple_records {
        analysis.valid = false;
        analysis.issues.push(
            "More than one DMARC record is published at _dmarc. RFC 7489 §6.6.3 requires \
             receivers to ignore the domain's policy entirely when this happens."
                .to_string(),
        );
    }

    match analysis.policy.as_deref() {
        None => {
            analysis.valid = false;
            analysis.issues.push(
                "The record has no 'p=' tag. It is syntactically invalid and receivers will \
                 discard it."
                    .to_string(),
            );
        }
        Some("none") => analysis.issues.push(
            "The policy is 'p=none', which only requests reports — no spoofed mail is \
             quarantined or rejected. Move to 'quarantine' and then 'reject' once reports show \
             all legitimate sources aligning."
                .to_string(),
        ),
        Some("quarantine") => analysis.issues.push(
            "The policy is 'p=quarantine'. Spoofed mail reaches the spam folder rather than \
             being rejected; 'p=reject' is the end state."
                .to_string(),
        ),
        Some("reject") => {}
        Some(other) => {
            analysis.valid = false;
            analysis
                .issues
                .push(format!("'p={}' is not a valid DMARC policy.", other));
        }
    }

    if analysis.percentage < 100 {
        analysis.issues.push(format!(
            "'pct={}' applies the policy to only {}% of failing mail; the rest is delivered \
             untouched.",
            analysis.percentage, analysis.percentage
        ));
    }

    if analysis.aggregate_reports.is_empty() {
        analysis.issues.push(
            "No 'rua=' address is set, so no aggregate reports are received. Without them there \
             is no way to see who is sending as this domain before tightening the policy."
                .to_string(),
        );
    }

    // A strict parent policy with a lax subdomain policy leaves every subdomain
    // spoofable — the exact gap attackers look for.
    if let (Some(p), Some(sp)) = (analysis.policy.as_deref(), analysis.subdomain_policy.as_deref()) {
        let rank = |policy: &str| match policy {
            "reject" => 2,
            "quarantine" => 1,
            _ => 0,
        };
        if rank(sp) < rank(p) {
            analysis.issues.push(format!(
                "The subdomain policy 'sp={}' is weaker than 'p={}', so subdomains stay \
                 spoofable even though the apex is protected.",
                sp, p
            ));
        }
    }

    analysis.enforced =
        analysis.policy.as_deref() == Some("reject") && analysis.percentage == 100 && analysis.valid;
}

// ---------------------------------------------------------------------------
// MTA-STS, TLS-RPT, BIMI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtaStsAnalysis {
    /// The `_mta-sts` TXT record announcing that a policy exists.
    pub dns_record_present: bool,
    pub policy_id: Option<String>,
    /// The policy itself, fetched over HTTPS from `mta-sts.<domain>`.
    pub policy_fetched: bool,
    /// `enforce`, `testing` or `none`.
    pub mode: Option<String>,
    pub mx_patterns: Vec<String>,
    pub max_age: Option<u64>,
    pub issues: Vec<String>,
}

pub fn parse_mta_sts_txt(record: &str) -> Option<String> {
    let cleaned: String = record.chars().filter(|c| *c != '"').collect();
    if !cleaned.to_ascii_lowercase().contains("v=stsv1") {
        return None;
    }
    for tag in cleaned.split(';') {
        if let Some((key, value)) = tag.trim().split_once('=') {
            if key.trim().eq_ignore_ascii_case("id") {
                return Some(value.trim().to_string());
            }
        }
    }
    Some(String::new())
}

/// Parse the `mta-sts.txt` policy body (RFC 8461 §3.2): a sequence of
/// `key: value` lines, with `mx` repeated once per pattern.
pub fn parse_mta_sts_policy(body: &str, analysis: &mut MtaStsAnalysis) {
    for line in body.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "mode" => analysis.mode = Some(value.to_ascii_lowercase()),
            "mx" => analysis.mx_patterns.push(value.to_ascii_lowercase()),
            "max_age" => analysis.max_age = value.parse().ok(),
            _ => {}
        }
    }
    analysis.policy_fetched = analysis.mode.is_some();

    match analysis.mode.as_deref() {
        Some("enforce") => {}
        Some("testing") => analysis.issues.push(
            "The MTA-STS policy is in 'testing' mode: failures are reported but mail is still \
             delivered over an unauthenticated channel."
                .to_string(),
        ),
        Some("none") => analysis.issues.push(
            "The MTA-STS policy mode is 'none', which disables the policy.".to_string(),
        ),
        Some(other) => analysis
            .issues
            .push(format!("'{}' is not a valid MTA-STS mode.", other)),
        None => {
            if analysis.dns_record_present {
                analysis.issues.push(
                    "The _mta-sts TXT record announces a policy, but no valid policy is served at \
                     https://mta-sts.<domain>/.well-known/mta-sts.txt. Senders fall back to \
                     opportunistic TLS."
                        .to_string(),
                );
            }
        }
    }
    // RFC 8461 recommends at least 604800 seconds (one week).
    if let Some(max_age) = analysis.max_age {
        if max_age < 86_400 {
            analysis.issues.push(format!(
                "max_age is {} seconds. RFC 8461 §3.2 recommends at least a week (604800) so a \
                 cached policy survives a DNS outage.",
                max_age
            ));
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SimpleRecordCheck {
    pub present: bool,
    pub record: Option<String>,
    pub issues: Vec<String>,
}

pub fn parse_tls_rpt(records: &[String]) -> SimpleRecordCheck {
    let record = records
        .iter()
        .find(|r| r.to_ascii_lowercase().contains("v=tlsrptv1"));
    let mut check = SimpleRecordCheck {
        present: record.is_some(),
        record: record.cloned(),
        issues: Vec::new(),
    };
    if let Some(value) = &check.record {
        if !value.to_ascii_lowercase().contains("rua=") {
            check.issues.push(
                "The TLS-RPT record has no 'rua=' destination, so no reports are delivered."
                    .to_string(),
            );
        }
    }
    check
}

pub fn parse_bimi(records: &[String]) -> SimpleRecordCheck {
    let record = records
        .iter()
        .find(|r| r.to_ascii_lowercase().contains("v=bimi1"));
    let mut check = SimpleRecordCheck {
        present: record.is_some(),
        record: record.cloned(),
        issues: Vec::new(),
    };
    if let Some(value) = &check.record {
        let lower = value.to_ascii_lowercase();
        if !lower.contains("l=") {
            check
                .issues
                .push("The BIMI record has no 'l=' logo URL.".to_string());
        }
        if !lower.contains("a=") {
            check.issues.push(
                "The BIMI record has no 'a=' Verified Mark Certificate, which Gmail and Apple \
                 Mail require before displaying the logo."
                    .to_string(),
            );
        }
    }
    check
}

/// DKIM selectors worth probing. There is no way to enumerate selectors from
/// DNS — they are only discoverable from a signed message — so every scanner
/// guesses from the same list of provider defaults. Absence proves nothing, and
/// the report says so.
pub const COMMON_DKIM_SELECTORS: &[&str] = &[
    "default", "dkim", "mail", "email", "selector1", "selector2", "google", "k1", "k2", "k3",
    "s1", "s2", "s1024", "smtp", "mandrill", "mailjet", "sendgrid", "zoho", "protonmail",
    "protonmail2", "protonmail3", "everlytickey1", "everlytickey2", "eversrv", "mxvault", "sig1",
    "sig2", "hs1", "hs2", "pm", "pic", "ctct1", "ctct2", "amazonses", "dkim1", "sm", "sm1", "sm2",
    "mimecast20230101", "20161025", "fd", "fdm", "scph0819", "sendinblue", "klaviyo", "postmark",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn analysed(record: &str) -> SpfAnalysis {
        let mut analysis = parse_spf_record(record);
        let lookups = analysis.dns_lookups;
        evaluate_spf(&mut analysis, lookups);
        analysis
    }

    #[test]
    fn spf_terms_and_qualifiers_are_parsed() {
        let spf = parse_spf_record("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com a mx -all");
        assert_eq!(spf.all_qualifier, Some(SpfQualifier::Fail));
        assert_eq!(spf.includes, vec!["_spf.google.com"]);
        // include + a + mx cost a lookup each; ip4 and all do not.
        assert_eq!(spf.dns_lookups, 3);
        assert!(!spf.uses_ptr);
    }

    #[test]
    fn lookup_counting_ignores_ip_literals_and_exp() {
        let spf = parse_spf_record(
            "v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 exp=explain.example.com exists:%{i}.spf.example.com -all",
        );
        assert_eq!(spf.dns_lookups, 1, "only exists: costs a lookup");
    }

    #[test]
    fn redirect_counts_as_a_lookup_and_is_captured() {
        let spf = parse_spf_record("v=spf1 redirect=_spf.example.net");
        assert_eq!(spf.redirect.as_deref(), Some("_spf.example.net"));
        assert_eq!(spf.dns_lookups, 1);
    }

    #[test]
    fn permissive_all_invalidates_the_policy() {
        let spf = analysed("v=spf1 +all");
        assert!(!spf.valid);
        assert!(spf.issues.iter().any(|i| i.contains("+all")));

        // The bare `all` with no qualifier is also a pass.
        let spf = analysed("v=spf1 mx all");
        assert_eq!(spf.all_qualifier, Some(SpfQualifier::Pass));
        assert!(!spf.valid);
    }

    #[test]
    fn softfail_and_neutral_are_reported_without_invalidating() {
        for (record, needle) in [("v=spf1 mx ~all", "~all"), ("v=spf1 mx ?all", "?all")] {
            let spf = analysed(record);
            assert!(spf.valid, "{} should stay valid", record);
            assert!(spf.issues.iter().any(|i| i.contains(needle)), "{}", record);
        }
    }

    #[test]
    fn missing_all_is_flagged_unless_there_is_a_redirect() {
        let spf = analysed("v=spf1 mx");
        assert!(spf.issues.iter().any(|i| i.contains("no 'all' mechanism")));

        let spf = analysed("v=spf1 redirect=_spf.example.net");
        assert!(!spf.issues.iter().any(|i| i.contains("no 'all' mechanism")));
    }

    #[test]
    fn exceeding_ten_lookups_is_a_permerror() {
        let mut spf = parse_spf_record("v=spf1 include:a.example -all");
        evaluate_spf(&mut spf, 11);
        assert!(spf.exceeds_lookup_limit);
        assert!(!spf.valid);
        assert!(spf.issues.iter().any(|i| i.contains("permerror")));

        // Exactly ten is legal, but worth warning about.
        let mut spf = parse_spf_record("v=spf1 include:a.example -all");
        evaluate_spf(&mut spf, 10);
        assert!(!spf.exceeds_lookup_limit);
        assert!(spf.valid);
        assert!(spf.issues.iter().any(|i| i.contains("10 of the 10")));
    }

    #[test]
    fn multiple_spf_records_are_a_permanent_error() {
        let mut spf = parse_spf_record("v=spf1 -all");
        spf.multiple_records = true;
        evaluate_spf(&mut spf, 0);
        assert!(!spf.valid);
        assert!(spf.issues.iter().any(|i| i.contains("§4.5")));
    }

    #[test]
    fn ptr_is_reported_as_deprecated() {
        let spf = analysed("v=spf1 ptr -all");
        assert!(spf.uses_ptr);
        assert!(spf.issues.iter().any(|i| i.contains("§5.5")));
    }

    #[test]
    fn dmarc_tags_are_parsed_with_their_defaults() {
        let dmarc = parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:d@example.com");
        assert_eq!(dmarc.policy.as_deref(), Some("reject"));
        assert_eq!(dmarc.percentage, 100, "pct defaults to 100");
        assert_eq!(dmarc.dkim_alignment, "r", "adkim defaults to relaxed");
        assert_eq!(dmarc.aggregate_reports, vec!["mailto:d@example.com"]);
    }

    #[test]
    fn dmarc_enforcement_requires_reject_at_full_percentage() {
        let mut dmarc = parse_dmarc_record("v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com");
        evaluate_dmarc(&mut dmarc);
        assert!(!dmarc.enforced);
        assert!(dmarc.issues.iter().any(|i| i.contains("pct=50")));

        let mut dmarc = parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:d@example.com");
        evaluate_dmarc(&mut dmarc);
        assert!(dmarc.enforced);
        assert!(dmarc.issues.is_empty());
    }

    #[test]
    fn a_weaker_subdomain_policy_is_flagged() {
        let mut dmarc =
            parse_dmarc_record("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com");
        evaluate_dmarc(&mut dmarc);
        assert!(dmarc.issues.iter().any(|i| i.contains("sp=none")));
    }

    #[test]
    fn dmarc_without_a_policy_tag_is_invalid() {
        let mut dmarc = parse_dmarc_record("v=DMARC1; rua=mailto:d@example.com");
        evaluate_dmarc(&mut dmarc);
        assert!(!dmarc.valid);
        assert!(!dmarc.enforced);
    }

    #[test]
    fn dmarc_without_rua_is_flagged() {
        let mut dmarc = parse_dmarc_record("v=DMARC1; p=none");
        evaluate_dmarc(&mut dmarc);
        assert!(dmarc.issues.iter().any(|i| i.contains("rua")));
    }

    #[test]
    fn mta_sts_policy_modes_are_graded() {
        let mut analysis = MtaStsAnalysis {
            dns_record_present: true,
            ..Default::default()
        };
        parse_mta_sts_policy(
            "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n",
            &mut analysis,
        );
        assert!(analysis.policy_fetched);
        assert_eq!(analysis.mode.as_deref(), Some("enforce"));
        assert_eq!(analysis.mx_patterns.len(), 2);
        assert!(analysis.issues.is_empty());

        let mut testing = MtaStsAnalysis::default();
        parse_mta_sts_policy("version: STSv1\nmode: testing\nmax_age: 3600\n", &mut testing);
        assert!(testing.issues.iter().any(|i| i.contains("testing")));
        assert!(testing.issues.iter().any(|i| i.contains("max_age")));
    }

    #[test]
    fn an_announced_policy_that_cannot_be_fetched_is_flagged() {
        let mut analysis = MtaStsAnalysis {
            dns_record_present: true,
            ..Default::default()
        };
        parse_mta_sts_policy("", &mut analysis);
        assert!(!analysis.policy_fetched);
        assert!(analysis.issues.iter().any(|i| i.contains("no valid policy")));
    }

    #[test]
    fn mta_sts_txt_yields_the_policy_id() {
        assert_eq!(
            parse_mta_sts_txt("v=STSv1; id=20240101T000000;").as_deref(),
            Some("20240101T000000")
        );
        assert!(parse_mta_sts_txt("v=spf1 -all").is_none());
    }

    #[test]
    fn tls_rpt_and_bimi_require_their_mandatory_tags() {
        let rpt = parse_tls_rpt(&["v=TLSRPTv1; rua=mailto:tls@example.com".into()]);
        assert!(rpt.present && rpt.issues.is_empty());
        let rpt = parse_tls_rpt(&["v=TLSRPTv1;".into()]);
        assert!(rpt.present && !rpt.issues.is_empty());

        let bimi = parse_bimi(&["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem".into()]);
        assert!(bimi.present && bimi.issues.is_empty());
        let bimi = parse_bimi(&["v=BIMI1; l=https://example.com/logo.svg".into()]);
        assert!(bimi.issues.iter().any(|i| i.contains("Verified Mark")));
    }

    #[test]
    fn quoted_records_are_handled() {
        let spf = parse_spf_record("\"v=spf1 include:_spf.example.com -all\"");
        assert_eq!(spf.all_qualifier, Some(SpfQualifier::Fail));
        assert_eq!(spf.includes, vec!["_spf.example.com"]);
    }

    #[test]
    fn selector_list_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for selector in COMMON_DKIM_SELECTORS {
            assert!(seen.insert(*selector), "duplicate selector {}", selector);
        }
    }
}

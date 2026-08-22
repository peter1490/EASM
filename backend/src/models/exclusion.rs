use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of object that can be excluded
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExclusionObjectType {
    Domain,
    Ip,
    Organization,
    Asn,
    Cidr,
    Certificate,
}

impl std::fmt::Display for ExclusionObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExclusionObjectType::Domain => write!(f, "domain"),
            ExclusionObjectType::Ip => write!(f, "ip"),
            ExclusionObjectType::Organization => write!(f, "organization"),
            ExclusionObjectType::Asn => write!(f, "asn"),
            ExclusionObjectType::Cidr => write!(f, "cidr"),
            ExclusionObjectType::Certificate => write!(f, "certificate"),
        }
    }
}

impl From<&str> for ExclusionObjectType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "domain" => ExclusionObjectType::Domain,
            "ip" => ExclusionObjectType::Ip,
            "organization" | "org" => ExclusionObjectType::Organization,
            "asn" => ExclusionObjectType::Asn,
            "cidr" => ExclusionObjectType::Cidr,
            "certificate" | "cert" => ExclusionObjectType::Certificate,
            _ => ExclusionObjectType::Domain, // Default fallback
        }
    }
}

/// The character that stands for "anything" in an exclusion value.
pub const WILDCARD: char = '*';

/// Whether a value is a pattern rather than a literal.
pub fn is_pattern(value: &str) -> bool {
    value.contains(WILDCARD)
}

/// Whether this kind of object can carry a pattern.
///
/// Only the three whose values are free text. An address range already has a
/// notation of its own -- that is what `cidr` entries are -- and `AS*` on an
/// autonomous system number is not a thing anyone means.
pub fn accepts_pattern(object_type: &ExclusionObjectType) -> bool {
    matches!(
        object_type,
        ExclusionObjectType::Domain
            | ExclusionObjectType::Organization
            | ExclusionObjectType::Certificate
    )
}

/// Does `value` match `pattern`, where `*` stands for any run of characters?
///
/// Dots are not special: `*.cdn.example.com` covers `a.cdn.example.com` and
/// `a.b.cdn.example.com` alike, which is what an operator excluding a provider's
/// estate means. It does *not* cover the bare apex `cdn.example.com` -- keeping
/// the apex while dropping everything under it is the reason to write a pattern
/// instead of a plain domain entry, which already covers both.
///
/// Both sides are compared as given; callers normalise case first.
pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    // Literal runs between the wildcards, in order. A pattern that starts or
    // ends with `*` yields an empty leading or trailing segment, which is
    // exactly the "anything goes at this end" the operator asked for.
    let mut segments = pattern.split(WILDCARD);

    let Some(first) = segments.next() else {
        return false;
    };
    let Some(rest) = value.strip_prefix(first) else {
        return false;
    };

    let mut remaining = rest;
    let mut pending: Option<&str> = None;

    for segment in segments {
        // The last segment must land at the very end, so it is held back and
        // matched as a suffix once the loop is done.
        if let Some(previous) = pending.replace(segment) {
            match remaining.find(previous) {
                Some(at) => remaining = &remaining[at + previous.len()..],
                None => return false,
            }
        }
    }

    match pending {
        Some(last) => remaining.len() >= last.len() && remaining.ends_with(last),
        // No wildcard at all: the whole value had to be the one literal.
        None => remaining.is_empty(),
    }
}

/// Translate an exclusion value into a SQL `LIKE` pattern.
///
/// `*` becomes `%`; everything else is escaped, so a literal `%` or `_` in a
/// stored value cannot quietly become a wildcard of its own. The result relies
/// on `LIKE`'s default escape character, which is a backslash.
pub fn like_pattern(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    for ch in value.chars() {
        match ch {
            WILDCARD => out.push('%'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Reject a pattern that would sweep up more than anyone means to exclude.
///
/// `*` on its own matches every asset in the company, and as a blacklist it
/// would delete the estate. The rule mirrors the one the matcher already
/// applies to plain domain entries, where a bare TLD never swallows a whole
/// zone: what is left after removing the wildcards has to be specific enough to
/// name something. For a domain that means two labels of literal text; for the
/// free-text kinds, enough characters to be a name rather than a letter.
pub fn validate_value(object_type: &ExclusionObjectType, value: &str) -> Result<(), String> {
    if !is_pattern(value) {
        return Ok(());
    }

    if !accepts_pattern(object_type) {
        return Err(format!(
            "Wildcards are not allowed on {} exclusions. Use a CIDR entry for a range of addresses.",
            object_type
        ));
    }

    let literal = value.replace(WILDCARD, "");

    match object_type {
        ExclusionObjectType::Domain => {
            let labels: Vec<&str> = literal
                .split('.')
                .filter(|label| !label.is_empty())
                .collect();
            if labels.len() < 2 {
                return Err(format!(
                    "'{}' is too broad: a domain pattern needs at least two labels of its own, as in '*.cdn.example.com'.",
                    value
                ));
            }
        }
        _ => {
            if literal.trim().chars().count() < MIN_PATTERN_LITERALS {
                return Err(format!(
                    "'{}' is too broad: a pattern needs at least {} characters of its own.",
                    value, MIN_PATTERN_LITERALS
                ));
            }
        }
    }

    Ok(())
}

/// How much literal text a free-text pattern has to carry.
const MIN_PATTERN_LITERALS: usize = 3;

/// An exclusion entry.
///
/// Two strengths live in one row. An ordinary exclusion tells discovery to stop
/// *growing* the estate here: nothing new is written for the object or anything
/// under it, but whatever was already found stays, keeps its findings, keeps
/// counting towards the score, and is still auto-scanned by later runs. A
/// `blacklisted` entry is the hard one: the matching assets are deleted and
/// never written again, so the object reaches no score, no scan and no list.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExclusionEntry {
    pub id: Uuid,
    pub object_type: String,
    pub object_value: String,
    pub company_id: Uuid,
    pub reason: Option<String>,
    pub created_by: Option<String>,
    /// Hard mode: purge what matches and keep it out for good.
    pub blacklisted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an exclusion entry
#[derive(Debug, Clone, Deserialize)]
pub struct ExclusionCreate {
    pub object_type: ExclusionObjectType,
    pub object_value: String,
    pub reason: Option<String>,
    /// If true, delete all descendant assets discovered from this object
    #[serde(default)]
    pub delete_descendants: bool,
    /// If true, also delete the matching assets themselves and keep discovery
    /// from ever storing them again. Off unless asked for: excluding is the
    /// reversible half of this feature and deleting is not.
    #[serde(default)]
    pub blacklisted: bool,
}

/// Request to update an exclusion entry
#[derive(Debug, Clone, Deserialize)]
pub struct ExclusionUpdate {
    pub reason: Option<String>,
    /// Promote an exclusion to a blacklist, or demote it back. Promoting purges
    /// what the entry matches; demoting only stops the rule, since what was
    /// already deleted is gone.
    pub blacklisted: Option<bool>,
}

/// Result of an exclusion operation that includes cascade deletion
#[derive(Debug, Clone, Serialize)]
pub struct ExclusionResult {
    pub entry: ExclusionEntry,
    pub descendants_deleted: i64,
    /// Assets deleted because the entry blacklists them: the objects the entry
    /// names, plus everything discovered through them. Zero for an ordinary
    /// exclusion, which deletes nothing on its own.
    #[serde(default)]
    pub assets_deleted: i64,
    /// Queued discovery items the new entry removed from a run in progress.
    #[serde(default)]
    pub queue_items_removed: i64,
    /// Security scans stopped because their target is now blacklisted.
    #[serde(default)]
    pub scans_cancelled: i64,
}

/// Check result for exclusion status
#[derive(Debug, Clone, Serialize)]
pub struct ExclusionCheckResult {
    pub is_excluded: bool,
    /// Whether the entry covering this object is a blacklist rather than an
    /// ordinary exclusion. False when nothing covers it.
    pub is_blacklisted: bool,
    pub entry: Option<ExclusionEntry>,
    /// For domains, indicates if a parent domain is excluded
    pub parent_excluded: bool,
    pub parent_entry: Option<ExclusionEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leading_wildcard_covers_every_depth_but_not_the_apex() {
        let pattern = "*.cdn.example.com";

        assert!(pattern_matches(pattern, "a.cdn.example.com"));
        assert!(pattern_matches(pattern, "a.b.cdn.example.com"));
        assert!(pattern_matches(pattern, "very.deep.chain.cdn.example.com"));

        // Keeping the apex while dropping everything under it is the whole
        // reason to write a pattern instead of a plain domain entry.
        assert!(!pattern_matches(pattern, "cdn.example.com"));
        // And a name that merely ends similarly is a different name.
        assert!(!pattern_matches(pattern, "evilcdn.example.com"));
        assert!(!pattern_matches(pattern, "cdn.example.com.evil.net"));
    }

    #[test]
    fn a_wildcard_in_the_middle_of_a_label_matches_that_label() {
        assert!(pattern_matches("api-*.example.com", "api-dev.example.com"));
        assert!(pattern_matches("api-*.example.com", "api-.example.com"));
        assert!(!pattern_matches("api-*.example.com", "api.example.com"));
        assert!(!pattern_matches("api-*.example.com", "web-dev.example.com"));
    }

    #[test]
    fn a_trailing_wildcard_matches_anything_after_the_literal() {
        assert!(pattern_matches("staging.*", "staging.example.com"));
        assert!(pattern_matches("staging.*", "staging."));
        assert!(!pattern_matches("staging.*", "staging"));
        assert!(!pattern_matches("staging.*", "www.staging.example.com"));
    }

    #[test]
    fn several_wildcards_match_their_literals_in_order() {
        assert!(pattern_matches("*acme*hosting*", "www.acme-hosting.net"));
        assert!(pattern_matches("*acme*hosting*", "acmehosting"));
        // In order, or not at all.
        assert!(!pattern_matches("*acme*hosting*", "hosting.acme.net"));
        assert!(!pattern_matches("*acme*hosting*", "acme.net"));
    }

    #[test]
    fn a_pattern_with_no_wildcard_is_an_exact_comparison() {
        assert!(pattern_matches("example.com", "example.com"));
        assert!(!pattern_matches("example.com", "api.example.com"));
        assert!(!pattern_matches("example.com", "example.co"));
    }

    #[test]
    fn a_bare_wildcard_matches_everything_which_is_why_it_is_rejected() {
        assert!(pattern_matches("*", "anything.at.all"));
        assert!(pattern_matches("*", ""));

        assert!(validate_value(&ExclusionObjectType::Domain, "*").is_err());
        assert!(validate_value(&ExclusionObjectType::Organization, "*").is_err());
    }

    #[test]
    fn a_domain_pattern_needs_two_labels_of_its_own() {
        assert!(validate_value(&ExclusionObjectType::Domain, "*.cdn.example.com").is_ok());
        assert!(validate_value(&ExclusionObjectType::Domain, "api-*.example.com").is_ok());

        // One label would put every `.com` in the world behind one entry.
        assert!(validate_value(&ExclusionObjectType::Domain, "*.com").is_err());
        assert!(validate_value(&ExclusionObjectType::Domain, "*com*").is_err());
    }

    #[test]
    fn free_text_patterns_need_enough_letters_to_name_something() {
        assert!(validate_value(&ExclusionObjectType::Organization, "*acme*").is_ok());
        assert!(validate_value(&ExclusionObjectType::Certificate, "CN=*.example.com").is_ok());

        assert!(validate_value(&ExclusionObjectType::Organization, "*a*").is_err());
    }

    #[test]
    fn address_kinds_refuse_a_pattern_outright() {
        // A range of addresses already has a notation, and it is not this one.
        assert!(validate_value(&ExclusionObjectType::Ip, "203.0.113.*").is_err());
        assert!(validate_value(&ExclusionObjectType::Cidr, "10.*").is_err());
        assert!(validate_value(&ExclusionObjectType::Asn, "AS*").is_err());

        // Literal values of those kinds are still fine.
        assert!(validate_value(&ExclusionObjectType::Ip, "203.0.113.4").is_ok());
        assert!(validate_value(&ExclusionObjectType::Cidr, "10.0.0.0/8").is_ok());
    }

    #[test]
    fn like_translation_escapes_what_sql_would_otherwise_treat_as_a_wildcard() {
        assert_eq!(like_pattern("*.cdn.example.com"), "%.cdn.example.com");
        assert_eq!(like_pattern("api-*.example.com"), "api-%.example.com");
        assert_eq!(like_pattern("plain.example.com"), "plain.example.com");

        // A stored `%` or `_` is a literal character, not a second wildcard
        // syntax nobody asked for.
        assert_eq!(like_pattern("a_b.example.com"), "a\\_b.example.com");
        assert_eq!(like_pattern("100%.example.com"), "100\\%.example.com");
        assert_eq!(like_pattern("back\\slash"), "back\\\\slash");
    }
}

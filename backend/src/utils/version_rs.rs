//! Software version parsing and comparison.
//!
//! CVE data expresses affected ranges with whatever versioning scheme the
//! upstream project happens to use, so a plain semver parser is not enough.
//! Real strings we have to order correctly include:
//!
//! | string            | project           | note                                  |
//! |-------------------|-------------------|---------------------------------------|
//! | `1.0.2k`          | OpenSSL           | trailing letter is a *patch*, higher   |
//! | `7.4p1`           | OpenSSH           | `pN` is a patch, higher                |
//! | `2.4.41`          | Apache httpd      | plain dotted                           |
//! | `8.0.32-log`      | MySQL banner      | build qualifier                        |
//! | `1.0.0-rc.10`     | semver            | pre-release, lower than `1.0.0`        |
//! | `1:2.3.4`         | Debian-style      | epoch dominates everything             |
//! | `5.6.40-1+ubuntu` | distro package    | revision, higher than `5.6.40`         |
//!
//! The comparison is an RPM `rpmvercmp`-style alternating numeric/alpha segment
//! walk, extended with semver's pre-release rule. Crucially, a *separated*
//! suffix whose first word is a known pre-release keyword (`-rc1`, `-beta`)
//! sorts **below** the bare version, while any other trailing segment
//! (`k`, `p1`, `-log`, `-1`) sorts **above** it. That distinction is what keeps
//! `1.0.2k > 1.0.2` and `1.0.0-rc1 < 1.0.0` both true.

use std::cmp::Ordering;

/// Words that mark a suffix as a *pre*-release (sorting below the bare version).
///
/// Deliberately excludes bare single letters (`a`, `b`, `m`) and `p`: OpenSSL
/// ships `1.0.1a` and OpenSSH ships `7.4p1` as post-release patches, and
/// treating those as pre-releases would place a *patched* build below the
/// unpatched one — inverting every CVE range check for the two products with
/// the densest CVE histories on the internet.
const PRE_RELEASE_WORDS: &[&str] = &[
    "alpha",
    "beta",
    "rc",
    "pre",
    "preview",
    "dev",
    "snapshot",
    "milestone",
    "nightly",
    "canary",
    "ea",
];

/// One run of digits or one run of non-digits.
#[derive(Debug, Clone, Eq, PartialEq)]
enum Segment {
    Num(u64),
    Alpha(String),
}

impl Segment {
    fn cmp_seg(&self, other: &Segment) -> Ordering {
        match (self, other) {
            (Segment::Num(a), Segment::Num(b)) => a.cmp(b),
            (Segment::Alpha(a), Segment::Alpha(b)) => a.cmp(b),
            // rpmvercmp: a numeric segment outranks an alpha one in the same slot,
            // so `1.10` > `1.beta`.
            (Segment::Num(_), Segment::Alpha(_)) => Ordering::Greater,
            (Segment::Alpha(_), Segment::Num(_)) => Ordering::Less,
        }
    }
}

/// Split a string into alternating numeric / non-numeric runs, dropping the
/// separators (`.`, `-`, `_`, `+`, `~`) that only delimit them.
fn segments(s: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut buf = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    buf.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            // Saturate rather than drop: a 30-digit "version" is junk either way,
            // but returning None here would make the caller assume "affected".
            out.push(Segment::Num(buf.parse().unwrap_or(u64::MAX)));
        } else if c.is_ascii_alphabetic() {
            let mut buf = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphabetic() {
                    buf.push(c.to_ascii_lowercase());
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(Segment::Alpha(buf));
        } else {
            chars.next();
        }
    }
    out
}

/// Compare two segment lists.
///
/// When one list runs out, its missing components are treated as **zero** for
/// numeric comparison, so `11 == 11.0.0` and `1.2 == 1.2.0` — the reading every
/// version scheme intends, and the one CVE range bounds are written against
/// (`versionStartIncluding: "11.0.0"` is meant to include a product that only
/// advertises "11"). A trailing *alpha* run is not a missing zero, though: it
/// is a patch suffix, so `1.0.2k` still ranks above `1.0.2` and `7.4p1` above
/// `7.4`.
fn cmp_segments(a: &[Segment], b: &[Segment]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let ord = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => x.cmp_seg(y),
            (Some(Segment::Num(n)), None) => n.cmp(&0),
            (None, Some(Segment::Num(n))) => 0.cmp(n),
            (Some(Segment::Alpha(_)), None) => Ordering::Greater,
            (None, Some(Segment::Alpha(_))) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// A parsed, comparable software version.
///
/// Equality is defined by the ordering, not by the source text, so
/// `1.0.09 == 1.0.9` and `v2.4 == 2.4`.
#[derive(Debug, Clone)]
pub struct Version {
    epoch: u64,
    core: Vec<Segment>,
    /// Pre-release suffix. `Some` sorts *below* `None` at equal cores.
    pre: Option<Vec<Segment>>,
    /// Build / revision suffix. `Some` sorts *above* `None` at equal cores.
    post: Option<Vec<Segment>>,
    raw: String,
}

impl Version {
    /// Parse a version out of a raw string, tolerating banner noise around it
    /// (`Apache/2.4.41 (Ubuntu)` → `2.4.41`). Returns `None` only when the input
    /// contains no digit at all, i.e. there is no version in it to compare.
    pub fn from(s: &str) -> Option<Self> {
        let raw = s.trim().to_string();

        // Cut banner tails: everything from the first space or '(' is commentary,
        // not part of the version ("1.21.0 (Ubuntu)", "2.4.41 (Debian)").
        let head = raw
            .split(|c: char| c.is_whitespace() || c == '(' || c == ',' || c == ';')
            .next()
            .unwrap_or("")
            .trim();

        // Drop any leading non-digit run ("v1.2.3", "Apache/2.4.41", "r12").
        let start = head.find(|c: char| c.is_ascii_digit())?;
        let head = &head[start..];

        // Debian-style epoch: "1:2.3.4". Only when the prefix is pure digits.
        let (epoch, rest) = match head.split_once(':') {
            Some((e, r)) if !e.is_empty() && e.chars().all(|c| c.is_ascii_digit()) => {
                (e.parse().unwrap_or(0), r)
            }
            _ => (0, head),
        };

        // Split off a separated suffix. `~` is always a pre-release (Debian).
        let (core_str, sep, suffix) = match rest.find(['-', '+', '~']) {
            Some(i) => (
                &rest[..i],
                rest[i..].chars().next().unwrap_or('-'),
                Some(&rest[i + 1..]),
            ),
            None => (rest, '\0', None),
        };

        let mut core = segments(core_str);
        let mut pre: Option<Vec<Segment>> = None;
        let mut post: Option<Vec<Segment>> = None;

        match suffix {
            Some(suf) if !suf.is_empty() => {
                let suffix_segments = segments(suf);
                let first_word = suffix_segments.iter().find_map(|s| match s {
                    Segment::Alpha(a) => Some(a.as_str()),
                    _ => None,
                });
                let is_pre = sep == '~'
                    || first_word.is_some_and(|w| PRE_RELEASE_WORDS.contains(&w));
                if is_pre {
                    pre = Some(suffix_segments);
                } else {
                    post = Some(suffix_segments);
                }
            }
            _ => {}
        }

        // Unseparated pre-release, e.g. "1.0.0rc1" or "3.0.0beta2": if the core
        // ends with a pre-release keyword, peel it (and anything after) into
        // `pre`. Attached patch letters ("1.0.2k", "7.4p1") are not keywords and
        // therefore stay in the core, where they correctly sort higher.
        if pre.is_none() {
            if let Some(idx) = core.iter().position(|s| {
                matches!(s, Segment::Alpha(a) if PRE_RELEASE_WORDS.contains(&a.as_str()))
            }) {
                pre = Some(core.split_off(idx));
            }
        }

        if core.is_empty() {
            return None;
        }

        Some(Version {
            epoch,
            core,
            pre,
            post,
            raw,
        })
    }

    /// The original string this version was parsed from.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// True when this is a pre-release build (`1.0.0-rc1`, `2.0.0-beta`).
    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }

    /// The leading numeric components, e.g. `[11]` for `11` and `[2, 4, 49]`
    /// for `2.4.49`. Stops at the first non-numeric segment, so `1.0.2k` gives
    /// `[1, 0, 2]`.
    pub fn numeric_components(&self) -> Vec<u64> {
        self.core
            .iter()
            .map_while(|s| match s {
                Segment::Num(n) => Some(*n),
                Segment::Alpha(_) => None,
            })
            .collect()
    }

    /// True when the string names one release rather than a whole series.
    ///
    /// A banner reading `Drupal 11` or `PHP 8.2` does not say which 11.x or
    /// 8.2.x is installed — it names a series, and the distinction decides
    /// whether a CVE lookup can ask about a point version or has to ask about a
    /// range. Three or more numeric components, or any suffix at all (`1.0.2k`,
    /// `7.4p1`, `8.0.32-log`), means a specific build.
    pub fn is_exact_release(&self) -> bool {
        self.numeric_components().len() >= 3
            || self.core.len() > self.numeric_components().len()
            || self.pre.is_some()
            || self.post.is_some()
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| cmp_segments(&self.core, &other.core))
            // Absent pre-release beats present: 1.0.0 > 1.0.0-rc1.
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => cmp_segments(a, b),
            })
            // Present build/revision beats absent: 5.6.40-1 > 5.6.40.
            .then_with(|| match (&self.post, &other.post) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some(a), Some(b)) => cmp_segments(a, b),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::from(s).unwrap_or_else(|| panic!("failed to parse version {s:?}"))
    }

    #[test]
    fn test_version_compare() {
        assert!(v("1.2.3") < v("1.2.4"));
        assert!(v("1.2.3") == v("1.2.3"));
        assert!(v("1.2") < v("1.2.1"));
        assert!(v("1.11") > v("1.2")); // numeric, not lexical
        assert!(v("1.0.0") > v("1.0.0-rc1"));
    }

    #[test]
    fn numeric_segments_never_compare_lexically() {
        assert!(v("2.4.10") > v("2.4.9"));
        assert!(v("1.2.10") > v("1.2.9"));
        assert!(v("2.4.41") > v("2.4.6"));
        assert!(v("10.0.0") > v("9.99.99"));
        assert!(v("1.0.09") == v("1.0.9")); // leading zeros are not significant
    }

    #[test]
    fn openssl_letter_releases_are_patches_not_prereleases() {
        // The whole point: 1.0.2k is *newer* than 1.0.2, so a CVE fixed in
        // 1.0.2 must not be reported against 1.0.2k.
        assert!(v("1.0.2k") > v("1.0.2"));
        assert!(v("1.0.2k") > v("1.0.2j"));
        assert!(v("1.0.2a") < v("1.0.2b"));
        assert!(v("1.1.1w") > v("1.1.1a"));
        assert!(v("3.0.8") > v("1.1.1w"));
    }

    #[test]
    fn openssh_p_releases_are_patches() {
        assert!(v("7.4p1") > v("7.4"));
        assert!(v("8.2p1") < v("8.3p1"));
        assert!(v("9.3p2") > v("9.3p1"));
    }

    #[test]
    fn semver_prerelease_ordering() {
        assert!(v("1.0.0-alpha") < v("1.0.0-beta"));
        assert!(v("1.0.0-beta") < v("1.0.0-rc1"));
        assert!(v("1.0.0-rc1") < v("1.0.0"));
        // Numeric pre-release counters compare numerically, not as strings.
        assert!(v("1.0.0-rc.2") < v("1.0.0-rc.10"));
        assert!(v("2.0.0-beta2") < v("2.0.0-beta10"));
    }

    #[test]
    fn unseparated_prerelease_keyword_is_still_a_prerelease() {
        assert!(v("3.0.0beta2") < v("3.0.0"));
        assert!(v("1.0.0rc1") < v("1.0.0"));
    }

    #[test]
    fn build_and_revision_suffixes_sort_above_the_bare_version() {
        assert!(v("8.0.32-log") > v("8.0.32"));
        assert!(v("5.6.40-1") > v("5.6.40"));
        assert!(v("5.6.40-1+ubuntu") > v("5.6.40-1"));
        assert!(v("1.2.3+build5") > v("1.2.3"));
    }

    #[test]
    fn tilde_always_means_prerelease() {
        assert!(v("1.2.3~beta") < v("1.2.3"));
        assert!(v("1.2.3~1") < v("1.2.3"));
    }

    #[test]
    fn epoch_dominates() {
        assert!(v("1:1.0.0") > v("99.0.0"));
        assert!(v("2:1.0") > v("1:9.9"));
    }

    #[test]
    fn tolerates_banner_noise_and_prefixes() {
        assert_eq!(v("v2.4"), v("2.4"));
        assert_eq!(v("1.21.0 (Ubuntu)"), v("1.21.0"));
        assert_eq!(v("2.4.41 (Debian)"), v("2.4.41"));
        assert_eq!(v("Apache/2.4.41"), v("2.4.41"));
        assert!(v("nginx/1.18.0") < v("nginx/1.19.0"));
    }

    #[test]
    fn returns_none_only_when_there_is_no_version() {
        assert!(Version::from("").is_none());
        assert!(Version::from("unknown").is_none());
        assert!(Version::from("stable").is_none());
        // Anything with a digit parses — never silently unparseable, because
        // callers treat "unparseable" as "assume vulnerable".
        assert!(Version::from("1.0.2k").is_some());
        assert!(Version::from("2.4.41p1").is_some());
        assert!(Version::from("10.0.19041.1").is_some());
        assert!(Version::from("R80.40").is_some());
        assert!(Version::from("13.1-49.13").is_some()); // Citrix NetScaler build
    }

    #[test]
    fn netscaler_style_build_numbers() {
        // Citrix reports "13.1-49.13"; the part after the dash is a build.
        assert!(v("13.1-49.13") > v("13.1-48.47"));
        assert!(v("13.1-49.15") > v("13.1-49.13"));
        assert!(v("14.1-8.50") > v("13.1-51.15"));
    }

    #[test]
    fn four_component_versions() {
        assert!(v("15.0.1497.2") < v("15.0.1497.12"));
        assert!(v("1.2.3.4") > v("1.2.3"));
    }

    #[test]
    fn missing_trailing_components_are_zero() {
        // A banner reading "Drupal 11" has to compare equal to the 11.0.0 that
        // NVD writes in `versionStartIncluding`, or every CVE whose range
        // starts at 11.0.0 is silently filtered out as "below the range".
        assert!(v("11") == v("11.0"));
        assert!(v("11") == v("11.0.0"));
        assert!(v("1.2") == v("1.2.0"));
        assert!(v("1.2.0.0") == v("1.2"));

        assert!(v("11") < v("11.0.1"));
        assert!(v("11") < v("11.1"));
        assert!(v("11") > v("10.9.9"));
        assert!(v("11.0.0") < v("11.0.1"));
    }

    #[test]
    fn a_trailing_letter_is_not_a_missing_zero() {
        // The zero-padding rule must not swallow patch suffixes: these are the
        // comparisons CVE ranges actually make against a letter-suffixed
        // build, and every one of them has to keep the patched build above the
        // bare version it patches.
        assert!(v("1.0.2k") > v("1.0.2"));
        assert!(v("1.0.2k") < v("1.0.3"));
        assert!(v("7.4p1") > v("7.4"));
        assert!(v("7.4p1") < v("7.5"));
        assert!(v("9.3p2") > v("9.3p1"));
        // Not asserted: `1.0.2k` against `1.0.2.0`. Those come from different
        // versioning schemes and no upstream ever publishes both, so any
        // ordering we picked would be arbitrary. The rpm rule (a numeric
        // segment outranks an alpha one in the same slot) decides it.
    }

    #[test]
    fn exactness_distinguishes_a_release_from_a_series() {
        // "Drupal 11" and "PHP 8.2" name a series; a CVE lookup for them has to
        // ask about a range, not pin a version that was never observed.
        assert!(!v("11").is_exact_release());
        assert!(!v("8.2").is_exact_release());
        assert!(!v("9").is_exact_release());

        assert!(v("2.4.49").is_exact_release());
        assert!(v("15.0.2.13").is_exact_release());
        assert!(v("1.0.2k").is_exact_release());
        assert!(v("7.4p1").is_exact_release());
        assert!(v("8.0.32-log").is_exact_release());
        assert!(v("1.0.0-rc1").is_exact_release());
    }

    #[test]
    fn numeric_components_stop_at_the_first_letter() {
        assert_eq!(v("11").numeric_components(), vec![11]);
        assert_eq!(v("2.4.49").numeric_components(), vec![2, 4, 49]);
        assert_eq!(v("1.0.2k").numeric_components(), vec![1, 0, 2]);
        assert_eq!(v("13.1-49.13").numeric_components(), vec![13, 1]);
    }

    #[test]
    fn prerelease_flag() {
        assert!(v("1.0.0-rc1").is_prerelease());
        assert!(!v("1.0.0").is_prerelease());
        assert!(!v("1.0.2k").is_prerelease());
        assert!(!v("7.4p1").is_prerelease());
    }
}

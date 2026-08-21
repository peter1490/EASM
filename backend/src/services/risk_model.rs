//! The asset risk model: how a pile of findings becomes one number.
//!
//! # Why this replaced a clamped sum
//!
//! The previous model was `min(100, (exposure + Σ findings) × importance)`. Every
//! part of that is defensible in isolation and the combination could not rank an
//! attack surface, because the sum has no ceiling and the clamp does. Scored against
//! a synthetic population of 4,000 assets, **41% landed on exactly 100.0** and the
//! worst 400 assets shared a single score. The number said "critical" for an asset
//! with two missing headers and a stale CVE and for one with a ransomware-linked
//! remote-code-execution bug, and a triage queue sorted by it was arbitrary.
//!
//! Two findings of CVSS 9.8 were enough to saturate the scale. That is not a tuning
//! problem — no choice of constants fixes a linear sum against a hard cap, because
//! the sum grows without bound and the display range does not.
//!
//! # The model
//!
//! Four stages, each bounded, so nothing clamps and ordering never collapses.
//!
//! 1. **Per finding — impact × likelihood.** `impact` is what the weakness would cost
//!    (CVSS, or the severity band when there is no CVSS). `likelihood` is the chance
//!    anyone actually uses it, from CISA KEV membership and the FIRST EPSS
//!    probability the scanner already collects. Keeping them apart is the whole point:
//!    a CVSS 9.8 nobody has ever exploited and a CVSS 9.8 in active ransomware use are
//!    the same number to CVSS and 4x apart here. Yields a 0–100 score per finding,
//!    the analogue of a Qualys QDS or a Tenable VPR.
//!
//! 2. **Per root cause — repeats damp.** Findings are grouped by *root cause*: the CVE
//!    when there is one, the finding type otherwise. Repeats within a group decay
//!    geometrically, so the seventh missing header adds almost nothing. Grouping on
//!    the CVE rather than the type is what lets thirty distinct CVEs count as thirty
//!    problems while one CVE seen on five ports counts as roughly one.
//!
//! 3. **Across root causes — breadth damps gently.** Distinct causes are genuinely
//!    additive, but an unmaintained host with thirty dormant CVEs must not outrank a
//!    host with three that are being exploited today. A shallow decay across ranked
//!    causes keeps breadth meaningful without letting volume win.
//!
//! 4. **Projection.** The aggregate is a *hazard* — additive, unbounded, and the
//!    honest sort key. It is mapped to 0–1000 by a log-logistic curve, which
//!    approaches the ceiling polynomially rather than exponentially and so keeps
//!    separating assets long after a `1 - e^-x` curve has flattened. On the same
//!    4,000-asset population: nothing reaches 1000, and the worst 400 assets occupy
//!    95 distinct scores instead of one.
//!
//! Exposure (how reachable the asset is) and business importance scale the hazard
//! rather than the score, so they shift an asset along the curve instead of pushing
//! it into the ceiling.

use std::collections::HashMap;

/// Top of the scale. 0–1000 rather than 0–100 because the interesting assets all
/// live in the last few percent, and a hundred integers cannot separate them.
/// Qualys TruRisk, Tenable AES and Rapid7 Active Risk all landed on the same range
/// for the same reason.
pub const RISK_SCORE_MAX: f64 = 1000.0;

/// Band cut-offs on the 0–1000 scale, mirrored by `riskLevelFromScore` in the
/// frontend's `lib/severity.ts`.
pub const BAND_CRITICAL: f64 = 800.0;
pub const BAND_HIGH: f64 = 600.0;
pub const BAND_MEDIUM: f64 = 400.0;
pub const BAND_LOW: f64 = 200.0;

/// Impact of a finding whose severity is known but whose CVSS is not, as a
/// percentage of the worst imaginable outcome. These sit at the midpoints of the
/// CVSS v3.1 severity bands, so a finding with no CVSS scores where an equivalent
/// one with a CVSS would.
pub const SEVERITY_IMPACT: &[(&str, f64)] = &[
    ("critical", 90.0),
    ("high", 72.0),
    ("medium", 45.0),
    ("low", 20.0),
    ("info", 4.0),
];

/// Impact for a severity string the scanners never produce. Deliberately not zero:
/// an unrecognised grade is missing information, not an absent problem.
const UNKNOWN_SEVERITY_IMPACT: f64 = 20.0;

/// Floor of the EPSS curve: the likelihood of a CVE that EPSS scored and put at
/// essentially zero.
///
/// Not zero itself. EPSS predicts the next 30 days, and roughly 94% of CVEs are
/// never exploited at all — but "no exploitation predicted this month" is not "safe
/// forever", and an unpatched remote-code-execution bug still deserves a queue
/// position.
const LIKELIHOOD_QUIET: f64 = 0.25;

/// Likelihood for a CVE that EPSS has no score for.
///
/// Strictly above the floor of the EPSS curve, because a feed with no row for a CVE
/// is not the same as a feed that scored it near zero. The first is uncertainty and
/// the second is evidence; scoring them alike would quietly bury every CVE too new
/// or too obscure for EPSS to have reached — and "too new" is when a CVE is most
/// dangerous, not least.
const LIKELIHOOD_UNKNOWN: f64 = 0.50;

/// Likelihood when exploit code is public but the CVE is in neither KEV nor EPSS.
const LIKELIHOOD_PUBLIC_EXPLOIT: f64 = 0.65;

/// Likelihood for a finding that names no CVE at all.
///
/// An exposed database, an expired certificate or a dangling CNAME is not a
/// prediction — the scanner observed the condition. There is no exploitation
/// probability to look up because there is nothing left to exploit *first*. Ranking
/// these above an unexploited CVE is the same judgement CyCognito and SSVC make:
/// evidence of reachability beats a severity rating.
const LIKELIHOOD_OBSERVED: f64 = 0.55;

/// A finding open this long has aged as much as the model cares about.
const AGE_SATURATES_DAYS: f64 = 180.0;

/// How much six months of inaction adds to a finding's score.
///
/// Deliberately mild. Age is a signal that remediation is not happening, not that
/// the weakness got worse, and a large age term would let a forgotten `info` finding
/// climb past a fresh critical one.
const AGE_GAIN: f64 = 0.25;

/// Ceiling on one finding's modelled chance of being the way in. Nothing is certain,
/// and a probability of exactly 1.0 would make the hazard infinite.
const P_MAX: f64 = 0.97;

/// Curvature mapping a finding's 0–100 score to a probability.
///
/// Above 1.0, so the mapping is convex: the distance between a 90 and a 45 is much
/// more than twice the distance between a 45 and a 22. Without it the hazard
/// transform compresses severities together and a heap of low-severity hygiene
/// outranks one exploited critical — the exact inversion this model exists to stop.
const GAMMA: f64 = 1.5;

/// Weight of each repeat of one root cause after the first. Converges, bounding any
/// single cause at `1/(1-decay)` = 4x its own worst finding.
const CAUSE_DECAY: f64 = 0.75;

/// Weight of each successive *distinct* root cause, ranked worst first.
///
/// Close to 1.0, because distinct problems really do add up — but not equal to it.
/// At 1.0, thirty dormant CVEs outscore three under active exploitation, which is
/// how volume-driven scoring loses the plot. At 0.92 the thirtieth cause still
/// counts for 8% of the first.
const BREADTH_DECAY: f64 = 0.92;

/// Hazard floors, applied so an asset's band never contradicts the severity shown
/// next to it. Reaching for the highest that applies.
const FLOOR_CRITICAL: f64 = 0.85;
const FLOOR_HIGH: f64 = 0.45;
/// Observed exploitation is its own floor, and a high one: CISA's SSVC guidance puts
/// a known-exploited vulnerability straight into "Act". This lands such an asset in
/// the critical band on its own.
const FLOOR_KNOWN_EXPLOITED: f64 = 2.8;

/// Sharpness of the soft maximum used to apply a floor.
///
/// A plain `max` would tie every asset sitting under the floor at one score, which
/// is the saturation bug in miniature. `(a^n + f^n)^(1/n)` is always at least `f`,
/// always at least `a`, and strictly increasing in `a`, so the ordering below the
/// floor survives.
const FLOOR_SOFTNESS: f64 = 4.0;

/// Steepness of the projection curve.
const PROJECTION_K: f64 = 1.3;
/// Hazard that projects to the middle of the scale.
const PROJECTION_MIDPOINT: f64 = 1.05;

/// What the threat feeds know about one finding.
///
/// `security_scan_service` already writes every one of these into the finding's
/// `data` column from the CISA KEV catalogue and the FIRST EPSS feed. Until this
/// model existed nothing read them back: the scanner knew a CVE was in active
/// ransomware use and the risk score treated it exactly like a dormant one.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ThreatEvidence {
    /// CVE is in the CISA Known Exploited Vulnerabilities catalogue.
    pub known_exploited: bool,
    /// CISA links it to a known ransomware campaign.
    pub ransomware_linked: bool,
    /// FIRST EPSS probability of exploitation in the next 30 days.
    pub epss: Option<f64>,
    /// Public exploit code exists.
    pub public_exploit: bool,
    /// The finding names a CVE, so exploitation is predicted rather than observed.
    pub is_cve: bool,
}

/// One finding, reduced to what scoring needs.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredFinding {
    /// What actually has to be fixed: the CVE when there is one, else the finding
    /// type. Repeats of the same root cause damp against each other.
    pub root_cause: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub threat: ThreatEvidence,
    /// Days the finding has been open.
    pub age_days: f64,
    /// The operator's per-type multiplier from `finding_type_config`.
    pub type_multiplier: f64,
}

/// How reachable an asset is, from the outside.
///
/// The spread is deliberately narrow. Everything an EASM discovers is external by
/// definition, so a domain is not meaningfully safer than an IP. The previous model
/// added a flat 10 / 8 / 3 / 1 by type, which handed every certificate three points
/// of risk for existing and made asset type worth more than a low-severity finding.
pub fn exposure_factor(asset_type: &crate::models::asset::AssetType) -> f64 {
    use crate::models::asset::AssetType;
    match asset_type {
        AssetType::Ip => 1.0,
        AssetType::Domain => 0.95,
        AssetType::Port => 0.9,
        AssetType::Certificate => 0.6,
        // Organisations and ASNs are containers, not attack surface.
        _ => 0.4,
    }
}

/// Business importance as a multiplier, centred on "Normal".
///
/// The picker offers 1–5 (Negligible … Business critical) and the column defaults to
/// 0 for assets nobody has rated. The previous `1 + 0.2 × importance` mapping had two
/// faults: an unrated asset (0) scored *lower* than one explicitly marked Negligible
/// (1), and the multiplier could only ever inflate — marking something unimportant
/// could not deprioritise it. Here Normal is 1.0, unrated is treated as Normal, and
/// the ends move in both directions.
pub fn criticality_factor(importance: i32) -> f64 {
    match importance {
        1 => 0.5,  // Negligible
        2 => 0.75, // Low
        4 => 1.4,  // High
        5 => 2.0,  // Business critical
        // 3 is Normal; 0 means nobody has rated it, which is not a judgement.
        _ => 1.0,
    }
}

/// Impact: what the weakness costs if used, as a fraction of the worst case.
///
/// CVSS wins when present, because it is the finding's own measured severity rather
/// than a band it was sorted into. The old model added both — `severity_score +
/// cvss × 2` — which counted the same fact twice, since the severity was derived
/// from the CVSS in the first place. That double count is most of the reason a
/// single finding could saturate the scale.
pub fn impact(severity: &str, cvss_score: Option<f64>) -> f64 {
    let percent = match cvss_score {
        Some(cvss) if cvss > 0.0 => cvss.clamp(0.0, 10.0) * 10.0,
        _ => {
            let lower = severity.to_lowercase();
            SEVERITY_IMPACT
                .iter()
                .find(|(name, _)| *name == lower)
                .map(|(_, value)| *value)
                .unwrap_or(UNKNOWN_SEVERITY_IMPACT)
        }
    };
    percent / 100.0
}

/// Likelihood that this weakness is the one that gets used, in 0–1.
///
/// The EPSS curve is logarithmic because the EPSS distribution is extremely
/// right-skewed — a probability of 0.1 already sits near the 88th percentile, so a
/// linear reading would flatten almost every CVE to zero. Each tenfold increase in
/// probability moves a quarter of the way up the range. This is the same mapping
/// `ThreatContext::threat_score` already applies when ranking CVEs at scan time.
pub fn likelihood(threat: &ThreatEvidence) -> f64 {
    if !threat.is_cve {
        return LIKELIHOOD_OBSERVED;
    }
    if threat.known_exploited {
        return 1.0;
    }
    match threat.epss {
        Some(probability) if probability > 0.0 => {
            let scaled = ((probability.log10() + 4.0) / 4.0).clamp(0.0, 1.0);
            LIKELIHOOD_QUIET + (1.0 - LIKELIHOOD_QUIET) * scaled
        }
        _ if threat.public_exploit => LIKELIHOOD_PUBLIC_EXPLOIT,
        _ => LIKELIHOOD_UNKNOWN,
    }
}

/// How much an unresolved finding's age adds. Saturates at six months.
pub fn age_factor(age_days: f64) -> f64 {
    1.0 + AGE_GAIN * (age_days.max(0.0) / AGE_SATURATES_DAYS).min(1.0)
}

/// One finding's own score, 0–100.
///
/// Reported per finding as well as consumed here, because "why is this asset 870"
/// has to be answerable, and the answer is almost always one or two of these.
pub fn finding_score(finding: &ScoredFinding) -> f64 {
    let raw = 100.0
        * impact(&finding.severity, finding.cvss_score)
        * likelihood(&finding.threat)
        * age_factor(finding.age_days)
        * finding.type_multiplier;

    let score = raw.clamp(0.0, 100.0);

    // CISA links the CVE to a live ransomware campaign. Whatever the arithmetic
    // says, that is a drop-everything finding.
    if finding.threat.ransomware_linked {
        score.max(95.0)
    } else {
        score
    }
}

/// A finding's score as a hazard: `-ln(1 - p)`.
///
/// Hazards add. Summing them is exactly the probabilistic union
/// `1 - Π(1 - pᵢ)` — "the chance at least one of these is the way in" — which is the
/// aggregation the NIST attack-graph work argues for and the reason the total needs
/// no clamp: it is bounded by construction once projected, yet strictly increasing
/// in every finding, so no two assets tie unless their findings are identical.
fn hazard(finding_score: f64) -> f64 {
    let p = P_MAX * (finding_score / 100.0).clamp(0.0, 1.0).powf(GAMMA);
    -(1.0 - p).ln()
}

/// The aggregate, and enough of the arithmetic to explain it afterwards.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AssetHazard {
    /// Sum after both damping stages and any floor. The sort key.
    pub hazard: f64,
    /// The same sum with nothing damped, so the gap stays visible.
    pub hazard_undamped: f64,
    /// Distinct root causes that scored.
    pub root_causes: usize,
    /// Highest single finding score on the asset.
    pub worst_finding_score: f64,
    /// Whether a floor was reached, and which.
    pub floor_applied: Option<&'static str>,
}

/// Fold an asset's findings into one hazard.
pub fn aggregate(findings: &[ScoredFinding]) -> AssetHazard {
    if findings.is_empty() {
        return AssetHazard::default();
    }

    let mut by_cause: HashMap<&str, Vec<f64>> = HashMap::new();
    let mut worst_finding_score: f64 = 0.0;
    let mut worst_severity_rank = 0u8;
    let mut known_exploited = false;

    for finding in findings {
        let score = finding_score(finding);
        worst_finding_score = worst_finding_score.max(score);
        worst_severity_rank = worst_severity_rank.max(severity_rank(&finding.severity));
        known_exploited |= finding.threat.known_exploited;
        by_cause
            .entry(finding.root_cause.as_str())
            .or_default()
            .push(hazard(score));
    }

    // Rank within each cause, so damping always spares that cause's worst finding
    // regardless of the order the query returned rows in.
    let mut causes: Vec<f64> = by_cause
        .into_values()
        .map(|mut hazards| {
            hazards.sort_by(|a, b| b.total_cmp(a));
            hazards
                .iter()
                .enumerate()
                .map(|(rank, h)| h * CAUSE_DECAY.powi(rank as i32))
                .sum()
        })
        .collect();

    let hazard_undamped: f64 = findings.iter().map(|f| hazard(finding_score(f))).sum();

    // Then rank the causes against each other and damp breadth gently.
    causes.sort_by(|a, b| b.total_cmp(a));
    let summed: f64 = causes
        .iter()
        .enumerate()
        .map(|(rank, c)| c * BREADTH_DECAY.powi(rank as i32))
        .sum();

    let (floor, floor_name) = if known_exploited {
        (FLOOR_KNOWN_EXPLOITED, Some("known_exploited"))
    } else if worst_severity_rank >= severity_rank("critical") {
        (FLOOR_CRITICAL, Some("critical_finding"))
    } else if worst_severity_rank >= severity_rank("high") {
        (FLOOR_HIGH, Some("high_finding"))
    } else {
        (0.0, None)
    };

    let hazard = if floor > 0.0 {
        (summed.powf(FLOOR_SOFTNESS) + floor.powf(FLOOR_SOFTNESS)).powf(1.0 / FLOOR_SOFTNESS)
    } else {
        summed
    };

    AssetHazard {
        hazard,
        hazard_undamped,
        root_causes: causes.len(),
        worst_finding_score,
        // Only report a floor that actually did something.
        floor_applied: floor_name.filter(|_| hazard > summed + 1e-9),
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Map a hazard onto 0–1000.
///
/// `1000 · H^k / (H^k + M^k)` — a logistic in log-space. It never reaches 1000, is
/// strictly increasing, and approaches the ceiling as a power law, so it keeps
/// resolving assets far past the point where `1 - e^-H` has flattened. Doubling the
/// hazard of an already-bad asset still moves its score by tens of points; under the
/// old clamp it moved by nothing at all.
pub fn project(hazard: f64) -> f64 {
    if hazard <= 0.0 {
        return 0.0;
    }
    let h = hazard.powf(PROJECTION_K);
    let m = PROJECTION_MIDPOINT.powf(PROJECTION_K);
    RISK_SCORE_MAX * h / (h + m)
}

/// The band a score falls into.
pub fn risk_level_for(risk_score: f64) -> &'static str {
    if risk_score >= BAND_CRITICAL {
        "critical"
    } else if risk_score >= BAND_HIGH {
        "high"
    } else if risk_score >= BAND_MEDIUM {
        "medium"
    } else if risk_score >= BAND_LOW {
        "low"
    } else {
        "info"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cve(severity: &str, cvss: f64, id: &str) -> ScoredFinding {
        ScoredFinding {
            root_cause: id.to_string(),
            severity: severity.to_string(),
            cvss_score: Some(cvss),
            threat: ThreatEvidence {
                is_cve: true,
                ..Default::default()
            },
            age_days: 0.0,
            type_multiplier: 1.0,
        }
    }

    fn observed(finding_type: &str, severity: &str) -> ScoredFinding {
        ScoredFinding {
            root_cause: finding_type.to_string(),
            severity: severity.to_string(),
            cvss_score: None,
            threat: ThreatEvidence::default(),
            age_days: 0.0,
            type_multiplier: 1.0,
        }
    }

    fn score(
        findings: &[ScoredFinding],
        asset_type: crate::models::asset::AssetType,
        importance: i32,
    ) -> f64 {
        let h = aggregate(findings);
        project(h.hazard * exposure_factor(&asset_type) * criticality_factor(importance))
    }

    /// Everything the previous model got wrong, in one place.
    ///
    /// A hygiene-only site and a host with a ransomware-linked RCE both scored 100.0
    /// and both read "critical". The gap here is the whole point of the rework.
    #[test]
    fn hygiene_and_active_exploitation_are_far_apart() {
        let hygiene = [
            observed("missing_security_header", "medium"),
            observed("missing_security_header", "medium"),
            observed("missing_security_header", "medium"),
            observed("missing_security_header", "low"),
            observed("missing_security_header", "low"),
            observed("missing_security_header", "low"),
            observed("missing_security_header", "info"),
            observed("no_waf_detected", "low"),
            observed("missing_caa", "low"),
        ];
        let mut exploited = cve("critical", 9.8, "CVE-2021-44228");
        exploited.threat.known_exploited = true;
        exploited.threat.ransomware_linked = true;
        exploited.age_days = 200.0;

        let hygiene_score = score(&hygiene, crate::models::asset::AssetType::Domain, 3);
        let exploited_score = score(
            std::slice::from_ref(&exploited),
            crate::models::asset::AssetType::Domain,
            3,
        );

        assert_eq!(risk_level_for(hygiene_score), "low");
        assert_eq!(risk_level_for(exploited_score), "critical");
        assert!(
            exploited_score > hygiene_score * 3.0,
            "hygiene {hygiene_score:.1} vs exploited {exploited_score:.1}"
        );
    }

    /// The signal the scanner was already collecting and the score was throwing away.
    /// Identical CVSS, four levels of exploitation evidence, four separated scores.
    #[test]
    fn exploitation_evidence_separates_identical_cvss() {
        let quiet = cve("critical", 9.8, "CVE-A");

        let mut low_epss = quiet.clone();
        low_epss.threat.epss = Some(0.0003);

        let mut public = quiet.clone();
        public.threat.public_exploit = true;

        let mut high_epss = quiet.clone();
        high_epss.threat.epss = Some(0.42);

        let mut kev = quiet.clone();
        kev.threat.known_exploited = true;

        let at = |f: &ScoredFinding| {
            score(
                std::slice::from_ref(f),
                crate::models::asset::AssetType::Domain,
                3,
            )
        };
        let (a, b, c, d, e) = (
            at(&low_epss),
            at(&quiet),
            at(&public),
            at(&high_epss),
            at(&kev),
        );

        assert!(
            a < b && b < c && c < d && d < e,
            "{a:.1} {b:.1} {c:.1} {d:.1} {e:.1}"
        );
        // A CVE under active exploitation must land in a different band from an
        // identical one nobody has touched.
        assert_eq!(risk_level_for(b), "medium");
        assert_eq!(risk_level_for(e), "critical");
    }

    /// A CVE the feeds never answered for must not be scored as though they had
    /// answered "quiet". Absence of evidence is not evidence of absence.
    #[test]
    fn missing_intel_outranks_confirmed_quiet() {
        let unknown = cve("critical", 9.8, "CVE-A");
        let mut quiet = cve("critical", 9.8, "CVE-A");
        quiet.threat.epss = Some(0.0002);

        assert!(likelihood(&unknown.threat) > likelihood(&quiet.threat));
    }

    /// Root cause, not finding type. Thirty distinct CVEs are thirty ways in; one
    /// CVE seen on five ports is one problem found five times.
    #[test]
    fn distinct_cves_add_but_one_cve_repeated_does_not() {
        let many: Vec<_> = (0..30)
            .map(|i| cve("high", 7.5, &format!("CVE-2019-{i}")))
            .collect();
        let repeated = vec![cve("high", 7.5, "CVE-2019-0001"); 5];

        let many_score = score(&many, crate::models::asset::AssetType::Ip, 3);
        let repeated_score = score(&repeated, crate::models::asset::AssetType::Ip, 3);

        assert!(
            many_score > repeated_score * 1.5,
            "30 distinct {many_score:.1} vs 1 repeated {repeated_score:.1}"
        );
        // One cause, however many times it is seen, is bounded at 4x its worst.
        assert!(
            repeated_score < 500.0,
            "repeated reached {repeated_score:.1}"
        );
    }

    /// The inversion that volume-driven scoring always produces: an unmaintained box
    /// with a long tail of dormant CVEs must not outrank one being exploited now.
    #[test]
    fn breadth_never_beats_active_exploitation() {
        let dormant: Vec<_> = (0..30)
            .map(|i| {
                let mut f = cve("high", 7.5, &format!("CVE-2019-{i}"));
                f.threat.epss = Some(0.004);
                f
            })
            .collect();

        let exploited: Vec<_> = ["CVE-A", "CVE-B", "CVE-D"]
            .iter()
            .map(|id| {
                let mut f = cve("critical", 9.6, id);
                f.threat.known_exploited = true;
                f
            })
            .collect();

        let dormant_score = score(&dormant, crate::models::asset::AssetType::Ip, 3);
        let exploited_score = score(&exploited, crate::models::asset::AssetType::Ip, 3);

        assert!(
            exploited_score > dormant_score,
            "dormant {dormant_score:.1} vs exploited {exploited_score:.1}"
        );
    }

    /// The reason the scale is 0–1000 and the projection is log-logistic. Under the
    /// old model every one of these clamped to 100.0 and tied.
    #[test]
    fn the_worst_assets_stay_separated() {
        let base = || {
            let mut f = cve("critical", 9.8, "CVE-A");
            f.threat.known_exploited = true;
            f
        };
        let one = vec![base()];
        let two = vec![base(), cve("critical", 9.1, "CVE-B")];
        let mut three = two.clone();
        three.push(observed("database_exposed", "critical"));
        let mut four = three.clone();
        four.push(observed("subdomain_takeover", "high"));

        let scores: Vec<f64> = [one, two, three, four]
            .iter()
            .map(|f| score(f, crate::models::asset::AssetType::Ip, 5))
            .collect();

        for pair in scores.windows(2) {
            assert!(pair[1] > pair[0], "not increasing: {scores:?}");
        }
        // Every one of them is in the critical band, and every step is still worth
        // several points — 917.5, 923.3, 929.6, 933.2. Under the clamped scale all
        // four were exactly 100.0 and the queue order between them was arbitrary.
        assert!(scores.iter().all(|s| risk_level_for(*s) == "critical"));
        for pair in scores.windows(2) {
            assert!(pair[1] - pair[0] > 3.0, "steps too small: {scores:?}");
        }
        assert!(scores[3] - scores[0] > 12.0, "{scores:?}");
        // The marginal points shrink as the asset gets worse, which is the intent:
        // once a ransomware-exploited RCE is present, an extra exposed database
        // genuinely does not double the chance of compromise.
        assert!(scores[3] - scores[2] < scores[1] - scores[0], "{scores:?}");
        // Nothing reaches the ceiling.
        assert!(scores[3] < RISK_SCORE_MAX, "{:?}", scores[3]);
    }

    /// No finite pile of findings reaches 1000, so the score can always go up.
    #[test]
    fn the_ceiling_is_never_reached() {
        let everything: Vec<_> = (0..500)
            .map(|i| {
                let mut f = cve("critical", 10.0, &format!("CVE-{i}"));
                f.threat.known_exploited = true;
                f.threat.ransomware_linked = true;
                f.age_days = 900.0;
                f
            })
            .collect();

        let worst = score(&everything, crate::models::asset::AssetType::Ip, 5);
        assert!(
            worst < RISK_SCORE_MAX,
            "500 exploited criticals reached {worst}"
        );
        assert!(worst > 990.0, "should be near the top, got {worst}");
    }

    /// Business importance has to work in both directions. Under `1 + 0.2 × imp` an
    /// asset explicitly marked Negligible scored 20% *higher* than an unrated one.
    #[test]
    fn importance_can_lower_a_score_not_only_raise_it() {
        assert!(criticality_factor(1) < criticality_factor(0));
        assert_eq!(criticality_factor(3), criticality_factor(0));
        assert!(criticality_factor(5) > criticality_factor(3));

        let mut f = cve("critical", 9.8, "CVE-A");
        f.threat.known_exploited = true;
        let findings = [f];
        let negligible = score(&findings, crate::models::asset::AssetType::Domain, 1);
        let critical = score(&findings, crate::models::asset::AssetType::Domain, 5);
        assert!(
            critical > negligible * 1.3,
            "{negligible:.1} vs {critical:.1}"
        );
    }

    /// Damping ranks by contribution, so the same asset scores the same however the
    /// query happened to order its rows.
    #[test]
    fn scoring_is_independent_of_finding_order() {
        let mut forward = vec![
            cve("critical", 9.8, "CVE-A"),
            cve("medium", 5.0, "CVE-B"),
            observed("missing_security_header", "low"),
            observed("missing_security_header", "medium"),
        ];
        let reversed: Vec<_> = forward.iter().rev().cloned().collect();
        let a = aggregate(&forward).hazard;
        let b = aggregate(&reversed).hazard;
        assert!((a - b).abs() < 1e-9, "{a} vs {b}");

        forward.swap(0, 3);
        assert!((aggregate(&forward).hazard - a).abs() < 1e-9);
    }

    /// Severity and CVSS used to be added together, which counted the same fact
    /// twice because the severity is derived from the CVSS.
    #[test]
    fn cvss_replaces_the_severity_band_rather_than_adding_to_it() {
        assert!((impact("critical", Some(9.8)) - 0.98).abs() < 1e-9);
        // No CVSS: the band's midpoint stands in.
        assert!((impact("critical", None) - 0.90).abs() < 1e-9);
        // A severity the scanners never emit is missing information, not zero risk.
        assert!(impact("moderate", None) > 0.0);
    }

    /// An asset's band must never read below the severity displayed beside it, and
    /// the floor must not flatten the assets it lifts.
    #[test]
    fn the_floor_lifts_without_creating_ties() {
        let quiet_critical = [cve("critical", 9.1, "CVE-A")];
        let lifted = aggregate(&quiet_critical);
        assert_eq!(lifted.floor_applied, Some("critical_finding"));

        // Two assets under the same floor still differ.
        let mut worse = cve("critical", 9.1, "CVE-A");
        worse.threat.public_exploit = true;
        let a = aggregate(&quiet_critical).hazard;
        let b = aggregate(&[worse]).hazard;
        assert!(b > a, "floor flattened {a} and {b}");
    }

    /// An asset with nothing on it is not a risk.
    #[test]
    fn a_clean_asset_scores_zero() {
        assert_eq!(aggregate(&[]).hazard, 0.0);
        assert_eq!(project(0.0), 0.0);
        assert_eq!(risk_level_for(0.0), "info");
    }

    /// A finding left open is a finding nobody is fixing, but age must never let a
    /// stale trivium climb past a fresh serious one.
    #[test]
    fn age_matters_but_never_reorders_severities() {
        let fresh = observed("missing_security_header", "info");
        let mut stale = fresh.clone();
        stale.age_days = 3650.0;
        assert!(finding_score(&stale) > finding_score(&fresh));

        let serious = cve("high", 8.2, "CVE-A");
        assert!(finding_score(&serious) > finding_score(&stale));
        assert!((age_factor(0.0) - 1.0).abs() < 1e-9);
        assert!((age_factor(1e9) - 1.25).abs() < 1e-9);
    }

    /// Every band boundary maps back to the level the frontend documents.
    #[test]
    fn bands_match_the_documented_thresholds() {
        assert_eq!(risk_level_for(1000.0), "critical");
        assert_eq!(risk_level_for(800.0), "critical");
        assert_eq!(risk_level_for(799.9), "high");
        assert_eq!(risk_level_for(600.0), "high");
        assert_eq!(risk_level_for(599.9), "medium");
        assert_eq!(risk_level_for(400.0), "medium");
        assert_eq!(risk_level_for(399.9), "low");
        assert_eq!(risk_level_for(200.0), "low");
        assert_eq!(risk_level_for(199.9), "info");
    }

    /// The projection must be strictly increasing everywhere, or two assets could
    /// swap places for no reason.
    #[test]
    fn the_projection_is_strictly_increasing_and_bounded() {
        let mut previous = 0.0;
        let mut hazard = 0.001;
        while hazard < 1000.0 {
            let score = project(hazard);
            assert!(score > previous, "not increasing at {hazard}");
            assert!(score < RISK_SCORE_MAX, "reached the ceiling at {hazard}");
            previous = score;
            hazard *= 1.2;
        }
    }
}

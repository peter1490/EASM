use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{
        asset::Asset,
        finding_type_config::{get_severity_score, TypeWeight},
        risk::CompanyEvolutionPoint,
        security::SecurityFinding,
    },
    repositories::{AssetRepository, SecurityFindingRepository},
};
use chrono::{DateTime, Duration, Utc};
use std::cmp::Ordering;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// The finding half of a risk score.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct FindingScore {
    /// Contribution after repeats of a type are damped. This is what scores the asset.
    total: f64,
    /// The same sum without damping. Recorded alongside `total` so the gap between
    /// them is visible in an asset's stored factors rather than inferred.
    raw_total: f64,
    scored: usize,
    suppressed: usize,
}

pub struct RiskService {
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    security_finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
    finding_type_config_repo:
        Arc<dyn crate::repositories::FindingTypeConfigRepository + Send + Sync>,
    db_pool: DatabasePool,
}

impl RiskService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        security_finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
        finding_type_config_repo: Arc<
            dyn crate::repositories::FindingTypeConfigRepository + Send + Sync,
        >,
        db_pool: DatabasePool,
    ) -> Self {
        Self {
            asset_repo,
            security_finding_repo,
            finding_type_config_repo,
            db_pool,
        }
    }

    /// Per-type weights.
    ///
    /// This was a byte-identical copy of
    /// `FindingTypeConfigRepository::get_type_weights` issued against a raw pool,
    /// which is the only reason this service held a `db_pool` for scoring.
    async fn load_type_weights(&self) -> Result<HashMap<String, TypeWeight>, ApiError> {
        self.finding_type_config_repo.get_type_weights().await
    }

    /// The band a score falls into. The thresholds the frontend documents in the
    /// risk-scoring settings pane.
    fn risk_level_for(risk_score: f64) -> &'static str {
        if risk_score >= 80.0 {
            "critical"
        } else if risk_score >= 60.0 {
            "high"
        } else if risk_score >= 40.0 {
            "medium"
        } else if risk_score >= 20.0 {
            "low"
        } else {
            "info"
        }
    }

    /// Weight of each successive finding of the same type, after the first.
    ///
    /// Scoring is a linear sum, so before this a pile of small findings outranked one
    /// serious one: seven missing response headers totalled 39.5 against 36.0 for an
    /// exposed database. That is backwards, and it is not something the per-type
    /// multiplier can fix — the multiplier acts on one finding at a time.
    ///
    /// The second missing header on an asset tells you much less than the first: both
    /// have the same cause, that nobody configured headers here. So repeats of one type
    /// decay geometrically. The series converges, which bounds each type's contribution
    /// at `1 / (1 - 0.75)` = 4x its own worst finding, no matter how many there are.
    /// Distinct types still add up undamped — five different kinds of problem really is
    /// worse than one.
    const REPEAT_DECAY: f64 = 0.75;

    /// Total contribution of an asset's findings, and how that total was reached.
    fn score_findings<'a>(
        findings: impl Iterator<Item = &'a SecurityFinding>,
        weights: &HashMap<String, TypeWeight>,
    ) -> FindingScore {
        let mut by_type: HashMap<&str, Vec<f64>> = HashMap::new();
        let mut score = FindingScore::default();

        for finding in findings {
            match Self::score_finding(finding, weights) {
                Some(points) => {
                    by_type
                        .entry(finding.finding_type.as_str())
                        .or_default()
                        .push(points);
                    score.scored += 1;
                }
                None => score.suppressed += 1,
            }
        }

        for points in by_type.values_mut() {
            // Rank by contribution, so the decay always spares a type's worst finding.
            // Findings arrive in whatever order the query returned them; without this
            // the same asset could score differently between two runs.
            points.sort_by(|a, b| b.partial_cmp(a).unwrap_or(Ordering::Equal));

            for (rank, contribution) in points.iter().enumerate() {
                score.raw_total += contribution;
                score.total += contribution * Self::REPEAT_DECAY.powi(rank as i32);
            }
        }

        score
    }

    /// Points one active finding contributes, or `None` if its type is disabled.
    ///
    /// The base score comes from the finding's *own* severity, always. Configuration
    /// used to supply a `severity_score` keyed by `finding_type`, which meant every
    /// finding of a type scored identically no matter what the scanner graded it: a
    /// HIGH missing Content-Security-Policy and a LOW missing Referrer-Policy are both
    /// `missing_security_header`, so both scored the type's 3.0 while the UI displayed
    /// HIGH and LOW. The score and the severity column disagreed by construction.
    ///
    /// A type's configuration now contributes exactly one thing — a multiplier — which
    /// scales the whole type without flattening the findings inside it.
    fn score_finding(
        finding: &SecurityFinding,
        weights: &HashMap<String, TypeWeight>,
    ) -> Option<f64> {
        let weight = weights
            .get(&finding.finding_type)
            .copied()
            .unwrap_or_default();

        if !weight.is_enabled {
            return None;
        }

        let severity_score = get_severity_score(&finding.severity);
        let cvss_bonus = finding.cvss_score.map(|s| s * 2.0).unwrap_or(0.0);

        Some((severity_score + cvss_bonus) * weight.multiplier)
    }

    /// Calculate risk score for a single asset based on its security findings
    pub async fn calculate_asset_risk(
        &self,
        company_id: Uuid,
        asset_id: Uuid,
    ) -> Result<Asset, ApiError> {
        self.calculate_asset_risk_with_config(company_id, asset_id, None)
            .await
    }

    /// Recalculate one asset, optionally reusing an already-loaded scoring map.
    ///
    /// `recalculate_all_risks` used to call the public entry point in a loop of
    /// up to 10,000 assets, which re-read the whole `finding_type_config` table
    /// once per asset.
    async fn calculate_asset_risk_with_config(
        &self,
        company_id: Uuid,
        asset_id: Uuid,
        preloaded_config: Option<&HashMap<String, TypeWeight>>,
    ) -> Result<Asset, ApiError> {
        // 1. Get Asset (company-scoped)
        let asset = self
            .asset_repo
            .get_by_id(company_id, &asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

        // 2. Per-type weights. Batch callers pass them in; a single
        //    recalculation loads them here.
        let type_weights = match preloaded_config {
            Some(config) => config.clone(),
            None => self.load_type_weights().await?,
        };

        // 3. Get Security Findings for Asset (proper security findings with severity)
        let findings = self
            .security_finding_repo
            .list_by_asset(&asset_id, 1000, company_id)
            .await?;

        // 4. Score the active findings. Each one is scored from its own severity, the
        //    configuration weights the type it belongs to, and repeats of a type decay.
        //    One definition of "still needs work", shared with the SQL paths.
        let active = || {
            findings
                .iter()
                .filter(|f| crate::models::security::is_active_status(&f.status))
        };

        let mut severity_counts: HashMap<String, i32> = HashMap::new();
        for finding in active() {
            *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }

        let score = Self::score_findings(active(), &type_weights);
        let finding_score = score.total;

        // 5. Base risk from asset type and exposure
        let exposure_score = match asset.asset_type {
            crate::models::asset::AssetType::Ip => 10.0, // Public IP most exposed
            crate::models::asset::AssetType::Domain => 8.0, // Domains are exposed
            crate::models::asset::AssetType::Certificate => 3.0,
            _ => 1.0,
        };

        // 6. Apply importance multiplier (0-5 mapped to 1.0 - 2.0)
        let importance_multiplier = 1.0 + (asset.importance as f64 * 0.2);

        let mut risk_score = (exposure_score + finding_score) * importance_multiplier;

        // Cap at 100 for display purposes
        risk_score = risk_score.min(100.0);

        // 7. Determine Risk Level
        let risk_level = Self::risk_level_for(risk_score);

        // 8. Store factors for history and debugging
        let factors = json!({
            "exposure_score": exposure_score,
            "finding_score": finding_score,
            "importance_multiplier": importance_multiplier,
            "finding_count": findings.len(),
            // Not `status != resolved && status != false_positive`: that inline pair
            // disagreed with `is_active_status` — the check the loop above uses — for
            // every other status, so this number could exceed the findings actually
            // scored. Active is scored plus suppressed, by construction.
            "active_findings": score.scored + score.suppressed,
            "severity_counts": severity_counts,
            "scored_findings": score.scored,
            "suppressed_findings": score.suppressed,
            "finding_score_undamped": score.raw_total,
        });

        // 9. Update Asset with new risk data
        let updated_asset = self
            .asset_repo
            .update_risk(company_id, &asset.id, risk_score, risk_level, &factors)
            .await?;

        tracing::info!(
            "Calculated risk for asset {}: score={:.1}, level={}, findings={}, suppressed={}",
            asset.identifier,
            risk_score,
            risk_level,
            findings.len(),
            score.suppressed
        );

        Ok(updated_asset)
    }

    /// Recalculate risk for all assets
    pub async fn recalculate_all_risks(
        &self,
        company_id: Uuid,
    ) -> Result<RiskRecalculationResult, ApiError> {
        let assets = self
            .asset_repo
            .list(company_id, None, Some(10000), None)
            .await?;

        // Read the type weights once for the whole batch.
        let type_weights = self.load_type_weights().await?;

        let mut success_count = 0;
        let mut error_count = 0;
        let mut errors: Vec<String> = Vec::new();

        for asset in assets {
            match self
                .calculate_asset_risk_with_config(company_id, asset.id, Some(&type_weights))
                .await
            {
                Ok(_) => success_count += 1,
                Err(e) => {
                    error_count += 1;
                    if errors.len() < 10 {
                        errors.push(format!("{}: {}", asset.identifier, e));
                    }
                }
            }
        }

        Ok(RiskRecalculationResult {
            success_count,
            error_count,
            errors,
        })
    }

    /// Get real risk overview with actual data from database
    pub async fn get_risk_overview(&self, company_id: Uuid) -> Result<serde_json::Value, ApiError> {
        // Query assets grouped by risk level
        let risk_levels = sqlx::query_as::<_, (Option<String>, i64)>(
            r#"
            SELECT risk_level, COUNT(*) as count
            FROM assets
            WHERE risk_level IS NOT NULL AND company_id = $1
            GROUP BY risk_level
            "#,
        )
        .bind(company_id)
        .fetch_all(&self.db_pool)
        .await?;

        let mut assets_by_level: HashMap<String, i64> = HashMap::new();
        assets_by_level.insert("critical".to_string(), 0);
        assets_by_level.insert("high".to_string(), 0);
        assets_by_level.insert("medium".to_string(), 0);
        assets_by_level.insert("low".to_string(), 0);
        assets_by_level.insert("info".to_string(), 0);

        for (level, count) in risk_levels {
            if let Some(l) = level {
                assets_by_level.insert(l, count);
            }
        }

        // Get total and average risk score
        let stats = sqlx::query_as::<_, (i64, Option<f64>, Option<f64>)>(
            r#"
            SELECT 
                COUNT(*) as total,
                AVG(risk_score) as avg_score,
                SUM(risk_score) as total_score
            FROM assets
            WHERE risk_score IS NOT NULL AND company_id = $1
            "#,
        )
        .bind(company_id)
        .fetch_one(&self.db_pool)
        .await?;

        let (total_with_scores, avg_score, total_score) = stats;

        // Composition by asset type. Nothing exposed this before, so an
        // overview wanting "812 domains, 341 IPs" had to issue one filtered
        // search per type just to read back each total_count.
        let type_rows = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT asset_type::text, COUNT(*) as count
            FROM assets
            WHERE company_id = $1
            GROUP BY asset_type
            "#,
        )
        .bind(company_id)
        .fetch_all(&self.db_pool)
        .await?;

        let mut assets_by_type: HashMap<String, i64> = HashMap::new();
        for key in ["domain", "ip", "port", "certificate", "organization", "asn"] {
            assets_by_type.insert(key.to_string(), 0);
        }
        for (asset_type, count) in type_rows {
            assets_by_type.insert(asset_type, count);
        }

        // How much of the surface has never been looked at.
        let never_scanned = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM assets_enriched
            WHERE company_id = $1 AND last_scan_id IS NULL
            "#,
        )
        .bind(company_id)
        .fetch_one(&self.db_pool)
        .await?;

        // Get total assets (system-wide)
        let total_assets = self.asset_repo.count(company_id, None).await?;

        // Get findings summary (system-wide)
        let findings_summary = self
            .security_finding_repo
            .count_by_severity(company_id)
            .await?;

        Ok(json!({
            "total_risk_score": total_score.unwrap_or(0.0),
            "average_risk_score": avg_score.unwrap_or(0.0),
            "total_assets": total_assets,
            "assets_with_scores": total_with_scores,
            "assets_pending_calculation": total_assets - total_with_scores,
            "assets_by_level": assets_by_level,
            "assets_by_type": assets_by_type,
            "assets_never_scanned": never_scanned,
            "findings_by_severity": findings_summary,
        }))
    }

    /// Get assets with highest risk scores
    pub async fn get_high_risk_assets(
        &self,
        company_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Asset>, ApiError> {
        let rows = sqlx::query_as::<_, crate::models::asset::AssetRow>(
            r#"
            SELECT 
                id, asset_type, identifier, confidence, sources, metadata, comment, created_at, updated_at, seed_id, parent_id, company_id,
                first_seen_at, last_seen_at, last_discovery_run_id, status, discovery_method,
                importance, risk_score, risk_level, last_risk_run,
                last_scan_id, last_scan_status, last_scanned_at,
                open_critical, open_high, open_medium, open_low, open_info, open_total
            FROM assets_enriched
            WHERE risk_score IS NOT NULL AND company_id = $1
            ORDER BY risk_score DESC
            LIMIT $2
            "#
        )
        .bind(company_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows.into_iter().map(Asset::from).collect())
    }

    pub async fn get_company_evolution(
        &self,
        company_id: Uuid,
        limit: i64,
    ) -> Result<Vec<CompanyEvolutionPoint>, ApiError> {
        let limit = limit.max(7).min(365);
        let today = Utc::now().date_naive();
        let start_day = today - Duration::days(limit - 1);
        let start_at = DateTime::<Utc>::from_naive_utc_and_offset(
            start_day.and_hms_opt(0, 0, 0).unwrap(),
            Utc,
        );
        let end_at = DateTime::<Utc>::from_naive_utc_and_offset(
            (today + Duration::days(1)).and_hms_opt(0, 0, 0).unwrap(),
            Utc,
        );

        let risk_rows = sqlx::query_as::<_, (DateTime<Utc>, Option<f64>)>(
            r#"
            SELECT date_trunc('day', h.calculated_at) as bucket, AVG(h.risk_score) as avg_score
            FROM asset_risk_history h
            JOIN assets a ON a.id = h.asset_id
            WHERE a.company_id = $1 AND h.calculated_at >= $2
            GROUP BY bucket
            ORDER BY bucket ASC
            "#,
        )
        .bind(company_id)
        .bind(start_at)
        .fetch_all(&self.db_pool)
        .await?;

        let mut risk_by_day: HashMap<DateTime<Utc>, Option<f64>> = HashMap::new();
        for (bucket, avg_score) in risk_rows {
            risk_by_day.insert(bucket, avg_score);
        }

        let findings_rows = sqlx::query_as::<_, (DateTime<Utc>, Option<DateTime<Utc>>)>(
            r#"
            SELECT first_seen_at, resolved_at
            FROM security_findings
            WHERE company_id = $1
              AND first_seen_at <= $2
              AND (resolved_at IS NULL OR resolved_at >= $3)
            "#,
        )
        .bind(company_id)
        .bind(end_at)
        .bind(start_at)
        .fetch_all(&self.db_pool)
        .await?;

        let mut series = Vec::with_capacity(limit as usize);
        for offset in 0..limit {
            let day = start_day + Duration::days(offset);
            let day_start =
                DateTime::<Utc>::from_naive_utc_and_offset(day.and_hms_opt(0, 0, 0).unwrap(), Utc);
            let day_end = day_start + Duration::days(1);
            let active = findings_rows
                .iter()
                .filter(|(first_seen, resolved_at)| {
                    *first_seen < day_end
                        && resolved_at
                            .map(|resolved| resolved > day_end)
                            .unwrap_or(true)
                })
                .count() as i64;

            series.push(CompanyEvolutionPoint {
                timestamp: day_start,
                risk_score: risk_by_day.get(&day_start).copied().flatten(),
                active_findings: active,
            });
        }

        Ok(series)
    }
}

/// Result of bulk risk recalculation
#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskRecalculationResult {
    pub success_count: i32,
    pub error_count: i32,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::SecurityFinding;

    /// Scores are sums of products of decimals, so they land a few ULPs off the
    /// value you would write down by hand. Compare against what a human expects.
    fn assert_score(actual: Option<f64>, expected: f64) {
        let actual = actual.expect("finding should have scored");
        assert!(
            (actual - expected).abs() < 1e-9,
            "expected {expected}, got {actual}"
        );
    }

    fn finding(finding_type: &str, severity: &str, cvss: Option<f64>) -> SecurityFinding {
        let now = Utc::now();
        SecurityFinding {
            id: Uuid::new_v4(),
            security_scan_id: None,
            asset_id: Uuid::new_v4(),
            asset_value: None,
            asset_type: None,
            finding_type: finding_type.to_string(),
            severity: severity.to_string(),
            title: finding_type.to_string(),
            description: None,
            remediation: None,
            data: json!({}),
            status: "open".to_string(),
            first_seen_at: now,
            last_seen_at: now,
            resolved_at: None,
            resolved_by: None,
            cvss_score: cvss,
            cve_ids: None,
            tags: None,
            company_id: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
        }
    }

    fn weights(entries: &[(&str, f64, bool)]) -> HashMap<String, TypeWeight> {
        entries
            .iter()
            .map(|(finding_type, multiplier, is_enabled)| {
                (
                    finding_type.to_string(),
                    TypeWeight {
                        multiplier: *multiplier,
                        is_enabled: *is_enabled,
                    },
                )
            })
            .collect()
    }

    /// The regression this change exists for. Both of these are
    /// `missing_security_header`; while configuration carried a per-type severity
    /// score, both flattened to an identical 3.3 regardless of what the scanner
    /// graded them.
    #[test]
    fn same_type_scores_by_its_own_severity() {
        let config = weights(&[("missing_security_header", 1.1, true)]);

        let csp =
            RiskService::score_finding(&finding("missing_security_header", "high", None), &config);
        let referrer =
            RiskService::score_finding(&finding("missing_security_header", "low", None), &config);

        assert_score(csp, 22.0); // 20.0 high × 1.1
        assert_score(referrer, 3.3); // 3.0 low  × 1.1
    }

    #[test]
    fn multiplier_is_the_only_thing_configuration_contributes() {
        let exposed = finding("database_exposed", "high", None);

        let unconfigured = RiskService::score_finding(&exposed, &weights(&[]));
        let weighted =
            RiskService::score_finding(&exposed, &weights(&[("database_exposed", 1.8, true)]));

        assert_score(unconfigured, 20.0); // no row: severity at face value
        assert_score(weighted, 36.0); // 20.0 × 1.8
    }

    #[test]
    fn cvss_is_added_before_the_multiplier() {
        let config = weights(&[("known_cve", 1.5, true)]);
        let scored = RiskService::score_finding(&finding("known_cve", "high", Some(9.8)), &config);

        // (20.0 + 19.6) × 1.5 — the bonus is weighted by the type, not bolted on after.
        assert_score(scored, 59.4);
    }

    /// A disabled type has to score nothing. Disabled rows used to be filtered out in
    /// SQL, which sent them down the "no configuration" path and scored them at full
    /// weight — the opposite of what the toggle promises.
    #[test]
    fn disabled_type_scores_nothing() {
        let config = weights(&[("no_waf_detected", 1.0, false)]);
        assert_eq!(
            RiskService::score_finding(&finding("no_waf_detected", "low", None), &config),
            None
        );
    }

    #[test]
    fn unknown_severity_falls_back_without_panicking() {
        let scored =
            RiskService::score_finding(&finding("something_new", "moderate", None), &weights(&[]));
        assert_score(scored, 1.0);
    }

    /// The two assets that surfaced the bug, scored end to end against the seeded
    /// multipliers and the current header grades.
    ///
    /// Three rounds of numbers for these: 43.8 medium / 34.1 low when configuration
    /// supplied a per-type severity score; 91.4 / 91.9 both critical once severity
    /// drove the score but the header table still graded HSTS critical and CSP high;
    /// and these, once the multipliers stopped restating severity and the headers were
    /// graded as the hardening gaps they are.
    ///
    /// The IP leads now on the one substantive difference between the two assets — a
    /// self-signed certificate — rather than on its exposure base.
    #[test]
    fn real_assets_rank_by_severity_not_by_type() {
        // Post-recalibration: every type here scores at its severity.
        let config = weights(&[
            ("missing_security_header", 1.0, true),
            ("self_signed_certificate", 1.0, true),
            ("no_waf_detected", 1.0, true),
            ("open_port", 1.0, true),
            ("missing_caa", 1.0, true),
            ("technology_detected", 1.0, true),
        ]);

        let total = |exposure: f64, findings: &[SecurityFinding]| -> f64 {
            exposure + RiskService::score_findings(findings.iter(), &config).total
        };

        // Header severities follow `SECURITY_HEADERS`: HSTS/CSP/X-Frame-Options
        // medium, X-Content-Type-Options and the rest low, X-XSS-Protection info.
        let ip = [
            finding("missing_security_header", "medium", None), // CSP        10.0
            finding("missing_security_header", "medium", None), // HSTS       10.0
            finding("missing_security_header", "medium", None), // XFO        10.0
            finding("missing_security_header", "low", None),    // Permissions 3.0
            finding("missing_security_header", "low", None),    // Referrer    3.0
            finding("missing_security_header", "info", None),   // XSS         0.5
            finding("self_signed_certificate", "medium", None), //            10.0
            finding("no_waf_detected", "low", None),            //             3.0
            finding("open_port", "info", None),                 // 443         0.5
            finding("open_port", "info", None),                 // 53          0.5
            finding("open_port", "info", None),                 // 80          0.5
        ];

        let domain = [
            finding("missing_security_header", "medium", None), // CSP        10.0
            finding("missing_security_header", "medium", None), // HSTS       10.0
            finding("missing_security_header", "medium", None), // XFO        10.0
            finding("missing_security_header", "low", None),    // XCTO        3.0
            finding("missing_security_header", "low", None),    // Permissions 3.0
            finding("missing_security_header", "low", None),    // Referrer    3.0
            finding("missing_security_header", "info", None),   // XSS         0.5
            finding("no_waf_detected", "low", None),            //             3.0
            finding("missing_caa", "low", None),                //             3.0
            finding("technology_detected", "info", None),       //             0.5
            finding("open_port", "info", None),                 // 443         0.5
            finding("open_port", "info", None),                 // 53          0.5
            finding("open_port", "info", None),                 // 80          0.5
        ];

        // Six missing headers damp from 36.5 to 25.46, seven from 39.5 to 26.14.
        let ip_score = total(10.0, &ip);
        let domain_score = total(8.0, &domain);

        assert!((ip_score - 49.61).abs() < 0.01, "ip scored {ip_score}");
        assert!(
            (domain_score - 41.80).abs() < 0.01,
            "domain scored {domain_score}"
        );

        // Header hygiene plus a self-signed certificate is a medium asset, not a
        // critical one. The IP still leads, now on the certificate rather than on the
        // two points its asset type gets for free.
        assert_eq!(RiskService::risk_level_for(ip_score), "medium");
        assert_eq!(RiskService::risk_level_for(domain_score), "medium");
    }

    /// A missing header must never on its own outweigh a finding that is exploitable
    /// without help. Four missing headers used to be enough to rate a site critical.
    #[test]
    fn header_hygiene_cannot_reach_critical_alone() {
        let config = weights(&[("missing_security_header", 1.0, true)]);

        // Every header in `SECURITY_HEADERS` missing at once, at its graded severity.
        let all_missing = [
            finding("missing_security_header", "medium", None), // HSTS
            finding("missing_security_header", "medium", None), // CSP
            finding("missing_security_header", "medium", None), // X-Frame-Options
            finding("missing_security_header", "low", None),    // X-Content-Type
            finding("missing_security_header", "low", None),    // Referrer-Policy
            finding("missing_security_header", "low", None),    // Permissions-Policy
            finding("missing_security_header", "info", None),   // X-XSS-Protection
        ];

        // 10.0 is the most exposed asset type.
        let worst = 10.0 + RiskService::score_findings(all_missing.iter(), &config).total;

        assert!(worst < 80.0, "header-only asset reached {worst}");
        assert_eq!(RiskService::risk_level_for(worst), "low");
    }

    /// What the multiplier is for: at equal severity, a type that means the weakness
    /// is reachable now outranks one that means a missing hardening layer.
    ///
    /// Note this holds per finding, not per asset — scoring sums linearly, so seven
    /// missing headers (39.5) still total more than one exposed database (36.0). Only
    /// raising the severity the port scanner assigns exposed databases, or damping
    /// repeats of one type, would change that; the multiplier alone cannot.
    #[test]
    fn active_exposure_outranks_hygiene_at_equal_severity() {
        let config = weights(&[
            ("missing_security_header", 1.0, true),
            ("database_exposed", 1.8, true),
        ]);

        let db = RiskService::score_finding(&finding("database_exposed", "high", None), &config);
        let header =
            RiskService::score_finding(&finding("missing_security_header", "high", None), &config);

        assert_score(db, 36.0); // 20.0 × 1.8
        assert_score(header, 20.0); // 20.0 × 1.0
        assert!(db > header);
    }

    /// The ordering that motivated damping, and that a linear sum got backwards: one
    /// internet-reachable database has to outrank a completely unhardened header set.
    #[test]
    fn one_exposed_database_outranks_every_missing_header() {
        let config = weights(&[
            ("missing_security_header", 1.0, true),
            ("database_exposed", 1.8, true),
        ]);

        // `categorize_port` reports an exposed database as critical.
        let database = [finding("database_exposed", "critical", None)];
        let all_headers = [
            finding("missing_security_header", "medium", None), // HSTS
            finding("missing_security_header", "medium", None), // CSP
            finding("missing_security_header", "medium", None), // X-Frame-Options
            finding("missing_security_header", "low", None),    // X-Content-Type
            finding("missing_security_header", "low", None),    // Referrer-Policy
            finding("missing_security_header", "low", None),    // Permissions-Policy
            finding("missing_security_header", "info", None),   // X-XSS-Protection
        ];

        let database_score = RiskService::score_findings(database.iter(), &config).total;
        let header_score = RiskService::score_findings(all_headers.iter(), &config).total;

        assert_score(Some(database_score), 72.0); // 40.0 critical × 1.8
        assert!(
            database_score > header_score,
            "database {database_score} vs headers {header_score}"
        );
    }

    /// A type's contribution is bounded at `1 / (1 - REPEAT_DECAY)` = 4x its own worst
    /// finding, so no volume of one finding type can run away with an asset's score.
    #[test]
    fn repeats_of_a_type_converge_to_a_bound() {
        let config = weights(&[("missing_security_header", 1.0, true)]);
        let many: Vec<_> = (0..500)
            .map(|_| finding("missing_security_header", "medium", None))
            .collect();

        let total = RiskService::score_findings(many.iter(), &config).total;

        assert!(total < 40.0, "500 medium findings reached {total}");
        assert!(total > 39.9, "bound should be approached, got {total}");
    }

    /// Findings arrive in whatever order the query returned them, so damping must rank
    /// by contribution rather than by position — otherwise the same asset scores
    /// differently between two runs, and a trailing critical gets damped to nothing.
    #[test]
    fn damping_is_independent_of_finding_order() {
        let config = weights(&[("known_cve", 1.0, true)]);

        let worst_first = [
            finding("known_cve", "critical", None),
            finding("known_cve", "low", None),
            finding("known_cve", "medium", None),
        ];
        let worst_last = [
            finding("known_cve", "low", None),
            finding("known_cve", "medium", None),
            finding("known_cve", "critical", None),
        ];

        let a = RiskService::score_findings(worst_first.iter(), &config).total;
        let b = RiskService::score_findings(worst_last.iter(), &config).total;

        assert!((a - b).abs() < 1e-9, "{a} vs {b}");
        assert_score(Some(a), 40.0 + 10.0 * 0.75 + 3.0 * 0.5625);
    }

    /// Damping is per type. Five different kinds of problem genuinely is worse than
    /// five instances of one, and the score has to say so.
    #[test]
    fn distinct_types_do_not_damp_each_other() {
        let config = weights(&[]);
        let distinct = [
            finding("missing_security_header", "medium", None),
            finding("self_signed_certificate", "medium", None),
            finding("missing_caa", "medium", None),
            finding("no_waf_detected", "medium", None),
        ];
        let repeated = [
            finding("missing_security_header", "medium", None),
            finding("missing_security_header", "medium", None),
            finding("missing_security_header", "medium", None),
            finding("missing_security_header", "medium", None),
        ];

        let spread = RiskService::score_findings(distinct.iter(), &config);
        let piled = RiskService::score_findings(repeated.iter(), &config);

        assert_score(Some(spread.total), 40.0); // four types, no damping
        assert!(piled.total < spread.total);
        // The undamped sum is recorded either way, so the gap stays visible.
        assert_score(Some(piled.raw_total), 40.0);
    }
}

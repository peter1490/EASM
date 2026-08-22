use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{
        asset::Asset, finding_type_config::TypeWeight, risk::CompanyEvolutionPoint,
        security::SecurityFinding,
    },
    repositories::{AssetRepository, SecurityFindingRepository},
    services::risk_model::{self, ScoredFinding, ThreatEvidence},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

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

    /// Everything one active finding contributes, or `None` if its type is disabled.
    ///
    /// This is where the signals the scanners already collect finally reach the
    /// score. `security_scan_service` writes CISA KEV membership, ransomware-campaign
    /// linkage and the FIRST EPSS probability into every `known_cve` finding's `data`
    /// column, and until now scoring read none of them: a CVE under active
    /// exploitation and a dormant one with the same CVSS were the same number.
    fn scored_finding(
        finding: &SecurityFinding,
        weights: &HashMap<String, TypeWeight>,
        now: DateTime<Utc>,
    ) -> Option<ScoredFinding> {
        let weight = weights
            .get(&finding.finding_type)
            .copied()
            .unwrap_or_default();

        if !weight.is_enabled {
            return None;
        }

        let data = &finding.data;
        let flag = |key: &str| data.get(key).and_then(serde_json::Value::as_bool) == Some(true);

        // A CVE is its own root cause, so the same CVE seen on five ports damps to
        // roughly one problem while five different CVEs stay five. Anything else is
        // keyed by type, where the type *is* the cause — "nobody set headers here".
        let cve_id = finding
            .cve_ids
            .as_ref()
            .and_then(|ids| ids.first())
            .cloned()
            .or_else(|| {
                data.get("cve_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });

        let threat = ThreatEvidence {
            known_exploited: flag("known_exploited") || flag("exploitable"),
            ransomware_linked: flag("known_ransomware_campaign_use"),
            epss: data
                .get("epss_probability")
                .and_then(serde_json::Value::as_f64),
            public_exploit: flag("has_public_exploit"),
            is_cve: cve_id.is_some(),
        };

        Some(ScoredFinding {
            root_cause: cve_id.unwrap_or_else(|| finding.finding_type.clone()),
            severity: finding.severity.clone(),
            cvss_score: finding.cvss_score,
            threat,
            age_days: (now - finding.first_seen_at).num_days().max(0) as f64,
            type_multiplier: weight.multiplier,
        })
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

        // 4. Reduce the active findings to what scoring needs. One definition of
        //    "still needs work", shared with the SQL paths.
        let now = Utc::now();
        let active: Vec<&SecurityFinding> = findings
            .iter()
            .filter(|f| crate::models::security::is_active_status(&f.status))
            .collect();

        let mut severity_counts: HashMap<String, i32> = HashMap::new();
        for finding in &active {
            *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }

        let scored: Vec<ScoredFinding> = active
            .iter()
            .filter_map(|f| Self::scored_finding(f, &type_weights, now))
            .collect();
        let suppressed = active.len() - scored.len();

        // 5. Fold them into one hazard. Repeats of a root cause damp, distinct causes
        //    add with a shallow breadth decay, and a floor keeps the asset's band from
        //    contradicting the severity shown beside it.
        let aggregate = risk_model::aggregate(&scored);

        // 6. Exposure and business importance scale the hazard rather than the score,
        //    so they move the asset along the curve instead of into its ceiling.
        let exposure_factor = risk_model::exposure_factor(&asset.asset_type);
        let criticality_factor = risk_model::criticality_factor(asset.importance);
        let weighted_hazard = aggregate.hazard * exposure_factor * criticality_factor;

        // 7. Project onto 0–1000. Bounded by construction — no clamp, and no ties.
        let risk_score = risk_model::project(weighted_hazard);
        let risk_level = risk_model::risk_level_for(risk_score);

        // 8. Store the whole derivation. "Why is this asset 870" has to be answerable
        //    from the stored factors alone, without re-running the scan.
        let top_findings: Vec<serde_json::Value> = {
            let mut ranked: Vec<(f64, &ScoredFinding)> = scored
                .iter()
                .map(|f| (risk_model::finding_score(f), f))
                .collect();
            ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
            ranked
                .iter()
                .take(5)
                .map(|(score, f)| {
                    json!({
                        "root_cause": f.root_cause,
                        "severity": f.severity,
                        "score": (score * 10.0).round() / 10.0,
                        "known_exploited": f.threat.known_exploited,
                        "ransomware_linked": f.threat.ransomware_linked,
                        "epss": f.threat.epss,
                        "age_days": f.age_days,
                    })
                })
                .collect()
        };

        let factors = json!({
            "model": "hazard-v2",
            "scale_max": risk_model::RISK_SCORE_MAX,
            "hazard": aggregate.hazard,
            "hazard_undamped": aggregate.hazard_undamped,
            "weighted_hazard": weighted_hazard,
            "exposure_factor": exposure_factor,
            "criticality_factor": criticality_factor,
            "root_causes": aggregate.root_causes,
            "worst_finding_score": aggregate.worst_finding_score,
            "floor_applied": aggregate.floor_applied,
            "finding_count": findings.len(),
            "active_findings": active.len(),
            "scored_findings": scored.len(),
            "suppressed_findings": suppressed,
            "severity_counts": severity_counts,
            "top_findings": top_findings,
        });

        // 9. Update Asset with new risk data
        let updated_asset = self
            .asset_repo
            .update_risk(company_id, &asset.id, risk_score, risk_level, &factors)
            .await?;

        tracing::info!(
            "Calculated risk for asset {}: score={:.1}, level={}, hazard={:.3}, causes={}, findings={}, suppressed={}",
            asset.identifier,
            risk_score,
            risk_level,
            aggregate.hazard,
            aggregate.root_causes,
            findings.len(),
            suppressed
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
                last_scan_id, last_scan_status, last_scanned_at, last_cancelled_scan_at,
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
            -- Normalise onto the current scale. Rows predating the hazard model were
            -- scored out of 100; averaging them raw against 0-1000 rows would draw a
            -- cliff on the trend chart where only the scale changed.
            SELECT date_trunc('day', h.calculated_at) as bucket,
                   AVG(h.risk_score * 1000.0 / h.scale_max) as avg_score
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

    /// The scoring arithmetic itself is covered in `risk_model`. What matters here is
    /// the translation: a `SecurityFinding` row carries its threat evidence inside a
    /// JSONB blob, and reading the wrong keys silently drops the signal rather than
    /// failing.
    fn finding(finding_type: &str, severity: &str, data: serde_json::Value) -> SecurityFinding {
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
            data,
            status: "open".to_string(),
            first_seen_at: now,
            last_seen_at: now,
            resolved_at: None,
            resolved_by: None,
            cvss_score: None,
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

    /// The whole point of the rework: the scanner has been writing KEV and EPSS into
    /// `data` all along and scoring never read them back.
    #[test]
    fn threat_evidence_is_read_out_of_the_finding_data() {
        let f = finding(
            "known_cve",
            "critical",
            json!({
                "cve_id": "CVE-2021-44228",
                "known_exploited": true,
                "known_ransomware_campaign_use": true,
                "epss_probability": 0.9746,
                "has_public_exploit": true,
            }),
        );

        let scored = RiskService::scored_finding(&f, &weights(&[]), Utc::now()).unwrap();

        assert_eq!(scored.root_cause, "CVE-2021-44228");
        assert!(scored.threat.is_cve);
        assert!(scored.threat.known_exploited);
        assert!(scored.threat.ransomware_linked);
        assert!(scored.threat.public_exploit);
        assert_eq!(scored.threat.epss, Some(0.9746));
    }

    /// `cve_ids` is the column; `data.cve_id` is what the technology scanner writes.
    /// Either one has to key the root cause, or the same CVE on two ports stops
    /// damping against itself.
    #[test]
    fn the_cve_column_also_names_the_root_cause() {
        let mut f = finding("known_cve", "high", json!({}));
        f.cve_ids = Some(vec!["CVE-2023-1234".to_string()]);

        let scored = RiskService::scored_finding(&f, &weights(&[]), Utc::now()).unwrap();
        assert_eq!(scored.root_cause, "CVE-2023-1234");
        assert!(scored.threat.is_cve);
    }

    /// A finding with no CVE is something the scanner observed, and it is keyed by
    /// type — the type is the cause.
    #[test]
    fn an_observed_finding_is_keyed_by_type_and_is_not_a_cve() {
        let scored = RiskService::scored_finding(
            &finding("missing_security_header", "medium", json!({})),
            &weights(&[]),
            Utc::now(),
        )
        .unwrap();

        assert_eq!(scored.root_cause, "missing_security_header");
        assert!(!scored.threat.is_cve);
        assert_eq!(scored.threat.epss, None);
    }

    /// A disabled type has to score nothing. Disabled rows used to be filtered out in
    /// SQL, which sent them down the "no configuration" path and scored them at full
    /// weight — the opposite of what the toggle promises.
    #[test]
    fn disabled_type_scores_nothing() {
        assert!(RiskService::scored_finding(
            &finding("no_waf_detected", "low", json!({})),
            &weights(&[("no_waf_detected", 1.0, false)]),
            Utc::now(),
        )
        .is_none());
    }

    /// An unconfigured type is counted at face value, and a configured one carries
    /// its multiplier through to the model.
    #[test]
    fn the_type_multiplier_reaches_the_model() {
        let f = finding("database_exposed", "critical", json!({}));
        let now = Utc::now();

        let unconfigured = RiskService::scored_finding(&f, &weights(&[]), now).unwrap();
        let weighted =
            RiskService::scored_finding(&f, &weights(&[("database_exposed", 1.8, true)]), now)
                .unwrap();

        assert_eq!(unconfigured.type_multiplier, 1.0);
        assert_eq!(weighted.type_multiplier, 1.8);
        assert!(risk_model::finding_score(&weighted) > risk_model::finding_score(&unconfigured));
    }

    /// Age comes from `first_seen_at`, and a clock skew that puts it in the future
    /// must not produce a negative age.
    #[test]
    fn age_is_measured_from_first_seen_and_never_negative() {
        let now = Utc::now();
        let mut old = finding("missing_security_header", "low", json!({}));
        old.first_seen_at = now - Duration::days(90);
        assert_eq!(
            RiskService::scored_finding(&old, &weights(&[]), now)
                .unwrap()
                .age_days,
            90.0
        );

        let mut future = finding("missing_security_header", "low", json!({}));
        future.first_seen_at = now + Duration::days(5);
        assert_eq!(
            RiskService::scored_finding(&future, &weights(&[]), now)
                .unwrap()
                .age_days,
            0.0
        );
    }

    /// The two real assets that drove the previous rework, scored end to end.
    ///
    /// Under the model this replaced both came out "critical" at the 100.0 ceiling
    /// once importance was applied; under the one before that, 43.8 and 34.1. Header
    /// hygiene plus a self-signed certificate is a low-risk asset that wants tidying,
    /// not an emergency, and the score now says so while leaving the whole upper half
    /// of the scale for assets that are actually being attacked.
    #[test]
    fn real_assets_land_in_the_hygiene_band() {
        let now = Utc::now();
        let config = weights(&[]);
        let score = |asset_type: crate::models::asset::AssetType, rows: &[SecurityFinding]| {
            let scored: Vec<_> = rows
                .iter()
                .filter_map(|f| RiskService::scored_finding(f, &config, now))
                .collect();
            risk_model::project(
                risk_model::aggregate(&scored).hazard
                    * risk_model::exposure_factor(&asset_type)
                    * risk_model::criticality_factor(3),
            )
        };

        let hdr = |severity: &str| finding("missing_security_header", severity, json!({}));
        let port = || finding("open_port", "info", json!({}));

        let ip = [
            hdr("medium"),
            hdr("medium"),
            hdr("medium"),
            hdr("low"),
            hdr("low"),
            hdr("info"),
            finding("self_signed_certificate", "medium", json!({})),
            finding("no_waf_detected", "low", json!({})),
            port(),
            port(),
            port(),
        ];
        let domain = [
            hdr("medium"),
            hdr("medium"),
            hdr("medium"),
            hdr("low"),
            hdr("low"),
            hdr("low"),
            hdr("info"),
            finding("no_waf_detected", "low", json!({})),
            finding("missing_caa", "low", json!({})),
            finding("technology_detected", "info", json!({})),
            port(),
            port(),
            port(),
        ];

        let ip_score = score(crate::models::asset::AssetType::Ip, &ip);
        let domain_score = score(crate::models::asset::AssetType::Domain, &domain);

        assert_eq!(risk_model::risk_level_for(ip_score), "low");
        assert_eq!(risk_model::risk_level_for(domain_score), "low");
        // The IP still leads, on the one substantive difference between them.
        assert!(ip_score > domain_score, "{ip_score} vs {domain_score}");
    }

    /// A missing header must never on its own outweigh a weakness that is exploitable
    /// without help. Four missing headers used to be enough to rate a site critical.
    #[test]
    fn header_hygiene_cannot_outrank_an_exploited_cve() {
        let now = Utc::now();
        let config = weights(&[]);
        let hazard = |rows: &[SecurityFinding]| {
            risk_model::aggregate(
                &rows
                    .iter()
                    .filter_map(|f| RiskService::scored_finding(f, &config, now))
                    .collect::<Vec<_>>(),
            )
            .hazard
        };

        let all_headers: Vec<_> = ["medium", "medium", "medium", "low", "low", "low", "info"]
            .iter()
            .map(|s| finding("missing_security_header", s, json!({})))
            .collect();

        let mut exploited = finding(
            "known_cve",
            "critical",
            json!({ "cve_id": "CVE-2021-44228", "known_exploited": true }),
        );
        exploited.cvss_score = Some(10.0);

        let headers = hazard(&all_headers);
        let cve = hazard(std::slice::from_ref(&exploited));

        // 0.33 against 3.35 — an order of magnitude, where the old linear sum put
        // seven headers (39.5 points) *above* an exposed database (36.0).
        assert!(cve > headers * 8.0, "headers {headers} vs cve {cve}");

        // Headers alone are one root cause and land at 182: informational hygiene,
        // not an incident. The same site also missing a WAF, CAA records and running
        // exposed ports adds root causes and crosses into "low" — which is the
        // gradient the band boundary is there to express.
        assert_eq!(
            risk_model::risk_level_for(risk_model::project(headers)),
            "info"
        );
        assert_eq!(risk_model::risk_level_for(risk_model::project(cve)), "critical");
    }
}

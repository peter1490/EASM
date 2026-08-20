use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{asset::Asset, risk::CompanyEvolutionPoint},
    repositories::{AssetRepository, SecurityFindingRepository},
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

    /// Configurable scoring parameters.
    ///
    /// This was a byte-identical copy of
    /// `FindingTypeConfigRepository::get_scoring_map` issued against a raw pool,
    /// which is the only reason this service held a `db_pool` for scoring.
    async fn load_scoring_config(&self) -> Result<HashMap<String, (f64, f64)>, ApiError> {
        self.finding_type_config_repo.get_scoring_map().await
    }

    /// Fallback severity score for finding types absent from `finding_type_config`.
    ///
    /// This used to be a private copy of the same 40/20/10/3/0.5 table that
    /// `models::finding_type_config::SEVERITY_SCORES` already declared — which
    /// meant the canonical constant had no callers at all and the two could
    /// drift apart silently.
    fn get_fallback_severity_score(severity: &str) -> f64 {
        crate::models::finding_type_config::get_severity_score(severity)
    }

    /// Get fallback type multiplier for special port handling
    fn get_port_multiplier(port: i64) -> f64 {
        match port {
            22 | 3389 | 23 => 1.5,     // Remote access (SSH, Telnet, RDP)
            3306 | 5432 | 6379 => 1.8, // Databases (MySQL, PostgreSQL, Redis)
            _ => 1.0,
        }
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
        preloaded_config: Option<&HashMap<String, (f64, f64)>>,
    ) -> Result<Asset, ApiError> {
        // 1. Get Asset (company-scoped)
        let asset = self
            .asset_repo
            .get_by_id(company_id, &asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

        // 2. Scoring configuration. Batch callers pass it in; a single
        //    recalculation loads it here.
        let scoring_config = match preloaded_config {
            Some(config) => config.clone(),
            None => self.load_scoring_config().await?,
        };

        // 3. Get Security Findings for Asset (proper security findings with severity)
        let findings = self
            .security_finding_repo
            .list_by_asset(&asset_id, 1000, company_id)
            .await?;

        // 4. Calculate Score based on findings severity and type
        let mut finding_score = 0.0;
        let mut severity_counts: HashMap<String, i32> = HashMap::new();
        let mut config_used: HashMap<String, bool> = HashMap::new();

        for finding in &findings {
            // One definition of "still needs work", shared with the SQL paths.
            if !crate::models::security::is_active_status(&finding.status) {
                continue;
            }

            // Count by severity
            *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;

            // Get scoring from config or use fallbacks
            let (severity_score, type_multiplier) =
                if let Some((score, mult)) = scoring_config.get(&finding.finding_type) {
                    config_used.insert(finding.finding_type.clone(), true);
                    (*score, *mult)
                } else {
                    // Fallback to hardcoded values for unknown types
                    let severity_score = Self::get_fallback_severity_score(&finding.severity);

                    // Special handling for open_port with port-specific multipliers
                    let type_multiplier = if finding.finding_type == "open_port" {
                        if let Some(port) = finding.data.get("port").and_then(|p| p.as_i64()) {
                            Self::get_port_multiplier(port)
                        } else {
                            1.0
                        }
                    } else {
                        1.0
                    };

                    (severity_score, type_multiplier)
                };

            // Add CVSS score if available (weighted)
            let cvss_bonus = finding.cvss_score.map(|s| s * 2.0).unwrap_or(0.0);

            finding_score += (severity_score + cvss_bonus) * type_multiplier;
        }

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
        let risk_level = if risk_score >= 80.0 {
            "critical"
        } else if risk_score >= 60.0 {
            "high"
        } else if risk_score >= 40.0 {
            "medium"
        } else if risk_score >= 20.0 {
            "low"
        } else {
            "info"
        };

        // 8. Store factors for history and debugging
        let factors = json!({
            "exposure_score": exposure_score,
            "finding_score": finding_score,
            "importance_multiplier": importance_multiplier,
            "finding_count": findings.len(),
            "active_findings": findings.iter().filter(|f| f.status != "resolved" && f.status != "false_positive").count(),
            "severity_counts": severity_counts,
            "config_types_used": config_used.len(),
        });

        // 9. Update Asset with new risk data
        let updated_asset = self
            .asset_repo
            .update_risk(company_id, &asset.id, risk_score, risk_level, &factors)
            .await?;

        tracing::info!(
            "Calculated risk for asset {}: score={:.1}, level={}, findings={}, config_types={}",
            asset.identifier,
            risk_score,
            risk_level,
            findings.len(),
            config_used.len()
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

        // Read the scoring configuration once for the whole batch.
        let scoring_config = self.load_scoring_config().await?;

        let mut success_count = 0;
        let mut error_count = 0;
        let mut errors: Vec<String> = Vec::new();

        for asset in assets {
            match self
                .calculate_asset_risk_with_config(company_id, asset.id, Some(&scoring_config))
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

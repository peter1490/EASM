use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde_json::json;
use crate::{
    error::ApiError,
    repositories::{AssetRepository, SecurityFindingRepository},
    models::asset::Asset,
    database::DatabasePool,
};

pub struct RiskService {
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    security_finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
    db_pool: DatabasePool,
}

impl RiskService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        security_finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
        db_pool: DatabasePool,
    ) -> Self {
        Self {
            asset_repo,
            security_finding_repo,
            db_pool,
        }
    }

    /// Calculate risk score for a single asset based on its security findings
    pub async fn calculate_asset_risk(&self, asset_id: Uuid) -> Result<Asset, ApiError> {
        // 1. Get Asset
        let asset = self.asset_repo.get_by_id(&asset_id).await?
            .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

        // 2. Get Security Findings for Asset (proper security findings with severity)
        let findings = self.security_finding_repo.list_by_asset(&asset_id, 1000).await?;
        
        // 3. Calculate Score based on findings severity and type
        let mut finding_score = 0.0;
        let mut severity_counts: HashMap<String, i32> = HashMap::new();
        
        for finding in &findings {
            // Skip resolved or false positive findings
            if finding.status == "resolved" || finding.status == "false_positive" {
                continue;
            }
            
            // Count by severity
            *severity_counts.entry(finding.severity.clone()).or_insert(0) += 1;
            
            // Score based on severity
            let severity_score = match finding.severity.as_str() {
                "critical" => 40.0,
                "high" => 20.0,
                "medium" => 10.0,
                "low" => 3.0,
                "info" => 0.5,
                _ => 1.0,
            };
            
            // Add CVSS score if available (weighted)
            let cvss_bonus = finding.cvss_score.map(|s| s * 2.0).unwrap_or(0.0);
            
            // Additional scoring based on finding type
            let type_multiplier = match finding.finding_type.as_str() {
                "expired_certificate" | "weak_tls_version" => 1.5,
                "self_signed_certificate" | "certificate_expiring_soon" => 1.2,
                "https_not_enforced" | "missing_security_header" => 1.1,
                "reputation_issue" | "malware_detected" => 2.0,
                "open_port" => {
                    // Check for critical ports
                    if let Some(port) = finding.data.get("port").and_then(|p| p.as_i64()) {
                        match port {
                            22 | 3389 | 23 => 1.5,      // Remote access
                            3306 | 5432 | 6379 => 1.8,  // Databases
                            _ => 1.0
                        }
                    } else {
                        1.0
                    }
                },
                _ => 1.0
            };
            
            finding_score += (severity_score + cvss_bonus) * type_multiplier;
        }
        
        // 4. Base risk from asset type and exposure
        let exposure_score = match asset.asset_type {
            crate::models::asset::AssetType::Ip => 10.0,     // Public IP most exposed
            crate::models::asset::AssetType::Domain => 8.0,  // Domains are exposed
            crate::models::asset::AssetType::Certificate => 3.0,
            _ => 1.0
        };
        
        // 5. Apply importance multiplier (0-5 mapped to 1.0 - 2.0)
        let importance_multiplier = 1.0 + (asset.importance as f64 * 0.2);
        
        let mut risk_score = (exposure_score + finding_score) * importance_multiplier;
        
        // Cap at 100 for display purposes
        risk_score = risk_score.min(100.0);
        
        // 6. Determine Risk Level
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
        
        // 7. Store factors for history and debugging
        let factors = json!({
            "exposure_score": exposure_score,
            "finding_score": finding_score,
            "importance_multiplier": importance_multiplier,
            "finding_count": findings.len(),
            "active_findings": findings.iter().filter(|f| f.status != "resolved" && f.status != "false_positive").count(),
            "severity_counts": severity_counts,
        });

        // 8. Update Asset with new risk data
        let updated_asset = self.asset_repo.update_risk(
            &asset.id, 
            risk_score, 
            risk_level, 
            &factors
        ).await?;
        
        tracing::info!(
            "Calculated risk for asset {}: score={:.1}, level={}, findings={}",
            asset.identifier, risk_score, risk_level, findings.len()
        );
        
        Ok(updated_asset)
    }
    
    /// Recalculate risk for all assets
    pub async fn recalculate_all_risks(&self) -> Result<RiskRecalculationResult, ApiError> {
        let assets = self.asset_repo.list(None, Some(10000), None).await?;
        
        let mut success_count = 0;
        let mut error_count = 0;
        let mut errors: Vec<String> = Vec::new();
        
        for asset in assets {
            match self.calculate_asset_risk(asset.id).await {
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
    pub async fn get_risk_overview(&self) -> Result<serde_json::Value, ApiError> {
        // Query assets grouped by risk level
        let risk_levels = sqlx::query_as::<_, (Option<String>, i64)>(
            r#"
            SELECT risk_level, COUNT(*) as count
            FROM assets
            WHERE risk_level IS NOT NULL
            GROUP BY risk_level
            "#
        )
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
            WHERE risk_score IS NOT NULL
            "#
        )
        .fetch_one(&self.db_pool)
        .await?;
        
        let (total_with_scores, avg_score, total_score) = stats;
        
        // Get total assets
        let total_assets = self.asset_repo.count(None).await?;
        
        // Get findings summary
        let findings_summary = self.security_finding_repo.count_by_severity().await?;
        
        Ok(json!({
            "total_risk_score": total_score.unwrap_or(0.0),
            "average_risk_score": avg_score.unwrap_or(0.0),
            "total_assets": total_assets,
            "assets_with_scores": total_with_scores,
            "assets_pending_calculation": total_assets - total_with_scores,
            "assets_by_level": assets_by_level,
            "findings_by_severity": findings_summary,
        }))
    }
    
    /// Get assets with highest risk scores
    pub async fn get_high_risk_assets(&self, limit: i64) -> Result<Vec<Asset>, ApiError> {
        let rows = sqlx::query_as::<_, crate::models::asset::AssetRow>(
            r#"
            SELECT 
                id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                importance, risk_score, risk_level, last_risk_run,
                NULL::uuid as last_scan_id, NULL::text as last_scan_status, NULL::timestamptz as last_scanned_at
            FROM assets
            WHERE risk_score IS NOT NULL
            ORDER BY risk_score DESC
            LIMIT $1
            "#
        )
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        
        Ok(rows.into_iter().map(Asset::from).collect())
    }
}

/// Result of bulk risk recalculation
#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskRecalculationResult {
    pub success_count: i32,
    pub error_count: i32,
    pub errors: Vec<String>,
}

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use crate::{
    error::ApiError,
    repositories::{AssetRepository, FindingRepository},
    models::asset::Asset,
};

pub struct RiskService {
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    finding_repo: Arc<dyn FindingRepository + Send + Sync>,
}

impl RiskService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        finding_repo: Arc<dyn FindingRepository + Send + Sync>,
    ) -> Self {
        Self {
            asset_repo,
            finding_repo,
        }
    }

    pub async fn calculate_asset_risk(&self, asset_id: Uuid) -> Result<Asset, ApiError> {
        // 1. Get Asset
        let asset = self.asset_repo.get_by_id(&asset_id).await?
            .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

        // 2. Get Findings for Asset
        let findings = self.finding_repo.list_by_asset(&asset.identifier).await?;
        
        // 3. Calculate Score
        let mut finding_score = 0.0;
        
        // Weight findings by type
        for finding in &findings {
            let score = match finding.finding_type.as_str() {
                "open_port" | "port_scan" => { // Handle both potential types
                    // Check for critical ports
                    if let Some(port) = finding.data.get("port").and_then(|p| p.as_i64()) {
                        match port {
                            22 | 3389 | 23 => 10.0, // Remote access
                            80 | 443 => 1.0, // Web
                            3306 | 5432 | 6379 | 27017 => 8.0, // Databases
                            _ => 2.0
                        }
                    } else {
                        2.0
                    }
                },
                "vulnerability" => {
                    // Parse CVSS if available
                    finding.data.get("cvss").and_then(|c| c.as_f64()).unwrap_or(5.0) * 2.0
                },
                _ => 1.0
            };
            finding_score += score;
        }
        
        // Base risk from exposure
        let exposure_score = match asset.asset_type {
            crate::models::asset::AssetType::Ip => 10.0, // Public IP exposed
            crate::models::asset::AssetType::Domain => 5.0,
            _ => 1.0
        };
        
        let mut risk_score = exposure_score + finding_score;
        
        // Importance Multiplier (0-5 mapped to 1.0 - 1.5)
        let importance_multiplier = 1.0 + (asset.importance as f64 * 0.1);
        risk_score *= importance_multiplier;
        
        // 4. Determine Level
        let risk_level = if risk_score >= 100.0 {
            "critical"
        } else if risk_score >= 70.0 {
            "high"
        } else if risk_score >= 40.0 {
            "medium"
        } else if risk_score >= 10.0 {
            "low"
        } else {
            "info"
        };
        
        // Store factors for history
        let factors = json!({
            "exposure_score": exposure_score,
            "finding_score": finding_score,
            "importance_multiplier": importance_multiplier,
            "finding_count": findings.len()
        });

        // 5. Update Asset
        let updated_asset = self.asset_repo.update_risk(
            &asset.id, 
            risk_score, 
            risk_level, 
            &factors
        ).await?;
        
        Ok(updated_asset)
    }
    
    pub async fn get_risk_overview(&self) -> Result<serde_json::Value, ApiError> {
        // Placeholder for overview
        Ok(json!({
            "total_risk_score": 0, 
            "assets_by_level": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }))
    }
}

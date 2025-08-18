use axum::{
    extract::{Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use crate::{
    error::ApiError,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct RiskCalculationRequest {
    /// Base CVSS score (0.0 - 10.0)
    pub cvss_score: f64,
    /// Asset criticality multiplier (0.0 - 2.0)
    pub asset_criticality: Option<f64>,
    /// Exploitability multiplier (0.0 - 2.0)
    pub exploitability: Option<f64>,
    /// Asset type for context
    pub asset_type: Option<String>,
    /// Additional context factors
    pub has_public_exploit: Option<bool>,
    pub is_internet_facing: Option<bool>,
    pub has_sensitive_data: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RiskCalculationResponse {
    /// Original CVSS score
    pub cvss_score: f64,
    /// Calculated risk score after multipliers
    pub risk_score: f64,
    /// Risk level (Low, Medium, High, Critical)
    pub risk_level: String,
    /// Asset criticality multiplier applied
    pub asset_criticality_multiplier: f64,
    /// Exploitability multiplier applied
    pub exploitability_multiplier: f64,
    /// Breakdown of calculation
    pub calculation_details: RiskCalculationDetails,
}

#[derive(Debug, Serialize)]
pub struct RiskCalculationDetails {
    pub base_score: f64,
    pub criticality_adjustment: f64,
    pub exploitability_adjustment: f64,
    pub context_adjustments: Vec<String>,
    pub final_calculation: String,
}

pub async fn calculate_risk(
    State(_app_state): State<AppState>,
    Query(request): Query<RiskCalculationRequest>,
) -> Result<Json<RiskCalculationResponse>, ApiError> {
    // Validate CVSS score
    if !(0.0..=10.0).contains(&request.cvss_score) {
        return Err(ApiError::Validation(
            "CVSS score must be between 0.0 and 10.0".to_string()
        ));
    }

    // Default multipliers based on Python backend logic
    let asset_criticality_multiplier = request.asset_criticality.unwrap_or(1.0).clamp(0.0, 2.0);
    let exploitability_multiplier = request.exploitability.unwrap_or(1.0).clamp(0.0, 2.0);

    // Context-based adjustments
    let mut context_adjustments = Vec::new();
    let mut context_multiplier = 1.0;

    if request.has_public_exploit.unwrap_or(false) {
        context_multiplier *= 1.2;
        context_adjustments.push("Public exploit available (+20%)".to_string());
    }

    if request.is_internet_facing.unwrap_or(false) {
        context_multiplier *= 1.1;
        context_adjustments.push("Internet-facing asset (+10%)".to_string());
    }

    if request.has_sensitive_data.unwrap_or(false) {
        context_multiplier *= 1.15;
        context_adjustments.push("Contains sensitive data (+15%)".to_string());
    }

    // Asset type specific adjustments
    if let Some(ref asset_type) = request.asset_type {
        match asset_type.to_lowercase().as_str() {
            "web_server" | "database" | "api" => {
                context_multiplier *= 1.1;
                context_adjustments.push(format!("High-value asset type: {} (+10%)", asset_type));
            }
            "workstation" | "mobile" => {
                context_multiplier *= 0.9;
                context_adjustments.push(format!("Lower-risk asset type: {} (-10%)", asset_type));
            }
            _ => {}
        }
    }

    // Calculate final risk score
    let base_adjusted = request.cvss_score * asset_criticality_multiplier;
    let exploit_adjusted = base_adjusted * exploitability_multiplier;
    let final_score = (exploit_adjusted * context_multiplier).min(10.0);

    // Determine risk level
    let risk_level = match final_score {
        score if score >= 9.0 => "Critical",
        score if score >= 7.0 => "High", 
        score if score >= 4.0 => "Medium",
        _ => "Low",
    }.to_string();

    let calculation_details = RiskCalculationDetails {
        base_score: request.cvss_score,
        criticality_adjustment: asset_criticality_multiplier,
        exploitability_adjustment: exploitability_multiplier,
        context_adjustments,
        final_calculation: format!(
            "{:.1} × {:.1} × {:.1} × {:.2} = {:.1}",
            request.cvss_score,
            asset_criticality_multiplier,
            exploitability_multiplier,
            context_multiplier,
            final_score
        ),
    };

    let response = RiskCalculationResponse {
        cvss_score: request.cvss_score,
        risk_score: final_score,
        risk_level,
        asset_criticality_multiplier,
        exploitability_multiplier,
        calculation_details,
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_risk_calculation_basic() {
        // Test basic calculation without multipliers
        let cvss_score: f64 = 7.5;
        let asset_criticality: f64 = 1.0;
        let exploitability: f64 = 1.0;
        let context_multiplier: f64 = 1.0;
        
        let expected = cvss_score * asset_criticality * exploitability * context_multiplier;
        assert_eq!(expected, 7.5);
    }

    #[test]
    fn test_risk_calculation_with_multipliers() {
        // Test calculation with multipliers
        let cvss_score: f64 = 6.0;
        let asset_criticality: f64 = 1.5; // High criticality
        let exploitability: f64 = 1.3; // High exploitability
        let context_multiplier: f64 = 1.2; // Public exploit
        
        let expected = (cvss_score * asset_criticality * exploitability * context_multiplier).min(10.0);
        assert_eq!(expected, 10.0); // Should be capped at 10.0
    }

    #[test]
    fn test_risk_level_classification() {
        assert_eq!(classify_risk_level(9.5), "Critical");
        assert_eq!(classify_risk_level(8.0), "High");
        assert_eq!(classify_risk_level(5.5), "Medium");
        assert_eq!(classify_risk_level(2.0), "Low");
    }

    fn classify_risk_level(score: f64) -> &'static str {
        match score {
            score if score >= 9.0 => "Critical",
            score if score >= 7.0 => "High", 
            score if score >= 4.0 => "Medium",
            _ => "Low",
        }
    }
}
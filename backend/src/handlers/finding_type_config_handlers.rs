use axum::{
    extract::{Path, State},
    response::Json,
};

use crate::error::ApiError;
use crate::models::finding_type_config::{
    FindingTypeConfig, FindingTypeConfigBulkUpdate, FindingTypeConfigListResponse,
    FindingTypeConfigUpdate,
};
use crate::AppState;

/// List all finding type configurations
pub async fn list_finding_type_configs(
    State(state): State<AppState>,
) -> Result<Json<FindingTypeConfigListResponse>, ApiError> {
    let configs = state.finding_type_config_repo.list().await?;

    let categories = state.finding_type_config_repo.get_categories().await?;

    let response = FindingTypeConfigListResponse {
        total_count: configs.len() as i64,
        configs,
        categories,
    };

    Ok(Json(response))
}

/// Get a single finding type configuration
pub async fn get_finding_type_config(
    State(state): State<AppState>,
    Path(finding_type): Path<String>,
) -> Result<Json<FindingTypeConfig>, ApiError> {
    let config = state
        .finding_type_config_repo
        .get_by_finding_type(&finding_type)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Finding type '{}' not found", finding_type)))?;

    Ok(Json(config))
}

/// Update a finding type configuration
pub async fn update_finding_type_config(
    State(state): State<AppState>,
    Path(finding_type): Path<String>,
    Json(update): Json<FindingTypeConfigUpdate>,
) -> Result<Json<FindingTypeConfig>, ApiError> {
    // Validate severity_score and type_multiplier if provided
    if let Some(score) = update.severity_score {
        if score < 0.0 || score > 100.0 {
            return Err(ApiError::validation(
                "severity_score must be between 0 and 100",
            ));
        }
    }

    if let Some(mult) = update.type_multiplier {
        if mult < 0.1 || mult > 10.0 {
            return Err(ApiError::validation(
                "type_multiplier must be between 0.1 and 10.0",
            ));
        }
    }

    if let Some(ref severity) = update.default_severity {
        let valid_severities = ["critical", "high", "medium", "low", "info"];
        if !valid_severities.contains(&severity.to_lowercase().as_str()) {
            return Err(ApiError::validation(format!(
                "Invalid severity '{}'. Must be one of: {:?}",
                severity, valid_severities
            )));
        }
    }

    let config = state
        .finding_type_config_repo
        .update(&finding_type, &update)
        .await?;

    tracing::info!(
        finding_type = %finding_type,
        "Updated finding type configuration"
    );

    Ok(Json(config))
}

/// Bulk update response
#[derive(serde::Serialize)]
pub struct BulkUpdateResponse {
    pub updated: Vec<FindingTypeConfig>,
    pub updated_count: usize,
    pub errors: Vec<String>,
    pub error_count: usize,
}

/// Bulk update multiple finding type configurations
pub async fn bulk_update_finding_type_configs(
    State(state): State<AppState>,
    Json(bulk_update): Json<FindingTypeConfigBulkUpdate>,
) -> Result<Json<BulkUpdateResponse>, ApiError> {
    let mut updated: Vec<FindingTypeConfig> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for item in bulk_update.configs {
        // Validate
        if let Some(score) = item.severity_score {
            if score < 0.0 || score > 100.0 {
                errors.push(format!(
                    "{}: severity_score must be between 0 and 100",
                    item.finding_type
                ));
                continue;
            }
        }

        if let Some(mult) = item.type_multiplier {
            if mult < 0.1 || mult > 10.0 {
                errors.push(format!(
                    "{}: type_multiplier must be between 0.1 and 10.0",
                    item.finding_type
                ));
                continue;
            }
        }

        let update = FindingTypeConfigUpdate {
            display_name: None,
            default_severity: item.default_severity,
            severity_score: item.severity_score,
            type_multiplier: item.type_multiplier,
            description: None,
            is_enabled: item.is_enabled,
        };

        match state
            .finding_type_config_repo
            .update(&item.finding_type, &update)
            .await
        {
            Ok(config) => updated.push(config),
            Err(e) => errors.push(format!("{}: {}", item.finding_type, e)),
        }
    }

    tracing::info!(
        updated_count = updated.len(),
        error_count = errors.len(),
        "Bulk updated finding type configurations"
    );

    Ok(Json(BulkUpdateResponse {
        updated_count: updated.len(),
        error_count: errors.len(),
        updated,
        errors,
    }))
}

/// Get the scoring map for risk calculation (internal use)
pub async fn get_scoring_map(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let map = state.finding_type_config_repo.get_scoring_map().await?;

    // Convert to a more readable format
    let formatted: Vec<serde_json::Value> = map
        .into_iter()
        .map(|(ft, (score, mult))| {
            serde_json::json!({
                "finding_type": ft,
                "severity_score": score,
                "type_multiplier": mult
            })
        })
        .collect();

    Ok(Json(formatted))
}


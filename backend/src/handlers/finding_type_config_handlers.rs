use axum::{
    extract::{Extension, Path, State},
    response::Json,
};

use crate::auth::context::UserContext;
use crate::error::ApiError;
use crate::models::finding_type_config::{
    FindingTypeConfig, FindingTypeConfigBulkUpdate, FindingTypeConfigListResponse,
    FindingTypeConfigUpdate, MULTIPLIER_MAX, MULTIPLIER_MIN,
};
use crate::AppState;

/// These endpoints sit behind `/api/admin/` but took no `UserContext` at all,
/// so any authenticated user — a Viewer included — could rewrite the global
/// risk-scoring weights that drive every score in the product. The table is
/// global rather than company-scoped, which makes it worse, not better: one
/// company's admin editing it would change every other company's scores. So
/// the gate is the global role, not `has_role(Role::Admin)`, which the active
/// company's membership role also satisfies.
fn require_global_admin(user: &UserContext) -> Result<(), ApiError> {
    if user.is_global_admin() {
        return Ok(());
    }
    Err(ApiError::Authorization(
        "Global admin role required to change risk scoring configuration".to_string(),
    ))
}

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
    Extension(user): Extension<UserContext>,
    Path(finding_type): Path<String>,
    Json(update): Json<FindingTypeConfigUpdate>,
) -> Result<Json<FindingTypeConfig>, ApiError> {
    require_global_admin(&user)?;

    if let Some(mult) = update.type_multiplier {
        if !(MULTIPLIER_MIN..=MULTIPLIER_MAX).contains(&mult) {
            return Err(ApiError::validation(format!(
                "type_multiplier must be between {} and {}",
                MULTIPLIER_MIN, MULTIPLIER_MAX
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
    Extension(user): Extension<UserContext>,
    Json(bulk_update): Json<FindingTypeConfigBulkUpdate>,
) -> Result<Json<BulkUpdateResponse>, ApiError> {
    require_global_admin(&user)?;

    let mut updated: Vec<FindingTypeConfig> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for item in bulk_update.configs {
        if let Some(mult) = item.type_multiplier {
            if !(MULTIPLIER_MIN..=MULTIPLIER_MAX).contains(&mult) {
                errors.push(format!(
                    "{}: type_multiplier must be between {} and {}",
                    item.finding_type, MULTIPLIER_MIN, MULTIPLIER_MAX
                ));
                continue;
            }
        }

        let update = FindingTypeConfigUpdate {
            display_name: None,
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

/// Get the per-type weights used by risk calculation (internal use)
pub async fn get_scoring_map(
    State(state): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let weights = state.finding_type_config_repo.get_type_weights().await?;

    let mut formatted: Vec<serde_json::Value> = weights
        .into_iter()
        .map(|(finding_type, weight)| {
            serde_json::json!({
                "finding_type": finding_type,
                "type_multiplier": weight.multiplier,
                "is_enabled": weight.is_enabled,
            })
        })
        .collect();

    // A HashMap iterates in an arbitrary order, so the same configuration used to
    // come back shuffled on every call.
    formatted.sort_by(|a, b| a["finding_type"].as_str().cmp(&b["finding_type"].as_str()));

    Ok(Json(formatted))
}

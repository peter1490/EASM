use crate::{
    auth::{context::UserContext, rbac::Role},
    error::ApiError,
    models::asset::Asset,
    services::RiskRecalculationResult,
    AppState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct RiskOverviewResponse {
    pub total_risk_score: f64,
    pub assets_by_level: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct HighRiskQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    20
}

/// GET /api/risk/assets/:id - Get risk data for a specific asset
pub async fn get_asset_risk(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    // Just return the asset, it includes risk fields
    let asset = app_state
        .asset_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;
    Ok(Json(asset))
}

/// POST /api/risk/assets/:id/recalculate - Recalculate risk for a single asset
pub async fn recalculate_asset_risk(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required".to_string(),
        ));
    }

    let company_id = user.company_id.unwrap_or_default();
    let asset = app_state
        .risk_service
        .calculate_asset_risk(company_id, id)
        .await?;
    Ok(Json(asset))
}

/// POST /api/risk/recalculate-all - Recalculate risk for all assets
pub async fn recalculate_all_risks(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<RiskRecalculationResult>, ApiError> {
    if !user.has_role(Role::Operator) && !user.has_role(Role::Admin) {
        return Err(ApiError::Authorization(
            "Operator role or higher required".to_string(),
        ));
    }

    let company_id = user.company_id.unwrap_or_default();
    let result = app_state
        .risk_service
        .recalculate_all_risks(company_id)
        .await?;
    Ok(Json(result))
}

/// GET /api/risk/overview - Get comprehensive risk overview
pub async fn get_risk_overview(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let overview = app_state.risk_service.get_risk_overview(company_id).await?;
    Ok(Json(overview))
}

/// GET /api/risk/high-risk-assets - Get assets with highest risk scores
pub async fn get_high_risk_assets(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<HighRiskQuery>,
) -> Result<Json<Vec<Asset>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let assets = app_state
        .risk_service
        .get_high_risk_assets(company_id, query.limit)
        .await?;
    Ok(Json(assets))
}

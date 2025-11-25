use axum::{
    extract::{Path, State, Extension},
    response::Json,
};
use serde::Serialize;
use uuid::Uuid;
use crate::{
    error::ApiError,
    AppState,
    models::asset::Asset,
    auth::{context::UserContext, rbac::Role},
};

#[derive(Debug, Serialize)]
pub struct RiskOverviewResponse {
    pub total_risk_score: f64,
    pub assets_by_level: serde_json::Value,
}

pub async fn get_asset_risk(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    // Just return the asset, it includes risk fields
    let asset = app_state.asset_repository.get_by_id(&id).await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;
    Ok(Json(asset))
}

pub async fn recalculate_asset_risk(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    if !user.has_role(Role::Analyst) && !user.has_role(Role::Operator) && !user.has_role(Role::Admin) {
         return Err(ApiError::Authorization("Analyst role or higher required".to_string()));
    }

    let asset = app_state.risk_service.calculate_asset_risk(id).await?;
    Ok(Json(asset))
}

pub async fn get_risk_overview(
    State(app_state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let overview = app_state.risk_service.get_risk_overview().await?;
    Ok(Json(overview))
}

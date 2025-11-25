use axum::{
    extract::{Path, Query, State, Extension},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{
    error::ApiError,
    models::{Asset, Seed, SeedCreate},
    AppState,
    auth::{context::UserContext, rbac::Role},
};

#[derive(Debug, Deserialize)]
pub struct AssetQuery {
    #[serde(default, alias = "min_confidence")]
    confidence_threshold: Option<f64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AssetListResponse {
    pub assets: Vec<Asset>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateImportanceRequest {
    pub importance: i32,
}

pub async fn create_seed(
    State(app_state): State<AppState>,
    Json(payload): Json<SeedCreate>,
) -> Result<Json<Seed>, ApiError> {
    let seed = app_state.discovery_service.create_seed(payload).await?;
    Ok(Json(seed))
}

pub async fn list_seeds(
    State(app_state): State<AppState>,
) -> Result<Json<Vec<Seed>>, ApiError> {
    let seeds = app_state.discovery_service.list_seeds().await?;
    Ok(Json(seeds))
}

pub async fn delete_seed(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<()>, ApiError> {
    app_state.discovery_service.delete_seed(&id).await?;
    Ok(Json(()))
}

pub async fn list_assets(
    State(app_state): State<AppState>,
    Query(params): Query<AssetQuery>,
) -> Result<Json<AssetListResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25);
    let offset = params.offset.unwrap_or(0);
    
    let assets = app_state.discovery_service.list_assets(
        params.confidence_threshold,
        Some(limit),
        Some(offset),
    ).await?;
    
    let total_count = app_state.discovery_service.count_assets(
        params.confidence_threshold,
    ).await?;
    
    Ok(Json(AssetListResponse {
        assets,
        total_count,
        limit,
        offset,
    }))
}

pub async fn get_asset(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    let asset = app_state.discovery_service.get_asset(&id).await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;
    Ok(Json(asset))
}

pub async fn get_asset_path(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Asset>>, ApiError> {
    let path = app_state.discovery_service.get_asset_path(&id).await?;
    Ok(Json(path))
}

pub async fn update_asset_importance(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateImportanceRequest>,
) -> Result<Json<Asset>, ApiError> {
    if !user.has_role(Role::Analyst) && !user.has_role(Role::Operator) && !user.has_role(Role::Admin) {
         return Err(ApiError::Authorization("Analyst role or higher required".to_string()));
    }
    
    if payload.importance < 0 || payload.importance > 5 {
        return Err(ApiError::Validation("Importance must be between 0 and 5".to_string()));
    }

    let asset = app_state.asset_repository.update_importance(&id, payload.importance).await?;
    Ok(Json(asset))
}

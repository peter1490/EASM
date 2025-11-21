use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{
    error::ApiError,
    models::{Asset, Seed, SeedCreate},
    AppState,
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
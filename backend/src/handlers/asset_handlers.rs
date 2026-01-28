use crate::{
    auth::{context::UserContext, rbac::Role},
    error::ApiError,
    models::{Asset, AssetEvolutionResponse, AssetScanHistoryEntry, AssetType, Seed, SeedCreate},
    AppState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AssetQuery {
    #[serde(default, alias = "min_confidence")]
    confidence_threshold: Option<f64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

/// Advanced search query parameters for assets
#[derive(Debug, Deserialize)]
pub struct AssetSearchQuery {
    /// Text search across value, sources, and metadata
    #[serde(default)]
    pub q: Option<String>,
    /// Filter by asset type (domain, ip)
    #[serde(default)]
    pub asset_type: Option<String>,
    /// Minimum confidence threshold
    #[serde(default)]
    pub min_confidence: Option<f64>,
    /// Filter by scan status: "scanned", "never_scanned", or "all"
    #[serde(default)]
    pub scan_status: Option<String>,
    /// Filter by source (exact match)
    #[serde(default)]
    pub source: Option<String>,
    /// Filter by risk level
    #[serde(default)]
    pub risk_level: Option<String>,
    /// Sort field: "created_at", "confidence", "value", "importance"
    #[serde(default)]
    pub sort_by: Option<String>,
    /// Sort direction: "asc" or "desc"
    #[serde(default)]
    pub sort_dir: Option<String>,
    /// Pagination limit
    #[serde(default)]
    pub limit: Option<i64>,
    /// Pagination offset
    #[serde(default)]
    pub offset: Option<i64>,
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

#[derive(Debug, Deserialize)]
pub struct AssetEvolutionQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

pub async fn create_seed(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<SeedCreate>,
) -> Result<Json<Seed>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let seed = app_state
        .discovery_service
        .create_seed(payload, company_id)
        .await?;
    Ok(Json(seed))
}

pub async fn list_seeds(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Vec<Seed>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let seeds = app_state.discovery_service.list_seeds(company_id).await?;
    Ok(Json(seeds))
}

pub async fn delete_seed(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<()>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    app_state
        .discovery_service
        .delete_seed(company_id, &id)
        .await?;
    Ok(Json(()))
}

pub async fn list_assets(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(params): Query<AssetQuery>,
) -> Result<Json<AssetListResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25);
    let offset = params.offset.unwrap_or(0);
    let company_id = user.company_id.unwrap_or_default(); // Fallback for API keys/Global or handle error

    let assets = app_state
        .discovery_service
        .list_assets(
            company_id,
            params.confidence_threshold,
            Some(limit),
            Some(offset),
        )
        .await?;

    let total_count = app_state
        .discovery_service
        .count_assets(company_id, params.confidence_threshold)
        .await?;

    Ok(Json(AssetListResponse {
        assets,
        total_count,
        limit,
        offset,
    }))
}

pub async fn get_asset(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let asset = app_state
        .discovery_service
        .get_asset(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;
    Ok(Json(asset))
}

pub async fn get_asset_path(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Asset>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let path = app_state
        .discovery_service
        .get_asset_path(company_id, &id)
        .await?;
    Ok(Json(path))
}

pub async fn update_asset_importance(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateImportanceRequest>,
) -> Result<Json<Asset>, ApiError> {
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required".to_string(),
        ));
    }

    if payload.importance < 0 || payload.importance > 5 {
        return Err(ApiError::Validation(
            "Importance must be between 0 and 5".to_string(),
        ));
    }

    let company_id = user.company_id.unwrap_or_default();
    let asset = app_state
        .asset_repository
        .update_importance(company_id, &id, payload.importance)
        .await?;
    Ok(Json(asset))
}

/// GET /api/assets/:id/evolution - Get evolution history for an asset
pub async fn get_asset_evolution(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Query(params): Query<AssetEvolutionQuery>,
) -> Result<Json<AssetEvolutionResponse>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let limit = params.limit.unwrap_or(50).min(200);

    // Ensure asset exists and is accessible
    let _asset = app_state
        .asset_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;

    let risk_history = app_state
        .asset_repository
        .get_risk_history(company_id, &id, limit)
        .await?;

    let scans = app_state
        .security_scan_service
        .list_scans_for_asset(&id, company_id)
        .await?;

    let scan_history: Vec<AssetScanHistoryEntry> = scans
        .into_iter()
        .take(limit as usize)
        .map(|scan| AssetScanHistoryEntry {
            id: scan.id,
            scan_type: scan.scan_type,
            status: scan.status,
            created_at: scan.created_at,
            started_at: scan.started_at,
            completed_at: scan.completed_at,
            result_summary: scan.result_summary,
        })
        .collect();

    Ok(Json(AssetEvolutionResponse {
        risk_history,
        scan_history,
    }))
}

/// Advanced search response with sources list
#[derive(Debug, Serialize)]
pub struct AssetSearchResponse {
    pub assets: Vec<Asset>,
    pub total_count: i64,
    pub sources: Vec<String>,
    pub limit: i64,
    pub offset: i64,
}

/// Advanced asset search endpoint with full-text search and filtering
pub async fn search_assets(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(params): Query<AssetSearchQuery>,
) -> Result<Json<AssetSearchResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25).min(500);
    let offset = params.offset.unwrap_or(0);
    let company_id = user.company_id.unwrap_or_default();

    // Parse asset type if provided
    let asset_type = params
        .asset_type
        .as_ref()
        .and_then(|t| match t.to_lowercase().as_str() {
            "domain" => Some(AssetType::Domain),
            "ip" => Some(AssetType::Ip),
            _ => None,
        });

    // Parse sort options
    let sort_by = params.sort_by.as_deref().unwrap_or("created_at");
    let sort_dir = params.sort_dir.as_deref().unwrap_or("desc");

    // Call the repository search method
    let (assets, total_count, sources) = app_state
        .asset_repository
        .search(
            company_id,
            params.q.as_deref(),
            asset_type,
            params.min_confidence,
            params.scan_status.as_deref(),
            params.source.as_deref(),
            params.risk_level.as_deref(),
            sort_by,
            sort_dir,
            limit,
            offset,
        )
        .await?;

    Ok(Json(AssetSearchResponse {
        assets,
        total_count,
        sources,
        limit,
        offset,
    }))
}

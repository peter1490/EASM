use axum::{
    extract::{Path, State},
    response::Json,
};
use uuid::Uuid;
use crate::{
    error::ApiError,
    models::{Scan, ScanCreate},
    AppState,
};

pub async fn create_scan(
    State(app_state): State<AppState>,
    Json(payload): Json<ScanCreate>,
) -> Result<Json<Scan>, ApiError> {
    let scan = app_state.scan_service.create_scan(payload).await?;
    Ok(Json(scan))
}

pub async fn get_scan(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::ScanDetailResponse>, ApiError> {
    let scan = app_state.scan_service.get_scan_with_findings(&id).await?
        .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))?;
    Ok(Json(scan))
}

pub async fn list_scans(
    State(app_state): State<AppState>,
) -> Result<Json<Vec<crate::models::ScanListResponse>>, ApiError> {
    let scans = app_state.scan_service.list_scans_with_findings_count().await?;
    Ok(Json(scans))
}
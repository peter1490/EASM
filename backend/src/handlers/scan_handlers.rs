use crate::{
    auth::context::UserContext,
    error::ApiError,
    models::{Scan, ScanCreate},
    AppState,
};
use axum::{
    extract::{Extension, Path, State},
    response::Json,
};
use uuid::Uuid;

pub async fn create_scan(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<ScanCreate>,
) -> Result<Json<Scan>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let scan = app_state
        .scan_service
        .create_scan(payload, company_id)
        .await?;
    Ok(Json(scan))
}

pub async fn get_scan(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::models::ScanDetailResponse>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let scan = app_state
        .scan_service
        .get_scan_with_findings(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))?;
    Ok(Json(scan))
}

pub async fn list_scans(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Vec<crate::models::ScanListResponse>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let scans = app_state
        .scan_service
        .list_scans_with_findings_count(company_id)
        .await?;
    Ok(Json(scans))
}

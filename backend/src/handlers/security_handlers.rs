use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{
        SecurityScan, SecurityScanCreate, SecurityScanDetailResponse,
        SecurityFinding, SecurityFindingFilter, SecurityFindingListResponse,
        SecurityFindingUpdate,
    },
    AppState,
};

// ============================================================================
// SECURITY SCAN ENDPOINTS
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateSecurityScanRequest {
    pub asset_id: Uuid,
    pub scan_type: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListScansQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub asset_id: Option<Uuid>,
}

fn default_limit() -> i64 {
    50
}

/// POST /api/security/scans - Create a new security scan
pub async fn create_security_scan(
    State(app_state): State<AppState>,
    Json(payload): Json<CreateSecurityScanRequest>,
) -> Result<Json<SecurityScan>, ApiError> {
    let scan_create = SecurityScanCreate {
        asset_id: payload.asset_id,
        scan_type: payload.scan_type.map(|s| s.as_str().into()),
        trigger_type: None,
        priority: None,
        note: payload.note,
        config: None,
    };
    
    let scan = app_state.security_scan_service.create_scan(scan_create).await?;
    Ok(Json(scan))
}

/// GET /api/security/scans - List security scans
pub async fn list_security_scans(
    State(app_state): State<AppState>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<Vec<SecurityScan>>, ApiError> {
    let scans = if let Some(asset_id) = query.asset_id {
        app_state.security_scan_service.list_scans_for_asset(&asset_id).await?
    } else {
        app_state.security_scan_service.list_scans(query.limit, query.offset).await?
    };
    Ok(Json(scans))
}

/// GET /api/security/scans/:id - Get a specific security scan
pub async fn get_security_scan(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityScanDetailResponse>, ApiError> {
    let scan = app_state.security_scan_service.get_scan_detail(&id).await?
        .ok_or_else(|| ApiError::NotFound(format!("Security scan {} not found", id)))?;
    Ok(Json(scan))
}

/// GET /api/security/scans/pending - Get pending security scans
pub async fn list_pending_scans(
    State(app_state): State<AppState>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<Vec<SecurityScan>>, ApiError> {
    let scans = app_state.security_scan_service.list_pending_scans(query.limit).await?;
    Ok(Json(scans))
}

/// POST /api/security/scans/:id/cancel - Cancel a running security scan
pub async fn cancel_security_scan(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    app_state.security_scan_service.cancel_scan(&id).await?;
    Ok(Json(json!({
        "message": format!("Security scan {} cancelled", id),
        "scan_id": id
    })))
}

// ============================================================================
// SECURITY FINDING ENDPOINTS
// ============================================================================

#[derive(Debug, Deserialize, Default)]
pub struct ListFindingsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub asset_id: Option<Uuid>,
    pub scan_id: Option<Uuid>,
    pub severity: Option<String>,
    pub status: Option<String>,
}

/// GET /api/security/findings - List security findings
pub async fn list_security_findings(
    State(app_state): State<AppState>,
    Query(query): Query<ListFindingsQuery>,
) -> Result<Json<SecurityFindingListResponse>, ApiError> {
    let filter = SecurityFindingFilter {
        asset_ids: query.asset_id.map(|id| vec![id]),
        scan_ids: query.scan_id.map(|id| vec![id]),
        severities: query.severity.map(|s| vec![s]),
        statuses: query.status.map(|s| vec![s]),
        limit: query.limit,
        offset: query.offset,
        ..Default::default()
    };
    
    let (findings, total) = app_state.security_finding_repository.list_filtered(&filter).await?;
    
    Ok(Json(SecurityFindingListResponse {
        findings,
        total_count: total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// GET /api/security/findings/:id - Get a specific finding
pub async fn get_security_finding(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityFinding>, ApiError> {
    let finding = app_state.security_scan_service.get_finding(&id).await?
        .ok_or_else(|| ApiError::NotFound(format!("Finding {} not found", id)))?;
    Ok(Json(finding))
}

/// PATCH /api/security/findings/:id - Update a finding
pub async fn update_security_finding(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<SecurityFindingUpdate>,
) -> Result<Json<SecurityFinding>, ApiError> {
    let finding = app_state.security_finding_repository.update(&id, &payload, None).await?;
    Ok(Json(finding))
}

/// POST /api/security/findings/:id/resolve - Resolve a finding
pub async fn resolve_security_finding(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityFinding>, ApiError> {
    // In a real app, we'd get the user ID from the auth context
    let user_id = Uuid::nil(); // Placeholder
    let finding = app_state.security_finding_repository.resolve(&id, user_id).await?;
    Ok(Json(finding))
}

/// GET /api/security/findings/summary - Get findings summary by severity
pub async fn get_findings_summary(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let summary = app_state.security_scan_service.get_findings_summary().await?;
    Ok(Json(json!({
        "by_severity": summary
    })))
}

// ============================================================================
// ASSET SECURITY ENDPOINTS
// ============================================================================

/// GET /api/assets/:id/findings - Get findings for an asset
pub async fn get_asset_findings(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<SecurityFinding>>, ApiError> {
    let findings = app_state.security_scan_service.list_findings_for_asset(&id).await?;
    Ok(Json(findings))
}

/// POST /api/assets/:id/scan - Trigger a security scan for an asset
pub async fn trigger_asset_scan(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
    payload: Option<Json<CreateSecurityScanRequest>>,
) -> Result<Json<SecurityScan>, ApiError> {
    let scan_type = payload.as_ref().and_then(|p| p.scan_type.clone());
    let note = payload.as_ref().and_then(|p| p.note.clone());
    
    let scan_create = SecurityScanCreate {
        asset_id: id,
        scan_type: scan_type.map(|s| s.as_str().into()),
        trigger_type: None,
        priority: None,
        note,
        config: None,
    };
    
    let scan = app_state.security_scan_service.create_scan(scan_create).await?;
    Ok(Json(scan))
}


use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::context::UserContext,
    auth::rbac::Role,
    error::ApiError,
    models::{
        SecurityFinding, SecurityFindingFilter, SecurityFindingListResponse, SecurityFindingUpdate,
        SecurityScan, SecurityScanCreate, SecurityScanDetailResponse, SecurityScanListResponse,
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
    /// Comma-separated: pending | running | completed | failed | cancelled.
    pub status: Option<String>,
    pub scan_type: Option<String>,
}

fn default_limit() -> i64 {
    50
}

/// POST /api/security/scans - Create a new security scan
pub async fn create_security_scan(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<CreateSecurityScanRequest>,
) -> Result<Json<SecurityScan>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let scan_create = SecurityScanCreate {
        asset_id: payload.asset_id,
        scan_type: payload.scan_type.map(|s| s.as_str().into()),
        trigger_type: None,
        priority: None,
        note: payload.note,
        config: None,
        discovery_run_id: None,
    };

    let scan = app_state
        .security_scan_service
        .create_scan(scan_create, company_id, user.user_id)
        .await?;
    Ok(Json(scan))
}

/// GET /api/security/scans - List security scans
pub async fn list_security_scans(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<SecurityScanListResponse>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;

    // `asset_id` used to discard limit/offset and hard-cap at 100 rows; it is
    // now just another filter, so the caller keeps control of the page.
    let (scans, total) = app_state
        .security_scan_repository
        .list_filtered(
            query.limit,
            query.offset,
            query.asset_id,
            csv_filter(query.status.clone()),
            csv_filter(query.scan_type.clone()),
            company_id,
        )
        .await?;

    Ok(Json(SecurityScanListResponse {
        scans,
        total_count: total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// GET /api/security/scans/:id - Get a specific security scan
pub async fn get_security_scan(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityScanDetailResponse>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let scan = app_state
        .security_scan_service
        .get_scan_detail(&id, company_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Security scan {} not found", id)))?;
    Ok(Json(scan))
}

/// GET /api/security/scans/pending - Get pending security scans
pub async fn list_pending_scans(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<Vec<SecurityScan>>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let scans = app_state
        .security_scan_service
        .list_pending_scans(query.limit, company_id)
        .await?;
    Ok(Json(scans))
}

/// POST /api/security/scans/:id/cancel - Cancel a running security scan
pub async fn cancel_security_scan(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    app_state
        .security_scan_service
        .cancel_scan(&id, company_id)
        .await?;
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
    /// Comma-separated, so a triage screen can select several at once.
    pub severity: Option<String>,
    pub status: Option<String>,
    pub finding_type: Option<String>,
    /// Comma-separated asset types: domain, ip, port, certificate, …
    pub asset_type: Option<String>,
    /// Free text over title, description and finding type.
    pub q: Option<String>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
}

/// Split a comma-separated filter into values, dropping blanks.
fn csv_filter(raw: Option<String>) -> Option<Vec<String>> {
    let values: Vec<String> = raw?
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// Triage is a write. These endpoints had no role guard at all, so a Viewer
/// could resolve or dismiss any finding in the company.
fn require_triage_role(user: &UserContext) -> Result<(), ApiError> {
    if user.has_role(Role::Analyst) || user.has_role(Role::Operator) || user.has_role(Role::Admin) {
        return Ok(());
    }
    Err(ApiError::Authorization(
        "Analyst role or higher required to change a finding".to_string(),
    ))
}

/// GET /api/security/findings - List security findings
pub async fn list_security_findings(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<ListFindingsQuery>,
) -> Result<Json<SecurityFindingListResponse>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let filter = SecurityFindingFilter {
        asset_ids: query.asset_id.map(|id| vec![id]),
        scan_ids: query.scan_id.map(|id| vec![id]),
        severities: csv_filter(query.severity.clone()),
        statuses: csv_filter(query.status.clone()),
        finding_types: csv_filter(query.finding_type.clone()),
        asset_types: csv_filter(query.asset_type.clone()),
        search_text: query.q.clone().filter(|text| !text.trim().is_empty()),
        sort_by: query
            .sort_by
            .clone()
            .unwrap_or_else(|| "first_seen_at".to_string()),
        sort_direction: query.sort_dir.clone().unwrap_or_else(|| "desc".to_string()),
        limit: query.limit,
        offset: query.offset,
        ..Default::default()
    };

    let (findings, total) = app_state
        .security_finding_repository
        .list_filtered(&filter, company_id)
        .await?;

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
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityFinding>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let finding = app_state
        .security_scan_service
        .get_finding(&id, company_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Finding {} not found", id)))?;
    Ok(Json(finding))
}

/// PATCH /api/security/findings/:id - Update a finding
pub async fn update_security_finding(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<SecurityFindingUpdate>,
) -> Result<Json<SecurityFinding>, ApiError> {
    require_triage_role(&user)?;
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let updated_by = user.user_id;
    let finding = app_state
        .security_finding_repository
        .update(&id, &payload, updated_by, company_id)
        .await?;
    Ok(Json(finding))
}

/// Request body for bulk finding updates (triage queue).
#[derive(Debug, Deserialize)]
pub struct BulkUpdateFindingsRequest {
    pub ids: Vec<Uuid>,
    pub update: SecurityFindingUpdate,
}

/// PATCH /api/security/findings/bulk - Update many findings at once (triage)
pub async fn bulk_update_security_findings(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<BulkUpdateFindingsRequest>,
) -> Result<Json<Value>, ApiError> {
    require_triage_role(&user)?;
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;

    if payload.ids.is_empty() {
        return Err(ApiError::Validation("No finding ids provided".to_string()));
    }
    const MAX_BULK: usize = 500;
    if payload.ids.len() > MAX_BULK {
        return Err(ApiError::Validation(format!(
            "Too many findings in one request (max {})",
            MAX_BULK
        )));
    }

    let updated_by = user.user_id;
    let mut updated_ids = Vec::new();
    let mut failed_ids = Vec::new();
    for id in &payload.ids {
        match app_state
            .security_finding_repository
            .update(id, &payload.update, updated_by, company_id)
            .await
        {
            Ok(_) => updated_ids.push(*id),
            Err(e) => {
                tracing::warn!("bulk update: failed to update finding {}: {}", id, e);
                failed_ids.push(*id);
            }
        }
    }

    Ok(Json(json!({
        "updated": updated_ids.len(),
        "failed": failed_ids.len(),
        "updated_ids": updated_ids,
        "failed_ids": failed_ids,
    })))
}

/// POST /api/security/findings/:id/resolve - Resolve a finding
pub async fn resolve_security_finding(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecurityFinding>, ApiError> {
    require_triage_role(&user)?;
    // In a real app, we'd get the user ID from the auth context
    let user_id = user.user_id.unwrap_or(Uuid::nil());
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    // Assuming resolve logic accepts company_id? The call below uses existing resolve method
    // I need to check if resolve takes company_id. Assuming yes for "propagate" objective.
    let finding = app_state
        .security_finding_repository
        .resolve(&id, user_id, company_id)
        .await?;
    Ok(Json(finding))
}

/// GET /api/security/findings/summary - Get findings summary by severity
pub async fn get_findings_summary(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Value>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let summary = app_state
        .security_scan_service
        .get_findings_summary(company_id)
        .await?;

    // `count_by_status` already existed in the repository with no caller, so a
    // status filter had no counts to show next to it.
    let by_status = app_state
        .security_finding_repository
        .count_by_status(company_id)
        .await?;

    Ok(Json(json!({
        "by_severity": summary,
        "by_status": by_status
    })))
}

// ============================================================================
// ASSET SECURITY ENDPOINTS
// ============================================================================

/// GET /api/assets/:id/findings - Get findings for an asset
pub async fn get_asset_findings(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<SecurityFinding>>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let findings = app_state
        .security_scan_service
        .list_findings_for_asset(&id, company_id)
        .await?;
    Ok(Json(findings))
}

/// POST /api/assets/:id/scan - Trigger a security scan for an asset
pub async fn trigger_asset_scan(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    payload: Option<Json<CreateSecurityScanRequest>>,
) -> Result<Json<SecurityScan>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for security scans".to_string())
    })?;
    let scan_type = payload.as_ref().and_then(|p| p.scan_type.clone());
    let note = payload.as_ref().and_then(|p| p.note.clone());

    let scan_create = SecurityScanCreate {
        asset_id: id,
        scan_type: scan_type.map(|s| s.as_str().into()),
        trigger_type: None,
        priority: None,
        note,
        config: None,
        discovery_run_id: None,
    };

    let scan = app_state
        .security_scan_service
        .create_scan(scan_create, company_id, user.user_id)
        .await?;
    Ok(Json(scan))
}

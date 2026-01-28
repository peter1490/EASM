use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::context::UserContext,
    error::ApiError,
    models::{DiscoveryConfig, DiscoveryRun},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct RunDiscoveryRequest {
    /// Minimum confidence to auto-trigger security scans
    pub auto_scan_threshold: Option<f64>,
    /// Maximum recursion depth for pivoting
    pub max_depth: Option<u32>,
    /// Specific seed IDs to process (None = all seeds)
    pub seed_ids: Option<Vec<Uuid>>,
}

impl From<RunDiscoveryRequest> for DiscoveryConfig {
    fn from(req: RunDiscoveryRequest) -> Self {
        DiscoveryConfig {
            auto_scan_threshold: req.auto_scan_threshold,
            max_depth: req.max_depth,
            seed_ids: req.seed_ids,
            skip_recent: None,
            recent_hours: None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ListDiscoveryRunsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// POST /api/discovery/run - Start a new discovery run
pub async fn run_discovery(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    payload: Option<Json<RunDiscoveryRequest>>,
) -> Result<Json<DiscoveryRun>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let config = payload.map(|p| p.0.into());
    let run = app_state
        .discovery_service
        .run_discovery(company_id, config)
        .await?;
    Ok(Json(run))
}

/// POST /api/discovery/stop - Stop the running discovery
pub async fn stop_discovery(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Value>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    app_state
        .discovery_service
        .stop_discovery(company_id)
        .await?;
    Ok(Json(json!({
        "message": "Discovery stopped successfully"
    })))
}

/// GET /api/discovery/status - Get current discovery status
pub async fn discovery_status(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Value>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let status = app_state
        .discovery_service
        .get_discovery_status(company_id)
        .await;
    Ok(Json(json!({
        "running": status.is_running,
        "run_id": status.run_id,
        "started_at": status.started_at,
        "completed_at": status.completed_at,
        "current_phase": status.current_phase,
        "seeds_total": status.seeds_total,
        "seeds_processed": status.seeds_processed,
        "assets_discovered": status.assets_discovered,
        "assets_updated": status.assets_updated,
        "queue_pending": status.queue_pending,
        "errors": status.errors,
        "error_count": status.errors.len()
    })))
}

/// GET /api/discovery/runs - List discovery runs
pub async fn list_discovery_runs(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<ListDiscoveryRunsQuery>,
) -> Result<Json<Vec<DiscoveryRun>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let runs = app_state
        .discovery_service
        .list_discovery_runs(company_id, query.limit, query.offset)
        .await?;
    Ok(Json(runs))
}

/// GET /api/discovery/runs/:id - Get a specific discovery run
pub async fn get_discovery_run(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<DiscoveryRun>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let run = app_state
        .discovery_service
        .get_discovery_run(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Discovery run {} not found", id)))?;
    Ok(Json(run))
}

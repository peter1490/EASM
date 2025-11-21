use axum::{
    extract::State,
    response::Json,
};
use serde_json::{json, Value};
use crate::{
    error::ApiError,
    AppState,
};

#[derive(serde::Deserialize)]
pub struct RunDiscoveryRequest {
    pub confidence_threshold: Option<f64>,
}

pub async fn run_discovery(
    State(app_state): State<AppState>,
    payload: Option<Json<RunDiscoveryRequest>>,
) -> Result<Json<Value>, ApiError> {
    let confidence_threshold = payload.and_then(|p| p.confidence_threshold);
    app_state.discovery_service.run_discovery(confidence_threshold).await?;
    
    // For API compatibility with the Python backend, return numeric fields
    Ok(Json(json!({
        "discovered_assets": 0,
        "scheduled_scans": 0
    })))
}

pub async fn stop_discovery(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    app_state.discovery_service.stop_discovery().await?;
    
    Ok(Json(json!({
        "message": "Discovery stopped successfully"
    })))
}

pub async fn discovery_status(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let status = app_state.discovery_service.get_discovery_status().await;
    
    // Return detailed status information
    Ok(Json(json!({
        "running": status.is_running,
        "started_at": status.started_at,
        "completed_at": status.completed_at,
        "seeds_processed": status.seeds_processed,
        "assets_discovered": status.assets_discovered,
        "errors": status.errors,
        "error_count": status.errors.len()
    })))
}
use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::ApiError,
    models::{FindingFilter, ScanStatus},
    AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub uptime_seconds: u64,
    pub memory_usage: MemoryUsage,
    pub cpu_usage_percent: f64,
    pub active_scans: i64,
    pub total_assets: i64,
    pub total_findings: i64,
    pub requests_per_second: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

/// Get overall dashboard metrics
pub async fn get_metrics(
    State(app_state): State<AppState>,
) -> Result<Json<DashboardMetrics>, ApiError> {
    // Get system performance metrics
    let report = app_state.metrics_service.generate_report();
    let system = report.system;
    let overall = report.overall;

    // Get counts from repositories
    let active_scans = match app_state.scan_repository.list_by_status(Some(ScanStatus::Running)).await {
        Ok(scans) => scans.len() as i64,
        Err(_) => 0,
    };

    let total_assets = match app_state.asset_repository.count(None).await {
        Ok(count) => count,
        Err(_) => 0,
    };

    let total_findings = match app_state.finding_repository.filter(&FindingFilter::default()).await {
        Ok(response) => response.total_count,
        Err(_) => 0,
    };

    // Construct response
    let metrics = DashboardMetrics {
        uptime_seconds: system.uptime_seconds,
        memory_usage: MemoryUsage {
            total_bytes: system.total_memory_bytes,
            used_bytes: system.memory_usage_bytes,
            free_bytes: system.total_memory_bytes.saturating_sub(system.memory_usage_bytes),
        },
        cpu_usage_percent: system.cpu_usage_percent,
        active_scans,
        total_assets,
        total_findings,
        requests_per_second: overall.requests_per_second,
    };

    Ok(Json(metrics))
}

/// Get comprehensive performance report
pub async fn get_performance_report(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let report = app_state.metrics_service.generate_report();
    Ok(Json(serde_json::to_value(report).unwrap()))
}

/// Get metrics for a specific endpoint
pub async fn get_endpoint_metrics(
    State(app_state): State<AppState>,
    Path(endpoint): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let endpoint_path = format!("/{}", endpoint);
    
    match app_state.metrics_service.get_endpoint_metrics(&endpoint_path) {
        Some(metrics) => Ok(Json(serde_json::to_value(metrics).unwrap())),
        None => Err(ApiError::not_found(format!("No metrics found for endpoint: {}", endpoint_path))),
    }
}

/// Clear all metrics (admin endpoint)
pub async fn clear_metrics(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    app_state.metrics_service.clear_metrics();
    Ok(Json(serde_json::json!({
        "message": "All metrics cleared successfully"
    })))
}

/// Get system health status
pub async fn get_health_metrics(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let report = app_state.metrics_service.generate_report();
    
    // Determine health status based on metrics
    let is_healthy = report.overall.average_response_time_ms < 1000.0 
        && (report.overall.failed_requests as f64 / report.overall.total_requests.max(1) as f64) < 0.1;
    
    let status = if is_healthy { "healthy" } else { "degraded" };
    
    Ok(Json(serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": report.system.uptime_seconds,
        "total_requests": report.overall.total_requests,
        "success_rate": if report.overall.total_requests > 0 {
            report.overall.successful_requests as f64 / report.overall.total_requests as f64
        } else {
            1.0
        },
        "average_response_time_ms": report.overall.average_response_time_ms,
        "requests_per_second": report.overall.requests_per_second,
        "endpoints_tracked": report.endpoints.len()
    })))
}

#[cfg(test)]
mod tests {
    
}

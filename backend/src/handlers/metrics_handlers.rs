use axum::{
    extract::{Path, State},
    response::Json,
};
use serde_json::Value;

use crate::{
    error::ApiError,
    AppState,
};

/// Get overall performance metrics
pub async fn get_metrics(
    State(app_state): State<AppState>,
) -> Result<Json<Value>, ApiError> {
    let metrics = app_state.metrics_service.get_overall_metrics();
    Ok(Json(serde_json::to_value(metrics).unwrap()))
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
    use super::*;
    use std::sync::Arc;
    use crate::services::MetricsService;

    fn create_test_metrics_service() -> Arc<MetricsService> {
        let service = Arc::new(MetricsService::new());
        
        // Add some test data
        service.record_request("/api/test", "GET", std::time::Duration::from_millis(100), true);
        service.record_request("/api/test", "GET", std::time::Duration::from_millis(200), false);
        
        service
    }

    #[test]
    fn test_metrics_service_integration() {
        let service = create_test_metrics_service();
        let metrics = service.get_overall_metrics();
        
        assert_eq!(metrics.total_requests, 2);
        assert_eq!(metrics.successful_requests, 1);
        assert_eq!(metrics.failed_requests, 1);
        assert_eq!(metrics.average_response_time_ms, 150.0);
    }

    #[test]
    fn test_performance_report_generation() {
        let service = create_test_metrics_service();
        let report = service.generate_report();
        
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(report.overall.total_requests, 2);
        assert!(report.system.uptime_seconds >= 0);
    }
}
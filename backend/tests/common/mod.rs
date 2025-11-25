use axum::Router;
use rust_backend::{AppState, config};

/// Create a test application instance with in-memory database
pub async fn create_test_app() -> Router {
    // Use DATABASE_URL from environment (must point to PostgreSQL)
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    std::env::set_var("CORS_ALLOW_ORIGINS", "*");
    std::env::set_var("LOG_LEVEL", "error");
    
    // Create test configuration
    let test_config = config::Settings::new_with_env_file(false)
        .expect("Failed to create test config");
    
    // Create the database pool first
    let pool = rust_backend::database::create_connection_pool(&db_url)
        .await
        .expect("Failed to create database pool");
    
    // Run migrations (handled by create_connection_pool)
    
    // Create application state with the existing pool
    let app_state = AppState::new_with_pool(test_config, pool)
        .await
        .expect("Failed to create test app state");
    
    // No temp dir for PostgreSQL-based tests
    
    // Create the router with all endpoints
    create_test_router(app_state)
}

// PostgreSQL migrations handle schema creation; helper removed

/// Create a test router with all API endpoints
pub fn create_test_router(app_state: AppState) -> Router {
    use axum::routing::{get, post, delete};
    use rust_backend::handlers;
    
    Router::new()
        // Health check endpoints
        .route("/api/health", get(handlers::health_check))
        .route("/api/health/simple", get(handlers::health_check_simple))
        .route("/api/health/ready", get(handlers::readiness_check))
        .route("/api/health/live", get(handlers::liveness_check))
        // Scan endpoints
        .route("/api/scans", post(handlers::scan_handlers::create_scan))
        .route("/api/scans", get(handlers::scan_handlers::list_scans))
        .route("/api/scans/:id", get(handlers::scan_handlers::get_scan))
        // Asset endpoints
        .route("/api/assets", get(handlers::asset_handlers::list_assets))
        .route("/api/assets/:id", get(handlers::asset_handlers::get_asset))
        // Seed endpoints
        .route("/api/seeds", post(handlers::asset_handlers::create_seed))
        .route("/api/seeds", get(handlers::asset_handlers::list_seeds))
        .route("/api/seeds/:id", delete(handlers::asset_handlers::delete_seed))
        // Discovery endpoints
        .route("/api/discovery/run", post(handlers::discovery_handlers::run_discovery))
        .route("/api/discovery/status", get(handlers::discovery_handlers::discovery_status))
        // Evidence endpoints
        .route("/api/scans/:scan_id/evidence", post(handlers::evidence_handlers::upload_evidence))
        .route("/api/scans/:scan_id/evidence", get(handlers::evidence_handlers::list_evidence_by_scan))
        .route("/api/evidence/:id", get(handlers::evidence_handlers::get_evidence))
        .route("/api/evidence/:id/download", get(handlers::evidence_handlers::download_evidence))
        // Risk scoring endpoints
        .route("/api/risk/assets/:id", get(handlers::risk_handlers::get_asset_risk))
        .route("/api/risk/assets/:id/recalculate", post(handlers::risk_handlers::recalculate_asset_risk))
        .route("/api/risk/overview", get(handlers::risk_handlers::get_risk_overview))
        .route("/api/risk/recalculate-all", post(handlers::risk_handlers::recalculate_all_risks))
        .route("/api/risk/high-risk-assets", get(handlers::risk_handlers::get_high_risk_assets))
        // Port drift detection endpoints
        .route("/api/scans/:id/drift/detect", post(handlers::drift_handlers::detect_port_drift))
        .route("/api/scans/:id/drift/findings", get(handlers::drift_handlers::get_drift_findings))
        // Search endpoints
        .route("/api/search/assets", get(handlers::search_handlers::search_assets))
        .route("/api/search/findings", get(handlers::search_handlers::search_findings))
        .route("/api/search/reindex", post(handlers::search_handlers::reindex_all))
        .route("/api/search/status", get(handlers::search_handlers::search_status))
        // Metrics endpoints
        .route("/api/metrics", get(handlers::metrics_handlers::get_metrics))
        .route("/api/metrics/report", get(handlers::metrics_handlers::get_performance_report))
        .route("/api/metrics/health", get(handlers::metrics_handlers::get_health_metrics))
        .route("/api/metrics/endpoint/*endpoint", get(handlers::metrics_handlers::get_endpoint_metrics))
        .route("/api/metrics/clear", post(handlers::metrics_handlers::clear_metrics))
        .with_state(app_state)
}

// Removed deprecated/unused helper constructors to reduce warnings

#[allow(dead_code)] // Used in end_to_end_tests.rs
/// Helper to validate datetime string format
pub fn is_valid_datetime_string(datetime_str: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(datetime_str).is_ok()
}

#[allow(dead_code)] 
/// Helper to validate UUID string format
pub fn is_valid_uuid_string(uuid_str: &str) -> bool {
    uuid::Uuid::parse_str(uuid_str).is_ok()
}

/// Helper to extract response body as bytes
pub async fn extract_body(response: axum::response::Response) -> Vec<u8> {
    use axum::body::to_bytes;
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    body.to_vec()
}
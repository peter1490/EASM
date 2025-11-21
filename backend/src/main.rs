use axum::{
    routing::{get, post, delete},
    Router,
};
use std::net::SocketAddr;

use tokio::signal;

use rust_backend::{AppState, config, handlers, middleware};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration first
    let config = config::Settings::new()?;

    // Initialize structured logging with configuration
    middleware::init_logging(&config.log_level, &config.log_format)?;

    tracing::info!("Starting Rust EASM Backend v{}", env!("CARGO_PKG_VERSION"));

    // Create application state with dependency injection
    let app_state = AppState::new(config.clone()).await?;

    // Create CORS layer with configuration
    let cors_layer = middleware::create_cors_layer(config.cors_allow_origins.clone());

    // Build our application with routes
    let app = Router::new()
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
        .route("/api/assets/:id/path", get(handlers::asset_handlers::get_asset_path))
        // Seed endpoints
        .route("/api/seeds", post(handlers::asset_handlers::create_seed))
        .route("/api/seeds", get(handlers::asset_handlers::list_seeds))
        .route("/api/seeds/:id", delete(handlers::asset_handlers::delete_seed))
        // Discovery endpoints
        .route("/api/discovery/run", post(handlers::discovery_handlers::run_discovery))
        .route("/api/discovery/stop", post(handlers::discovery_handlers::stop_discovery))
        .route("/api/discovery/status", get(handlers::discovery_handlers::discovery_status))
        // Evidence endpoints
        .route("/api/scans/:scan_id/evidence", post(handlers::evidence_handlers::upload_evidence))
        .route("/api/scans/:scan_id/evidence", get(handlers::evidence_handlers::list_evidence_by_scan))
        .route("/api/evidence/:id", get(handlers::evidence_handlers::get_evidence))
        .route("/api/evidence/:id/download", get(handlers::evidence_handlers::download_evidence))
        // Static file serving for evidence files
        .route("/api/static/evidence/*file", get(handlers::serve_evidence_file))
        .route("/api/static/health", get(handlers::static_files_health_check))
        // Risk scoring endpoint
        .route("/api/risk/calculate", get(handlers::risk_handlers::calculate_risk))
        // Port drift detection endpoints
        .route("/api/scans/:id/drift/detect", post(handlers::drift_handlers::detect_port_drift))
        .route("/api/scans/:id/drift/findings", get(handlers::drift_handlers::get_drift_findings))
        // Search endpoints
        .route("/api/search/assets", get(handlers::search_handlers::search_assets))
        .route("/api/search/findings", get(handlers::search_handlers::search_findings))
        .route("/api/search/reindex", post(handlers::search_handlers::reindex_all))
        .route("/api/search/status", get(handlers::search_handlers::search_status))
        // Finding filter endpoints
        .route("/api/findings/filter", get(handlers::finding_handlers::filter_findings))
        .route("/api/findings/types", get(handlers::finding_handlers::get_finding_types))
        // Metrics and performance endpoints
        .route("/api/metrics", get(handlers::metrics_handlers::get_metrics))
        .route("/api/metrics/report", get(handlers::metrics_handlers::get_performance_report))
        .route("/api/metrics/health", get(handlers::metrics_handlers::get_health_metrics))
        .route("/api/metrics/endpoint/*endpoint", get(handlers::metrics_handlers::get_endpoint_metrics))
        .route("/api/metrics/clear", post(handlers::metrics_handlers::clear_metrics))
        .with_state(app_state)
        // Apply middleware layers
        .layer(axum::middleware::from_fn(middleware::performance_middleware))
        .layer(axum::middleware::from_fn(middleware::security_headers_middleware))
        .layer(axum::middleware::from_fn(middleware::request_logging_middleware))
        .layer(middleware::create_logging_layer())
        .layer(cors_layer);

    // Run the server with graceful shutdown
    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    tracing::info!("Server starting on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown");
        },
    }
}
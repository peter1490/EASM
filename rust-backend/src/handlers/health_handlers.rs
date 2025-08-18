use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};
use sqlx::Row;
use crate::{AppState, error::ApiError};

/// Enhanced health check endpoint with database connectivity check
pub async fn health_check(State(app_state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let mut health_status = json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "service": "rust-backend",
        "checks": {}
    });

    // Check database connectivity
    let db_status = check_database_health(&app_state).await;
    health_status["checks"]["database"] = db_status;

    // Determine overall health status
    let overall_healthy = health_status["checks"]
        .as_object()
        .unwrap()
        .values()
        .all(|check| check["healthy"].as_bool().unwrap_or(false));

    if !overall_healthy {
        health_status["status"] = json!("unhealthy");
        return Err(ApiError::internal("Service is unhealthy"));
    }

    Ok(Json(health_status))
}

/// Simple health check endpoint for load balancers
pub async fn health_check_simple() -> Result<&'static str, StatusCode> {
    Ok("OK")
}

/// Check database connectivity and return health status
async fn check_database_health(app_state: &AppState) -> Value {
    match sqlx::query("SELECT 1 as health_check")
        .fetch_one(&app_state.db_pool)
        .await
    {
        Ok(row) => {
            let result: i32 = row.try_get("health_check").unwrap_or(0);
            if result == 1 {
                json!({
                    "healthy": true,
                    "message": "Database connection successful",
                    "response_time_ms": 0 // Could add timing if needed
                })
            } else {
                json!({
                    "healthy": false,
                    "message": "Database query returned unexpected result",
                    "error": format!("Expected 1, got {}", result)
                })
            }
        }
        Err(e) => {
            tracing::error!("Database health check failed: {}", e);
            json!({
                "healthy": false,
                "message": "Database connection failed",
                "error": e.to_string()
            })
        }
    }
}

/// Readiness check endpoint for Kubernetes
pub async fn readiness_check(State(app_state): State<AppState>) -> Result<Json<Value>, ApiError> {
    // Check if the service is ready to accept traffic
    let db_ready = check_database_health(&app_state).await;
    
    let ready = db_ready["healthy"].as_bool().unwrap_or(false);
    
    let readiness_status = json!({
        "ready": ready,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": db_ready
        }
    });

    if !ready {
        return Err(ApiError::internal("Service is not ready"));
    }

    Ok(Json(readiness_status))
}

/// Liveness check endpoint for Kubernetes
pub async fn liveness_check() -> Json<Value> {
    // Simple liveness check - if this endpoint responds, the service is alive
    Json(json!({
        "alive": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Settings, database::create_database_pool};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn create_test_app_state() -> AppState {
        let settings = Settings::new_with_env_file(false).unwrap();
        // Requires DATABASE_URL to be set to a valid PostgreSQL URL in test env
        let db_pool = create_database_pool(&settings.database_url).await.expect("DB pool");
        AppState::new_with_pool(settings, db_pool).await.unwrap()
    }

    #[tokio::test]
    async fn test_health_check_simple() {
        let app = Router::new()
            .route("/health", get(health_check_simple));

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_liveness_check() {
        let app = Router::new()
            .route("/liveness", get(liveness_check));

        let request = Request::builder()
            .uri("/liveness")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_with_database() {
        let app_state = create_test_app_state().await;
        
        let app = Router::new()
            .route("/health", get(health_check))
            .with_state(app_state);

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should be OK if database is available, or 500 if not
        assert!(matches!(response.status(), StatusCode::OK | StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[tokio::test]
    async fn test_readiness_check() {
        let app_state = create_test_app_state().await;
        
        let app = Router::new()
            .route("/ready", get(readiness_check))
            .with_state(app_state);

        let request = Request::builder()
            .uri("/ready")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should be OK if database is available, or 500 if not
        assert!(matches!(response.status(), StatusCode::OK | StatusCode::INTERNAL_SERVER_ERROR));
    }
}
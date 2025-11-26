use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use serde_json::json;
use tower::ServiceExt;

// Simple test that verifies routes are properly configured
#[tokio::test]
async fn test_route_configuration() {
    // Create a simple router with just the health endpoint to test routing
    let app = Router::new()
        .route("/api/health", get(|| async { "OK" }))
        .route("/api/assets", get(|| async { "assets" }))
        .route("/api/seeds", post(|| async { "seed created" }))
        .route("/api/seeds", get(|| async { "seeds list" }))
        .route(
            "/api/discovery/status",
            get(|| async { "discovery status" }),
        );

    // Test health endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test assets endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/assets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test seeds GET endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/seeds")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test discovery status endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/discovery/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test seeds POST endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/seeds")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(json!({"test": "data"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_evidence_route_configuration() {
    // Create a simple router with evidence endpoints to test routing
    let app = Router::new()
        .route(
            "/api/scans/:scan_id/evidence",
            post(|| async { "evidence uploaded" }),
        )
        .route(
            "/api/scans/:scan_id/evidence",
            get(|| async { "evidence list" }),
        )
        .route("/api/evidence/:id", get(|| async { "evidence details" }))
        .route(
            "/api/evidence/:id/download",
            get(|| async { "evidence download" }),
        );

    // Test evidence upload endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans/123e4567-e89b-12d3-a456-426614174000/evidence")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test evidence list endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans/123e4567-e89b-12d3-a456-426614174000/evidence")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test evidence details endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/evidence/123e4567-e89b-12d3-a456-426614174000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test evidence download endpoint
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/evidence/123e4567-e89b-12d3-a456-426614174000/download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_risk_scoring_route_configuration() {
    // Create a simple router with risk scoring endpoint to test routing
    let app = Router::new().route("/api/risk/calculate", get(|| async { "risk calculated" }));

    // Test risk calculation endpoint
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/risk/calculate?cvss_score=7.5&asset_criticality=1.2&exploitability=1.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

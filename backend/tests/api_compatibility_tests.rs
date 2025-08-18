use axum::{
    body::Body,
    http::{Request, StatusCode, Method},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

mod common;
use common::{extract_body, create_test_app};

/// Test suite comparing Rust and Python API responses for compatibility
/// This ensures the Rust backend maintains 100% API compatibility with the Python backend

#[tokio::test]
async fn test_health_endpoint_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should match Python backend response format: {"status": "ok"}
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn test_scan_creation_compatibility() {
    let app = create_test_app().await;
    
    let scan_payload = json!({
        "target": "example.com",
        "note": "Test scan"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from(scan_payload.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Verify response structure matches Python backend
    assert!(json["id"].is_string());
    assert_eq!(json["target"], "example.com");
    assert_eq!(json["note"], "Test scan");
    assert_eq!(json["status"], "queued");
    assert!(json["created_at"].is_string());
    assert!(json["updated_at"].is_string());
}

#[tokio::test]
async fn test_scan_list_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/scans").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should return an array
    assert!(json.is_array());
    
    // If there are scans, verify structure
    if let Some(scan) = json.as_array().unwrap().first() {
        assert!(scan["id"].is_string());
        assert!(scan["target"].is_string());
        assert!(scan["status"].is_string());
        assert!(scan["created_at"].is_string());
        assert!(scan["updated_at"].is_string());
        // findings_count should be present for list endpoint
        assert!(scan["findings_count"].is_number());
    }
}

#[tokio::test]
async fn test_scan_get_compatibility() {
    let app = create_test_app().await;
    
    // First create a scan
    let scan_payload = json!({
        "target": "example.com",
        "note": "Test scan for get"
    });
    
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from(scan_payload.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    let create_body = extract_body(create_response).await;
    let create_json: Value = serde_json::from_slice(&create_body).unwrap();
    let scan_id = create_json["id"].as_str().unwrap();
    
    // Now get the scan
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/scans/{}", scan_id))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Verify response structure matches Python backend
    assert_eq!(json["id"], scan_id);
    assert_eq!(json["target"], "example.com");
    assert_eq!(json["note"], "Test scan for get");
    assert_eq!(json["status"], "queued");
    assert!(json["created_at"].is_string());
    assert!(json["updated_at"].is_string());
    // findings should be an array for get endpoint
    assert!(json["findings"].is_array());
    assert!(json["findings_count"].is_number());
}

#[tokio::test]
async fn test_seed_creation_compatibility() {
    let app = create_test_app().await;
    
    let seed_payload = json!({
        "seed_type": "domain",
        "value": "example.com",
        "note": "Test seed"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/seeds")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from(seed_payload.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Verify response structure matches Python backend
    assert!(json["id"].is_string());
    assert_eq!(json["seed_type"], "domain");
    assert_eq!(json["value"], "example.com");
    assert_eq!(json["note"], "Test seed");
    assert!(json["created_at"].is_string());
    assert!(json["updated_at"].is_string());
}

#[tokio::test]
async fn test_seed_list_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/seeds").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should return an array
    assert!(json.is_array());
    
    // If there are seeds, verify structure
    if let Some(seed) = json.as_array().unwrap().first() {
        assert!(seed["id"].is_string());
        assert!(seed["seed_type"].is_string());
        assert!(seed["value"].is_string());
        assert!(seed["created_at"].is_string());
        assert!(seed["updated_at"].is_string());
    }
}

#[tokio::test]
async fn test_asset_list_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/assets").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should return an array
    assert!(json.is_array());
    
    // If there are assets, verify structure matches Python backend
    if let Some(asset) = json.as_array().unwrap().first() {
        assert!(asset["id"].is_string());
        assert!(asset["asset_type"].is_string());
        assert!(asset["value"].is_string());
        assert!(asset["ownership_confidence"].is_number());
        assert!(asset["sources"].is_array());
        assert!(asset["metadata"].is_object());
        assert!(asset["created_at"].is_string());
        assert!(asset["updated_at"].is_string());
    }
}

#[tokio::test]
async fn test_asset_list_with_confidence_filter_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/assets?min_confidence=0.5")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should return an array
    assert!(json.is_array());
    
    // All returned assets should have confidence >= 0.5
    for asset in json.as_array().unwrap() {
        let confidence = asset["ownership_confidence"].as_f64().unwrap();
        assert!(confidence >= 0.5);
    }
}

#[tokio::test]
async fn test_discovery_status_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/discovery/status")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should match Python backend response format: {"running": bool}
    assert!(json["running"].is_boolean());
}

#[tokio::test]
async fn test_discovery_run_compatibility() {
    let app = create_test_app().await;
    
    let discovery_payload = json!({
        "confidence_threshold": 0.7,
        "include_scan": true
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/discovery/run")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from(discovery_payload.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should match Python backend response format
    assert!(json["discovered_assets"].is_number());
    assert!(json["scheduled_scans"].is_number());
}

#[tokio::test]
async fn test_risk_calculation_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/risk/calculate?cvss_base=7.5&asset_criticality_weight=1.2&exploitability_multiplier=1.1")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Should match Python backend response format
    assert!(json["risk_score"].is_number());
    assert!(json["components"].is_object());
    assert!(json["components"]["cvss_base"].is_number());
    assert!(json["components"]["asset_criticality_weight"].is_number());
    assert!(json["components"]["exploitability_multiplier"].is_number());
}

#[tokio::test]
async fn test_error_response_compatibility() {
    let app = create_test_app().await;
    
    // Test 404 for non-existent scan
    let fake_uuid = Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/scans/{}", fake_uuid))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Error response should have detail field like Python backend
    assert!(json["detail"].is_string());
}

#[tokio::test]
async fn test_validation_error_compatibility() {
    let app = create_test_app().await;
    
    // Test invalid scan payload
    let invalid_payload = json!({
        "target": "",  // Empty target should be invalid
        "note": "Test"
    });
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from(invalid_payload.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Should return validation error (400 or 422)
    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Error response should have detail field
    assert!(json["detail"].is_string() || json["detail"].is_array());
}

#[tokio::test]
async fn test_content_type_headers_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    // Should return JSON content type like Python backend
    let content_type = response.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().contains("application/json"));
}

#[tokio::test]
async fn test_cors_headers_compatibility() {
    let app = create_test_app().await;
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .header("origin", "http://localhost:3000")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    // Should have CORS headers like Python backend
    assert!(response.headers().contains_key("access-control-allow-origin"));
}
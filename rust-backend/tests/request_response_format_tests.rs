use axum::{
    body::Body,
    http::{Request, StatusCode, Method},
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;
use common::*;

/// Test suite validating request/response format compatibility with Python backend
/// This ensures exact API contract compliance

#[tokio::test]
async fn test_scan_response_format_compatibility() {
    let app = create_test_app().await;
    
    let scan_payload = json!({
        "target": "response-test.com",
        "note": "Testing response format"
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
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Verify exact field names and types match Python backend
    let required_fields = vec![
        ("id", "string"),
        ("target", "string"),
        ("note", "string"),
        ("status", "string"),
        ("created_at", "string"),
        ("updated_at", "string"),
    ];
    
    for (field_name, expected_type) in required_fields {
        assert!(json.get(field_name).is_some(), "Missing field: {}", field_name);
        
        match expected_type {
            "string" => assert!(json[field_name].is_string(), "Field {} should be string", field_name),
            "number" => assert!(json[field_name].is_number(), "Field {} should be number", field_name),
            "boolean" => assert!(json[field_name].is_boolean(), "Field {} should be boolean", field_name),
            "array" => assert!(json[field_name].is_array(), "Field {} should be array", field_name),
            "object" => assert!(json[field_name].is_object(), "Field {} should be object", field_name),
            _ => panic!("Unknown expected type: {}", expected_type),
        }
    }
    
    // Verify status enum values match Python backend
    let status = json["status"].as_str().unwrap();
    let valid_statuses = vec!["queued", "running", "completed", "failed"];
    assert!(valid_statuses.contains(&status), "Invalid status: {}", status);
    
    // Verify datetime format (ISO 8601 with timezone)
    let created_at = json["created_at"].as_str().unwrap();
    assert!(is_valid_datetime_string(created_at), "Invalid datetime format: {}", created_at);
}

#[tokio::test]
async fn test_error_response_format_compatibility() {
    let app = create_test_app().await;
    
    // Test 404 error format
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans/00000000-0000-0000-0000-000000000000")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    
    let body = extract_body(response).await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    // Error format should match Python backend (FastAPI format)
    assert!(json.get("detail").is_some(), "Missing detail field in error response");
    assert!(json["detail"].is_string(), "detail should be string");
}
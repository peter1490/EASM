use axum::{
    body::Body,
    http::{Request, StatusCode, Method},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

mod common;
use common::*;

/// End-to-end integration tests with real database operations
/// These tests verify complete workflows work correctly

#[tokio::test]
async fn test_complete_scan_workflow() {
    let app = create_test_app().await;
    
    // Step 1: Create a scan
    let scan_payload = json!({
        "target": "example.com",
        "note": "E2E test scan"
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
    
    assert_eq!(create_response.status(), StatusCode::OK);
    
    let create_body = extract_body(create_response).await;
    let create_json: Value = serde_json::from_slice(&create_body).unwrap();
    let scan_id = create_json["id"].as_str().unwrap();
    
    // Step 2: Verify scan appears in list
    let list_response = app
        .clone()
        .oneshot(Request::builder().uri("/api/scans").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(list_response.status(), StatusCode::OK);
    
    let list_body = extract_body(list_response).await;
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    
    let scan_found = list_json.as_array().unwrap()
        .iter()
        .any(|scan| scan["id"].as_str().unwrap() == scan_id);
    assert!(scan_found, "Created scan not found in list");
    
    // Step 3: Get scan details
    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/api/scans/{}", scan_id))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(get_response.status(), StatusCode::OK);
    
    let get_body = extract_body(get_response).await;
    let get_json: Value = serde_json::from_slice(&get_body).unwrap();
    
    assert_eq!(get_json["id"], scan_id);
    assert_eq!(get_json["target"], "example.com");
    assert_eq!(get_json["note"], "E2E test scan");
}

#[tokio::test]
async fn test_complete_seed_and_asset_workflow() {
    let app = create_test_app().await;
    
    // Step 1: Create a seed
    let seed_payload = json!({
        "seed_type": "domain",
        "value": "example.com",
        "note": "E2E test seed"
    });
    
    let create_response = app
        .clone()
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
    
    assert_eq!(create_response.status(), StatusCode::OK);
    
    let create_body = extract_body(create_response).await;
    let create_json: Value = serde_json::from_slice(&create_body).unwrap();
    let seed_id = create_json["id"].as_str().unwrap();
    
    // Step 2: Verify seed appears in list
    let list_response = app
        .clone()
        .oneshot(Request::builder().uri("/api/seeds").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(list_response.status(), StatusCode::OK);
    
    let list_body = extract_body(list_response).await;
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    
    let seed_found = list_json.as_array().unwrap()
        .iter()
        .any(|seed| seed["id"].as_str().unwrap() == seed_id);
    assert!(seed_found, "Created seed not found in list");
    
    // Step 3: Check discovery status
    let status_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/discovery/status")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(status_response.status(), StatusCode::OK);
    
    let status_body = extract_body(status_response).await;
    let status_json: Value = serde_json::from_slice(&status_body).unwrap();
    
    // Initially should not be running
    assert_eq!(status_json["running"], false);
    
    // Step 4: Run discovery
    let discovery_payload = json!({
        "confidence_threshold": 0.5,
        "include_scan": false
    });
    
    let discovery_response = app
        .clone()
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
    
    assert_eq!(discovery_response.status(), StatusCode::OK);
    
    let discovery_body = extract_body(discovery_response).await;
    let discovery_json: Value = serde_json::from_slice(&discovery_body).unwrap();
    
    assert!(discovery_json["discovered_assets"].is_number());
    assert!(discovery_json["scheduled_scans"].is_number());
    
    // Step 5: List assets (may be empty in test environment)
    let assets_response = app
        .clone()
        .oneshot(Request::builder().uri("/api/assets").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    assert_eq!(assets_response.status(), StatusCode::OK);
    
    let assets_body = extract_body(assets_response).await;
    let assets_json: Value = serde_json::from_slice(&assets_body).unwrap();
    
    assert!(assets_json.is_array());
    
    // Step 6: Delete the seed
    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/api/seeds/{}", seed_id))
                .method(Method::DELETE)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(delete_response.status(), StatusCode::OK);
    
    // Step 7: Verify seed is deleted
    let final_list_response = app
        .oneshot(Request::builder().uri("/api/seeds").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    let final_list_body = extract_body(final_list_response).await;
    let final_list_json: Value = serde_json::from_slice(&final_list_body).unwrap();
    
    let seed_still_exists = final_list_json.as_array().unwrap()
        .iter()
        .any(|seed| seed["id"].as_str().unwrap() == seed_id);
    assert!(!seed_still_exists, "Seed should be deleted");
}

#[tokio::test]
async fn test_risk_calculation_workflow() {
    let app = create_test_app().await;
    
    // Test various risk calculation scenarios
    let test_cases = vec![
        (7.5, 1.0, 1.0, 7.5),  // Base case
        (5.0, 1.5, 2.0, 15.0), // High multipliers
        (10.0, 0.5, 0.8, 4.0), // Low multipliers
        (0.0, 3.0, 5.0, 0.0),  // Zero base score
    ];
    
    for (cvss_base, asset_criticality, exploitability, expected_risk) in test_cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&format!(
                        "/api/risk/calculate?cvss_base={}&asset_criticality_weight={}&exploitability_multiplier={}",
                        cvss_base, asset_criticality, exploitability
                    ))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
        
        let body = extract_body(response).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        
        let calculated_risk = json["risk_score"].as_f64().unwrap();
        assert!((calculated_risk - expected_risk).abs() < 0.001, 
                "Risk calculation mismatch: expected {}, got {}", expected_risk, calculated_risk);
        
        // Verify components are returned
        assert_eq!(json["components"]["cvss_base"].as_f64().unwrap(), cvss_base);
        assert_eq!(json["components"]["asset_criticality_weight"].as_f64().unwrap(), asset_criticality);
        assert_eq!(json["components"]["exploitability_multiplier"].as_f64().unwrap(), exploitability);
    }
}

#[tokio::test]
async fn test_health_check_workflow() {
    let app = create_test_app().await;
    
    // Test all health check endpoints
    let health_endpoints = vec![
        "/api/health",
        "/api/health/simple",
        "/api/health/ready",
        "/api/health/live",
    ];
    
    for endpoint in health_endpoints {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(endpoint)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK, "Health check failed for {}", endpoint);
        
        let body = extract_body(response).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        
        // All health endpoints should return status
        assert!(json["status"].is_string(), "Missing status in health check response for {}", endpoint);
    }
}

#[tokio::test]
async fn test_concurrent_operations() {
    let app = create_test_app().await;
    
    // Test concurrent scan creation
    let mut handles = Vec::new();
    
    for i in 0..5 {
        let app_clone = app.clone();
        let handle = tokio::spawn(async move {
            let scan_payload = json!({
                "target": format!("test{}.com", i),
                "note": format!("Concurrent test scan {}", i)
            });
            
            let response = app_clone
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
            
            json["id"].as_str().unwrap().to_string()
        });
        
        handles.push(handle);
    }
    
    // Wait for all concurrent operations to complete
    let scan_ids: Vec<String> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|result| result.unwrap())
        .collect();
    
    // Verify all scans were created
    assert_eq!(scan_ids.len(), 5);
    
    // Verify all scans are unique
    let mut unique_ids = std::collections::HashSet::new();
    for id in &scan_ids {
        assert!(unique_ids.insert(id.clone()), "Duplicate scan ID: {}", id);
    }
    
    // Verify all scans appear in the list
    let list_response = app
        .oneshot(Request::builder().uri("/api/scans").body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    let list_body = extract_body(list_response).await;
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    
    let listed_scan_ids: Vec<String> = list_json.as_array().unwrap()
        .iter()
        .map(|scan| scan["id"].as_str().unwrap().to_string())
        .collect();
    
    for scan_id in &scan_ids {
        assert!(listed_scan_ids.contains(scan_id), "Scan {} not found in list", scan_id);
    }
}

#[tokio::test]
async fn test_error_handling_workflow() {
    let app = create_test_app().await;
    
    // Test 404 errors
    let fake_uuid = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&format!("/api/scans/{}", fake_uuid))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    
    // Test validation errors
    let invalid_scan = json!({
        "target": "",  // Invalid empty target
        "note": "Test"
    });
    
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from(invalid_scan.to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Should return validation error
    assert!(response.status().is_client_error());
    
    // Test malformed JSON
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method(Method::POST)
                .header("content-type", "application/json")
                .body(Body::from("invalid json"))
                .unwrap()
        )
        .await
        .unwrap();
    
    assert!(response.status().is_client_error());
    
    // Test unsupported method
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method(Method::PATCH)  // Not supported
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_data_persistence() {
    let app = create_test_app().await;
    
    // Create a scan
    let scan_payload = json!({
        "target": "persistence-test.com",
        "note": "Testing data persistence"
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
    let created_at = create_json["created_at"].as_str().unwrap();
    
    // Wait a moment to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Retrieve the scan multiple times to ensure consistency
    for _ in 0..3 {
        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/scans/{}", scan_id))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();
        
        let get_body = extract_body(get_response).await;
        let get_json: Value = serde_json::from_slice(&get_body).unwrap();
        
        // Data should be consistent across retrievals
        assert_eq!(get_json["id"], scan_id);
        assert_eq!(get_json["target"], "persistence-test.com");
        assert_eq!(get_json["note"], "Testing data persistence");
        assert_eq!(get_json["created_at"], created_at);
        
        // Verify datetime format is valid
        assert!(is_valid_datetime_string(get_json["created_at"].as_str().unwrap()));
        assert!(is_valid_datetime_string(get_json["updated_at"].as_str().unwrap()));
        
        // Verify UUID format is valid
        assert!(is_valid_uuid_string(get_json["id"].as_str().unwrap()));
    }
}
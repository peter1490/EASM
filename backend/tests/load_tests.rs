use axum::{body::Body, http::Request};
use rust_backend::{config::Settings, database::create_connection_pool, AppState};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use tower::ServiceExt;
use uuid::Uuid;

/// Load test configuration
#[derive(Debug, Clone)]
struct LoadTestConfig {
    concurrent_users: usize,
    requests_per_user: usize,
    ramp_up_duration: Duration,
    _test_duration: Duration,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_users: 10,
            requests_per_user: 50,
            ramp_up_duration: Duration::from_secs(10),
            _test_duration: Duration::from_secs(60),
        }
    }
}

/// Load test results
#[derive(Debug)]
struct LoadTestResults {
    total_requests: usize,
    successful_requests: usize,
    failed_requests: usize,
    average_response_time: Duration,
    min_response_time: Duration,
    max_response_time: Duration,
    requests_per_second: f64,
    error_rate: f64,
}

/// Test scan creation under load
#[tokio::test]
async fn test_scan_creation_load() {
    let app = create_test_app().await;

    let config = LoadTestConfig {
        concurrent_users: 20,
        requests_per_user: 25,
        ..Default::default()
    };

    let results = run_load_test(app, config, |i| {
        create_scan_request(format!("load-test-{}.com", i))
    })
    .await;

    println!("Scan Creation Load Test Results:");
    print_load_test_results(&results);

    // Assertions for acceptable performance
    assert!(
        results.error_rate < 0.05,
        "Error rate should be less than 5%"
    );
    assert!(
        results.requests_per_second > 10.0,
        "Should handle at least 10 requests per second"
    );
    assert!(
        results.average_response_time < Duration::from_millis(500),
        "Average response time should be under 500ms"
    );
}

/// Test asset listing under load
#[tokio::test]
async fn test_asset_listing_load() {
    let app = create_test_app().await;

    // Pre-populate with assets
    populate_test_assets(&app, 1000).await;

    let config = LoadTestConfig {
        concurrent_users: 30,
        requests_per_user: 20,
        ..Default::default()
    };

    let results = run_load_test(app, config, |_| create_asset_list_request()).await;

    println!("Asset Listing Load Test Results:");
    print_load_test_results(&results);

    // Assertions for acceptable performance
    assert!(
        results.error_rate < 0.02,
        "Error rate should be less than 2%"
    );
    assert!(
        results.requests_per_second > 15.0,
        "Should handle at least 15 requests per second"
    );
    assert!(
        results.average_response_time < Duration::from_millis(300),
        "Average response time should be under 300ms"
    );
}

/// Test mixed workload under load
#[tokio::test]
async fn test_mixed_workload_load() {
    let app = create_test_app().await;

    // Pre-populate with some data
    populate_test_data(&app, 500).await;

    let config = LoadTestConfig {
        concurrent_users: 25,
        requests_per_user: 30,
        _test_duration: Duration::from_secs(90),
        ..Default::default()
    };

    let results = run_mixed_workload_test(app, config).await;

    println!("Mixed Workload Load Test Results:");
    print_load_test_results(&results);

    // Assertions for acceptable performance under mixed load
    assert!(
        results.error_rate < 0.08,
        "Error rate should be less than 8% for mixed workload"
    );
    assert!(
        results.requests_per_second > 8.0,
        "Should handle at least 8 requests per second"
    );
    assert!(
        results.average_response_time < Duration::from_millis(800),
        "Average response time should be under 800ms"
    );
}

/// Test discovery operations under load
#[tokio::test]
async fn test_discovery_load() {
    let app = create_test_app().await;

    // Pre-populate with seeds
    populate_test_seeds(&app, 100).await;

    let config = LoadTestConfig {
        concurrent_users: 5, // Lower concurrency for discovery operations
        requests_per_user: 10,
        _test_duration: Duration::from_secs(120),
        ..Default::default()
    };

    let results = run_load_test(app, config, |_| create_discovery_request()).await;

    println!("Discovery Load Test Results:");
    print_load_test_results(&results);

    // More lenient assertions for discovery operations
    assert!(
        results.error_rate < 0.15,
        "Error rate should be less than 15% for discovery"
    );
    assert!(
        results.requests_per_second > 1.0,
        "Should handle at least 1 discovery request per second"
    );
}

/// Test evidence upload under load
#[tokio::test]
async fn test_evidence_upload_load() {
    let app = create_test_app().await;

    // Create test scans for evidence upload
    let scan_ids = create_test_scans(&app, 50).await;

    let config = LoadTestConfig {
        concurrent_users: 15,
        requests_per_user: 10,
        ..Default::default()
    };

    let scan_ids_cloned = scan_ids.clone();
    let results = run_load_test(app, config, move |i| {
        create_evidence_upload_request(&scan_ids_cloned[i % scan_ids_cloned.len()])
    })
    .await;

    println!("Evidence Upload Load Test Results:");
    print_load_test_results(&results);

    // Assertions for file upload performance
    assert!(
        results.error_rate < 0.10,
        "Error rate should be less than 10% for file uploads"
    );
    assert!(
        results.requests_per_second > 5.0,
        "Should handle at least 5 uploads per second"
    );
    assert!(
        results.average_response_time < Duration::from_secs(2),
        "Average response time should be under 2 seconds"
    );
}

/// Run a generic load test
async fn run_load_test<F>(
    app: axum::Router,
    config: LoadTestConfig,
    request_factory: F,
) -> LoadTestResults
where
    F: Fn(usize) -> Request<Body> + Send + Sync + 'static,
{
    let semaphore = Arc::new(Semaphore::new(config.concurrent_users));
    let request_factory = Arc::new(request_factory);
    let mut tasks = Vec::new();
    let start_time = Instant::now();

    // Spawn concurrent users
    for user_id in 0..config.concurrent_users {
        let app = app.clone();
        let semaphore = semaphore.clone();
        let request_factory = request_factory.clone();
        let config = config.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            // Stagger user start times for ramp-up
            let delay = config
                .ramp_up_duration
                .mul_f64(user_id as f64 / config.concurrent_users as f64);
            tokio::time::sleep(delay).await;

            let mut user_results = Vec::new();

            // Execute requests for this user
            for request_id in 0..config.requests_per_user {
                let request_start = Instant::now();
                let request = request_factory(user_id * config.requests_per_user + request_id);

                let response = app.clone().oneshot(request).await;
                let request_duration = request_start.elapsed();

                let success = response.map(|r| r.status().is_success()).unwrap_or(false);
                user_results.push((success, request_duration));

                // Small delay between requests to simulate realistic usage
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            user_results
        });

        tasks.push(task);
    }

    // Collect results from all users
    let mut all_results = Vec::new();
    for task in tasks {
        if let Ok(user_results) = task.await {
            all_results.extend(user_results);
        }
    }

    let total_duration = start_time.elapsed();

    // Calculate statistics
    let total_requests = all_results.len();
    let successful_requests = all_results.iter().filter(|(success, _)| *success).count();
    let failed_requests = total_requests - successful_requests;

    let response_times: Vec<Duration> = all_results.iter().map(|(_, duration)| *duration).collect();
    let average_response_time = if !response_times.is_empty() {
        response_times.iter().sum::<Duration>() / response_times.len() as u32
    } else {
        Duration::ZERO
    };

    let min_response_time = response_times
        .iter()
        .min()
        .copied()
        .unwrap_or(Duration::ZERO);
    let max_response_time = response_times
        .iter()
        .max()
        .copied()
        .unwrap_or(Duration::ZERO);

    let requests_per_second = total_requests as f64 / total_duration.as_secs_f64();
    let error_rate = failed_requests as f64 / total_requests as f64;

    LoadTestResults {
        total_requests,
        successful_requests,
        failed_requests,
        average_response_time,
        min_response_time,
        max_response_time,
        requests_per_second,
        error_rate,
    }
}

/// Run mixed workload test with different types of requests
async fn run_mixed_workload_test(app: axum::Router, config: LoadTestConfig) -> LoadTestResults {
    let semaphore = Arc::new(Semaphore::new(config.concurrent_users));
    let mut tasks = Vec::new();
    let start_time = Instant::now();

    // Define request types and their weights
    let request_types = vec![
        ("scan_creation", 0.3),
        ("asset_listing", 0.25),
        ("scan_listing", 0.2),
        ("health_check", 0.15),
        ("seed_creation", 0.1),
    ];

    // Spawn concurrent users
    for user_id in 0..config.concurrent_users {
        let app = app.clone();
        let semaphore = semaphore.clone();
        let config = config.clone();
        let request_types = request_types.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            // Stagger user start times
            let delay = config
                .ramp_up_duration
                .mul_f64(user_id as f64 / config.concurrent_users as f64);
            tokio::time::sleep(delay).await;

            let mut user_results = Vec::new();

            // Execute mixed requests for this user
            for request_id in 0..config.requests_per_user {
                let request_start = Instant::now();

                // Select request type based on weights
                let rand_val = (request_id as f64 / config.requests_per_user as f64) % 1.0;
                let mut cumulative_weight = 0.0;
                let mut selected_type = "health_check";

                for (req_type, weight) in &request_types {
                    cumulative_weight += weight;
                    if rand_val <= cumulative_weight {
                        selected_type = req_type;
                        break;
                    }
                }

                // Create request based on selected type
                let request = match selected_type {
                    "scan_creation" => {
                        create_scan_request(format!("mixed-{}-{}.com", user_id, request_id))
                    }
                    "asset_listing" => create_asset_list_request(),
                    "scan_listing" => create_scan_list_request(),
                    "seed_creation" => {
                        create_seed_request(format!("mixed-seed-{}-{}.com", user_id, request_id))
                    }
                    _ => create_health_check_request(),
                };

                let response = app.clone().oneshot(request).await;
                let request_duration = request_start.elapsed();

                let success = response.map(|r| r.status().is_success()).unwrap_or(false);
                user_results.push((success, request_duration));

                // Variable delay between requests
                let delay_ms = match selected_type {
                    "scan_creation" => 100,
                    "asset_listing" => 50,
                    "discovery" => 200,
                    _ => 25,
                };
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            user_results
        });

        tasks.push(task);
    }

    // Collect and process results (same as run_load_test)
    let mut all_results = Vec::new();
    for task in tasks {
        if let Ok(user_results) = task.await {
            all_results.extend(user_results);
        }
    }

    let total_duration = start_time.elapsed();

    // Calculate statistics
    let total_requests = all_results.len();
    let successful_requests = all_results.iter().filter(|(success, _)| *success).count();
    let failed_requests = total_requests - successful_requests;

    let response_times: Vec<Duration> = all_results.iter().map(|(_, duration)| *duration).collect();
    let average_response_time = if !response_times.is_empty() {
        response_times.iter().sum::<Duration>() / response_times.len() as u32
    } else {
        Duration::ZERO
    };

    let min_response_time = response_times
        .iter()
        .min()
        .copied()
        .unwrap_or(Duration::ZERO);
    let max_response_time = response_times
        .iter()
        .max()
        .copied()
        .unwrap_or(Duration::ZERO);

    let requests_per_second = total_requests as f64 / total_duration.as_secs_f64();
    let error_rate = failed_requests as f64 / total_requests as f64;

    LoadTestResults {
        total_requests,
        successful_requests,
        failed_requests,
        average_response_time,
        min_response_time,
        max_response_time,
        requests_per_second,
        error_rate,
    }
}

// Request factory functions
fn create_scan_request(target: String) -> Request<Body> {
    let body = json!({
        "target": target,
        "note": "Load test scan"
    });

    Request::builder()
        .uri("/api/scans")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn create_asset_list_request() -> Request<Body> {
    Request::builder()
        .uri("/api/assets")
        .body(Body::empty())
        .unwrap()
}

fn create_scan_list_request() -> Request<Body> {
    Request::builder()
        .uri("/api/scans")
        .body(Body::empty())
        .unwrap()
}

fn create_health_check_request() -> Request<Body> {
    Request::builder()
        .uri("/api/health")
        .body(Body::empty())
        .unwrap()
}

fn create_seed_request(value: String) -> Request<Body> {
    let body = json!({
        "seed_type": "domain",
        "value": value
    });

    Request::builder()
        .uri("/api/seeds")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn create_discovery_request() -> Request<Body> {
    Request::builder()
        .uri("/api/discovery/run")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

fn create_evidence_upload_request(scan_id: &Uuid) -> Request<Body> {
    let body = "test evidence content";

    Request::builder()
        .uri(&format!("/api/scans/{}/evidence", scan_id))
        .method("POST")
        .header("content-type", "multipart/form-data")
        .body(Body::from(body))
        .unwrap()
}

// Helper functions
async fn create_test_app() -> axum::Router {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");

    // Set environment variables for test configuration
    std::env::set_var("DATABASE_URL", &db_url);
    std::env::set_var("CORS_ALLOW_ORIGINS", "*");
    std::env::set_var("LOG_LEVEL", "error");

    let test_config = Settings::new_with_env_file(false).expect("Failed to create test config");

    let pool = create_connection_pool(&db_url)
        .await
        .expect("Failed to create database pool");

    // Create test schema
    create_test_schema(&pool).await;

    let app_state = AppState::new_with_pool(test_config, pool)
        .await
        .expect("Failed to create test app state");

    // Keep temp_dir alive
    std::mem::forget(temp_dir);

    create_test_router(app_state)
}

async fn create_test_schema(pool: &rust_backend::database::DatabasePool) {
    // Same schema creation as in other tests
    sqlx::query(
        r#"
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            note TEXT,
            status TEXT NOT NULL DEFAULT 'queued',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create scans table");

    sqlx::query(
        r#"
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            finding_type TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create findings table");

    sqlx::query(
        r#"
        CREATE TABLE assets (
            id TEXT PRIMARY KEY,
            asset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.0,
            sources TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(asset_type, identifier)
        )
    "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create assets table");

    sqlx::query(
        r#"
        CREATE TABLE seeds (
            id TEXT PRIMARY KEY,
            seed_type TEXT NOT NULL,
            value TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(seed_type, value)
        )
    "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create seeds table");

    sqlx::query(
        r#"
        CREATE TABLE evidence (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    "#,
    )
    .execute(pool)
    .await
    .expect("Failed to create evidence table");
}

fn create_test_router(app_state: AppState) -> axum::Router {
    use axum::routing::{get, post};
    use rust_backend::handlers;

    axum::Router::new()
        .route("/api/health", get(handlers::health_check))
        .route("/api/scans", post(handlers::scan_handlers::create_scan))
        .route("/api/scans", get(handlers::scan_handlers::list_scans))
        .route("/api/assets", get(handlers::asset_handlers::list_assets))
        .route("/api/seeds", post(handlers::asset_handlers::create_seed))
        .route("/api/seeds", get(handlers::asset_handlers::list_seeds))
        .route(
            "/api/discovery/run",
            post(handlers::discovery_handlers::run_discovery),
        )
        .route(
            "/api/scans/:scan_id/evidence",
            post(handlers::evidence_handlers::upload_evidence),
        )
        .with_state(app_state)
}

async fn populate_test_assets(app: &axum::Router, count: usize) {
    // Implementation would populate test assets
    // Simplified for brevity
    let _ = (app, count);
}

async fn populate_test_data(app: &axum::Router, count: usize) {
    // Implementation would populate mixed test data
    let _ = (app, count);
}

async fn populate_test_seeds(app: &axum::Router, count: usize) {
    // Implementation would populate test seeds
    let _ = (app, count);
}

async fn create_test_scans(app: &axum::Router, count: usize) -> Vec<Uuid> {
    // Implementation would create test scans and return their IDs
    let _ = (app, count);
    vec![Uuid::new_v4(); count]
}

fn print_load_test_results(results: &LoadTestResults) {
    println!("  Total Requests: {}", results.total_requests);
    println!("  Successful: {}", results.successful_requests);
    println!("  Failed: {}", results.failed_requests);
    println!("  Error Rate: {:.2}%", results.error_rate * 100.0);
    println!("  Requests/Second: {:.2}", results.requests_per_second);
    println!(
        "  Average Response Time: {:?}",
        results.average_response_time
    );
    println!("  Min Response Time: {:?}", results.min_response_time);
    println!("  Max Response Time: {:?}", results.max_response_time);
    println!();
}

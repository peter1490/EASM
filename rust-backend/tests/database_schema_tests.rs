use sqlx::{Row, PgPool};
use std::collections::HashMap;

mod common;
use common::*;

/// Test suite validating database schema compatibility between Rust and Python backends
/// This ensures the Rust backend can work with existing Python backend databases

#[tokio::test]
async fn test_database_schema_compatibility() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    // Test that all expected tables exist
    let tables = get_table_names(&pool).await;
    let expected_tables = vec![
        "scans", "findings", "assets", "seeds", "evidence"
    ];
    
    for table in expected_tables {
        assert!(tables.contains(&table.to_string()), "Missing table: {}", table);
    }
}

#[tokio::test]
async fn test_scans_table_schema() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    let columns = get_table_columns(&pool, "scans").await;
    
    // Verify all required columns exist with correct types
    let expected_columns = vec![
        ("id", "TEXT"),
        ("target", "TEXT"),
        ("note", "TEXT"),
        ("status", "TEXT"),
        ("created_at", "DATETIME"),
        ("updated_at", "DATETIME"),
    ];
    
    for (col_name, col_type) in expected_columns {
        assert!(
            columns.contains_key(col_name),
            "Missing column '{}' in scans table", col_name
        );
        
        let actual_type = columns.get(col_name).unwrap();
        assert!(
            actual_type.to_uppercase().contains(col_type),
            "Column '{}' has type '{}', expected '{}'", col_name, actual_type, col_type
        );
    }
}

#[tokio::test]
async fn test_findings_table_schema() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    let columns = get_table_columns(&pool, "findings").await;
    
    let expected_columns = vec![
        ("id", "TEXT"),
        ("scan_id", "TEXT"),
        ("category", "TEXT"),
        ("title", "TEXT"),
        ("severity", "TEXT"),
        ("data", "JSON"),
        ("created_at", "DATETIME"),
    ];
    
    for (col_name, _col_type) in expected_columns {
        assert!(
            columns.contains_key(col_name),
            "Missing column '{}' in findings table", col_name
        );
    }
}

#[tokio::test]
async fn test_assets_table_schema() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    let columns = get_table_columns(&pool, "assets").await;
    
    let expected_columns = vec![
        ("id", "TEXT"),
        ("asset_type", "TEXT"),
        ("value", "TEXT"),
        ("ownership_confidence", "REAL"),
        ("sources", "JSON"),
        ("metadata", "JSON"),
        ("created_at", "DATETIME"),
        ("updated_at", "DATETIME"),
    ];
    
    for (col_name, _col_type) in expected_columns {
        assert!(
            columns.contains_key(col_name),
            "Missing column '{}' in assets table", col_name
        );
    }
}

#[tokio::test]
async fn test_seeds_table_schema() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    let columns = get_table_columns(&pool, "seeds").await;
    
    let expected_columns = vec![
        ("id", "TEXT"),
        ("seed_type", "TEXT"),
        ("value", "TEXT"),
        ("note", "TEXT"),
        ("created_at", "DATETIME"),
        ("updated_at", "DATETIME"),
    ];
    
    for (col_name, _col_type) in expected_columns {
        assert!(
            columns.contains_key(col_name),
            "Missing column '{}' in seeds table", col_name
        );
    }
}

#[tokio::test]
async fn test_evidence_table_schema() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    let columns = get_table_columns(&pool, "evidence").await;
    
    let expected_columns = vec![
        ("id", "TEXT"),
        ("finding_id", "TEXT"),
        ("filename", "TEXT"),
        ("content_type", "TEXT"),
        ("size_bytes", "INTEGER"),
        ("storage_path", "TEXT"),
        ("created_at", "DATETIME"),
    ];
    
    for (col_name, _col_type) in expected_columns {
        assert!(
            columns.contains_key(col_name),
            "Missing column '{}' in evidence table", col_name
        );
    }
}

#[tokio::test]
async fn test_foreign_key_constraints() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    // Test that foreign key relationships are properly defined
    let fk_info = get_foreign_keys(&pool, "findings").await;
    
    // findings.scan_id should reference scans.id
    let scan_fk = fk_info.iter().find(|fk| fk.from_column == "scan_id");
    assert!(scan_fk.is_some(), "Missing foreign key from findings.scan_id to scans.id");
    
    let scan_fk = scan_fk.unwrap();
    assert_eq!(scan_fk.to_table, "scans");
    assert_eq!(scan_fk.to_column, "id");
}

#[tokio::test]
async fn test_enum_values_compatibility() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    // Test scan status enum values
    let valid_scan_statuses = vec!["queued", "running", "completed", "failed"];
    
    // Insert test data with each status
    for status in valid_scan_statuses {
        let result = sqlx::query(
            "INSERT INTO scans (id, target, status, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())"
        )
        .bind(uuid::Uuid::new_v4())
        .bind("test.com")
        .bind(status)
        .execute(&pool)
        .await;
        
        assert!(result.is_ok(), "Failed to insert scan with status: {}", status);
    }
    
    // Test asset type enum values
    let valid_asset_types = vec!["domain", "ip", "port", "certificate"];
    
    for asset_type in valid_asset_types {
        let result = sqlx::query(
            "INSERT INTO assets (id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())"
        )
        .bind(uuid::Uuid::new_v4())
        .bind(asset_type)
        .bind("test-value")
        .bind(0.5f64)
        .bind(serde_json::json!([]))
        .bind(serde_json::json!({}))
        .execute(&pool)
        .await;
        
        assert!(result.is_ok(), "Failed to insert asset with type: {}", asset_type);
    }
}

#[tokio::test]
async fn test_json_field_compatibility() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");
    
    // Test that JSON fields can store and retrieve complex data
    let test_metadata = serde_json::json!({
        "organization": "Test Corp",
        "country": "US",
        "tags": ["web", "ssl"],
        "ports": [80, 443],
        "nested": {
            "key": "value",
            "number": 42
        }
    });
    
    let asset_id = uuid::Uuid::new_v4().to_string();
    
    // Insert asset with JSON metadata
    sqlx::query(
        "INSERT INTO assets (id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())"
    )
    .bind(&asset_id)
    .bind("domain")
    .bind("test.com")
    .bind(0.8f64)
    .bind(serde_json::json!([]))
    .bind(&test_metadata)
    .execute(&pool)
    .await
    .expect("Failed to insert asset with JSON metadata");
    
    // Retrieve and verify JSON data
    let row = sqlx::query("SELECT metadata FROM assets WHERE id = $1")
        .bind(&asset_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to retrieve asset");
    
    let metadata_str: String = row.get("metadata");
    let retrieved_metadata: serde_json::Value = serde_json::from_str(&metadata_str)
        .expect("Failed to parse JSON metadata");
    
    assert_eq!(retrieved_metadata, test_metadata);
}

// Helper functions

async fn get_table_names(pool: &PgPool) -> Vec<String> {
    let rows = sqlx::query("SELECT table_name as name FROM information_schema.tables WHERE table_schema='public'")
        .fetch_all(pool)
        .await
        .expect("Failed to get table names");
    
    rows.into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect()
}

async fn get_table_columns(pool: &PgPool, table_name: &str) -> HashMap<String, String> {
    let rows = sqlx::query(
        "SELECT column_name as name, data_type as type FROM information_schema.columns WHERE table_name = $1"
    )
    .bind(table_name)
    .fetch_all(pool)
    .await
    .expect("Failed to get table info");
    
    let mut columns = HashMap::new();
    for row in rows {
        let name: String = row.get("name");
        let type_name: String = row.get("type");
        columns.insert(name, type_name);
    }
    
    columns
}

#[derive(Debug)]
struct ForeignKeyInfo {
    from_column: String,
    to_table: String,
    to_column: String,
}

async fn get_foreign_keys(pool: &PgPool, _table_name: &str) -> Vec<ForeignKeyInfo> {
    // Simplified check for PostgreSQL using information_schema
    let rows = sqlx::query(
        "SELECT kcu.column_name as from_column, ccu.table_name as to_table, ccu.column_name as to_column\
         FROM information_schema.table_constraints tc\
         JOIN information_schema.key_column_usage kcu\
           ON tc.constraint_name = kcu.constraint_name\
         JOIN information_schema.constraint_column_usage ccu\
           ON ccu.constraint_name = tc.constraint_name\
         WHERE constraint_type = 'FOREIGN KEY' AND tc.table_name = 'findings'"
    )
    .fetch_all(pool)
    .await
    .expect("Failed to get foreign key info");

    rows.into_iter().map(|row| ForeignKeyInfo {
        from_column: row.get("from_column"),
        to_table: row.get("to_table"),
        to_column: row.get("to_column"),
    }).collect()
}
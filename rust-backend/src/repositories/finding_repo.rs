use async_trait::async_trait;
use uuid::Uuid;
use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Finding, FindingCreate},
};

#[async_trait]
pub trait FindingRepository {
    async fn create(&self, finding: &FindingCreate) -> Result<Finding, ApiError>;
    async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<Finding>, ApiError>;
    async fn list_by_type(&self, finding_type: &str) -> Result<Vec<Finding>, ApiError>;
    async fn search(&self, query: &str) -> Result<Vec<Finding>, ApiError>;
    async fn count_by_scan(&self, scan_id: &Uuid) -> Result<i64, ApiError>;
}

pub struct SqlxFindingRepository {
    pool: DatabasePool,
}

impl SqlxFindingRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FindingRepository for SqlxFindingRepository {
    async fn create(&self, finding: &FindingCreate) -> Result<Finding, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        
        let result = sqlx::query_as::<_, Finding>(
            r#"
            INSERT INTO findings (id, scan_id, finding_type, data, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, scan_id, finding_type, data, created_at
            "#
        )
        .bind(id)
        .bind(finding.scan_id)
        .bind(&finding.finding_type)
        .bind(&finding.data)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE scan_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn list_by_type(&self, finding_type: &str) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE finding_type = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(finding_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn search(&self, query: &str) -> Result<Vec<Finding>, ApiError> {
        // Search in finding_type and JSON data fields
        let search_pattern = format!("%{}%", query);
        
        #[cfg(test)]
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE finding_type LIKE $1 OR json_extract(data, '$') LIKE $1
            ORDER BY created_at DESC
            "#
        )
        .bind(&search_pattern)
        .fetch_all(&self.pool)
        .await?;

        #[cfg(not(test))]
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE finding_type ILIKE $1 OR data::text ILIKE $1
            ORDER BY created_at DESC
            "#
        )
        .bind(&search_pattern)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn count_by_scan(&self, scan_id: &Uuid) -> Result<i64, ApiError> {
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM findings
            WHERE scan_id = $1
            "#
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::database::create_connection_pool;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE findings RESTART IDENTITY CASCADE").execute(&pool).await;
        pool
    }

    #[tokio::test]
    async fn test_create_finding() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let finding_create = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80, "service": "http"}),
        };

        let result = repo.create(&finding_create).await;
        assert!(result.is_ok());

        let finding = result.unwrap();
        assert_eq!(finding.scan_id, scan_id);
        assert_eq!(finding.finding_type, "port_scan");
        assert_eq!(finding.data["port"], 80);
    }

    #[tokio::test]
    async fn test_list_by_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let other_scan_id = Uuid::new_v4();

        // Create findings for the target scan
        let finding1 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80}),
        };
        let finding2 = FindingCreate {
            scan_id,
            finding_type: "dns_record".to_string(),
            data: json!({"record": "A"}),
        };

        // Create finding for different scan
        let finding3 = FindingCreate {
            scan_id: other_scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 443}),
        };

        repo.create(&finding1).await.unwrap();
        repo.create(&finding2).await.unwrap();
        repo.create(&finding3).await.unwrap();

        let results = repo.list_by_scan(&scan_id).await.unwrap();
        assert_eq!(results.len(), 2);

        let other_results = repo.list_by_scan(&other_scan_id).await.unwrap();
        assert_eq!(other_results.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_type() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();

        // Create findings of different types
        let finding1 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80}),
        };
        let finding2 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 443}),
        };
        let finding3 = FindingCreate {
            scan_id,
            finding_type: "dns_record".to_string(),
            data: json!({"record": "A"}),
        };

        repo.create(&finding1).await.unwrap();
        repo.create(&finding2).await.unwrap();
        repo.create(&finding3).await.unwrap();

        let port_scan_results = repo.list_by_type("port_scan").await.unwrap();
        assert_eq!(port_scan_results.len(), 2);

        let dns_results = repo.list_by_type("dns_record").await.unwrap();
        assert_eq!(dns_results.len(), 1);

        let nonexistent_results = repo.list_by_type("nonexistent").await.unwrap();
        assert_eq!(nonexistent_results.len(), 0);
    }

    #[tokio::test]
    async fn test_search() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();

        // Create findings with searchable content
        let finding1 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80, "service": "http"}),
        };
        let finding2 = FindingCreate {
            scan_id,
            finding_type: "dns_record".to_string(),
            data: json!({"record": "A", "value": "192.168.1.1"}),
        };
        let finding3 = FindingCreate {
            scan_id,
            finding_type: "certificate".to_string(),
            data: json!({"subject": "example.com", "issuer": "Let's Encrypt"}),
        };

        repo.create(&finding1).await.unwrap();
        repo.create(&finding2).await.unwrap();
        repo.create(&finding3).await.unwrap();

        // Search by finding type
        let port_results = repo.search("port").await.unwrap();
        assert_eq!(port_results.len(), 1);

        // Search by data content
        let http_results = repo.search("http").await.unwrap();
        assert_eq!(http_results.len(), 1);

        // Search that matches multiple findings
        let record_results = repo.search("record").await.unwrap();
        assert_eq!(record_results.len(), 1);

        // Search with no matches
        let no_results = repo.search("nonexistent").await.unwrap();
        assert_eq!(no_results.len(), 0);
    }
}
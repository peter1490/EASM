use async_trait::async_trait;
use uuid::Uuid;
use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Scan, ScanCreate, ScanStatus},
};

#[async_trait]
pub trait ScanRepository {
    async fn create(&self, scan: &ScanCreate) -> Result<Scan, ApiError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Scan>, ApiError>;
    async fn list(&self) -> Result<Vec<Scan>, ApiError>;
    async fn list_by_status(&self, status: Option<ScanStatus>) -> Result<Vec<Scan>, ApiError>;
    async fn update_status(&self, id: &Uuid, status: ScanStatus) -> Result<(), ApiError>;
}

pub struct SqlxScanRepository {
    pool: DatabasePool,
}

impl SqlxScanRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ScanRepository for SqlxScanRepository {
    async fn create(&self, scan: &ScanCreate) -> Result<Scan, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        
        let result = sqlx::query_as::<_, Scan>(
            r#"
            INSERT INTO scans (id, target, note, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, target, note, status, created_at, updated_at
            "#
        )
        .bind(id)
        .bind(&scan.target)
        .bind(&scan.note)
        .bind(ScanStatus::Queued)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Scan>, ApiError> {
        let result = sqlx::query_as::<_, Scan>(
            r#"
            SELECT id, target, note, status, created_at, updated_at
            FROM scans
            WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list(&self) -> Result<Vec<Scan>, ApiError> {
        let results = sqlx::query_as::<_, Scan>(
            r#"
            SELECT id, target, note, status, created_at, updated_at
            FROM scans
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn update_status(&self, id: &Uuid, status: ScanStatus) -> Result<(), ApiError> {
        let now = chrono::Utc::now();
        
        let result = sqlx::query(
            r#"
            UPDATE scans
            SET status = $1, updated_at = $2
            WHERE id = $3
            "#
        )
        .bind(status)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!("Scan with id {} not found", id)));
        }

        Ok(())
    }

    async fn list_by_status(&self, status: Option<ScanStatus>) -> Result<Vec<Scan>, ApiError> {
        let results = match status {
            Some(status) => {
                sqlx::query_as::<_, Scan>(
                    r#"
                    SELECT id, target, note, status, created_at, updated_at
                    FROM scans
                    WHERE status = $1
                    ORDER BY created_at DESC
                    "#
                )
                .bind(status)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Scan>(
                    r#"
                    SELECT id, target, note, status, created_at, updated_at
                    FROM scans
                    ORDER BY created_at DESC
                    "#
                )
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanStatus;
    use crate::database::create_connection_pool;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE scans RESTART IDENTITY CASCADE").execute(&pool).await;
        pool
    }

    #[tokio::test]
    async fn test_create_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        let scan_create = ScanCreate {
            target: "example.com".to_string(),
            note: Some("Test scan".to_string()),
        };

        let result = repo.create(&scan_create).await;
        assert!(result.is_ok());

        let scan = result.unwrap();
        assert_eq!(scan.target, "example.com");
        assert_eq!(scan.note, Some("Test scan".to_string()));
        assert_eq!(scan.status, ScanStatus::Queued);
    }

    #[tokio::test]
    async fn test_get_scan_by_id() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        let scan_create = ScanCreate {
            target: "example.com".to_string(),
            note: None,
        };

        let created_scan = repo.create(&scan_create).await.unwrap();
        let retrieved_scan = repo.get_by_id(&created_scan.id).await.unwrap();

        assert!(retrieved_scan.is_some());
        let scan = retrieved_scan.unwrap();
        assert_eq!(scan.id, created_scan.id);
        assert_eq!(scan.target, "example.com");
    }

    #[tokio::test]
    async fn test_get_nonexistent_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        let nonexistent_id = Uuid::new_v4();
        let result = repo.get_by_id(&nonexistent_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_scans() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        // Create multiple scans
        let scan1 = ScanCreate {
            target: "example1.com".to_string(),
            note: None,
        };
        let scan2 = ScanCreate {
            target: "example2.com".to_string(),
            note: Some("Test".to_string()),
        };

        repo.create(&scan1).await.unwrap();
        repo.create(&scan2).await.unwrap();

        let scans = repo.list().await.unwrap();
        assert_eq!(scans.len(), 2);
    }

    #[tokio::test]
    async fn test_update_scan_status() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        let scan_create = ScanCreate {
            target: "example.com".to_string(),
            note: None,
        };

        let created_scan = repo.create(&scan_create).await.unwrap();
        assert_eq!(created_scan.status, ScanStatus::Queued);

        // Update status to running
        repo.update_status(&created_scan.id, ScanStatus::Running).await.unwrap();

        let updated_scan = repo.get_by_id(&created_scan.id).await.unwrap().unwrap();
        assert_eq!(updated_scan.status, ScanStatus::Running);
        assert!(updated_scan.updated_at > created_scan.updated_at);
    }

    #[tokio::test]
    async fn test_update_nonexistent_scan_status() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        let nonexistent_id = Uuid::new_v4();
        let result = repo.update_status(&nonexistent_id, ScanStatus::Running).await;
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::NotFound(_) => (),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_list_by_status() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        // Create scans with different statuses
        let scan1 = repo.create(&ScanCreate {
            target: "example1.com".to_string(),
            note: None,
        }).await.unwrap();

        let scan2 = repo.create(&ScanCreate {
            target: "example2.com".to_string(),
            note: None,
        }).await.unwrap();

        // Update one scan to running
        repo.update_status(&scan2.id, ScanStatus::Running).await.unwrap();

        // Test filtering by status
        let queued_scans = repo.list_by_status(Some(ScanStatus::Queued)).await.unwrap();
        assert_eq!(queued_scans.len(), 1);
        assert_eq!(queued_scans[0].id, scan1.id);

        let running_scans = repo.list_by_status(Some(ScanStatus::Running)).await.unwrap();
        assert_eq!(running_scans.len(), 1);
        assert_eq!(running_scans[0].id, scan2.id);

        // Test listing all scans
        let all_scans = repo.list_by_status(None).await.unwrap();
        assert_eq!(all_scans.len(), 2);
    }
}
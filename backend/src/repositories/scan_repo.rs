use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Scan, ScanCreate, ScanStatus},
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait ScanRepository {
    async fn create(&self, scan: &ScanCreate, company_id: Uuid) -> Result<Scan, ApiError>;
    async fn get_by_id(&self, company_id: Uuid, id: &Uuid) -> Result<Option<Scan>, ApiError>;
    async fn list(&self, company_id: Uuid) -> Result<Vec<Scan>, ApiError>;
    async fn list_by_status(
        &self,
        company_id: Uuid,
        status: Option<ScanStatus>,
    ) -> Result<Vec<Scan>, ApiError>;
    async fn update_status(
        &self,
        company_id: Uuid,
        id: &Uuid,
        status: ScanStatus,
    ) -> Result<(), ApiError>;
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
    async fn create(&self, scan: &ScanCreate, company_id: Uuid) -> Result<Scan, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let result = sqlx::query_as::<_, Scan>(
            r#"
            INSERT INTO scans (id, target, note, status, created_at, updated_at, company_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, target, note, status, created_at, updated_at, company_id
            "#,
        )
        .bind(id)
        .bind(&scan.target)
        .bind(&scan.note)
        .bind(ScanStatus::Queued)
        .bind(now)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn get_by_id(&self, company_id: Uuid, id: &Uuid) -> Result<Option<Scan>, ApiError> {
        let result = sqlx::query_as::<_, Scan>(
            r#"
            SELECT id, target, note, status, created_at, updated_at, company_id
            FROM scans
            WHERE id = $1 AND company_id = $2
            "#,
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list(&self, company_id: Uuid) -> Result<Vec<Scan>, ApiError> {
        let results = sqlx::query_as::<_, Scan>(
            r#"
            SELECT id, target, note, status, created_at, updated_at, company_id
            FROM scans
            WHERE company_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn update_status(
        &self,
        company_id: Uuid,
        id: &Uuid,
        status: ScanStatus,
    ) -> Result<(), ApiError> {
        let now = chrono::Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE scans
            SET status = $1, updated_at = $2
            WHERE id = $3 AND company_id = $4
            "#,
        )
        .bind(status)
        .bind(now)
        .bind(id)
        .bind(company_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!("Scan with id {} not found", id)));
        }

        Ok(())
    }

    async fn list_by_status(
        &self,
        company_id: Uuid,
        status: Option<ScanStatus>,
    ) -> Result<Vec<Scan>, ApiError> {
        let results = match status {
            Some(status) => {
                sqlx::query_as::<_, Scan>(
                    r#"
                    SELECT id, target, note, status, created_at, updated_at, company_id
                    FROM scans
                    WHERE status = $1 AND company_id = $2
                    ORDER BY created_at DESC
                    "#,
                )
                .bind(status)
                .bind(company_id)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Scan>(
                    r#"
                    SELECT id, target, note, status, created_at, updated_at, company_id
                    FROM scans
                    WHERE company_id = $1
                    ORDER BY created_at DESC
                    "#,
                )
                .bind(company_id)
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
    use crate::database::create_connection_pool;
    use crate::models::ScanStatus;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE scans RESTART IDENTITY CASCADE")
            .execute(&pool)
            .await;
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

        let company_id = Uuid::new_v4();
        let result = repo.create(&scan_create, company_id).await;
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

        let company_id = Uuid::new_v4();
        let created_scan = repo.create(&scan_create, company_id).await.unwrap();
        let retrieved_scan = repo.get_by_id(company_id, &created_scan.id).await.unwrap();

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
        let company_id = Uuid::new_v4();
        let result = repo.get_by_id(company_id, &nonexistent_id).await.unwrap();
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

        let company_id = Uuid::new_v4();
        repo.create(&scan1, company_id).await.unwrap();
        repo.create(&scan2, company_id).await.unwrap();

        let scans = repo.list(company_id).await.unwrap();
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

        let company_id = Uuid::new_v4();
        let created_scan = repo.create(&scan_create, company_id).await.unwrap();
        assert_eq!(created_scan.status, ScanStatus::Queued);

        // Update status to running
        repo.update_status(company_id, &created_scan.id, ScanStatus::Running)
            .await
            .unwrap();

        let updated_scan = repo
            .get_by_id(company_id, &created_scan.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_scan.status, ScanStatus::Running);
        assert!(updated_scan.updated_at > created_scan.updated_at);
    }

    #[tokio::test]
    async fn test_update_nonexistent_scan_status() {
        let pool = setup_test_db().await;
        let repo = SqlxScanRepository::new(pool);

        let nonexistent_id = Uuid::new_v4();
        let company_id = Uuid::new_v4();
        let result = repo
            .update_status(company_id, &nonexistent_id, ScanStatus::Running)
            .await;

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

        let company_id = Uuid::new_v4();
        // Create scans with different statuses
        let scan1 = repo
            .create(
                &ScanCreate {
                    target: "example1.com".to_string(),
                    note: None,
                },
                company_id,
            )
            .await
            .unwrap();

        let scan2 = repo
            .create(
                &ScanCreate {
                    target: "example2.com".to_string(),
                    note: None,
                },
                company_id,
            )
            .await
            .unwrap();

        // Update one scan to running
        repo.update_status(company_id, &scan2.id, ScanStatus::Running)
            .await
            .unwrap();

        // Test filtering by status
        let queued_scans = repo
            .list_by_status(company_id, Some(ScanStatus::Queued))
            .await
            .unwrap();
        assert_eq!(queued_scans.len(), 1);
        assert_eq!(queued_scans[0].id, scan1.id);

        let running_scans = repo
            .list_by_status(company_id, Some(ScanStatus::Running))
            .await
            .unwrap();
        assert_eq!(running_scans.len(), 1);
        assert_eq!(running_scans[0].id, scan2.id);

        // Test listing all scans
        let all_scans = repo.list_by_status(company_id, None).await.unwrap();
        assert_eq!(all_scans.len(), 2);
    }
}

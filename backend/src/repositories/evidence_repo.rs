use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Evidence, EvidenceCreate},
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait EvidenceRepository {
    async fn create(
        &self,
        evidence: &EvidenceCreate,
        company_id: Uuid,
    ) -> Result<Evidence, ApiError>;
    async fn get_by_id(&self, id: &Uuid, company_id: Uuid) -> Result<Option<Evidence>, ApiError>;
    async fn list_by_scan(
        &self,
        scan_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<Evidence>, ApiError>;
    async fn list_by_content_type(
        &self,
        content_type: &str,
        company_id: Uuid,
    ) -> Result<Vec<Evidence>, ApiError>;
    async fn delete(&self, id: &Uuid, company_id: Uuid) -> Result<(), ApiError>;
}

pub struct SqlxEvidenceRepository {
    pool: DatabasePool,
}

impl SqlxEvidenceRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    fn validate_evidence(&self, evidence: &EvidenceCreate) -> Result<(), ApiError> {
        // Validate filename
        if evidence.filename.trim().is_empty() {
            return Err(ApiError::Validation("Filename cannot be empty".to_string()));
        }

        // Validate file size (max 100MB for example)
        const MAX_FILE_SIZE: i64 = 100 * 1024 * 1024; // 100MB
        if evidence.file_size < 0 {
            return Err(ApiError::Validation(
                "File size cannot be negative".to_string(),
            ));
        }
        if evidence.file_size > MAX_FILE_SIZE {
            return Err(ApiError::Validation(format!(
                "File size {} exceeds maximum allowed size of {} bytes",
                evidence.file_size, MAX_FILE_SIZE
            )));
        }

        // Validate content type
        if evidence.content_type.trim().is_empty() {
            return Err(ApiError::Validation(
                "Content type cannot be empty".to_string(),
            ));
        }

        // Validate file path
        if evidence.file_path.trim().is_empty() {
            return Err(ApiError::Validation(
                "File path cannot be empty".to_string(),
            ));
        }

        // Basic security check - prevent path traversal
        if evidence.file_path.contains("..") || evidence.file_path.contains("//") {
            return Err(ApiError::Validation(
                "Invalid file path - path traversal not allowed".to_string(),
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl EvidenceRepository for SqlxEvidenceRepository {
    async fn create(
        &self,
        evidence: &EvidenceCreate,
        company_id: Uuid,
    ) -> Result<Evidence, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        // Validate file metadata
        self.validate_evidence(evidence)?;

        let result = sqlx::query_as::<_, Evidence>(
            r#"
            INSERT INTO evidence (id, scan_id, filename, content_type, file_size, file_path, created_at)
            SELECT $1, $2, $3, $4, $5, $6, $7
            FROM scans
            WHERE scans.id = $2 AND scans.company_id = $8
            RETURNING id, scan_id, filename, content_type, file_size, file_path, created_at
            "#,
        )
        .bind(id)
        .bind(evidence.scan_id)
        .bind(&evidence.filename)
        .bind(&evidence.content_type)
        .bind(evidence.file_size)
        .bind(&evidence.file_path)
        .bind(now)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        result.ok_or_else(|| ApiError::NotFound("Scan not found for company".to_string()))
    }

    async fn get_by_id(&self, id: &Uuid, company_id: Uuid) -> Result<Option<Evidence>, ApiError> {
        let result = sqlx::query_as::<_, Evidence>(
            r#"
            SELECT e.id, e.scan_id, e.filename, e.content_type, e.file_size, e.file_path, e.created_at
            FROM evidence e
            JOIN scans s ON e.scan_id = s.id
            WHERE e.id = $1 AND s.company_id = $2
            "#,
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list_by_scan(
        &self,
        scan_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<Evidence>, ApiError> {
        let results = sqlx::query_as::<_, Evidence>(
            r#"
            SELECT e.id, e.scan_id, e.filename, e.content_type, e.file_size, e.file_path, e.created_at
            FROM evidence e
            JOIN scans s ON e.scan_id = s.id
            WHERE e.scan_id = $1 AND s.company_id = $2
            ORDER BY e.created_at DESC
            "#,
        )
        .bind(scan_id)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn list_by_content_type(
        &self,
        content_type: &str,
        company_id: Uuid,
    ) -> Result<Vec<Evidence>, ApiError> {
        let results = sqlx::query_as::<_, Evidence>(
            r#"
            SELECT e.id, e.scan_id, e.filename, e.content_type, e.file_size, e.file_path, e.created_at
            FROM evidence e
            JOIN scans s ON e.scan_id = s.id
            WHERE e.content_type = $1 AND s.company_id = $2
            ORDER BY e.created_at DESC
            "#,
        )
        .bind(content_type)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn delete(&self, id: &Uuid, company_id: Uuid) -> Result<(), ApiError> {
        let result = sqlx::query(
            r#"
            DELETE FROM evidence e
            USING scans s
            WHERE e.id = $1 AND e.scan_id = s.id AND s.company_id = $2
            "#,
        )
        .bind(id)
        .bind(company_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!(
                "Evidence with id {} not found",
                id
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::create_connection_pool;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE evidence RESTART IDENTITY CASCADE")
            .execute(&pool)
            .await;
        pool
    }

    async fn insert_scan(pool: &DatabasePool, scan_id: Uuid, company_id: Uuid) {
        let _ = sqlx::query(
            r#"
            INSERT INTO scans (id, target, status, created_at, updated_at, company_id)
            VALUES ($1, $2, 'queued', NOW(), NOW(), $3)
            "#,
        )
        .bind(scan_id)
        .bind("test-scan")
        .bind(company_id)
        .execute(pool)
        .await;
    }

    #[tokio::test]
    async fn test_create_evidence() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;
        let evidence_create = EvidenceCreate {
            scan_id,
            filename: "screenshot.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/screenshot.png".to_string(),
        };

        let result = repo.create(&evidence_create, company_id).await;
        assert!(result.is_ok());

        let evidence = result.unwrap();
        assert_eq!(evidence.scan_id, scan_id);
        assert_eq!(evidence.filename, "screenshot.png");
        assert_eq!(evidence.content_type, "image/png");
        assert_eq!(evidence.file_size, 1024);
    }

    #[tokio::test]
    async fn test_evidence_validation() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;

        // Test empty filename
        let invalid_filename = EvidenceCreate {
            scan_id,
            filename: "".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/file.png".to_string(),
        };
        let result = repo.create(&invalid_filename, company_id).await;
        assert!(result.is_err());

        // Test negative file size
        let invalid_size = EvidenceCreate {
            scan_id,
            filename: "file.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: -1,
            file_path: "/evidence/file.png".to_string(),
        };
        let result = repo.create(&invalid_size, company_id).await;
        assert!(result.is_err());

        // Test path traversal
        let invalid_path = EvidenceCreate {
            scan_id,
            filename: "file.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "../../../etc/passwd".to_string(),
        };
        let result = repo.create(&invalid_path, company_id).await;
        assert!(result.is_err());

        // Test empty content type
        let invalid_content_type = EvidenceCreate {
            scan_id,
            filename: "file.png".to_string(),
            content_type: "".to_string(),
            file_size: 1024,
            file_path: "/evidence/file.png".to_string(),
        };
        let result = repo.create(&invalid_content_type, company_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;
        let evidence_create = EvidenceCreate {
            scan_id,
            filename: "screenshot.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/screenshot.png".to_string(),
        };

        let created_evidence = repo.create(&evidence_create, company_id).await.unwrap();

        let found_evidence = repo
            .get_by_id(&created_evidence.id, company_id)
            .await
            .unwrap();
        assert!(found_evidence.is_some());
        assert_eq!(found_evidence.unwrap().filename, "screenshot.png");

        let nonexistent_id = Uuid::new_v4();
        let not_found = repo.get_by_id(&nonexistent_id, company_id).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_list_by_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let other_scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;
        insert_scan(&pool, other_scan_id, company_id).await;

        // Create evidence for the target scan
        let evidence1 = EvidenceCreate {
            scan_id,
            filename: "screenshot1.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/screenshot1.png".to_string(),
        };
        let evidence2 = EvidenceCreate {
            scan_id,
            filename: "report.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            file_size: 2048,
            file_path: "/evidence/report.pdf".to_string(),
        };

        // Create evidence for different scan
        let evidence3 = EvidenceCreate {
            scan_id: other_scan_id,
            filename: "other.txt".to_string(),
            content_type: "text/plain".to_string(),
            file_size: 512,
            file_path: "/evidence/other.txt".to_string(),
        };

        repo.create(&evidence1, company_id).await.unwrap();
        repo.create(&evidence2, company_id).await.unwrap();
        repo.create(&evidence3, company_id).await.unwrap();

        let results = repo.list_by_scan(&scan_id, company_id).await.unwrap();
        assert_eq!(results.len(), 2);

        let other_results = repo.list_by_scan(&other_scan_id, company_id).await.unwrap();
        assert_eq!(other_results.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_content_type() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;

        // Create evidence with different content types
        let evidence1 = EvidenceCreate {
            scan_id,
            filename: "screenshot1.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/screenshot1.png".to_string(),
        };
        let evidence2 = EvidenceCreate {
            scan_id,
            filename: "screenshot2.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/screenshot2.png".to_string(),
        };
        let evidence3 = EvidenceCreate {
            scan_id,
            filename: "report.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            file_size: 2048,
            file_path: "/evidence/report.pdf".to_string(),
        };

        repo.create(&evidence1, company_id).await.unwrap();
        repo.create(&evidence2, company_id).await.unwrap();
        repo.create(&evidence3, company_id).await.unwrap();

        let png_results = repo
            .list_by_content_type("image/png", company_id)
            .await
            .unwrap();
        assert_eq!(png_results.len(), 2);

        let pdf_results = repo
            .list_by_content_type("application/pdf", company_id)
            .await
            .unwrap();
        assert_eq!(pdf_results.len(), 1);

        let nonexistent_results = repo
            .list_by_content_type("video/mp4", company_id)
            .await
            .unwrap();
        assert_eq!(nonexistent_results.len(), 0);
    }

    #[tokio::test]
    async fn test_delete_evidence() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;
        let evidence_create = EvidenceCreate {
            scan_id,
            filename: "screenshot.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/screenshot.png".to_string(),
        };

        let created_evidence = repo.create(&evidence_create, company_id).await.unwrap();

        // Delete the evidence
        let result = repo.delete(&created_evidence.id, company_id).await;
        assert!(result.is_ok());

        // Verify it's deleted
        let found = repo
            .get_by_id(&created_evidence.id, company_id)
            .await
            .unwrap();
        assert!(found.is_none());

        // Try to delete non-existent evidence
        let nonexistent_id = Uuid::new_v4();
        let result = repo.delete(&nonexistent_id, company_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_company_scoping() {
        let pool = setup_test_db().await;
        let repo = SqlxEvidenceRepository::new(pool.clone());

        let company_a = Uuid::nil();
        let company_b = Uuid::new_v4();
        let _ =
            sqlx::query("INSERT INTO companies (id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(company_b)
                .bind("Company B")
                .execute(&pool)
                .await;

        let scan_id = Uuid::new_v4();
        insert_scan(&pool, scan_id, company_a).await;

        let evidence_create = EvidenceCreate {
            scan_id,
            filename: "company_a.png".to_string(),
            content_type: "image/png".to_string(),
            file_size: 1024,
            file_path: "/evidence/company_a.png".to_string(),
        };

        let created = repo.create(&evidence_create, company_a).await.unwrap();
        let wrong_company = repo.get_by_id(&created.id, company_b).await.unwrap();
        assert!(wrong_company.is_none());
    }
}

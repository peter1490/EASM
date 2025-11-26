use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{
        FindingSeverity, FindingStatus, ScanTriggerType, SecurityFinding, SecurityFindingCreate,
        SecurityFindingFilter, SecurityFindingUpdate, SecurityScan, SecurityScanCreate,
        SecurityScanStatus, SecurityScanType,
    },
};

// ============================================================================
// Security Scan Repository
// ============================================================================

#[async_trait]
pub trait SecurityScanRepository: Send + Sync {
    async fn create(&self, scan: &SecurityScanCreate) -> Result<SecurityScan, ApiError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<SecurityScan>, ApiError>;
    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
    ) -> Result<Vec<SecurityScan>, ApiError>;
    async fn list_pending(&self, limit: i64) -> Result<Vec<SecurityScan>, ApiError>;
    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<SecurityScan>, ApiError>;
    async fn update_status(
        &self,
        id: &Uuid,
        status: SecurityScanStatus,
    ) -> Result<SecurityScan, ApiError>;
    async fn start(&self, id: &Uuid) -> Result<SecurityScan, ApiError>;
    async fn complete(&self, id: &Uuid, result_summary: &Value) -> Result<SecurityScan, ApiError>;
    async fn fail(&self, id: &Uuid, error: &str) -> Result<SecurityScan, ApiError>;
    async fn get_latest_for_asset(&self, asset_id: &Uuid)
        -> Result<Option<SecurityScan>, ApiError>;
    async fn count_by_status(&self) -> Result<std::collections::HashMap<String, i64>, ApiError>;
}

pub struct SqlxSecurityScanRepository {
    pool: PgPool,
}

impl SqlxSecurityScanRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecurityScanRepository for SqlxSecurityScanRepository {
    async fn create(&self, scan: &SecurityScanCreate) -> Result<SecurityScan, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let scan_type = scan
            .scan_type
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "full".to_string());
        let trigger_type = scan
            .trigger_type
            .as_ref()
            .map(|t| format!("{:?}", t).to_lowercase())
            .unwrap_or_else(|| "manual".to_string());
        let priority = scan.priority.unwrap_or(5);
        let config = scan.config.clone().unwrap_or(json!({}));

        let row = sqlx::query_as::<_, SecurityScan>(
            r#"
            INSERT INTO security_scans 
                (id, asset_id, scan_type, status, trigger_type, priority, note, config, result_summary, created_at, updated_at)
            VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, '{}', $8, $8)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(scan.asset_id)
        .bind(&scan_type)
        .bind(&trigger_type)
        .bind(priority)
        .bind(&scan.note)
        .bind(&config)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<SecurityScan>, ApiError> {
        let row = sqlx::query_as::<_, SecurityScan>("SELECT * FROM security_scans WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row)
    }

    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE asset_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(asset_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_pending(&self, limit: i64) -> Result<Vec<SecurityScan>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE status = 'pending' ORDER BY priority DESC, created_at ASC LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_all(&self, limit: i64, offset: i64) -> Result<Vec<SecurityScan>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn update_status(
        &self,
        id: &Uuid,
        status: SecurityScanStatus,
    ) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();
        let status_str = status.to_string();

        let row = sqlx::query_as::<_, SecurityScan>(
            "UPDATE security_scans SET status = $2, updated_at = $3 WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(&status_str)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn start(&self, id: &Uuid) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, SecurityScan>(
            "UPDATE security_scans SET status = 'running', started_at = $2, updated_at = $2 WHERE id = $1 RETURNING *"
        )
        .bind(id)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn complete(&self, id: &Uuid, result_summary: &Value) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, SecurityScan>(
            r#"
            UPDATE security_scans 
            SET status = 'completed', completed_at = $2, result_summary = $3, updated_at = $2 
            WHERE id = $1 
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(result_summary)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn fail(&self, id: &Uuid, error: &str) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();
        let result_summary = json!({ "error": error });

        let row = sqlx::query_as::<_, SecurityScan>(
            r#"
            UPDATE security_scans 
            SET status = 'failed', completed_at = $2, result_summary = $3, updated_at = $2 
            WHERE id = $1 
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(&result_summary)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_latest_for_asset(
        &self,
        asset_id: &Uuid,
    ) -> Result<Option<SecurityScan>, ApiError> {
        let row = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE asset_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn count_by_status(&self) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT status, COUNT(*) FROM security_scans GROUP BY status",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }
}

// ============================================================================
// Security Finding Repository
// ============================================================================

#[async_trait]
pub trait SecurityFindingRepository: Send + Sync {
    async fn create(&self, finding: &SecurityFindingCreate) -> Result<SecurityFinding, ApiError>;
    async fn create_or_update(
        &self,
        finding: &SecurityFindingCreate,
    ) -> Result<SecurityFinding, ApiError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<SecurityFinding>, ApiError>;
    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
    ) -> Result<Vec<SecurityFinding>, ApiError>;
    async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<SecurityFinding>, ApiError>;
    async fn list_filtered(
        &self,
        filter: &SecurityFindingFilter,
    ) -> Result<(Vec<SecurityFinding>, i64), ApiError>;
    async fn update(
        &self,
        id: &Uuid,
        update: &SecurityFindingUpdate,
        updated_by: Option<Uuid>,
    ) -> Result<SecurityFinding, ApiError>;
    async fn resolve(&self, id: &Uuid, resolved_by: Uuid) -> Result<SecurityFinding, ApiError>;
    async fn count_by_severity(&self) -> Result<std::collections::HashMap<String, i64>, ApiError>;
    async fn count_by_status(&self) -> Result<std::collections::HashMap<String, i64>, ApiError>;
    async fn count_by_asset(&self, asset_id: &Uuid) -> Result<i64, ApiError>;
}

pub struct SqlxSecurityFindingRepository {
    pool: PgPool,
}

impl SqlxSecurityFindingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecurityFindingRepository for SqlxSecurityFindingRepository {
    async fn create(&self, finding: &SecurityFindingCreate) -> Result<SecurityFinding, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let severity = finding.severity.to_string();

        let row = sqlx::query_as::<_, SecurityFinding>(
            r#"
            INSERT INTO security_findings 
                (id, security_scan_id, asset_id, finding_type, severity, title, description, remediation, data, status, first_seen_at, last_seen_at, cvss_score, cve_ids, tags, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', $10, $10, $11, $12, $13, $10, $10)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(finding.security_scan_id)
        .bind(finding.asset_id)
        .bind(&finding.finding_type)
        .bind(&severity)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.remediation)
        .bind(&finding.data)
        .bind(now)
        .bind(finding.cvss_score)
        .bind(&finding.cve_ids)
        .bind(&finding.tags)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn create_or_update(
        &self,
        finding: &SecurityFindingCreate,
    ) -> Result<SecurityFinding, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let severity = finding.severity.to_string();

        // Try to find existing finding of same type for same asset
        let existing = sqlx::query_as::<_, SecurityFinding>(
            r#"
            SELECT * FROM security_findings 
            WHERE asset_id = $1 AND finding_type = $2 AND status NOT IN ('resolved', 'false_positive')
            ORDER BY first_seen_at DESC LIMIT 1
            "#
        )
        .bind(finding.asset_id)
        .bind(&finding.finding_type)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(existing) = existing {
            // Update existing finding
            let row = sqlx::query_as::<_, SecurityFinding>(
                r#"
                UPDATE security_findings 
                SET last_seen_at = $2, security_scan_id = COALESCE($3, security_scan_id), data = $4, updated_at = $2
                WHERE id = $1
                RETURNING *
                "#
            )
            .bind(existing.id)
            .bind(now)
            .bind(finding.security_scan_id)
            .bind(&finding.data)
            .fetch_one(&self.pool)
            .await?;

            Ok(row)
        } else {
            // Create new finding
            self.create(finding).await
        }
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<SecurityFinding>, ApiError> {
        let row =
            sqlx::query_as::<_, SecurityFinding>("SELECT * FROM security_findings WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row)
    }

    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
    ) -> Result<Vec<SecurityFinding>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityFinding>(
            "SELECT * FROM security_findings WHERE asset_id = $1 ORDER BY first_seen_at DESC LIMIT $2"
        )
        .bind(asset_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<SecurityFinding>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityFinding>(
            "SELECT * FROM security_findings WHERE security_scan_id = $1 ORDER BY severity, first_seen_at DESC"
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_filtered(
        &self,
        filter: &SecurityFindingFilter,
    ) -> Result<(Vec<SecurityFinding>, i64), ApiError> {
        // Build dynamic query
        let mut conditions: Vec<String> = Vec::new();
        let mut params_count = 0u32;

        // Start with base query
        let mut query = String::from("SELECT * FROM security_findings WHERE 1=1");
        let mut count_query = String::from("SELECT COUNT(*) FROM security_findings WHERE 1=1");

        // Add conditions based on filter
        if filter.asset_ids.is_some() {
            params_count += 1;
            let cond = format!(" AND asset_id = ANY(${})", params_count);
            query.push_str(&cond);
            count_query.push_str(&cond);
        }

        if filter.severities.is_some() {
            params_count += 1;
            let cond = format!(" AND severity = ANY(${})", params_count);
            query.push_str(&cond);
            count_query.push_str(&cond);
        }

        if filter.statuses.is_some() {
            params_count += 1;
            let cond = format!(" AND status = ANY(${})", params_count);
            query.push_str(&cond);
            count_query.push_str(&cond);
        }

        // Add ordering
        let order = format!(
            " ORDER BY {} {} LIMIT {} OFFSET {}",
            filter.sort_by, filter.sort_direction, filter.limit, filter.offset
        );
        query.push_str(&order);

        // For simplicity, use a simpler approach
        let rows = sqlx::query_as::<_, SecurityFinding>(
            r#"
            SELECT * FROM security_findings 
            WHERE ($1::uuid[] IS NULL OR asset_id = ANY($1))
              AND ($2::text[] IS NULL OR severity = ANY($2))
              AND ($3::text[] IS NULL OR status = ANY($3))
            ORDER BY first_seen_at DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(filter.asset_ids.as_ref().map(|v| v.as_slice()))
        .bind(filter.severities.as_ref().map(|v| v.as_slice()))
        .bind(filter.statuses.as_ref().map(|v| v.as_slice()))
        .bind(filter.limit)
        .bind(filter.offset)
        .fetch_all(&self.pool)
        .await?;

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM security_findings 
            WHERE ($1::uuid[] IS NULL OR asset_id = ANY($1))
              AND ($2::text[] IS NULL OR severity = ANY($2))
              AND ($3::text[] IS NULL OR status = ANY($3))
            "#,
        )
        .bind(filter.asset_ids.as_ref().map(|v| v.as_slice()))
        .bind(filter.severities.as_ref().map(|v| v.as_slice()))
        .bind(filter.statuses.as_ref().map(|v| v.as_slice()))
        .fetch_one(&self.pool)
        .await?;

        Ok((rows, total))
    }

    async fn update(
        &self,
        id: &Uuid,
        update: &SecurityFindingUpdate,
        _updated_by: Option<Uuid>,
    ) -> Result<SecurityFinding, ApiError> {
        let now = Utc::now();
        let status = update.status.as_ref().map(|s| s.to_string());

        let row = sqlx::query_as::<_, SecurityFinding>(
            r#"
            UPDATE security_findings 
            SET status = COALESCE($2, status),
                description = COALESCE($3, description),
                remediation = COALESCE($4, remediation),
                tags = COALESCE($5, tags),
                updated_at = $6
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&status)
        .bind(&update.description)
        .bind(&update.remediation)
        .bind(update.tags.as_ref().map(|v| v.as_slice()))
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn resolve(&self, id: &Uuid, resolved_by: Uuid) -> Result<SecurityFinding, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, SecurityFinding>(
            r#"
            UPDATE security_findings 
            SET status = 'resolved', resolved_at = $2, resolved_by = $3, updated_at = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(resolved_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn count_by_severity(&self) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT severity, COUNT(*) FROM security_findings WHERE status != 'resolved' GROUP BY severity"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    async fn count_by_status(&self) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT status, COUNT(*) FROM security_findings GROUP BY status",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    async fn count_by_asset(&self, asset_id: &Uuid) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM security_findings WHERE asset_id = $1",
        )
        .bind(asset_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }
}

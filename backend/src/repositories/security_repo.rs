use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{
        SecurityFinding, SecurityFindingCreate, SecurityFindingFilter, SecurityFindingUpdate,
        SecurityScan, SecurityScanCreate, SecurityScanStatus,
    },
};

// ============================================================================
// Security Scan Repository
// ============================================================================

/// Every finding read path selects through this, so a finding always arrives
/// with the asset it belongs to. Without it a findings table has to resolve
/// each distinct `asset_id` separately just to print a hostname.
const FINDING_SELECT: &str = r#"
            SELECT f.*, a.identifier AS asset_value, a.asset_type::text AS asset_type
            FROM security_findings f
            JOIN assets a ON a.id = f.asset_id
        "#;

/// `severity` is a VARCHAR, so `ORDER BY severity` sorts alphabetically and puts
/// `info` above `medium` and `low`. Order by rank instead.
const SEVERITY_RANK_ORDER: &str =
    "CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END";

#[async_trait]
pub trait SecurityScanRepository: Send + Sync {
    async fn create(
        &self,
        scan: &SecurityScanCreate,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError>;
    async fn get_by_id(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityScan>, ApiError>;

    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError>;
    async fn list_pending(
        &self,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError>;
    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError>;
    /// Scan list with optional status/type filters, each row carrying its asset
    /// and finding count, plus the total for pagination.
    async fn list_filtered(
        &self,
        limit: i64,
        offset: i64,
        asset_id: Option<Uuid>,
        statuses: Option<Vec<String>>,
        scan_types: Option<Vec<String>>,
        company_id: Uuid,
    ) -> Result<(Vec<SecurityScan>, i64), ApiError>;
    async fn update_status(
        &self,
        id: &Uuid,
        status: SecurityScanStatus,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError>;
    async fn start(&self, id: &Uuid, company_id: Uuid) -> Result<SecurityScan, ApiError>;
    async fn complete(
        &self,
        id: &Uuid,
        result_summary: &Value,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError>;
    async fn fail(
        &self,
        id: &Uuid,
        error: &str,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError>;
    async fn get_latest_for_asset(
        &self,
        asset_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityScan>, ApiError>;
    async fn count_by_status(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError>;
    /// Cancel every scan a discovery run queued that has not finished, and
    /// return their ids so the caller can stop the tasks still executing them.
    ///
    /// Done in one statement: a stopped run can have hundreds of auto-scans
    /// outstanding, and reading then updating them one by one would let scans
    /// created between the two steps slip through.
    async fn cancel_active_by_discovery_run(
        &self,
        discovery_run_id: &Uuid,
        company_id: Uuid,
        note: &str,
    ) -> Result<Vec<Uuid>, ApiError>;
    /// Cancel every unfinished scan targeting one of `asset_ids`, returning the
    /// cancelled ids. Used when an asset is blacklisted while it is being
    /// scanned.
    async fn cancel_active_for_assets(
        &self,
        asset_ids: &[Uuid],
        company_id: Uuid,
        note: &str,
    ) -> Result<Vec<Uuid>, ApiError>;
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
    async fn create(
        &self,
        scan: &SecurityScanCreate,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError> {
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
                (id, asset_id, scan_type, status, trigger_type, priority, note, config, result_summary, created_at, updated_at, company_id, discovery_run_id)
            VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7, '{}', $8, $8, $9, $10)
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
        .bind(company_id)
        .bind(scan.discovery_run_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_id(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityScan>, ApiError> {
        let row = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE id = $1 AND company_id = $2",
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE asset_id = $1 AND company_id = $2 ORDER BY created_at DESC LIMIT $3",
        )
        .bind(asset_id)
        .bind(company_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_pending(
        &self,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE status = 'pending' AND company_id = $2 ORDER BY priority DESC, created_at ASC LIMIT $1"
        )
        .bind(limit)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE company_id = $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_filtered(
        &self,
        limit: i64,
        offset: i64,
        asset_id: Option<Uuid>,
        statuses: Option<Vec<String>>,
        scan_types: Option<Vec<String>>,
        company_id: Uuid,
    ) -> Result<(Vec<SecurityScan>, i64), ApiError> {
        // `result_summary` is returned in full. It is heavy — TLS chains,
        // detected services, DNS records — and a queue table shows none of it,
        // but the asset detail's technology/port panel and activity timeline
        // both read it off this list. Narrowing it here silently emptied them.
        // Slimming this is worth doing behind an explicit `fields` parameter,
        // not by guessing what callers need.
        let predicates = r#"
            WHERE s.company_id = $1
              AND ($2::uuid IS NULL OR s.asset_id = $2)
              AND ($3::text[] IS NULL OR s.status = ANY($3))
              AND ($4::text[] IS NULL OR s.scan_type = ANY($4))
        "#;

        let query_sql = format!(
            r#"
            SELECT
                s.id, s.asset_id, s.scan_type, s.status, s.trigger_type, s.priority,
                s.started_at, s.completed_at, s.note, s.config, s.company_id,
                s.created_at, s.updated_at, s.discovery_run_id,
                s.result_summary,
                a.identifier AS asset_value,
                a.asset_type::text AS asset_type,
                (
                    SELECT COUNT(*) FROM security_findings f
                    WHERE f.security_scan_id = s.id AND f.company_id = s.company_id
                ) AS findings_count
            FROM security_scans s
            JOIN assets a ON a.id = s.asset_id
            {predicates}
            ORDER BY s.created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            predicates = predicates,
        );

        let rows = sqlx::query_as::<_, SecurityScan>(&query_sql)
            .bind(company_id)
            .bind(asset_id)
            .bind(statuses.as_ref().map(|v| v.as_slice()))
            .bind(scan_types.as_ref().map(|v| v.as_slice()))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

        let count_sql = format!(
            "SELECT COUNT(*) FROM security_scans s JOIN assets a ON a.id = s.asset_id{predicates}",
            predicates = predicates,
        );

        let total = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(company_id)
            .bind(asset_id)
            .bind(statuses.as_ref().map(|v| v.as_slice()))
            .bind(scan_types.as_ref().map(|v| v.as_slice()))
            .fetch_one(&self.pool)
            .await?;

        Ok((rows, total))
    }

    async fn update_status(
        &self,
        id: &Uuid,
        status: SecurityScanStatus,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();
        let status_str = status.to_string();

        let row = sqlx::query_as::<_, SecurityScan>(
            "UPDATE security_scans SET status = $2, updated_at = $3 WHERE id = $1 AND company_id = $4 RETURNING *",
        )
        .bind(id)
        .bind(&status_str)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn start(&self, id: &Uuid, company_id: Uuid) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, SecurityScan>(
            "UPDATE security_scans SET status = 'running', started_at = $2, updated_at = $2 WHERE id = $1 AND company_id = $3 RETURNING *"
        )
        .bind(id)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn complete(
        &self,
        id: &Uuid,
        result_summary: &Value,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, SecurityScan>(
            r#"
            UPDATE security_scans 
            SET status = 'completed', completed_at = $2, result_summary = $3, updated_at = $2 
            WHERE id = $1 AND company_id = $4
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(result_summary)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn fail(
        &self,
        id: &Uuid,
        error: &str,
        company_id: Uuid,
    ) -> Result<SecurityScan, ApiError> {
        let now = Utc::now();
        let result_summary = json!({ "error": error });

        let row = sqlx::query_as::<_, SecurityScan>(
            r#"
            UPDATE security_scans 
            SET status = 'failed', completed_at = $2, result_summary = $3, updated_at = $2 
            WHERE id = $1 AND company_id = $4
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(&result_summary)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_latest_for_asset(
        &self,
        asset_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityScan>, ApiError> {
        let row = sqlx::query_as::<_, SecurityScan>(
            "SELECT * FROM security_scans WHERE asset_id = $1 AND company_id = $2 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(asset_id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn count_by_status(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT status, COUNT(*) FROM security_scans WHERE company_id = $1 GROUP BY status",
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    async fn cancel_active_by_discovery_run(
        &self,
        discovery_run_id: &Uuid,
        company_id: Uuid,
        note: &str,
    ) -> Result<Vec<Uuid>, ApiError> {
        let now = Utc::now();

        let ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE security_scans
            SET status = 'cancelled',
                completed_at = $1,
                updated_at = $1,
                note = COALESCE(note || ' | ', '') || $4
            WHERE discovery_run_id = $2
              AND company_id = $3
              AND status IN ('pending', 'running')
            RETURNING id
            "#,
        )
        .bind(now)
        .bind(discovery_run_id)
        .bind(company_id)
        .bind(note)
        .fetch_all(&self.pool)
        .await?;

        Ok(ids)
    }

    async fn cancel_active_for_assets(
        &self,
        asset_ids: &[Uuid],
        company_id: Uuid,
        note: &str,
    ) -> Result<Vec<Uuid>, ApiError> {
        if asset_ids.is_empty() {
            return Ok(Vec::new());
        }

        let now = Utc::now();

        let ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE security_scans
            SET status = 'cancelled',
                completed_at = $1,
                updated_at = $1,
                note = COALESCE(note || ' | ', '') || $4
            WHERE asset_id = ANY($2::uuid[])
              AND company_id = $3
              AND status IN ('pending', 'running')
            RETURNING id
            "#,
        )
        .bind(now)
        .bind(asset_ids)
        .bind(company_id)
        .bind(note)
        .fetch_all(&self.pool)
        .await?;

        Ok(ids)
    }
}

// ============================================================================
// Security Finding Repository
// ============================================================================

#[async_trait]
pub trait SecurityFindingRepository: Send + Sync {
    async fn create(
        &self,
        finding: &SecurityFindingCreate,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError>;
    async fn create_or_update(
        &self,
        finding: &SecurityFindingCreate,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError>;
    async fn get_by_id(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityFinding>, ApiError>;
    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityFinding>, ApiError>;
    async fn list_by_scan(
        &self,
        scan_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<SecurityFinding>, ApiError>;
    async fn list_filtered(
        &self,
        filter: &SecurityFindingFilter,
        company_id: Uuid,
    ) -> Result<(Vec<SecurityFinding>, i64), ApiError>;

    async fn update(
        &self,
        id: &Uuid,
        update: &SecurityFindingUpdate,
        updated_by: Option<Uuid>,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError>;
    async fn resolve(
        &self,
        id: &Uuid,
        resolved_by: Uuid,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError>;
    async fn resolve_by_ids(&self, ids: &[Uuid], company_id: Uuid) -> Result<u64, ApiError>;
    async fn count_by_severity(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError>;
    async fn count_by_status(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError>;
    async fn count_by_asset(&self, asset_id: &Uuid, company_id: Uuid) -> Result<i64, ApiError>;
    async fn count_active(&self, company_id: Uuid) -> Result<i64, ApiError>;
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
    async fn create(
        &self,
        finding: &SecurityFindingCreate,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let severity = finding.severity.to_string();

        let row = sqlx::query_as::<_, SecurityFinding>(
            r#"
            INSERT INTO security_findings 
                (id, security_scan_id, asset_id, finding_type, severity, title, description, remediation, data, status, first_seen_at, last_seen_at, cvss_score, cve_ids, tags, created_at, updated_at, company_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open', $10, $10, $11, $12, $13, $10, $10, $14)
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
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn create_or_update(
        &self,
        finding: &SecurityFindingCreate,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError> {
        let now = Utc::now();
        let severity = finding.severity.to_string();

        // Try to find existing finding of same type AND title for same asset
        // Including title in the match ensures different CVEs create separate findings
        let existing = sqlx::query_as::<_, SecurityFinding>(
            r#"
            SELECT * FROM security_findings 
            WHERE asset_id = $1 AND finding_type = $2 AND title = $3 AND company_id = $4 AND status NOT IN ('resolved', 'false_positive')
            ORDER BY first_seen_at DESC LIMIT 1
            "#
        )
        .bind(finding.asset_id)
        .bind(&finding.finding_type)
        .bind(&finding.title)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(existing) = existing {
            // Update existing finding - also update cvss_score, cve_ids, severity, and data
            let row = sqlx::query_as::<_, SecurityFinding>(
                r#"
                UPDATE security_findings 
                SET last_seen_at = $2, 
                    security_scan_id = COALESCE($3, security_scan_id), 
                    data = $4, 
                    severity = $5,
                    cvss_score = COALESCE($6, cvss_score),
                    cve_ids = COALESCE($7, cve_ids),
                    updated_at = $2
                WHERE id = $1 AND company_id = $8
                RETURNING *
                "#,
            )
            .bind(existing.id)
            .bind(now)
            .bind(finding.security_scan_id)
            .bind(&finding.data)
            .bind(&severity)
            .bind(finding.cvss_score)
            .bind(&finding.cve_ids)
            .bind(company_id)
            .fetch_one(&self.pool)
            .await?;

            Ok(row)
        } else {
            // Create new finding
            self.create(finding, company_id).await
        }
    }

    async fn get_by_id(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityFinding>, ApiError> {
        let row = sqlx::query_as::<_, SecurityFinding>(
            "SELECT * FROM security_findings WHERE id = $1 AND company_id = $2",
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list_by_asset(
        &self,
        asset_id: &Uuid,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityFinding>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityFinding>(&format!(
            "{FINDING_SELECT} WHERE f.asset_id = $1 AND f.company_id = $2 ORDER BY f.first_seen_at DESC LIMIT $3"
        ))
        .bind(asset_id)
        .bind(company_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_by_scan(
        &self,
        scan_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<SecurityFinding>, ApiError> {
        let rows = sqlx::query_as::<_, SecurityFinding>(&format!(
            "{FINDING_SELECT} WHERE f.security_scan_id = $1 AND f.company_id = $2 \
             ORDER BY {SEVERITY_RANK_ORDER} DESC, f.first_seen_at DESC"
        ))
        .bind(scan_id)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_filtered(
        &self,
        filter: &SecurityFindingFilter,
        company_id: Uuid,
    ) -> Result<(Vec<SecurityFinding>, i64), ApiError> {
        // Every field on SecurityFindingFilter is honoured here. Seven of them
        // used to be accepted and silently dropped — most visibly `scan_ids`,
        // so `?scan_id=X` returned every finding in the company with a 200.
        let sort_expression = match filter.sort_by.as_str() {
            "severity" => SEVERITY_RANK_ORDER,
            "cvss_score" => "f.cvss_score",
            "last_seen_at" => "f.last_seen_at",
            "status" => "f.status",
            // Anything unrecognised falls back rather than being interpolated.
            _ => "f.first_seen_at",
        };
        let direction = if filter.sort_direction.eq_ignore_ascii_case("asc") {
            "ASC"
        } else {
            "DESC"
        };

        let predicates = r#"
            WHERE f.company_id = $10
              AND ($1::uuid[] IS NULL OR f.asset_id = ANY($1))
              AND ($2::text[] IS NULL OR f.severity = ANY($2))
              AND ($3::text[] IS NULL OR f.status = ANY($3))
              AND ($4::uuid[] IS NULL OR f.security_scan_id = ANY($4))
              AND ($5::text[] IS NULL OR f.finding_type = ANY($5))
              AND ($6::text IS NULL OR f.title ILIKE $6 OR f.description ILIKE $6 OR f.finding_type ILIKE $6)
              AND ($7::timestamptz IS NULL OR f.first_seen_at >= $7)
              AND ($8::timestamptz IS NULL OR f.first_seen_at <= $8)
              AND ($9::text[] IS NULL OR a.asset_type::text = ANY($9))
        "#;

        let search_pattern = filter
            .search_text
            .as_ref()
            .map(|text| format!("%{}%", text.replace('%', "\\%").replace('_', "\\_")));

        let query_sql = format!(
            "{select}{predicates} ORDER BY {sort} {direction} NULLS LAST, f.first_seen_at DESC LIMIT $11 OFFSET $12",
            select = FINDING_SELECT,
            predicates = predicates,
            sort = sort_expression,
            direction = direction,
        );

        let rows = sqlx::query_as::<_, SecurityFinding>(&query_sql)
            .bind(filter.asset_ids.as_ref().map(|v| v.as_slice()))
            .bind(filter.severities.as_ref().map(|v| v.as_slice()))
            .bind(filter.statuses.as_ref().map(|v| v.as_slice()))
            .bind(filter.scan_ids.as_ref().map(|v| v.as_slice()))
            .bind(filter.finding_types.as_ref().map(|v| v.as_slice()))
            .bind(search_pattern.as_deref())
            .bind(filter.created_after)
            .bind(filter.created_before)
            .bind(filter.asset_types.as_ref().map(|v| v.as_slice()))
            .bind(company_id)
            .bind(filter.limit)
            .bind(filter.offset)
            .fetch_all(&self.pool)
            .await?;

        let count_sql = format!(
            "SELECT COUNT(*) FROM security_findings f JOIN assets a ON a.id = f.asset_id{predicates}",
            predicates = predicates,
        );

        let total = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(filter.asset_ids.as_ref().map(|v| v.as_slice()))
            .bind(filter.severities.as_ref().map(|v| v.as_slice()))
            .bind(filter.statuses.as_ref().map(|v| v.as_slice()))
            .bind(filter.scan_ids.as_ref().map(|v| v.as_slice()))
            .bind(filter.finding_types.as_ref().map(|v| v.as_slice()))
            .bind(search_pattern.as_deref())
            .bind(filter.created_after)
            .bind(filter.created_before)
            .bind(filter.asset_types.as_ref().map(|v| v.as_slice()))
            .bind(company_id)
            .fetch_one(&self.pool)
            .await?;

        Ok((rows, total))
    }

    async fn update(
        &self,
        id: &Uuid,
        update: &SecurityFindingUpdate,
        updated_by: Option<Uuid>,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError> {
        let now = Utc::now();
        let status = update.status.as_ref().map(|s| s.to_string());

        // Resolution bookkeeping belongs to whichever path sets the status.
        // It used to live only in `resolve()`, so a finding resolved through
        // this method — which is what the bulk endpoint calls — ended up
        // `status = 'resolved'` with a NULL `resolved_at`, and reopening one
        // left a stale resolution date behind.
        let row = sqlx::query_as::<_, SecurityFinding>(
            r#"
            UPDATE security_findings 
            SET status = COALESCE($2, status),
                description = COALESCE($3, description),
                remediation = COALESCE($4, remediation),
                tags = COALESCE($5, tags),
                updated_at = $6,
                resolved_at = CASE
                    WHEN $2 IS NULL THEN resolved_at
                    WHEN $2 IN ('resolved', 'false_positive') THEN COALESCE(resolved_at, $6)
                    ELSE NULL
                END,
                resolved_by = CASE
                    WHEN $2 IS NULL THEN resolved_by
                    WHEN $2 IN ('resolved', 'false_positive') THEN COALESCE(resolved_by, $8)
                    ELSE NULL
                END
            WHERE id = $1 AND company_id = $7
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&status)
        .bind(&update.description)
        .bind(&update.remediation)
        .bind(update.tags.as_ref().map(|v| v.as_slice()))
        .bind(now)
        .bind(company_id)
        .bind(updated_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn resolve(
        &self,
        id: &Uuid,
        resolved_by: Uuid,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, SecurityFinding>(
            r#"
            UPDATE security_findings 
            SET status = 'resolved', resolved_at = $2, resolved_by = $3, updated_at = $2
            WHERE id = $1 AND company_id = $4
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(resolved_by)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn resolve_by_ids(&self, ids: &[Uuid], company_id: Uuid) -> Result<u64, ApiError> {
        if ids.is_empty() {
            return Ok(0);
        }

        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE security_findings
            SET status = 'resolved',
                resolved_at = $2,
                updated_at = $2
            WHERE id = ANY($1) AND company_id = $3
            "#,
        )
        .bind(ids)
        .bind(now)
        .bind(company_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn count_by_severity(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT severity, COUNT(*) FROM security_findings \
             WHERE status IN ('open', 'acknowledged', 'in_progress') AND company_id = $1 GROUP BY severity"
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    async fn count_by_status(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT status, COUNT(*) FROM security_findings WHERE company_id = $1 GROUP BY status",
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    async fn count_by_asset(&self, asset_id: &Uuid, company_id: Uuid) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM security_findings WHERE asset_id = $1 AND company_id = $2",
        )
        .bind(asset_id)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    async fn count_active(&self, company_id: Uuid) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM security_findings \
             WHERE status IN ('open', 'acknowledged', 'in_progress') AND company_id = $1",
        )
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }
}

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{error::ApiError, models::DiscoverySchedule};

#[async_trait]
pub trait DiscoveryScheduleRepository: Send + Sync {
    async fn create(
        &self,
        company_id: Uuid,
        name: &str,
        cron: &str,
        enabled: bool,
        config: &Value,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<DiscoverySchedule, ApiError>;
    async fn get_by_id(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<DiscoverySchedule>, ApiError>;
    async fn list(&self, company_id: Uuid) -> Result<Vec<DiscoverySchedule>, ApiError>;
    async fn list_due(&self, now: DateTime<Utc>) -> Result<Vec<DiscoverySchedule>, ApiError>;
    async fn update(
        &self,
        company_id: Uuid,
        id: &Uuid,
        name: &str,
        cron: &str,
        enabled: bool,
        config: &Value,
        last_run_at: Option<DateTime<Utc>>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<DiscoverySchedule, ApiError>;
    async fn update_run_times(
        &self,
        company_id: Uuid,
        id: &Uuid,
        last_run_at: Option<DateTime<Utc>>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<DiscoverySchedule, ApiError>;
    async fn delete(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError>;
}

pub struct SqlxDiscoveryScheduleRepository {
    pool: PgPool,
}

impl SqlxDiscoveryScheduleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DiscoveryScheduleRepository for SqlxDiscoveryScheduleRepository {
    async fn create(
        &self,
        company_id: Uuid,
        name: &str,
        cron: &str,
        enabled: bool,
        config: &Value,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<DiscoverySchedule, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoverySchedule>(
            r#"
            INSERT INTO discovery_schedules
                (id, company_id, name, cron, enabled, config, last_run_at, next_run_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $8)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(company_id)
        .bind(name)
        .bind(cron)
        .bind(enabled)
        .bind(config)
        .bind(next_run_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_id(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<DiscoverySchedule>, ApiError> {
        let row = sqlx::query_as::<_, DiscoverySchedule>(
            "SELECT * FROM discovery_schedules WHERE id = $1 AND company_id = $2",
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list(&self, company_id: Uuid) -> Result<Vec<DiscoverySchedule>, ApiError> {
        let rows = sqlx::query_as::<_, DiscoverySchedule>(
            "SELECT * FROM discovery_schedules WHERE company_id = $1 ORDER BY created_at DESC",
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_due(&self, now: DateTime<Utc>) -> Result<Vec<DiscoverySchedule>, ApiError> {
        let rows = sqlx::query_as::<_, DiscoverySchedule>(
            r#"
            SELECT * FROM discovery_schedules
            WHERE enabled = true AND (next_run_at IS NULL OR next_run_at <= $1)
            ORDER BY next_run_at ASC NULLS FIRST
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn update(
        &self,
        company_id: Uuid,
        id: &Uuid,
        name: &str,
        cron: &str,
        enabled: bool,
        config: &Value,
        last_run_at: Option<DateTime<Utc>>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<DiscoverySchedule, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoverySchedule>(
            r#"
            UPDATE discovery_schedules
            SET name = $3,
                cron = $4,
                enabled = $5,
                config = $6,
                last_run_at = $7,
                next_run_at = $8,
                updated_at = $9
            WHERE id = $1 AND company_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(company_id)
        .bind(name)
        .bind(cron)
        .bind(enabled)
        .bind(config)
        .bind(last_run_at)
        .bind(next_run_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_run_times(
        &self,
        company_id: Uuid,
        id: &Uuid,
        last_run_at: Option<DateTime<Utc>>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<DiscoverySchedule, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoverySchedule>(
            r#"
            UPDATE discovery_schedules
            SET last_run_at = $3,
                next_run_at = $4,
                updated_at = $5
            WHERE id = $1 AND company_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(company_id)
        .bind(last_run_at)
        .bind(next_run_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn delete(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM discovery_schedules WHERE id = $1 AND company_id = $2")
            .bind(id)
            .bind(company_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

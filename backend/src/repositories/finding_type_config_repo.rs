use crate::database::DatabasePool;
use crate::error::ApiError;
use crate::models::finding_type_config::{FindingTypeConfig, FindingTypeConfigUpdate, TypeWeight};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;

#[async_trait]
pub trait FindingTypeConfigRepository: Send + Sync {
    async fn list(&self) -> Result<Vec<FindingTypeConfig>, ApiError>;
    async fn get_by_finding_type(
        &self,
        finding_type: &str,
    ) -> Result<Option<FindingTypeConfig>, ApiError>;
    async fn update(
        &self,
        finding_type: &str,
        update: &FindingTypeConfigUpdate,
    ) -> Result<FindingTypeConfig, ApiError>;
    async fn get_type_weights(&self) -> Result<HashMap<String, TypeWeight>, ApiError>;
    async fn get_categories(&self) -> Result<Vec<String>, ApiError>;
    async fn reset_to_defaults(&self) -> Result<i64, ApiError>;
}

pub struct SqlxFindingTypeConfigRepository {
    pool: DatabasePool,
}

impl SqlxFindingTypeConfigRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FindingTypeConfigRepository for SqlxFindingTypeConfigRepository {
    async fn list(&self) -> Result<Vec<FindingTypeConfig>, ApiError> {
        let configs = sqlx::query_as::<_, FindingTypeConfig>(
            r#"
            SELECT id, finding_type, display_name, category,
                   type_multiplier, description, is_enabled,
                   created_at, updated_at
            FROM finding_type_config
            ORDER BY category, display_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(configs)
    }

    async fn get_by_finding_type(
        &self,
        finding_type: &str,
    ) -> Result<Option<FindingTypeConfig>, ApiError> {
        let config = sqlx::query_as::<_, FindingTypeConfig>(
            r#"
            SELECT id, finding_type, display_name, category,
                   type_multiplier, description, is_enabled,
                   created_at, updated_at
            FROM finding_type_config
            WHERE finding_type = $1
            "#,
        )
        .bind(finding_type)
        .fetch_optional(&self.pool)
        .await?;

        Ok(config)
    }

    async fn update(
        &self,
        finding_type: &str,
        update: &FindingTypeConfigUpdate,
    ) -> Result<FindingTypeConfig, ApiError> {
        let now = Utc::now();

        // Build dynamic update query
        let config = sqlx::query_as::<_, FindingTypeConfig>(
            r#"
            UPDATE finding_type_config SET
                display_name = COALESCE($1, display_name),
                type_multiplier = COALESCE($2, type_multiplier),
                description = COALESCE($3, description),
                is_enabled = COALESCE($4, is_enabled),
                updated_at = $5
            WHERE finding_type = $6
            RETURNING id, finding_type, display_name, category,
                      type_multiplier, description, is_enabled,
                      created_at, updated_at
            "#,
        )
        .bind(&update.display_name)
        .bind(update.type_multiplier)
        .bind(&update.description)
        .bind(update.is_enabled)
        .bind(now)
        .bind(finding_type)
        .fetch_one(&self.pool)
        .await?;

        Ok(config)
    }

    /// Every configured type's weight, for risk calculation.
    ///
    /// Disabled rows are returned rather than filtered out in SQL: the scorer treats
    /// an absent type as "no configuration, score it at face value", so dropping
    /// disabled rows here would score them at full weight instead of silencing them.
    async fn get_type_weights(&self) -> Result<HashMap<String, TypeWeight>, ApiError> {
        let rows = sqlx::query_as::<_, (String, f64, bool)>(
            r#"
            SELECT finding_type, type_multiplier, is_enabled
            FROM finding_type_config
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(finding_type, multiplier, is_enabled)| {
                (
                    finding_type,
                    TypeWeight {
                        multiplier,
                        is_enabled,
                    },
                )
            })
            .collect())
    }

    async fn get_categories(&self) -> Result<Vec<String>, ApiError> {
        let categories = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT category
            FROM finding_type_config
            ORDER BY category
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(categories)
    }

    async fn reset_to_defaults(&self) -> Result<i64, ApiError> {
        // This would re-run the default inserts - for now just return count
        let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM finding_type_config"#)
            .fetch_one(&self.pool)
            .await?;

        Ok(count)
    }
}

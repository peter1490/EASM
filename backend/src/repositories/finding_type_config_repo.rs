use crate::database::DatabasePool;
use crate::error::ApiError;
use crate::models::finding_type_config::{FindingTypeConfig, FindingTypeConfigUpdate};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;

#[async_trait]
pub trait FindingTypeConfigRepository: Send + Sync {
    async fn list(&self) -> Result<Vec<FindingTypeConfig>, ApiError>;
    async fn get_by_finding_type(&self, finding_type: &str) -> Result<Option<FindingTypeConfig>, ApiError>;
    async fn update(&self, finding_type: &str, update: &FindingTypeConfigUpdate) -> Result<FindingTypeConfig, ApiError>;
    async fn get_scoring_map(&self) -> Result<HashMap<String, (f64, f64)>, ApiError>;
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
            SELECT id, finding_type, display_name, category, default_severity, 
                   severity_score, type_multiplier, description, is_enabled,
                   created_at, updated_at
            FROM finding_type_config
            ORDER BY category, display_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(configs)
    }

    async fn get_by_finding_type(&self, finding_type: &str) -> Result<Option<FindingTypeConfig>, ApiError> {
        let config = sqlx::query_as::<_, FindingTypeConfig>(
            r#"
            SELECT id, finding_type, display_name, category, default_severity,
                   severity_score, type_multiplier, description, is_enabled,
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

    async fn update(&self, finding_type: &str, update: &FindingTypeConfigUpdate) -> Result<FindingTypeConfig, ApiError> {
        let now = Utc::now();

        // Build dynamic update query
        let config = sqlx::query_as::<_, FindingTypeConfig>(
            r#"
            UPDATE finding_type_config SET
                display_name = COALESCE($1, display_name),
                default_severity = COALESCE($2, default_severity),
                severity_score = COALESCE($3, severity_score),
                type_multiplier = COALESCE($4, type_multiplier),
                description = COALESCE($5, description),
                is_enabled = COALESCE($6, is_enabled),
                updated_at = $7
            WHERE finding_type = $8
            RETURNING id, finding_type, display_name, category, default_severity,
                      severity_score, type_multiplier, description, is_enabled,
                      created_at, updated_at
            "#,
        )
        .bind(&update.display_name)
        .bind(&update.default_severity)
        .bind(update.severity_score)
        .bind(update.type_multiplier)
        .bind(&update.description)
        .bind(update.is_enabled)
        .bind(now)
        .bind(finding_type)
        .fetch_one(&self.pool)
        .await?;

        Ok(config)
    }

    /// Get a map of finding_type -> (severity_score, type_multiplier) for risk calculation
    async fn get_scoring_map(&self) -> Result<HashMap<String, (f64, f64)>, ApiError> {
        let rows = sqlx::query_as::<_, (String, f64, f64)>(
            r#"
            SELECT finding_type, severity_score, type_multiplier
            FROM finding_type_config
            WHERE is_enabled = true
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let map: HashMap<String, (f64, f64)> = rows
            .into_iter()
            .map(|(ft, score, mult)| (ft, (score, mult)))
            .collect();

        Ok(map)
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
        let count = sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM finding_type_config"#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }
}


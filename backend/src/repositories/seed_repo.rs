use crate::error::ApiError;
use crate::models::asset::{Seed, SeedCreate, SeedType};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[async_trait]
pub trait SeedRepository: Send + Sync {
    async fn create(&self, seed: &SeedCreate, company_id: Uuid) -> Result<Seed, ApiError>;
    async fn list(&self, company_id: Uuid) -> Result<Vec<Seed>, ApiError>;
    async fn list_by_type(
        &self,
        company_id: Uuid,
        seed_type: SeedType,
    ) -> Result<Vec<Seed>, ApiError>;
    async fn delete(&self, company_id: Uuid, id: Uuid) -> Result<(), ApiError>;
    async fn get_by_value(
        &self,
        company_id: Uuid,
        seed_type: SeedType,
        value: &str,
    ) -> Result<Option<Seed>, ApiError>;
}

pub struct SqlxSeedRepository {
    pool: PgPool,
}

impl SqlxSeedRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// Row type for reading from database
#[derive(sqlx::FromRow)]
struct SeedRow {
    id: Uuid,
    seed_type: String,
    value: String,
    note: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    company_id: Uuid,
}

impl From<SeedRow> for Seed {
    fn from(row: SeedRow) -> Self {
        let seed_type = match row.seed_type.as_str() {
            "domain" => SeedType::Domain,
            "asn" => SeedType::Asn,
            "cidr" => SeedType::Cidr,
            "organization" => SeedType::Organization,
            "keyword" => SeedType::Keyword,
            _ => SeedType::Domain, // Default fallback
        };
        Seed {
            id: row.id,
            seed_type,
            value: row.value,
            note: row.note,
            created_at: row.created_at,
            updated_at: row.updated_at,
            company_id: row.company_id,
        }
    }
}

#[async_trait]
impl SeedRepository for SqlxSeedRepository {
    async fn create(&self, seed: &SeedCreate, company_id: Uuid) -> Result<Seed, ApiError> {
        let id = Uuid::new_v4();
        let seed_type_str = seed.seed_type.to_string();

        let row = sqlx::query_as::<_, SeedRow>(
            r#"
            INSERT INTO seeds (id, seed_type, value, note, created_at, updated_at, company_id)
            VALUES ($1, $2::seed_type, $3, $4, NOW(), NOW(), $5)
            RETURNING id, seed_type::text, value, note, created_at, updated_at, company_id
            "#,
        )
        .bind(id)
        .bind(&seed_type_str)
        .bind(&seed.value)
        .bind(&seed.note)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("seeds_company_id_seed_type_value_key") {
                    return ApiError::Validation(format!(
                        "Seed '{}' already exists for this company",
                        seed.value
                    ));
                }
            }
            ApiError::from(e) // Convert sqlx::Error to ApiError::Database
        })?;

        Ok(row.into())
    }

    async fn list(&self, company_id: Uuid) -> Result<Vec<Seed>, ApiError> {
        let rows = sqlx::query_as::<_, SeedRow>(
            r#"
            SELECT id, seed_type::text, value, note, created_at, COALESCE(updated_at, created_at) as updated_at, company_id
            FROM seeds
            WHERE company_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    async fn list_by_type(
        &self,
        company_id: Uuid,
        seed_type: SeedType,
    ) -> Result<Vec<Seed>, ApiError> {
        let rows = sqlx::query_as::<_, SeedRow>(
            r#"
            SELECT id, seed_type::text, value, note, created_at, COALESCE(updated_at, created_at) as updated_at, company_id
            FROM seeds
            WHERE company_id = $1 AND seed_type = $2::seed_type
            ORDER BY created_at DESC
            "#
        )
        .bind(company_id)
        .bind(seed_type.to_string())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    async fn delete(&self, company_id: Uuid, id: Uuid) -> Result<(), ApiError> {
        let result = sqlx::query("DELETE FROM seeds WHERE id = $1 AND company_id = $2")
            .bind(id)
            .bind(company_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!("Seed {} not found", id)));
        }

        Ok(())
    }

    async fn get_by_value(
        &self,
        company_id: Uuid,
        seed_type: SeedType,
        value: &str,
    ) -> Result<Option<Seed>, ApiError> {
        let result = sqlx::query_as::<_, SeedRow>(
            r#"
            SELECT id, seed_type::text, value, note, created_at, COALESCE(updated_at, created_at) as updated_at, company_id
            FROM seeds
            WHERE company_id = $1 AND seed_type = $2::seed_type AND value = $3
            "#
        )
        .bind(company_id)
        .bind(seed_type.to_string())
        .bind(value)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|r| r.into()))
    }
}

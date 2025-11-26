use crate::error::ApiError;
use crate::models::asset::{Seed, SeedCreate, SeedType};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[async_trait]
pub trait SeedRepository: Send + Sync {
    async fn create(&self, seed: &SeedCreate) -> Result<Seed, ApiError>;
    async fn list(&self) -> Result<Vec<Seed>, ApiError>;
    async fn delete(&self, id: Uuid) -> Result<(), ApiError>;
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
        }
    }
}

#[async_trait]
impl SeedRepository for SqlxSeedRepository {
    async fn create(&self, seed: &SeedCreate) -> Result<Seed, ApiError> {
        let id = Uuid::new_v4();
        let seed_type_str = seed.seed_type.to_string();

        let row = sqlx::query_as::<_, SeedRow>(
            r#"
            INSERT INTO seeds (id, seed_type, value, note, created_at, updated_at)
            VALUES ($1, $2::seed_type, $3, $4, NOW(), NOW())
            RETURNING id, seed_type::text, value, note, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&seed_type_str)
        .bind(&seed.value)
        .bind(&seed.note)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("seeds_seed_type_value_key") {
                    return ApiError::Validation(format!("Seed '{}' already exists", seed.value));
                }
            }
            ApiError::from(e) // Convert sqlx::Error to ApiError::Database
        })?;

        Ok(row.into())
    }

    async fn list(&self) -> Result<Vec<Seed>, ApiError> {
        let rows = sqlx::query_as::<_, SeedRow>(
            r#"
            SELECT id, seed_type::text, value, note, created_at, COALESCE(updated_at, created_at) as updated_at
            FROM seeds
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?; // Use ? operator - #[from] will convert sqlx::Error to ApiError::Database

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    async fn delete(&self, id: Uuid) -> Result<(), ApiError> {
        let result = sqlx::query("DELETE FROM seeds WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?; // Use ? operator

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!("Seed {} not found", id)));
        }

        Ok(())
    }
}

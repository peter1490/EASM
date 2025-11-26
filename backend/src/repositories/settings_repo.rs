use crate::error::ApiError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct StoredSettingsRow {
    pub id: Uuid,
    pub encrypted_payload: Vec<u8>,
    pub nonce: Vec<u8>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

pub struct SettingsRepository {
    pool: PgPool,
}

impl SettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_latest(&self) -> Result<Option<StoredSettingsRow>, ApiError> {
        let row = sqlx::query_as!(
            StoredSettingsRow,
            r#"
            SELECT id, encrypted_payload, nonce, updated_at, updated_by
            FROM app_settings
            ORDER BY updated_at DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(ApiError::Database)?;

        Ok(row)
    }

    pub async fn upsert_payload(
        &self,
        encrypted_payload: Vec<u8>,
        nonce: Vec<u8>,
        updated_by: Option<Uuid>,
    ) -> Result<(), ApiError> {
        sqlx::query!(
            r#"
            INSERT INTO app_settings (encrypted_payload, nonce, updated_by, singleton)
            VALUES ($1, $2, $3, TRUE)
            ON CONFLICT (singleton)
            DO UPDATE SET
                encrypted_payload = EXCLUDED.encrypted_payload,
                nonce = EXCLUDED.nonce,
                updated_at = NOW(),
                updated_by = EXCLUDED.updated_by
            "#,
            encrypted_payload,
            nonce,
            updated_by
        )
        .execute(&self.pool)
        .await
        .map_err(ApiError::Database)?;

        Ok(())
    }
}

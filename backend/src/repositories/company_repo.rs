use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{Company, CompanyCreate, CompanyUpdate, CompanyWithRole},
};

#[async_trait]
pub trait CompanyRepository: Send + Sync {
    async fn create(&self, company: &CompanyCreate, owner_user_id: Uuid)
        -> Result<Company, ApiError>;
    async fn get_by_id(&self, id: Uuid) -> Result<Option<Company>, ApiError>;
    async fn list_all(&self) -> Result<Vec<Company>, ApiError>;
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<CompanyWithRole>, ApiError>;
    async fn update(&self, id: Uuid, update: &CompanyUpdate) -> Result<Company, ApiError>;
    async fn add_user_to_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
        role: &str,
    ) -> Result<(), ApiError>;
}

pub struct SqlxCompanyRepository {
    pool: PgPool,
}

impl SqlxCompanyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CompanyRepository for SqlxCompanyRepository {
    async fn create(
        &self,
        company: &CompanyCreate,
        owner_user_id: Uuid,
    ) -> Result<Company, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let mut tx = self.pool.begin().await?;

        let row = sqlx::query_as::<_, Company>(
            r#"
            INSERT INTO companies (id, name, created_at, updated_at)
            VALUES ($1, $2, $3, $3)
            RETURNING id, name, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&company.name)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO user_companies (user_id, company_id, role)
            VALUES ($1, $2, 'admin')
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(owner_user_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(row)
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<Company>, ApiError> {
        let row = sqlx::query_as::<_, Company>(
            "SELECT id, name, created_at, updated_at FROM companies WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list_all(&self) -> Result<Vec<Company>, ApiError> {
        let rows = sqlx::query_as::<_, Company>(
            "SELECT id, name, created_at, updated_at FROM companies ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<CompanyWithRole>, ApiError> {
        let rows = sqlx::query_as::<_, CompanyWithRole>(
            r#"
            SELECT c.id, c.name, uc.role, uc.assigned_at, c.created_at, c.updated_at
            FROM user_companies uc
            JOIN companies c ON c.id = uc.company_id
            WHERE uc.user_id = $1
            ORDER BY c.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn update(&self, id: Uuid, update: &CompanyUpdate) -> Result<Company, ApiError> {
        let row = sqlx::query_as::<_, Company>(
            r#"
            UPDATE companies
            SET name = COALESCE($2, name),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn add_user_to_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
        role: &str,
    ) -> Result<(), ApiError> {
        sqlx::query(
            r#"
            INSERT INTO user_companies (user_id, company_id, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, company_id) DO UPDATE SET role = EXCLUDED.role
            "#,
        )
        .bind(user_id)
        .bind(company_id)
        .bind(role)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

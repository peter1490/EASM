use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use std::collections::BTreeMap;

use crate::{
    error::ApiError,
    models::{Company, CompanyCreate, CompanyMember, CompanyUpdate, CompanyWithRole},
};

pub const DEFAULT_COMPANY_ID: Uuid = Uuid::nil();

#[async_trait]
pub trait CompanyRepository: Send + Sync {
    async fn create(
        &self,
        company: &CompanyCreate,
        owner_user_id: Uuid,
    ) -> Result<Company, ApiError>;
    async fn get_by_id(&self, id: Uuid) -> Result<Option<Company>, ApiError>;
    async fn list_all(&self) -> Result<Vec<Company>, ApiError>;
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<CompanyWithRole>, ApiError>;
    async fn update(&self, id: Uuid, update: &CompanyUpdate) -> Result<Company, ApiError>;
    async fn delete(&self, id: Uuid) -> Result<bool, ApiError>;
    async fn clear_data(&self, company_id: Uuid) -> Result<BTreeMap<String, u64>, ApiError>;
    async fn add_user_to_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
        role: &str,
    ) -> Result<(), ApiError>;
    async fn remove_user_from_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
    ) -> Result<bool, ApiError>;
    async fn list_members(&self, company_id: Uuid) -> Result<Vec<CompanyMember>, ApiError>;
    async fn count_admins(&self, company_id: Uuid) -> Result<i64, ApiError>;
    async fn role_of_user_in_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
    ) -> Result<Option<String>, ApiError>;
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

    async fn delete(&self, id: Uuid) -> Result<bool, ApiError> {
        let result = sqlx::query("DELETE FROM companies WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn clear_data(&self, company_id: Uuid) -> Result<BTreeMap<String, u64>, ApiError> {
        // Tables scoped by company_id whose rows we wipe but whose parent company row we preserve.
        // Cascades inside each table (e.g. findings -> evidence) handle deeper cleanup.
        const TABLES: &[&str] = &[
            "security_findings",
            "security_scans",
            "findings",
            "scans",
            "discovery_schedules",
            "discovery_runs",
            "assets",
            "seeds",
            "tags",
            "exclusions",
        ];

        let mut tx = self.pool.begin().await?;
        let mut summary = BTreeMap::new();
        for table in TABLES {
            let sql = format!("DELETE FROM {} WHERE company_id = $1", table);
            let result = sqlx::query(&sql)
                .bind(company_id)
                .execute(&mut *tx)
                .await?;
            summary.insert((*table).to_string(), result.rows_affected());
        }
        tx.commit().await?;
        Ok(summary)
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

    async fn remove_user_from_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
    ) -> Result<bool, ApiError> {
        let result = sqlx::query(
            "DELETE FROM user_companies WHERE user_id = $1 AND company_id = $2",
        )
        .bind(user_id)
        .bind(company_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_members(&self, company_id: Uuid) -> Result<Vec<CompanyMember>, ApiError> {
        let rows = sqlx::query_as::<_, CompanyMember>(
            r#"
            SELECT u.id AS user_id,
                   u.email,
                   u.display_name,
                   uc.role,
                   uc.assigned_at
            FROM user_companies uc
            JOIN users u ON u.id = uc.user_id
            WHERE uc.company_id = $1
            ORDER BY uc.assigned_at ASC
            "#,
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn count_admins(&self, company_id: Uuid) -> Result<i64, ApiError> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_companies WHERE company_id = $1 AND role = 'admin'",
        )
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    async fn role_of_user_in_company(
        &self,
        user_id: Uuid,
        company_id: Uuid,
    ) -> Result<Option<String>, ApiError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM user_companies WHERE user_id = $1 AND company_id = $2",
        )
        .bind(user_id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(r,)| r))
    }
}

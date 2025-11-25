use async_trait::async_trait;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;
use crate::error::ApiError;
use crate::auth::rbac::Role;
use chrono::{DateTime, Utc};

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub password_hash: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct Identity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_id: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub last_login_at: DateTime<Utc>,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, ApiError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, ApiError>;
    async fn create_user(&self, email: &str, password_hash: Option<String>) -> Result<User, ApiError>;
    async fn update_last_login(&self, user_id: Uuid) -> Result<(), ApiError>;
    
    async fn find_identity(&self, provider: &str, provider_id: &str) -> Result<Option<Identity>, ApiError>;
    async fn create_identity(&self, user_id: Uuid, provider: &str, provider_id: &str, email: &str) -> Result<Identity, ApiError>;
    
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<Role>, ApiError>;
    async fn add_user_role(&self, user_id: Uuid, role: Role, assigned_by: Option<Uuid>) -> Result<(), ApiError>;
    async fn remove_user_role(&self, user_id: Uuid, role: Role) -> Result<(), ApiError>;
    
    async fn list_users(&self) -> Result<Vec<User>, ApiError>;
}

pub struct SqlxUserRepository {
    pool: PgPool,
}

impl SqlxUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, ApiError> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, created_at, updated_at, last_login_at, password_hash FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(user)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, ApiError> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, created_at, updated_at, last_login_at, password_hash FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(user)
    }

    async fn create_user(&self, email: &str, password_hash: Option<String>) -> Result<User, ApiError> {
        let user = sqlx::query_as!(
            User,
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at, updated_at, last_login_at, password_hash",
            email,
            password_hash
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(user)
    }

    async fn update_last_login(&self, user_id: Uuid) -> Result<(), ApiError> {
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(())
    }

    async fn find_identity(&self, provider: &str, provider_id: &str) -> Result<Option<Identity>, ApiError> {
        let identity = sqlx::query_as!(
            Identity,
            "SELECT id, user_id, provider, provider_id, email, created_at, last_login_at FROM identities WHERE provider = $1 AND provider_id = $2",
            provider,
            provider_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(identity)
    }

    async fn create_identity(&self, user_id: Uuid, provider: &str, provider_id: &str, email: &str) -> Result<Identity, ApiError> {
        let identity = sqlx::query_as!(
            Identity,
            "INSERT INTO identities (user_id, provider, provider_id, email) VALUES ($1, $2, $3, $4) RETURNING id, user_id, provider, provider_id, email, created_at, last_login_at",
            user_id,
            provider,
            provider_id,
            email
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(identity)
    }

    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<Role>, ApiError> {
        let roles = sqlx::query!(
            "SELECT role FROM user_roles WHERE user_id = $1",
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        let roles = roles
            .into_iter()
            .filter_map(|r| Role::from_str(&r.role))
            .collect();
            
        Ok(roles)
    }

    async fn add_user_role(&self, user_id: Uuid, role: Role, assigned_by: Option<Uuid>) -> Result<(), ApiError> {
        let role_str = role.as_str();
        sqlx::query!(
            "INSERT INTO user_roles (user_id, role, assigned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            user_id,
            role_str,
            assigned_by
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(())
    }

    async fn remove_user_role(&self, user_id: Uuid, role: Role) -> Result<(), ApiError> {
        let role_str = role.as_str();
        sqlx::query!(
            "DELETE FROM user_roles WHERE user_id = $1 AND role = $2",
            user_id,
            role_str
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>, ApiError> {
        let users = sqlx::query_as!(
            User,
            "SELECT id, email, created_at, updated_at, last_login_at, password_hash FROM users ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ApiError::Database(e))?;
        
        Ok(users)
    }
}

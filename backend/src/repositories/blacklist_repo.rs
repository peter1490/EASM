use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{BlacklistCreate, BlacklistEntry, BlacklistObjectType, BlacklistUpdate},
};

#[async_trait]
pub trait BlacklistRepository: Send + Sync {
    /// Create a new blacklist entry
    async fn create(
        &self,
        entry: &BlacklistCreate,
        created_by: Option<&str>,
    ) -> Result<BlacklistEntry, ApiError>;

    /// Get a blacklist entry by ID
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<BlacklistEntry>, ApiError>;

    /// Get a blacklist entry by type and value
    async fn get_by_type_value(
        &self,
        object_type: &BlacklistObjectType,
        object_value: &str,
    ) -> Result<Option<BlacklistEntry>, ApiError>;

    /// Check if an object is blacklisted (exact match)
    async fn is_blacklisted(
        &self,
        object_type: &BlacklistObjectType,
        object_value: &str,
    ) -> Result<bool, ApiError>;

    /// Check if a domain or any of its parent domains is blacklisted
    /// e.g., if "example.com" is blacklisted, "sub.example.com" would also be considered blacklisted
    async fn is_domain_or_parent_blacklisted(
        &self,
        domain: &str,
    ) -> Result<Option<BlacklistEntry>, ApiError>;

    /// Check if an IP is blacklisted (either exact match or within a blacklisted CIDR)
    async fn is_ip_blacklisted(&self, ip: &str) -> Result<Option<BlacklistEntry>, ApiError>;

    /// List all blacklist entries
    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<BlacklistEntry>, ApiError>;

    /// List blacklist entries by type
    async fn list_by_type(
        &self,
        object_type: &BlacklistObjectType,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<BlacklistEntry>, ApiError>;

    /// Count all blacklist entries
    async fn count(&self) -> Result<i64, ApiError>;

    /// Update a blacklist entry
    async fn update(&self, id: &Uuid, update: &BlacklistUpdate) -> Result<BlacklistEntry, ApiError>;

    /// Delete a blacklist entry
    async fn delete(&self, id: &Uuid) -> Result<(), ApiError>;

    /// Delete all descendant assets that were discovered from a blacklisted object
    /// Returns the count of deleted assets
    async fn delete_descendant_assets(&self, asset_id: &Uuid) -> Result<i64, ApiError>;

    /// Find asset ID by type and identifier
    async fn find_asset_id(
        &self,
        object_type: &BlacklistObjectType,
        object_value: &str,
    ) -> Result<Option<Uuid>, ApiError>;

    /// Search blacklist entries
    async fn search(
        &self,
        query: Option<&str>,
        object_type: Option<&BlacklistObjectType>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<BlacklistEntry>, i64), ApiError>;
}

pub struct SqlxBlacklistRepository {
    pool: PgPool,
}

impl SqlxBlacklistRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BlacklistRepository for SqlxBlacklistRepository {
    async fn create(
        &self,
        entry: &BlacklistCreate,
        created_by: Option<&str>,
    ) -> Result<BlacklistEntry, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let object_type = entry.object_type.to_string();
        let object_value = entry.object_value.trim().to_lowercase();

        let row = sqlx::query_as::<_, BlacklistEntry>(
            r#"
            INSERT INTO blacklist (id, object_type, object_value, reason, created_by, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&object_type)
        .bind(&object_value)
        .bind(&entry.reason)
        .bind(created_by)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<BlacklistEntry>, ApiError> {
        let row = sqlx::query_as::<_, BlacklistEntry>("SELECT * FROM blacklist WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row)
    }

    async fn get_by_type_value(
        &self,
        object_type: &BlacklistObjectType,
        object_value: &str,
    ) -> Result<Option<BlacklistEntry>, ApiError> {
        let type_str = object_type.to_string();
        let value = object_value.trim().to_lowercase();

        let row = sqlx::query_as::<_, BlacklistEntry>(
            "SELECT * FROM blacklist WHERE object_type = $1 AND object_value = $2",
        )
        .bind(&type_str)
        .bind(&value)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn is_blacklisted(
        &self,
        object_type: &BlacklistObjectType,
        object_value: &str,
    ) -> Result<bool, ApiError> {
        let type_str = object_type.to_string();
        let value = object_value.trim().to_lowercase();

        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM blacklist WHERE object_type = $1 AND object_value = $2)",
        )
        .bind(&type_str)
        .bind(&value)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    async fn is_domain_or_parent_blacklisted(
        &self,
        domain: &str,
    ) -> Result<Option<BlacklistEntry>, ApiError> {
        let domain = domain.trim().to_lowercase();

        // Check exact match first
        let exact = sqlx::query_as::<_, BlacklistEntry>(
            "SELECT * FROM blacklist WHERE object_type = 'domain' AND object_value = $1",
        )
        .bind(&domain)
        .fetch_optional(&self.pool)
        .await?;

        if exact.is_some() {
            return Ok(exact);
        }

        // Check parent domains (e.g., if example.com is blacklisted, sub.example.com is too)
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            for i in 1..parts.len() - 1 {
                let parent = parts[i..].join(".");
                let parent_match = sqlx::query_as::<_, BlacklistEntry>(
                    "SELECT * FROM blacklist WHERE object_type = 'domain' AND object_value = $1",
                )
                .bind(&parent)
                .fetch_optional(&self.pool)
                .await?;

                if parent_match.is_some() {
                    return Ok(parent_match);
                }
            }
        }

        Ok(None)
    }

    async fn is_ip_blacklisted(&self, ip: &str) -> Result<Option<BlacklistEntry>, ApiError> {
        let ip = ip.trim();

        // Check exact IP match
        let exact = sqlx::query_as::<_, BlacklistEntry>(
            "SELECT * FROM blacklist WHERE object_type = 'ip' AND object_value = $1",
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;

        if exact.is_some() {
            return Ok(exact);
        }

        // Check CIDR ranges - use PostgreSQL's inet operators
        // This requires the IP to be parseable as inet
        let cidr_match = sqlx::query_as::<_, BlacklistEntry>(
            r#"
            SELECT * FROM blacklist 
            WHERE object_type = 'cidr' 
            AND $1::inet <<= object_value::inet
            LIMIT 1
            "#,
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await;

        // If CIDR check fails (e.g., invalid IP format), just return None
        match cidr_match {
            Ok(entry) => Ok(entry),
            Err(_) => Ok(None),
        }
    }

    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<BlacklistEntry>, ApiError> {
        let rows = sqlx::query_as::<_, BlacklistEntry>(
            "SELECT * FROM blacklist ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_by_type(
        &self,
        object_type: &BlacklistObjectType,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<BlacklistEntry>, ApiError> {
        let type_str = object_type.to_string();

        let rows = sqlx::query_as::<_, BlacklistEntry>(
            "SELECT * FROM blacklist WHERE object_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(&type_str)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn count(&self) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM blacklist")
            .fetch_one(&self.pool)
            .await?;

        Ok(count)
    }

    async fn update(&self, id: &Uuid, update: &BlacklistUpdate) -> Result<BlacklistEntry, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, BlacklistEntry>(
            r#"
            UPDATE blacklist 
            SET reason = COALESCE($2, reason), updated_at = $3
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.reason)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn delete(&self, id: &Uuid) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM blacklist WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_descendant_assets(&self, asset_id: &Uuid) -> Result<i64, ApiError> {
        // Use a recursive CTE to find all descendants and delete them
        // This preserves the root asset but deletes all children
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            WITH RECURSIVE descendants AS (
                -- Start with direct children of the blacklisted asset
                SELECT id, parent_id, 1 as depth
                FROM assets
                WHERE parent_id = $1
                
                UNION ALL
                
                -- Recursively get children of children
                SELECT a.id, a.parent_id, d.depth + 1
                FROM assets a
                INNER JOIN descendants d ON a.parent_id = d.id
                WHERE d.depth < 100  -- Prevent infinite loops
            ),
            deleted AS (
                DELETE FROM assets
                WHERE id IN (SELECT id FROM descendants)
                RETURNING id
            )
            SELECT COUNT(*) FROM deleted
            "#,
        )
        .bind(asset_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn find_asset_id(
        &self,
        object_type: &BlacklistObjectType,
        object_value: &str,
    ) -> Result<Option<Uuid>, ApiError> {
        let type_str = object_type.to_string();
        let value = object_value.trim().to_lowercase();

        let id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM assets WHERE asset_type::text = $1 AND LOWER(identifier) = $2",
        )
        .bind(&type_str)
        .bind(&value)
        .fetch_optional(&self.pool)
        .await?;

        Ok(id)
    }

    async fn search(
        &self,
        query: Option<&str>,
        object_type: Option<&BlacklistObjectType>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<BlacklistEntry>, i64), ApiError> {
        let search_pattern = query.map(|q| format!("%{}%", q.to_lowercase()));
        let type_str = object_type.map(|t| t.to_string());

        let rows = sqlx::query_as::<_, BlacklistEntry>(
            r#"
            SELECT * FROM blacklist 
            WHERE ($1::text IS NULL OR object_value ILIKE $1 OR reason ILIKE $1)
            AND ($2::text IS NULL OR object_type = $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(&search_pattern)
        .bind(&type_str)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM blacklist 
            WHERE ($1::text IS NULL OR object_value ILIKE $1 OR reason ILIKE $1)
            AND ($2::text IS NULL OR object_type = $2)
            "#,
        )
        .bind(&search_pattern)
        .bind(&type_str)
        .fetch_one(&self.pool)
        .await?;

        Ok((rows, total))
    }
}


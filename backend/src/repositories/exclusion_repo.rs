use async_trait::async_trait;
use chrono::Utc;
use ipnet::IpNet;
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{ExclusionCreate, ExclusionEntry, ExclusionObjectType, ExclusionUpdate},
};

#[async_trait]
pub trait ExclusionRepository: Send + Sync {
    /// Create a new exclusion entry
    async fn create(
        &self,
        entry: &ExclusionCreate,
        created_by: Option<&str>,
        company_id: Uuid,
    ) -> Result<ExclusionEntry, ApiError>;

    /// Get an exclusion entry by ID
    async fn get_by_id(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError>;

    /// Get an exclusion entry by type and value
    async fn get_by_type_value(
        &self,
        object_type: &ExclusionObjectType,
        object_value: &str,
        company_id: Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError>;

    /// Check if an object is excluded (exact match)
    async fn is_excluded(
        &self,
        object_type: &ExclusionObjectType,
        object_value: &str,
        company_id: Uuid,
    ) -> Result<bool, ApiError>;

    /// Check if a domain or any of its parent domains is excluded
    /// e.g., if "example.com" is excluded, "sub.example.com" would also be considered excluded
    async fn is_domain_or_parent_excluded(
        &self,
        domain: &str,
        company_id: Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError>;

    /// Check if an IP is excluded (either exact match or within an excluded CIDR)
    async fn is_ip_excluded(
        &self,
        ip: &str,
        company_id: Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError>;

    /// List all exclusion entries
    async fn list(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ExclusionEntry>, ApiError>;

    /// Every entry for a company, unpaginated.
    ///
    /// Discovery evaluates the exclusion list against each asset it is about to
    /// write, which is thousands of checks per run. Reading the list once and
    /// matching in memory turns that into one query per refresh.
    async fn list_all(&self, company_id: Uuid) -> Result<Vec<ExclusionEntry>, ApiError>;

    /// List exclusion entries by type
    async fn list_by_type(
        &self,
        object_type: &ExclusionObjectType,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ExclusionEntry>, ApiError>;

    /// Count all exclusion entries
    async fn count(&self, company_id: Uuid) -> Result<i64, ApiError>;

    /// Count the entries that blacklist rather than merely exclude.
    async fn count_blacklisted(&self, company_id: Uuid) -> Result<i64, ApiError>;

    /// Update an exclusion entry
    async fn update(
        &self,
        company_id: Uuid,
        id: &Uuid,
        update: &ExclusionUpdate,
    ) -> Result<ExclusionEntry, ApiError>;

    /// Delete an exclusion entry
    async fn delete(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError>;

    /// Delete all descendant assets that were discovered from an excluded object
    /// Returns the count of deleted assets
    async fn delete_descendant_assets(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
    ) -> Result<i64, ApiError>;

    /// Delete descendants for every IP asset that falls inside the given CIDR.
    /// Returns the count of deleted assets (root IP assets are preserved).
    async fn delete_descendant_assets_for_cidr(
        &self,
        company_id: Uuid,
        cidr: &str,
    ) -> Result<i64, ApiError>;

    /// Delete the assets a blacklist entry names, and everything discovered
    /// through them. Returns the count of deleted assets.
    ///
    /// "Names" is deliberately narrow: the asset carrying the entry's own
    /// value, and for a CIDR every address inside it. A sibling that merely
    /// matches the rule — another subdomain of the blacklisted domain, reached
    /// by some other path and never a descendant of it — is left where it is.
    /// The rule still keeps discovery from writing it again, so it disappears
    /// when it is next matched rather than being deleted out from under an
    /// operator who pointed at one asset.
    ///
    /// Findings, scans, sources and relationships go with the assets: every one
    /// of those tables cascades from `assets.id`. That is what takes a
    /// blacklisted object out of the risk score.
    async fn purge_entry_assets(
        &self,
        company_id: Uuid,
        object_type: &ExclusionObjectType,
        object_value: &str,
    ) -> Result<i64, ApiError>;

    /// Find asset ID by type and identifier
    async fn find_asset_id(
        &self,
        object_type: &ExclusionObjectType,
        object_value: &str,
        company_id: Uuid,
    ) -> Result<Option<Uuid>, ApiError>;

    /// Search exclusion entries
    async fn search(
        &self,
        query: Option<&str>,
        object_type: Option<&ExclusionObjectType>,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ExclusionEntry>, i64), ApiError>;
}

pub struct SqlxExclusionRepository {
    pool: PgPool,
}

impl SqlxExclusionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Every IP asset whose address falls inside `cidr`.
    ///
    /// Candidates are loaded and their identifiers parsed in Rust rather than
    /// compared with `inet` in SQL: one unparseable identifier would fail the
    /// cast for the whole statement, and asset identifiers come from sources
    /// that do not promise well-formed addresses.
    async fn ip_asset_ids_in_cidr(
        &self,
        company_id: Uuid,
        cidr: &str,
    ) -> Result<Vec<Uuid>, ApiError> {
        let cidr = cidr.trim();
        let cidr_net: IpNet = cidr
            .parse()
            .map_err(|e| ApiError::Validation(format!("Invalid CIDR format '{}': {}", cidr, e)))?;

        let ip_assets = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT id, identifier
            FROM assets
            WHERE company_id = $1
              AND asset_type::text = 'ip'
            "#,
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(ip_assets
            .into_iter()
            .filter(|(_, identifier)| {
                identifier
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| cidr_net.contains(&ip))
            })
            .map(|(id, _)| id)
            .collect())
    }
}

#[async_trait]
impl ExclusionRepository for SqlxExclusionRepository {
    async fn create(
        &self,
        entry: &ExclusionCreate,
        created_by: Option<&str>,
        company_id: Uuid,
    ) -> Result<ExclusionEntry, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let object_type = entry.object_type.to_string();
        let object_value = entry.object_value.trim().to_lowercase();

        // Upsert rather than insert: the natural way to blacklist something is
        // to blacklist a thing you already excluded, and a unique violation is
        // a poor answer to "make this one stronger". Only ever a promotion --
        // re-excluding a blacklisted object does not quietly undo the deletion
        // it already caused, and demoting goes through `update`.
        let row = sqlx::query_as::<_, ExclusionEntry>(
            r#"
            INSERT INTO exclusions (id, object_type, object_value, reason, created_by, company_id, blacklisted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
            ON CONFLICT (company_id, object_type, object_value) DO UPDATE
            SET reason = COALESCE(EXCLUDED.reason, exclusions.reason),
                blacklisted = exclusions.blacklisted OR EXCLUDED.blacklisted,
                updated_at = EXCLUDED.updated_at
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&object_type)
        .bind(&object_value)
        .bind(&entry.reason)
        .bind(created_by)
        .bind(company_id)
        .bind(entry.blacklisted)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_id(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError> {
        let row = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE id = $1 AND company_id = $2",
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_type_value(
        &self,
        object_type: &ExclusionObjectType,
        object_value: &str,
        company_id: Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError> {
        let type_str = object_type.to_string();
        let value = object_value.trim().to_lowercase();

        let row = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE object_type = $1 AND object_value = $2 AND company_id = $3",
        )
        .bind(&type_str)
        .bind(&value)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn is_excluded(
        &self,
        object_type: &ExclusionObjectType,
        object_value: &str,
        company_id: Uuid,
    ) -> Result<bool, ApiError> {
        let type_str = object_type.to_string();
        let value = object_value.trim().to_lowercase();

        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM exclusions WHERE object_type = $1 AND object_value = $2 AND company_id = $3)",
        )
        .bind(&type_str)
        .bind(&value)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    async fn is_domain_or_parent_excluded(
        &self,
        domain: &str,
        company_id: Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError> {
        let domain = domain.trim().to_lowercase();

        // Check exact match first
        let exact = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE object_type = 'domain' AND object_value = $1 AND company_id = $2",
        )
        .bind(&domain)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        if exact.is_some() {
            return Ok(exact);
        }

        // Check parent domains (e.g., if example.com is excluded, sub.example.com is too)
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            for i in 1..parts.len() - 1 {
                let parent = parts[i..].join(".");
                let parent_match = sqlx::query_as::<_, ExclusionEntry>(
                    "SELECT * FROM exclusions WHERE object_type = 'domain' AND object_value = $1 AND company_id = $2",
                )
                .bind(&parent)
                .bind(company_id)
                .fetch_optional(&self.pool)
                .await?;

                if parent_match.is_some() {
                    return Ok(parent_match);
                }
            }
        }

        Ok(None)
    }

    async fn is_ip_excluded(
        &self,
        ip: &str,
        company_id: Uuid,
    ) -> Result<Option<ExclusionEntry>, ApiError> {
        let ip = ip.trim();

        // Check exact IP match
        let exact = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE object_type = 'ip' AND object_value = $1 AND company_id = $2",
        )
        .bind(ip)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        if exact.is_some() {
            return Ok(exact);
        }

        // Check CIDR ranges - use PostgreSQL's inet operators
        // This requires the IP to be parseable as inet
        let cidr_match = sqlx::query_as::<_, ExclusionEntry>(
            r#"
            SELECT * FROM exclusions 
            WHERE object_type = 'cidr' 
            AND company_id = $2
            AND $1::inet <<= object_value::inet
            LIMIT 1
            "#,
        )
        .bind(ip)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await;

        // If CIDR check fails (e.g., invalid IP format), just return None
        match cidr_match {
            Ok(entry) => Ok(entry),
            Err(_) => Ok(None),
        }
    }

    async fn list(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ExclusionEntry>, ApiError> {
        let rows = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE company_id = $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_all(&self, company_id: Uuid) -> Result<Vec<ExclusionEntry>, ApiError> {
        let rows = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE company_id = $1 ORDER BY created_at DESC",
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_by_type(
        &self,
        object_type: &ExclusionObjectType,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ExclusionEntry>, ApiError> {
        let type_str = object_type.to_string();

        let rows = sqlx::query_as::<_, ExclusionEntry>(
            "SELECT * FROM exclusions WHERE object_type = $1 AND company_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(&type_str)
        .bind(company_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn count(&self, company_id: Uuid) -> Result<i64, ApiError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM exclusions WHERE company_id = $1")
                .bind(company_id)
                .fetch_one(&self.pool)
                .await?;

        Ok(count)
    }

    async fn count_blacklisted(&self, company_id: Uuid) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM exclusions WHERE company_id = $1 AND blacklisted",
        )
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    async fn update(
        &self,
        company_id: Uuid,
        id: &Uuid,
        update: &ExclusionUpdate,
    ) -> Result<ExclusionEntry, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, ExclusionEntry>(
            r#"
            UPDATE exclusions
            SET reason = COALESCE($2, reason),
                blacklisted = COALESCE($5, blacklisted),
                updated_at = $3
            WHERE id = $1 AND company_id = $4
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.reason)
        .bind(now)
        .bind(company_id)
        .bind(update.blacklisted)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn delete(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM exclusions WHERE id = $1 AND company_id = $2")
            .bind(id)
            .bind(company_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_descendant_assets(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
    ) -> Result<i64, ApiError> {
        // Use a recursive CTE to find all descendants and delete them
        // This preserves the root asset but deletes all children
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            WITH RECURSIVE descendants AS (
                -- Start with direct children of the excluded asset
                SELECT id, parent_id, 1 as depth
                FROM assets
                WHERE parent_id = $1 AND company_id = $2
                
                UNION ALL
                
                -- Recursively get children of children
                SELECT a.id, a.parent_id, d.depth + 1
                FROM assets a
                INNER JOIN descendants d ON a.parent_id = d.id
                WHERE d.depth < 100 AND a.company_id = $2 -- Prevent infinite loops
            ),
            deleted AS (
                DELETE FROM assets
                WHERE id IN (SELECT id FROM descendants) AND company_id = $2
                RETURNING id
            )
            SELECT COUNT(*) FROM deleted
            "#,
        )
        .bind(asset_id)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn delete_descendant_assets_for_cidr(
        &self,
        company_id: Uuid,
        cidr: &str,
    ) -> Result<i64, ApiError> {
        let root_ids = self.ip_asset_ids_in_cidr(company_id, cidr).await?;

        if root_ids.is_empty() {
            return Ok(0);
        }

        // Recursively delete descendants of matching root IP assets.
        // Root IP assets are intentionally preserved.
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT id, parent_id, 1 as depth
                FROM assets
                WHERE company_id = $2
                  AND parent_id = ANY($1::uuid[])

                UNION ALL

                SELECT a.id, a.parent_id, d.depth + 1
                FROM assets a
                INNER JOIN descendants d ON a.parent_id = d.id
                WHERE d.depth < 100 AND a.company_id = $2
            ),
            deleted AS (
                DELETE FROM assets
                WHERE id IN (SELECT id FROM descendants) AND company_id = $2
                RETURNING id
            )
            SELECT COUNT(*) FROM deleted
            "#,
        )
        .bind(&root_ids)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn purge_entry_assets(
        &self,
        company_id: Uuid,
        object_type: &ExclusionObjectType,
        object_value: &str,
    ) -> Result<i64, ApiError> {
        // A CIDR is not an asset, so the addresses inside it are the roots.
        // Everything else names one asset, if it exists at all.
        let root_ids = match object_type {
            ExclusionObjectType::Cidr => {
                self.ip_asset_ids_in_cidr(company_id, object_value).await?
            }
            _ => self
                .find_asset_id(object_type, object_value, company_id)
                .await?
                .into_iter()
                .collect(),
        };

        if root_ids.is_empty() {
            return Ok(0);
        }

        // The roots go with their descendants, which is the whole difference
        // between this and `delete_descendant_assets`: excluding keeps the
        // object and drops what grew from it, blacklisting keeps neither.
        let deleted = sqlx::query_scalar::<_, i64>(
            r#"
            WITH RECURSIVE tree AS (
                SELECT id, parent_id, 0 as depth
                FROM assets
                WHERE company_id = $2
                  AND id = ANY($1::uuid[])

                UNION ALL

                SELECT a.id, a.parent_id, t.depth + 1
                FROM assets a
                INNER JOIN tree t ON a.parent_id = t.id
                WHERE t.depth < 100 AND a.company_id = $2
            ),
            deleted AS (
                DELETE FROM assets
                WHERE id IN (SELECT id FROM tree) AND company_id = $2
                RETURNING id
            )
            SELECT COUNT(*) FROM deleted
            "#,
        )
        .bind(&root_ids)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(deleted)
    }

    async fn find_asset_id(
        &self,
        object_type: &ExclusionObjectType,
        object_value: &str,
        company_id: Uuid,
    ) -> Result<Option<Uuid>, ApiError> {
        let type_str = object_type.to_string();
        let value = object_value.trim().to_lowercase();

        let id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM assets WHERE asset_type::text = $1 AND LOWER(identifier) = $2 AND company_id = $3",
        )
        .bind(&type_str)
        .bind(&value)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(id)
    }

    async fn search(
        &self,
        query: Option<&str>,
        object_type: Option<&ExclusionObjectType>,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ExclusionEntry>, i64), ApiError> {
        let search_pattern = query.map(|q| format!("%{}%", q.to_lowercase()));
        let type_str = object_type.map(|t| t.to_string());

        let rows = sqlx::query_as::<_, ExclusionEntry>(
            r#"
            SELECT * FROM exclusions 
            WHERE company_id = $3
            AND ($1::text IS NULL OR object_value ILIKE $1 OR reason ILIKE $1)
            AND ($2::text IS NULL OR object_type = $2)
            ORDER BY created_at DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(&search_pattern)
        .bind(&type_str)
        .bind(company_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM exclusions 
            WHERE company_id = $3
            AND ($1::text IS NULL OR object_value ILIKE $1 OR reason ILIKE $1)
            AND ($2::text IS NULL OR object_type = $2)
            "#,
        )
        .bind(&search_pattern)
        .bind(&type_str)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok((rows, total))
    }
}

use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{
        AssetTag, AssetTagCreate, AssetTagDetail, AssetTagRow, Tag, TagCreate, TagRow, TagUpdate,
        TagWithCount,
    },
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait TagRepository: Send + Sync {
    // Tag CRUD
    async fn create(&self, company_id: Uuid, tag: &TagCreate) -> Result<Tag, ApiError>;
    async fn get_by_id(&self, company_id: Uuid, id: &Uuid) -> Result<Option<Tag>, ApiError>;
    async fn get_by_name(&self, company_id: Uuid, name: &str) -> Result<Option<Tag>, ApiError>;
    async fn list(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TagWithCount>, ApiError>;
    async fn list_with_rules(&self, company_id: Uuid) -> Result<Vec<Tag>, ApiError>;
    async fn count(&self, company_id: Uuid) -> Result<i64, ApiError>;
    async fn update(
        &self,
        company_id: Uuid,
        id: &Uuid,
        update: &TagUpdate,
    ) -> Result<Tag, ApiError>;
    async fn delete(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError>;

    // Asset tagging
    async fn tag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_create: &AssetTagCreate,
    ) -> Result<AssetTag, ApiError>;
    async fn untag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_id: &Uuid,
    ) -> Result<(), ApiError>;
    async fn get_asset_tags(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
    ) -> Result<Vec<AssetTagDetail>, ApiError>;
    async fn get_assets_by_tag(
        &self,
        company_id: Uuid,
        tag_id: &Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Uuid>, ApiError>;
    async fn is_asset_tagged(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_id: &Uuid,
    ) -> Result<bool, ApiError>;
    
    // Bulk operations for auto-tagging
    async fn bulk_tag_assets(
        &self,
        company_id: Uuid,
        asset_ids: &[Uuid],
        tag_id: &Uuid,
        matched_rule: &str,
    ) -> Result<i64, ApiError>;
}

pub struct SqlxTagRepository {
    pool: DatabasePool,
}

impl SqlxTagRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TagRepository for SqlxTagRepository {
    async fn create(&self, company_id: Uuid, tag: &TagCreate) -> Result<Tag, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, TagRow>(
            r#"
            INSERT INTO tags (id, name, description, importance, rule_type, rule_value, color, company_id, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, name, description, importance, rule_type, rule_value, color, company_id, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&tag.name)
        .bind(&tag.description)
        .bind(tag.importance)
        .bind(&tag.rule_type)
        .bind(&tag.rule_value)
        .bind(&tag.color)
        .bind(company_id)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(Tag::from(row))
    }

    async fn get_by_id(&self, company_id: Uuid, id: &Uuid) -> Result<Option<Tag>, ApiError> {
        let result = sqlx::query_as::<_, TagRow>(
            r#"
            SELECT id, name, description, importance, rule_type, rule_value, color, company_id, created_at, updated_at
            FROM tags
            WHERE id = $1 AND company_id = $2
            "#,
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?
        .map(Tag::from);

        Ok(result)
    }

    async fn get_by_name(&self, company_id: Uuid, name: &str) -> Result<Option<Tag>, ApiError> {
        let result = sqlx::query_as::<_, TagRow>(
            r#"
            SELECT id, name, description, importance, rule_type, rule_value, color, company_id, created_at, updated_at
            FROM tags
            WHERE company_id = $1 AND LOWER(name) = LOWER($2)
            "#,
        )
        .bind(company_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .map(Tag::from);

        Ok(result)
    }

    async fn list(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TagWithCount>, ApiError> {
        // Use a dedicated row struct for the query with count
        #[derive(sqlx::FromRow)]
        struct TagWithCountRow {
            id: Uuid,
            name: String,
            description: Option<String>,
            importance: i32,
            rule_type: Option<String>,
            rule_value: Option<String>,
            color: Option<String>,
            company_id: Uuid,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            asset_count: i64,
        }

        let rows = sqlx::query_as::<_, TagWithCountRow>(
            r#"
            SELECT 
                t.id, t.name, t.description, t.importance, t.rule_type, t.rule_value, t.color, t.company_id, t.created_at, t.updated_at,
                COUNT(at.id)::bigint as asset_count
            FROM tags t
            LEFT JOIN asset_tags at ON t.id = at.tag_id AND at.company_id = $1
            WHERE t.company_id = $1
            GROUP BY t.id, t.company_id
            ORDER BY t.name ASC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(company_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let tags = rows
            .into_iter()
            .map(|row| TagWithCount {
                tag: Tag {
                    id: row.id,
                    name: row.name,
                    description: row.description,
                    importance: row.importance,
                    rule_type: row.rule_type,
                    rule_value: row.rule_value,
                    color: row.color,
                    company_id: row.company_id,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                },
                asset_count: row.asset_count,
            })
            .collect();

        Ok(tags)
    }

    async fn list_with_rules(&self, company_id: Uuid) -> Result<Vec<Tag>, ApiError> {
        let rows = sqlx::query_as::<_, TagRow>(
            r#"
            SELECT id, name, description, importance, rule_type, rule_value, color, company_id, created_at, updated_at
            FROM tags
            WHERE company_id = $1 AND rule_type IS NOT NULL AND rule_value IS NOT NULL
            ORDER BY name ASC
            "#,
        )
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Tag::from).collect())
    }

    async fn count(&self, company_id: Uuid) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tags WHERE company_id = $1",
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
        update: &TagUpdate,
    ) -> Result<Tag, ApiError> {
        let now = chrono::Utc::now();

        // Get current tag to merge with updates
        let current = self.get_by_id(company_id, id).await?.ok_or_else(|| {
            ApiError::NotFound(format!("Tag {} not found", id))
        })?;

        let name = update.name.as_ref().unwrap_or(&current.name);
        let description = if update.description.is_some() {
            update.description.clone()
        } else {
            current.description
        };
        let importance = update.importance.unwrap_or(current.importance);
        let color = if update.color.is_some() {
            update.color.clone()
        } else {
            current.color
        };

        // Handle rule clearing vs updating
        let (rule_type, rule_value) = if update.clear_rule {
            (None, None)
        } else {
            let rt = if update.rule_type.is_some() {
                update.rule_type.clone()
            } else {
                current.rule_type
            };
            let rv = if update.rule_value.is_some() {
                update.rule_value.clone()
            } else {
                current.rule_value
            };
            (rt, rv)
        };

        let row = sqlx::query_as::<_, TagRow>(
            r#"
            UPDATE tags
            SET name = $1, description = $2, importance = $3, rule_type = $4, rule_value = $5, color = $6, updated_at = $7
            WHERE id = $8 AND company_id = $9
            RETURNING id, name, description, importance, rule_type, rule_value, color, company_id, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(&description)
        .bind(importance)
        .bind(&rule_type)
        .bind(&rule_value)
        .bind(&color)
        .bind(now)
        .bind(id)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Tag::from(row))
    }

    async fn delete(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM tags WHERE id = $1 AND company_id = $2")
            .bind(id)
            .bind(company_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn tag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_create: &AssetTagCreate,
    ) -> Result<AssetTag, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, AssetTagRow>(
            r#"
            INSERT INTO asset_tags (id, company_id, asset_id, tag_id, applied_by, matched_rule, created_at)
            SELECT $1, a.company_id, a.id, t.id, $4, $5, $6
            FROM assets a
            JOIN tags t ON t.id = $3
            WHERE a.id = $2 AND a.company_id = $7 AND t.company_id = $7
            ON CONFLICT (company_id, asset_id, tag_id) DO UPDATE SET
                applied_by = EXCLUDED.applied_by,
                matched_rule = EXCLUDED.matched_rule
            RETURNING id, company_id, asset_id, tag_id, applied_by, matched_rule, created_at
            "#,
        )
        .bind(id)
        .bind(asset_id)
        .bind(&tag_create.tag_id)
        .bind(&tag_create.applied_by)
        .bind(&tag_create.matched_rule)
        .bind(now)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        let row = row.ok_or_else(|| {
            ApiError::NotFound("Asset or tag not found for this company".to_string())
        })?;

        Ok(AssetTag::from(row))
    }

    async fn untag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_id: &Uuid,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "DELETE FROM asset_tags WHERE company_id = $1 AND asset_id = $2 AND tag_id = $3",
        )
        .bind(company_id)
            .bind(asset_id)
            .bind(tag_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_asset_tags(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
    ) -> Result<Vec<AssetTagDetail>, ApiError> {
        // Use a custom struct for the query result since we need both tag and asset_tag fields
        #[derive(sqlx::FromRow)]
        struct AssetTagDetailRow {
            // Tag fields
            tag_id: Uuid,
            tag_name: String,
            tag_description: Option<String>,
            tag_importance: i32,
            tag_rule_type: Option<String>,
            tag_rule_value: Option<String>,
            tag_color: Option<String>,
            tag_company_id: Uuid,
            tag_created_at: chrono::DateTime<chrono::Utc>,
            tag_updated_at: chrono::DateTime<chrono::Utc>,
            // Asset tag fields
            applied_by: String,
            matched_rule: Option<String>,
            tagged_at: chrono::DateTime<chrono::Utc>,
        }

        let rows = sqlx::query_as::<_, AssetTagDetailRow>(
            r#"
            SELECT 
                t.id as tag_id, t.name as tag_name, t.description as tag_description, 
                t.importance as tag_importance, t.rule_type as tag_rule_type, 
                t.rule_value as tag_rule_value, t.color as tag_color, t.company_id as tag_company_id,
                t.created_at as tag_created_at, t.updated_at as tag_updated_at,
                at.applied_by, at.matched_rule, at.created_at as tagged_at
            FROM asset_tags at
            JOIN tags t ON at.tag_id = t.id
            WHERE at.company_id = $2 AND at.asset_id = $1 AND t.company_id = at.company_id
            ORDER BY t.name ASC
            "#,
        )
        .bind(asset_id)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        let details = rows
            .into_iter()
            .map(|row| AssetTagDetail {
                tag: Tag {
                    id: row.tag_id,
                    name: row.tag_name,
                    description: row.tag_description,
                    importance: row.tag_importance,
                    rule_type: row.tag_rule_type,
                    rule_value: row.tag_rule_value,
                    color: row.tag_color,
                    company_id: row.tag_company_id,
                    created_at: row.tag_created_at,
                    updated_at: row.tag_updated_at,
                },
                applied_by: row.applied_by,
                matched_rule: row.matched_rule,
                tagged_at: row.tagged_at,
            })
            .collect();

        Ok(details)
    }

    async fn get_assets_by_tag(
        &self,
        company_id: Uuid,
        tag_id: &Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Uuid>, ApiError> {
        let rows = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT asset_id
            FROM asset_tags
            WHERE company_id = $1 AND tag_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(company_id)
        .bind(tag_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn is_asset_tagged(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_id: &Uuid,
    ) -> Result<bool, ApiError> {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(SELECT 1 FROM asset_tags WHERE company_id = $1 AND asset_id = $2 AND tag_id = $3)
            "#,
        )
        .bind(company_id)
        .bind(asset_id)
        .bind(tag_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    async fn bulk_tag_assets(
        &self,
        company_id: Uuid,
        asset_ids: &[Uuid],
        tag_id: &Uuid,
        matched_rule: &str,
    ) -> Result<i64, ApiError> {
        if asset_ids.is_empty() {
            return Ok(0);
        }

        let now = chrono::Utc::now();
        let applied_by = "auto_rule";

        // Use unnest for bulk insert
        let result = sqlx::query(
            r#"
            INSERT INTO asset_tags (id, company_id, asset_id, tag_id, applied_by, matched_rule, created_at)
            SELECT gen_random_uuid(), $6, a.id, $2, $3, $4, $5
            FROM assets a
            WHERE a.id = ANY($1::uuid[]) AND a.company_id = $6
              AND EXISTS (SELECT 1 FROM tags t WHERE t.id = $2 AND t.company_id = $6)
            ON CONFLICT (company_id, asset_id, tag_id) DO NOTHING
            "#,
        )
        .bind(asset_ids)
        .bind(tag_id)
        .bind(applied_by)
        .bind(matched_rule)
        .bind(now)
        .bind(company_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }
}

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{
        AssetRelationship, AssetRelationshipCreate, AssetSource, AssetSourceCreate,
        DiscoveryQueueItem, DiscoveryQueueItemCreate, DiscoveryRun, DiscoveryRunCreate,
    },
};

// ============================================================================
// Discovery Run Repository
// ============================================================================

#[async_trait]
pub trait DiscoveryRunRepository: Send + Sync {
    async fn create(
        &self,
        run: &DiscoveryRunCreate,
        company_id: Uuid,
    ) -> Result<DiscoveryRun, ApiError>;
    async fn get_by_id(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<DiscoveryRun>, ApiError>;
    async fn get_running(&self, company_id: Uuid) -> Result<Option<DiscoveryRun>, ApiError>;
    async fn list(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscoveryRun>, ApiError>;
    async fn update_status(
        &self,
        company_id: Uuid,
        id: &Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<DiscoveryRun, ApiError>;
    async fn update_progress(
        &self,
        company_id: Uuid,
        id: &Uuid,
        seeds_processed: i32,
        assets_discovered: i32,
        assets_updated: i32,
    ) -> Result<DiscoveryRun, ApiError>;
    async fn start(&self, company_id: Uuid, id: &Uuid) -> Result<DiscoveryRun, ApiError>;
    async fn complete(&self, company_id: Uuid, id: &Uuid) -> Result<DiscoveryRun, ApiError>;
    async fn fail(
        &self,
        company_id: Uuid,
        id: &Uuid,
        error: &str,
    ) -> Result<DiscoveryRun, ApiError>;
}

pub struct SqlxDiscoveryRunRepository {
    pool: PgPool,
}

impl SqlxDiscoveryRunRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DiscoveryRunRepository for SqlxDiscoveryRunRepository {
    async fn create(
        &self,
        run: &DiscoveryRunCreate,
        company_id: Uuid,
    ) -> Result<DiscoveryRun, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let trigger_type = run
            .trigger_type
            .as_ref()
            .map(|t| format!("{:?}", t).to_lowercase())
            .unwrap_or_else(|| "manual".to_string());
        let config = run.config.clone().unwrap_or(json!({}));

        let row = sqlx::query_as::<_, DiscoveryRun>(
            r#"
            INSERT INTO discovery_runs (id, status, trigger_type, config, created_at, updated_at, company_id)
            VALUES ($1, 'pending', $2, $3, $4, $4, $5)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&trigger_type)
        .bind(&config)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_by_id(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<DiscoveryRun>, ApiError> {
        let row = sqlx::query_as::<_, DiscoveryRun>(
            "SELECT * FROM discovery_runs WHERE id = $1 AND company_id = $2",
        )
        .bind(id)
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn get_running(&self, company_id: Uuid) -> Result<Option<DiscoveryRun>, ApiError> {
        let row = sqlx::query_as::<_, DiscoveryRun>(
            "SELECT * FROM discovery_runs WHERE status = 'running' AND company_id = $1 ORDER BY started_at DESC LIMIT 1"
        )
        .bind(company_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscoveryRun>, ApiError> {
        let rows = sqlx::query_as::<_, DiscoveryRun>(
            "SELECT * FROM discovery_runs WHERE company_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(company_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn update_status(
        &self,
        company_id: Uuid,
        id: &Uuid,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<DiscoveryRun, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoveryRun>(
            r#"
            UPDATE discovery_runs 
            SET status = $2, error_message = COALESCE($3, error_message), updated_at = $4
            WHERE id = $1 AND company_id = $5
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(error_message)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn update_progress(
        &self,
        company_id: Uuid,
        id: &Uuid,
        seeds_processed: i32,
        assets_discovered: i32,
        assets_updated: i32,
    ) -> Result<DiscoveryRun, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoveryRun>(
            r#"
            UPDATE discovery_runs 
            SET seeds_processed = $2, assets_discovered = $3, assets_updated = $4, updated_at = $5
            WHERE id = $1 AND company_id = $6
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(seeds_processed)
        .bind(assets_discovered)
        .bind(assets_updated)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn start(&self, company_id: Uuid, id: &Uuid) -> Result<DiscoveryRun, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoveryRun>(
            r#"
            UPDATE discovery_runs 
            SET status = 'running', started_at = $2, updated_at = $2
            WHERE id = $1 AND company_id = $3
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn complete(&self, company_id: Uuid, id: &Uuid) -> Result<DiscoveryRun, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoveryRun>(
            r#"
            UPDATE discovery_runs 
            SET status = 'completed', completed_at = $2, updated_at = $2
            WHERE id = $1 AND company_id = $3
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn fail(
        &self,
        company_id: Uuid,
        id: &Uuid,
        error: &str,
    ) -> Result<DiscoveryRun, ApiError> {
        let now = Utc::now();

        let row = sqlx::query_as::<_, DiscoveryRun>(
            r#"
            UPDATE discovery_runs 
            SET status = 'failed', completed_at = $2, error_message = $3, updated_at = $2
            WHERE id = $1 AND company_id = $4
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(error)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }
}

// ============================================================================
// Discovery Queue Repository
// ============================================================================

#[async_trait]
pub trait DiscoveryQueueRepository: Send + Sync {
    async fn enqueue(
        &self,
        item: &DiscoveryQueueItemCreate,
    ) -> Result<DiscoveryQueueItem, ApiError>;
    async fn enqueue_batch(
        &self,
        items: &[DiscoveryQueueItemCreate],
    ) -> Result<Vec<DiscoveryQueueItem>, ApiError>;
    async fn dequeue(
        &self,
        run_id: &Uuid,
        batch_size: i32,
    ) -> Result<Vec<DiscoveryQueueItem>, ApiError>;
    async fn complete_item(&self, id: &Uuid) -> Result<(), ApiError>;
    async fn fail_item(&self, id: &Uuid, error: &str) -> Result<(), ApiError>;
    async fn skip_item(&self, id: &Uuid) -> Result<(), ApiError>;
    async fn get_pending_count(&self, run_id: &Uuid) -> Result<i64, ApiError>;
    async fn clear_run(&self, run_id: &Uuid) -> Result<(), ApiError>;
}

pub struct SqlxDiscoveryQueueRepository {
    pool: PgPool,
}

impl SqlxDiscoveryQueueRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DiscoveryQueueRepository for SqlxDiscoveryQueueRepository {
    async fn enqueue(
        &self,
        item: &DiscoveryQueueItemCreate,
    ) -> Result<DiscoveryQueueItem, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let item_type = item.item_type.to_string();

        let row = sqlx::query_as::<_, DiscoveryQueueItem>(
            r#"
            INSERT INTO discovery_queue 
                (id, discovery_run_id, item_type, item_value, parent_asset_id, seed_id, depth, priority, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9)
            ON CONFLICT (discovery_run_id, item_type, item_value) DO UPDATE SET
                priority = GREATEST(discovery_queue.priority, EXCLUDED.priority),
                parent_asset_id = COALESCE(discovery_queue.parent_asset_id, EXCLUDED.parent_asset_id),
                -- Keep the minimum depth to allow maximum exploration depth
                depth = LEAST(discovery_queue.depth, EXCLUDED.depth),
                -- Reset to pending if it was skipped/completed but now requeued at shallower depth
                status = CASE 
                    WHEN EXCLUDED.depth < discovery_queue.depth AND discovery_queue.status IN ('skipped', 'completed') 
                    THEN 'pending' 
                    ELSE discovery_queue.status 
                END
            RETURNING *
            "#
        )
        .bind(id)
        .bind(item.discovery_run_id)
        .bind(&item_type)
        .bind(&item.item_value)
        .bind(item.parent_asset_id)
        .bind(item.seed_id)
        .bind(item.depth)
        .bind(item.priority)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn enqueue_batch(
        &self,
        items: &[DiscoveryQueueItemCreate],
    ) -> Result<Vec<DiscoveryQueueItem>, ApiError> {
        let mut results = Vec::with_capacity(items.len());
        for item in items {
            let result = self.enqueue(item).await?;
            results.push(result);
        }
        Ok(results)
    }

    async fn dequeue(
        &self,
        run_id: &Uuid,
        batch_size: i32,
    ) -> Result<Vec<DiscoveryQueueItem>, ApiError> {
        let now = Utc::now();

        let rows = sqlx::query_as::<_, DiscoveryQueueItem>(
            r#"
            UPDATE discovery_queue 
            SET status = 'processing', processed_at = $3
            WHERE id IN (
                SELECT id FROM discovery_queue 
                WHERE discovery_run_id = $1 AND status = 'pending'
                ORDER BY priority DESC, depth ASC, created_at ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
            "#,
        )
        .bind(run_id)
        .bind(batch_size)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn complete_item(&self, id: &Uuid) -> Result<(), ApiError> {
        let now = Utc::now();

        sqlx::query(
            "UPDATE discovery_queue SET status = 'completed', processed_at = $2 WHERE id = $1",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn fail_item(&self, id: &Uuid, error: &str) -> Result<(), ApiError> {
        let now = Utc::now();

        sqlx::query("UPDATE discovery_queue SET status = 'failed', error_message = $2, processed_at = $3 WHERE id = $1")
            .bind(id)
            .bind(error)
            .bind(now)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn skip_item(&self, id: &Uuid) -> Result<(), ApiError> {
        let now = Utc::now();

        sqlx::query(
            "UPDATE discovery_queue SET status = 'skipped', processed_at = $2 WHERE id = $1",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_pending_count(&self, run_id: &Uuid) -> Result<i64, ApiError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM discovery_queue WHERE discovery_run_id = $1 AND status = 'pending'"
        )
        .bind(run_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    async fn clear_run(&self, run_id: &Uuid) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM discovery_queue WHERE discovery_run_id = $1")
            .bind(run_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

// ============================================================================
// Asset Source Repository
// ============================================================================

#[async_trait]
pub trait AssetSourceRepository: Send + Sync {
    async fn create(&self, source: &AssetSourceCreate) -> Result<AssetSource, ApiError>;
    async fn list_by_asset(&self, asset_id: &Uuid) -> Result<Vec<AssetSource>, ApiError>;
    async fn list_by_discovery_run(&self, run_id: &Uuid) -> Result<Vec<AssetSource>, ApiError>;
    async fn get_by_asset_and_type(
        &self,
        asset_id: &Uuid,
        source_type: &str,
    ) -> Result<Option<AssetSource>, ApiError>;
}

pub struct SqlxAssetSourceRepository {
    pool: PgPool,
}

impl SqlxAssetSourceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AssetSourceRepository for SqlxAssetSourceRepository {
    async fn create(&self, source: &AssetSourceCreate) -> Result<AssetSource, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let source_type = source.source_type.to_string();
        let raw_data = source.raw_data.clone().unwrap_or(json!({}));

        let row = sqlx::query_as::<_, AssetSource>(
            r#"
            INSERT INTO asset_sources 
                (id, asset_id, discovery_run_id, source_type, source_confidence, raw_data, discovered_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (asset_id, source_type, discovery_run_id) DO UPDATE SET
                source_confidence = GREATEST(asset_sources.source_confidence, EXCLUDED.source_confidence),
                raw_data = asset_sources.raw_data || EXCLUDED.raw_data,
                discovered_at = EXCLUDED.discovered_at
            RETURNING *
            "#
        )
        .bind(id)
        .bind(source.asset_id)
        .bind(source.discovery_run_id)
        .bind(&source_type)
        .bind(source.source_confidence)
        .bind(&raw_data)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list_by_asset(&self, asset_id: &Uuid) -> Result<Vec<AssetSource>, ApiError> {
        let rows = sqlx::query_as::<_, AssetSource>(
            "SELECT * FROM asset_sources WHERE asset_id = $1 ORDER BY discovered_at DESC",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_by_discovery_run(&self, run_id: &Uuid) -> Result<Vec<AssetSource>, ApiError> {
        let rows = sqlx::query_as::<_, AssetSource>(
            "SELECT * FROM asset_sources WHERE discovery_run_id = $1 ORDER BY discovered_at DESC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn get_by_asset_and_type(
        &self,
        asset_id: &Uuid,
        source_type: &str,
    ) -> Result<Option<AssetSource>, ApiError> {
        let row = sqlx::query_as::<_, AssetSource>(
            "SELECT * FROM asset_sources WHERE asset_id = $1 AND source_type = $2 ORDER BY discovered_at DESC LIMIT 1"
        )
        .bind(asset_id)
        .bind(source_type)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }
}

// ============================================================================
// Asset Relationship Repository
// ============================================================================

#[async_trait]
pub trait AssetRelationshipRepository: Send + Sync {
    async fn create_or_update(
        &self,
        rel: &AssetRelationshipCreate,
    ) -> Result<AssetRelationship, ApiError>;
    async fn list_by_source(&self, source_id: &Uuid) -> Result<Vec<AssetRelationship>, ApiError>;
    async fn list_by_target(&self, target_id: &Uuid) -> Result<Vec<AssetRelationship>, ApiError>;
    async fn get_relationship(
        &self,
        source_id: &Uuid,
        target_id: &Uuid,
        rel_type: &str,
    ) -> Result<Option<AssetRelationship>, ApiError>;
    async fn delete(&self, id: &Uuid) -> Result<(), ApiError>;
}

pub struct SqlxAssetRelationshipRepository {
    pool: PgPool,
}

impl SqlxAssetRelationshipRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AssetRelationshipRepository for SqlxAssetRelationshipRepository {
    async fn create_or_update(
        &self,
        rel: &AssetRelationshipCreate,
    ) -> Result<AssetRelationship, ApiError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let rel_type = rel.relationship_type.to_string();
        let metadata = rel.metadata.clone().unwrap_or(json!({}));

        let row = sqlx::query_as::<_, AssetRelationship>(
            r#"
            INSERT INTO asset_relationships 
                (id, source_asset_id, target_asset_id, relationship_type, confidence, metadata, discovery_run_id, first_seen_at, last_seen_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
            ON CONFLICT (source_asset_id, target_asset_id, relationship_type) DO UPDATE SET
                confidence = GREATEST(asset_relationships.confidence, EXCLUDED.confidence),
                metadata = asset_relationships.metadata || EXCLUDED.metadata,
                last_seen_at = EXCLUDED.last_seen_at,
                discovery_run_id = COALESCE(EXCLUDED.discovery_run_id, asset_relationships.discovery_run_id)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(rel.source_asset_id)
        .bind(rel.target_asset_id)
        .bind(&rel_type)
        .bind(rel.confidence)
        .bind(&metadata)
        .bind(rel.discovery_run_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list_by_source(&self, source_id: &Uuid) -> Result<Vec<AssetRelationship>, ApiError> {
        let rows = sqlx::query_as::<_, AssetRelationship>(
            "SELECT * FROM asset_relationships WHERE source_asset_id = $1 ORDER BY last_seen_at DESC"
        )
        .bind(source_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn list_by_target(&self, target_id: &Uuid) -> Result<Vec<AssetRelationship>, ApiError> {
        let rows = sqlx::query_as::<_, AssetRelationship>(
            "SELECT * FROM asset_relationships WHERE target_asset_id = $1 ORDER BY last_seen_at DESC"
        )
        .bind(target_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn get_relationship(
        &self,
        source_id: &Uuid,
        target_id: &Uuid,
        rel_type: &str,
    ) -> Result<Option<AssetRelationship>, ApiError> {
        let row = sqlx::query_as::<_, AssetRelationship>(
            "SELECT * FROM asset_relationships WHERE source_asset_id = $1 AND target_asset_id = $2 AND relationship_type = $3"
        )
        .bind(source_id)
        .bind(target_id)
        .bind(rel_type)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn delete(&self, id: &Uuid) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM asset_relationships WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

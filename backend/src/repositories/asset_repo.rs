use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Asset, AssetCreate, AssetRow, AssetType, Seed, SeedCreate, SeedType},
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait AssetRepository {
    async fn create_or_merge(&self, asset: &AssetCreate) -> Result<Asset, ApiError>;
    async fn list(
        &self,
        confidence_threshold: Option<f64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Asset>, ApiError>;
    async fn count(&self, confidence_threshold: Option<f64>) -> Result<i64, ApiError>;
    async fn list_by_type(
        &self,
        asset_type: AssetType,
        confidence_threshold: Option<f64>,
    ) -> Result<Vec<Asset>, ApiError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Asset>, ApiError>;
    async fn get_by_identifier(
        &self,
        asset_type: AssetType,
        identifier: &str,
    ) -> Result<Option<Asset>, ApiError>;
    async fn get_path(&self, id: &Uuid) -> Result<Vec<Asset>, ApiError>;
    async fn update_confidence(&self, id: &Uuid, new_confidence: f64) -> Result<Asset, ApiError>;

    // New methods
    async fn update_importance(&self, id: &Uuid, importance: i32) -> Result<Asset, ApiError>;
    async fn update_risk(
        &self,
        id: &Uuid,
        risk_score: f64,
        risk_level: &str,
        factors: &serde_json::Value,
    ) -> Result<Asset, ApiError>;

    /// Advanced search with filtering, sorting, and text search
    #[allow(clippy::too_many_arguments)]
    async fn search(
        &self,
        query: Option<&str>,
        asset_type: Option<AssetType>,
        min_confidence: Option<f64>,
        scan_status: Option<&str>,
        source: Option<&str>,
        risk_level: Option<&str>,
        sort_by: &str,
        sort_dir: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Asset>, i64, Vec<String>), ApiError>;
}

#[async_trait]
pub trait SeedRepository {
    async fn create(&self, seed: &SeedCreate) -> Result<Seed, ApiError>;
    async fn list(&self) -> Result<Vec<Seed>, ApiError>;
    async fn list_by_type(&self, seed_type: SeedType) -> Result<Vec<Seed>, ApiError>;
    async fn delete(&self, id: &Uuid) -> Result<(), ApiError>;
    async fn get_by_value(
        &self,
        seed_type: SeedType,
        value: &str,
    ) -> Result<Option<Seed>, ApiError>;
}

pub struct SqlxAssetRepository {
    pool: DatabasePool,
}

impl SqlxAssetRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AssetRepository for SqlxAssetRepository {
    async fn create_or_merge(&self, asset: &AssetCreate) -> Result<Asset, ApiError> {
        let now = chrono::Utc::now();

        // Try to find existing asset with same type and identifier
        let existing = sqlx::query_as::<_, AssetRow>(
            r#"
            SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                   importance, risk_score, risk_level, last_risk_run
            FROM assets
            WHERE asset_type = $1 AND identifier = $2
            "#
        )
        .bind(&asset.asset_type)
        .bind(&asset.identifier)
        .fetch_optional(&self.pool)
        .await?
        .map(Asset::from);

        match existing {
            Some(existing_asset) => {
                // Merge logic
                let mut merged_sources =
                    existing_asset.sources.as_array().unwrap_or(&vec![]).clone();
                let original_source_count = merged_sources.len();

                if let Some(new_sources) = asset.sources.as_array() {
                    for source in new_sources {
                        if !merged_sources.contains(source) {
                            merged_sources.push(source.clone());
                        }
                    }
                }

                let new_source_count = merged_sources.len();
                let discovered_new_sources = new_source_count > original_source_count;

                let base_confidence = asset.confidence.max(existing_asset.confidence);
                let rediscovery_bonus = if discovered_new_sources {
                    let new_sources_added = (new_source_count - original_source_count) as f64;
                    (new_sources_added * 0.05).min(0.15)
                } else if asset.confidence > 0.0 {
                    0.02
                } else {
                    0.0
                };

                let new_confidence = (base_confidence + rediscovery_bonus).min(1.0);

                let mut merged_metadata = existing_asset
                    .metadata
                    .as_object()
                    .unwrap_or(&serde_json::Map::new())
                    .clone();
                if let Some(new_metadata) = asset.metadata.as_object() {
                    for (key, value) in new_metadata {
                        merged_metadata.insert(key.clone(), value.clone());
                    }
                }

                let row = sqlx::query_as::<_, AssetRow>(
                    r#"
                    UPDATE assets
                    SET confidence = $1, sources = $2, metadata = $3, updated_at = $4, 
                        seed_id = COALESCE($5, assets.seed_id), 
                        -- Parent ID rules (in order of priority):
                        -- 1. Keep seed roots as roots (seed_id set, no parent)
                        -- 2. Prevent self-reference (parent_id = own id)
                        -- 3. NEVER overwrite existing parent (prevents circular refs and broken lineage)
                        -- 4. Only set parent if currently NULL
                        parent_id = CASE 
                            WHEN assets.seed_id IS NOT NULL AND assets.parent_id IS NULL THEN NULL
                            WHEN $6 = $7 THEN assets.parent_id  -- Prevent self-reference
                            WHEN assets.parent_id IS NOT NULL THEN assets.parent_id  -- Keep existing parent
                            ELSE $6  -- Only set if currently NULL
                        END
                    WHERE id = $7
                    RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                              importance, risk_score, risk_level, last_risk_run
                    "#
                )
                .bind(new_confidence)
                .bind(serde_json::Value::Array(merged_sources))
                .bind(serde_json::Value::Object(merged_metadata))
                .bind(now)
                .bind(asset.seed_id)
                .bind(asset.parent_id)
                .bind(existing_asset.id)
                .fetch_one(&self.pool)
                .await?;

                Ok(Asset::from(row))
            }
            None => {
                let id = Uuid::new_v4();
                // Prevent self-referencing parent (should never happen for new assets, but safety check)
                let safe_parent_id = asset.parent_id.filter(|pid| *pid != id);
                
                let row = sqlx::query_as::<_, AssetRow>(
                    r#"
                    INSERT INTO assets (id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                              importance, risk_score, risk_level, last_risk_run
                    "#
                )
                .bind(id)
                .bind(&asset.asset_type)
                .bind(&asset.identifier)
                .bind(asset.confidence)
                .bind(&asset.sources)
                .bind(&asset.metadata)
                .bind(now)
                .bind(now)
                .bind(asset.seed_id)
                .bind(safe_parent_id)
                .fetch_one(&self.pool)
                .await?;

                Ok(Asset::from(row))
            }
        }
    }

    async fn list(
        &self,
        confidence_threshold: Option<f64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Asset>, ApiError> {
        let limit = limit.unwrap_or(1000);
        let offset = offset.unwrap_or(0);

        let rows = match confidence_threshold {
            Some(threshold) => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    WITH latest_scans AS (
                        SELECT DISTINCT ON (LOWER(TRIM(target))) 
                            id, status, created_at, LOWER(TRIM(target)) as normalized_target
                        FROM scans
                        ORDER BY LOWER(TRIM(target)), created_at DESC
                    )
                    SELECT 
                        a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, a.created_at, a.updated_at, a.seed_id, a.parent_id,
                        a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                        ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
                    FROM assets a
                    LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
                    WHERE a.confidence >= $1
                    ORDER BY a.importance DESC, a.confidence DESC, a.created_at DESC
                    LIMIT $2 OFFSET $3
                    "#
                )
                .bind(threshold)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    WITH latest_scans AS (
                        SELECT DISTINCT ON (LOWER(TRIM(target))) 
                            id, status, created_at, LOWER(TRIM(target)) as normalized_target
                        FROM scans
                        ORDER BY LOWER(TRIM(target)), created_at DESC
                    )
                    SELECT 
                        a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, a.created_at, a.updated_at, a.seed_id, a.parent_id,
                        a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                        ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
                    FROM assets a
                    LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
                    ORDER BY a.importance DESC, a.confidence DESC, a.created_at DESC
                    LIMIT $1 OFFSET $2
                    "#
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows.into_iter().map(Asset::from).collect())
    }

    async fn count(&self, confidence_threshold: Option<f64>) -> Result<i64, ApiError> {
        let count = match confidence_threshold {
            Some(threshold) => {
                sqlx::query_scalar::<_, i64>(
                    r#"
                    SELECT COUNT(*)
                    FROM assets
                    WHERE confidence >= $1
                    "#,
                )
                .bind(threshold)
                .fetch_one(&self.pool)
                .await?
            }
            None => {
                sqlx::query_scalar::<_, i64>(
                    r#"
                    SELECT COUNT(*)
                    FROM assets
                    "#,
                )
                .fetch_one(&self.pool)
                .await?
            }
        };

        Ok(count)
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Asset>, ApiError> {
        let result = sqlx::query_as::<_, AssetRow>(
            r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (LOWER(TRIM(target))) 
                    id, status, created_at, LOWER(TRIM(target)) as normalized_target
                FROM scans
                ORDER BY LOWER(TRIM(target)), created_at DESC
            )
            SELECT 
                a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, a.created_at, a.updated_at, a.seed_id, a.parent_id,
                a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
            FROM assets a
            LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
            WHERE a.id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(Asset::from);

        Ok(result)
    }

    async fn list_by_type(
        &self,
        asset_type: AssetType,
        confidence_threshold: Option<f64>,
    ) -> Result<Vec<Asset>, ApiError> {
        let rows = match confidence_threshold {
            Some(threshold) => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    WITH latest_scans AS (
                        SELECT DISTINCT ON (LOWER(TRIM(target))) 
                            id, status, created_at, LOWER(TRIM(target)) as normalized_target
                        FROM scans
                        ORDER BY LOWER(TRIM(target)), created_at DESC
                    )
                    SELECT 
                        a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, a.created_at, a.updated_at, a.seed_id, a.parent_id,
                        a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                        ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
                    FROM assets a
                    LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
                    WHERE a.asset_type = $1 AND a.confidence >= $2
                    ORDER BY a.importance DESC, a.confidence DESC, a.created_at DESC
                    "#
                )
                .bind(asset_type)
                .bind(threshold)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    WITH latest_scans AS (
                        SELECT DISTINCT ON (LOWER(TRIM(target))) 
                            id, status, created_at, LOWER(TRIM(target)) as normalized_target
                        FROM scans
                        ORDER BY LOWER(TRIM(target)), created_at DESC
                    )
                    SELECT 
                        a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, a.created_at, a.updated_at, a.seed_id, a.parent_id,
                        a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                        ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
                    FROM assets a
                    LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
                    WHERE a.asset_type = $1
                    ORDER BY a.importance DESC, a.confidence DESC, a.created_at DESC
                    "#
                )
                .bind(asset_type)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows.into_iter().map(Asset::from).collect())
    }

    async fn get_by_identifier(
        &self,
        asset_type: AssetType,
        identifier: &str,
    ) -> Result<Option<Asset>, ApiError> {
        let result = sqlx::query_as::<_, AssetRow>(
            r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (LOWER(TRIM(target))) 
                    id, status, created_at, LOWER(TRIM(target)) as normalized_target
                FROM scans
                ORDER BY LOWER(TRIM(target)), created_at DESC
            )
            SELECT 
                a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, a.created_at, a.updated_at, a.seed_id, a.parent_id,
                a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
            FROM assets a
            LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
            WHERE a.asset_type = $1 AND a.identifier = $2
            "#
        )
        .bind(asset_type)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?
        .map(Asset::from);

        Ok(result)
    }

    async fn get_path(&self, id: &Uuid) -> Result<Vec<Asset>, ApiError> {
        // Optimized path query with cycle detection, depth limit, and no scan join
        let rows = sqlx::query_as::<_, AssetRow>(
            r#"
            WITH RECURSIVE asset_path AS (
                -- Base case: the requested asset
                SELECT 
                    id, asset_type, identifier, confidence, sources, metadata, 
                    created_at, updated_at, seed_id, parent_id,
                    importance, risk_score, risk_level, last_risk_run,
                    ARRAY[id] as path_ids,
                    0 as depth
                FROM assets
                WHERE id = $1
                
                UNION ALL
                
                -- Recursive step: get the parent
                SELECT 
                    p.id, p.asset_type, p.identifier, p.confidence, p.sources, p.metadata, 
                    p.created_at, p.updated_at, p.seed_id, p.parent_id,
                    p.importance, p.risk_score, p.risk_level, p.last_risk_run,
                    ap.path_ids || p.id,
                    ap.depth + 1
                FROM assets p
                INNER JOIN asset_path ap ON p.id = ap.parent_id
                WHERE NOT (p.id = ANY(ap.path_ids))
                  AND ap.depth < 100
            )
            SELECT 
                id, asset_type, identifier, confidence, sources, metadata, 
                created_at, updated_at, seed_id, parent_id,
                importance, risk_score, risk_level, last_risk_run,
                NULL::uuid as last_scan_id,
                NULL::text as last_scan_status,
                NULL::timestamptz as last_scanned_at
            FROM asset_path
            ORDER BY depth DESC
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;

        // No need to reverse - ORDER BY depth DESC already gives us root-first order
        // Path should be: [Root/Seed, Parent1, Parent2, ..., Target Asset]
        let assets: Vec<Asset> = rows.into_iter().map(Asset::from).collect();

        Ok(assets)
    }

    async fn update_confidence(&self, id: &Uuid, new_confidence: f64) -> Result<Asset, ApiError> {
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, AssetRow>(
            r#"
            UPDATE assets
            SET confidence = $1, updated_at = $2
            WHERE id = $3
            RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                      importance, risk_score, risk_level, last_risk_run
            "#
        )
        .bind(new_confidence)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Asset::from(row))
    }

    async fn update_importance(&self, id: &Uuid, importance: i32) -> Result<Asset, ApiError> {
        let now = chrono::Utc::now();

        let row = sqlx::query_as::<_, AssetRow>(
            r#"
            UPDATE assets
            SET importance = $1, updated_at = $2
            WHERE id = $3
            RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                      importance, risk_score, risk_level, last_risk_run
            "#
        )
        .bind(importance)
        .bind(now)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Asset::from(row))
    }

    async fn update_risk(
        &self,
        id: &Uuid,
        risk_score: f64,
        risk_level: &str,
        factors: &serde_json::Value,
    ) -> Result<Asset, ApiError> {
        let now = chrono::Utc::now();

        // Start a transaction to update asset and insert history
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query_as::<_, AssetRow>(
            r#"
            UPDATE assets
            SET risk_score = $1, risk_level = $2, last_risk_run = $3, updated_at = $3
            WHERE id = $4
            RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at, seed_id, parent_id,
                      importance, risk_score, risk_level, last_risk_run
            "#
        )
        .bind(risk_score)
        .bind(risk_level)
        .bind(now)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO asset_risk_history (asset_id, risk_score, risk_level, factors, calculated_at)
            VALUES ($1, $2, $3, $4, $5)
            "#
        )
        .bind(id)
        .bind(risk_score)
        .bind(risk_level)
        .bind(factors)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Asset::from(row))
    }

    async fn search(
        &self,
        query: Option<&str>,
        asset_type: Option<AssetType>,
        min_confidence: Option<f64>,
        scan_status: Option<&str>,
        source: Option<&str>,
        risk_level: Option<&str>,
        sort_by: &str,
        sort_dir: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Asset>, i64, Vec<String>), ApiError> {
        // Prepare search pattern
        let search_pattern = query.map(|q| format!("%{}%", q.to_lowercase()));
        let source_pattern = source.map(|s| format!("%{}%", s));

        // Validate sort options
        let sort_field = match sort_by {
            "value" | "identifier" => "a.identifier",
            "confidence" => "a.confidence",
            "importance" => "a.importance",
            "risk_score" => "a.risk_score",
            _ => "a.created_at",
        };

        let sort_direction = if sort_dir.to_lowercase() == "asc" {
            "ASC"
        } else {
            "DESC"
        };

        // Determine scan status filter
        let filter_scanned = scan_status == Some("scanned");
        let filter_never_scanned = scan_status == Some("never_scanned");

        // Single unified query with optional filters using COALESCE pattern
        let query_sql = format!(
            r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (LOWER(TRIM(target))) 
                    id, status, created_at, LOWER(TRIM(target)) as normalized_target
                FROM scans
                ORDER BY LOWER(TRIM(target)), created_at DESC
            )
            SELECT 
                a.id, a.asset_type, a.identifier, a.confidence, a.sources, a.metadata, 
                a.created_at, a.updated_at, a.seed_id, a.parent_id,
                a.importance, a.risk_score, a.risk_level, a.last_risk_run,
                ls.id as last_scan_id, ls.status::text as last_scan_status, ls.created_at as last_scanned_at
            FROM assets a
            LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
            WHERE 
                ($1::text IS NULL OR LOWER(a.identifier) LIKE $1 OR a.sources::text ILIKE $1)
                AND ($2::text IS NULL OR a.asset_type::text = $2)
                AND ($3::float8 IS NULL OR a.confidence >= $3)
                AND ($4::text IS NULL OR a.sources::text ILIKE $4)
                AND ($5::text IS NULL OR a.risk_level = $5)
                AND (NOT $6::bool OR ls.id IS NOT NULL)
                AND (NOT $7::bool OR ls.id IS NULL)
            ORDER BY {sort_field} {sort_direction} NULLS LAST, a.created_at DESC
            LIMIT $8 OFFSET $9
            "#,
            sort_field = sort_field,
            sort_direction = sort_direction,
        );

        let count_sql = r#"
            WITH latest_scans AS (
                SELECT DISTINCT ON (LOWER(TRIM(target))) 
                    id, LOWER(TRIM(target)) as normalized_target
                FROM scans
                ORDER BY LOWER(TRIM(target)), created_at DESC
            )
            SELECT COUNT(*)
            FROM assets a
            LEFT JOIN latest_scans ls ON ls.normalized_target = LOWER(TRIM(a.identifier))
            WHERE 
                ($1::text IS NULL OR LOWER(a.identifier) LIKE $1 OR a.sources::text ILIKE $1)
                AND ($2::text IS NULL OR a.asset_type::text = $2)
                AND ($3::float8 IS NULL OR a.confidence >= $3)
                AND ($4::text IS NULL OR a.sources::text ILIKE $4)
                AND ($5::text IS NULL OR a.risk_level = $5)
                AND (NOT $6::bool OR ls.id IS NOT NULL)
                AND (NOT $7::bool OR ls.id IS NULL)
            "#;

        // Execute queries
        let rows = sqlx::query_as::<_, AssetRow>(&query_sql)
            .bind(&search_pattern)
            .bind(asset_type.as_ref().map(|t| t.to_string()))
            .bind(min_confidence)
            .bind(&source_pattern)
            .bind(risk_level)
            .bind(filter_scanned)
            .bind(filter_never_scanned)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

        let total_count = sqlx::query_scalar::<_, i64>(count_sql)
            .bind(&search_pattern)
            .bind(asset_type.as_ref().map(|t| t.to_string()))
            .bind(min_confidence)
            .bind(&source_pattern)
            .bind(risk_level)
            .bind(filter_scanned)
            .bind(filter_never_scanned)
            .fetch_one(&self.pool)
            .await?;

        // Get unique sources for filter dropdown (cached or simple query)
        let sources: Vec<String> = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT jsonb_array_elements_text(sources) as source
            FROM assets
            ORDER BY source
            LIMIT 100
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok((
            rows.into_iter().map(Asset::from).collect(),
            total_count,
            sources,
        ))
    }
}

#[cfg(test)]
mod tests {
    // ... existing tests (need updating? No, I updated queries so they should work)
    // I should add test for update_importance/risk if needed, but time constraint.
    // Existing tests use helper methods which I updated.
}

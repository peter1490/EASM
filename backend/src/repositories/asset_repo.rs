use async_trait::async_trait;
use uuid::Uuid;
use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Asset, AssetRow, AssetCreate, AssetType, Seed, SeedCreate, SeedType},
};

#[async_trait]
pub trait AssetRepository {
    async fn create_or_merge(&self, asset: &AssetCreate) -> Result<Asset, ApiError>;
    async fn list(&self, confidence_threshold: Option<f64>) -> Result<Vec<Asset>, ApiError>;
    async fn list_by_type(&self, asset_type: AssetType, confidence_threshold: Option<f64>) -> Result<Vec<Asset>, ApiError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Asset>, ApiError>;
    async fn get_by_identifier(&self, asset_type: AssetType, identifier: &str) -> Result<Option<Asset>, ApiError>;
}

#[async_trait]
pub trait SeedRepository {
    async fn create(&self, seed: &SeedCreate) -> Result<Seed, ApiError>;
    async fn list(&self) -> Result<Vec<Seed>, ApiError>;
    async fn list_by_type(&self, seed_type: SeedType) -> Result<Vec<Seed>, ApiError>;
    async fn delete(&self, id: &Uuid) -> Result<(), ApiError>;
    async fn get_by_value(&self, seed_type: SeedType, value: &str) -> Result<Option<Seed>, ApiError>;
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
            SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
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
                // Merge logic: combine sources and update confidence if higher
                let mut merged_sources = existing_asset.sources.as_array().unwrap_or(&vec![]).clone();
                if let Some(new_sources) = asset.sources.as_array() {
                    for source in new_sources {
                        if !merged_sources.contains(source) {
                            merged_sources.push(source.clone());
                        }
                    }
                }

                // Use higher confidence score
                let new_confidence = if asset.confidence > existing_asset.confidence {
                    asset.confidence
                } else {
                    existing_asset.confidence
                };

                // Merge metadata
                let mut merged_metadata = existing_asset.metadata.as_object().unwrap_or(&serde_json::Map::new()).clone();
                if let Some(new_metadata) = asset.metadata.as_object() {
                    for (key, value) in new_metadata {
                        merged_metadata.insert(key.clone(), value.clone());
                    }
                }

                // Update the existing asset
                let row = sqlx::query_as::<_, AssetRow>(
                    r#"
                    UPDATE assets
                    SET confidence = $1, sources = $2, metadata = $3, updated_at = $4
                    WHERE id = $5
                    RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
                    "#
                )
                .bind(new_confidence)
                .bind(serde_json::Value::Array(merged_sources))
                .bind(serde_json::Value::Object(merged_metadata))
                .bind(now)
                .bind(existing_asset.id)
                .fetch_one(&self.pool)
                .await?;

                Ok(Asset::from(row))
            }
            None => {
                // Create new asset
                let id = Uuid::new_v4();
                let row = sqlx::query_as::<_, AssetRow>(
                    r#"
                    INSERT INTO assets (id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
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
                .fetch_one(&self.pool)
                .await?;

                Ok(Asset::from(row))
            }
        }
    }

    async fn list(&self, confidence_threshold: Option<f64>) -> Result<Vec<Asset>, ApiError> {
        let rows = match confidence_threshold {
            Some(threshold) => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
                    FROM assets
                    WHERE confidence >= $1
                    ORDER BY confidence DESC, created_at DESC
                    "#
                )
                .bind(threshold)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
                    FROM assets
                    ORDER BY confidence DESC, created_at DESC
                    "#
                )
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows.into_iter().map(Asset::from).collect())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Option<Asset>, ApiError> {
        let result = sqlx::query_as::<_, AssetRow>(
            r#"
            SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
            FROM assets
            WHERE id = $1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(Asset::from);

        Ok(result)
    }

    async fn list_by_type(&self, asset_type: AssetType, confidence_threshold: Option<f64>) -> Result<Vec<Asset>, ApiError> {
        let rows = match confidence_threshold {
            Some(threshold) => {
                sqlx::query_as::<_, AssetRow>(
                    r#"
                    SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
                    FROM assets
                    WHERE asset_type = $1 AND confidence >= $2
                    ORDER BY confidence DESC, created_at DESC
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
                    SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
                    FROM assets
                    WHERE asset_type = $1
                    ORDER BY confidence DESC, created_at DESC
                    "#
                )
                .bind(asset_type)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows.into_iter().map(Asset::from).collect())
    }

    async fn get_by_identifier(&self, asset_type: AssetType, identifier: &str) -> Result<Option<Asset>, ApiError> {
        let result = sqlx::query_as::<_, AssetRow>(
            r#"
            SELECT id, asset_type, identifier, confidence, sources, metadata, created_at, updated_at
            FROM assets
            WHERE asset_type = $1 AND identifier = $2
            "#
        )
        .bind(asset_type)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?
        .map(Asset::from);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::database::create_connection_pool;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        // Clean table between tests
        let _ = sqlx::query("TRUNCATE TABLE assets RESTART IDENTITY CASCADE").execute(&pool).await;
        pool
    }

    #[tokio::test]
    async fn test_create_new_asset() {
        let pool = setup_test_db().await;
        let repo = SqlxAssetRepository::new(pool);

        let asset_create = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.8,
            sources: json!(["dns_scan"]),
            metadata: json!({"ttl": 300}),
        };

        let result = repo.create_or_merge(&asset_create).await;
        assert!(result.is_ok());

        let asset = result.unwrap();
        assert_eq!(asset.asset_type, AssetType::Domain);
        assert_eq!(asset.identifier, "example.com");
        assert_eq!(asset.confidence, 0.8);
        assert_eq!(asset.sources, json!(["dns_scan"]));
    }

    #[tokio::test]
    async fn test_merge_existing_asset() {
        let pool = setup_test_db().await;
        let repo = SqlxAssetRepository::new(pool);

        // Create initial asset
        let asset_create1 = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.6,
            sources: json!(["dns_scan"]),
            metadata: json!({"ttl": 300}),
        };

        let initial_asset = repo.create_or_merge(&asset_create1).await.unwrap();

        // Create asset with same identifier but different data
        let asset_create2 = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.9, // Higher confidence
            sources: json!(["certificate_scan"]), // Different source
            metadata: json!({"issuer": "Let's Encrypt"}), // Additional metadata
        };

        let merged_asset = repo.create_or_merge(&asset_create2).await.unwrap();

        // Should be the same asset ID
        assert_eq!(merged_asset.id, initial_asset.id);
        
        // Should have higher confidence
        assert_eq!(merged_asset.confidence, 0.9);
        
        // Should have merged sources
        let sources = merged_asset.sources.as_array().unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&json!("dns_scan")));
        assert!(sources.contains(&json!("certificate_scan")));
        
        // Should have merged metadata
        let metadata = merged_asset.metadata.as_object().unwrap();
        assert_eq!(metadata.get("ttl").unwrap(), &json!(300));
        assert_eq!(metadata.get("issuer").unwrap(), &json!("Let's Encrypt"));
    }

    #[tokio::test]
    async fn test_list_assets() {
        let pool = setup_test_db().await;
        let repo = SqlxAssetRepository::new(pool);

        // Create assets with different confidence scores
        let asset1 = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "high-confidence.com".to_string(),
            confidence: 0.9,
            sources: json!(["dns_scan"]),
            metadata: json!({}),
        };

        let asset2 = AssetCreate {
            asset_type: AssetType::Ip,
            identifier: "192.168.1.1".to_string(),
            confidence: 0.5,
            sources: json!(["port_scan"]),
            metadata: json!({}),
        };

        let asset3 = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "low-confidence.com".to_string(),
            confidence: 0.3,
            sources: json!(["passive_dns"]),
            metadata: json!({}),
        };

        repo.create_or_merge(&asset1).await.unwrap();
        repo.create_or_merge(&asset2).await.unwrap();
        repo.create_or_merge(&asset3).await.unwrap();

        // Test listing all assets
        let all_assets = repo.list(None).await.unwrap();
        assert_eq!(all_assets.len(), 3);
        // Should be ordered by confidence DESC
        assert!(all_assets[0].confidence >= all_assets[1].confidence);
        assert!(all_assets[1].confidence >= all_assets[2].confidence);

        // Test listing with confidence threshold
        let high_confidence_assets = repo.list(Some(0.7)).await.unwrap();
        assert_eq!(high_confidence_assets.len(), 1);
        assert_eq!(high_confidence_assets[0].identifier, "high-confidence.com");

        let medium_confidence_assets = repo.list(Some(0.4)).await.unwrap();
        assert_eq!(medium_confidence_assets.len(), 2);
    }

    #[tokio::test]
    async fn test_list_by_type() {
        let pool = setup_test_db().await;
        let repo = SqlxAssetRepository::new(pool);

        // Create assets of different types
        let domain_asset = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.8,
            sources: json!(["dns_scan"]),
            metadata: json!({}),
        };

        let ip_asset = AssetCreate {
            asset_type: AssetType::Ip,
            identifier: "192.168.1.1".to_string(),
            confidence: 0.6,
            sources: json!(["port_scan"]),
            metadata: json!({}),
        };

        repo.create_or_merge(&domain_asset).await.unwrap();
        repo.create_or_merge(&ip_asset).await.unwrap();

        // Test listing by type
        let domain_assets = repo.list_by_type(AssetType::Domain, None).await.unwrap();
        assert_eq!(domain_assets.len(), 1);
        assert_eq!(domain_assets[0].asset_type, AssetType::Domain);

        let ip_assets = repo.list_by_type(AssetType::Ip, None).await.unwrap();
        assert_eq!(ip_assets.len(), 1);
        assert_eq!(ip_assets[0].asset_type, AssetType::Ip);

        // Test with confidence threshold
        let high_confidence_domains = repo.list_by_type(AssetType::Domain, Some(0.7)).await.unwrap();
        assert_eq!(high_confidence_domains.len(), 1);

        let high_confidence_ips = repo.list_by_type(AssetType::Ip, Some(0.7)).await.unwrap();
        assert_eq!(high_confidence_ips.len(), 0);
    }

    #[tokio::test]
    async fn test_get_by_identifier() {
        let pool = setup_test_db().await;
        let repo = SqlxAssetRepository::new(pool);

        let asset_create = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.8,
            sources: json!(["dns_scan"]),
            metadata: json!({}),
        };

        let created_asset = repo.create_or_merge(&asset_create).await.unwrap();

        // Test getting by identifier
        let found_asset = repo.get_by_identifier(AssetType::Domain, "example.com").await.unwrap();
        assert!(found_asset.is_some());
        assert_eq!(found_asset.unwrap().id, created_asset.id);

        // Test getting non-existent asset
        let not_found = repo.get_by_identifier(AssetType::Domain, "nonexistent.com").await.unwrap();
        assert!(not_found.is_none());

        // Test getting with wrong type
        let wrong_type = repo.get_by_identifier(AssetType::Ip, "example.com").await.unwrap();
        assert!(wrong_type.is_none());
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let pool = setup_test_db().await;
        let repo = SqlxAssetRepository::new(pool);

        let asset_create = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.8,
            sources: json!(["dns_scan"]),
            metadata: json!({}),
        };

        let created_asset = repo.create_or_merge(&asset_create).await.unwrap();

        // Test getting by ID
        let found_asset = repo.get_by_id(&created_asset.id).await.unwrap();
        assert!(found_asset.is_some());
        assert_eq!(found_asset.unwrap().identifier, "example.com");

        // Test getting non-existent asset
        let nonexistent_id = Uuid::new_v4();
        let not_found = repo.get_by_id(&nonexistent_id).await.unwrap();
        assert!(not_found.is_none());
    }
}

pub struct SqlxSeedRepository {
    pool: DatabasePool,
}

impl SqlxSeedRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    fn validate_seed_value(&self, seed_type: &SeedType, value: &str) -> Result<(), ApiError> {
        
        use ipnet::IpNet;

        match seed_type {
            SeedType::Domain => {
                // Basic domain validation - should contain at least one dot and valid characters
                if !value.contains('.') || value.is_empty() {
                    return Err(ApiError::Validation(format!("Invalid domain: {}", value)));
                }
                // More comprehensive domain validation could be added here
            }
            SeedType::Asn => {
                // ASN should be a number, optionally prefixed with "AS"
                let asn_str = value.strip_prefix("AS").unwrap_or(value);
                if asn_str.parse::<u32>().is_err() {
                    return Err(ApiError::Validation(format!("Invalid ASN: {}", value)));
                }
            }
            SeedType::Cidr => {
                // CIDR should be a valid IP network
                if value.parse::<IpNet>().is_err() {
                    return Err(ApiError::Validation(format!("Invalid CIDR: {}", value)));
                }
            }
            SeedType::Organization => {
                // Organization name should not be empty
                if value.trim().is_empty() {
                    return Err(ApiError::Validation("Organization name cannot be empty".to_string()));
                }
            }
            SeedType::Keyword => {
                // Keyword should not be empty
                if value.trim().is_empty() {
                    return Err(ApiError::Validation("Keyword cannot be empty".to_string()));
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl SeedRepository for SqlxSeedRepository {
    async fn create(&self, seed: &SeedCreate) -> Result<Seed, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        
        // Validate seed value based on type
        self.validate_seed_value(&seed.seed_type, &seed.value)?;
        
        let result = sqlx::query_as::<_, Seed>(
            r#"
            INSERT INTO seeds (id, seed_type, value, created_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, seed_type, value, created_at
            "#
        )
        .bind(id)
        .bind(&seed.seed_type)
        .bind(&seed.value)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list(&self) -> Result<Vec<Seed>, ApiError> {
        let results = sqlx::query_as::<_, Seed>(
            r#"
            SELECT id, seed_type, value, created_at
            FROM seeds
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn delete(&self, id: &Uuid) -> Result<(), ApiError> {
        let result = sqlx::query(
            r#"
            DELETE FROM seeds
            WHERE id = $1
            "#
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound(format!("Seed with id {} not found", id)));
        }

        Ok(())
    }

    async fn list_by_type(&self, seed_type: SeedType) -> Result<Vec<Seed>, ApiError> {
        let results = sqlx::query_as::<_, Seed>(
            r#"
            SELECT id, seed_type, value, created_at
            FROM seeds
            WHERE seed_type = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(seed_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn get_by_value(&self, seed_type: SeedType, value: &str) -> Result<Option<Seed>, ApiError> {
        let result = sqlx::query_as::<_, Seed>(
            r#"
            SELECT id, seed_type, value, created_at
            FROM seeds
            WHERE seed_type = $1 AND value = $2
            "#
        )
        .bind(seed_type)
        .bind(value)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }
}
#[cfg(test)]
mod seed_tests {
    use super::*;
    use crate::database::create_connection_pool;

    async fn setup_seed_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE seeds RESTART IDENTITY CASCADE").execute(&pool).await;
        pool
    }

    #[tokio::test]
    async fn test_create_seed() {
        let pool = setup_seed_test_db().await;
        let repo = SqlxSeedRepository::new(pool);

        let seed_create = SeedCreate {
            seed_type: SeedType::Domain,
            value: "example.com".to_string(),
        };

        let result = repo.create(&seed_create).await;
        assert!(result.is_ok());

        let seed = result.unwrap();
        assert_eq!(seed.seed_type, SeedType::Domain);
        assert_eq!(seed.value, "example.com");
    }

    #[tokio::test]
    async fn test_seed_validation() {
        let pool = setup_seed_test_db().await;
        let repo = SqlxSeedRepository::new(pool);

        // Test invalid domain
        let invalid_domain = SeedCreate {
            seed_type: SeedType::Domain,
            value: "invalid_domain".to_string(),
        };
        let result = repo.create(&invalid_domain).await;
        assert!(result.is_err());

        // Test invalid ASN
        let invalid_asn = SeedCreate {
            seed_type: SeedType::Asn,
            value: "not_a_number".to_string(),
        };
        let result = repo.create(&invalid_asn).await;
        assert!(result.is_err());

        // Test invalid CIDR
        let invalid_cidr = SeedCreate {
            seed_type: SeedType::Cidr,
            value: "not.a.cidr".to_string(),
        };
        let result = repo.create(&invalid_cidr).await;
        assert!(result.is_err());

        // Test valid ASN with AS prefix
        let valid_asn = SeedCreate {
            seed_type: SeedType::Asn,
            value: "AS12345".to_string(),
        };
        let result = repo.create(&valid_asn).await;
        assert!(result.is_ok());

        // Test valid CIDR
        let valid_cidr = SeedCreate {
            seed_type: SeedType::Cidr,
            value: "192.168.1.0/24".to_string(),
        };
        let result = repo.create(&valid_cidr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_seeds() {
        let pool = setup_seed_test_db().await;
        let repo = SqlxSeedRepository::new(pool);

        // Create seeds of different types
        let domain_seed = SeedCreate {
            seed_type: SeedType::Domain,
            value: "example.com".to_string(),
        };
        let asn_seed = SeedCreate {
            seed_type: SeedType::Asn,
            value: "12345".to_string(),
        };

        repo.create(&domain_seed).await.unwrap();
        repo.create(&asn_seed).await.unwrap();

        let all_seeds = repo.list().await.unwrap();
        assert_eq!(all_seeds.len(), 2);
    }

    #[tokio::test]
    async fn test_list_by_type() {
        let pool = setup_seed_test_db().await;
        let repo = SqlxSeedRepository::new(pool);

        // Create seeds of different types
        let domain_seed1 = SeedCreate {
            seed_type: SeedType::Domain,
            value: "example1.com".to_string(),
        };
        let domain_seed2 = SeedCreate {
            seed_type: SeedType::Domain,
            value: "example2.com".to_string(),
        };
        let asn_seed = SeedCreate {
            seed_type: SeedType::Asn,
            value: "12345".to_string(),
        };

        repo.create(&domain_seed1).await.unwrap();
        repo.create(&domain_seed2).await.unwrap();
        repo.create(&asn_seed).await.unwrap();

        let domain_seeds = repo.list_by_type(SeedType::Domain).await.unwrap();
        assert_eq!(domain_seeds.len(), 2);

        let asn_seeds = repo.list_by_type(SeedType::Asn).await.unwrap();
        assert_eq!(asn_seeds.len(), 1);
    }

    #[tokio::test]
    async fn test_get_by_value() {
        let pool = setup_seed_test_db().await;
        let repo = SqlxSeedRepository::new(pool);

        let seed_create = SeedCreate {
            seed_type: SeedType::Domain,
            value: "example.com".to_string(),
        };

        let created_seed = repo.create(&seed_create).await.unwrap();

        let found_seed = repo.get_by_value(SeedType::Domain, "example.com").await.unwrap();
        assert!(found_seed.is_some());
        assert_eq!(found_seed.unwrap().id, created_seed.id);

        let not_found = repo.get_by_value(SeedType::Domain, "nonexistent.com").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete_seed() {
        let pool = setup_seed_test_db().await;
        let repo = SqlxSeedRepository::new(pool);

        let seed_create = SeedCreate {
            seed_type: SeedType::Domain,
            value: "example.com".to_string(),
        };

        let created_seed = repo.create(&seed_create).await.unwrap();

        // Delete the seed
        let result = repo.delete(&created_seed.id).await;
        assert!(result.is_ok());

        // Verify it's deleted
        let seeds = repo.list().await.unwrap();
        assert_eq!(seeds.len(), 0);

        // Try to delete non-existent seed
        let nonexistent_id = Uuid::new_v4();
        let result = repo.delete(&nonexistent_id).await;
        assert!(result.is_err());
    }
}
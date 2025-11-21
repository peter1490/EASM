use async_trait::async_trait;
use elasticsearch::{
    Elasticsearch, 
    http::transport::Transport,
    indices::{IndicesCreateParts, IndicesExistsParts, IndicesDeleteParts},
    IndexParts, DeleteParts, SearchParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    config::Settings,
    error::ApiError,
    models::{Asset, Finding},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedAsset {
    pub id: String,
    pub asset_type: String,
    pub identifier: String,
    pub confidence: f64,
    pub sources: Value,
    pub metadata: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFinding {
    pub id: String,
    pub scan_id: String,
    pub finding_type: String,
    pub data: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    pub filters: HashMap<String, Value>,
    pub size: Option<usize>,
    pub from: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult<T> {
    pub hits: Vec<T>,
    pub total: u64,
    pub took: u64,
}

#[async_trait]
pub trait SearchService {
    async fn initialize_indices(&self) -> Result<(), ApiError>;
    async fn index_asset(&self, asset: &Asset) -> Result<(), ApiError>;
    async fn index_finding(&self, finding: &Finding) -> Result<(), ApiError>;
    async fn bulk_index_assets(&self, assets: &[Asset]) -> Result<(), ApiError>;
    async fn bulk_index_findings(&self, findings: &[Finding]) -> Result<(), ApiError>;
    async fn search_assets(&self, query: &SearchQuery) -> Result<SearchResult<IndexedAsset>, ApiError>;
    async fn search_findings(&self, query: &SearchQuery) -> Result<SearchResult<IndexedFinding>, ApiError>;
    async fn delete_asset(&self, asset_id: &Uuid) -> Result<(), ApiError>;
    async fn delete_finding(&self, finding_id: &Uuid) -> Result<(), ApiError>;
    async fn recreate_indices(&self) -> Result<(), ApiError>;
}

pub struct ElasticsearchService {
    client: Elasticsearch,
    asset_index: String,
    finding_index: String,
}

impl ElasticsearchService {
    pub fn new(settings: Arc<Settings>) -> Result<Self, ApiError> {
        let url = settings.elasticsearch_url.as_deref()
            .unwrap_or("http://localhost:9200");
        
        let transport = Transport::single_node(url)
            .map_err(|e| ApiError::internal(format!("Failed to create Elasticsearch transport: {}", e)))?;
        
        let client = Elasticsearch::new(transport);
        
        Ok(Self {
            client,
            asset_index: settings.elasticsearch_asset_index.clone()
                .unwrap_or_else(|| "easm_assets".to_string()),
            finding_index: settings.elasticsearch_finding_index.clone()
                .unwrap_or_else(|| "easm_findings".to_string()),
        })
    }

    async fn create_asset_index(&self) -> Result<(), ApiError> {
        let mapping = json!({
            "mappings": {
                "properties": {
                    "id": { "type": "keyword" },
                    "asset_type": { "type": "keyword" },
                    "identifier": { 
                        "type": "text",
                        "fields": {
                            "keyword": { "type": "keyword" }
                        }
                    },
                    "confidence": { "type": "float" },
                    "sources": { "type": "object" },
                    "metadata": { "type": "object" },
                    "created_at": { "type": "date" },
                    "updated_at": { "type": "date" }
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        });

        let response = self.client
            .indices()
            .create(IndicesCreateParts::Index(&self.asset_index))
            .body(mapping)
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to create asset index: {}", e)))?;

        if response.status_code().is_success() {
            tracing::info!("Created asset index: {}", self.asset_index);
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to create asset index: {}", error_text)))
        }
    }

    async fn create_finding_index(&self) -> Result<(), ApiError> {
        let mapping = json!({
            "mappings": {
                "properties": {
                    "id": { "type": "keyword" },
                    "scan_id": { "type": "keyword" },
                    "finding_type": { "type": "keyword" },
                    "data": { "type": "object" },
                    "created_at": { "type": "date" }
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        });

        let response = self.client
            .indices()
            .create(IndicesCreateParts::Index(&self.finding_index))
            .body(mapping)
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to create finding index: {}", e)))?;

        if response.status_code().is_success() {
            tracing::info!("Created finding index: {}", self.finding_index);
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to create finding index: {}", error_text)))
        }
    }

    async fn index_exists(&self, index_name: &str) -> Result<bool, ApiError> {
        let response = self.client
            .indices()
            .exists(IndicesExistsParts::Index(&[index_name]))
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to check index existence: {}", e)))?;

        Ok(response.status_code().is_success())
    }

    fn asset_to_indexed(&self, asset: &Asset) -> IndexedAsset {
        IndexedAsset {
            id: asset.id.to_string(),
            asset_type: format!("{:?}", asset.asset_type).to_lowercase(),
            identifier: asset.identifier.clone(),
            confidence: asset.confidence,
            sources: asset.sources.clone(),
            metadata: asset.metadata.clone(),
            created_at: asset.created_at.to_rfc3339(),
            updated_at: asset.updated_at.to_rfc3339(),
        }
    }

    fn finding_to_indexed(&self, finding: &Finding) -> IndexedFinding {
        IndexedFinding {
            id: finding.id.to_string(),
            scan_id: finding.scan_id.to_string(),
            finding_type: finding.finding_type.clone(),
            data: finding.data.clone(),
            created_at: finding.created_at.to_rfc3339(),
        }
    }


}

#[async_trait]
impl SearchService for ElasticsearchService {
    async fn initialize_indices(&self) -> Result<(), ApiError> {
        // Check if indices exist, create them if they don't
        if !self.index_exists(&self.asset_index).await? {
            self.create_asset_index().await?;
        }

        if !self.index_exists(&self.finding_index).await? {
            self.create_finding_index().await?;
        }

        Ok(())
    }

    async fn index_asset(&self, asset: &Asset) -> Result<(), ApiError> {
        let indexed_asset = self.asset_to_indexed(asset);
        
        let response = self.client
            .index(IndexParts::IndexId(&self.asset_index, &asset.id.to_string()))
            .body(indexed_asset)
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to index asset: {}", e)))?;

        if response.status_code().is_success() {
            tracing::debug!("Indexed asset: {}", asset.id);
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to index asset: {}", error_text)))
        }
    }

    async fn index_finding(&self, finding: &Finding) -> Result<(), ApiError> {
        let indexed_finding = self.finding_to_indexed(finding);
        
        let response = self.client
            .index(IndexParts::IndexId(&self.finding_index, &finding.id.to_string()))
            .body(indexed_finding)
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to index finding: {}", e)))?;

        if response.status_code().is_success() {
            tracing::debug!("Indexed finding: {}", finding.id);
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to index finding: {}", error_text)))
        }
    }

    async fn bulk_index_assets(&self, assets: &[Asset]) -> Result<(), ApiError> {
        if assets.is_empty() {
            return Ok(());
        }

        // For now, index assets one by one
        for asset in assets {
            self.index_asset(asset).await?;
        }

        tracing::info!("Bulk indexed {} assets", assets.len());
        Ok(())
    }

    async fn bulk_index_findings(&self, findings: &[Finding]) -> Result<(), ApiError> {
        if findings.is_empty() {
            return Ok(());
        }

        // For now, index findings one by one
        for finding in findings {
            self.index_finding(finding).await?;
        }

        tracing::info!("Bulk indexed {} findings", findings.len());
        Ok(())
    }

    async fn search_assets(&self, query: &SearchQuery) -> Result<SearchResult<IndexedAsset>, ApiError> {
        let mut search_body = json!({
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query.query,
                                "fields": ["identifier^2", "metadata.*", "sources.*"]
                            }
                        }
                    ]
                }
            }
        });

        // Add filters
        if !query.filters.is_empty() {
            let mut filter_clauses = Vec::new();
            for (field, value) in &query.filters {
                filter_clauses.push(json!({
                    "term": { field: value }
                }));
            }
            search_body["query"]["bool"]["filter"] = json!(filter_clauses);
        }

        // Add pagination
        if let Some(size) = query.size {
            search_body["size"] = json!(size);
        }
        if let Some(from) = query.from {
            search_body["from"] = json!(from);
        }

        let response = self.client
            .search(SearchParts::Index(&[&self.asset_index]))
            .body(search_body)
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to search assets: {}", e)))?;

        if response.status_code().is_success() {
            let response_body: Value = response.json().await
                .map_err(|e| ApiError::external_service(format!("Failed to parse search response: {}", e)))?;

            let hits = response_body["hits"]["hits"].as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|hit| {
                    serde_json::from_value(hit["_source"].clone()).ok()
                })
                .collect();

            let total = response_body["hits"]["total"]["value"].as_u64().unwrap_or(0);
            let took = response_body["took"].as_u64().unwrap_or(0);

            Ok(SearchResult { hits, total, took })
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to search assets: {}", error_text)))
        }
    }

    async fn search_findings(&self, query: &SearchQuery) -> Result<SearchResult<IndexedFinding>, ApiError> {
        let mut search_body = json!({
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query.query,
                                "fields": ["finding_type^2", "data.*"]
                            }
                        }
                    ]
                }
            }
        });

        // Add filters
        if !query.filters.is_empty() {
            let mut filter_clauses = Vec::new();
            for (field, value) in &query.filters {
                filter_clauses.push(json!({
                    "term": { field: value }
                }));
            }
            search_body["query"]["bool"]["filter"] = json!(filter_clauses);
        }

        // Add pagination
        if let Some(size) = query.size {
            search_body["size"] = json!(size);
        }
        if let Some(from) = query.from {
            search_body["from"] = json!(from);
        }

        let response = self.client
            .search(SearchParts::Index(&[&self.finding_index]))
            .body(search_body)
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to search findings: {}", e)))?;

        if response.status_code().is_success() {
            let response_body: Value = response.json().await
                .map_err(|e| ApiError::external_service(format!("Failed to parse search response: {}", e)))?;

            let hits = response_body["hits"]["hits"].as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|hit| {
                    serde_json::from_value(hit["_source"].clone()).ok()
                })
                .collect();

            let total = response_body["hits"]["total"]["value"].as_u64().unwrap_or(0);
            let took = response_body["took"].as_u64().unwrap_or(0);

            Ok(SearchResult { hits, total, took })
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to search findings: {}", error_text)))
        }
    }

    async fn delete_asset(&self, asset_id: &Uuid) -> Result<(), ApiError> {
        let response = self.client
            .delete(DeleteParts::IndexId(&self.asset_index, &asset_id.to_string()))
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to delete asset from index: {}", e)))?;

        if response.status_code().is_success() {
            tracing::debug!("Deleted asset from index: {}", asset_id);
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to delete asset from index: {}", error_text)))
        }
    }

    async fn delete_finding(&self, finding_id: &Uuid) -> Result<(), ApiError> {
        let response = self.client
            .delete(DeleteParts::IndexId(&self.finding_index, &finding_id.to_string()))
            .send()
            .await
            .map_err(|e| ApiError::external_service(format!("Failed to delete finding from index: {}", e)))?;

        if response.status_code().is_success() {
            tracing::debug!("Deleted finding from index: {}", finding_id);
            Ok(())
        } else {
            let error_text = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(ApiError::external_service(format!("Failed to delete finding from index: {}", error_text)))
        }
    }

    async fn recreate_indices(&self) -> Result<(), ApiError> {
        // Delete existing indices
        for index in [&self.asset_index, &self.finding_index] {
            if self.index_exists(index).await? {
                let response = self.client
                    .indices()
                    .delete(IndicesDeleteParts::Index(&[index]))
                    .send()
                    .await
                    .map_err(|e| ApiError::external_service(format!("Failed to delete index {}: {}", index, e)))?;

                if response.status_code().is_success() {
                    tracing::info!("Deleted index: {}", index);
                } else {
                    let error_text = response.text().await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    return Err(ApiError::external_service(format!("Failed to delete index {}: {}", index, error_text)));
                }
            }
        }

        // Recreate indices
        self.initialize_indices().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AssetType;
    use chrono::Utc;
    use serde_json::json;

    fn create_test_settings() -> Settings {
        crate::config::Settings::new_with_env_file(false).unwrap()
    }

    fn create_test_asset() -> Asset {
        Asset {
            id: Uuid::new_v4(),
            asset_type: AssetType::Domain,
            identifier: "example.com".to_string(),
            confidence: 0.95,
            sources: json!({"crt.sh": true}),
            metadata: json!({"organization": "Example Corp"}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            seed_id: None,
            parent_id: None,
            last_scan_id: None,
            last_scan_status: None,
            last_scanned_at: None,
        }
    }

    fn create_test_finding() -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scan_id: Uuid::new_v4(),
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80, "service": "http"}),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_asset_to_indexed_conversion() {
        let settings = Arc::new(create_test_settings());
        let service = ElasticsearchService::new(settings).unwrap();
        let asset = create_test_asset();
        
        let indexed = service.asset_to_indexed(&asset);
        
        assert_eq!(indexed.id, asset.id.to_string());
        assert_eq!(indexed.asset_type, "domain");
        assert_eq!(indexed.identifier, asset.identifier);
        assert_eq!(indexed.confidence, asset.confidence);
    }

    #[tokio::test]
    async fn test_finding_to_indexed_conversion() {
        let settings = Arc::new(create_test_settings());
        let service = ElasticsearchService::new(settings).unwrap();
        let finding = create_test_finding();
        
        let indexed = service.finding_to_indexed(&finding);
        
        assert_eq!(indexed.id, finding.id.to_string());
        assert_eq!(indexed.scan_id, finding.scan_id.to_string());
        assert_eq!(indexed.finding_type, finding.finding_type);
        assert_eq!(indexed.data, finding.data);
    }

    #[tokio::test]
    async fn test_search_query_creation() {
        let mut filters = HashMap::new();
        filters.insert("asset_type".to_string(), json!("domain"));
        
        let query = SearchQuery {
            query: "example.com".to_string(),
            filters,
            size: Some(10),
            from: Some(0),
        };
        
        assert_eq!(query.query, "example.com");
        assert_eq!(query.size, Some(10));
        assert_eq!(query.from, Some(0));
        assert!(query.filters.contains_key("asset_type"));
    }

    // Note: Integration tests with actual Elasticsearch would require a running instance
    // For now, we'll focus on unit tests for the conversion logic and query building
}
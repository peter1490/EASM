use axum::{
    extract::{Extension, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    auth::context::UserContext,
    error::ApiError,
    services::{IndexedAsset, IndexedFinding, SearchQuery},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
    pub size: Option<usize>,
    pub from: Option<usize>,
    #[serde(flatten)]
    pub filters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse<T> {
    pub results: Vec<T>,
    pub total: u64,
    pub took: u64,
    pub query: String,
}

/// Search assets using Elasticsearch
pub async fn search_assets(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse<IndexedAsset>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let search_service = app_state
        .search_service
        .as_ref()
        .ok_or_else(|| ApiError::not_found("Search service not available"))?;

    let query = SearchQuery {
        query: params.q.clone(),
        filters: params.filters,
        size: params.size,
        from: params.from,
    };

    let result = search_service.search_assets(company_id, &query).await?;

    Ok(Json(SearchResponse {
        results: result.hits,
        total: result.total,
        took: result.took,
        query: params.q,
    }))
}

/// Search findings using Elasticsearch
pub async fn search_findings(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse<IndexedFinding>>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let search_service = app_state
        .search_service
        .as_ref()
        .ok_or_else(|| ApiError::not_found("Search service not available"))?;

    let query = SearchQuery {
        query: params.q.clone(),
        filters: params.filters,
        size: params.size,
        from: params.from,
    };

    let result = search_service.search_findings(company_id, &query).await?;

    Ok(Json(SearchResponse {
        results: result.hits,
        total: result.total,
        took: result.took,
        query: params.q,
    }))
}

/// Reindex all assets and findings
pub async fn reindex_all(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let search_service = app_state
        .search_service
        .as_ref()
        .ok_or_else(|| ApiError::not_found("Search service not available"))?;

    // Recreate indices
    search_service.recreate_indices().await?;

    // Get all assets and findings from database for this company (no limit for reindexing)
    let assets = app_state
        .asset_repository
        .list(company_id, None, Some(100000), None)
        .await?;
    let findings = app_state
        .finding_repository
        .list_by_type("", company_id)
        .await?; // Get all findings

    // Bulk index them
    if !assets.is_empty() {
        search_service.bulk_index_assets(&assets).await?;
    }

    if !findings.is_empty() {
        search_service.bulk_index_findings(&findings).await?;
    }

    Ok(Json(serde_json::json!({
        "message": "Reindexing completed",
        "assets_indexed": assets.len(),
        "findings_indexed": findings.len()
    })))
}

/// Get search service status
pub async fn search_status(
    State(app_state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let search_available = app_state.search_service.is_some();

    if search_available {
        // Try to initialize indices to check connectivity
        let search_service = app_state.search_service.as_ref().unwrap();
        match search_service.initialize_indices().await {
            Ok(_) => Ok(Json(serde_json::json!({
                "status": "healthy",
                "search_available": true,
                "message": "Search service is operational"
            }))),
            Err(e) => Ok(Json(serde_json::json!({
                "status": "unhealthy",
                "search_available": true,
                "message": format!("Search service error: {}", e)
            }))),
        }
    } else {
        Ok(Json(serde_json::json!({
            "status": "disabled",
            "search_available": false,
            "message": "Search service not configured"
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_search_params_parsing() {
        let params = SearchParams {
            q: "example.com".to_string(),
            size: Some(10),
            from: Some(0),
            filters: {
                let mut filters = HashMap::new();
                filters.insert("asset_type".to_string(), json!("domain"));
                filters
            },
        };

        assert_eq!(params.q, "example.com");
        assert_eq!(params.size, Some(10));
        assert_eq!(params.from, Some(0));
        assert!(params.filters.contains_key("asset_type"));
    }

    #[test]
    fn test_search_response_creation() {
        let response: SearchResponse<IndexedAsset> = SearchResponse {
            results: vec![],
            total: 0,
            took: 10,
            query: "test".to_string(),
        };

        assert_eq!(response.query, "test");
        assert_eq!(response.total, 0);
        assert_eq!(response.took, 10);
        assert!(response.results.is_empty());
    }
}

use axum::{
    extract::{Query, State},
    response::Json,
};
use serde::Deserialize;

use crate::{
    error::ApiError,
    models::{FindingFilter, FindingListResponse},
    AppState,
};

/// Query parameters for finding filter endpoint
#[derive(Debug, Deserialize)]
pub struct FindingFilterParams {
    /// Filter by finding types (comma-separated)
    #[serde(default)]
    pub finding_types: Option<String>,
    
    /// Filter by scan IDs (comma-separated UUIDs)
    #[serde(default)]
    pub scan_ids: Option<String>,
    
    /// Filter by date range - from (ISO 8601)
    #[serde(default)]
    pub created_after: Option<String>,
    
    /// Filter by date range - to (ISO 8601)
    #[serde(default)]
    pub created_before: Option<String>,
    
    /// Text search in finding_type and data fields
    #[serde(default)]
    pub search_text: Option<String>,
    
    /// Sort field (created_at, finding_type)
    #[serde(default)]
    pub sort_by: Option<String>,
    
    /// Sort direction (asc, desc)
    #[serde(default)]
    pub sort_direction: Option<String>,
    
    /// Pagination - limit
    #[serde(default)]
    pub limit: Option<i64>,
    
    /// Pagination - offset
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Filter findings with advanced criteria
pub async fn filter_findings(
    State(app_state): State<AppState>,
    Query(params): Query<FindingFilterParams>,
) -> Result<Json<FindingListResponse>, ApiError> {
    // Parse finding types
    let finding_types = params.finding_types
        .map(|types| types.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>());
    
    // Parse scan IDs
    let scan_ids = if let Some(scan_ids_str) = params.scan_ids {
        let parsed_ids: Result<Vec<uuid::Uuid>, _> = scan_ids_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse())
            .collect();
        
        match parsed_ids {
            Ok(ids) => Some(ids),
            Err(e) => {
                return Err(ApiError::Validation(format!("Invalid scan ID format: {}", e)));
            }
        }
    } else {
        None
    };
    
    // Parse dates
    let created_after = if let Some(date_str) = params.created_after {
        match chrono::DateTime::parse_from_rfc3339(&date_str) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(e) => {
                return Err(ApiError::Validation(format!("Invalid created_after date format: {}. Use ISO 8601 format.", e)));
            }
        }
    } else {
        None
    };
    
    let created_before = if let Some(date_str) = params.created_before {
        match chrono::DateTime::parse_from_rfc3339(&date_str) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(e) => {
                return Err(ApiError::Validation(format!("Invalid created_before date format: {}. Use ISO 8601 format.", e)));
            }
        }
    } else {
        None
    };
    
    // Build filter
    let filter = FindingFilter {
        finding_types: finding_types.filter(|v| !v.is_empty()),
        scan_ids: scan_ids.filter(|v| !v.is_empty()),
        created_after,
        created_before,
        search_text: params.search_text.filter(|s| !s.is_empty()),
        data_filters: None, // Can be extended for JSONB path queries
        sort_by: params.sort_by.unwrap_or_else(|| "created_at".to_string()),
        sort_direction: params.sort_direction.unwrap_or_else(|| "desc".to_string()),
        limit: params.limit.unwrap_or(100),
        offset: params.offset.unwrap_or(0),
    };
    
    let result = app_state.finding_repository.filter(&filter).await?;
    
    Ok(Json(result))
}

/// Get all distinct finding types for filter UI
pub async fn get_finding_types(
    State(app_state): State<AppState>,
) -> Result<Json<Vec<String>>, ApiError> {
    // Query to get distinct finding types
    let types = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT finding_type FROM findings ORDER BY finding_type"
    )
    .fetch_all(&app_state.db_pool)
    .await?;
    
    Ok(Json(types))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_finding_filter_params_parsing() {
        // Test comma-separated finding types
        let types = "port_scan,dns_resolution,http_probe";
        let parsed: Vec<String> = types.split(',')
            .map(|s| s.trim().to_string())
            .collect();
        
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], "port_scan");
        assert_eq!(parsed[1], "dns_resolution");
        assert_eq!(parsed[2], "http_probe");
    }

    #[test]
    fn test_scan_ids_parsing() {
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let ids_str = format!("{},{}", id1, id2);
        
        let parsed: Result<Vec<uuid::Uuid>, _> = ids_str
            .split(',')
            .map(|s| s.trim().parse())
            .collect();
        
        assert!(parsed.is_ok());
        let ids = parsed.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], id1);
        assert_eq!(ids[1], id2);
    }

    #[test]
    fn test_date_parsing() {
        let date_str = "2024-01-01T00:00:00Z";
        let parsed = chrono::DateTime::parse_from_rfc3339(date_str);
        
        assert!(parsed.is_ok());
    }
}


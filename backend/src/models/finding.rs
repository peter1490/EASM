use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub finding_type: String,
    pub data: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingCreate {
    pub scan_id: Uuid,
    pub finding_type: String,
    pub data: Value,
}

/// Advanced filter criteria for finding search
#[derive(Debug, Clone, Deserialize)]
pub struct FindingFilter {
    /// Filter by finding types (e.g., "port_scan", "dns_resolution")
    #[serde(default)]
    pub finding_types: Option<Vec<String>>,
    
    /// Filter by scan IDs
    #[serde(default)]
    pub scan_ids: Option<Vec<Uuid>>,
    
    /// Filter by date range - from
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,
    
    /// Filter by date range - to
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,
    
    /// Text search in finding_type and data fields
    #[serde(default)]
    pub search_text: Option<String>,
    
    /// Filter by specific data field values (JSONB path queries)
    /// Example: {"data.port": "443", "data.is_malicious": "true"}
    #[serde(default)]
    pub data_filters: Option<serde_json::Map<String, Value>>,
    
    /// Sort field (created_at, finding_type)
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    
    /// Sort direction (asc, desc)
    #[serde(default = "default_sort_direction")]
    pub sort_direction: String,
    
    /// Pagination - limit
    #[serde(default = "default_limit")]
    pub limit: i64,
    
    /// Pagination - offset
    #[serde(default)]
    pub offset: i64,
}

fn default_sort_by() -> String {
    "created_at".to_string()
}

fn default_sort_direction() -> String {
    "desc".to_string()
}

fn default_limit() -> i64 {
    100
}

impl Default for FindingFilter {
    fn default() -> Self {
        Self {
            finding_types: None,
            scan_ids: None,
            created_after: None,
            created_before: None,
            search_text: None,
            data_filters: None,
            sort_by: default_sort_by(),
            sort_direction: default_sort_direction(),
            limit: default_limit(),
            offset: 0,
        }
    }
}

/// Response for paginated findings
#[derive(Debug, Clone, Serialize)]
pub struct FindingListResponse {
    pub findings: Vec<Finding>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}
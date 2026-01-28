use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "asset_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    Domain,
    Ip,
    Port,
    Certificate,
    Organization,
    Asn,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::Domain => write!(f, "domain"),
            AssetType::Ip => write!(f, "ip"),
            AssetType::Port => write!(f, "port"),
            AssetType::Certificate => write!(f, "certificate"),
            AssetType::Organization => write!(f, "organization"),
            AssetType::Asn => write!(f, "asn"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "seed_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SeedType {
    #[serde(alias = "root_domain", alias = "acquisition_domain")]
    Domain,
    Asn,
    Cidr,
    Organization,
    Keyword,
}

impl std::fmt::Display for SeedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedType::Domain => write!(f, "domain"),
            SeedType::Asn => write!(f, "asn"),
            SeedType::Cidr => write!(f, "cidr"),
            SeedType::Organization => write!(f, "organization"),
            SeedType::Keyword => write!(f, "keyword"),
        }
    }
}

/// Asset lifecycle status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetStatus {
    /// Asset is active and recently confirmed
    Active,
    /// Asset hasn't been seen in a while
    Stale,
    /// Asset was removed or is no longer accessible
    Removed,
    /// Asset discovery is pending verification
    Pending,
}

impl Default for AssetStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for AssetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetStatus::Active => write!(f, "active"),
            AssetStatus::Stale => write!(f, "stale"),
            AssetStatus::Removed => write!(f, "removed"),
            AssetStatus::Pending => write!(f, "pending"),
        }
    }
}

impl From<&str> for AssetStatus {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "active" => AssetStatus::Active,
            "stale" => AssetStatus::Stale,
            "removed" => AssetStatus::Removed,
            "pending" => AssetStatus::Pending,
            _ => AssetStatus::Active,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub asset_type: AssetType,
    #[serde(rename = "value")]
    pub identifier: String,
    #[serde(rename = "ownership_confidence")]
    pub confidence: f64,
    pub sources: Value,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub seed_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub company_id: Uuid,

    // Lifecycle tracking (new fields)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_discovery_run_id: Option<Uuid>,
    #[serde(default)]
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_method: Option<String>,

    // Risk related fields
    #[serde(default)]
    pub importance: i32,
    pub risk_score: Option<f64>,
    pub risk_level: Option<String>,
    pub last_risk_run: Option<DateTime<Utc>>,

    // Security scan tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scanned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AssetRow {
    pub id: Uuid,
    pub asset_type: AssetType,
    pub identifier: String,
    pub confidence: f64,
    pub sources: Value,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[sqlx(default)]
    pub seed_id: Option<Uuid>,
    #[sqlx(default)]
    pub parent_id: Option<Uuid>,
    pub company_id: Uuid,
    // Lifecycle fields
    #[sqlx(default)]
    pub first_seen_at: Option<DateTime<Utc>>,
    #[sqlx(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[sqlx(default)]
    pub last_discovery_run_id: Option<Uuid>,
    #[sqlx(default)]
    pub status: Option<String>,
    #[sqlx(default)]
    pub discovery_method: Option<String>,
    // Risk fields
    #[sqlx(default)]
    pub importance: i32,
    #[sqlx(default)]
    pub risk_score: Option<f64>,
    #[sqlx(default)]
    pub risk_level: Option<String>,
    #[sqlx(default)]
    pub last_risk_run: Option<DateTime<Utc>>,
    // Scan tracking (computed from joins)
    #[sqlx(default)]
    pub last_scan_id: Option<Uuid>,
    #[sqlx(default)]
    pub last_scan_status: Option<String>,
    #[sqlx(default)]
    pub last_scanned_at: Option<DateTime<Utc>>,
}

impl From<AssetRow> for Asset {
    fn from(row: AssetRow) -> Self {
        Self {
            id: row.id,
            asset_type: row.asset_type,
            identifier: row.identifier,
            confidence: row.confidence,
            sources: row.sources,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
            seed_id: row.seed_id,
            parent_id: row.parent_id,
            company_id: row.company_id,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            last_discovery_run_id: row.last_discovery_run_id,
            status: row.status.unwrap_or_else(|| "active".to_string()),
            discovery_method: row.discovery_method,
            importance: row.importance,
            risk_score: row.risk_score,
            risk_level: row.risk_level,
            last_risk_run: row.last_risk_run,
            last_scan_id: row.last_scan_id.map(|id| id.to_string()),
            last_scan_status: row.last_scan_status,
            last_scanned_at: row.last_scanned_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seed {
    pub id: Uuid,
    pub seed_type: SeedType,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct AssetRiskHistoryEntry {
    pub risk_score: f64,
    pub risk_level: String,
    pub factors: Value,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetScanHistoryEntry {
    pub id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result_summary: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetEvolutionResponse {
    pub risk_history: Vec<AssetRiskHistoryEntry>,
    pub scan_history: Vec<AssetScanHistoryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetCreate {
    pub asset_type: AssetType,
    pub identifier: String,
    pub confidence: f64,
    pub sources: Value,
    pub metadata: Value,
    pub seed_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    // New optional fields
    #[serde(default)]
    pub discovery_run_id: Option<Uuid>,
    #[serde(default)]
    pub discovery_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetUpdate {
    pub confidence: Option<f64>,
    pub metadata: Option<Value>,
    pub importance: Option<i32>,
    pub status: Option<AssetStatus>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeedCreate {
    pub seed_type: SeedType,
    pub value: String,
    pub note: Option<String>,
}

/// Filter criteria for asset queries
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AssetFilter {
    #[serde(default)]
    pub asset_types: Option<Vec<AssetType>>,
    #[serde(default)]
    pub statuses: Option<Vec<String>>,
    #[serde(default)]
    pub min_confidence: Option<f64>,
    #[serde(default)]
    pub max_confidence: Option<f64>,
    #[serde(default)]
    pub min_importance: Option<i32>,
    #[serde(default)]
    pub search_text: Option<String>,
    #[serde(default)]
    pub seed_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub discovery_run_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub has_findings: Option<bool>,
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    #[serde(default = "default_sort_direction")]
    pub sort_direction: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_sort_by() -> String {
    "importance".to_string()
}

fn default_sort_direction() -> String {
    "desc".to_string()
}

fn default_limit() -> i64 {
    100
}

/// Response for paginated assets
#[derive(Debug, Clone, Serialize)]
pub struct AssetListResponse {
    pub assets: Vec<Asset>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Asset summary for dashboard/overview
#[derive(Debug, Clone, Serialize)]
pub struct AssetSummary {
    pub total_assets: i64,
    pub by_type: std::collections::HashMap<String, i64>,
    pub by_status: std::collections::HashMap<String, i64>,
    pub high_confidence_count: i64,
    pub with_findings_count: i64,
    pub recent_discoveries: i64,
}

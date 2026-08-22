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

/// Open findings rolled up per asset.
///
/// Without this a list has to issue one findings request per row: at the
/// default page size that is 26 requests to draw one table, each dragging the
/// full `data` JSONB back with it. It is computed in the same CTE that already
/// resolves each asset's latest scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct OpenFindingCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub total: i64,
}

impl OpenFindingCounts {
    /// Worst severity present, or `None` when the asset is clean.
    pub fn worst_severity(&self) -> Option<&'static str> {
        if self.critical > 0 {
            Some("critical")
        } else if self.high > 0 {
            Some("high")
        } else if self.medium > 0 {
            Some("medium")
        } else if self.low > 0 {
            Some("low")
        } else if self.info > 0 {
            Some("info")
        } else {
            None
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
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
    /// The newest scan that was cancelled, whatever the outcome of the others.
    /// The list falls back to it when `last_scanned_at` is absent, so a stopped
    /// scan reads "Cancelled" rather than as an asset nobody ever looked at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_cancelled_scan_at: Option<DateTime<Utc>>,

    /// Absent where the query does not compute it (`get_path`), so a client can
    /// distinguish "not loaded" from "no open findings".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_findings: Option<OpenFindingCounts>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AssetRow {
    pub id: Uuid,
    pub asset_type: AssetType,
    pub identifier: String,
    pub confidence: f64,
    pub sources: Value,
    pub metadata: Value,
    #[sqlx(default)]
    pub comment: Option<String>,
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
    #[sqlx(default)]
    pub last_cancelled_scan_at: Option<DateTime<Utc>>,
    // Finding rollup (computed in the same CTE as the latest scan)
    #[sqlx(default)]
    pub open_critical: Option<i64>,
    #[sqlx(default)]
    pub open_high: Option<i64>,
    #[sqlx(default)]
    pub open_medium: Option<i64>,
    #[sqlx(default)]
    pub open_low: Option<i64>,
    #[sqlx(default)]
    pub open_info: Option<i64>,
    #[sqlx(default)]
    pub open_total: Option<i64>,
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
            comment: row.comment,
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
            last_cancelled_scan_at: row.last_cancelled_scan_at,
            // Only queries that select the rollup produce `open_total`; the
            // rest leave the whole object off the wire.
            open_findings: row.open_total.map(|total| OpenFindingCounts {
                critical: row.open_critical.unwrap_or(0),
                high: row.open_high.unwrap_or(0),
                medium: row.open_medium.unwrap_or(0),
                low: row.open_low.unwrap_or(0),
                info: row.open_info.unwrap_or(0),
                total,
            }),
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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, sqlx::Type, Serialize, Deserialize)]
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
    // Risk related fields
    #[serde(default)]
    pub importance: i32,
    pub risk_score: Option<f64>,
    pub risk_level: Option<String>,
    pub last_risk_run: Option<DateTime<Utc>>,
    // Optional fields for frontend compatibility (not in DB yet)
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
    #[sqlx(default)]
    pub importance: i32,
    #[sqlx(default)]
    pub risk_score: Option<f64>,
    #[sqlx(default)]
    pub risk_level: Option<String>,
    #[sqlx(default)]
    pub last_risk_run: Option<DateTime<Utc>>,
    #[sqlx(default)]
    pub last_scan_id: Option<Uuid>,
    #[sqlx(default)]
    pub last_scan_status: Option<String>, // Using String since ScanStatus enum might need sqlx Type impl
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeedCreate {
    pub seed_type: SeedType,
    pub value: String,
    pub note: Option<String>,
}

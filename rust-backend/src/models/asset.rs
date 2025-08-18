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

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Seed {
    pub id: Uuid,
    pub seed_type: SeedType,
    pub value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AssetCreate {
    pub asset_type: AssetType,
    pub identifier: String,
    pub confidence: f64,
    pub sources: Value,
    pub metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeedCreate {
    pub seed_type: SeedType,
    pub value: String,
}
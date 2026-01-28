use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of object that can be blacklisted
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlacklistObjectType {
    Domain,
    Ip,
    Organization,
    Asn,
    Cidr,
    Certificate,
}

impl std::fmt::Display for BlacklistObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlacklistObjectType::Domain => write!(f, "domain"),
            BlacklistObjectType::Ip => write!(f, "ip"),
            BlacklistObjectType::Organization => write!(f, "organization"),
            BlacklistObjectType::Asn => write!(f, "asn"),
            BlacklistObjectType::Cidr => write!(f, "cidr"),
            BlacklistObjectType::Certificate => write!(f, "certificate"),
        }
    }
}

impl From<&str> for BlacklistObjectType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "domain" => BlacklistObjectType::Domain,
            "ip" => BlacklistObjectType::Ip,
            "organization" | "org" => BlacklistObjectType::Organization,
            "asn" => BlacklistObjectType::Asn,
            "cidr" => BlacklistObjectType::Cidr,
            "certificate" | "cert" => BlacklistObjectType::Certificate,
            _ => BlacklistObjectType::Domain, // Default fallback
        }
    }
}

/// A blacklist entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BlacklistEntry {
    pub id: Uuid,
    pub object_type: String,
    pub object_value: String,
    pub company_id: Uuid,
    pub reason: Option<String>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a blacklist entry
#[derive(Debug, Clone, Deserialize)]
pub struct BlacklistCreate {
    pub object_type: BlacklistObjectType,
    pub object_value: String,
    pub reason: Option<String>,
    /// If true, delete all descendant assets discovered from this object
    #[serde(default)]
    pub delete_descendants: bool,
}

/// Request to update a blacklist entry
#[derive(Debug, Clone, Deserialize)]
pub struct BlacklistUpdate {
    pub reason: Option<String>,
}

/// Result of a blacklist operation that includes cascade deletion
#[derive(Debug, Clone, Serialize)]
pub struct BlacklistResult {
    pub entry: BlacklistEntry,
    pub descendants_deleted: i64,
}

/// Check result for blacklist status
#[derive(Debug, Clone, Serialize)]
pub struct BlacklistCheckResult {
    pub is_blacklisted: bool,
    pub entry: Option<BlacklistEntry>,
    /// For domains, indicates if a parent domain is blacklisted
    pub parent_blacklisted: bool,
    pub parent_entry: Option<BlacklistEntry>,
}

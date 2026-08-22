use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of object that can be excluded
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExclusionObjectType {
    Domain,
    Ip,
    Organization,
    Asn,
    Cidr,
    Certificate,
}

impl std::fmt::Display for ExclusionObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExclusionObjectType::Domain => write!(f, "domain"),
            ExclusionObjectType::Ip => write!(f, "ip"),
            ExclusionObjectType::Organization => write!(f, "organization"),
            ExclusionObjectType::Asn => write!(f, "asn"),
            ExclusionObjectType::Cidr => write!(f, "cidr"),
            ExclusionObjectType::Certificate => write!(f, "certificate"),
        }
    }
}

impl From<&str> for ExclusionObjectType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "domain" => ExclusionObjectType::Domain,
            "ip" => ExclusionObjectType::Ip,
            "organization" | "org" => ExclusionObjectType::Organization,
            "asn" => ExclusionObjectType::Asn,
            "cidr" => ExclusionObjectType::Cidr,
            "certificate" | "cert" => ExclusionObjectType::Certificate,
            _ => ExclusionObjectType::Domain, // Default fallback
        }
    }
}

/// An exclusion entry.
///
/// Two strengths live in one row. An ordinary exclusion tells discovery to stop
/// *growing* the estate here: nothing new is written for the object or anything
/// under it, but whatever was already found stays, keeps its findings, keeps
/// counting towards the score, and is still auto-scanned by later runs. A
/// `blacklisted` entry is the hard one: the matching assets are deleted and
/// never written again, so the object reaches no score, no scan and no list.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExclusionEntry {
    pub id: Uuid,
    pub object_type: String,
    pub object_value: String,
    pub company_id: Uuid,
    pub reason: Option<String>,
    pub created_by: Option<String>,
    /// Hard mode: purge what matches and keep it out for good.
    pub blacklisted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an exclusion entry
#[derive(Debug, Clone, Deserialize)]
pub struct ExclusionCreate {
    pub object_type: ExclusionObjectType,
    pub object_value: String,
    pub reason: Option<String>,
    /// If true, delete all descendant assets discovered from this object
    #[serde(default)]
    pub delete_descendants: bool,
    /// If true, also delete the matching assets themselves and keep discovery
    /// from ever storing them again. Off unless asked for: excluding is the
    /// reversible half of this feature and deleting is not.
    #[serde(default)]
    pub blacklisted: bool,
}

/// Request to update an exclusion entry
#[derive(Debug, Clone, Deserialize)]
pub struct ExclusionUpdate {
    pub reason: Option<String>,
    /// Promote an exclusion to a blacklist, or demote it back. Promoting purges
    /// what the entry matches; demoting only stops the rule, since what was
    /// already deleted is gone.
    pub blacklisted: Option<bool>,
}

/// Result of an exclusion operation that includes cascade deletion
#[derive(Debug, Clone, Serialize)]
pub struct ExclusionResult {
    pub entry: ExclusionEntry,
    pub descendants_deleted: i64,
    /// Assets deleted because the entry blacklists them: the objects the entry
    /// names, plus everything discovered through them. Zero for an ordinary
    /// exclusion, which deletes nothing on its own.
    #[serde(default)]
    pub assets_deleted: i64,
    /// Queued discovery items the new entry removed from a run in progress.
    #[serde(default)]
    pub queue_items_removed: i64,
    /// Security scans stopped because their target is now blacklisted.
    #[serde(default)]
    pub scans_cancelled: i64,
}

/// Check result for exclusion status
#[derive(Debug, Clone, Serialize)]
pub struct ExclusionCheckResult {
    pub is_excluded: bool,
    /// Whether the entry covering this object is a blacklist rather than an
    /// ordinary exclusion. False when nothing covers it.
    pub is_blacklisted: bool,
    pub entry: Option<ExclusionEntry>,
    /// For domains, indicates if a parent domain is excluded
    pub parent_excluded: bool,
    pub parent_entry: Option<ExclusionEntry>,
}

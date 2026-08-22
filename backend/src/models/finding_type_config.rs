use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Finding type configuration for risk scoring
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingTypeConfig {
    pub id: Uuid,
    pub finding_type: String,
    pub display_name: String,
    pub category: String,
    pub type_multiplier: f64,
    pub description: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to update a finding type configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FindingTypeConfigUpdate {
    pub display_name: Option<String>,
    pub type_multiplier: Option<f64>,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
}

/// Bulk update request
#[derive(Debug, Clone, Deserialize)]
pub struct FindingTypeConfigBulkUpdate {
    pub configs: Vec<FindingTypeConfigUpdateItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FindingTypeConfigUpdateItem {
    pub finding_type: String,
    pub type_multiplier: Option<f64>,
    pub is_enabled: Option<bool>,
}

/// Response with configs grouped by category
#[derive(Debug, Clone, Serialize)]
pub struct FindingTypeConfigListResponse {
    pub configs: Vec<FindingTypeConfig>,
    pub categories: Vec<String>,
    pub total_count: i64,
}

/// Bounds the API enforces on a type multiplier. A type may be weighted down to a
/// tenth of its severity or up to ten times it, but never to zero — silencing a type
/// is what `is_enabled` is for, and a 0.0 multiplier would hide that intent inside a
/// number nobody reads.
pub const MULTIPLIER_MIN: f64 = 0.1;
pub const MULTIPLIER_MAX: f64 = 10.0;

/// What `finding_type_config` contributes to a score: a multiplier, and whether the
/// type counts at all.
///
/// `is_enabled` has to travel with the multiplier rather than being filtered out in
/// SQL. The scorer falls back to a neutral 1.0 for types it has no row for, so a
/// disabled type that simply went missing from the map would keep scoring at full
/// weight — the opposite of what disabling it means.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TypeWeight {
    pub multiplier: f64,
    pub is_enabled: bool,
}

impl Default for TypeWeight {
    /// The weight applied to a finding type with no configuration row: counted, at
    /// face value, with no thumb on the scale.
    fn default() -> Self {
        Self {
            multiplier: 1.0,
            is_enabled: true,
        }
    }
}

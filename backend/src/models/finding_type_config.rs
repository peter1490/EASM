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
    pub default_severity: String,
    pub severity_score: f64,
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
    pub default_severity: Option<String>,
    pub severity_score: Option<f64>,
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
    pub severity_score: Option<f64>,
    pub type_multiplier: Option<f64>,
    pub default_severity: Option<String>,
    pub is_enabled: Option<bool>,
}

/// Response with configs grouped by category
#[derive(Debug, Clone, Serialize)]
pub struct FindingTypeConfigListResponse {
    pub configs: Vec<FindingTypeConfig>,
    pub categories: Vec<String>,
    pub total_count: i64,
}

/// Severity levels with their default scores
pub const SEVERITY_SCORES: &[(&str, f64)] = &[
    ("critical", 40.0),
    ("high", 20.0),
    ("medium", 10.0),
    ("low", 3.0),
    ("info", 0.5),
];

/// Get severity score from severity name
pub fn get_severity_score(severity: &str) -> f64 {
    SEVERITY_SCORES
        .iter()
        .find(|(s, _)| *s == severity.to_lowercase())
        .map(|(_, score)| *score)
        .unwrap_or(1.0)
}


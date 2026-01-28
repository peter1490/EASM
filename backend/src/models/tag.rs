use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Rule type for auto-tagging
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagRuleType {
    /// Regex pattern for matching string-based assets (domains, certificates, ASNs, etc.)
    Regex,
    /// IP range in CIDR notation for matching IP assets
    IpRange,
}

impl std::fmt::Display for TagRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TagRuleType::Regex => write!(f, "regex"),
            TagRuleType::IpRange => write!(f, "ip_range"),
        }
    }
}

impl From<&str> for TagRuleType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "regex" => TagRuleType::Regex,
            "ip_range" => TagRuleType::IpRange,
            _ => TagRuleType::Regex, // Default to regex
        }
    }
}

/// Tag definition with optional auto-tagging rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub importance: i32,
    pub rule_type: Option<String>,
    pub rule_value: Option<String>,
    pub color: Option<String>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database row representation for Tag
#[derive(Debug, Clone, FromRow)]
pub struct TagRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub importance: i32,
    pub rule_type: Option<String>,
    pub rule_value: Option<String>,
    pub color: Option<String>,
    pub company_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<TagRow> for Tag {
    fn from(row: TagRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            importance: row.importance,
            rule_type: row.rule_type,
            rule_value: row.rule_value,
            color: row.color,
            company_id: row.company_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Request payload for creating a new tag
#[derive(Debug, Clone, Deserialize)]
pub struct TagCreate {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_importance")]
    pub importance: i32,
    pub rule_type: Option<String>,
    pub rule_value: Option<String>,
    pub color: Option<String>,
}

fn default_importance() -> i32 {
    3
}

/// Request payload for updating an existing tag
#[derive(Debug, Clone, Deserialize)]
pub struct TagUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub importance: Option<i32>,
    pub rule_type: Option<String>,
    pub rule_value: Option<String>,
    pub color: Option<String>,
    /// Set to true to clear the rule (set rule_type and rule_value to NULL)
    #[serde(default)]
    pub clear_rule: bool,
}

/// How a tag was applied to an asset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagAppliedBy {
    Manual,
    AutoRule,
}

impl std::fmt::Display for TagAppliedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TagAppliedBy::Manual => write!(f, "manual"),
            TagAppliedBy::AutoRule => write!(f, "auto_rule"),
        }
    }
}

impl From<&str> for TagAppliedBy {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "manual" => TagAppliedBy::Manual,
            "auto_rule" => TagAppliedBy::AutoRule,
            _ => TagAppliedBy::Manual,
        }
    }
}

/// Asset-Tag relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTag {
    pub id: Uuid,
    pub company_id: Uuid,
    pub asset_id: Uuid,
    pub tag_id: Uuid,
    pub applied_by: String,
    pub matched_rule: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database row representation for AssetTag
#[derive(Debug, Clone, FromRow)]
pub struct AssetTagRow {
    pub id: Uuid,
    pub company_id: Uuid,
    pub asset_id: Uuid,
    pub tag_id: Uuid,
    pub applied_by: String,
    pub matched_rule: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<AssetTagRow> for AssetTag {
    fn from(row: AssetTagRow) -> Self {
        Self {
            id: row.id,
            company_id: row.company_id,
            asset_id: row.asset_id,
            tag_id: row.tag_id,
            applied_by: row.applied_by,
            matched_rule: row.matched_rule,
            created_at: row.created_at,
        }
    }
}

/// Request payload for tagging an asset
#[derive(Debug, Clone, Deserialize)]
pub struct AssetTagCreate {
    pub tag_id: Uuid,
    #[serde(default = "default_applied_by")]
    pub applied_by: String,
    pub matched_rule: Option<String>,
}

fn default_applied_by() -> String {
    "manual".to_string()
}

/// Tag with usage count for listing
#[derive(Debug, Clone, Serialize)]
pub struct TagWithCount {
    #[serde(flatten)]
    pub tag: Tag,
    pub asset_count: i64,
}

/// Tag attached to an asset (for asset detail views)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTagDetail {
    pub tag: Tag,
    pub applied_by: String,
    pub matched_rule: Option<String>,
    pub tagged_at: DateTime<Utc>,
}

/// Result of an auto-tagging run
#[derive(Debug, Clone, Serialize)]
pub struct AutoTagResult {
    pub tags_applied: i64,
    pub assets_tagged: i64,
    pub errors: Vec<String>,
}

/// Filter options for listing tags
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TagFilter {
    /// Filter by rule type (regex, ip_range, or null for manual-only tags)
    pub rule_type: Option<String>,
    /// Search by name or description
    pub search: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// Response for paginated tag list
#[derive(Debug, Clone, Serialize)]
pub struct TagListResponse {
    pub tags: Vec<TagWithCount>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

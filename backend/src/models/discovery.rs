use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================================
// Discovery Run - Tracks each discovery execution
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryRunStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl Default for DiscoveryRunStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TriggerType {
    Manual,
    Scheduled,
    SeedAdded,
}

impl Default for TriggerType {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DiscoveryRun {
    pub id: Uuid,
    pub status: String,
    pub trigger_type: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub seeds_processed: i32,
    pub assets_discovered: i32,
    pub assets_updated: i32,
    pub error_message: Option<String>,
    pub config: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryRunCreate {
    pub trigger_type: Option<TriggerType>,
    pub config: Option<Value>,
}

impl Default for DiscoveryRunCreate {
    fn default() -> Self {
        Self {
            trigger_type: Some(TriggerType::Manual),
            config: None,
        }
    }
}

/// Discovery configuration options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryConfig {
    /// Minimum confidence to auto-trigger security scans
    pub auto_scan_threshold: Option<f64>,
    /// Maximum recursion depth for pivoting
    pub max_depth: Option<u32>,
    /// Specific seed IDs to process (None = all seeds)
    pub seed_ids: Option<Vec<Uuid>>,
    /// Whether to skip recently processed seeds
    pub skip_recent: Option<bool>,
    /// Recent threshold in hours
    pub recent_hours: Option<u32>,
}

// ============================================================================
// Discovery Queue Item - For async processing
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueueItemType {
    Seed,
    Domain,
    Organization,
    Asn,
    Ip,
    Cidr,
}

impl std::fmt::Display for QueueItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueItemType::Seed => write!(f, "seed"),
            QueueItemType::Domain => write!(f, "domain"),
            QueueItemType::Organization => write!(f, "organization"),
            QueueItemType::Asn => write!(f, "asn"),
            QueueItemType::Ip => write!(f, "ip"),
            QueueItemType::Cidr => write!(f, "cidr"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueueItemStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DiscoveryQueueItem {
    pub id: Uuid,
    pub discovery_run_id: Uuid,
    pub item_type: String,
    pub item_value: String,
    pub parent_asset_id: Option<Uuid>,
    pub seed_id: Option<Uuid>,
    pub depth: i32,
    pub priority: i32,
    pub status: String,
    pub error_message: Option<String>,
    pub processed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DiscoveryQueueItemCreate {
    pub discovery_run_id: Uuid,
    pub item_type: QueueItemType,
    pub item_value: String,
    pub parent_asset_id: Option<Uuid>,
    pub seed_id: Option<Uuid>,
    pub depth: i32,
    pub priority: i32,
}

// ============================================================================
// Asset Source - Tracks where each asset came from
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    Shodan,
    Crtsh,
    Certspotter,
    Virustotal,
    DnsResolution,
    TlsCertificate,
    CidrExpansion,
    ReverseDns,
    Seed,
    UserInput,
    HttpProbe,
    PortScan,
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceType::Shodan => write!(f, "shodan"),
            SourceType::Crtsh => write!(f, "crtsh"),
            SourceType::Certspotter => write!(f, "certspotter"),
            SourceType::Virustotal => write!(f, "virustotal"),
            SourceType::DnsResolution => write!(f, "dns_resolution"),
            SourceType::TlsCertificate => write!(f, "tls_certificate"),
            SourceType::CidrExpansion => write!(f, "cidr_expansion"),
            SourceType::ReverseDns => write!(f, "reverse_dns"),
            SourceType::Seed => write!(f, "seed"),
            SourceType::UserInput => write!(f, "user_input"),
            SourceType::HttpProbe => write!(f, "http_probe"),
            SourceType::PortScan => write!(f, "port_scan"),
        }
    }
}

impl From<&str> for SourceType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "shodan" => SourceType::Shodan,
            "crtsh" | "crt.sh" => SourceType::Crtsh,
            "certspotter" => SourceType::Certspotter,
            "virustotal" => SourceType::Virustotal,
            "dns_resolution" | "dns" => SourceType::DnsResolution,
            "tls_certificate" | "tls" | "certificate" => SourceType::TlsCertificate,
            "cidr_expansion" | "cidr" => SourceType::CidrExpansion,
            "reverse_dns" | "rdns" | "ptr" => SourceType::ReverseDns,
            "seed" => SourceType::Seed,
            "http_probe" | "http" => SourceType::HttpProbe,
            "port_scan" | "ports" => SourceType::PortScan,
            _ => SourceType::UserInput,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetSource {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub discovery_run_id: Option<Uuid>,
    pub source_type: String,
    pub source_confidence: f64,
    pub raw_data: Value,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AssetSourceCreate {
    pub asset_id: Uuid,
    pub discovery_run_id: Option<Uuid>,
    pub source_type: SourceType,
    pub source_confidence: f64,
    pub raw_data: Option<Value>,
}

// ============================================================================
// Asset Relationship - Graph edges between assets
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Domain resolves to IP (A/AAAA record)
    ResolvesTo,
    /// IP reverse-resolves to domain (PTR record)
    ReverseResolvesTo,
    /// Parent domain has this subdomain
    HasSubdomain,
    /// Domain/IP has this certificate
    HasCertificate,
    /// Asset belongs to this organization
    BelongsToOrg,
    /// Asset belongs to this ASN
    BelongsToAsn,
    /// Asset was discovered via this other asset
    DiscoveredVia,
    /// Same organization owns both assets
    SameOwner,
    /// Assets share the same IP
    SharesIp,
    /// Certificate covers both domains
    SharedCertificate,
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::ResolvesTo => write!(f, "resolves_to"),
            RelationshipType::ReverseResolvesTo => write!(f, "reverse_resolves_to"),
            RelationshipType::HasSubdomain => write!(f, "has_subdomain"),
            RelationshipType::HasCertificate => write!(f, "has_certificate"),
            RelationshipType::BelongsToOrg => write!(f, "belongs_to_org"),
            RelationshipType::BelongsToAsn => write!(f, "belongs_to_asn"),
            RelationshipType::DiscoveredVia => write!(f, "discovered_via"),
            RelationshipType::SameOwner => write!(f, "same_owner"),
            RelationshipType::SharesIp => write!(f, "shares_ip"),
            RelationshipType::SharedCertificate => write!(f, "shared_certificate"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetRelationship {
    pub id: Uuid,
    pub source_asset_id: Uuid,
    pub target_asset_id: Uuid,
    pub relationship_type: String,
    pub confidence: f64,
    pub metadata: Value,
    pub discovery_run_id: Option<Uuid>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AssetRelationshipCreate {
    pub source_asset_id: Uuid,
    pub target_asset_id: Uuid,
    pub relationship_type: RelationshipType,
    pub confidence: f64,
    pub metadata: Option<Value>,
    pub discovery_run_id: Option<Uuid>,
}

// ============================================================================
// Discovery Result - Returned from discovery operations
// ============================================================================

/// Result of a single discovery operation
#[derive(Debug, Clone, Default)]
pub struct DiscoveryResult {
    /// New assets created
    pub assets_created: Vec<Uuid>,
    /// Existing assets that were updated
    pub assets_updated: Vec<Uuid>,
    /// New relationships created
    pub relationships_created: Vec<Uuid>,
    /// Sources that were added
    pub sources_added: Vec<Uuid>,
    /// Errors encountered (non-fatal)
    pub warnings: Vec<String>,
}

impl DiscoveryResult {
    pub fn merge(&mut self, other: DiscoveryResult) {
        self.assets_created.extend(other.assets_created);
        self.assets_updated.extend(other.assets_updated);
        self.relationships_created
            .extend(other.relationships_created);
        self.sources_added.extend(other.sources_added);
        self.warnings.extend(other.warnings);
    }

    pub fn total_assets(&self) -> usize {
        self.assets_created.len() + self.assets_updated.len()
    }
}

/// Summary of a completed discovery run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRunSummary {
    pub run_id: Uuid,
    pub status: String,
    pub duration_seconds: Option<i64>,
    pub seeds_processed: i32,
    pub assets_discovered: i32,
    pub assets_updated: i32,
    pub relationships_created: i32,
    pub errors: Vec<String>,
}

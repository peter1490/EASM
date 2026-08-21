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
    pub company_id: Uuid,
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
    /// Timezone for scheduled discovery runs (IANA tz string)
    pub timezone: Option<String>,
}

// ============================================================================
// Discovery Schedules - Cron-based automation
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DiscoverySchedule {
    pub id: Uuid,
    pub name: String,
    pub cron: String,
    pub enabled: bool,
    pub config: Value,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub company_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryScheduleCreate {
    pub name: String,
    pub cron: String,
    pub enabled: Option<bool>,
    pub config: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryScheduleUpdate {
    pub name: Option<String>,
    pub cron: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<Value>,
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
    // Lateral OSINT pivots — find apex domains that share infrastructure/content/mail
    // with a seed, rather than subdomains of the seed.
    FaviconPivot,
    JarmPivot,
    AnalyticsIdPivot,
    SpfPivot,
    DmarcPivot,
    MxPivot,
    // Passive OSINT aggregators. Each is an independent corpus: certificate
    // transparency, passive DNS, internet-wide scan data or web archives. A
    // hostname corroborated by several of them is far more likely to be real
    // than one seen by a single crawler.
    Otx,
    HackerTarget,
    RapidDns,
    AnubisDb,
    UrlScan,
    Wayback,
    Columbus,
    Digitorus,
    SecurityTrails,
    Censys,
    Chaos,
    LeakIx,
    FullHunt,
    BinaryEdge,
    Netlas,
    // Active DNS discovery — names that no passive corpus has ever recorded.
    DnsBruteforce,
    DnsPermutation,
    NsecWalk,
    SrvRecord,
    CnameChain,
    // Infrastructure attribution.
    AsnNetblock,
    Rdap,
    TxtVerification,
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
            SourceType::FaviconPivot => write!(f, "favicon_pivot"),
            SourceType::JarmPivot => write!(f, "jarm_pivot"),
            SourceType::AnalyticsIdPivot => write!(f, "analytics_id_pivot"),
            SourceType::SpfPivot => write!(f, "spf_pivot"),
            SourceType::DmarcPivot => write!(f, "dmarc_pivot"),
            SourceType::MxPivot => write!(f, "mx_pivot"),
            SourceType::Otx => write!(f, "otx"),
            SourceType::HackerTarget => write!(f, "hackertarget"),
            SourceType::RapidDns => write!(f, "rapiddns"),
            SourceType::AnubisDb => write!(f, "anubisdb"),
            SourceType::UrlScan => write!(f, "urlscan"),
            SourceType::Wayback => write!(f, "wayback"),
            SourceType::Columbus => write!(f, "columbus"),
            SourceType::Digitorus => write!(f, "digitorus"),
            SourceType::SecurityTrails => write!(f, "securitytrails"),
            SourceType::Censys => write!(f, "censys"),
            SourceType::Chaos => write!(f, "chaos"),
            SourceType::LeakIx => write!(f, "leakix"),
            SourceType::FullHunt => write!(f, "fullhunt"),
            SourceType::BinaryEdge => write!(f, "binaryedge"),
            SourceType::Netlas => write!(f, "netlas"),
            SourceType::DnsBruteforce => write!(f, "dns_bruteforce"),
            SourceType::DnsPermutation => write!(f, "dns_permutation"),
            SourceType::NsecWalk => write!(f, "nsec_walk"),
            SourceType::SrvRecord => write!(f, "srv_record"),
            SourceType::CnameChain => write!(f, "cname_chain"),
            SourceType::AsnNetblock => write!(f, "asn_netblock"),
            SourceType::Rdap => write!(f, "rdap"),
            SourceType::TxtVerification => write!(f, "txt_verification"),
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
            "favicon_pivot" => SourceType::FaviconPivot,
            "jarm_pivot" => SourceType::JarmPivot,
            "analytics_id_pivot" => SourceType::AnalyticsIdPivot,
            "spf_pivot" => SourceType::SpfPivot,
            "dmarc_pivot" => SourceType::DmarcPivot,
            "mx_pivot" => SourceType::MxPivot,
            "otx" | "alienvault" => SourceType::Otx,
            "hackertarget" => SourceType::HackerTarget,
            "rapiddns" => SourceType::RapidDns,
            "anubisdb" | "anubis" => SourceType::AnubisDb,
            "urlscan" => SourceType::UrlScan,
            "wayback" | "waybackarchive" => SourceType::Wayback,
            "columbus" => SourceType::Columbus,
            "digitorus" => SourceType::Digitorus,
            "securitytrails" => SourceType::SecurityTrails,
            "censys" => SourceType::Censys,
            "chaos" => SourceType::Chaos,
            "leakix" => SourceType::LeakIx,
            "fullhunt" => SourceType::FullHunt,
            "binaryedge" => SourceType::BinaryEdge,
            "netlas" => SourceType::Netlas,
            "dns_bruteforce" | "bruteforce" => SourceType::DnsBruteforce,
            "dns_permutation" | "permutation" => SourceType::DnsPermutation,
            "nsec_walk" | "nsec" => SourceType::NsecWalk,
            "srv_record" | "srv" => SourceType::SrvRecord,
            "cname_chain" | "cname" => SourceType::CnameChain,
            "asn_netblock" => SourceType::AsnNetblock,
            "rdap" => SourceType::Rdap,
            "txt_verification" => SourceType::TxtVerification,
            _ => SourceType::UserInput,
        }
    }
}

impl SourceType {
    /// Default confidence weight for an asset discovered solely via this source.
    ///
    /// The scale is deliberately tiered by *what the source actually observed*:
    ///
    /// - **1.0** — the analyst said so (seed / user input).
    /// - **0.85–0.95** — the name was resolved or actively answered right now.
    ///   Nothing beats a live DNS answer.
    /// - **0.75–0.85** — a certificate authority logged the name to a public,
    ///   append-only CT log. Names in CT were provably requested by whoever
    ///   controlled the domain at issuance time.
    /// - **0.6–0.75** — a third party observed the name in passive DNS, scan
    ///   data or a web archive. Real, but possibly stale or third-party-owned.
    /// - **0.3–0.5** — a *pivot*: this asset merely shares an attribute
    ///   (favicon, JARM, analytics ID, mail relay, netblock) with a known asset.
    ///   Shared attributes are shared by unrelated SaaS tenants all the time,
    ///   so these need analyst review before they are treated as owned.
    pub fn confidence_weight(&self) -> f64 {
        match self {
            SourceType::Seed | SourceType::UserInput => 1.0,

            // Observed live, by us.
            SourceType::DnsResolution => 0.9,
            SourceType::DnsBruteforce | SourceType::SrvRecord | SourceType::CnameChain => 0.85,
            // A signed zone hands over its own contents; there is no guesswork.
            SourceType::NsecWalk => 0.9,
            SourceType::ReverseDns => 0.7,
            SourceType::HttpProbe | SourceType::PortScan => 0.6,
            // Permutations are generated, then confirmed by resolution. The name
            // resolves, but a wildcard-adjacent catch-all can still inflate this.
            SourceType::DnsPermutation => 0.7,

            // Certificate transparency and live certificates.
            SourceType::Crtsh | SourceType::Certspotter => 0.85,
            SourceType::Censys | SourceType::Digitorus => 0.8,
            SourceType::TlsCertificate => 0.8,

            // Passive DNS / internet-wide scan corpora.
            SourceType::Shodan | SourceType::Virustotal => 0.75,
            SourceType::SecurityTrails | SourceType::Chaos => 0.75,
            SourceType::BinaryEdge | SourceType::Netlas | SourceType::FullHunt => 0.7,
            SourceType::Otx | SourceType::LeakIx | SourceType::HackerTarget => 0.7,
            SourceType::RapidDns | SourceType::AnubisDb | SourceType::Columbus => 0.65,
            // Archives record what *was* live, which is not the same as what is.
            SourceType::UrlScan => 0.65,
            SourceType::Wayback => 0.55,

            // Infrastructure attribution.
            SourceType::CidrExpansion => 0.5,
            SourceType::AsnNetblock => 0.5,
            SourceType::Rdap => 0.5,
            // A verification token proves the org *proved ownership* to a SaaS
            // vendor — strong signal about tenancy, weak about the hostname.
            SourceType::TxtVerification => 0.45,

            // Lateral pivots: shared attribute, unproven ownership.
            SourceType::FaviconPivot
            | SourceType::JarmPivot
            | SourceType::AnalyticsIdPivot
            | SourceType::SpfPivot
            | SourceType::DmarcPivot
            | SourceType::MxPivot => 0.3,
        }
    }

    /// Whether this source is an independent third-party corpus.
    ///
    /// Corroboration only means something between *independent* observers.
    /// Two CT aggregators reading the same logs are one observation, not two,
    /// so they are grouped into a single evidence class by
    /// [`SourceType::evidence_class`].
    pub fn is_passive_corpus(&self) -> bool {
        matches!(
            self,
            SourceType::Shodan
                | SourceType::Virustotal
                | SourceType::Crtsh
                | SourceType::Certspotter
                | SourceType::Otx
                | SourceType::HackerTarget
                | SourceType::RapidDns
                | SourceType::AnubisDb
                | SourceType::UrlScan
                | SourceType::Wayback
                | SourceType::Columbus
                | SourceType::Digitorus
                | SourceType::SecurityTrails
                | SourceType::Censys
                | SourceType::Chaos
                | SourceType::LeakIx
                | SourceType::FullHunt
                | SourceType::BinaryEdge
                | SourceType::Netlas
        )
    }

    /// The class of evidence this source represents.
    ///
    /// Counting raw sources overstates confidence: crt.sh, CertSpotter, Censys
    /// and Digitorus all read the same certificate transparency logs, so four
    /// hits there is still one independent fact. Confidence scoring counts
    /// distinct classes instead.
    pub fn evidence_class(&self) -> EvidenceClass {
        match self {
            SourceType::Crtsh
            | SourceType::Certspotter
            | SourceType::Censys
            | SourceType::Digitorus
            | SourceType::TlsCertificate => EvidenceClass::CertificateTransparency,

            SourceType::Otx
            | SourceType::Virustotal
            | SourceType::SecurityTrails
            | SourceType::HackerTarget
            | SourceType::RapidDns
            | SourceType::AnubisDb
            | SourceType::Columbus
            | SourceType::Chaos => EvidenceClass::PassiveDns,

            SourceType::Shodan
            | SourceType::BinaryEdge
            | SourceType::Netlas
            | SourceType::FullHunt
            | SourceType::LeakIx => EvidenceClass::InternetScan,

            SourceType::UrlScan | SourceType::Wayback => EvidenceClass::WebArchive,

            SourceType::DnsResolution
            | SourceType::ReverseDns
            | SourceType::DnsBruteforce
            | SourceType::DnsPermutation
            | SourceType::NsecWalk
            | SourceType::SrvRecord
            | SourceType::CnameChain
            | SourceType::TxtVerification => EvidenceClass::ActiveDns,

            SourceType::HttpProbe | SourceType::PortScan => EvidenceClass::ActiveProbe,

            SourceType::CidrExpansion | SourceType::AsnNetblock | SourceType::Rdap => {
                EvidenceClass::Registry
            }

            SourceType::FaviconPivot
            | SourceType::JarmPivot
            | SourceType::AnalyticsIdPivot
            | SourceType::SpfPivot
            | SourceType::DmarcPivot
            | SourceType::MxPivot => EvidenceClass::SharedAttribute,

            SourceType::Seed | SourceType::UserInput => EvidenceClass::Declared,
        }
    }
}

/// Independent classes of evidence for an asset's existence and ownership.
///
/// Two sources in the same class are not independent corroboration — see
/// [`SourceType::evidence_class`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Declared,
    CertificateTransparency,
    PassiveDns,
    InternetScan,
    WebArchive,
    ActiveDns,
    ActiveProbe,
    Registry,
    SharedAttribute,
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
    /// Domains share mail infrastructure (MX target / SPF include / DMARC report mailbox)
    UsesMailInfrastructure,
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
            RelationshipType::UsesMailInfrastructure => write!(f, "uses_mail_infrastructure"),
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

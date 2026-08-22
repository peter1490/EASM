//! Discovery Service
//!
//! Handles asset discovery from seeds. This service is purely focused on
//! **discovering** assets (passive reconnaissance), not scanning them.
//!
//! The discovery flow:
//! 1. User triggers a discovery run
//! 2. Seeds are loaded and queued for processing
//! 3. Each seed type is processed using appropriate external services
//! 4. Discovered assets are stored with proper lineage and sources
//! 5. Relationships between assets are recorded
//!
//! Security scanning is handled separately by SecurityScanService.

use chrono::Utc;
use ipnet::IpNet;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    config::{Settings, SharedSettings},
    error::ApiError,
    models::{
        Asset, AssetCreate, AssetRelationshipCreate, AssetSourceCreate, AssetType, DiscoveryConfig,
        DiscoveryQueueItemCreate, DiscoveryResult, DiscoveryRun, DiscoveryRunCreate,
        ExclusionEntry, ExclusionObjectType, QueueItemType, RelationshipType, ScanTriggerType,
        SecurityScanCreate, SecurityScanType, Seed, SeedCreate, SeedType, SourceType, TriggerType,
    },
    repositories::{
        AssetRelationshipRepository, AssetRepository, AssetSourceRepository,
        DiscoveryQueueRepository, DiscoveryRunRepository, ExclusionRepository, SeedRepository,
    },
    services::{
        confidence::ConfidenceScorer,
        external::{
            ActiveDnsConfig, ActiveDnsDiscovery, ActiveDnsResult, AsnClient, DnsResolver,
            ExternalServicesManager, HttpAnalyzer,
        },
        task_manager::{TaskContext, TaskManager, TaskType},
        RiskService, SecurityScanService,
    },
    utils::network::expand_cidr,
};

/// Common CDN, cloud provider, and hosting organizations to filter.
/// Keep this list focused on explicit infrastructure names only.
static COMMON_INFRASTRUCTURE_ORGS: &[&str] = &[
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "amazon cloudfront",
    "stackpath",
    "keycdn",
    "bunnycdn",
    "maxcdn",
    "amazon",
    "aws",
    "google",
    "google cloud",
    "microsoft",
    "azure",
    "digitalocean",
    "linode",
    "vultr",
    "ovh",
    "hetzner",
    "scaleway",
    "godaddy",
    "namecheap",
    "bluehost",
    "hostgator",
    "dreamhost",
    "let's encrypt",
    "digicert",
    "comodo",
    "sectigo",
    "globalsign",
    "incapsula",
    "imperva",
    "sucuri",
    "wordfence",
    "barracuda",
    "domain administrator",
    "domain admin",
    "whois privacy",
    "contact privacy",
    "registration private",
];

/// Provider keywords used to classify cloud/WAF infrastructure IPs.
static KNOWN_CLOUD_PROVIDER_KEYWORDS: &[&str] = &[
    "amazon",
    "aws",
    "cloudfront",
    "google",
    "google cloud",
    "gcp",
    "cloudflare",
    "microsoft",
    "azure",
    "akamai",
    "fastly",
    "digitalocean",
    "linode",
    "vultr",
    "ovh",
    "hetzner",
    "incapsula",
    "imperva",
];

/// Canonical source ordering, strongest evidence first.
///
/// Two things read this: the order sources are listed against an asset, and
/// which one becomes the asset's `discovery_method`. So it is ranked by how
/// much a source proves, not by how fast it answers — a name confirmed by live
/// DNS outranks the same name seen in a web archive, whichever arrived first.
///
/// Sources absent from this list sort after it in the order they were recorded.
static DISCOVERY_SOURCE_PRIORITY: &[SourceType] = &[
    // Observed live, by us.
    SourceType::DnsResolution,
    SourceType::NsecWalk,
    SourceType::DnsBruteforce,
    SourceType::SrvRecord,
    SourceType::CnameChain,
    SourceType::DnsPermutation,
    // Certificate transparency.
    SourceType::Crtsh,
    SourceType::Certspotter,
    SourceType::Censys,
    SourceType::Digitorus,
    SourceType::TlsCertificate,
    // Passive DNS and scan corpora.
    SourceType::Shodan,
    SourceType::Virustotal,
    SourceType::SecurityTrails,
    SourceType::Chaos,
    SourceType::BinaryEdge,
    SourceType::Netlas,
    SourceType::FullHunt,
    SourceType::LeakIx,
    SourceType::Otx,
    SourceType::HackerTarget,
    SourceType::RapidDns,
    SourceType::AnubisDb,
    SourceType::Columbus,
    // Archives.
    SourceType::UrlScan,
    SourceType::Wayback,
    // Infrastructure attribution.
    SourceType::ReverseDns,
    SourceType::AsnNetblock,
    SourceType::TxtVerification,
];

/// How long a company's exclusion list is reused before it is read again.
///
/// Every asset discovery is about to write is checked against the list, so
/// a query per check would be thousands of round-trips per run. Ten seconds is
/// short enough that an operator excluding something mid-run sees it take
/// effect immediately in practice -- and the write paths invalidate the entry
/// outright, so the window only ever covers changes made outside this process.
const EXCLUSION_CACHE_TTL: Duration = Duration::from_secs(10);

/// What the exclusion list has to say about one object.
///
/// The two strengths are not interchangeable and the call sites treat them
/// differently, so the check returns which one applies rather than a bool that
/// each caller would have to qualify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExclusionLevel {
    /// Nothing covers it.
    None,
    /// An ordinary exclusion: discovery writes nothing new here, but whatever
    /// was already found stays, and is still auto-scanned.
    Excluded,
    /// A blacklist: the object must not exist at all.
    Blacklisted,
}

impl ExclusionLevel {
    fn is_excluded(self) -> bool {
        !matches!(self, ExclusionLevel::None)
    }

    fn is_blacklisted(self) -> bool {
        matches!(self, ExclusionLevel::Blacklisted)
    }
}

/// The values one strength of exclusion covers, indexed for in-memory matching.
///
/// The matching mirrors `ExclusionRepository`: a domain entry covers the name
/// and anything under it, an IP entry covers that address, a CIDR entry covers
/// every address inside it, and the rest match their own value exactly.
#[derive(Debug, Default)]
struct ExclusionSets {
    domains: HashSet<String>,
    ips: HashSet<String>,
    cidrs: Vec<IpNet>,
    organizations: HashSet<String>,
    asns: HashSet<String>,
    certificates: HashSet<String>,
}

impl ExclusionSets {
    fn insert(&mut self, object_type: ExclusionObjectType, value: String) {
        match object_type {
            ExclusionObjectType::Domain => {
                self.domains.insert(value);
            }
            ExclusionObjectType::Ip => {
                self.ips.insert(value);
            }
            ExclusionObjectType::Cidr => {
                // A CIDR that will not parse can never match an address, so
                // it is dropped rather than carried as dead weight.
                match value.parse::<IpNet>() {
                    Ok(net) => self.cidrs.push(net),
                    Err(e) => {
                        tracing::warn!("Ignoring unparseable excluded CIDR '{}': {}", value, e)
                    }
                }
            }
            ExclusionObjectType::Organization => {
                self.organizations.insert(value);
            }
            ExclusionObjectType::Asn => {
                self.asns.insert(Self::normalize_asn(&value));
            }
            ExclusionObjectType::Certificate => {
                self.certificates.insert(value);
            }
        }
    }

    /// `AS64496`, `as64496` and `64496` are the same autonomous system.
    fn normalize_asn(value: &str) -> String {
        value
            .trim()
            .trim_start_matches("as")
            .trim_start_matches("AS")
            .trim()
            .to_lowercase()
    }

    fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.ips.is_empty()
            && self.cidrs.is_empty()
            && self.organizations.is_empty()
            && self.asns.is_empty()
            && self.certificates.is_empty()
    }

    fn covers(&self, item_type: &str, item_value: &str) -> bool {
        match item_type {
            "domain" => self.covers_domain(item_value),
            "ip" => self.covers_ip(item_value),
            "organization" => self.covers_organization(item_value),
            "asn" => self.covers_asn(item_value),
            "cidr" => self.covers_cidr(item_value),
            "certificate" => self.covers_certificate(item_value),
            _ => false,
        }
    }

    fn covers_domain(&self, domain: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        let domain = domain.trim().trim_end_matches('.').to_lowercase();
        if self.domains.contains(&domain) {
            return true;
        }
        // Parent domains, matching the repository: a parent is any suffix of at
        // least two labels, so a bare TLD entry never swallows a whole zone.
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            for i in 1..parts.len() - 1 {
                if self.domains.contains(&parts[i..].join(".")) {
                    return true;
                }
            }
        }
        false
    }

    fn covers_ip(&self, ip: &str) -> bool {
        let ip = ip.trim().to_lowercase();
        if self.ips.contains(&ip) {
            return true;
        }
        if self.cidrs.is_empty() {
            return false;
        }
        match ip.parse::<IpAddr>() {
            Ok(addr) => self.cidrs.iter().any(|net| net.contains(&addr)),
            Err(_) => false,
        }
    }

    fn covers_organization(&self, org: &str) -> bool {
        self.organizations.contains(&org.trim().to_lowercase())
    }

    fn covers_asn(&self, asn: &str) -> bool {
        self.asns.contains(&Self::normalize_asn(asn))
    }

    fn covers_cidr(&self, cidr: &str) -> bool {
        let value = cidr.trim().to_lowercase();
        if self.cidrs.is_empty() {
            return false;
        }
        // Both an identical entry and one that contains this range exclude it.
        match value.parse::<IpNet>() {
            Ok(net) => self
                .cidrs
                .iter()
                .any(|blocked| blocked.contains(&net) || *blocked == net),
            Err(_) => false,
        }
    }

    fn covers_certificate(&self, subject: &str) -> bool {
        self.certificates.contains(&subject.trim().to_lowercase())
    }
}

/// One company's exclusion list, resolved once and matched in memory.
///
/// Held as two sets rather than one set of entries: the blacklisted rows are a
/// subset of the excluded ones, and every check asks both questions in that
/// order, so keeping them separate makes the strong answer a second lookup
/// rather than a scan.
#[derive(Debug)]
struct ExclusionSnapshot {
    all: ExclusionSets,
    blacklisted: ExclusionSets,
    loaded_at: Instant,
}

impl ExclusionSnapshot {
    fn from_entries(entries: Vec<ExclusionEntry>) -> Self {
        let mut snapshot = Self {
            all: ExclusionSets::default(),
            blacklisted: ExclusionSets::default(),
            loaded_at: Instant::now(),
        };

        for entry in entries {
            let value = entry.object_value.trim().to_lowercase();
            if value.is_empty() {
                continue;
            }
            let object_type = ExclusionObjectType::from(entry.object_type.as_str());
            if entry.blacklisted {
                snapshot
                    .blacklisted
                    .insert(object_type.clone(), value.clone());
            }
            snapshot.all.insert(object_type, value);
        }

        snapshot
    }

    fn is_expired(&self) -> bool {
        self.loaded_at.elapsed() >= EXCLUSION_CACHE_TTL
    }

    fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    fn level(&self, item_type: &str, item_value: &str) -> ExclusionLevel {
        if self.blacklisted.covers(item_type, item_value) {
            ExclusionLevel::Blacklisted
        } else if self.all.covers(item_type, item_value) {
            ExclusionLevel::Excluded
        } else {
            ExclusionLevel::None
        }
    }
}

/// Discovery run status tracking (in-memory for real-time updates)
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryStatus {
    pub is_running: bool,
    pub run_id: Option<Uuid>,
    /// Task ID in the TaskManager for the current discovery run
    #[serde(skip)]
    pub task_id: Option<Uuid>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub current_phase: String,
    pub seeds_total: usize,
    pub seeds_processed: usize,
    pub assets_discovered: usize,
    pub assets_updated: usize,
    pub queue_pending: usize,
    pub scans_queued: usize,
    pub errors: Vec<String>,
    /// Auto-scan threshold for high-confidence assets (0.0 = disabled)
    #[serde(skip)]
    pub auto_scan_threshold: f64,
}

pub struct DiscoveryService {
    // Repositories
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    seed_repo: Arc<dyn SeedRepository + Send + Sync>,
    discovery_run_repo: Arc<dyn DiscoveryRunRepository + Send + Sync>,
    discovery_queue_repo: Arc<dyn DiscoveryQueueRepository + Send + Sync>,
    asset_source_repo: Arc<dyn AssetSourceRepository + Send + Sync>,
    asset_relationship_repo: Arc<dyn AssetRelationshipRepository + Send + Sync>,
    exclusion_repo: Arc<dyn ExclusionRepository + Send + Sync>,

    // Services
    security_scan_service: Option<Arc<SecurityScanService>>,
    risk_service: Arc<RiskService>,

    // External services
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_analyzer: Arc<HttpAnalyzer>,
    /// ASN, netblock and RDAP attribution. `None` only if the HTTP client could
    /// not be built at start-up; attribution is then skipped rather than fatal.
    asn_client: Option<Arc<AsnClient>>,

    // Utilities
    task_manager: Arc<TaskManager>,
    settings: SharedSettings,
    confidence_scorer: Arc<ConfidenceScorer>,

    // State
    status: Arc<Mutex<HashMap<Uuid, DiscoveryStatus>>>,
    ip_cloud_provider_cache: Arc<Mutex<HashMap<String, bool>>>,
    /// `(run_id, prefix)` pairs already reverse-swept.
    ///
    /// Every resolved address in a zone tends to sit in the same handful of
    /// prefixes; without this the same /24 would be swept once per hostname.
    swept_prefixes: Arc<Mutex<HashSet<(Uuid, String)>>>,
    /// Per-company exclusion list, refreshed on a short TTL and dropped outright
    /// whenever an entry is added or removed.
    exclusion_cache: Arc<Mutex<HashMap<Uuid, Arc<ExclusionSnapshot>>>>,
}

impl DiscoveryService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        seed_repo: Arc<dyn SeedRepository + Send + Sync>,
        discovery_run_repo: Arc<dyn DiscoveryRunRepository + Send + Sync>,
        discovery_queue_repo: Arc<dyn DiscoveryQueueRepository + Send + Sync>,
        asset_source_repo: Arc<dyn AssetSourceRepository + Send + Sync>,
        asset_relationship_repo: Arc<dyn AssetRelationshipRepository + Send + Sync>,
        exclusion_repo: Arc<dyn ExclusionRepository + Send + Sync>,
        external_services: Arc<ExternalServicesManager>,
        dns_resolver: Arc<DnsResolver>,
        http_analyzer: Arc<HttpAnalyzer>,
        task_manager: Arc<TaskManager>,
        settings: SharedSettings,
        risk_service: Arc<RiskService>,
    ) -> Self {
        Self {
            asset_repo,
            seed_repo,
            discovery_run_repo,
            discovery_queue_repo,
            asset_source_repo,
            asset_relationship_repo,
            exclusion_repo,
            security_scan_service: None,
            risk_service,
            external_services,
            asn_client: AsnClient::new(
                Arc::clone(&dns_resolver),
                std::time::Duration::from_secs(15),
            )
            .map(Arc::new)
            .map_err(|e| {
                tracing::warn!("ASN attribution unavailable: {}", e);
                e
            })
            .ok(),
            dns_resolver,
            http_analyzer,
            task_manager,
            settings,
            confidence_scorer: Arc::new(ConfidenceScorer::new()),
            status: Arc::new(Mutex::new(HashMap::new())),
            ip_cloud_provider_cache: Arc::new(Mutex::new(HashMap::new())),
            swept_prefixes: Arc::new(Mutex::new(HashSet::new())),
            exclusion_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn current_settings(&self) -> Arc<Settings> {
        self.settings.load_full()
    }

    /// Set the security scan service for auto-scan functionality
    pub fn with_security_scan_service(mut self, service: Arc<SecurityScanService>) -> Self {
        self.security_scan_service = Some(service);
        self
    }

    // ========================================================================
    // SEED MANAGEMENT
    // ========================================================================

    pub async fn create_seed(
        &self,
        seed_create: SeedCreate,
        company_id: Uuid,
    ) -> Result<Seed, ApiError> {
        self.validate_seed(&seed_create)?;
        self.seed_repo.create(&seed_create, company_id).await
    }

    pub async fn list_seeds(&self, company_id: Uuid) -> Result<Vec<Seed>, ApiError> {
        self.seed_repo.list(company_id).await
    }

    pub async fn delete_seed(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError> {
        self.seed_repo.delete(company_id, *id).await
    }

    fn validate_seed(&self, seed: &SeedCreate) -> Result<(), ApiError> {
        match seed.seed_type {
            SeedType::Domain => {
                if seed.value.is_empty() || !seed.value.contains('.') {
                    return Err(ApiError::Validation("Invalid domain format".to_string()));
                }
            }
            SeedType::Asn => {
                let value = seed.value.trim_start_matches("AS");
                if value.parse::<u32>().is_err() {
                    return Err(ApiError::Validation("Invalid ASN format".to_string()));
                }
            }
            SeedType::Cidr => {
                if expand_cidr(&seed.value).is_err() {
                    return Err(ApiError::Validation("Invalid CIDR format".to_string()));
                }
            }
            SeedType::Organization => {
                if seed.value.is_empty() {
                    return Err(ApiError::Validation(
                        "Organization name cannot be empty".to_string(),
                    ));
                }
            }
            SeedType::Keyword => {
                if seed.value.is_empty() {
                    return Err(ApiError::Validation("Keyword cannot be empty".to_string()));
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // ASSET MANAGEMENT
    // ========================================================================

    pub async fn list_assets(
        &self,
        company_id: Uuid,
        confidence_threshold: Option<f64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Asset>, ApiError> {
        self.asset_repo
            .list(company_id, confidence_threshold, limit, offset)
            .await
    }

    pub async fn count_assets(
        &self,
        company_id: Uuid,
        confidence_threshold: Option<f64>,
    ) -> Result<i64, ApiError> {
        self.asset_repo
            .count(company_id, confidence_threshold)
            .await
    }

    pub async fn get_asset(&self, company_id: Uuid, id: &Uuid) -> Result<Option<Asset>, ApiError> {
        self.asset_repo.get_by_id(company_id, id).await
    }

    pub async fn get_asset_path(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Vec<Asset>, ApiError> {
        self.asset_repo.get_path(company_id, id).await
    }

    // ========================================================================
    // DISCOVERY RUN MANAGEMENT
    // ========================================================================

    pub async fn get_discovery_status(&self, company_id: Uuid) -> DiscoveryStatus {
        let statuses = self.status.lock().await;
        statuses.get(&company_id).cloned().unwrap_or_default()
    }

    pub async fn get_discovery_run(
        &self,
        company_id: Uuid,
        id: &Uuid,
    ) -> Result<Option<DiscoveryRun>, ApiError> {
        self.discovery_run_repo.get_by_id(company_id, id).await
    }

    pub async fn list_discovery_runs(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscoveryRun>, ApiError> {
        self.discovery_run_repo
            .list(company_id, limit, offset)
            .await
    }

    /// Start a new discovery run for a company.
    pub async fn run_discovery(
        &self,
        company_id: Uuid,
        config: Option<DiscoveryConfig>,
        requested_by: Option<Uuid>,
    ) -> Result<DiscoveryRun, ApiError> {
        self.run_discovery_with_trigger(company_id, config, TriggerType::Manual, requested_by)
            .await
    }

    /// Start a new discovery run for a company with a specific trigger type.
    pub async fn run_discovery_with_trigger(
        &self,
        company_id: Uuid,
        config: Option<DiscoveryConfig>,
        trigger_type: TriggerType,
        requested_by: Option<Uuid>,
    ) -> Result<DiscoveryRun, ApiError> {
        // Check if discovery is already running for this company
        {
            let statuses = self.status.lock().await;
            if statuses
                .get(&company_id)
                .map(|status| status.is_running)
                .unwrap_or(false)
            {
                return Err(ApiError::Validation(
                    "Discovery is already running".to_string(),
                ));
            }
        }

        if let Some(user_id) = requested_by {
            let settings = self.current_settings();
            let active = self
                .task_manager
                .count_active_tasks_by_requester(&user_id.to_string(), TaskType::Discovery)
                .await;
            if active >= settings.max_active_discovery_per_user as usize {
                return Err(ApiError::RateLimit(format!(
                    "Too many active discovery tasks (limit {})",
                    settings.max_active_discovery_per_user
                )));
            }
        }

        // Create a new discovery run
        let trigger_type_clone = trigger_type.clone();
        let run_create = DiscoveryRunCreate {
            trigger_type: Some(trigger_type_clone),
            config: config
                .as_ref()
                .map(|c| serde_json::to_value(c).unwrap_or(json!({}))),
        };

        let run = self
            .discovery_run_repo
            .create(&run_create, company_id)
            .await?;
        let run_id = run.id;

        tracing::info!(
            run_id = %run_id,
            company_id = %company_id,
            trigger_type = ?trigger_type,
            requested_by = ?requested_by,
            "Created discovery run"
        );

        // Update status. Replace the whole struct rather than patching fields:
        // the counters, the queue depth and the auto-scan threshold all belong
        // to the previous run, and a new run that inherits them reports the
        // last run's numbers until it happens to overwrite each one.
        {
            let mut statuses = self.status.lock().await;
            statuses.insert(
                company_id,
                DiscoveryStatus {
                    is_running: true,
                    run_id: Some(run_id),
                    started_at: Some(Utc::now()),
                    current_phase: "Initializing".to_string(),
                    ..DiscoveryStatus::default()
                },
            );
        }

        // Submit discovery task to TaskManager
        let discovery_service = self.clone();
        let config_arc = Arc::new(config);

        let task_metadata = json!({
            "discovery_run_id": run_id,
            "started_at": Utc::now(),
            "company_id": company_id,
            "requested_by": requested_by.map(|id| id.to_string()),
        });

        let task_id = self
            .task_manager
            .submit_task(TaskType::Discovery, task_metadata, move |ctx| {
                let discovery_service = discovery_service.clone();
                let config_clone = (*config_arc).clone();
                Box::pin(async move {
                    discovery_service
                        .execute_discovery(ctx, run_id, company_id, config_clone)
                        .await
                })
            })
            .await?;

        // Store the task ID for cancellation support
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.task_id = Some(task_id);
        }

        Ok(run)
    }

    /// Stop the running discovery.
    ///
    /// Stopping is not just "abort the discovery task". A run owns three other
    /// things that outlive that task and all had to be taken down with it:
    ///
    ///  - the security scans it auto-triggered, which are separate tasks and
    ///    used to keep probing after the run they belonged to was stopped;
    ///  - its queue, whose pending rows were left behind for a run that will
    ///    never dequeue them again;
    ///  - its live counters, which stayed on screen and were still there when
    ///    the next run started, so a fresh run opened showing the last one's
    ///    seeds, discoveries and errors.
    pub async fn stop_discovery(&self, company_id: Uuid) -> Result<(), ApiError> {
        let (run_id, task_id, seeds_processed, assets_discovered, assets_updated) = {
            let statuses = self.status.lock().await;
            let status = statuses.get(&company_id).cloned().unwrap_or_default();
            if !status.is_running {
                return Err(ApiError::Validation("Discovery is not running".to_string()));
            }
            (
                status.run_id,
                status.task_id,
                status.seeds_processed,
                status.assets_discovered,
                status.assets_updated,
            )
        };

        // Cancel the task in TaskManager first - this will signal the task to stop
        if let Some(tid) = task_id {
            if let Err(e) = self.task_manager.cancel_task(tid).await {
                tracing::warn!("Failed to cancel discovery task {}: {}", tid, e);
                // Continue anyway - the task might have already completed
            } else {
                tracing::info!("Cancelled discovery task {}", tid);
            }
        }

        let mut scans_cancelled = 0usize;
        let mut mark_cancelled = None;

        if let Some(id) = run_id {
            // The run's own scans. Aborting the discovery task cannot reach
            // them: each auto-scan was submitted as its own task and would
            // otherwise run to completion against targets the operator has
            // just asked us to stop touching.
            if let Some(scan_service) = &self.security_scan_service {
                match scan_service
                    .cancel_scans_for_discovery_run(&id, company_id)
                    .await
                {
                    Ok(count) => scans_cancelled = count,
                    Err(e) => tracing::warn!(
                        "Failed to cancel scans for stopped discovery run {}: {}",
                        id,
                        e
                    ),
                }
            }

            // The counters are only written to the run row at the end of a
            // successful pass, which a stopped run never reaches -- so a
            // cancelled run used to be filed as 0 seeds, 0 assets whatever it
            // had actually found. Persist what it did before letting go of it.
            if let Err(e) = self
                .discovery_run_repo
                .update_progress(
                    company_id,
                    &id,
                    seeds_processed as i32,
                    assets_discovered as i32,
                    assets_updated as i32,
                )
                .await
            {
                tracing::warn!(
                    "Failed to persist progress for stopped discovery run {}: {}",
                    id,
                    e
                );
            }

            // Mark run as cancelled in the database. Held rather than
            // propagated: the in-memory reset below has to happen either way,
            // or a company whose run row cannot be written stays wedged at
            // "discovery is already running" and can never start another.
            mark_cancelled = Some(
                self.discovery_run_repo
                    .update_status(company_id, &id, "cancelled", Some("Stopped by user"))
                    .await,
            );

            // Nothing will dequeue this run again, so its pending rows are
            // dead weight; clearing them also means an exclusion added later
            // has no stale queue to disagree with.
            if let Err(e) = self.discovery_queue_repo.clear_run(&id).await {
                tracing::warn!("Failed to clear queue for discovery run {}: {}", id, e);
            }

            self.forget_run_caches(&id).await;
        }

        // Reset the live counters. Everything worth keeping is now on the run
        // row; what is left here is only ever read as "the run happening now".
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            let stopped_run = status.run_id;
            let stopped_at = status.started_at;
            *status = DiscoveryStatus {
                // Kept so the UI can still name the run it just stopped.
                run_id: stopped_run,
                started_at: stopped_at,
                completed_at: Some(Utc::now()),
                current_phase: "Cancelled".to_string(),
                ..DiscoveryStatus::default()
            };
        }

        tracing::info!(
            company_id = %company_id,
            run_id = ?run_id,
            scans_cancelled,
            "Stopped discovery run"
        );

        if let Some(result) = mark_cancelled {
            result?;
        }

        Ok(())
    }

    /// Drop the per-run memoisation held for `run_id`.
    ///
    /// `swept_prefixes` is keyed by run, so entries for a finished run are only
    /// ever dead weight -- and on a long-lived process they never went away.
    async fn forget_run_caches(&self, run_id: &Uuid) {
        let mut swept = self.swept_prefixes.lock().await;
        swept.retain(|(swept_run, _)| swept_run != run_id);
    }

    /// Make a new exclusion entry take effect on work already in flight.
    ///
    /// Discovery checks the list on the way in, so an entry added between runs
    /// needs nothing. An entry added *during* one does: the run has a queue full
    /// of items it decided to visit before the entry existed, and — if the entry
    /// blacklists them — scans already probing hosts that are about to be
    /// deleted. Neither notices on its own; the queue item would only be dropped
    /// when its turn finally came, and the scan not at all.
    ///
    /// Scans are only cancelled for a blacklist. An ordinary exclusion is the
    /// operator saying "stop finding more of this", not "stop scanning what I
    /// have", and killing a scan already halfway through the asset they are
    /// keeping would be the opposite of what they asked for.
    ///
    /// Returns `(queue items skipped, scans cancelled)`.
    pub async fn apply_exclusion_entry(
        &self,
        company_id: Uuid,
        object_type: &ExclusionObjectType,
        object_value: &str,
        blacklisted: bool,
    ) -> Result<(i64, usize), ApiError> {
        // First, so nothing below reads a stale snapshot.
        self.invalidate_exclusion_cache(company_id).await;

        let queue_items_skipped = self
            .discovery_queue_repo
            .purge_excluded(company_id, object_type, object_value)
            .await?;

        // The queue shrank, so the reported depth has to shrink with it --
        // otherwise the run advertises pending work it will never do.
        if queue_items_skipped > 0 {
            let run_id = {
                let statuses = self.status.lock().await;
                statuses
                    .get(&company_id)
                    .filter(|status| status.is_running)
                    .and_then(|status| status.run_id)
            };
            if let Some(run_id) = run_id {
                if let Ok(pending) = self.discovery_queue_repo.get_pending_count(&run_id).await {
                    let mut statuses = self.status.lock().await;
                    if let Some(status) = statuses.get_mut(&company_id) {
                        status.queue_pending = pending.try_into().unwrap_or(0);
                    }
                }
            }
        }

        let scans_cancelled = if blacklisted {
            self.cancel_scans_for_blacklisted(company_id, object_type, object_value)
                .await?
        } else {
            0
        };

        if queue_items_skipped > 0 || scans_cancelled > 0 {
            tracing::info!(
                company_id = %company_id,
                object_type = %object_type,
                object_value = %object_value,
                blacklisted,
                queue_items_skipped,
                scans_cancelled,
                "Applied exclusion entry to in-flight discovery"
            );
        }

        Ok((queue_items_skipped, scans_cancelled))
    }

    /// Stop any scan still running against an asset the entry blacklists.
    async fn cancel_scans_for_blacklisted(
        &self,
        company_id: Uuid,
        object_type: &ExclusionObjectType,
        object_value: &str,
    ) -> Result<usize, ApiError> {
        let Some(scan_service) = &self.security_scan_service else {
            return Ok(0);
        };

        // Every asset the entry covers, not just the one named: blacklisting a
        // domain excludes its subdomains, and a CIDR excludes every address in
        // it -- each of which can have a scan of its own in flight.
        let asset_ids = self
            .asset_repo
            .find_excluded_ids(company_id, object_type, object_value)
            .await?;

        scan_service
            .cancel_scans_for_assets(&asset_ids, company_id, "Cancelled: target blacklisted")
            .await
    }

    // ========================================================================
    // DISCOVERY EXECUTION
    // ========================================================================

    /// Main discovery execution loop
    async fn execute_discovery(
        &self,
        ctx: TaskContext,
        run_id: Uuid,
        company_id: Uuid,
        config: Option<DiscoveryConfig>,
    ) -> Result<(), ApiError> {
        tracing::info!("Starting discovery run {}", run_id);

        // Mark run as started
        self.discovery_run_repo.start(company_id, &run_id).await?;

        let result = self
            .execute_discovery_internal(&ctx, run_id, company_id, config)
            .await;

        // Finalize discovery run.
        //
        // Cancellation reaches here only when the task noticed it at a
        // `check_cancellation` before the abort landed; `stop_discovery` does
        // the same tidy-up for the abort case, and both are idempotent.
        let cancelled = match &result {
            Ok(_) => false,
            Err(e) => {
                let error_msg = e.to_string();
                error_msg.contains("cancelled") || error_msg.contains("Task was cancelled")
            }
        };

        if cancelled {
            // What the run managed before it was stopped, filed against the run
            // itself. `execute_discovery_internal` only writes these once it has
            // drained the queue, which a cancelled run never does.
            let (seeds_processed, assets_discovered, assets_updated) = {
                let statuses = self.status.lock().await;
                statuses
                    .get(&company_id)
                    .map(|status| {
                        (
                            status.seeds_processed,
                            status.assets_discovered,
                            status.assets_updated,
                        )
                    })
                    .unwrap_or((0, 0, 0))
            };
            if let Err(e) = self
                .discovery_run_repo
                .update_progress(
                    company_id,
                    &run_id,
                    seeds_processed as i32,
                    assets_discovered as i32,
                    assets_updated as i32,
                )
                .await
            {
                tracing::warn!(
                    "Failed to persist progress for cancelled discovery run {}: {}",
                    run_id,
                    e
                );
            }

            if let Some(scan_service) = &self.security_scan_service {
                if let Err(e) = scan_service
                    .cancel_scans_for_discovery_run(&run_id, company_id)
                    .await
                {
                    tracing::warn!(
                        "Failed to cancel scans for cancelled discovery run {}: {}",
                        run_id,
                        e
                    );
                }
            }
            if let Err(e) = self.discovery_queue_repo.clear_run(&run_id).await {
                tracing::warn!("Failed to clear queue for discovery run {}: {}", run_id, e);
            }
        }

        self.forget_run_caches(&run_id).await;

        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.is_running = false;
            status.completed_at = Some(Utc::now());
            status.task_id = None; // Clear task ID on completion
            status.queue_pending = 0;

            match &result {
                Ok(_) => {
                    status.current_phase = "Completed".to_string();
                    self.discovery_run_repo
                        .complete(company_id, &run_id)
                        .await?;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    if cancelled {
                        // Same reset as `stop_discovery`: the run's numbers live
                        // on its row from here, and leaving them here would seed
                        // the next run with them.
                        let stopped_run = status.run_id;
                        let stopped_at = status.started_at;
                        *status = DiscoveryStatus {
                            run_id: stopped_run,
                            started_at: stopped_at,
                            completed_at: Some(Utc::now()),
                            current_phase: "Cancelled".to_string(),
                            ..DiscoveryStatus::default()
                        };
                        self.discovery_run_repo
                            .update_status(
                                company_id,
                                &run_id,
                                "cancelled",
                                Some("Task was cancelled"),
                            )
                            .await?;
                    } else {
                        status.current_phase = "Failed".to_string();
                        status.errors.push(error_msg.clone());
                        self.discovery_run_repo
                            .fail(company_id, &run_id, &error_msg)
                            .await?;
                    }
                }
            }
        }

        result
    }

    async fn execute_discovery_internal(
        &self,
        ctx: &TaskContext,
        run_id: Uuid,
        company_id: Uuid,
        config: Option<DiscoveryConfig>,
    ) -> Result<(), ApiError> {
        // Load seeds
        let all_seeds = self.seed_repo.list(company_id).await?;
        let (seeds, missing_seed_ids) = Self::filter_seeds_by_requested_ids(
            all_seeds,
            config.as_ref().and_then(|c| c.seed_ids.as_ref()),
        );
        if !missing_seed_ids.is_empty() {
            tracing::warn!(
                "Discovery run {} requested {} seed_ids that do not exist for company {}: {:?}",
                run_id,
                missing_seed_ids.len(),
                company_id,
                missing_seed_ids
            );
        }
        if config
            .as_ref()
            .and_then(|c| c.seed_ids.as_ref())
            .map(|ids| !ids.is_empty())
            .unwrap_or(false)
        {
            tracing::info!(
                "Discovery run {} filtered seeds by seed_ids: {} selected",
                run_id,
                seeds.len()
            );
        }
        let seed_count = seeds.len();

        // Extract auto_scan_threshold from config
        let auto_scan_threshold = config
            .as_ref()
            .and_then(|c| c.auto_scan_threshold)
            .unwrap_or(0.0);
        let settings = self.current_settings();

        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.seeds_total = seed_count;
            status.current_phase = "Loading seeds".to_string();
            status.auto_scan_threshold = auto_scan_threshold;
            status.scans_queued = 0;
        }

        if auto_scan_threshold > 0.0 {
            tracing::info!(
                "Auto-scan enabled: assets with confidence >= {:.2} will be scanned",
                auto_scan_threshold
            );
        }

        ctx.update_progress(0.05, Some(format!("Found {} seeds", seed_count)))
            .await?;

        if seeds.is_empty() {
            tracing::info!("No seeds to process");
            return Ok(());
        }

        // Phase 1: Queue all seeds for processing
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.current_phase = "Queuing seeds".to_string();
        }

        let mut blacklisted_seeds = 0usize;

        for seed in &seeds {
            ctx.check_cancellation().await?;

            let item_type = match seed.seed_type {
                SeedType::Domain => QueueItemType::Domain,
                SeedType::Organization => QueueItemType::Organization,
                SeedType::Asn => QueueItemType::Asn,
                SeedType::Cidr => QueueItemType::Cidr,
                SeedType::Keyword => QueueItemType::Domain, // Keywords search for domains
            };
            let item_value = if seed.seed_type == SeedType::Domain {
                Self::normalize_discovery_hostname(&seed.value)
                    .unwrap_or_else(|| seed.value.trim().trim_end_matches('.').to_lowercase())
            } else {
                seed.value.clone()
            };

            // A blacklisted seed is never queued. It would be dropped at
            // dequeue anyway, but queueing it first reports pending work the
            // run has already decided not to do, and counts against the seed
            // total the UI shows progress against.
            //
            // A merely excluded one is queued: the run will not expand on it,
            // but it will auto-scan the asset the seed names, and that is work
            // the progress bar should account for.
            if self
                .exclusion_level(company_id, &item_type.to_string(), &item_value)
                .await?
                .is_blacklisted()
            {
                blacklisted_seeds += 1;
                tracing::info!(
                    run_id = %run_id,
                    seed = %item_value,
                    "Skipping blacklisted seed"
                );
                continue;
            }

            let item = DiscoveryQueueItemCreate {
                discovery_run_id: run_id,
                item_type,
                item_value,
                parent_asset_id: None,
                seed_id: Some(seed.id),
                depth: 0,
                priority: 10, // Seeds have highest priority
            };

            self.discovery_queue_repo.enqueue(&item).await?;
        }

        // Everything downstream counts seeds this run will actually walk: the
        // progress bar divides by it, and the run row records it as the number
        // of seeds processed.
        let seed_count = seed_count.saturating_sub(blacklisted_seeds);

        if blacklisted_seeds > 0 {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.seeds_total = seed_count;
            if status.errors.len() < 50 {
                status.errors.push(format!(
                    "{} seed{} skipped (blacklisted)",
                    blacklisted_seeds,
                    if blacklisted_seeds == 1 { "" } else { "s" }
                ));
            }
        }

        if seed_count == 0 {
            tracing::info!(
                "All seeds for run {} are blacklisted; nothing to do",
                run_id
            );
            return Ok(());
        }

        ctx.update_progress(0.1, Some("Seeds queued".to_string()))
            .await?;

        // Phase 2: Process queue
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.current_phase = "Processing discovery queue".to_string();
        }

        let max_depth = config
            .as_ref()
            .and_then(|c| c.max_depth)
            .unwrap_or(settings.max_discovery_depth);
        let max_assets_per_discovery = settings.max_assets_per_discovery as usize;

        let mut total_result = DiscoveryResult::default();
        let mut unique_discovered_assets: HashSet<Uuid> = HashSet::new();
        let mut processed = 0;

        'queue_loop: loop {
            ctx.check_cancellation().await?;

            // Get pending count
            let pending = self.discovery_queue_repo.get_pending_count(&run_id).await?;

            {
                let mut statuses = self.status.lock().await;
                let status = statuses
                    .entry(company_id)
                    .or_insert_with(DiscoveryStatus::default);
                status.queue_pending = pending.try_into().unwrap_or(0);
            }

            if pending == 0 {
                break;
            }

            // Dequeue batch
            let batch = self.discovery_queue_repo.dequeue(&run_id, 10).await?;

            if batch.is_empty() {
                break;
            }

            // Process batch
            for item in batch {
                ctx.check_cancellation().await?;

                // Skip if over depth limit
                if item.depth > max_depth as i32 {
                    self.discovery_queue_repo.skip_item(&item.id).await?;
                    continue;
                }

                // Process the queue item
                let result = self
                    .process_queue_item(
                        run_id,
                        company_id,
                        &item.item_type,
                        &item.item_value,
                        item.seed_id,
                        item.parent_asset_id,
                        item.depth,
                        max_depth as i32,
                    )
                    .await;

                match result {
                    Ok(item_result) => {
                        self.discovery_queue_repo.complete_item(&item.id).await?;
                        unique_discovered_assets.extend(item_result.assets_created.iter().copied());
                        unique_discovered_assets.extend(item_result.assets_updated.iter().copied());
                        total_result.merge(item_result);
                        if unique_discovered_assets.len() >= max_assets_per_discovery {
                            let warning = format!(
                                "Discovery asset cap reached ({} unique assets). Stopping further queue processing.",
                                max_assets_per_discovery
                            );
                            tracing::warn!(
                                run_id = %run_id,
                                company_id = %company_id,
                                "{}",
                                warning
                            );
                            total_result.warnings.push(warning.clone());
                            let mut statuses = self.status.lock().await;
                            let status = statuses
                                .entry(company_id)
                                .or_insert_with(DiscoveryStatus::default);
                            status.current_phase = "Asset cap reached".to_string();
                            if status.errors.len() < 50 {
                                status.errors.push(warning);
                            }
                            drop(statuses);
                            self.discovery_queue_repo.clear_run(&run_id).await?;
                            break 'queue_loop;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to process queue item {}: {}", item.item_value, e);
                        self.discovery_queue_repo
                            .fail_item(&item.id, &e.to_string())
                            .await?;
                        total_result
                            .warnings
                            .push(format!("{}: {}", item.item_value, e));
                    }
                }

                processed += 1;

                // Update progress
                let pending_usize: usize = pending.try_into().unwrap_or(0);
                let progress =
                    0.1 + (0.8 * (processed as f32 / (processed + pending_usize).max(1) as f32));
                ctx.update_progress(progress, Some(format!("Processed {} items", processed)))
                    .await?;

                // Update status
                {
                    let mut statuses = self.status.lock().await;
                    let status = statuses
                        .entry(company_id)
                        .or_insert_with(DiscoveryStatus::default);
                    status.seeds_processed = processed.min(seed_count);
                    status.assets_discovered = total_result.assets_created.len();
                    status.assets_updated = total_result.assets_updated.len();
                }
            }
        }

        // Update discovery run with final counts
        self.discovery_run_repo
            .update_progress(
                company_id,
                &run_id,
                seed_count as i32,
                total_result.assets_created.len() as i32,
                total_result.assets_updated.len() as i32,
            )
            .await?;

        if total_result.total_assets() > 0 {
            if let Err(e) = self
                .update_risk_history_for_assets(company_id, &total_result)
                .await
            {
                tracing::warn!("Failed to update risk history after discovery: {}", e);
            }
        }

        ctx.update_progress(0.95, Some("Finalizing".to_string()))
            .await?;

        tracing::info!(
            "Discovery run {} completed: {} seeds, {} new assets, {} updated",
            run_id,
            seed_count,
            total_result.assets_created.len(),
            total_result.assets_updated.len()
        );

        Ok(())
    }

    async fn update_risk_history_for_assets(
        &self,
        company_id: Uuid,
        result: &DiscoveryResult,
    ) -> Result<(), ApiError> {
        let mut asset_ids: HashSet<Uuid> = HashSet::new();
        asset_ids.extend(result.assets_created.iter().copied());
        asset_ids.extend(result.assets_updated.iter().copied());

        if asset_ids.is_empty() {
            return Ok(());
        }

        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.current_phase = "Updating risk scores".to_string();
        }

        for asset_id in asset_ids {
            if let Err(e) = self
                .risk_service
                .calculate_asset_risk(company_id, asset_id)
                .await
            {
                tracing::warn!(
                    "Failed to calculate risk for asset {} after discovery: {}",
                    asset_id,
                    e
                );
                let mut statuses = self.status.lock().await;
                let status = statuses
                    .entry(company_id)
                    .or_insert_with(DiscoveryStatus::default);
                if status.errors.len() < 50 {
                    status
                        .errors
                        .push(format!("Risk calc failed for asset {}", asset_id));
                }
            }
        }

        Ok(())
    }

    /// Process a single queue item
    async fn process_queue_item(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        item_type: &str,
        item_value: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        tracing::debug!(
            "Processing {} '{}' at depth {} (max: {})",
            item_type,
            item_value,
            depth,
            max_depth
        );

        // An excluded item is not expanded on. What that means depends on the
        // strength of the entry: a blacklisted one must not be touched at all,
        // while an ordinary exclusion still leaves an asset the operator owns
        // and expects to see scan results for, so the run scans what is already
        // there and stops short of looking for more of it.
        match self
            .exclusion_level(company_id, item_type, item_value)
            .await?
        {
            ExclusionLevel::None => {}
            ExclusionLevel::Blacklisted => {
                tracing::info!(
                    "Skipping blacklisted {} '{}' during discovery",
                    item_type,
                    item_value
                );
                return Ok(DiscoveryResult::default());
            }
            ExclusionLevel::Excluded => {
                tracing::info!(
                    "Not expanding excluded {} '{}'; auto-scanning it if it is already known",
                    item_type,
                    item_value
                );
                self.auto_scan_known_asset(run_id, company_id, item_type, item_value)
                    .await;
                return Ok(DiscoveryResult::default());
            }
        }

        match item_type {
            "domain" => {
                self.discover_from_domain(
                    run_id,
                    company_id,
                    item_value,
                    seed_id,
                    parent_asset_id,
                    depth,
                    max_depth,
                )
                .await
            }
            "organization" => {
                self.discover_from_organization(
                    run_id,
                    company_id,
                    item_value,
                    seed_id,
                    parent_asset_id,
                    depth,
                    max_depth,
                )
                .await
            }
            "asn" => {
                self.discover_from_asn(
                    run_id,
                    company_id,
                    item_value,
                    seed_id,
                    parent_asset_id,
                    depth,
                    max_depth,
                )
                .await
            }
            "cidr" => {
                self.discover_from_cidr(
                    run_id,
                    company_id,
                    item_value,
                    seed_id,
                    parent_asset_id,
                    depth,
                    max_depth,
                )
                .await
            }
            "ip" => {
                self.discover_from_ip(
                    run_id,
                    company_id,
                    item_value,
                    seed_id,
                    parent_asset_id,
                    depth,
                    max_depth,
                )
                .await
            }
            _ => {
                tracing::warn!("Unknown item type: {}", item_type);
                Ok(DiscoveryResult::default())
            }
        }
    }

    /// The company's exclusion list, from cache when it is still fresh.
    async fn exclusion_snapshot(
        &self,
        company_id: Uuid,
    ) -> Result<Arc<ExclusionSnapshot>, ApiError> {
        {
            let cache = self.exclusion_cache.lock().await;
            if let Some(snapshot) = cache.get(&company_id) {
                if !snapshot.is_expired() {
                    return Ok(Arc::clone(snapshot));
                }
            }
        }

        // Loaded outside the lock: holding it across the query would serialise
        // every concurrent discovery on one database round-trip. Two callers
        // refreshing at once both get a correct snapshot and the later write
        // wins, which is the same result as one refreshing.
        let entries = self.exclusion_repo.list_all(company_id).await?;
        let snapshot = Arc::new(ExclusionSnapshot::from_entries(entries));

        let mut cache = self.exclusion_cache.lock().await;
        cache.insert(company_id, Arc::clone(&snapshot));
        Ok(snapshot)
    }

    /// Drop a company's cached exclusion list so the next check reads it again.
    ///
    /// Called whenever the list changes, so an entry added during a run takes
    /// effect on the next asset discovery considers rather than at the end of
    /// the cache window.
    pub async fn invalidate_exclusion_cache(&self, company_id: Uuid) {
        let mut cache = self.exclusion_cache.lock().await;
        cache.remove(&company_id);
    }

    /// How strongly, if at all, the exclusion list covers an item.
    async fn exclusion_level(
        &self,
        company_id: Uuid,
        item_type: &str,
        item_value: &str,
    ) -> Result<ExclusionLevel, ApiError> {
        let exclusions = self.exclusion_snapshot(company_id).await?;
        if exclusions.is_empty() {
            return Ok(ExclusionLevel::None);
        }

        Ok(exclusions.level(item_type, item_value))
    }

    /// How the exclusion list covers an asset about to be written.
    ///
    /// This is the gate every discovery path goes through. The per-technique
    /// checks it backs up covered the queue and the subdomain enumerators, but
    /// not resolution, certificate SANs, reverse DNS, CIDR expansion or the
    /// Shodan pivots -- so an excluded host stayed out of the queue and was
    /// written anyway the moment another path turned it up.
    async fn asset_exclusion_level(
        &self,
        company_id: Uuid,
        asset_type: &AssetType,
        identifier: &str,
    ) -> Result<ExclusionLevel, ApiError> {
        let item_type = match asset_type {
            AssetType::Domain => "domain",
            AssetType::Ip => "ip",
            AssetType::Organization => "organization",
            AssetType::Asn => "asn",
            AssetType::Certificate => "certificate",
            // Ports are not excludable in their own right; the host they
            // belong to is what gets excluded.
            AssetType::Port => return Ok(ExclusionLevel::None),
        };

        self.exclusion_level(company_id, item_type, identifier)
            .await
    }

    /// Auto-scan an asset the run has decided not to expand on.
    ///
    /// An excluded object still belongs to the operator — excluding is about
    /// not growing the estate here, not about looking away from it — so the
    /// asset already in the inventory goes through the same auto-scan path a
    /// freshly discovered one would take. Nothing is written and nothing is
    /// enqueued: if the asset is not already known, there is nothing to scan,
    /// and finding out would be the discovery the exclusion just declined.
    async fn auto_scan_known_asset(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        item_type: &str,
        item_value: &str,
    ) {
        // Cheapest check first. With auto-scan off there is nothing this can
        // do, and the write gate reaches it once per encounter -- which for a
        // CDN name every host CNAMEs to is a great many encounters.
        if self.auto_scan_threshold(company_id).await <= 0.0 {
            return;
        }

        let asset_type = match item_type {
            "domain" => AssetType::Domain,
            "ip" => AssetType::Ip,
            "certificate" => AssetType::Certificate,
            // Organisations, ASNs and CIDRs are not scan targets. The hosts
            // under them are, and each is checked on its own way in.
            _ => return,
        };

        let identifier = if matches!(asset_type, AssetType::Domain) {
            Self::normalize_discovery_hostname(item_value)
                .unwrap_or_else(|| item_value.trim().trim_end_matches('.').to_lowercase())
        } else {
            item_value.trim().to_string()
        };

        let known = match self
            .asset_repo
            .get_by_identifier(company_id, asset_type.clone(), &identifier)
            .await
        {
            Ok(Some(asset)) => asset,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(
                    "Failed to look up excluded asset '{}' for auto-scan: {}",
                    identifier,
                    e
                );
                return;
            }
        };

        self.consider_auto_scan(
            run_id,
            company_id,
            known.id,
            &identifier,
            &asset_type,
            known.confidence,
        )
        .await;
    }

    /// The running run's auto-scan threshold, or 0.0 when nothing is running.
    ///
    /// It lives on the live status rather than on the run row, so it is read
    /// here rather than threaded through every caller.
    async fn auto_scan_threshold(&self, company_id: Uuid) -> f64 {
        let statuses = self.status.lock().await;
        statuses
            .get(&company_id)
            .map(|status| status.auto_scan_threshold)
            .unwrap_or(0.0)
    }

    /// Offer an asset to the auto-scan threshold, and count it if it clears.
    async fn consider_auto_scan(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        asset_id: Uuid,
        identifier: &str,
        asset_type: &AssetType,
        confidence: f64,
    ) {
        let threshold = self.auto_scan_threshold(company_id).await;
        if threshold <= 0.0 {
            return;
        }

        if let Err(e) = self
            .maybe_trigger_auto_scan(
                run_id,
                company_id,
                asset_id,
                identifier,
                asset_type,
                confidence,
                Some(threshold),
            )
            .await
        {
            tracing::warn!("Failed to trigger auto-scan for {}: {}", identifier, e);
        } else if confidence >= threshold {
            // Upper-bound counter; real dedup happens inside maybe_trigger_auto_scan.
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.scans_queued += 1;
        }
    }

    // ========================================================================
    // DISCOVERY BY TYPE
    // ========================================================================

    /// Discover assets from a domain
    async fn discover_from_domain(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        domain: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();
        let canonical_domain = Self::normalize_discovery_hostname(domain)
            .unwrap_or_else(|| domain.trim().trim_end_matches('.').to_lowercase());
        if canonical_domain.is_empty() {
            return Err(ApiError::Validation("Invalid domain format".to_string()));
        }

        let settings = self.current_settings();
        // Seeds are enqueued at depth 0; everything else is queued at parent depth + 1.
        // Never skip a seed on DNS resolution: an apex with no A/AAAA record (mail-only or
        // parked domains) still has subdomains worth enumerating, and dropping it here would
        // abandon the whole branch. The gate stays in place for discovered hostnames below.
        let is_seed = depth == 0;
        if settings.skip_unresolved_domains && !is_seed {
            let resolves = match self.dns_resolver.resolve_hostname(&canonical_domain).await {
                Ok(ips) => ips.iter().any(|ip| !ip.is_loopback()),
                Err(_) => false,
            };
            if !resolves {
                result.warnings.push(format!(
                    "Skipped {} (no non-loopback DNS resolution; skip_unresolved_domains enabled)",
                    canonical_domain
                ));
                return Ok(result);
            }
        }

        // Create the domain asset first (if it's not from a seed)
        let domain_asset = self
            .create_or_update_asset(
                run_id,
                company_id,
                AssetType::Domain,
                &canonical_domain,
                SourceType::Seed,
                1.0, // Full confidence for seed domains
                seed_id,
                parent_asset_id,
                Some(json!({ "discovery_depth": depth })),
            )
            .await?;

        // Excluded between the queue check and here, or reached by a path
        // that never went through the queue: there is no branch to walk.
        let Some(domain_asset) = domain_asset else {
            result
                .warnings
                .push(format!("Skipped {} (excluded)", canonical_domain));
            return Ok(result);
        };

        if domain_asset.1 {
            // was created
            result.assets_created.push(domain_asset.0);
        } else {
            result.assets_updated.push(domain_asset.0);
        }

        let domain_asset_id = domain_asset.0;

        // Every hostname the passive stage confirmed, in discovery order. The
        // active stage mutates these, so it has to run second.
        let mut passive_hostnames: Vec<String> = Vec::new();

        // Step 1: Passive enumeration — every configured OSINT corpus, in parallel
        match self
            .external_services
            .enumerate_subdomains(&canonical_domain)
            .await
        {
            Ok(subdomain_result) => {
                self.cache_ip_owner_hints(&subdomain_result.shodan_ip_owners)
                    .await;

                for execution in &subdomain_result.source_execution {
                    if execution.status == "failed" {
                        result.warnings.push(format!(
                            "{} enumeration failed: {}",
                            execution.source,
                            execution
                                .message
                                .clone()
                                .unwrap_or_else(|| "unknown error".to_string())
                        ));
                    }
                }

                for subdomain in &subdomain_result.subdomains {
                    if subdomain == &canonical_domain {
                        continue; // Skip the main domain
                    }

                    if settings.skip_unresolved_domains {
                        let resolves = match self.dns_resolver.resolve_hostname(subdomain).await {
                            Ok(ips) => ips.iter().any(|ip| !ip.is_loopback()),
                            Err(_) => false,
                        };
                        if !resolves {
                            result.warnings.push(format!(
                                "Skipped subdomain {} (no non-loopback DNS resolution)",
                                subdomain
                            ));
                            continue;
                        }
                    }

                    // Checked before the name joins `passive_hostnames`: that
                    // list is what the active stage permutes and resolves, so an
                    // excluded host left in it would still be probed even
                    // though no asset is written for it.
                    if self
                        .exclusion_level(company_id, "domain", subdomain)
                        .await?
                        .is_excluded()
                    {
                        continue;
                    }

                    passive_hostnames.push(subdomain.clone());

                    let source_types = subdomain_result
                        .hostname_sources
                        .get(subdomain)
                        .cloned()
                        .unwrap_or_else(|| vec![SourceType::UserInput]);
                    let source_names: Vec<String> =
                        source_types.iter().map(|s| s.to_string()).collect();
                    let confidence = Self::calculate_subdomain_confidence(&source_types);

                    let asset = self
                        .create_or_update_asset_with_sources(
                            run_id,
                            company_id,
                            AssetType::Domain,
                            subdomain,
                            source_types,
                            confidence,
                            seed_id,
                            Some(domain_asset_id),
                            Some(json!({
                                "parent_domain": canonical_domain.clone(),
                                "discovered_by_sources": source_names,
                            })),
                        )
                        .await?;

                    let Some(asset) = asset else {
                        continue;
                    };

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    } else {
                        result.assets_updated.push(asset.0);
                    }

                    // Create relationship
                    self.create_relationship(
                        run_id,
                        domain_asset_id,
                        asset.0,
                        RelationshipType::HasSubdomain,
                        confidence,
                    )
                    .await?;

                    // Queue subdomain for its own discovery (DNS, certs, etc.) if depth allows
                    // This enables deeper exploration when max_depth is increased
                    // NOTE: Pass domain_asset_id as parent (not the subdomain's own ID!)
                    // to maintain correct lineage
                    if depth < max_depth {
                        self.queue_for_discovery(
                            run_id,
                            QueueItemType::Domain,
                            subdomain,
                            seed_id,
                            Some(domain_asset_id),
                            depth + 1,
                            4, // Slightly lower priority than seeds
                        )
                        .await?;
                    }
                }
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Subdomain enumeration failed: {}", e));
            }
        }

        // Step 2: Active DNS discovery — the names no corpus ever recorded.
        //
        // Wildcard detection runs inside this stage and gates everything that
        // follows it; without it a catch-all zone would "confirm" the entire
        // wordlist. Seeded with the passive results so permutation has real
        // names to mutate.
        if settings.enable_dns_bruteforce
            || settings.enable_dns_permutations
            || settings.enable_nsec_walk
            || settings.enable_srv_probe
        {
            match self
                .run_active_dns(
                    run_id,
                    company_id,
                    &canonical_domain,
                    domain_asset_id,
                    seed_id,
                    &passive_hostnames,
                    depth,
                    max_depth,
                )
                .await
            {
                Ok((active_result, active)) => {
                    tracing::info!(
                        "Active DNS for {}: {} brute-forced, {} permuted, {} from NSEC, {} SRV targets",
                        canonical_domain,
                        active.bruteforced.len(),
                        active.permutations.len(),
                        active.nsec_names.len(),
                        active.srv_targets.len()
                    );
                    result.merge(active_result);
                }
                Err(e) => {
                    tracing::warn!("Active DNS failed for {}: {}", canonical_domain, e);
                    result.warnings.push(format!("Active DNS failed: {}", e));
                }
            }
        }

        // Step 3: DNS resolution
        match self.dns_resolver.resolve_hostname(&canonical_domain).await {
            Ok(ips) => {
                for ip in ips {
                    let ip_str = ip.to_string();
                    let confidence = self
                        .confidence_scorer
                        .calculate_ip_confidence(vec!["dns_resolution".to_string()]);

                    let asset = self
                        .create_or_update_asset(
                            run_id,
                            company_id,
                            AssetType::Ip,
                            &ip_str,
                            SourceType::DnsResolution,
                            confidence,
                            seed_id,
                            Some(domain_asset_id),
                            Some(json!({ "resolved_from": canonical_domain.clone() })),
                        )
                        .await?;

                    let Some(asset) = asset else {
                        continue;
                    };

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    } else {
                        result.assets_updated.push(asset.0);
                    }

                    // Create relationship
                    self.create_relationship(
                        run_id,
                        domain_asset_id,
                        asset.0,
                        RelationshipType::ResolvesTo,
                        confidence,
                    )
                    .await?;

                    // Attribute the address to its origin AS and netblock. This
                    // is what turns a name inventory into an address-space
                    // inventory; cloud and CDN addresses are recognised and
                    // skipped inside the helper.
                    match self
                        .attribute_ip_infrastructure(run_id, company_id, &ip_str, asset.0, seed_id)
                        .await
                    {
                        Ok(attribution) => result.merge(attribution),
                        Err(e) => tracing::debug!("ASN attribution failed for {}: {}", ip_str, e),
                    }

                    // IP recursion is intentionally disabled: discovered IPs are persisted,
                    // but never enqueued for further recursive discovery.
                }
            }
            Err(e) => {
                tracing::debug!("DNS resolution failed for {}: {}", canonical_domain, e);
            }
        }

        // Step 4: TLS Certificate analysis (for pivoting)
        match self
            .http_analyzer
            .get_tls_certificate_info(&canonical_domain, 443)
            .await
        {
            Ok(cert_result) => {
                // Labelled so an excluded certificate can abandon just this
                // step. Everything under it -- the SAN names and the
                // organisation pivot -- hangs off the certificate asset, but
                // the steps after it do not.
                'certificate: {
                    if cert_result.certificate_chain.is_empty() {
                        break 'certificate;
                    }
                    let cert_info = &cert_result.certificate_chain[0];

                    let confidence = self.confidence_scorer.calculate_certificate_confidence(
                        cert_info.organization.is_some(),
                        vec!["tls_certificate".to_string()],
                    );

                    let cert_asset = self
                        .create_or_update_asset(
                            run_id,
                            company_id,
                            AssetType::Certificate,
                            &cert_info.subject,
                            SourceType::TlsCertificate,
                            confidence,
                            seed_id,
                            Some(domain_asset_id),
                            Some(json!({
                                "organization": cert_info.organization,
                                "issuer": cert_info.issuer,
                                "san_domains": cert_info.san_domains,
                            })),
                        )
                        .await?;

                    // An excluded certificate takes its SANs with it: they
                    // are only reachable through the certificate that lists
                    // them, and the block below hangs every one off it.
                    let Some(cert_asset) = cert_asset else {
                        break 'certificate;
                    };

                    if cert_asset.1 {
                        result.assets_created.push(cert_asset.0);
                    } else {
                        result.assets_updated.push(cert_asset.0);
                    }

                    self.create_relationship(
                        run_id,
                        domain_asset_id,
                        cert_asset.0,
                        RelationshipType::HasCertificate,
                        confidence,
                    )
                    .await?;

                    let san_confidence = self.calculate_multi_source_confidence(0.55, 1);
                    for san_domain in &cert_info.san_domains {
                        let Some(canonical_san_domain) =
                            Self::normalize_discovery_hostname(san_domain)
                        else {
                            continue;
                        };
                        if canonical_san_domain == canonical_domain {
                            continue;
                        }

                        let san_asset = self
                            .create_or_update_asset_with_sources(
                                run_id,
                                company_id,
                                AssetType::Domain,
                                &canonical_san_domain,
                                vec![SourceType::TlsCertificate],
                                san_confidence,
                                seed_id,
                                Some(cert_asset.0),
                                Some(json!({
                                    "discovered_from": "certificate_san",
                                    "certificate_subject": cert_info.subject.clone(),
                                    "certificate_parent_domain": canonical_domain.clone(),
                                })),
                            )
                            .await?;

                        let Some(san_asset) = san_asset else {
                            continue;
                        };

                        if san_asset.1 {
                            result.assets_created.push(san_asset.0);
                        } else {
                            result.assets_updated.push(san_asset.0);
                        }

                        self.create_relationship(
                            run_id,
                            san_asset.0,
                            cert_asset.0,
                            RelationshipType::HasCertificate,
                            san_confidence,
                        )
                        .await?;

                        if depth < max_depth {
                            self.queue_for_discovery(
                                run_id,
                                QueueItemType::Domain,
                                &canonical_san_domain,
                                seed_id,
                                Some(cert_asset.0),
                                depth + 1,
                                4,
                            )
                            .await?;
                        }
                    }

                    // Queue organization for discovery if found and depth allows
                    if let Some(ref org) = cert_info.organization {
                        if !Self::should_filter_organization(org) && depth < max_depth {
                            self.queue_for_discovery(
                                run_id,
                                QueueItemType::Organization,
                                org,
                                seed_id,
                                Some(cert_asset.0),
                                depth + 1,
                                5, // Lower priority for pivot
                            )
                            .await?;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "TLS certificate analysis failed for {}: {}",
                    canonical_domain,
                    e
                );
            }
        }

        // Step 5: SaaS tenancy from apex TXT verification tokens.
        if settings.enable_saas_tenant_discovery {
            match self
                .record_saas_tenancies(
                    run_id,
                    company_id,
                    &canonical_domain,
                    domain_asset_id,
                    seed_id,
                    depth,
                    max_depth,
                )
                .await
            {
                Ok(saas_result) => result.merge(saas_result),
                Err(e) => tracing::debug!(
                    "SaaS tenancy discovery failed for {}: {}",
                    canonical_domain,
                    e
                ),
            }
        }

        // Step 6: CNAME chain — the takeover surface, and the infrastructure
        // hostnames a CNAME points at along the way.
        if settings.enable_cname_chain_analysis {
            match self
                .record_cname_chain(
                    run_id,
                    company_id,
                    &canonical_domain,
                    domain_asset_id,
                    seed_id,
                    depth,
                    max_depth,
                )
                .await
            {
                Ok(cname_result) => result.merge(cname_result),
                Err(e) => tracing::debug!(
                    "CNAME chain analysis failed for {}: {}",
                    canonical_domain,
                    e
                ),
            }
        }

        // Step 7: Lateral OSINT pivots (favicon, HTML fingerprints, DNS metadata).
        // These surface apex domains that share infrastructure or mail relays with
        // the seed. By design they do NOT trigger further recursion — lateral hits
        // can be unrelated SaaS tenants and the analyst triages in the UI.
        if let Err(e) = self
            .run_lateral_pivots(
                run_id,
                company_id,
                &canonical_domain,
                domain_asset_id,
                seed_id,
            )
            .await
        {
            tracing::debug!("Lateral pivots failed for {}: {}", canonical_domain, e);
            result
                .warnings
                .push(format!("Lateral pivots failed: {}", e));
        }

        Ok(result)
    }

    /// Build the active-DNS configuration from the live settings.
    fn active_dns_config(&self, settings: &Settings) -> ActiveDnsConfig {
        ActiveDnsConfig {
            bruteforce_enabled: settings.enable_dns_bruteforce,
            permutations_enabled: settings.enable_dns_permutations,
            nsec_walk_enabled: settings.enable_nsec_walk,
            srv_probe_enabled: settings.enable_srv_probe,
            concurrency: settings.active_dns_concurrency.max(1) as usize,
            max_bruteforce_words: settings.dns_bruteforce_max_words as usize,
            max_permutations: settings.dns_permutation_max_candidates as usize,
            max_permutation_seeds: settings.dns_permutation_max_seeds as usize,
            wordlist_path: settings.dns_bruteforce_wordlist_path.clone(),
            query_timeout: self.dns_resolver.config().query_timeout,
        }
    }

    /// Run the active DNS stage and persist everything it finds.
    ///
    /// Runs *after* passive enumeration, because permutation needs known-good
    /// names to mutate and brute force should not re-resolve names a corpus
    /// already handed us. Each technique gets its own `SourceType`, so the
    /// asset graph records that a host was guessed rather than observed.
    #[allow(clippy::too_many_arguments)]
    async fn run_active_dns(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        canonical_domain: &str,
        domain_asset_id: Uuid,
        seed_id: Option<Uuid>,
        known_hostnames: &[String],
        depth: i32,
        max_depth: i32,
    ) -> Result<(DiscoveryResult, ActiveDnsResult), ApiError> {
        let settings = self.current_settings();
        let config = self.active_dns_config(&settings);

        let discovery = ActiveDnsDiscovery::new(Arc::clone(&self.dns_resolver), config);
        let active = discovery.discover(canonical_domain, known_hostnames).await;

        let mut result = DiscoveryResult::default();
        result.warnings.extend(active.warnings.iter().cloned());

        // Each technique is persisted separately so the source recorded against
        // an asset is the one that actually found it.
        let batches: Vec<(SourceType, Vec<String>, serde_json::Value)> = vec![
            (
                SourceType::NsecWalk,
                active.nsec_names.clone(),
                json!({
                    "technique": "dnssec_nsec_zone_walk",
                    "zone": canonical_domain,
                }),
            ),
            (
                SourceType::DnsBruteforce,
                active
                    .bruteforced
                    .iter()
                    .map(|host| host.hostname.clone())
                    .collect(),
                json!({
                    "technique": "dns_bruteforce",
                    "zone": canonical_domain,
                    "wildcard_filtered": !active.wildcard.wildcard_zones().is_empty(),
                }),
            ),
            (
                SourceType::DnsPermutation,
                active
                    .permutations
                    .iter()
                    .map(|host| host.hostname.clone())
                    .collect(),
                json!({
                    "technique": "dns_permutation",
                    "zone": canonical_domain,
                    "wildcard_filtered": !active.wildcard.wildcard_zones().is_empty(),
                }),
            ),
            (
                SourceType::SrvRecord,
                active
                    .srv_targets
                    .iter()
                    .map(|(_, target)| target.clone())
                    .collect(),
                json!({
                    "technique": "srv_record_probe",
                    "zone": canonical_domain,
                    "srv_labels": active
                        .srv_targets
                        .iter()
                        .map(|(label, _)| label.clone())
                        .collect::<Vec<_>>(),
                }),
            ),
        ];

        for (source, hostnames, metadata) in batches {
            if hostnames.is_empty() {
                continue;
            }
            // An SRV target routinely points outside the zone (a hosted PBX, a
            // mail provider); a name found *inside* the zone is a subdomain and
            // is worth recursing into, one found outside is not.
            let recurse = !matches!(source, SourceType::SrvRecord);
            let batch = self
                .persist_discovered_hostnames(
                    run_id,
                    company_id,
                    canonical_domain,
                    domain_asset_id,
                    seed_id,
                    source,
                    hostnames,
                    metadata,
                    RelationshipType::HasSubdomain,
                    recurse,
                    depth,
                    max_depth,
                )
                .await?;
            result.merge(batch);
        }

        Ok((result, active))
    }

    /// Persist a batch of hostnames discovered by one technique.
    ///
    /// Shared by every non-pivot discovery path so scoping, exclusion,
    /// relationship recording and recursion behave identically no matter which
    /// technique produced the name.
    #[allow(clippy::too_many_arguments)]
    async fn persist_discovered_hostnames(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        parent_domain: &str,
        parent_asset_id: Uuid,
        seed_id: Option<Uuid>,
        source: SourceType,
        hostnames: Vec<String>,
        metadata: serde_json::Value,
        relationship: RelationshipType,
        enqueue_for_recursion: bool,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();
        let confidence = source.confidence_weight();
        let mut seen: HashSet<String> = HashSet::new();

        for raw in hostnames {
            let Some(canonical) = Self::normalize_discovery_hostname(&raw) else {
                continue;
            };
            if canonical == parent_domain || !seen.insert(canonical.clone()) {
                continue;
            }

            let asset = self
                .create_or_update_asset_with_sources(
                    run_id,
                    company_id,
                    AssetType::Domain,
                    &canonical,
                    vec![source.clone()],
                    confidence,
                    seed_id,
                    Some(parent_asset_id),
                    Some(metadata.clone()),
                )
                .await?;

            // Excluded: no asset, no relationship, and nothing queued off it.
            let Some(asset) = asset else {
                continue;
            };

            if asset.1 {
                result.assets_created.push(asset.0);
            } else {
                result.assets_updated.push(asset.0);
            }

            self.create_relationship(
                run_id,
                parent_asset_id,
                asset.0,
                relationship.clone(),
                confidence,
            )
            .await?;

            // Only names inside the zone are recursed into. A CNAME target or
            // SRV host in somebody else's zone is evidence, not a branch to
            // enumerate on their behalf.
            let inside_zone =
                crate::services::external::active_dns::is_within(&canonical, parent_domain);
            if enqueue_for_recursion && inside_zone && depth < max_depth {
                self.queue_for_discovery(
                    run_id,
                    QueueItemType::Domain,
                    &canonical,
                    seed_id,
                    Some(parent_asset_id),
                    depth + 1,
                    4,
                )
                .await?;
            }
        }

        Ok(result)
    }

    /// Record the SaaS tenancies proven by the apex TXT records.
    ///
    /// A verification token is durable evidence that the organisation onboarded
    /// a vendor. Two things fall out of it: an inventory of third-party services
    /// holding the organisation's data, and a short list of predictable tenant
    /// hostnames (`support.`, `autodiscover.`, `status.`) worth resolving.
    #[allow(clippy::too_many_arguments)]
    async fn record_saas_tenancies(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        canonical_domain: &str,
        domain_asset_id: Uuid,
        seed_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        let tenancies = match self
            .dns_resolver
            .lookup_saas_tenancies(canonical_domain)
            .await
        {
            Ok(tenancies) => tenancies,
            Err(e) => {
                tracing::debug!("SaaS tenancy lookup failed for {}: {}", canonical_domain, e);
                return Ok(result);
            }
        };

        if tenancies.is_empty() {
            return Ok(result);
        }

        let vendors: Vec<&str> = tenancies.iter().map(|tenancy| tenancy.vendor).collect();
        tracing::info!(
            "{} publishes verification tokens for {} SaaS vendors: {}",
            canonical_domain,
            vendors.len(),
            vendors.join(", ")
        );

        // The vendor list belongs on the domain asset: it describes the domain,
        // not a separate asset of its own.
        if let Err(e) = self
            .asset_repo
            .merge_metadata(
                company_id,
                &domain_asset_id,
                json!({
                    "saas_tenancies": tenancies
                        .iter()
                        .map(|tenancy| json!({
                            "vendor": tenancy.vendor,
                            "token_prefix": tenancy.token_prefix,
                        }))
                        .collect::<Vec<_>>(),
                }),
            )
            .await
        {
            tracing::debug!(
                "Could not record SaaS tenancies on {}: {}",
                canonical_domain,
                e
            );
        }

        // Only the hostnames a tenancy actually implies; these are candidates
        // and are resolved before being kept, like any other guess.
        let mut implied: Vec<String> = Vec::new();
        for tenancy in &tenancies {
            if let Some(hostname) = tenancy.implied_hostname.as_ref() {
                match self.dns_resolver.resolve_hostname(hostname).await {
                    Ok(ips) if ips.iter().any(|ip| !ip.is_loopback()) => {
                        implied.push(hostname.clone())
                    }
                    _ => {}
                }
            }
        }

        if !implied.is_empty() {
            let batch = self
                .persist_discovered_hostnames(
                    run_id,
                    company_id,
                    canonical_domain,
                    domain_asset_id,
                    seed_id,
                    SourceType::TxtVerification,
                    implied,
                    json!({
                        "technique": "saas_verification_token",
                        "vendors": vendors,
                    }),
                    RelationshipType::HasSubdomain,
                    true,
                    depth,
                    max_depth,
                )
                .await?;
            result.merge(batch);
        }

        Ok(result)
    }

    /// Walk a hostname's CNAME chain and record every hop.
    ///
    /// The chain is where subdomain takeover lives: a CNAME still pointing at a
    /// deprovisioned cloud tenant is claimable by anyone. Recording the hops as
    /// assets puts them in front of the scanner rather than leaving them
    /// implicit. Targets outside the zone are recorded but never recursed into.
    #[allow(clippy::too_many_arguments)]
    async fn record_cname_chain(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        canonical_domain: &str,
        domain_asset_id: Uuid,
        seed_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let chain = match self
            .dns_resolver
            .lookup_cname_chain(canonical_domain, 8)
            .await
        {
            Ok(chain) if !chain.is_empty() => chain,
            _ => return Ok(DiscoveryResult::default()),
        };

        self.persist_discovered_hostnames(
            run_id,
            company_id,
            canonical_domain,
            domain_asset_id,
            seed_id,
            SourceType::CnameChain,
            chain.clone(),
            json!({
                "technique": "cname_chain",
                "source_hostname": canonical_domain,
                "chain": chain,
            }),
            RelationshipType::DiscoveredVia,
            true,
            depth,
            max_depth,
        )
        .await
    }

    /// Attribute an address to its AS and netblock, and record the ASN asset.
    ///
    /// This is the step that turns a list of names into a list of *owned
    /// address space*. Team Cymru answers the routing question over DNS;
    /// RIPEstat turns the AS number into the full set of prefixes it announces,
    /// which is where hosts with no DNS name at all are found.
    #[allow(clippy::too_many_arguments)]
    async fn attribute_ip_infrastructure(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        ip: &str,
        ip_asset_id: Uuid,
        seed_id: Option<Uuid>,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();
        let settings = self.current_settings();

        if !settings.enable_asn_discovery {
            return Ok(result);
        }
        let Some(client) = self.asn_client.as_ref() else {
            return Ok(result);
        };
        let Ok(parsed) = ip.parse::<std::net::IpAddr>() else {
            return Ok(result);
        };

        let attribution = match client.lookup_ip_asn(&parsed).await {
            Ok(attribution) => attribution,
            Err(e) => {
                tracing::debug!("ASN attribution failed for {}: {}", ip, e);
                return Ok(result);
            }
        };

        let Some(asn) = attribution.asn else {
            return Ok(result);
        };

        // A cloud or CDN AS is not the organisation's address space. Recording
        // "this asset belongs to AS16509" is true and useless; sweeping Amazon's
        // netblocks on its strength would be actively harmful.
        let owner = attribution.organization().unwrap_or_default().to_string();
        if self.is_known_cloud_provider_name(&owner) {
            tracing::debug!(
                "Skipping netblock expansion for {}: AS{} ({}) is shared infrastructure",
                ip,
                asn,
                owner
            );
            return Ok(result);
        }

        let asn_identifier = format!("AS{}", asn);
        let prefixes = match client.announced_prefixes(asn).await {
            Ok(prefixes) => prefixes,
            Err(e) => {
                tracing::debug!("RIPEstat prefix lookup failed for AS{}: {}", asn, e);
                Default::default()
            }
        };

        let recorded_prefixes: Vec<String> = prefixes
            .prefixes
            .iter()
            .take(settings.asn_max_prefixes as usize)
            .cloned()
            .collect();

        let asn_asset = self
            .create_or_update_asset_with_sources(
                run_id,
                company_id,
                AssetType::Asn,
                &asn_identifier,
                vec![SourceType::AsnNetblock],
                SourceType::AsnNetblock.confidence_weight(),
                seed_id,
                Some(ip_asset_id),
                Some(json!({
                    "technique": "bgp_origin_attribution",
                    "as_name": attribution.as_name,
                    "holder": prefixes.holder.clone().or(attribution.holder.clone()),
                    "country": attribution.country,
                    "registry": attribution.registry,
                    "announced_prefixes": recorded_prefixes,
                    "announced_prefix_count": prefixes.prefixes.len(),
                    "observed_prefix": attribution.prefix,
                    "attributed_from_ip": ip,
                })),
            )
            .await?;

        // An excluded AS is not attributed, and its prefix is not swept: the
        // sweep exists to enumerate that AS's address space.
        let Some(asn_asset) = asn_asset else {
            return Ok(result);
        };

        if asn_asset.1 {
            result.assets_created.push(asn_asset.0);
        } else {
            result.assets_updated.push(asn_asset.0);
        }

        self.create_relationship(
            run_id,
            asn_asset.0,
            ip_asset_id,
            RelationshipType::BelongsToAsn,
            SourceType::AsnNetblock.confidence_weight(),
        )
        .await?;

        // Sweep the covering prefix. Hosts with no forward DNS record still
        // usually have a PTR, which is why this finds management interfaces and
        // appliances that name-based enumeration never will.
        if let Some(prefix) = attribution.prefix.as_deref() {
            let sweep = self
                .reverse_sweep_prefix(run_id, company_id, prefix, asn_asset.0, seed_id)
                .await?;
            result.merge(sweep);
        }

        Ok(result)
    }

    /// Reverse-resolve every address in a netblock and record the names found.
    ///
    /// Bounded three ways, because an unbounded sweep of a large prefix is a
    /// denial-of-service against the target's own resolvers:
    ///
    /// - `reverse_dns_sweep_max_hosts` caps addresses per prefix (0 disables it)
    /// - a prefix is swept at most once per discovery run
    /// - the resolver's own concurrency and rate limits still apply
    ///
    /// Discovered names are recorded but never enqueued for recursion: a PTR in
    /// a shared hosting range routinely names somebody else's domain.
    async fn reverse_sweep_prefix(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        prefix: &str,
        asn_asset_id: Uuid,
        seed_id: Option<Uuid>,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();
        let settings = self.current_settings();
        let max_hosts = settings.reverse_dns_sweep_max_hosts as usize;
        if max_hosts == 0 {
            return Ok(result);
        }

        {
            let mut swept = self.swept_prefixes.lock().await;
            if !swept.insert((run_id, prefix.to_string())) {
                return Ok(result);
            }
        }

        let Ok(network) = prefix.parse::<ipnet::IpNet>() else {
            return Ok(result);
        };
        // `.take()` on the iterator rather than expanding first: a /16 would
        // otherwise materialise 65 534 addresses just to discard most of them.
        let addresses: Vec<std::net::IpAddr> = network.hosts().take(max_hosts).collect();
        if addresses.is_empty() {
            return Ok(result);
        }

        // The prefix length gives the host count arithmetically; calling
        // `.count()` on the iterator would walk all 65 534 addresses of a /16
        // purely to write a log line.
        let total_hosts =
            2u128.saturating_pow(u32::from(network.max_prefix_len() - network.prefix_len()));
        tracing::info!(
            "Reverse-sweeping {} ({} of {} addresses)",
            prefix,
            addresses.len(),
            total_hosts
        );

        let sweep = self.dns_resolver.reverse_lookup_concurrent(addresses).await;

        for entry in sweep {
            if entry.hostnames.is_empty() {
                continue;
            }
            let ip_str = entry.ip.to_string();

            let ip_asset = self
                .create_or_update_asset_with_sources(
                    run_id,
                    company_id,
                    AssetType::Ip,
                    &ip_str,
                    vec![SourceType::AsnNetblock],
                    SourceType::AsnNetblock.confidence_weight(),
                    seed_id,
                    Some(asn_asset_id),
                    Some(json!({
                        "technique": "reverse_dns_sweep",
                        "prefix": prefix,
                    })),
                )
                .await?;

            // Excluded address: its PTR names are not recorded either, since
            // they are only evidence about this address.
            let Some(ip_asset) = ip_asset else {
                continue;
            };

            if ip_asset.1 {
                result.assets_created.push(ip_asset.0);
            } else {
                result.assets_updated.push(ip_asset.0);
            }

            self.create_relationship(
                run_id,
                asn_asset_id,
                ip_asset.0,
                RelationshipType::BelongsToAsn,
                SourceType::AsnNetblock.confidence_weight(),
            )
            .await?;

            for hostname in entry.hostnames {
                let Some(canonical) = Self::normalize_discovery_hostname(&hostname) else {
                    continue;
                };
                let host_asset = self
                    .create_or_update_asset_with_sources(
                        run_id,
                        company_id,
                        AssetType::Domain,
                        &canonical,
                        vec![SourceType::ReverseDns],
                        SourceType::ReverseDns.confidence_weight(),
                        seed_id,
                        Some(ip_asset.0),
                        Some(json!({
                            "technique": "reverse_dns_sweep",
                            "prefix": prefix,
                            "reverse_resolved_from": ip_str,
                        })),
                    )
                    .await?;

                let Some(host_asset) = host_asset else {
                    continue;
                };

                if host_asset.1 {
                    result.assets_created.push(host_asset.0);
                } else {
                    result.assets_updated.push(host_asset.0);
                }

                self.create_relationship(
                    run_id,
                    ip_asset.0,
                    host_asset.0,
                    RelationshipType::ReverseResolvesTo,
                    SourceType::ReverseDns.confidence_weight(),
                )
                .await?;
            }
        }

        Ok(result)
    }

    /// Run all Phase-1 lateral OSINT pivots for a seed domain.
    ///
    /// Pivots fired (cost-bounded by the Shodan `host/count` pre-check):
    ///   - Favicon hash (Shodan `http.favicon.hash:`)
    ///   - HTML content fingerprints (Shodan `http.html:` for each unique
    ///     analytics/tag-manager/pixel ID found on the seed's homepage)
    ///   - DNS metadata: SPF `include:`/`redirect=`, DMARC `rua=`/`ruf=`,
    ///     MX hostnames
    ///
    /// All discovered apex domains are persisted as low-confidence assets with
    /// the appropriate `SourceType::*Pivot` variant and a `DiscoveredVia`
    /// (Shodan pivots) or `UsesMailInfrastructure` (DNS pivots) relationship to
    /// the seed. They are NOT enqueued for recursive discovery.
    async fn run_lateral_pivots(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        canonical_domain: &str,
        domain_asset_id: Uuid,
        seed_id: Option<Uuid>,
    ) -> Result<(), ApiError> {
        let settings = self.current_settings();
        let max_results = settings.lateral_pivot_max_results as usize;
        let max_html_needles = settings.lateral_pivot_max_html_needles as usize;
        let shodan_enabled = settings.shodan_lateral_pivots_enabled;

        // --- Favicon-hash pivot ---
        if shodan_enabled {
            match self
                .http_analyzer
                .fetch_favicon_hash(canonical_domain)
                .await
            {
                Ok(Some(hash)) => {
                    match self
                        .external_services
                        .shodan_favicon_pivot(hash, max_results)
                        .await
                    {
                        Ok(extracted) => {
                            self.persist_lateral_pivot_hosts(
                                run_id,
                                company_id,
                                domain_asset_id,
                                seed_id,
                                SourceType::FaviconPivot,
                                RelationshipType::DiscoveredVia,
                                extracted.domains.into_iter().collect(),
                                json!({
                                    "pivot": "favicon_hash",
                                    "favicon_hash": hash,
                                    "seed_domain": canonical_domain,
                                }),
                            )
                            .await?;
                        }
                        Err(e) => tracing::debug!(
                            "Shodan favicon pivot failed for {}: {}",
                            canonical_domain,
                            e
                        ),
                    }
                }
                Ok(None) => {
                    tracing::debug!("No favicon found for {}", canonical_domain);
                }
                Err(e) => {
                    tracing::debug!("Favicon fetch failed for {}: {}", canonical_domain, e);
                }
            }
        }

        // --- JARM pivot ---
        // JARM fingerprints a server's whole TLS stack, so it groups hosts by
        // *how they are built* rather than by what they serve — which is how
        // sibling infrastructure behind different names gets found. The
        // fingerprint is read from Shodan's own record so the value queried is
        // one its index actually contains.
        if shodan_enabled {
            match self.dns_resolver.resolve_hostname(canonical_domain).await {
                Ok(ips) => {
                    if let Some(ip) = ips.iter().find(|ip| !ip.is_loopback()) {
                        let ip_str = ip.to_string();
                        match self.external_services.shodan_jarm_for_ip(&ip_str).await {
                            Ok(Some(jarm)) => {
                                match self
                                    .external_services
                                    .shodan_jarm_pivot(&jarm, max_results)
                                    .await
                                {
                                    Ok(extracted) => {
                                        self.persist_lateral_pivot_hosts(
                                            run_id,
                                            company_id,
                                            domain_asset_id,
                                            seed_id,
                                            SourceType::JarmPivot,
                                            RelationshipType::DiscoveredVia,
                                            extracted.domains.into_iter().collect(),
                                            json!({
                                                "pivot": "jarm",
                                                "jarm": jarm,
                                                "observed_on_ip": ip_str,
                                                "seed_domain": canonical_domain,
                                            }),
                                        )
                                        .await?;
                                    }
                                    Err(e) => tracing::debug!(
                                        "Shodan JARM pivot failed for {}: {}",
                                        canonical_domain,
                                        e
                                    ),
                                }
                            }
                            Ok(None) => tracing::debug!(
                                "Shodan has no JARM fingerprint for {} ({})",
                                canonical_domain,
                                ip_str
                            ),
                            Err(e) => {
                                tracing::debug!("Shodan host lookup failed for {}: {}", ip_str, e)
                            }
                        }
                    }
                }
                Err(e) => tracing::debug!(
                    "Could not resolve {} for the JARM pivot: {}",
                    canonical_domain,
                    e
                ),
            }
        }

        // --- HTML content-fingerprint pivot ---
        if shodan_enabled && max_html_needles > 0 {
            let homepage_url = format!("https://{}/", canonical_domain);
            let probe = self.http_analyzer.probe_url(&homepage_url).await;
            // The probe only stores the title in HttpProbeResult; for fingerprint
            // extraction we need the body. Re-fetch the body via a single GET —
            // discovery already accepts an HTTP probe cost per domain.
            if probe.status_code.is_some() {
                if let Ok(body) =
                    Self::fetch_body_for_fingerprints(&self.http_analyzer, &homepage_url).await
                {
                    let fingerprints = self.http_analyzer.extract_html_fingerprints(&body);
                    let needles = fingerprints.pivot_needles(max_html_needles);
                    for needle in needles {
                        match self
                            .external_services
                            .shodan_html_pivot(&needle, max_results)
                            .await
                        {
                            Ok(extracted) => {
                                self.persist_lateral_pivot_hosts(
                                    run_id,
                                    company_id,
                                    domain_asset_id,
                                    seed_id,
                                    SourceType::AnalyticsIdPivot,
                                    RelationshipType::DiscoveredVia,
                                    extracted.domains.into_iter().collect(),
                                    json!({
                                        "pivot": "html_fingerprint",
                                        "needle": needle,
                                        "seed_domain": canonical_domain,
                                    }),
                                )
                                .await?;
                            }
                            Err(e) => tracing::debug!(
                                "Shodan HTML pivot failed for needle '{}': {}",
                                needle,
                                e
                            ),
                        }
                    }
                }
            }
        }

        // --- DNS metadata pivots: SPF / DMARC / MX ---
        // These do not depend on Shodan; even without an API key they yield value.
        if let Ok(spf) = self.dns_resolver.lookup_spf(canonical_domain).await {
            let mut spf_targets: Vec<String> = Vec::new();
            spf_targets.extend(spf.includes);
            spf_targets.extend(spf.hosts);
            spf_targets.extend(spf.exists);
            self.persist_lateral_pivot_hosts(
                run_id,
                company_id,
                domain_asset_id,
                seed_id,
                SourceType::SpfPivot,
                RelationshipType::UsesMailInfrastructure,
                spf_targets,
                json!({
                    "pivot": "spf",
                    "seed_domain": canonical_domain,
                }),
            )
            .await?;
        }

        if let Ok(dmarc) = self.dns_resolver.lookup_dmarc(canonical_domain).await {
            let mut dmarc_targets: Vec<String> = Vec::new();
            dmarc_targets.extend(dmarc.aggregate);
            dmarc_targets.extend(dmarc.forensic);
            self.persist_lateral_pivot_hosts(
                run_id,
                company_id,
                domain_asset_id,
                seed_id,
                SourceType::DmarcPivot,
                RelationshipType::UsesMailInfrastructure,
                dmarc_targets,
                json!({
                    "pivot": "dmarc",
                    "seed_domain": canonical_domain,
                }),
            )
            .await?;
        }

        if let Ok(mx) = self.dns_resolver.lookup_mx(canonical_domain).await {
            let mx_targets: Vec<String> = mx.into_iter().map(|(_, host)| host).collect();
            self.persist_lateral_pivot_hosts(
                run_id,
                company_id,
                domain_asset_id,
                seed_id,
                SourceType::MxPivot,
                RelationshipType::UsesMailInfrastructure,
                mx_targets,
                json!({
                    "pivot": "mx",
                    "seed_domain": canonical_domain,
                }),
            )
            .await?;
        }

        Ok(())
    }

    /// Fetch the response body for a single URL via the analyzer's underlying
    /// reqwest client. Used by the HTML-fingerprint pivot to retrieve the seed
    /// homepage body separately from `probe_url`, which discards it.
    async fn fetch_body_for_fingerprints(
        analyzer: &Arc<HttpAnalyzer>,
        url: &str,
    ) -> Result<String, ApiError> {
        // Use the analyzer's existing rate limiting indirectly by going through
        // probe_url first (already called); here we just do a lightweight GET.
        // A small dedicated reqwest client avoids polluting probe_url's API.
        let client = reqwest::Client::builder()
            .timeout(analyzer.config().request_timeout)
            .redirect(reqwest::redirect::Policy::limited(
                analyzer.config().max_redirects,
            ))
            .user_agent(&analyzer.config().user_agent)
            .build()
            .map_err(ApiError::HttpClient)?;
        let response = client.get(url).send().await.map_err(ApiError::HttpClient)?;
        if !response.status().is_success() {
            return Err(ApiError::ExternalService(format!(
                "HTML fetch returned {} for {}",
                response.status(),
                url
            )));
        }
        response.text().await.map_err(ApiError::HttpClient)
    }

    /// Persist a batch of lateral-pivot-discovered hostnames as low-confidence
    /// domain assets linked to the seed via the given relationship. Filters
    /// blank / malformed / self-matching / excluded infrastructure hostnames.
    /// Does NOT enqueue results for recursive discovery.
    #[allow(clippy::too_many_arguments)]
    async fn persist_lateral_pivot_hosts(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        seed_asset_id: Uuid,
        seed_id: Option<Uuid>,
        source_type: SourceType,
        relationship: RelationshipType,
        candidates: Vec<String>,
        metadata: serde_json::Value,
    ) -> Result<(), ApiError> {
        let confidence = source_type.confidence_weight();
        let mut persisted: HashSet<String> = HashSet::new();
        for raw in candidates {
            let Some(canonical) = Self::normalize_discovery_hostname(&raw) else {
                continue;
            };
            // Skip self-matches and trivial provider noise. Infrastructure-domain
            // filtering reuses the existing common-org keyword list as a heuristic.
            if !persisted.insert(canonical.clone()) {
                continue;
            }
            if Self::is_common_infrastructure_host(&canonical) {
                continue;
            }
            let asset = self
                .create_or_update_asset_with_sources(
                    run_id,
                    company_id,
                    AssetType::Domain,
                    &canonical,
                    vec![source_type.clone()],
                    confidence,
                    seed_id,
                    Some(seed_asset_id),
                    Some(metadata.clone()),
                )
                .await?;
            let Some(asset) = asset else {
                continue;
            };
            self.create_relationship(
                run_id,
                seed_asset_id,
                asset.0,
                relationship.clone(),
                confidence,
            )
            .await?;
        }
        Ok(())
    }

    /// Heuristic filter — drop hostnames that match the same common-infrastructure
    /// keyword list used to filter organization names. Catches the obvious noise
    /// (`_spf.google.com`, `mx.protection.outlook.com`, `amazonses.com`, …)
    /// without needing a separate maintenance list.
    fn is_common_infrastructure_host(hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        for keyword in COMMON_INFRASTRUCTURE_ORGS {
            // Match keywords as whole-label substrings — "amazon" hits
            // `amazonses.com`, "google" hits `_spf.google.com`, but
            // "amazon" must not hit a domain like `mycompany.com` just
            // because of a substring collision.
            let kw = keyword.replace([' ', '\''], "");
            if kw.is_empty() || kw.len() < 4 {
                continue;
            }
            if lower.contains(&kw) {
                return true;
            }
        }
        false
    }

    /// Discover assets from an organization
    async fn discover_from_organization(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        org: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        // Skip common infrastructure orgs
        if Self::should_filter_organization(org) {
            tracing::debug!("Filtered organization: {}", org);
            return Ok(result);
        }

        // Create organization asset
        let org_asset = self
            .create_or_update_asset(
                run_id,
                company_id,
                AssetType::Organization,
                org,
                SourceType::Seed,
                0.8,
                seed_id,
                parent_asset_id,
                Some(json!({ "discovery_depth": depth })),
            )
            .await?;

        let Some(org_asset) = org_asset else {
            result
                .warnings
                .push(format!("Skipped organization {} (excluded)", org));
            return Ok(result);
        };

        if org_asset.1 {
            result.assets_created.push(org_asset.0);
        } else {
            result.assets_updated.push(org_asset.0);
        }

        let org_asset_id = org_asset.0;
        let mut discovered_domains: HashMap<String, Vec<SourceType>> = HashMap::new();

        // Source order 1: Shodan (direct-capable)
        match self
            .external_services
            .search_shodan_org_comprehensive(org)
            .await
        {
            Ok(extracted) => {
                self.cache_ip_owner_hints(&extracted.ip_owners).await;

                // Process IPs
                for ip in &extracted.ips {
                    let asset = self
                        .create_or_update_asset(
                            run_id,
                            company_id,
                            AssetType::Ip,
                            ip,
                            SourceType::Shodan,
                            0.7,
                            seed_id,
                            Some(org_asset_id),
                            Some(json!({ "organization": org })),
                        )
                        .await?;

                    let Some(asset) = asset else {
                        continue;
                    };

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    }

                    self.create_relationship(
                        run_id,
                        org_asset_id,
                        asset.0,
                        RelationshipType::BelongsToOrg,
                        0.7,
                    )
                    .await?;
                    if depth < max_depth {
                        self.queue_for_discovery(
                            run_id,
                            QueueItemType::Ip,
                            ip,
                            seed_id,
                            Some(org_asset_id),
                            depth + 1,
                            3,
                        )
                        .await?;
                    }
                }

                // Collect domains from Shodan, then process all domains in source-priority order.
                for domain in &extracted.domains {
                    Self::record_discovered_domain_source(
                        &mut discovered_domains,
                        domain,
                        SourceType::Shodan,
                    );
                }
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Shodan org search failed: {}", e));
            }
        }

        // Source order 2: VirusTotal has no direct organization endpoint (pivot-only via domain flow).
        tracing::debug!(
            "Skipping direct VirusTotal organization discovery for '{}' (pivot-only)",
            org
        );

        // Source order 3: crt.sh (direct-capable)
        match self
            .external_services
            .search_crtsh_by_organization(org)
            .await
        {
            Ok(domains) => {
                for domain in &domains {
                    Self::record_discovered_domain_source(
                        &mut discovered_domains,
                        domain,
                        SourceType::Crtsh,
                    );
                }
            }
            Err(e) => {
                tracing::debug!("crt.sh org search failed: {}", e);
            }
        }

        // Source order 4: CertSpotter has no direct organization endpoint (pivot-only via domain flow).
        tracing::debug!(
            "Skipping direct CertSpotter organization discovery for '{}' (pivot-only)",
            org
        );

        let mut ordered_domains: Vec<String> = discovered_domains.keys().cloned().collect();
        ordered_domains.sort();
        let max_domains_per_org = self.current_settings().max_domains_per_org as usize;
        if ordered_domains.len() > max_domains_per_org {
            let warning = format!(
                "Organization '{}' discovery found {} domains; limiting to {}",
                org,
                ordered_domains.len(),
                max_domains_per_org
            );
            tracing::warn!("{}", warning);
            result.warnings.push(warning);
        }

        for domain in ordered_domains.into_iter().take(max_domains_per_org) {
            let source_types = discovered_domains.remove(&domain).unwrap_or_default();
            let source_names: Vec<String> = source_types.iter().map(|s| s.to_string()).collect();
            let confidence = self.calculate_multi_source_confidence(0.6, source_types.len());

            let asset = self
                .create_or_update_asset_with_sources(
                    run_id,
                    company_id,
                    AssetType::Domain,
                    &domain,
                    source_types,
                    confidence,
                    seed_id,
                    Some(org_asset_id),
                    Some(json!({
                        "organization": org,
                        "discovered_by_sources": source_names,
                    })),
                )
                .await?;

            let Some(asset) = asset else {
                continue;
            };

            if asset.1 {
                result.assets_created.push(asset.0);
            } else {
                result.assets_updated.push(asset.0);
            }

            self.create_relationship(
                run_id,
                org_asset_id,
                asset.0,
                RelationshipType::BelongsToOrg,
                confidence,
            )
            .await?;

            if depth < max_depth {
                self.queue_for_discovery(
                    run_id,
                    QueueItemType::Domain,
                    &domain,
                    seed_id,
                    Some(org_asset_id),
                    depth + 1,
                    3,
                )
                .await?;
            }
        }

        Ok(result)
    }

    /// Discover assets from an ASN
    async fn discover_from_asn(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        asn: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        // Create ASN asset
        let asn_asset = self
            .create_or_update_asset(
                run_id,
                company_id,
                AssetType::Asn,
                asn,
                SourceType::Seed,
                1.0,
                seed_id,
                parent_asset_id,
                Some(json!({ "discovery_depth": depth })),
            )
            .await?;

        let Some(asn_asset) = asn_asset else {
            result
                .warnings
                .push(format!("Skipped ASN {} (excluded)", asn));
            return Ok(result);
        };

        if asn_asset.1 {
            result.assets_created.push(asn_asset.0);
        }

        let asn_asset_id = asn_asset.0;
        let mut discovered_domains: HashMap<String, Vec<SourceType>> = HashMap::new();

        // Source order 1: Shodan (direct-capable)
        match self
            .external_services
            .search_shodan_asn_comprehensive(asn)
            .await
        {
            Ok(extracted) => {
                self.cache_ip_owner_hints(&extracted.ip_owners).await;

                for ip in &extracted.ips {
                    let asset = self
                        .create_or_update_asset(
                            run_id,
                            company_id,
                            AssetType::Ip,
                            ip,
                            SourceType::Shodan,
                            0.8,
                            seed_id,
                            Some(asn_asset_id),
                            Some(json!({ "asn": asn })),
                        )
                        .await?;

                    let Some(asset) = asset else {
                        continue;
                    };

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    }

                    self.create_relationship(
                        run_id,
                        asn_asset_id,
                        asset.0,
                        RelationshipType::BelongsToAsn,
                        0.8,
                    )
                    .await?;
                    if depth < max_depth {
                        self.queue_for_discovery(
                            run_id,
                            QueueItemType::Ip,
                            ip,
                            seed_id,
                            Some(asn_asset_id),
                            depth + 1,
                            3,
                        )
                        .await?;
                    }
                }

                for domain in &extracted.domains {
                    Self::record_discovered_domain_source(
                        &mut discovered_domains,
                        domain,
                        SourceType::Shodan,
                    );
                }
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Shodan ASN search failed: {}", e));
            }
        }

        // Source order 2-4: no direct ASN queries for VirusTotal/crt.sh/CertSpotter (pivot-only).
        tracing::debug!(
            "Skipping direct VirusTotal/crt.sh/CertSpotter ASN discovery for '{}' (pivot-only)",
            asn
        );

        let mut ordered_domains: Vec<String> = discovered_domains.keys().cloned().collect();
        ordered_domains.sort();

        for domain in ordered_domains {
            let source_types = discovered_domains.remove(&domain).unwrap_or_default();
            let source_names: Vec<String> = source_types.iter().map(|s| s.to_string()).collect();
            let confidence = self.calculate_multi_source_confidence(0.7, source_types.len());

            let asset = self
                .create_or_update_asset_with_sources(
                    run_id,
                    company_id,
                    AssetType::Domain,
                    &domain,
                    source_types,
                    confidence,
                    seed_id,
                    Some(asn_asset_id),
                    Some(json!({
                        "asn": asn,
                        "discovered_by_sources": source_names,
                    })),
                )
                .await?;

            let Some(asset) = asset else {
                continue;
            };

            if asset.1 {
                result.assets_created.push(asset.0);
            } else {
                result.assets_updated.push(asset.0);
            }

            self.create_relationship(
                run_id,
                asn_asset_id,
                asset.0,
                RelationshipType::BelongsToAsn,
                confidence,
            )
            .await?;

            if depth < max_depth {
                self.queue_for_discovery(
                    run_id,
                    QueueItemType::Domain,
                    &domain,
                    seed_id,
                    Some(asn_asset_id),
                    depth + 1,
                    3,
                )
                .await?;
            }
        }

        Ok(result)
    }

    /// Discover assets from a CIDR range
    async fn discover_from_cidr(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        cidr: &str,
        seed_id: Option<Uuid>,
        _parent_asset_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();
        let settings = self.current_settings();

        let ips = expand_cidr(cidr)?;
        let max_hosts = settings.max_cidr_hosts as usize;

        if ips.len() > max_hosts {
            return Err(ApiError::Validation(format!(
                "CIDR range {} has {} hosts, exceeding limit of {}",
                cidr,
                ips.len(),
                max_hosts
            )));
        }

        for ip in ips {
            let ip_str = ip.to_string();
            let asset = self
                .create_or_update_asset(
                    run_id,
                    company_id,
                    AssetType::Ip,
                    &ip_str,
                    SourceType::CidrExpansion,
                    0.9, // High confidence for CIDR expansion
                    seed_id,
                    None,
                    Some(json!({ "cidr": cidr })),
                )
                .await?;

            // An excluded address inside an otherwise in-scope range: skip
            // this one, keep expanding the rest.
            let Some(asset) = asset else {
                continue;
            };

            if asset.1 {
                result.assets_created.push(asset.0);
            }

            if depth < max_depth {
                self.queue_for_discovery(
                    run_id,
                    QueueItemType::Ip,
                    &ip_str,
                    seed_id,
                    Some(asset.0),
                    depth + 1,
                    3,
                )
                .await?;
            }
        }

        Ok(result)
    }

    /// Discover information about an IP (reverse DNS, etc.)
    async fn discover_from_ip(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        ip: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
        max_depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        if self
            .exclusion_level(company_id, "ip", ip)
            .await?
            .is_excluded()
        {
            tracing::info!("Skipping excluded IP '{}' during discovery", ip);
            return Ok(result);
        }

        // Create or get IP asset
        let ip_asset = self
            .create_or_update_asset(
                run_id,
                company_id,
                AssetType::Ip,
                ip,
                SourceType::Seed,
                1.0,
                seed_id,
                parent_asset_id,
                None,
            )
            .await?;

        let Some(ip_asset) = ip_asset else {
            result
                .warnings
                .push(format!("Skipped IP {} (excluded)", ip));
            return Ok(result);
        };

        if ip_asset.1 {
            result.assets_created.push(ip_asset.0);
        }

        let ip_asset_id = ip_asset.0;

        // Attribute the address to its origin AS and announced netblocks. A seed
        // IP is exactly the case where this matters most: one address the
        // analyst knows about frequently sits in a /24 the organisation owns
        // outright, and nothing else in that range has a DNS name.
        match self
            .attribute_ip_infrastructure(run_id, company_id, ip, ip_asset_id, seed_id)
            .await
        {
            Ok(attribution) => result.merge(attribution),
            Err(e) => tracing::debug!("ASN attribution failed for {}: {}", ip, e),
        }

        // Reverse DNS lookup
        if let Ok(ip_addr) = ip.parse() {
            match self.dns_resolver.reverse_lookup(&ip_addr).await {
                Ok(hostnames) => {
                    for hostname in hostnames {
                        let asset = self
                            .create_or_update_asset(
                                run_id,
                                company_id,
                                AssetType::Domain,
                                &hostname,
                                SourceType::ReverseDns,
                                0.7,
                                seed_id,
                                Some(ip_asset_id),
                                Some(json!({ "reverse_resolved_from": ip })),
                            )
                            .await?;

                        let Some(asset) = asset else {
                            continue;
                        };

                        if asset.1 {
                            result.assets_created.push(asset.0);
                        }

                        self.create_relationship(
                            run_id,
                            ip_asset_id,
                            asset.0,
                            RelationshipType::ReverseResolvesTo,
                            0.7,
                        )
                        .await?;

                        if depth < max_depth {
                            self.queue_for_discovery(
                                run_id,
                                QueueItemType::Domain,
                                &hostname,
                                seed_id,
                                Some(ip_asset_id),
                                depth + 1,
                                3,
                            )
                            .await?;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Reverse DNS failed for {}: {}", ip, e);
                }
            }
        }

        Ok(result)
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /// Create or update an asset and record its source.
    ///
    /// `Ok(None)` means the asset is excluded and was not written; callers
    /// skip whatever they were going to hang off it.
    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_asset(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        asset_type: AssetType,
        identifier: &str,
        source_type: SourceType,
        confidence: f64,
        seed_id: Option<Uuid>,
        parent_id: Option<Uuid>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Option<(Uuid, bool)>, ApiError> {
        self.create_or_update_asset_with_sources(
            run_id,
            company_id,
            asset_type,
            identifier,
            vec![source_type],
            confidence,
            seed_id,
            parent_id,
            metadata,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_asset_with_sources(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        asset_type: AssetType,
        identifier: &str,
        source_types: Vec<SourceType>,
        confidence: f64,
        seed_id: Option<Uuid>,
        parent_id: Option<Uuid>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Option<(Uuid, bool)>, ApiError> {
        // Returns Some((asset_id, was_created)), or None if excluded.
        let normalized_identifier = if matches!(asset_type, AssetType::Domain) {
            Self::normalize_discovery_hostname(identifier)
                .ok_or_else(|| ApiError::Validation("Invalid domain format".to_string()))?
        } else {
            identifier.to_string()
        };

        // The single point every discovery path writes through, so the
        // exclusion list is enforced here rather than trusted to each caller.
        // Either strength ends the write -- the difference is what happens to
        // the asset that is already there. A blacklisted one should not exist,
        // so it is left alone to be deleted; an excluded one is the operator's
        // and is offered to auto-scan on the way past.
        match self
            .asset_exclusion_level(company_id, &asset_type, &normalized_identifier)
            .await?
        {
            ExclusionLevel::None => {}
            ExclusionLevel::Blacklisted => {
                tracing::debug!(
                    "Skipping blacklisted {} '{}' during discovery",
                    asset_type,
                    normalized_identifier
                );
                return Ok(None);
            }
            ExclusionLevel::Excluded => {
                tracing::debug!(
                    "Not storing excluded {} '{}' during discovery",
                    asset_type,
                    normalized_identifier
                );
                self.auto_scan_known_asset(
                    run_id,
                    company_id,
                    &asset_type.to_string(),
                    &normalized_identifier,
                )
                .await;
                return Ok(None);
            }
        }

        let mut ordered_sources = Self::order_source_types(source_types);
        if ordered_sources.is_empty() {
            ordered_sources.push(SourceType::UserInput);
        }
        let source_strings: Vec<String> = ordered_sources.iter().map(|s| s.to_string()).collect();
        let primary_source = ordered_sources
            .first()
            .cloned()
            .unwrap_or(SourceType::UserInput);

        let asset_create = AssetCreate {
            asset_type: asset_type.clone(),
            identifier: normalized_identifier.clone(),
            confidence,
            sources: json!(source_strings),
            metadata: metadata.unwrap_or(json!({})),
            seed_id,
            parent_id,
            discovery_run_id: Some(run_id),
            discovery_method: Some(primary_source.to_string()),
        };

        // Check if asset exists
        let existing = self
            .asset_repo
            .get_by_identifier(company_id, asset_type.clone(), &normalized_identifier)
            .await?;
        let was_created = existing.is_none();

        let asset = self
            .asset_repo
            .create_or_merge(&asset_create, company_id)
            .await?;

        // Record all contributing sources for this asset.
        for source_type in ordered_sources {
            let source_create = AssetSourceCreate {
                asset_id: asset.id,
                discovery_run_id: Some(run_id),
                source_type,
                source_confidence: confidence,
                raw_data: None,
            };
            self.asset_source_repo.create(&source_create).await?;
        }

        // Auto-scan assets whose merged confidence clears the threshold. We use the merged
        // asset.confidence (returned by create_or_merge) rather than the discovery-time
        // `confidence` parameter, and we run on every touch — not just on first create — so
        // that subdomains whose confidence rises through re-discovery still get scanned.
        // The 24h dedup inside maybe_trigger_auto_scan prevents repeated scans.
        self.consider_auto_scan(
            run_id,
            company_id,
            asset.id,
            &normalized_identifier,
            &asset_type,
            asset.confidence,
        )
        .await;

        Ok(Some((asset.id, was_created)))
    }

    /// Create a relationship between assets
    async fn create_relationship(
        &self,
        run_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        rel_type: RelationshipType,
        confidence: f64,
    ) -> Result<Uuid, ApiError> {
        let rel_create = AssetRelationshipCreate {
            source_asset_id: source_id,
            target_asset_id: target_id,
            relationship_type: rel_type,
            confidence,
            metadata: None,
            discovery_run_id: Some(run_id),
        };

        let rel = self
            .asset_relationship_repo
            .create_or_update(&rel_create)
            .await?;
        Ok(rel.id)
    }

    /// Queue an item for discovery
    async fn queue_for_discovery(
        &self,
        run_id: Uuid,
        item_type: QueueItemType,
        item_value: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
        priority: i32,
    ) -> Result<(), ApiError> {
        let normalized_item_value = if item_type == QueueItemType::Domain {
            Self::normalize_discovery_hostname(item_value)
                .unwrap_or_else(|| item_value.trim().trim_end_matches('.').to_lowercase())
        } else {
            item_value.to_string()
        };

        let item = DiscoveryQueueItemCreate {
            discovery_run_id: run_id,
            item_type,
            item_value: normalized_item_value,
            parent_asset_id,
            seed_id,
            depth,
            priority,
        };

        self.discovery_queue_repo.enqueue(&item).await?;
        Ok(())
    }

    /// Check if an organization should be filtered out
    fn should_filter_organization(org: &str) -> bool {
        let normalized_org = Self::normalize_organization_name(org);
        if normalized_org.len() < 3 {
            return true;
        }

        let tokens: HashSet<&str> = normalized_org.split_whitespace().collect();
        for infra_org in COMMON_INFRASTRUCTURE_ORGS {
            if Self::organization_matches_infra_keyword(&normalized_org, &tokens, infra_org) {
                return true;
            }
        }

        false
    }

    fn normalize_discovery_hostname(hostname: &str) -> Option<String> {
        let normalized = hostname.trim().trim_end_matches('.').to_lowercase();
        if normalized.is_empty()
            || normalized.len() > 253
            || normalized.contains(char::is_whitespace)
            || normalized.contains('/')
        {
            return None;
        }

        let labels: Vec<&str> = normalized.split('.').collect();
        if labels.is_empty() {
            return None;
        }

        for label in labels {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return None;
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return None;
            }
        }

        Some(normalized)
    }

    fn normalize_organization_name(org: &str) -> String {
        org.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    ' '
                }
            })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
    }

    fn organization_matches_infra_keyword(
        normalized_org: &str,
        tokens: &HashSet<&str>,
        keyword: &str,
    ) -> bool {
        let normalized_keyword = Self::normalize_organization_name(keyword);
        if normalized_keyword.is_empty() {
            return false;
        }
        if normalized_keyword.contains(' ') {
            return normalized_org.contains(&normalized_keyword);
        }
        tokens.contains(normalized_keyword.as_str())
    }

    fn record_discovered_domain_source(
        domain_sources: &mut HashMap<String, Vec<SourceType>>,
        domain: &str,
        source: SourceType,
    ) {
        let Some(canonical_domain) = Self::normalize_discovery_hostname(domain) else {
            return;
        };
        let entry = domain_sources.entry(canonical_domain).or_default();
        if !entry.contains(&source) {
            entry.push(source);
        }
        let ordered = Self::order_source_types(entry.clone());
        *entry = ordered;
    }

    fn filter_seeds_by_requested_ids(
        all_seeds: Vec<Seed>,
        requested_ids: Option<&Vec<Uuid>>,
    ) -> (Vec<Seed>, Vec<Uuid>) {
        let Some(ids) = requested_ids.filter(|ids| !ids.is_empty()) else {
            return (all_seeds, Vec::new());
        };

        let requested_set: HashSet<Uuid> = ids.iter().copied().collect();
        let available_set: HashSet<Uuid> = all_seeds.iter().map(|seed| seed.id).collect();
        let mut missing_ids: Vec<Uuid> =
            requested_set.difference(&available_set).copied().collect();
        missing_ids.sort_unstable();
        let filtered = all_seeds
            .into_iter()
            .filter(|seed| requested_set.contains(&seed.id))
            .collect();
        (filtered, missing_ids)
    }

    fn source_priority(source: &SourceType) -> usize {
        DISCOVERY_SOURCE_PRIORITY
            .iter()
            .position(|ordered| ordered == source)
            .unwrap_or(usize::MAX)
    }

    fn order_source_types(source_types: Vec<SourceType>) -> Vec<SourceType> {
        let mut deduped: Vec<SourceType> = Vec::new();
        for source in source_types {
            if !deduped.contains(&source) {
                deduped.push(source);
            }
        }
        deduped.sort_by_key(Self::source_priority);
        deduped
    }

    fn is_known_cloud_provider_name(&self, owner: &str) -> bool {
        let owner_lower = owner.to_lowercase();
        KNOWN_CLOUD_PROVIDER_KEYWORDS
            .iter()
            .any(|keyword| owner_lower.contains(keyword))
    }

    async fn cache_ip_owner_hints(&self, ip_owners: &HashMap<String, String>) {
        if ip_owners.is_empty() {
            return;
        }

        let mut cache = self.ip_cloud_provider_cache.lock().await;
        for (ip, owner) in ip_owners {
            cache.insert(ip.clone(), self.is_known_cloud_provider_name(owner));
        }
    }

    /// Returns true if the IP belongs to known cloud/WAF infrastructure.
    /// Uses owner hints first, then a Shodan host lookup fallback.
    async fn is_cloud_or_waf_ip(&self, ip: &str, owner_hint: Option<&str>) -> bool {
        if let Some(owner) = owner_hint {
            let is_cloud_provider = self.is_known_cloud_provider_name(owner);
            let mut cache = self.ip_cloud_provider_cache.lock().await;
            cache.insert(ip.to_string(), is_cloud_provider);
            return is_cloud_provider;
        }

        {
            let cache = self.ip_cloud_provider_cache.lock().await;
            if let Some(cached) = cache.get(ip).copied() {
                return cached;
            }
        }

        match self.external_services.get_shodan_host_info(ip).await {
            Ok(Some(host_info)) => {
                let owner = host_info.org.or(host_info.isp).unwrap_or_default();
                let is_cloud_provider = self.is_known_cloud_provider_name(&owner);
                let mut cache = self.ip_cloud_provider_cache.lock().await;
                cache.insert(ip.to_string(), is_cloud_provider);
                is_cloud_provider
            }
            Ok(None) => {
                let mut cache = self.ip_cloud_provider_cache.lock().await;
                cache.insert(ip.to_string(), false);
                false
            }
            Err(e) => {
                tracing::debug!(
                    "Shodan host lookup failed for {} while classifying infrastructure IP: {}",
                    ip,
                    e
                );
                false
            }
        }
    }

    /// Calculate confidence for subdomain discovery
    /// Confidence for a hostname, given every source that reported it.
    ///
    /// Counting raw sources was defensible with four of them. With nineteen it
    /// is not: crt.sh, CertSpotter, Censys and Digitorus all read the same
    /// certificate transparency logs, so four hits there is one fact observed
    /// four times, not four independent facts. Scoring it as four would let a
    /// single CT entry reach maximum confidence.
    ///
    /// So the score is:
    ///
    /// - **base** — the strongest single source's own weight. A name in a CT
    ///   log starts high because a CA logged it; a name seen only in a web
    ///   archive starts low because it may be years dead.
    /// - **corroboration** — `+0.06` for each *additional independent evidence
    ///   class* (see [`SourceType::evidence_class`]), so passive DNS agreeing
    ///   with CT counts, and a fifth CT aggregator does not.
    ///
    /// Capped below 1.0: only a seed or an analyst gets certainty.
    fn calculate_subdomain_confidence(sources: &[SourceType]) -> f64 {
        if sources.is_empty() {
            return 0.5;
        }

        let base = sources
            .iter()
            .map(|source| source.confidence_weight())
            .fold(0.0_f64, f64::max);

        let independent_classes: HashSet<_> = sources
            .iter()
            .map(|source| source.evidence_class())
            .collect();
        let corroboration = independent_classes.len().saturating_sub(1) as f64 * 0.06;

        (base + corroboration).clamp(0.0, 0.95)
    }

    /// Confidence for a discovery path whose floor is set by the path itself
    /// rather than by the source — an organisation or ASN pivot, say, where the
    /// link to the company is what is uncertain, not the asset's existence.
    fn calculate_multi_source_confidence(&self, base: f64, source_count: usize) -> f64 {
        let effective_source_count = source_count.max(1);
        let boost = ((effective_source_count as f64) - 1.0) * 0.1;
        (base + boost).min(0.9)
    }

    /// Check if asset should be auto-scanned and queue a security scan
    #[allow(clippy::too_many_arguments)]
    async fn maybe_trigger_auto_scan(
        &self,
        run_id: Uuid,
        company_id: Uuid,
        asset_id: Uuid,
        asset_identifier: &str,
        asset_type: &AssetType,
        confidence: f64,
        auto_scan_threshold: Option<f64>,
    ) -> Result<(), ApiError> {
        // Only proceed if we have a threshold set and the security scan service is available
        let threshold = match auto_scan_threshold {
            Some(t) if t > 0.0 => t,
            _ => return Ok(()), // No threshold set or threshold is 0
        };

        let security_scan_service = match &self.security_scan_service {
            Some(service) => service,
            None => return Ok(()), // No security scan service configured
        };

        // Only scan scannable asset types
        let is_scannable = matches!(
            asset_type,
            AssetType::Domain | AssetType::Ip | AssetType::Certificate
        );
        if !is_scannable {
            return Ok(());
        }

        // Check if confidence meets threshold
        if confidence < threshold {
            tracing::debug!(
                "Asset {} confidence {:.2} below auto-scan threshold {:.2}",
                asset_id,
                confidence,
                threshold
            );
            return Ok(());
        }

        // Keep discovery auto-scans away from cloud/WAF infrastructure IPs.
        if matches!(asset_type, AssetType::Ip)
            && self.is_cloud_or_waf_ip(asset_identifier, None).await
        {
            tracing::info!(
                "Skipping auto-scan for cloud/WAF IP asset {}",
                asset_identifier
            );
            return Ok(());
        }

        // Check if asset was recently scanned (avoid duplicate scans)
        let existing_scans = security_scan_service
            .list_scans_for_asset(&asset_id, company_id)
            .await?;
        if let Some(scan) = existing_scans.first() {
            let scan_age = chrono::Utc::now() - scan.created_at;
            if scan_age.num_hours() < 24 {
                tracing::debug!(
                    "Asset {} was scanned within 24h, skipping auto-scan",
                    asset_id
                );
                return Ok(());
            }
        }

        // Create and execute a security scan via the service (this submits to task manager)
        let scan_create = SecurityScanCreate {
            asset_id,
            scan_type: Some(SecurityScanType::Full),
            trigger_type: Some(ScanTriggerType::Discovery),
            priority: Some(3), // Lower priority than manual scans
            note: Some("Auto-triggered by discovery (high confidence asset)".to_string()),
            config: None,
            // The link that makes "stop the run" reach the scans the run queued.
            discovery_run_id: Some(run_id),
        };

        match security_scan_service
            .create_scan(scan_create, company_id, None)
            .await
        {
            Ok(scan) => {
                tracing::info!(
                    "Auto-triggered security scan {} for asset {} (confidence: {:.2})",
                    scan.id,
                    asset_id,
                    confidence
                );
            }
            Err(e) => {
                tracing::warn!("Failed to trigger auto-scan for asset {}: {}", asset_id, e);
            }
        }

        Ok(())
    }
}

// Implement Clone for async task spawning
impl Clone for DiscoveryService {
    fn clone(&self) -> Self {
        Self {
            asset_repo: Arc::clone(&self.asset_repo),
            seed_repo: Arc::clone(&self.seed_repo),
            discovery_run_repo: Arc::clone(&self.discovery_run_repo),
            discovery_queue_repo: Arc::clone(&self.discovery_queue_repo),
            asset_source_repo: Arc::clone(&self.asset_source_repo),
            asset_relationship_repo: Arc::clone(&self.asset_relationship_repo),
            exclusion_repo: Arc::clone(&self.exclusion_repo),
            security_scan_service: self.security_scan_service.clone(),
            risk_service: Arc::clone(&self.risk_service),
            external_services: Arc::clone(&self.external_services),
            asn_client: self.asn_client.clone(),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_analyzer: Arc::clone(&self.http_analyzer),
            task_manager: Arc::clone(&self.task_manager),
            settings: Arc::clone(&self.settings),
            confidence_scorer: Arc::clone(&self.confidence_scorer),
            status: Arc::clone(&self.status),
            ip_cloud_provider_cache: Arc::clone(&self.ip_cloud_provider_cache),
            swept_prefixes: Arc::clone(&self.swept_prefixes),
            exclusion_cache: Arc::clone(&self.exclusion_cache),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_discovery_hostname() {
        assert_eq!(
            DiscoveryService::normalize_discovery_hostname(" WWW.Example.com. "),
            Some("www.example.com".to_string())
        );
        assert_eq!(
            DiscoveryService::normalize_discovery_hostname("api.example.com"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            DiscoveryService::normalize_discovery_hostname("bad host"),
            None
        );
        assert_eq!(DiscoveryService::normalize_discovery_hostname(""), None);
    }

    #[test]
    fn test_order_source_types_uses_priority_and_dedupes() {
        let ordered = DiscoveryService::order_source_types(vec![
            SourceType::Crtsh,
            SourceType::Shodan,
            SourceType::Crtsh,
            SourceType::Virustotal,
        ]);
        // Certificate transparency outranks scan data: a CA logging the name is
        // stronger evidence of ownership than a scanner having seen it answer.
        assert_eq!(
            ordered,
            vec![
                SourceType::Crtsh,
                SourceType::Shodan,
                SourceType::Virustotal
            ]
        );
    }

    #[test]
    fn test_order_source_types_puts_live_dns_first() {
        let ordered = DiscoveryService::order_source_types(vec![
            SourceType::Wayback,
            SourceType::DnsResolution,
            SourceType::Crtsh,
        ]);
        assert_eq!(
            ordered,
            vec![
                SourceType::DnsResolution,
                SourceType::Crtsh,
                SourceType::Wayback
            ]
        );
    }

    #[test]
    fn test_order_source_types_keeps_unranked_sources_in_insertion_order() {
        // Nothing ranks lateral pivots; they must trail in the order recorded
        // rather than being reshuffled.
        let ordered = DiscoveryService::order_source_types(vec![
            SourceType::MxPivot,
            SourceType::Crtsh,
            SourceType::FaviconPivot,
        ]);
        assert_eq!(
            ordered,
            vec![
                SourceType::Crtsh,
                SourceType::MxPivot,
                SourceType::FaviconPivot
            ]
        );
    }

    #[test]
    fn confidence_rewards_independent_corroboration_not_repetition() {
        // Four aggregators, all reading the same certificate transparency logs.
        // That is one fact seen four times.
        let all_ct = DiscoveryService::calculate_subdomain_confidence(&[
            SourceType::Crtsh,
            SourceType::Certspotter,
            SourceType::Censys,
            SourceType::Digitorus,
        ]);
        let single_ct = DiscoveryService::calculate_subdomain_confidence(&[SourceType::Crtsh]);
        assert_eq!(
            all_ct, single_ct,
            "sources in one evidence class must not stack"
        );

        // Certificate transparency plus passive DNS: two independent facts.
        let two_classes =
            DiscoveryService::calculate_subdomain_confidence(&[SourceType::Crtsh, SourceType::Otx]);
        assert!(
            two_classes > single_ct,
            "independent corroboration must raise confidence"
        );

        // And a third class raises it again.
        let three_classes = DiscoveryService::calculate_subdomain_confidence(&[
            SourceType::Crtsh,
            SourceType::Otx,
            SourceType::Shodan,
        ]);
        assert!(three_classes > two_classes);
    }

    #[test]
    fn confidence_is_anchored_on_the_strongest_source() {
        // A web archive alone is weak: the name existed once, not necessarily now.
        let archive_only = DiscoveryService::calculate_subdomain_confidence(&[SourceType::Wayback]);
        // Live resolution is the strongest evidence there is short of a seed.
        let resolved =
            DiscoveryService::calculate_subdomain_confidence(&[SourceType::DnsResolution]);
        assert!(archive_only < resolved);

        // Adding a weak source never lowers the score below the strong one.
        let both = DiscoveryService::calculate_subdomain_confidence(&[
            SourceType::DnsResolution,
            SourceType::Wayback,
        ]);
        assert!(both >= resolved);
    }

    #[test]
    fn confidence_never_reaches_certainty_and_handles_no_sources() {
        let everything = DiscoveryService::calculate_subdomain_confidence(&[
            SourceType::DnsResolution,
            SourceType::Crtsh,
            SourceType::Otx,
            SourceType::Shodan,
            SourceType::Wayback,
            SourceType::AsnNetblock,
        ]);
        assert!(
            everything < 1.0,
            "only a seed or an analyst gets certainty, got {everything}"
        );
        // An empty source list is a bug elsewhere, but must not panic or score 0.
        assert_eq!(DiscoveryService::calculate_subdomain_confidence(&[]), 0.5);
    }

    #[test]
    fn test_record_discovered_domain_source_canonicalizes() {
        let mut domain_sources: HashMap<String, Vec<SourceType>> = HashMap::new();
        DiscoveryService::record_discovered_domain_source(
            &mut domain_sources,
            "WWW.Example.com.",
            SourceType::Shodan,
        );
        DiscoveryService::record_discovered_domain_source(
            &mut domain_sources,
            "www.example.com",
            SourceType::Virustotal,
        );

        let sources = domain_sources
            .get("www.example.com")
            .cloned()
            .unwrap_or_default();
        assert_eq!(sources, vec![SourceType::Shodan, SourceType::Virustotal]);
    }

    #[test]
    fn test_should_filter_organization_precision() {
        assert!(DiscoveryService::should_filter_organization(
            "Cloudflare, Inc."
        ));
        assert!(DiscoveryService::should_filter_organization(
            "Akamai Technologies"
        ));
        assert!(!DiscoveryService::should_filter_organization(
            "Principal Financial Group, Inc."
        ));
        assert!(!DiscoveryService::should_filter_organization(
            "Acme Corporation"
        ));
    }

    #[test]
    fn test_normalize_organization_name() {
        assert_eq!(
            DiscoveryService::normalize_organization_name("  Cloudflare, Inc.  "),
            "cloudflare inc"
        );
        assert_eq!(
            DiscoveryService::normalize_organization_name("ACME-Group LLC"),
            "acme group llc"
        );
    }

    #[test]
    fn test_filter_seeds_by_requested_ids() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let missing = Uuid::new_v4();
        let seeds = vec![
            Seed {
                id: id_a,
                seed_type: SeedType::Domain,
                value: "example.com".to_string(),
                note: None,
                company_id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Seed {
                id: id_b,
                seed_type: SeedType::Domain,
                value: "api.example.com".to_string(),
                note: None,
                company_id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        let requested = vec![id_b, missing];
        let (filtered, missing_ids) =
            DiscoveryService::filter_seeds_by_requested_ids(seeds, Some(&requested));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, id_b);
        assert_eq!(missing_ids, vec![missing]);
    }

    // ------------------------------------------------------------------
    // Exclusion snapshot
    // ------------------------------------------------------------------

    fn entry(object_type: &str, object_value: &str, blacklisted: bool) -> ExclusionEntry {
        ExclusionEntry {
            id: Uuid::new_v4(),
            object_type: object_type.to_string(),
            object_value: object_value.to_string(),
            company_id: Uuid::new_v4(),
            reason: None,
            created_by: None,
            blacklisted,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn excluded(object_type: &str, object_value: &str) -> ExclusionEntry {
        entry(object_type, object_value, false)
    }

    fn blacklisted(object_type: &str, object_value: &str) -> ExclusionEntry {
        entry(object_type, object_value, true)
    }

    #[test]
    fn an_excluded_domain_covers_itself_and_its_subdomains() {
        let snapshot = ExclusionSnapshot::from_entries(vec![excluded("domain", "Example.COM")]);
        let covers = |name: &str| snapshot.level("domain", name).is_excluded();

        assert!(covers("example.com"));
        assert!(covers("api.example.com"));
        assert!(covers("a.b.example.com"));
        // Trailing dots and casing are normalisation, not different names.
        assert!(covers("API.Example.com."));

        // A suffix that is not a label boundary is a different domain.
        assert!(!covers("notexample.com"));
        assert!(!covers("example.com.evil.net"));
        assert!(!covers("example.org"));
    }

    #[test]
    fn a_bare_tld_entry_does_not_swallow_every_domain() {
        // Mirrors the repository, which only ever compares parents of two
        // labels or more.
        let snapshot = ExclusionSnapshot::from_entries(vec![excluded("domain", "com")]);

        assert!(snapshot.level("domain", "com").is_excluded());
        assert!(!snapshot.level("domain", "example.com").is_excluded());
    }

    #[test]
    fn an_excluded_cidr_covers_the_addresses_inside_it() {
        let snapshot = ExclusionSnapshot::from_entries(vec![
            excluded("cidr", "10.0.0.0/24"),
            excluded("ip", "192.0.2.7"),
        ]);
        let covers = |ip: &str| snapshot.level("ip", ip).is_excluded();

        assert!(covers("10.0.0.1"));
        assert!(covers("10.0.0.255"));
        assert!(!covers("10.0.1.1"));

        assert!(covers("192.0.2.7"));
        assert!(!covers("192.0.2.8"));

        // A hostname reaching the IP matcher must not be treated as an address.
        assert!(!covers("example.com"));
    }

    #[test]
    fn an_excluded_cidr_covers_a_range_inside_it() {
        let snapshot = ExclusionSnapshot::from_entries(vec![excluded("cidr", "10.0.0.0/16")]);
        let covers = |cidr: &str| snapshot.level("cidr", cidr).is_excluded();

        assert!(covers("10.0.0.0/16"));
        assert!(covers("10.0.5.0/24"));
        assert!(!covers("10.1.0.0/24"));
        // A range that contains the excluded one is not itself excluded.
        assert!(!covers("10.0.0.0/8"));
    }

    #[test]
    fn asn_matching_ignores_the_as_prefix() {
        let snapshot = ExclusionSnapshot::from_entries(vec![excluded("asn", "AS64496")]);
        let covers = |asn: &str| snapshot.level("asn", asn).is_excluded();

        assert!(covers("AS64496"));
        assert!(covers("as64496"));
        assert!(covers("64496"));
        assert!(!covers("64497"));
    }

    #[test]
    fn an_unparseable_cidr_entry_is_dropped_rather_than_matching_everything() {
        let snapshot = ExclusionSnapshot::from_entries(vec![excluded("cidr", "not-a-cidr")]);

        assert!(snapshot.is_empty());
        assert!(!snapshot.level("ip", "10.0.0.1").is_excluded());
    }

    #[test]
    fn an_empty_exclusion_list_matches_nothing() {
        let snapshot = ExclusionSnapshot::from_entries(vec![]);

        assert!(snapshot.is_empty());
        assert!(!snapshot.level("domain", "example.com").is_excluded());
        assert!(!snapshot.level("ip", "10.0.0.1").is_excluded());
        assert!(!snapshot.level("organization", "acme").is_excluded());
        assert!(!snapshot.level("certificate", "CN=acme").is_excluded());
    }

    #[test]
    fn organization_and_certificate_entries_match_their_own_value() {
        let snapshot = ExclusionSnapshot::from_entries(vec![
            excluded("organization", "Acme Corp"),
            excluded("certificate", "CN=acme.example.com"),
        ]);

        assert!(snapshot.level("organization", "acme corp").is_excluded());
        assert!(snapshot
            .level("organization", "  ACME Corp  ")
            .is_excluded());
        assert!(!snapshot.level("organization", "acme").is_excluded());

        assert!(snapshot
            .level("certificate", "CN=acme.example.com")
            .is_excluded());
        assert!(!snapshot
            .level("certificate", "CN=other.example.com")
            .is_excluded());
    }

    #[test]
    fn a_fresh_snapshot_is_not_expired() {
        let snapshot = ExclusionSnapshot::from_entries(vec![]);
        assert!(!snapshot.is_expired());
    }

    // ------------------------------------------------------------------
    // Exclusion strength
    // ------------------------------------------------------------------

    #[test]
    fn an_ordinary_exclusion_is_excluded_but_not_blacklisted() {
        let snapshot = ExclusionSnapshot::from_entries(vec![excluded("domain", "cdn.example")]);

        let level = snapshot.level("domain", "assets.cdn.example");
        assert_eq!(level, ExclusionLevel::Excluded);
        assert!(level.is_excluded());
        // The whole point of the distinction: discovery leaves this one's
        // assets alone rather than deleting them.
        assert!(!level.is_blacklisted());
    }

    #[test]
    fn a_blacklist_reaches_everything_an_exclusion_would() {
        let snapshot = ExclusionSnapshot::from_entries(vec![
            blacklisted("domain", "not-ours.example"),
            blacklisted("cidr", "198.51.100.0/24"),
        ]);

        assert_eq!(
            snapshot.level("domain", "www.not-ours.example"),
            ExclusionLevel::Blacklisted
        );
        assert_eq!(
            snapshot.level("ip", "198.51.100.9"),
            ExclusionLevel::Blacklisted
        );
        assert_eq!(
            snapshot.level("domain", "ours.example"),
            ExclusionLevel::None
        );
    }

    #[test]
    fn the_stronger_entry_wins_when_both_cover_the_same_name() {
        // A domain excluded outright and a subdomain of it blacklisted: the
        // subdomain has to come back blacklisted, or it would be kept.
        let snapshot = ExclusionSnapshot::from_entries(vec![
            excluded("domain", "example.com"),
            blacklisted("domain", "dead.example.com"),
        ]);

        assert_eq!(
            snapshot.level("domain", "example.com"),
            ExclusionLevel::Excluded
        );
        assert_eq!(
            snapshot.level("domain", "api.example.com"),
            ExclusionLevel::Excluded
        );
        assert_eq!(
            snapshot.level("domain", "dead.example.com"),
            ExclusionLevel::Blacklisted
        );
        assert_eq!(
            snapshot.level("domain", "www.dead.example.com"),
            ExclusionLevel::Blacklisted
        );
    }
}

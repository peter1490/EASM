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
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    config::{Settings, SharedSettings},
    error::ApiError,
    models::{
        Asset, AssetCreate, AssetRelationshipCreate, AssetSourceCreate, AssetType,
        BlacklistObjectType, DiscoveryConfig, DiscoveryQueueItemCreate, DiscoveryResult,
        DiscoveryRun, DiscoveryRunCreate, QueueItemType, RelationshipType, ScanTriggerType,
        SecurityScanCreate, SecurityScanType, Seed, SeedCreate, SeedType, SourceType, TriggerType,
    },
    repositories::{
        AssetRelationshipRepository, AssetRepository, AssetSourceRepository, BlacklistRepository,
        DiscoveryQueueRepository, DiscoveryRunRepository, SeedRepository,
    },
    services::{
        confidence::ConfidenceScorer,
        external::{DnsResolver, ExternalServicesManager, HttpAnalyzer},
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

/// Discovery source priority for canonical ordering and primary discovery method selection.
static DISCOVERY_SOURCE_PRIORITY: &[SourceType] = &[
    SourceType::Shodan,
    SourceType::Virustotal,
    SourceType::Crtsh,
    SourceType::Certspotter,
];

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
    blacklist_repo: Arc<dyn BlacklistRepository + Send + Sync>,

    // Services
    security_scan_service: Option<Arc<SecurityScanService>>,
    risk_service: Arc<RiskService>,

    // External services
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_analyzer: Arc<HttpAnalyzer>,

    // Utilities
    task_manager: Arc<TaskManager>,
    settings: SharedSettings,
    confidence_scorer: Arc<ConfidenceScorer>,

    // State
    status: Arc<Mutex<HashMap<Uuid, DiscoveryStatus>>>,
    ip_cloud_provider_cache: Arc<Mutex<HashMap<String, bool>>>,
}

impl DiscoveryService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        seed_repo: Arc<dyn SeedRepository + Send + Sync>,
        discovery_run_repo: Arc<dyn DiscoveryRunRepository + Send + Sync>,
        discovery_queue_repo: Arc<dyn DiscoveryQueueRepository + Send + Sync>,
        asset_source_repo: Arc<dyn AssetSourceRepository + Send + Sync>,
        asset_relationship_repo: Arc<dyn AssetRelationshipRepository + Send + Sync>,
        blacklist_repo: Arc<dyn BlacklistRepository + Send + Sync>,
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
            blacklist_repo,
            security_scan_service: None,
            risk_service,
            external_services,
            dns_resolver,
            http_analyzer,
            task_manager,
            settings,
            confidence_scorer: Arc::new(ConfidenceScorer::new()),
            status: Arc::new(Mutex::new(HashMap::new())),
            ip_cloud_provider_cache: Arc::new(Mutex::new(HashMap::new())),
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

        // Update status
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.is_running = true;
            status.run_id = Some(run_id);
            status.started_at = Some(Utc::now());
            status.completed_at = None;
            status.current_phase = "Initializing".to_string();
            status.errors.clear();
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

    /// Stop the running discovery
    pub async fn stop_discovery(&self, company_id: Uuid) -> Result<(), ApiError> {
        let (run_id, task_id) = {
            let statuses = self.status.lock().await;
            let status = statuses.get(&company_id).cloned().unwrap_or_default();
            if !status.is_running {
                return Err(ApiError::Validation("Discovery is not running".to_string()));
            }
            (status.run_id, status.task_id)
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

        if let Some(id) = run_id {
            // Mark run as cancelled in the database
            self.discovery_run_repo
                .update_status(company_id, &id, "cancelled", Some("Stopped by user"))
                .await?;
        }

        // Update status
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.is_running = false;
            status.completed_at = Some(Utc::now());
            status.current_phase = "Cancelled".to_string();
            status.task_id = None;
        }

        Ok(())
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

        // Finalize discovery run
        {
            let mut statuses = self.status.lock().await;
            let status = statuses
                .entry(company_id)
                .or_insert_with(DiscoveryStatus::default);
            status.is_running = false;
            status.completed_at = Some(Utc::now());
            status.task_id = None; // Clear task ID on completion

            match &result {
                Ok(_) => {
                    status.current_phase = "Completed".to_string();
                    self.discovery_run_repo
                        .complete(company_id, &run_id)
                        .await?;
                }
                Err(e) => {
                    // Check if error is due to cancellation
                    let error_msg = e.to_string();
                    if error_msg.contains("cancelled") || error_msg.contains("Task was cancelled") {
                        status.current_phase = "Cancelled".to_string();
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

        // Check if the item is blacklisted before processing
        if self
            .is_item_blacklisted(company_id, item_type, item_value)
            .await?
        {
            tracing::info!(
                "Skipping blacklisted {} '{}' during discovery",
                item_type,
                item_value
            );
            return Ok(DiscoveryResult::default());
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

    /// Check if an item is blacklisted based on its type
    async fn is_item_blacklisted(
        &self,
        company_id: Uuid,
        item_type: &str,
        item_value: &str,
    ) -> Result<bool, ApiError> {
        match item_type {
            "domain" => {
                // Check if domain or any parent domain is blacklisted
                Ok(self
                    .blacklist_repo
                    .is_domain_or_parent_blacklisted(item_value, company_id)
                    .await?
                    .is_some())
            }
            "ip" => {
                // Check if IP is blacklisted directly or within a blacklisted CIDR
                Ok(self
                    .blacklist_repo
                    .is_ip_blacklisted(item_value, company_id)
                    .await?
                    .is_some())
            }
            "organization" => Ok(self
                .blacklist_repo
                .is_blacklisted(&BlacklistObjectType::Organization, item_value, company_id)
                .await?),
            "asn" => Ok(self
                .blacklist_repo
                .is_blacklisted(&BlacklistObjectType::Asn, item_value, company_id)
                .await?),
            "cidr" => Ok(self
                .blacklist_repo
                .is_blacklisted(&BlacklistObjectType::Cidr, item_value, company_id)
                .await?),
            _ => Ok(false),
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

        if domain_asset.1 {
            // was created
            result.assets_created.push(domain_asset.0);
        } else {
            result.assets_updated.push(domain_asset.0);
        }

        let domain_asset_id = domain_asset.0;

        // Step 1: Subdomain enumeration from multiple sources
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

                    let source_types = subdomain_result
                        .hostname_sources
                        .get(subdomain)
                        .cloned()
                        .unwrap_or_else(|| vec![SourceType::UserInput]);
                    let source_names: Vec<String> =
                        source_types.iter().map(|s| s.to_string()).collect();
                    let confidence = self.calculate_subdomain_confidence(source_types.len());

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

        // Step 2: DNS resolution
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

                    // IP recursion is intentionally disabled: discovered IPs are persisted,
                    // but never enqueued for further recursive discovery.
                }
            }
            Err(e) => {
                tracing::debug!("DNS resolution failed for {}: {}", canonical_domain, e);
            }
        }

        // Step 3: TLS Certificate analysis (for pivoting)
        match self
            .http_analyzer
            .get_tls_certificate_info(&canonical_domain, 443)
            .await
        {
            Ok(cert_result) => {
                if !cert_result.certificate_chain.is_empty() {
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

        Ok(result)
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

        if self.is_item_blacklisted(company_id, "ip", ip).await? {
            tracing::info!("Skipping blacklisted IP '{}' during discovery", ip);
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

        if ip_asset.1 {
            result.assets_created.push(ip_asset.0);
        }

        let ip_asset_id = ip_asset.0;

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

    /// Create or update an asset and record its source
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
    ) -> Result<(Uuid, bool), ApiError> {
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
    ) -> Result<(Uuid, bool), ApiError> {
        // Returns (asset_id, was_created)
        let normalized_identifier = if matches!(asset_type, AssetType::Domain) {
            Self::normalize_discovery_hostname(identifier)
                .ok_or_else(|| ApiError::Validation("Invalid domain format".to_string()))?
        } else {
            identifier.to_string()
        };

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

        // Auto-scan high confidence newly created assets
        if was_created {
            let auto_scan_threshold = {
                let statuses = self.status.lock().await;
                statuses
                    .get(&company_id)
                    .map(|status| status.auto_scan_threshold)
                    .unwrap_or(0.0)
            };

            if auto_scan_threshold > 0.0 {
                if let Err(e) = self
                    .maybe_trigger_auto_scan(
                        company_id,
                        asset.id,
                        &normalized_identifier,
                        &asset_type,
                        confidence,
                        Some(auto_scan_threshold),
                    )
                    .await
                {
                    tracing::warn!(
                        "Failed to trigger auto-scan for {}: {}",
                        normalized_identifier,
                        e
                    );
                } else if confidence >= auto_scan_threshold {
                    // Increment counter if scan was likely queued
                    let mut statuses = self.status.lock().await;
                    let status = statuses
                        .entry(company_id)
                        .or_insert_with(DiscoveryStatus::default);
                    status.scans_queued += 1;
                }
            }
        }

        Ok((asset.id, was_created))
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
    fn calculate_subdomain_confidence(&self, source_count: usize) -> f64 {
        self.calculate_multi_source_confidence(0.5, source_count)
    }

    fn calculate_multi_source_confidence(&self, base: f64, source_count: usize) -> f64 {
        let effective_source_count = source_count.max(1);
        let boost = ((effective_source_count as f64) - 1.0) * 0.1;
        (base + boost).min(0.9)
    }

    /// Check if asset should be auto-scanned and queue a security scan
    async fn maybe_trigger_auto_scan(
        &self,
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
            blacklist_repo: Arc::clone(&self.blacklist_repo),
            security_scan_service: self.security_scan_service.clone(),
            risk_service: Arc::clone(&self.risk_service),
            external_services: Arc::clone(&self.external_services),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_analyzer: Arc::clone(&self.http_analyzer),
            task_manager: Arc::clone(&self.task_manager),
            settings: Arc::clone(&self.settings),
            confidence_scorer: Arc::clone(&self.confidence_scorer),
            status: Arc::clone(&self.status),
            ip_cloud_provider_cache: Arc::clone(&self.ip_cloud_provider_cache),
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
        assert_eq!(
            ordered,
            vec![
                SourceType::Shodan,
                SourceType::Virustotal,
                SourceType::Crtsh
            ]
        );
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
}

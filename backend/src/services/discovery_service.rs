use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use uuid::Uuid;
use serde_json::json;

use crate::{
    config::Settings,
    error::ApiError,
    models::{Asset, AssetCreate, AssetType, Seed, SeedCreate, SeedType},
    repositories::{AssetRepository, SeedRepository},
    services::{
        external::{
            ExternalServicesManager, DnsResolver, HttpAnalyzer, ShodanExtractedAssets
        },
        task_manager::{TaskManager, TaskType, TaskContext},
        confidence::{ConfidenceScorer, ConfidenceFactors, MethodConfidence},
    },
    utils::network::expand_cidr,
};

use super::ScanService;
use crate::models::ScanCreate;

/// Common CDN, cloud provider, and hosting organizations that should be filtered
/// to prevent excessive false-positives in recursive discovery
static COMMON_INFRASTRUCTURE_ORGS: &[&str] = &[
    // CDN Providers
    "cloudflare", "akamai", "fastly", "cloudfront", "amazon cloudfront",
    "stackpath", "keycdn", "bunnycdn", "maxcdn",
    
    // Cloud Providers
    "amazon", "aws", "google", "google cloud", "microsoft", "azure",
    "digitalocean", "linode", "vultr", "ovh", "hetzner", "scaleway",
    
    // Hosting Providers
    "godaddy", "namecheap", "bluehost", "hostgator", "dreamhost",
    "1&1", "ionos", "rackspace", "liquidweb",
    
    // Certificate Authorities
    "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
    "verisign", "thawte", "geotrust", "rapidssl", "godaddy.com",
    
    // CDN/WAF Services
    "incapsula", "imperva", "sucuri", "wordfence", "barracuda",
    
    // Generic/Common
    "domain administrator", "domain admin", "privacy", "whois privacy",
    "contact privacy", "private", "registration private", "proxy",
    
    // Too broad/generic
    "inc", "llc", "ltd", "corporation", "corp", "company", "co.",
];

/// Domains/organizations that contain these keywords should be skipped
static SKIP_ORG_KEYWORDS: &[&str] = &[
    "sale", "force", "salesforce", "adobe", "oracle", "sap",
    "marketo", "hubspot", "mailchimp", "sendgrid",
];

/// Tracking context for recursive discovery to enforce limits
#[derive(Debug, Clone)]
struct RecursiveContext {
    /// Current depth in the recursion tree
    depth: u32,
    /// Total assets discovered so far
    total_assets: usize,
    /// Organizations processed per domain (to limit pivots)
    orgs_per_domain: HashMap<String, u32>,
    /// Domains processed per org (to limit pivots)  
    domains_per_org: HashMap<String, u32>,
}

/// Discovery run status tracking
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryStatus {
    #[serde(default)]
    pub is_running: bool,
    #[serde(default)]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub seeds_processed: usize,
    #[serde(default)]
    pub assets_discovered: usize,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub task_id: Option<Uuid>,
}

/// Asset discovery result with confidence scoring
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub assets: Vec<Asset>,
    pub confidence_scores: HashMap<String, f64>,
    pub sources: HashMap<String, Vec<String>>,
}

pub struct DiscoveryService {
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    seed_repo: Arc<dyn SeedRepository + Send + Sync>,
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_analyzer: Arc<HttpAnalyzer>,
    task_manager: Arc<TaskManager>,
    settings: Arc<Settings>,
    discovery_status: Arc<Mutex<DiscoveryStatus>>,
    scan_service: Arc<ScanService>,
    confidence_scorer: Arc<ConfidenceScorer>,
}

impl DiscoveryService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        seed_repo: Arc<dyn SeedRepository + Send + Sync>,
        external_services: Arc<ExternalServicesManager>,
        dns_resolver: Arc<DnsResolver>,
        http_analyzer: Arc<HttpAnalyzer>,
        task_manager: Arc<TaskManager>,
        settings: Arc<Settings>,
        scan_service: Arc<ScanService>,
    ) -> Self {
        Self {
            asset_repo,
            seed_repo,
            external_services,
            dns_resolver,
            http_analyzer,
            task_manager,
            settings,
            discovery_status: Arc::new(Mutex::new(DiscoveryStatus::default())),
            scan_service,
            confidence_scorer: Arc::new(ConfidenceScorer::new()),
        }
    }
    
    /// Check if an organization should be filtered out to reduce false-positives
    /// Returns true if the org should be skipped
    fn should_filter_organization(&self, org: &str) -> bool {
        let org_lower = org.to_lowercase();
        
        // Skip if empty or too short
        if org_lower.trim().is_empty() || org_lower.len() < 3 {
            return true;
        }
        
        // Check against skip keywords (known problematic orgs)
        for keyword in SKIP_ORG_KEYWORDS {
            if org_lower.contains(keyword) {
                return true;
            }
        }
        
        // Check against common infrastructure organizations
        for infra_org in COMMON_INFRASTRUCTURE_ORGS {
            // Exact match or contains for common orgs
            if org_lower == *infra_org || org_lower.contains(infra_org) {
                tracing::debug!("Filtering common infrastructure org: {}", org);
                return true;
            }
        }
        
        // Filter overly generic organization names
        let generic_only = org_lower.chars()
            .filter(|c| c.is_alphabetic())
            .collect::<String>();
            
        if generic_only.len() <= 3 {
            // Too short after removing non-alphabetic chars
            return true;
        }
        
        false
    }
    
    /// Calculate pivot relationship strength score (0.0 - 1.0)
    /// Higher score = stronger relationship = more likely to be legitimate pivot
    fn calculate_pivot_score(&self, org: &str, from_domain: &str, cert_has_san: bool, multiple_sources: bool) -> f64 {
        let mut score: f64 = 0.5; // Base score
        
        // Bonus for certificate with SAN (shows it's an active cert for multiple domains)
        if cert_has_san {
            score += 0.15;
        }
        
        // Bonus for multiple sources confirming the relationship
        if multiple_sources {
            score += 0.2;
        }
        
        // Check if org name is similar to domain
        let org_lower = org.to_lowercase();
        let domain_parts: Vec<&str> = from_domain.split('.').collect();
        
        // Check if org contains domain name parts
        if domain_parts.len() >= 2 {
            let domain_base = domain_parts[domain_parts.len() - 2];
            if org_lower.contains(domain_base) {
                score += 0.15; // Strong signal that they're related
            }
        }
        
        // Penalty for very generic org names
        if org.len() < 5 {
            score -= 0.2;
        }
        
        // Penalty if org is in common infrastructure list
        if self.should_filter_organization(org) {
            score -= 0.5; // Heavy penalty
        }
        
        score.clamp(0.0, 1.0)
    }
    
    /// Check if we should continue recursive discovery based on context and limits
    fn should_continue_recursion(&self, ctx: &RecursiveContext) -> bool {
        // Check depth limit
        if ctx.depth >= self.settings.max_discovery_depth {
            tracing::info!("Stopping recursion: reached max depth {} / {}", ctx.depth, self.settings.max_discovery_depth);
            return false;
        }
        
        // Check asset count limit
        if ctx.total_assets >= self.settings.max_assets_per_discovery as usize {
            tracing::info!("Stopping recursion: reached max assets {} / {}", ctx.total_assets, self.settings.max_assets_per_discovery);
            return false;
        }
        
        true
    }
    
    /// Check if we can add another org pivot from a domain
    fn can_add_org_pivot(&self, ctx: &RecursiveContext, domain: &str) -> bool {
        let count = ctx.orgs_per_domain.get(domain).unwrap_or(&0);
        *count < self.settings.max_orgs_per_domain
    }
    
    /// Check if we can add another domain pivot from an org
    fn can_add_domain_pivot(&self, ctx: &RecursiveContext, org: &str) -> bool {
        let count = ctx.domains_per_org.get(org).unwrap_or(&0);
        *count < self.settings.max_domains_per_org
    }

    pub async fn create_seed(&self, seed_create: SeedCreate) -> Result<Seed, ApiError> {
        // Validate seed based on type
        self.validate_seed(&seed_create)?;
        self.seed_repo.create(&seed_create).await
    }

    pub async fn list_seeds(&self) -> Result<Vec<Seed>, ApiError> {
        self.seed_repo.list().await
    }

    pub async fn delete_seed(&self, id: &Uuid) -> Result<(), ApiError> {
        self.seed_repo.delete(*id).await
    }

    pub async fn list_assets(
        &self,
        confidence_threshold: Option<f64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Asset>, ApiError> {
        self.asset_repo.list(confidence_threshold, limit, offset).await
    }

    pub async fn count_assets(
        &self,
        confidence_threshold: Option<f64>,
    ) -> Result<i64, ApiError> {
        self.asset_repo.count(confidence_threshold).await
    }

    pub async fn get_asset(&self, id: &Uuid) -> Result<Option<Asset>, ApiError> {
        self.asset_repo.get_by_id(id).await
    }

    pub async fn get_asset_path(&self, id: &Uuid) -> Result<Vec<Asset>, ApiError> {
        self.asset_repo.get_path(id).await
    }

    pub async fn create_or_merge_asset(&self, asset_create: AssetCreate) -> Result<Asset, ApiError> {
        self.asset_repo.create_or_merge(&asset_create).await
    }
    
    /// Update asset confidence based on scan results
    /// This should be called after a scan completes to adjust confidence based on validation
    pub async fn update_asset_confidence_from_scan(
        &self,
        asset_id: &Uuid,
        scan_successful: bool,
    ) -> Result<Asset, ApiError> {
        // Get current asset
        let asset = self.asset_repo.get_by_id(asset_id).await?
            .ok_or_else(|| ApiError::NotFound("Asset not found".to_string()))?;
        
        // Calculate new confidence using the confidence scorer
        let new_confidence = self.confidence_scorer.update_confidence_from_scan(
            asset.confidence,
            scan_successful,
            asset.created_at,
        );
        
        // Update the asset
        self.asset_repo.update_confidence(asset_id, new_confidence).await
    }

    /// Get current discovery status
    pub async fn get_discovery_status(&self) -> DiscoveryStatus {
        self.discovery_status.lock().await.clone()
    }

    /// Run comprehensive asset discovery based on all seeds
    pub async fn run_discovery(&self, confidence_threshold: Option<f64>) -> Result<(), ApiError> {
        // Check if discovery is already running
        {
            let mut status = self.discovery_status.lock().await;
            if status.is_running {
                return Err(ApiError::Validation("Discovery is already running".to_string()));
            }
            
            // Reset and start discovery
            *status = DiscoveryStatus {
                is_running: true,
                started_at: Some(chrono::Utc::now()),
                ..Default::default()
            };
        }

        // Submit discovery task to TaskManager
        let discovery_service = self.clone();
        let task_metadata = json!({
            "discovery_type": "comprehensive",
            "started_at": chrono::Utc::now()
        });
        
        let task_id = self.task_manager.submit_task(
            TaskType::Discovery,
            task_metadata,
            move |ctx| {
                let discovery_service = discovery_service.clone();
                Box::pin(async move {
                    discovery_service.run_discovery_with_context(ctx, confidence_threshold).await
                })
            }
        ).await?;

        // Update status with task_id
        {
            let mut status = self.discovery_status.lock().await;
            status.task_id = Some(task_id);
        }

        Ok(())
    }

    /// Stop the running discovery task
    pub async fn stop_discovery(&self) -> Result<(), ApiError> {
        let task_id = {
            let status = self.discovery_status.lock().await;
            if !status.is_running {
                return Err(ApiError::Validation("Discovery is not running".to_string()));
            }
            status.task_id
        };

        if let Some(id) = task_id {
            self.task_manager.cancel_task(id).await?;
            
            // Update status immediately
            let mut status = self.discovery_status.lock().await;
            status.is_running = false;
            status.completed_at = Some(chrono::Utc::now());
            status.errors.push("Discovery stopped by user".to_string());
        }

        Ok(())
    }

    /// Discovery processing with task context
    async fn run_discovery_with_context(&self, ctx: TaskContext, confidence_threshold: Option<f64>) -> Result<(), ApiError> {
        tracing::info!("Starting comprehensive asset discovery with task context");
        
        // Ensure status is always reset, even on error
        let result = self.run_discovery_internal(&ctx, confidence_threshold).await;
        
        // Mark discovery as completed (whether success or failure)
        {
            let mut status = self.discovery_status.lock().await;
            status.is_running = false;
            status.completed_at = Some(chrono::Utc::now());
            
            // Add error if failed
            if let Err(ref e) = result {
                status.errors.push(format!("Discovery failed: {}", e));
            }
        }
        
        result
    }

    /// Internal discovery implementation
    async fn run_discovery_internal(&self, ctx: &TaskContext, confidence_threshold: Option<f64>) -> Result<(), ApiError> {
        let seeds = self.seed_repo.list().await?;
        let mut total_assets_discovered = 0;
        let mut processed_seeds = 0;

        ctx.update_progress(0.1, Some(format!("Found {} seeds to process", seeds.len()))).await?;

        // Process seeds with concurrency control
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.settings.max_concurrent_scans as usize));
        let mut tasks = Vec::new();
        let total_seeds = seeds.len();

        for (i, seed) in seeds.iter().enumerate() {
            ctx.check_cancellation().await?;
            
            let discovery_service = self.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let seed = seed.clone();
            
            let task = tokio::spawn(async move {
                let _permit = permit;
                discovery_service.process_seed(&seed, confidence_threshold).await
            });
            
            tasks.push(task);
            
            // Update progress for task submission
            let submission_progress = 0.1 + ((i as f32) / (total_seeds as f32)) * 0.2;
            ctx.update_progress(submission_progress, Some(format!("Submitted {} of {} seed processing tasks", i + 1, total_seeds))).await?;
        }

        // Wait for all seed processing to complete
        for (i, task) in tasks.into_iter().enumerate() {
            ctx.check_cancellation().await?;
            
            match task.await {
                Ok(Ok(result)) => {
                    total_assets_discovered += result.assets.len();
                    processed_seeds += 1;
                    
                    // Update status
                    {
                        let mut status = self.discovery_status.lock().await;
                        status.seeds_processed = processed_seeds;
                        status.assets_discovered = total_assets_discovered;
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!("Seed processing failed: {}", e);
                    let mut status = self.discovery_status.lock().await;
                    status.errors.push(e.to_string());
                }
                Err(e) => {
                    tracing::error!("Seed processing task failed: {}", e);
                    let mut status = self.discovery_status.lock().await;
                    status.errors.push(format!("Task error: {}", e));
                }
            }
            
            // Update progress for completed tasks
            let completion_progress = 0.3 + ((i as f32) / (total_seeds as f32)) * 0.6;
            ctx.update_progress(completion_progress, Some(format!("Completed {} of {} seed processing tasks", i + 1, total_seeds))).await?;
        }

        ctx.update_progress(0.95, Some("Finalizing discovery".to_string())).await?;

        tracing::info!(
            "Discovery completed: {} seeds processed, {} assets discovered",
            processed_seeds,
            total_assets_discovered
        );

        Ok(())
    }



    /// Process a single seed for asset discovery
    async fn process_seed(&self, seed: &Seed, confidence_threshold: Option<f64>) -> Result<DiscoveryResult, ApiError> {
        tracing::info!("Processing seed: {} ({})", seed.value, seed.seed_type);
        
        let timeout_duration = Duration::from_secs_f64(self.settings.subdomain_enum_timeout * 1440.0); // 1440 = 24 hours
        
        // Create root asset for the seed to establish lineage
        let root_asset_type = match seed.seed_type {
            SeedType::Domain => AssetType::Domain,
            SeedType::Organization => AssetType::Organization,
            SeedType::Asn => AssetType::Asn,
            SeedType::Cidr => AssetType::Ip, // CIDR usually resolves to IPs, but we might want a CIDR type later. For now keep as is or map to what fits.
            SeedType::Keyword => AssetType::Domain, // Keywords usually find domains
        };

        // For CIDR and Keyword we might not want a root asset if they don't map 1:1 to an asset type
        // But for Domain, Org, ASN we definitely do.
        let root_asset_id = if matches!(seed.seed_type, SeedType::Domain | SeedType::Organization | SeedType::Asn) {
            let root_asset = AssetCreate {
                asset_type: root_asset_type,
                identifier: seed.value.clone(),
                confidence: 1.0,
                sources: json!(["seed"]),
                metadata: json!({"seed_type": seed.seed_type}),
                seed_id: Some(seed.id),
                parent_id: None,
            };
            match self.asset_repo.create_or_merge(&root_asset).await {
                Ok(asset) => Some(asset.id),
                Err(e) => {
                    tracing::error!("Failed to create root asset for seed {}: {}", seed.value, e);
                    return Err(e);
                }
            }
        } else {
            None
        };

        let result = timeout(timeout_duration, async {
            match seed.seed_type {
                SeedType::Domain => self.discover_from_domain_recursive(&seed.value, confidence_threshold, Some(seed.id), root_asset_id).await,
                SeedType::Organization => self.discover_from_organization_recursive(&seed.value, confidence_threshold, Some(seed.id), root_asset_id).await,
                SeedType::Asn => self.discover_from_asn(&seed.value, Some(seed.id), root_asset_id).await,
                SeedType::Cidr => self.discover_from_cidr(&seed.value, Some(seed.id), root_asset_id).await,
                SeedType::Keyword => self.discover_from_keyword(&seed.value, Some(seed.id), root_asset_id).await,
            }
        }).await;

        match result {
            Ok(discovery_result) => {
                match discovery_result {
                    Ok(result) => {
                        // Asset creation is now handled in the discovery functions
                        // Store discovered assets and trigger scans for non-recursive seed types
                        // Domain and Organization seeds handle saving and scanning internally during recursion
                        if !matches!(seed.seed_type, SeedType::Domain | SeedType::Organization) {
                            for asset in &result.assets {
                                // Check if we should trigger a scan
                                if let Some(threshold) = confidence_threshold {
                                    if asset.confidence >= threshold {
                                        // Only scan domains and IPs
                                        if matches!(asset.asset_type, AssetType::Domain | AssetType::Ip) {
                                            let scan_create = ScanCreate {
                                                target: asset.identifier.clone(),
                                                note: Some(format!("Auto-scan triggered by discovery (confidence: {:.2})", asset.confidence)),
                                            };
                                            
                                            match self.scan_service.create_scan(scan_create).await {
                                                Ok(scan) => tracing::info!("Triggered auto-scan {} for discovered asset {}", scan.id, asset.identifier),
                                                Err(e) => tracing::warn!("Failed to trigger auto-scan for {}: {}", asset.identifier, e),
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        Ok(result)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                Err(ApiError::ExternalService(format!(
                    "Seed processing timeout for {} ({})",
                    seed.value, seed.seed_type
                )))
            }
        }
    }

    /// Recursively discover assets starting from a domain by pivoting on certificate organizations
    async fn discover_from_domain_recursive(&self, root_domain: &str, confidence_threshold: Option<f64>, seed_id: Option<Uuid>, root_parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut all_assets: Vec<Asset> = Vec::new();
        let mut all_confidence: HashMap<String, f64> = HashMap::new();
        let mut all_sources: HashMap<String, Vec<String>> = HashMap::new();

        let mut visited_domains: HashSet<String> = HashSet::new();
        let mut visited_orgs: HashSet<String> = HashSet::new();

        // Initialize recursive context for tracking limits
        let mut context = RecursiveContext {
            depth: 0,
            total_assets: 0,
            orgs_per_domain: HashMap::new(),
            domains_per_org: HashMap::new(),
        };

        let mut domain_queue: VecDeque<(String, Option<Uuid>, u32)> = VecDeque::new(); // Added depth tracking
        let mut org_queue: VecDeque<(String, Option<Uuid>, u32)> = VecDeque::new(); // Added depth tracking
        domain_queue.push_back((root_domain.to_string(), root_parent_id, 0));

        loop {
            // Check if we should continue recursion
            if !self.should_continue_recursion(&context) {
                tracing::info!("Stopping domain recursion at depth {}, {} assets discovered", context.depth, context.total_assets);
                break;
            }

            if let Some((domain_value, parent_id, depth)) = domain_queue.pop_front() {
                if !visited_domains.insert(domain_value.clone()) { continue; }

                // Update context depth
                context.depth = depth;
                
                tracing::debug!("Processing domain '{}' at depth {}", domain_value, depth);

                // Discover from domain
                let result = self.discover_from_domain(&domain_value, seed_id, parent_id).await?;
                
                // Assets are already saved by discover_from_domain
                for asset in &result.assets {
                    tracing::debug!("Discovered {:?} asset: {}", asset.asset_type, asset.identifier);
                    
                    // Check if we should trigger a scan
                    if let Some(threshold) = confidence_threshold {
                        if asset.confidence >= threshold {
                            // Only scan domains and IPs
                            if matches!(asset.asset_type, AssetType::Domain | AssetType::Ip) {
                                let scan_create = ScanCreate {
                                    target: asset.identifier.clone(),
                                    note: Some(format!("Auto-scan triggered by discovery (confidence: {:.2})", asset.confidence)),
                                };
                                
                                match self.scan_service.create_scan(scan_create).await {
                                    Ok(scan) => tracing::info!("Triggered auto-scan {} for discovered asset {}", scan.id, asset.identifier),
                                    Err(e) => tracing::warn!("Failed to trigger auto-scan for {}: {}", asset.identifier, e),
                                }
                            }
                        }
                    }
                }

                // Update asset count in context
                context.total_assets += result.assets.len();

                // Merge assets and extract organization pivots
                for asset in &result.assets {
                    all_assets.push(asset.clone());

                    // Extract organization from certificate metadata for pivoting
                    if let Some(org) = asset.metadata.get("organization").and_then(|v| v.as_str()) {
                        let org_trimmed = org.trim();
                        
                        // Apply organization filtering
                        if self.should_filter_organization(org_trimmed) {
                            tracing::debug!("Filtered organization: {} (from domain: {})", org_trimmed, domain_value);
                            continue;
                        }
                        
                        if !org_trimmed.is_empty() && !visited_orgs.contains(org_trimmed) {
                            // Check if we can add more org pivots from this domain
                            if !self.can_add_org_pivot(&context, &domain_value) {
                                tracing::debug!("Skipping org '{}': max orgs per domain reached for '{}'", org_trimmed, domain_value);
                                continue;
                            }
                            
                            // Calculate pivot score to determine if relationship is strong enough
                            let cert_has_san = asset.metadata.get("san_domains")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.len() > 1)
                                .unwrap_or(false);
                            let multiple_sources = asset.sources.as_array()
                                .map(|arr| arr.len() > 1)
                                .unwrap_or(false);
                            
                            let pivot_score = self.calculate_pivot_score(
                                org_trimmed, 
                                &domain_value, 
                                cert_has_san, 
                                multiple_sources
                            );
                            
                            // Only pivot if score is high enough (above min_pivot_confidence)
                            if pivot_score < self.settings.min_pivot_confidence {
                                tracing::debug!(
                                    "Skipping weak pivot to org '{}' (score: {:.2}, threshold: {:.2})",
                                    org_trimmed, pivot_score, self.settings.min_pivot_confidence
                                );
                                continue;
                            }
                            
                            tracing::info!(
                                "Following strong pivot to org '{}' (score: {:.2}) from domain '{}' at depth {}",
                                org_trimmed, pivot_score, domain_value, depth
                            );
                            
                            // Determine parent_id based on asset type
                            // The source asset (Domain, IP, or Certificate) is the parent of the discovered organization
                            let org_parent_id = Some(asset.id);
                            
                            // Create Organization Asset with proper lineage
                            // Adjust confidence based on pivot score and depth
                            let base_confidence = MethodConfidence::TLS_CERT_WITH_ORG.base * pivot_score;
                            let org_confidence = {
                                let factors = ConfidenceFactors {
                                    base_confidence,
                                    sources: vec!["certificate_pivot".to_string()],
                                    distance_from_seed: (depth + 1) as usize,
                                    ..Default::default()
                                };
                                self.confidence_scorer.calculate_confidence(&factors)
                            };
                            
                            // Only create org asset if confidence is above threshold
                            if org_confidence < self.settings.min_pivot_confidence {
                                tracing::debug!(
                                    "Skipping org '{}' due to low confidence: {:.2}",
                                    org_trimmed, org_confidence
                                );
                                continue;
                            }
                            
                            let org_asset = AssetCreate {
                                asset_type: AssetType::Organization,
                                identifier: org_trimmed.to_string(),
                                confidence: org_confidence,
                                sources: json!(["certificate_pivot"]),
                                metadata: json!({
                                    "source_domain": domain_value, 
                                    "source_asset_type": format!("{:?}", asset.asset_type),
                                    "pivot_score": pivot_score,
                                    "discovery_depth": depth + 1
                                }),
                                seed_id,
                                parent_id: org_parent_id,
                            };
                            
                            // Create the organization asset and get its ID for the queue
                            let org_id = match self.asset_repo.create_or_merge(&org_asset).await {
                                Ok(a) => Some(a.id),
                                Err(e) => {
                                    tracing::warn!("Failed to create organization asset {}: {}", org_trimmed, e);
                                    None
                                }
                            };

                            if !org_queue.iter().any(|(o, _, _)| o == org_trimmed) {
                                // Increment org pivot count for this domain
                                *context.orgs_per_domain.entry(domain_value.clone()).or_insert(0) += 1;
                                org_queue.push_back((org_trimmed.to_string(), org_id, depth + 1));
                            }
                        }
                    }
                }
                for (k, v) in result.confidence_scores {
                    match all_confidence.get_mut(&k) {
                        Some(existing) => { if v > *existing { *existing = v; } }
                        None => { all_confidence.insert(k, v); }
                    }
                }
                for (k, mut v) in result.sources {
                    all_sources.entry(k).and_modify(|existing| {
                        for src in &v { if !existing.contains(src) { existing.push(src.clone()); } }
                    }).or_insert_with(|| { v.sort(); v.dedup(); v });
                }
            } else if let Some((org_value, parent_id, depth)) = org_queue.pop_front() {
                // Organization pivot
                if !visited_orgs.insert(org_value.clone()) { continue; }

                // Update context depth
                context.depth = depth;
                
                tracing::debug!("Processing organization '{}' at depth {}", org_value, depth);

                // Double-check filtering (should have been done earlier, but defensive check)
                if self.should_filter_organization(&org_value) {
                    tracing::debug!("Skipping filtered organization: {}", org_value);
                    continue;
                }

                let result = self.discover_from_organization(&org_value, seed_id, parent_id).await?;

                // Update asset count
                context.total_assets += result.assets.len();

                // Merge
                let mut domains_added = 0u32;
                for asset in &result.assets {
                    // Queue newly found domains for further exploration
                    if asset.asset_type == AssetType::Domain {
                        let domain = asset.identifier.clone();
                        let mut top_domain = String::new();

                        // extract top domain and add to queue
                        let parts: Vec<&str> = domain.split('.').collect();

                        if parts.len() >= 2 {
                            top_domain.push_str(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]).as_str());
                        }else{
                            top_domain.push_str(domain.as_str());
                        }
                        
                        // Check if we can add more domain pivots from this org
                        if !self.can_add_domain_pivot(&context, &org_value) {
                            tracing::debug!("Skipping domain '{}': max domains per org reached for '{}'", top_domain, org_value);
                            continue;
                        }
                        
                        // Check confidence threshold
                        if asset.confidence < self.settings.min_pivot_confidence {
                            tracing::debug!(
                                "Skipping low confidence domain '{}' (confidence: {:.2}, threshold: {:.2})",
                                top_domain, asset.confidence, self.settings.min_pivot_confidence
                            );
                            continue;
                        }
                        
                        if !visited_domains.contains(&top_domain) && !domain_queue.iter().any(|(d, _, _)| d == &top_domain) {
                            tracing::info!("New top domain found from org '{}': {} (depth {})", org_value, top_domain, depth + 1);
                            
                            // To ensure proper hierarchy (Org -> Top Domain -> Subdomains), we need to ensure
                            // the top domain asset exists and use its ID as the parent for subsequent discovery.
                            // If the top_domain is the same as the current asset, use the current asset's ID.
                            // Otherwise, create/merge the top_domain asset.
                            
                            let domain_parent_id = if top_domain == domain {
                                Some(asset.id)
                            } else {
                                // Create/merge the top domain asset
                                let top_domain_asset = AssetCreate {
                                    asset_type: AssetType::Domain,
                                    identifier: top_domain.clone(),
                                    confidence: asset.confidence, // Inherit confidence
                                    sources: asset.sources.clone(),
                                    metadata: json!({
                                        "organization": org_value,
                                        "discovery_method": "org_pivot_parent",
                                        "derived_from": domain
                                    }),
                                    seed_id,
                                    parent_id, // Parent is the Organization
                                };
                                
                                match self.asset_repo.create_or_merge(&top_domain_asset).await {
                                    Ok(a) => Some(a.id),
                                    Err(e) => {
                                        tracing::warn!("Failed to create top domain asset {}: {}", top_domain, e);
                                        None
                                    }
                                }
                            };
                            
                            // Push to queue with the Top Domain's ID as parent for its children
                            domain_queue.push_back((top_domain, domain_parent_id, depth + 1));
                            domains_added += 1;
                        }
                    }
                    all_assets.push(asset.clone());
                }
                
                // Update domain pivot count for this org
                if domains_added > 0 {
                    *context.domains_per_org.entry(org_value.clone()).or_insert(0) += domains_added;
                }
                for (k, v) in result.confidence_scores {
                    match all_confidence.get_mut(&k) {
                        Some(existing) => { if v > *existing { *existing = v; } }
                        None => { all_confidence.insert(k, v); }
                    }
                }
                for (k, mut v) in result.sources {
                    all_sources.entry(k).and_modify(|existing| {
                        for src in &v { if !existing.contains(src) { existing.push(src.clone()); } }
                    }).or_insert_with(|| { v.sort(); v.dedup(); v });
                }
            } else {
                break;
            }
        }

        Ok(DiscoveryResult {
            assets: all_assets,
            confidence_scores: all_confidence,
            sources: all_sources,
        })
    }

    /// Recursively discover assets starting from an organization by pivoting to domains then back to organizations
    async fn discover_from_organization_recursive(&self, root_org: &str, confidence_threshold: Option<f64>, seed_id: Option<Uuid>, root_parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut all_assets: Vec<Asset> = Vec::new();
        let mut all_confidence: HashMap<String, f64> = HashMap::new();
        let mut all_sources: HashMap<String, Vec<String>> = HashMap::new();

        let mut visited_domains: HashSet<String> = HashSet::new();
        let mut visited_orgs: HashSet<String> = HashSet::new();

        // Initialize recursive context for tracking limits
        let mut context = RecursiveContext {
            depth: 0,
            total_assets: 0,
            orgs_per_domain: HashMap::new(),
            domains_per_org: HashMap::new(),
        };

        let mut domain_queue: VecDeque<(String, Option<Uuid>, u32)> = VecDeque::new(); // Added depth tracking
        let mut org_queue: VecDeque<(String, Option<Uuid>, u32)> = VecDeque::new(); // Added depth tracking
        org_queue.push_back((root_org.to_string(), root_parent_id, 0));

        loop {
            // Check if we should continue recursion
            if !self.should_continue_recursion(&context) {
                tracing::info!("Stopping organization recursion at depth {}, {} assets discovered", context.depth, context.total_assets);
                break;
            }

            if let Some((domain_value, parent_id, depth)) = domain_queue.pop_front() {
                if !visited_domains.insert(domain_value.clone()) { continue; }

                // Update context depth
                context.depth = depth;
                
                tracing::debug!("Processing domain '{}' at depth {} (from org recursion)", domain_value, depth);

                let result = self.discover_from_domain(&domain_value, seed_id, parent_id).await?;

                // Update asset count
                context.total_assets += result.assets.len();

                // Assets are already saved
                for asset in &result.assets {
                    // Check if we should trigger a scan
                    if let Some(threshold) = confidence_threshold {
                        if asset.confidence >= threshold {
                            // Only scan domains and IPs
                            if matches!(asset.asset_type, AssetType::Domain | AssetType::Ip) {
                                let scan_create = ScanCreate {
                                    target: asset.identifier.clone(),
                                    note: Some(format!("Auto-scan triggered by discovery (confidence: {:.2})", asset.confidence)),
                                };
                                
                                match self.scan_service.create_scan(scan_create).await {
                                    Ok(scan) => tracing::info!("Triggered auto-scan {} for discovered asset {}", scan.id, asset.identifier),
                                    Err(e) => tracing::warn!("Failed to trigger auto-scan for {}: {}", asset.identifier, e),
                                }
                            }
                        }
                    }

                    all_assets.push(asset.clone());
                    
                    // Extract organization from certificate metadata for pivoting
                    if let Some(org) = asset.metadata.get("organization").and_then(|v| v.as_str()) {
                        let org_trimmed = org.trim();
                        
                        // Apply organization filtering
                        if self.should_filter_organization(org_trimmed) {
                            tracing::debug!("Filtered organization: {} (from domain: {})", org_trimmed, domain_value);
                            continue;
                        }
                        
                        if !org_trimmed.is_empty() && !visited_orgs.contains(org_trimmed) && !org_queue.iter().any(|(o, _, _)| o == org_trimmed) {
                            // Check if we can add more org pivots from this domain
                            if !self.can_add_org_pivot(&context, &domain_value) {
                                tracing::debug!("Skipping org '{}': max orgs per domain reached for '{}'", org_trimmed, domain_value);
                                continue;
                            }
                            
                            // Calculate pivot score
                            let cert_has_san = asset.metadata.get("san_domains")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.len() > 1)
                                .unwrap_or(false);
                            let multiple_sources = asset.sources.as_array()
                                .map(|arr| arr.len() > 1)
                                .unwrap_or(false);
                            
                            let pivot_score = self.calculate_pivot_score(
                                org_trimmed, 
                                &domain_value, 
                                cert_has_san, 
                                multiple_sources
                            );
                            
                            // Only pivot if score is high enough
                            if pivot_score < self.settings.min_pivot_confidence {
                                tracing::debug!(
                                    "Skipping weak pivot to org '{}' (score: {:.2}, threshold: {:.2})",
                                    org_trimmed, pivot_score, self.settings.min_pivot_confidence
                                );
                                continue;
                            }
                            
                            tracing::info!(
                                "Following strong pivot to org '{}' (score: {:.2}) from domain '{}' at depth {}",
                                org_trimmed, pivot_score, domain_value, depth
                            );
                            
                            // Determine parent_id based on asset type
                            let org_parent_id = if asset.asset_type == AssetType::Certificate {
                                Some(asset.id)
                            } else {
                                None
                            };
                            
                            // Create Organization asset with proper lineage
                            let base_confidence = MethodConfidence::TLS_CERT_WITH_ORG.base * pivot_score;
                            let org_confidence = {
                                let factors = ConfidenceFactors {
                                    base_confidence,
                                    sources: vec!["certificate_pivot".to_string()],
                                    distance_from_seed: (depth + 1) as usize,
                                    ..Default::default()
                                };
                                self.confidence_scorer.calculate_confidence(&factors)
                            };
                            
                            // Only create org asset if confidence is above threshold
                            if org_confidence < self.settings.min_pivot_confidence {
                                tracing::debug!(
                                    "Skipping org '{}' due to low confidence: {:.2}",
                                    org_trimmed, org_confidence
                                );
                                continue;
                            }
                            
                            let org_asset = AssetCreate {
                                asset_type: AssetType::Organization,
                                identifier: org_trimmed.to_string(),
                                confidence: org_confidence,
                                sources: json!(["certificate_pivot"]),
                                metadata: json!({
                                    "source_domain": domain_value, 
                                    "source_asset_type": format!("{:?}", asset.asset_type),
                                    "pivot_score": pivot_score,
                                    "discovery_depth": depth + 1
                                }),
                                seed_id,
                                parent_id: org_parent_id,
                            };
                            let org_id = match self.asset_repo.create_or_merge(&org_asset).await {
                                Ok(a) => Some(a.id),
                                Err(e) => {
                                    tracing::warn!("Failed to create organization asset {}: {}", org_trimmed, e);
                                    None
                                }
                            };
                            
                            // Increment org pivot count for this domain
                            *context.orgs_per_domain.entry(domain_value.clone()).or_insert(0) += 1;
                            org_queue.push_back((org_trimmed.to_string(), org_id, depth + 1));
                        }
                    }
                }
            } else if let Some((org_value, parent_id, depth)) = org_queue.pop_front() {
                if !visited_orgs.insert(org_value.clone()) { continue; }

                // Update context depth
                context.depth = depth;
                
                tracing::debug!("Processing organization '{}' at depth {} (from org recursion)", org_value, depth);

                // Double-check filtering
                if self.should_filter_organization(&org_value) {
                    tracing::debug!("Skipping filtered organization: {}", org_value);
                    continue;
                }

                let result = self.discover_from_organization(&org_value, seed_id, parent_id).await?;

                // Update asset count
                context.total_assets += result.assets.len();

                let mut domains_added = 0u32;
                for asset in &result.assets {
                    // Check if we should trigger a scan
                    if let Some(threshold) = confidence_threshold {
                        if asset.confidence >= threshold {
                            // Only scan domains and IPs
                            if matches!(asset.asset_type, AssetType::Domain | AssetType::Ip) {
                                let scan_create = ScanCreate {
                                    target: asset.identifier.clone(),
                                    note: Some(format!("Auto-scan triggered by discovery (confidence: {:.2})", asset.confidence)),
                                };
                                
                                match self.scan_service.create_scan(scan_create).await {
                                    Ok(scan) => tracing::info!("Triggered auto-scan {} for discovered asset {}", scan.id, asset.identifier),
                                    Err(e) => tracing::warn!("Failed to trigger auto-scan for {}: {}", asset.identifier, e),
                                }
                            }
                        }
                    }

                    if asset.asset_type == AssetType::Domain {
                        let domain = asset.identifier.clone();
                        let mut top_domain = String::new();

                        let parts: Vec<&str> = domain.split('.').collect();

                        if parts.len() >= 2 {
                            top_domain.push_str(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]).as_str());
                        }else{
                            top_domain.push_str(domain.as_str());
                        }
                        
                        // Check if we can add more domain pivots from this org
                        if !self.can_add_domain_pivot(&context, &org_value) {
                            tracing::debug!("Skipping domain '{}': max domains per org reached for '{}'", top_domain, org_value);
                            continue;
                        }
                        
                        // Check confidence threshold
                        if asset.confidence < self.settings.min_pivot_confidence {
                            tracing::debug!(
                                "Skipping low confidence domain '{}' (confidence: {:.2}, threshold: {:.2})",
                                top_domain, asset.confidence, self.settings.min_pivot_confidence
                            );
                            continue;
                        }
                        
                        if !visited_domains.contains(&top_domain) && !domain_queue.iter().any(|(d, _, _)| d == &top_domain) {
                            tracing::info!("New top domain found from org '{}': {} (depth {})", org_value, top_domain, depth + 1);
                            domain_queue.push_back((top_domain, parent_id, depth + 1));
                            domains_added += 1;
                        }
                    }
                    all_assets.push(asset.clone());
                }
                
                // Update domain pivot count for this org
                if domains_added > 0 {
                    *context.domains_per_org.entry(org_value.clone()).or_insert(0) += domains_added;
                }
                for (k, v) in result.confidence_scores {
                    match all_confidence.get_mut(&k) {
                        Some(existing) => { if v > *existing { *existing = v; } }
                        None => { all_confidence.insert(k, v); }
                    }
                }
                for (k, mut v) in result.sources {
                    all_sources.entry(k).and_modify(|existing| {
                        for src in &v { if !existing.contains(src) { existing.push(src.clone()); } }
                    }).or_insert_with(|| { v.sort(); v.dedup(); v });
                }
            } else {
                break;
            }
        }

        Ok(DiscoveryResult { assets: all_assets, confidence_scores: all_confidence, sources: all_sources })
    }

    /// Discover assets from a domain seed
    async fn discover_from_domain(&self, domain: &str, seed_id: Option<Uuid>, parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut assets: Vec<Asset> = Vec::new();
        let mut confidence_scores = HashMap::new();
        let mut sources = HashMap::new();

        // Step 1: Get comprehensive Shodan data first (extracts IPs, domains, ASNs, orgs, certs)
        let mut shodan_extracted = ShodanExtractedAssets::default();
        match self.external_services.get_shodan_comprehensive_data(domain).await {
            Ok(extracted) => {
                tracing::info!(
                    "Comprehensive Shodan extraction for {}: {} domains, {} IPs, {} ASNs, {} orgs, {} certs",
                    domain, extracted.domains.len(), extracted.ips.len(), 
                    extracted.asns.len(), extracted.organizations.len(), extracted.certificates.len()
                );
                shodan_extracted = extracted;
            }
            Err(e) => {
                tracing::debug!("Shodan comprehensive extraction not available for {}: {}", domain, e);
            }
        }

        // Step 2: Subdomain enumeration (includes Shodan + all other sources)
        match self.external_services.enumerate_subdomains(domain).await {
            Ok(subdomain_result) => {
                for subdomain in &subdomain_result.subdomains {
                    let confidence = self.calculate_domain_confidence(subdomain, domain, &subdomain_result.sources);
                    
                    // Prevent self-referencing cycles if the subdomain is the same as the search domain
                    // If we pass the domain's own ID as parent_id (which happens during recursive discovery),
                    // we must not assign it to the domain itself. Passing None to create_or_merge preserves existing parent.
                    let effective_parent_id = if subdomain == domain {
                        None
                    } else {
                        parent_id
                    };

                    let asset_create = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: subdomain.clone(),
                        confidence,
                        sources: json!(subdomain_result.sources.keys().collect::<Vec<_>>()),
                        metadata: json!({
                            "parent_domain": domain,
                            "discovery_method": "subdomain_enumeration",
                            "sources": subdomain_result.sources
                        }),
                        seed_id,
                        parent_id: effective_parent_id,
                    };
                    
                    match self.asset_repo.create_or_merge(&asset_create).await {
                        Ok(asset) => {
                            confidence_scores.insert(subdomain.clone(), confidence);
                            sources.insert(subdomain.clone(), subdomain_result.sources.keys().cloned().collect());
                            assets.push(asset);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to store subdomain {}: {}", subdomain, e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Subdomain enumeration failed for {}: {}", domain, e);
            }
        }

        // Step 3: Process IPs extracted from Shodan
        for ip in &shodan_extracted.ips {
            // Calculate confidence using the confidence scorer
            let confidence = {
                let factors = ConfidenceFactors {
                    base_confidence: MethodConfidence::SHODAN_ASN.base,
                    sources: vec!["shodan".to_string()],
                    distance_from_seed: 1,
                    ..Default::default()
                };
                self.confidence_scorer.calculate_confidence(&factors)
            };
            let asset_create = AssetCreate {
                asset_type: AssetType::Ip,
                identifier: ip.clone(),
                confidence,
                sources: json!(["shodan"]),
                metadata: json!({
                    "discovered_from": domain,
                    "discovery_method": "shodan_comprehensive",
                    "source": "shodan_domain_search"
                }),
                seed_id,
                parent_id,
            };
            
            match self.asset_repo.create_or_merge(&asset_create).await {
                Ok(asset) => {
                    confidence_scores.insert(ip.clone(), confidence);
                    sources.insert(ip.clone(), vec!["shodan".to_string()]);
                    assets.push(asset);
                }
                Err(e) => {
                    tracing::warn!("Failed to store Shodan IP {}: {}", ip, e);
                }
            }
        }

        // Step 4: Process certificates extracted from Shodan
        for cert in &shodan_extracted.certificates {
            if let Some(ref org) = cert.organization {
                let confidence = self.confidence_scorer.calculate_certificate_confidence(true, vec!["shodan".to_string()]);
                let cert_asset = AssetCreate {
                    asset_type: AssetType::Certificate,
                    identifier: cert.subject.clone(),
                    confidence,
                    sources: json!(["shodan"]),
                    metadata: json!({
                        "organization": org,
                        "issuer": cert.issuer,
                        "san_domains": cert.domains,
                        "discovered_from": domain,
                        "discovery_method": "shodan_comprehensive"
                    }),
                    seed_id,
                    parent_id,
                };
                
                match self.asset_repo.create_or_merge(&cert_asset).await {
                    Ok(asset) => {
                        confidence_scores.insert(cert.subject.clone(), confidence);
                        sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
                        assets.push(asset);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to store certificate {}: {}", cert.subject, e);
                    }
                }
            }
        }

        // Step 5: DNS resolution for discovered domains
        // We use the assets we just saved (which have IDs) to link the IPs
        let domain_assets: Vec<_> = assets.iter()
            .filter(|asset| asset.asset_type == AssetType::Domain)
            .cloned()
            .collect();
            
        for asset in domain_assets {
            match self.dns_resolver.resolve_hostname(&asset.identifier).await {
                Ok(ips) => {
                    for ip in ips {
                        let ip_confidence = self.calculate_ip_confidence(&ip.to_string(), &asset.identifier);
                        let ip_asset = AssetCreate {
                            asset_type: AssetType::Ip,
                            identifier: ip.to_string(),
                            confidence: ip_confidence,
                            sources: json!(["dns_resolution"]),
                            metadata: json!({
                                "resolved_from": asset.identifier,
                                "discovery_method": "dns_resolution"
                            }),
                            seed_id,
                            parent_id: Some(asset.id), // Link to the domain asset!
                        };
                        
                        match self.asset_repo.create_or_merge(&ip_asset).await {
                            Ok(saved_ip) => {
                                confidence_scores.insert(ip.to_string(), ip_confidence);
                                sources.insert(ip.to_string(), vec!["dns_resolution".to_string()]);
                                assets.push(saved_ip);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to store resolved IP {}: {}", ip, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("DNS resolution failed for {}: {}", asset.identifier, e);
                }
            }
        }

        // Step 6: Certificate analysis for HTTPS domains
        let domain_assets_for_certs: Vec<_> = assets.iter()
            .filter(|asset| asset.asset_type == AssetType::Domain)
            .cloned()
            .collect();
            
        for asset in domain_assets_for_certs {
            match self.http_analyzer.get_tls_certificate_info(&asset.identifier, 443).await {
                Ok(cert_result) => {
                    if !cert_result.certificate_chain.is_empty() {
                        let cert_info = &cert_result.certificate_chain[0];
                        
                        // Create certificate asset
                        if let Some(org) = &cert_info.organization {
                            let cert_confidence = self.calculate_certificate_confidence(org, domain);
                            let cert_asset = AssetCreate {
                                asset_type: AssetType::Certificate,
                                identifier: cert_info.subject.clone(),
                                confidence: cert_confidence,
                                sources: json!(["tls_certificate"]),
                                metadata: json!({
                                    "organization": org,
                                    "issuer": cert_info.issuer,
                                    "san_domains": cert_info.san_domains,
                                    "discovered_from": asset.identifier,
                                    "discovery_method": "tls_certificate"
                                }),
                                seed_id,
                                parent_id: Some(asset.id), // Link to the domain asset
                            };
                            
                            match self.asset_repo.create_or_merge(&cert_asset).await {
                                Ok(saved_cert) => {
                                    confidence_scores.insert(cert_info.subject.clone(), cert_confidence);
                                    sources.insert(cert_info.subject.clone(), vec!["tls_certificate".to_string()]);
                                    assets.push(saved_cert);
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to store certificate from TLS {}: {}", cert_info.subject, e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Certificate analysis failed for {}: {}", asset.identifier, e);
                }
            }
        }

        Ok(DiscoveryResult {
            assets,
            confidence_scores,
            sources,
        })
    }

    /// Discover assets from an organization seed
    /// Uses comprehensive Shodan extraction for ALL asset types, then queries crt.sh for additional domains
    /// Discover assets from an organization seed
    /// Uses comprehensive Shodan extraction for ALL asset types, then queries crt.sh for additional domains
    async fn discover_from_organization(&self, org: &str, seed_id: Option<Uuid>, parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut assets: Vec<Asset> = Vec::new();
        let mut confidence_scores = HashMap::new();
        let mut sources = HashMap::new();

        // PRIORITY 1: Comprehensive Shodan search - extracts IPs, domains, ASNs, certs, etc.
        tracing::info!("Searching organization '{}' using Shodan (PRIMARY - Comprehensive)", org);
        match self.external_services.search_shodan_org_comprehensive(org).await {
            Ok(extracted) => {
                tracing::info!(
                    "✓ Shodan comprehensive extraction for '{}': {} IPs, {} domains, {} ASNs, {} orgs, {} certs",
                    org, extracted.ips.len(), extracted.domains.len(), 
                    extracted.asns.len(), extracted.organizations.len(), extracted.certificates.len()
                );
                
                // Process IPs
                for ip in &extracted.ips {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::SHODAN_ORG.base,
                            sources: vec!["shodan".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let asset_create = AssetCreate {
                        asset_type: AssetType::Ip,
                        identifier: ip.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "organization": org,
                            "discovery_method": "shodan_org_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&asset_create).await {
                        Ok(asset) => {
                            confidence_scores.insert(ip.clone(), confidence);
                            sources.insert(ip.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                        }
                        Err(e) => tracing::warn!("Failed to store IP {}: {}", ip, e),
                    }
                }
                
                // Process domains found in Shodan
                for domain in &extracted.domains {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::SUBDOMAIN_ENUM.base,
                            sources: vec!["shodan".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let asset_create = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "organization": org,
                            "discovery_method": "shodan_org_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&asset_create).await {
                        Ok(asset) => {
                            confidence_scores.insert(domain.clone(), confidence);
                            sources.insert(domain.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                        }
                        Err(e) => tracing::warn!("Failed to store domain {}: {}", domain, e),
                    }
                }
                
                // Process certificates
                for cert in &extracted.certificates {
                    if let Some(ref cert_org) = cert.organization {
                        let confidence = self.confidence_scorer.calculate_certificate_confidence(true, vec!["shodan".to_string()]);
                        let cert_asset = AssetCreate {
                            asset_type: AssetType::Certificate,
                            identifier: cert.subject.clone(),
                            confidence,
                            sources: json!(["shodan"]),
                            metadata: json!({
                                "organization": cert_org,
                                "issuer": cert.issuer,
                                "san_domains": cert.domains,
                                "discovered_from": org,
                                "discovery_method": "shodan_org_comprehensive"
                            }),
                            seed_id,
                            parent_id,
                        };
                        match self.asset_repo.create_or_merge(&cert_asset).await {
                            Ok(asset) => {
                                confidence_scores.insert(cert.subject.clone(), confidence);
                                sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
                                assets.push(asset);
                            }
                            Err(e) => tracing::warn!("Failed to store cert {}: {}", cert.subject, e),
                        }
                    }
                }
                
                // Log discovered ASNs for potential recursive discovery
                if !extracted.asns.is_empty() {
                    tracing::info!("Discovered ASNs from organization '{}': {:?} (available for recursive discovery)", 
                        org, extracted.asns);
                }
                
                // Log discovered related organizations
                if !extracted.organizations.is_empty() {
                    tracing::info!("Discovered related organizations: {:?} (available for recursive discovery)", 
                        extracted.organizations);
                }
            }
            Err(e) => {
                tracing::warn!("Shodan comprehensive organization search failed for {}: {}", org, e);
            }
        }

        // ALWAYS query crt.sh for additional domain coverage
        tracing::info!("Searching organization '{}' using crt.sh for additional domain coverage", org);
        match self.external_services.search_crtsh_by_organization(org).await {
            Ok(domains) => {
                tracing::info!("Found {} domains from crt.sh for organization '{}'", domains.len(), org);
                for domain in domains {
                    let confidence = self.calculate_crtsh_org_confidence(&domain, org);

                    let asset_create = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["crt.sh"]),
                        metadata: json!({
                            "organization": org,
                            "discovery_method": "crtsh_org_search"
                        }),
                        seed_id,
                        parent_id,
                    };

                    match self.asset_repo.create_or_merge(&asset_create).await {
                        Ok(asset) => {
                            confidence_scores.insert(domain.clone(), confidence);
                            sources.insert(domain, vec!["crt.sh".to_string()]);
                            assets.push(asset);
                        }
                        Err(e) => tracing::warn!("Failed to store domain from crt.sh {}: {}", domain, e),
                    }
                }
            }
            Err(e) => {
                tracing::warn!("crt.sh organization search failed for {}: {}", org, e);
            }
        }

        tracing::info!(
            "Organization discovery complete for '{}': {} total assets found (IPs + Domains + Certificates)",
            org,
            assets.len()
        );

        Ok(DiscoveryResult {
            assets,
            confidence_scores,
            sources,
        })
    }

    /// Discover assets from an ASN seed
    /// Uses comprehensive Shodan extraction to find ALL asset types associated with the ASN
    /// Discover assets from an ASN seed
    /// Uses comprehensive Shodan extraction to find ALL asset types associated with the ASN
    async fn discover_from_asn(&self, asn: &str, seed_id: Option<Uuid>, parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut assets: Vec<Asset> = Vec::new();
        let mut confidence_scores = HashMap::new();
        let mut sources = HashMap::new();

        // Use comprehensive Shodan search for ASN
        tracing::info!("Searching ASN '{}' using Shodan (Comprehensive)", asn);
        match self.external_services.search_shodan_asn_comprehensive(asn).await {
            Ok(extracted) => {
                tracing::info!(
                    "✓ Shodan comprehensive extraction for ASN '{}': {} IPs, {} domains, {} orgs, {} certs",
                    asn, extracted.ips.len(), extracted.domains.len(), 
                    extracted.organizations.len(), extracted.certificates.len()
                );
                
                // Process IPs
                for ip in &extracted.ips {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::SHODAN_ASN.base,
                            sources: vec!["shodan".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let asset_create = AssetCreate {
                        asset_type: AssetType::Ip,
                        identifier: ip.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "asn": asn,
                            "discovery_method": "shodan_asn_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&asset_create).await {
                         Ok(asset) => {
                            confidence_scores.insert(ip.clone(), confidence);
                            sources.insert(ip.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                         },
                         Err(e) => tracing::warn!("Failed to store IP {}: {}", ip, e),
                    }
                }
                
                // Process domains
                for domain in &extracted.domains {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::SHODAN_ORG.base,
                            sources: vec!["shodan".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let asset_create = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "asn": asn,
                            "discovery_method": "shodan_asn_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&asset_create).await {
                         Ok(asset) => {
                            confidence_scores.insert(domain.clone(), confidence);
                            sources.insert(domain.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                         },
                         Err(e) => tracing::warn!("Failed to store domain {}: {}", domain, e),
                    }
                }
                
                // Process certificates
                for cert in &extracted.certificates {
                    let has_org = cert.organization.is_some();
                    let confidence = self.confidence_scorer.calculate_certificate_confidence(has_org, vec!["shodan".to_string()]);
                    let cert_asset = AssetCreate {
                        asset_type: AssetType::Certificate,
                        identifier: cert.subject.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "asn": asn,
                            "organization": cert.organization,
                            "issuer": cert.issuer,
                            "san_domains": cert.domains,
                            "discovery_method": "shodan_asn_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&cert_asset).await {
                         Ok(asset) => {
                            confidence_scores.insert(cert.subject.clone(), confidence);
                            sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                         },
                         Err(e) => tracing::warn!("Failed to store cert {}: {}", cert.subject, e),
                    }
                }
                
                // Log discovered organizations for potential recursive discovery
                if !extracted.organizations.is_empty() {
                    tracing::info!("Discovered organizations from ASN '{}': {:?} (available for recursive discovery)", 
                        asn, extracted.organizations);
                }
            }
            Err(e) => {
                tracing::warn!("Shodan comprehensive ASN search failed for {}: {}", asn, e);
            }
        }

        Ok(DiscoveryResult {
            assets,
            confidence_scores,
            sources,
        })
    }

    /// Discover assets from a CIDR seed
    async fn discover_from_cidr(&self, cidr: &str, seed_id: Option<Uuid>, parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut assets: Vec<Asset> = Vec::new();
        let mut confidence_scores = HashMap::new();
        let mut sources = HashMap::new();

        // Expand CIDR range
        let ips = expand_cidr(cidr)?;
        let max_hosts = self.settings.max_cidr_hosts as usize;
        
        if ips.len() > max_hosts {
            return Err(ApiError::Validation(format!(
                "CIDR range {} contains {} hosts, exceeding limit of {}",
                cidr, ips.len(), max_hosts
            )));
        }

        // Create IP assets for CIDR range
        for ip in ips {
            let confidence = {
                let factors = ConfidenceFactors {
                    base_confidence: MethodConfidence::CIDR_EXPANSION.base,
                    sources: vec!["cidr_expansion".to_string()],
                    distance_from_seed: 1,
                    ..Default::default()
                };
                self.confidence_scorer.calculate_confidence(&factors)
            };
            
            let asset_create = AssetCreate {
                asset_type: AssetType::Ip,
                identifier: ip.to_string(),
                confidence,
                sources: json!(["cidr_expansion"]),
                metadata: json!({
                    "cidr": cidr,
                    "discovery_method": "cidr_expansion"
                }),
                seed_id,
                parent_id,
            };
            
            match self.asset_repo.create_or_merge(&asset_create).await {
                 Ok(asset) => {
                    confidence_scores.insert(ip.to_string(), confidence);
                    sources.insert(ip.to_string(), vec!["cidr_expansion".to_string()]);
                    assets.push(asset);
                 },
                 Err(e) => tracing::warn!("Failed to store IP {}: {}", ip, e),
            }
        }

        Ok(DiscoveryResult {
            assets,
            confidence_scores,
            sources,
        })
    }

    /// Discover assets from a keyword seed
    /// Uses comprehensive Shodan extraction to find ALL asset types matching the keyword
    /// Discover assets from a keyword seed
    /// Uses comprehensive Shodan extraction to find ALL asset types matching the keyword
    async fn discover_from_keyword(&self, keyword: &str, seed_id: Option<Uuid>, parent_id: Option<Uuid>) -> Result<DiscoveryResult, ApiError> {
        let mut assets: Vec<Asset> = Vec::new();
        let mut confidence_scores = HashMap::new();
        let mut sources = HashMap::new();

        // Use comprehensive Shodan search for keyword
        tracing::info!("Searching keyword '{}' using Shodan (Comprehensive)", keyword);
        match self.external_services.search_shodan_comprehensive(keyword).await {
            Ok(extracted) => {
                tracing::info!(
                    "✓ Shodan comprehensive extraction for keyword '{}': {} IPs, {} domains, {} ASNs, {} orgs, {} certs",
                    keyword, extracted.ips.len(), extracted.domains.len(), 
                    extracted.asns.len(), extracted.organizations.len(), extracted.certificates.len()
                );
                
                // Process IPs
                for ip in &extracted.ips {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::KEYWORD_SEARCH.base,
                            sources: vec!["shodan".to_string(), "keyword_search".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let asset_create = AssetCreate {
                        asset_type: AssetType::Ip,
                        identifier: ip.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "keyword": keyword,
                            "discovery_method": "shodan_keyword_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&asset_create).await {
                         Ok(asset) => {
                            confidence_scores.insert(ip.clone(), confidence);
                            sources.insert(ip.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                         },
                         Err(e) => tracing::warn!("Failed to store IP {}: {}", ip, e),
                    }
                }
                
                // Process domains
                for domain in &extracted.domains {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::KEYWORD_SEARCH.base,
                            sources: vec!["shodan".to_string(), "keyword_search".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let asset_create = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "keyword": keyword,
                            "discovery_method": "shodan_keyword_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&asset_create).await {
                         Ok(asset) => {
                            confidence_scores.insert(domain.clone(), confidence);
                            sources.insert(domain.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                         },
                         Err(e) => tracing::warn!("Failed to store domain {}: {}", domain, e),
                    }
                }
                
                // Process certificates
                for cert in &extracted.certificates {
                    let confidence = {
                        let factors = ConfidenceFactors {
                            base_confidence: MethodConfidence::KEYWORD_SEARCH.base,
                            sources: vec!["shodan".to_string(), "keyword_search".to_string()],
                            distance_from_seed: 1,
                            ..Default::default()
                        };
                        self.confidence_scorer.calculate_confidence(&factors)
                    };
                    let cert_asset = AssetCreate {
                        asset_type: AssetType::Certificate,
                        identifier: cert.subject.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "keyword": keyword,
                            "organization": cert.organization,
                            "issuer": cert.issuer,
                            "san_domains": cert.domains,
                            "discovery_method": "shodan_keyword_comprehensive"
                        }),
                        seed_id,
                        parent_id,
                    };
                    match self.asset_repo.create_or_merge(&cert_asset).await {
                         Ok(asset) => {
                            confidence_scores.insert(cert.subject.clone(), confidence);
                            sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
                            assets.push(asset);
                         },
                         Err(e) => tracing::warn!("Failed to store cert {}: {}", cert.subject, e),
                    }
                }
                
                // Log discovered ASNs and organizations for potential recursive discovery
                if !extracted.asns.is_empty() {
                    tracing::info!("Discovered ASNs from keyword '{}': {:?}", keyword, extracted.asns);
                }
                if !extracted.organizations.is_empty() {
                    tracing::info!("Discovered organizations from keyword '{}': {:?}", keyword, extracted.organizations);
                }
            }
            Err(e) => {
                tracing::warn!("Shodan comprehensive keyword search failed for {}: {}", keyword, e);
            }
        }

        Ok(DiscoveryResult {
            assets,
            confidence_scores,
            sources,
        })
    }

    // Confidence scoring algorithms using the new confidence scorer
    fn calculate_domain_confidence(&self, domain: &str, parent_domain: &str, sources: &HashMap<String, Vec<String>>) -> f64 {
        self.confidence_scorer.calculate_domain_confidence(domain, parent_domain, sources)
    }

    fn calculate_ip_confidence(&self, _ip: &str, _resolved_from: &str) -> f64 {
        self.confidence_scorer.calculate_ip_confidence(vec!["dns_resolution".to_string()])
    }

    fn calculate_certificate_confidence(&self, org: &str, _domain: &str) -> f64 {
        let has_org = !org.is_empty();
        self.confidence_scorer.calculate_certificate_confidence(has_org, vec!["tls_certificate".to_string()])
    }

    fn calculate_crtsh_org_confidence(&self, _domain: &str, _organization: &str) -> f64 {
        // crt.sh organization search has medium confidence
        let factors = ConfidenceFactors {
            base_confidence: MethodConfidence::CRTSH_ORG.base,
            sources: vec!["crt.sh".to_string(), "org_search".to_string()],
            ..Default::default()
        };
        self.confidence_scorer.calculate_confidence(&factors)
    }

    /// Validate seed based on its type
    fn validate_seed(&self, seed: &SeedCreate) -> Result<(), ApiError> {
        match seed.seed_type {
            SeedType::Domain => {
                if seed.value.is_empty() || !seed.value.contains('.') {
                    return Err(ApiError::Validation("Invalid domain format".to_string()));
                }
            }
            SeedType::Asn => {
                if !seed.value.starts_with("AS") && seed.value.parse::<u32>().is_err() {
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
                    return Err(ApiError::Validation("Organization name cannot be empty".to_string()));
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
}

// Implement Clone for DiscoveryService to enable Arc sharing in background tasks
impl Clone for DiscoveryService {
    fn clone(&self) -> Self {
        Self {
            asset_repo: Arc::clone(&self.asset_repo),
            seed_repo: Arc::clone(&self.seed_repo),
            external_services: Arc::clone(&self.external_services),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_analyzer: Arc::clone(&self.http_analyzer),
            task_manager: Arc::clone(&self.task_manager),
            settings: Arc::clone(&self.settings),
            discovery_status: Arc::clone(&self.discovery_status),
            scan_service: Arc::clone(&self.scan_service),
            confidence_scorer: Arc::clone(&self.confidence_scorer),
        }
    }
}
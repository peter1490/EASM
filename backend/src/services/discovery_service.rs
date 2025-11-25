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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use uuid::Uuid;
use serde_json::json;
use chrono::Utc;

use crate::{
    config::Settings,
    error::ApiError,
    models::{
        Asset, AssetCreate, AssetType, Seed, SeedCreate, SeedType,
        DiscoveryRun, DiscoveryRunCreate, DiscoveryConfig, DiscoveryResult,
        DiscoveryQueueItemCreate, QueueItemType, QueueItemStatus,
        AssetSourceCreate, SourceType, AssetRelationshipCreate, RelationshipType,
        TriggerType,
    },
    repositories::{
        AssetRepository, SeedRepository,
        DiscoveryRunRepository, DiscoveryQueueRepository,
        AssetSourceRepository, AssetRelationshipRepository,
    },
    services::{
        external::{
            ExternalServicesManager, DnsResolver, HttpAnalyzer, ShodanExtractedAssets
        },
        task_manager::{TaskManager, TaskType, TaskContext},
        confidence::{ConfidenceScorer, ConfidenceFactors, MethodConfidence},
    },
    utils::network::expand_cidr,
};

/// Common CDN, cloud provider, and hosting organizations to filter
static COMMON_INFRASTRUCTURE_ORGS: &[&str] = &[
    "cloudflare", "akamai", "fastly", "cloudfront", "amazon cloudfront",
    "stackpath", "keycdn", "bunnycdn", "maxcdn",
    "amazon", "aws", "google", "google cloud", "microsoft", "azure",
    "digitalocean", "linode", "vultr", "ovh", "hetzner", "scaleway",
    "godaddy", "namecheap", "bluehost", "hostgator", "dreamhost",
    "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
    "incapsula", "imperva", "sucuri", "wordfence", "barracuda",
    "domain administrator", "domain admin", "privacy", "whois privacy",
    "contact privacy", "private", "registration private", "proxy",
    "inc", "llc", "ltd", "corporation", "corp", "company", "co.",
];

/// Discovery run status tracking (in-memory for real-time updates)
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryStatus {
    pub is_running: bool,
    pub run_id: Option<Uuid>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub current_phase: String,
    pub seeds_total: usize,
    pub seeds_processed: usize,
    pub assets_discovered: usize,
    pub assets_updated: usize,
    pub queue_pending: usize,
    pub errors: Vec<String>,
}

pub struct DiscoveryService {
    // Repositories
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    seed_repo: Arc<dyn SeedRepository + Send + Sync>,
    discovery_run_repo: Arc<dyn DiscoveryRunRepository + Send + Sync>,
    discovery_queue_repo: Arc<dyn DiscoveryQueueRepository + Send + Sync>,
    asset_source_repo: Arc<dyn AssetSourceRepository + Send + Sync>,
    asset_relationship_repo: Arc<dyn AssetRelationshipRepository + Send + Sync>,
    
    // External services
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_analyzer: Arc<HttpAnalyzer>,
    
    // Utilities
    task_manager: Arc<TaskManager>,
    settings: Arc<Settings>,
    confidence_scorer: Arc<ConfidenceScorer>,
    
    // State
    status: Arc<Mutex<DiscoveryStatus>>,
}

impl DiscoveryService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        seed_repo: Arc<dyn SeedRepository + Send + Sync>,
        discovery_run_repo: Arc<dyn DiscoveryRunRepository + Send + Sync>,
        discovery_queue_repo: Arc<dyn DiscoveryQueueRepository + Send + Sync>,
        asset_source_repo: Arc<dyn AssetSourceRepository + Send + Sync>,
        asset_relationship_repo: Arc<dyn AssetRelationshipRepository + Send + Sync>,
        external_services: Arc<ExternalServicesManager>,
        dns_resolver: Arc<DnsResolver>,
        http_analyzer: Arc<HttpAnalyzer>,
        task_manager: Arc<TaskManager>,
        settings: Arc<Settings>,
    ) -> Self {
        Self {
            asset_repo,
            seed_repo,
            discovery_run_repo,
            discovery_queue_repo,
            asset_source_repo,
            asset_relationship_repo,
            external_services,
            dns_resolver,
            http_analyzer,
            task_manager,
            settings,
            confidence_scorer: Arc::new(ConfidenceScorer::new()),
            status: Arc::new(Mutex::new(DiscoveryStatus::default())),
        }
    }

    // ========================================================================
    // SEED MANAGEMENT
    // ========================================================================

    pub async fn create_seed(&self, seed_create: SeedCreate) -> Result<Seed, ApiError> {
        self.validate_seed(&seed_create)?;
        self.seed_repo.create(&seed_create).await
    }

    pub async fn list_seeds(&self) -> Result<Vec<Seed>, ApiError> {
        self.seed_repo.list().await
    }

    pub async fn delete_seed(&self, id: &Uuid) -> Result<(), ApiError> {
        self.seed_repo.delete(*id).await
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

    // ========================================================================
    // ASSET MANAGEMENT
    // ========================================================================

    pub async fn list_assets(
        &self,
        confidence_threshold: Option<f64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Asset>, ApiError> {
        self.asset_repo.list(confidence_threshold, limit, offset).await
    }

    pub async fn count_assets(&self, confidence_threshold: Option<f64>) -> Result<i64, ApiError> {
        self.asset_repo.count(confidence_threshold).await
    }

    pub async fn get_asset(&self, id: &Uuid) -> Result<Option<Asset>, ApiError> {
        self.asset_repo.get_by_id(id).await
    }

    pub async fn get_asset_path(&self, id: &Uuid) -> Result<Vec<Asset>, ApiError> {
        self.asset_repo.get_path(id).await
    }

    // ========================================================================
    // DISCOVERY RUN MANAGEMENT
    // ========================================================================

    pub async fn get_discovery_status(&self) -> DiscoveryStatus {
        self.status.lock().await.clone()
    }

    pub async fn get_discovery_run(&self, id: &Uuid) -> Result<Option<DiscoveryRun>, ApiError> {
        self.discovery_run_repo.get_by_id(id).await
    }

    pub async fn list_discovery_runs(&self, limit: i64, offset: i64) -> Result<Vec<DiscoveryRun>, ApiError> {
        self.discovery_run_repo.list(limit, offset).await
    }

    /// Start a new discovery run
    pub async fn run_discovery(&self, config: Option<DiscoveryConfig>) -> Result<DiscoveryRun, ApiError> {
        // Check if discovery is already running
        {
            let status = self.status.lock().await;
            if status.is_running {
                return Err(ApiError::Validation("Discovery is already running".to_string()));
            }
        }

        // Create a new discovery run
        let run_create = DiscoveryRunCreate {
            trigger_type: Some(TriggerType::Manual),
            config: config.as_ref().map(|c| serde_json::to_value(c).unwrap_or(json!({}))),
        };
        
        let run = self.discovery_run_repo.create(&run_create).await?;
        let run_id = run.id;

        // Update status
        {
            let mut status = self.status.lock().await;
            status.is_running = true;
            status.run_id = Some(run_id);
            status.started_at = Some(Utc::now());
            status.current_phase = "Initializing".to_string();
            status.errors.clear();
        }

        // Submit discovery task to TaskManager
        let discovery_service = self.clone();
        let config_arc = Arc::new(config);
        
        let task_metadata = json!({
            "discovery_run_id": run_id,
            "started_at": Utc::now()
        });
        
        self.task_manager.submit_task(
            TaskType::Discovery,
            task_metadata,
            move |ctx| {
                let discovery_service = discovery_service.clone();
                let config_clone = (*config_arc).clone();
                Box::pin(async move {
                    discovery_service.execute_discovery(ctx, run_id, config_clone).await
                })
            }
        ).await?;

        Ok(run)
    }

    /// Stop the running discovery
    pub async fn stop_discovery(&self) -> Result<(), ApiError> {
        let run_id = {
            let status = self.status.lock().await;
            if !status.is_running {
                return Err(ApiError::Validation("Discovery is not running".to_string()));
            }
            status.run_id
        };

        if let Some(id) = run_id {
            // Mark run as cancelled
            self.discovery_run_repo.update_status(&id, "cancelled", Some("Stopped by user")).await?;
            
            // Update status
            let mut status = self.status.lock().await;
            status.is_running = false;
            status.completed_at = Some(Utc::now());
            status.current_phase = "Cancelled".to_string();
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
        config: Option<DiscoveryConfig>
    ) -> Result<(), ApiError> {
        tracing::info!("Starting discovery run {}", run_id);
        
        // Mark run as started
        self.discovery_run_repo.start(&run_id).await?;
        
        let result = self.execute_discovery_internal(&ctx, run_id, config).await;
        
        // Finalize discovery run
        {
            let mut status = self.status.lock().await;
            status.is_running = false;
            status.completed_at = Some(Utc::now());
            
            match &result {
                Ok(_) => {
                    status.current_phase = "Completed".to_string();
                    self.discovery_run_repo.complete(&run_id).await?;
                }
                Err(e) => {
                    status.current_phase = "Failed".to_string();
                    status.errors.push(e.to_string());
                    self.discovery_run_repo.fail(&run_id, &e.to_string()).await?;
                }
            }
        }
        
        result
    }

    async fn execute_discovery_internal(
        &self, 
        ctx: &TaskContext, 
        run_id: Uuid, 
        config: Option<DiscoveryConfig>
    ) -> Result<(), ApiError> {
        // Load seeds
        let seeds = self.seed_repo.list().await?;
        let seed_count = seeds.len();
        
        {
            let mut status = self.status.lock().await;
            status.seeds_total = seed_count;
            status.current_phase = "Loading seeds".to_string();
        }
        
        ctx.update_progress(0.05, Some(format!("Found {} seeds", seed_count))).await?;

        if seeds.is_empty() {
            tracing::info!("No seeds to process");
            return Ok(());
        }

        // Phase 1: Queue all seeds for processing
        {
            let mut status = self.status.lock().await;
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
            
            let item = DiscoveryQueueItemCreate {
                discovery_run_id: run_id,
                item_type,
                item_value: seed.value.clone(),
                parent_asset_id: None,
                seed_id: Some(seed.id),
                depth: 0,
                priority: 10, // Seeds have highest priority
            };
            
            self.discovery_queue_repo.enqueue(&item).await?;
        }

        ctx.update_progress(0.1, Some("Seeds queued".to_string())).await?;

        // Phase 2: Process queue
        {
            let mut status = self.status.lock().await;
            status.current_phase = "Processing discovery queue".to_string();
        }

        let max_depth = config.as_ref()
            .and_then(|c| c.max_depth)
            .unwrap_or(self.settings.max_discovery_depth);

        let mut total_result = DiscoveryResult::default();
        let mut processed = 0;

        loop {
            ctx.check_cancellation().await?;

            // Get pending count
            let pending = self.discovery_queue_repo.get_pending_count(&run_id).await?;
            
            {
                let mut status = self.status.lock().await;
                status.queue_pending = pending as usize;
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
                let result = self.process_queue_item(
                    run_id,
                    &item.item_type,
                    &item.item_value,
                    item.seed_id,
                    item.parent_asset_id,
                    item.depth,
                ).await;

                match result {
                    Ok(item_result) => {
                        self.discovery_queue_repo.complete_item(&item.id).await?;
                        total_result.merge(item_result);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to process queue item {}: {}", item.item_value, e);
                        self.discovery_queue_repo.fail_item(&item.id, &e.to_string()).await?;
                        total_result.warnings.push(format!("{}: {}", item.item_value, e));
                    }
                }

                processed += 1;

                // Update progress
                let progress = 0.1 + (0.8 * (processed as f32 / (processed + pending as usize) as f32));
                ctx.update_progress(progress, Some(format!("Processed {} items", processed))).await?;

                // Update status
                {
                    let mut status = self.status.lock().await;
                    status.seeds_processed = processed.min(seed_count);
                    status.assets_discovered = total_result.assets_created.len();
                    status.assets_updated = total_result.assets_updated.len();
                }
            }
        }

        // Update discovery run with final counts
        self.discovery_run_repo.update_progress(
            &run_id,
            seed_count as i32,
            total_result.assets_created.len() as i32,
            total_result.assets_updated.len() as i32,
        ).await?;

        ctx.update_progress(0.95, Some("Finalizing".to_string())).await?;

        tracing::info!(
            "Discovery run {} completed: {} seeds, {} new assets, {} updated",
            run_id, seed_count, total_result.assets_created.len(), total_result.assets_updated.len()
        );

        Ok(())
    }

    /// Process a single queue item
    async fn process_queue_item(
        &self,
        run_id: Uuid,
        item_type: &str,
        item_value: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        tracing::debug!("Processing {} '{}' at depth {}", item_type, item_value, depth);

        match item_type {
            "domain" => self.discover_from_domain(run_id, item_value, seed_id, parent_asset_id, depth).await,
            "organization" => self.discover_from_organization(run_id, item_value, seed_id, parent_asset_id, depth).await,
            "asn" => self.discover_from_asn(run_id, item_value, seed_id, parent_asset_id, depth).await,
            "cidr" => self.discover_from_cidr(run_id, item_value, seed_id, parent_asset_id, depth).await,
            "ip" => self.discover_from_ip(run_id, item_value, seed_id, parent_asset_id, depth).await,
            _ => {
                tracing::warn!("Unknown item type: {}", item_type);
                Ok(DiscoveryResult::default())
            }
        }
    }

    // ========================================================================
    // DISCOVERY BY TYPE
    // ========================================================================

    /// Discover assets from a domain
    async fn discover_from_domain(
        &self,
        run_id: Uuid,
        domain: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        // Create the domain asset first (if it's not from a seed)
        let domain_asset = self.create_or_update_asset(
            run_id,
            AssetType::Domain,
            domain,
            SourceType::Seed,
            1.0, // Full confidence for seed domains
            seed_id,
            parent_asset_id,
            Some(json!({ "discovery_depth": depth })),
        ).await?;

        if domain_asset.1 { // was created
            result.assets_created.push(domain_asset.0);
        } else {
            result.assets_updated.push(domain_asset.0);
        }

        let domain_asset_id = domain_asset.0;

        // Step 1: Subdomain enumeration from multiple sources
        match self.external_services.enumerate_subdomains(domain).await {
            Ok(subdomain_result) => {
                for subdomain in &subdomain_result.subdomains {
                    if subdomain == domain {
                        continue; // Skip the main domain
                    }

                    let confidence = self.calculate_subdomain_confidence(&subdomain_result.sources);
                    
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Domain,
                        subdomain,
                        SourceType::Shodan, // Primary source
                        confidence,
                        seed_id,
                        Some(domain_asset_id),
                        Some(json!({
                            "parent_domain": domain,
                            "sources": subdomain_result.sources.keys().collect::<Vec<_>>()
                        })),
                    ).await?;

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
                    ).await?;
                }
            }
            Err(e) => {
                result.warnings.push(format!("Subdomain enumeration failed: {}", e));
            }
        }

        // Step 2: DNS resolution
        match self.dns_resolver.resolve_hostname(domain).await {
            Ok(ips) => {
                for ip in ips {
                    let ip_str = ip.to_string();
                    let confidence = self.confidence_scorer.calculate_ip_confidence(vec!["dns_resolution".to_string()]);
                    
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Ip,
                        &ip_str,
                        SourceType::DnsResolution,
                        confidence,
                        seed_id,
                        Some(domain_asset_id),
                        Some(json!({ "resolved_from": domain })),
                    ).await?;

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
                    ).await?;
                }
            }
            Err(e) => {
                tracing::debug!("DNS resolution failed for {}: {}", domain, e);
            }
        }

        // Step 3: TLS Certificate analysis (for pivoting)
        match self.http_analyzer.get_tls_certificate_info(domain, 443).await {
            Ok(cert_result) => {
                if !cert_result.certificate_chain.is_empty() {
                    let cert_info = &cert_result.certificate_chain[0];
                    
                    let confidence = self.confidence_scorer.calculate_certificate_confidence(
                        cert_info.organization.is_some(),
                        vec!["tls_certificate".to_string()],
                    );

                    let cert_asset = self.create_or_update_asset(
                        run_id,
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
                    ).await?;

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
                    ).await?;

                    // Queue organization for discovery if found and depth allows
                    if let Some(ref org) = cert_info.organization {
                        if !self.should_filter_organization(org) && depth < self.settings.max_discovery_depth as i32 {
                            self.queue_for_discovery(
                                run_id,
                                QueueItemType::Organization,
                                org,
                                seed_id,
                                Some(cert_asset.0),
                                depth + 1,
                                5, // Lower priority for pivot
                            ).await?;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!("TLS certificate analysis failed for {}: {}", domain, e);
            }
        }

        Ok(result)
    }

    /// Discover assets from an organization
    async fn discover_from_organization(
        &self,
        run_id: Uuid,
        org: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        // Skip common infrastructure orgs
        if self.should_filter_organization(org) {
            tracing::debug!("Filtered organization: {}", org);
            return Ok(result);
        }

        // Create organization asset
        let org_asset = self.create_or_update_asset(
            run_id,
            AssetType::Organization,
            org,
            SourceType::Seed,
            0.8,
            seed_id,
            parent_asset_id,
            Some(json!({ "discovery_depth": depth })),
        ).await?;

        if org_asset.1 {
            result.assets_created.push(org_asset.0);
        } else {
            result.assets_updated.push(org_asset.0);
        }

        let org_asset_id = org_asset.0;

        // Search Shodan for organization
        match self.external_services.search_shodan_org_comprehensive(org).await {
            Ok(extracted) => {
                // Process IPs
                for ip in &extracted.ips {
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Ip,
                        ip,
                        SourceType::Shodan,
                        0.7,
                        seed_id,
                        Some(org_asset_id),
                        Some(json!({ "organization": org })),
                    ).await?;

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    }

                    self.create_relationship(run_id, org_asset_id, asset.0, RelationshipType::BelongsToOrg, 0.7).await?;
                }

                // Process domains - queue for further discovery
                for domain in &extracted.domains {
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Domain,
                        domain,
                        SourceType::Shodan,
                        0.6,
                        seed_id,
                        Some(org_asset_id),
                        Some(json!({ "organization": org })),
                    ).await?;

                    if asset.1 {
                        result.assets_created.push(asset.0);

                        // Queue for deeper discovery if within depth limit
                        if depth < self.settings.max_discovery_depth as i32 {
                            self.queue_for_discovery(
                                run_id,
                                QueueItemType::Domain,
                                domain,
                                seed_id,
                                Some(asset.0),
                                depth + 1,
                                3,
                            ).await?;
                        }
                    }

                    self.create_relationship(run_id, org_asset_id, asset.0, RelationshipType::BelongsToOrg, 0.6).await?;
                }
            }
            Err(e) => {
                result.warnings.push(format!("Shodan org search failed: {}", e));
            }
        }

        // Also search crt.sh for domains
        match self.external_services.search_crtsh_by_organization(org).await {
            Ok(domains) => {
                for domain in domains.iter().take(50) { // Limit to prevent explosion
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Domain,
                        domain,
                        SourceType::Crtsh,
                        0.6,
                        seed_id,
                        Some(org_asset_id),
                        Some(json!({ "organization": org, "source": "crt.sh" })),
                    ).await?;

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    }

                    self.create_relationship(run_id, org_asset_id, asset.0, RelationshipType::BelongsToOrg, 0.6).await?;
                }
            }
            Err(e) => {
                tracing::debug!("crt.sh org search failed: {}", e);
            }
        }

        Ok(result)
    }

    /// Discover assets from an ASN
    async fn discover_from_asn(
        &self,
        run_id: Uuid,
        asn: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        // Create ASN asset
        let asn_asset = self.create_or_update_asset(
            run_id,
            AssetType::Asn,
            asn,
            SourceType::Seed,
            1.0,
            seed_id,
            parent_asset_id,
            Some(json!({ "discovery_depth": depth })),
        ).await?;

        if asn_asset.1 {
            result.assets_created.push(asn_asset.0);
        }

        let asn_asset_id = asn_asset.0;

        // Search Shodan for ASN
        match self.external_services.search_shodan_asn_comprehensive(asn).await {
            Ok(extracted) => {
                for ip in &extracted.ips {
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Ip,
                        ip,
                        SourceType::Shodan,
                        0.8,
                        seed_id,
                        Some(asn_asset_id),
                        Some(json!({ "asn": asn })),
                    ).await?;

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    }

                    self.create_relationship(run_id, asn_asset_id, asset.0, RelationshipType::BelongsToAsn, 0.8).await?;
                }

                for domain in &extracted.domains {
                    let asset = self.create_or_update_asset(
                        run_id,
                        AssetType::Domain,
                        domain,
                        SourceType::Shodan,
                        0.7,
                        seed_id,
                        Some(asn_asset_id),
                        Some(json!({ "asn": asn })),
                    ).await?;

                    if asset.1 {
                        result.assets_created.push(asset.0);
                    }
                }
            }
            Err(e) => {
                result.warnings.push(format!("Shodan ASN search failed: {}", e));
            }
        }

        Ok(result)
    }

    /// Discover assets from a CIDR range
    async fn discover_from_cidr(
        &self,
        run_id: Uuid,
        cidr: &str,
        seed_id: Option<Uuid>,
        _parent_asset_id: Option<Uuid>,
        _depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        let ips = expand_cidr(cidr)?;
        let max_hosts = self.settings.max_cidr_hosts as usize;

        if ips.len() > max_hosts {
            return Err(ApiError::Validation(format!(
                "CIDR range {} has {} hosts, exceeding limit of {}",
                cidr, ips.len(), max_hosts
            )));
        }

        for ip in ips {
            let ip_str = ip.to_string();
            let asset = self.create_or_update_asset(
                run_id,
                AssetType::Ip,
                &ip_str,
                SourceType::CidrExpansion,
                0.9, // High confidence for CIDR expansion
                seed_id,
                None,
                Some(json!({ "cidr": cidr })),
            ).await?;

            if asset.1 {
                result.assets_created.push(asset.0);
            }
        }

        Ok(result)
    }

    /// Discover information about an IP (reverse DNS, etc.)
    async fn discover_from_ip(
        &self,
        run_id: Uuid,
        ip: &str,
        seed_id: Option<Uuid>,
        parent_asset_id: Option<Uuid>,
        _depth: i32,
    ) -> Result<DiscoveryResult, ApiError> {
        let mut result = DiscoveryResult::default();

        // Create or get IP asset
        let ip_asset = self.create_or_update_asset(
            run_id,
            AssetType::Ip,
            ip,
            SourceType::Seed,
            1.0,
            seed_id,
            parent_asset_id,
            None,
        ).await?;

        if ip_asset.1 {
            result.assets_created.push(ip_asset.0);
        }

        let ip_asset_id = ip_asset.0;

        // Reverse DNS lookup
        if let Ok(ip_addr) = ip.parse() {
            match self.dns_resolver.reverse_lookup(&ip_addr).await {
                Ok(hostnames) => {
                    for hostname in hostnames {
                        let asset = self.create_or_update_asset(
                            run_id,
                            AssetType::Domain,
                            &hostname,
                            SourceType::ReverseDns,
                            0.7,
                            seed_id,
                            Some(ip_asset_id),
                            Some(json!({ "reverse_resolved_from": ip })),
                        ).await?;

                        if asset.1 {
                            result.assets_created.push(asset.0);
                        }

                        self.create_relationship(
                            run_id,
                            ip_asset_id,
                            asset.0,
                            RelationshipType::ReverseResolvesTo,
                            0.7,
                        ).await?;
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
        asset_type: AssetType,
        identifier: &str,
        source_type: SourceType,
        confidence: f64,
        seed_id: Option<Uuid>,
        parent_id: Option<Uuid>,
        metadata: Option<serde_json::Value>,
    ) -> Result<(Uuid, bool), ApiError> { // Returns (asset_id, was_created)
        let asset_create = AssetCreate {
            asset_type: asset_type.clone(),
            identifier: identifier.to_string(),
            confidence,
            sources: json!([source_type.to_string()]),
            metadata: metadata.unwrap_or(json!({})),
            seed_id,
            parent_id,
            discovery_run_id: Some(run_id),
            discovery_method: Some(source_type.to_string()),
        };

        // Check if asset exists
        let existing = self.asset_repo.get_by_identifier(asset_type.clone(), identifier).await?;
        let was_created = existing.is_none();

        let asset = self.asset_repo.create_or_merge(&asset_create).await?;

        // Record the source
        let source_create = AssetSourceCreate {
            asset_id: asset.id,
            discovery_run_id: Some(run_id),
            source_type,
            source_confidence: confidence,
            raw_data: None,
        };
        self.asset_source_repo.create(&source_create).await?;

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

        let rel = self.asset_relationship_repo.create_or_update(&rel_create).await?;
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
        let item = DiscoveryQueueItemCreate {
            discovery_run_id: run_id,
            item_type,
            item_value: item_value.to_string(),
            parent_asset_id,
            seed_id,
            depth,
            priority,
        };

        self.discovery_queue_repo.enqueue(&item).await?;
        Ok(())
    }

    /// Check if an organization should be filtered out
    fn should_filter_organization(&self, org: &str) -> bool {
        let org_lower = org.to_lowercase();
        
        if org_lower.trim().is_empty() || org_lower.len() < 3 {
            return true;
        }

        for infra_org in COMMON_INFRASTRUCTURE_ORGS {
            if org_lower.contains(infra_org) {
                return true;
            }
        }

        false
    }

    /// Calculate confidence for subdomain discovery
    fn calculate_subdomain_confidence(&self, sources: &HashMap<String, Vec<String>>) -> f64 {
        let source_count = sources.len();
        let base = 0.5;
        let boost = (source_count as f64 - 1.0) * 0.1;
        (base + boost).min(0.9)
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
            external_services: Arc::clone(&self.external_services),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_analyzer: Arc::clone(&self.http_analyzer),
            task_manager: Arc::clone(&self.task_manager),
            settings: Arc::clone(&self.settings),
            confidence_scorer: Arc::clone(&self.confidence_scorer),
            status: Arc::clone(&self.status),
        }
    }
}

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
    },
    utils::network::expand_cidr,
};

/// Discovery run status tracking
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryStatus {
    pub is_running: bool,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub seeds_processed: usize,
    pub assets_discovered: usize,
    pub errors: Vec<String>,
    pub task_id: Option<Uuid>,
}

impl Default for DiscoveryStatus {
    fn default() -> Self {
        Self {
            is_running: false,
            started_at: None,
            completed_at: None,
            seeds_processed: 0,
            assets_discovered: 0,
            errors: Vec::new(),
            task_id: None,
        }
    }
}

/// Asset discovery result with confidence scoring
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub assets: Vec<AssetCreate>,
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
        }
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
        self.seed_repo.delete(id).await
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

    pub async fn create_or_merge_asset(&self, asset_create: AssetCreate) -> Result<Asset, ApiError> {
        self.asset_repo.create_or_merge(&asset_create).await
    }

    /// Get current discovery status
    pub async fn get_discovery_status(&self) -> DiscoveryStatus {
        self.discovery_status.lock().await.clone()
    }

    /// Run comprehensive asset discovery based on all seeds
    pub async fn run_discovery(&self) -> Result<(), ApiError> {
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
                    discovery_service.run_discovery_with_context(ctx).await
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
    async fn run_discovery_with_context(&self, ctx: TaskContext) -> Result<(), ApiError> {
        tracing::info!("Starting comprehensive asset discovery with task context");
        
        // Ensure status is always reset, even on error
        let result = self.run_discovery_internal(&ctx).await;
        
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
    async fn run_discovery_internal(&self, ctx: &TaskContext) -> Result<(), ApiError> {
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
                discovery_service.process_seed(&seed).await
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
    async fn process_seed(&self, seed: &Seed) -> Result<DiscoveryResult, ApiError> {
        tracing::info!("Processing seed: {} ({})", seed.value, seed.seed_type);
        
        let timeout_duration = Duration::from_secs_f64(self.settings.subdomain_enum_timeout * 1440.0); // 1440 = 24 hours
        
        let result = timeout(timeout_duration, async {
            match seed.seed_type {
                SeedType::Domain => self.discover_from_domain_recursive(&seed.value).await,
                SeedType::Organization => self.discover_from_organization_recursive(&seed.value).await,
                SeedType::Asn => self.discover_from_asn(&seed.value).await,
                SeedType::Cidr => self.discover_from_cidr(&seed.value).await,
                SeedType::Keyword => self.discover_from_keyword(&seed.value).await,
            }
        }).await;

        match result {
            Ok(discovery_result) => {
                match discovery_result {
                    Ok(result) => {
                        // Asset creation is now handled in the discovery_from_domain function
                        // Store discovered assets
                        /* for asset in &result.assets {
                            if let Err(e) = self.asset_repo.create_or_merge(asset).await {
                                tracing::warn!("Failed to store asset {}: {}", asset.identifier, e);
                            }
                        } */
                        
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
    async fn discover_from_domain_recursive(&self, root_domain: &str) -> Result<DiscoveryResult, ApiError> {
        let mut all_assets: Vec<AssetCreate> = Vec::new();
        let mut all_confidence: HashMap<String, f64> = HashMap::new();
        let mut all_sources: HashMap<String, Vec<String>> = HashMap::new();

        let mut visited_domains: HashSet<String> = HashSet::new();
        let mut visited_orgs: HashSet<String> = HashSet::new();

        let mut domain_queue: VecDeque<String> = VecDeque::new();
        let mut org_queue: VecDeque<String> = VecDeque::new();
        domain_queue.push_back(root_domain.to_string());

        loop {
            if let Some(domain_value) = domain_queue.pop_front() {
                if !visited_domains.insert(domain_value.clone()) { continue; }

                // Discover from domain
                let result = self.discover_from_domain(&domain_value).await?;
                
                // Save assets to db
                for asset in &result.assets {
                    match self.asset_repo.create_or_merge(asset).await {
                        Ok(_) => {
                            tracing::debug!("Successfully stored {:?} asset: {}", asset.asset_type, asset.identifier);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to store asset {}: {}", asset.identifier, e);
                        }
                    }
                }

                // Merge assets
                for asset in &result.assets {
                    all_assets.push(asset.clone());
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

                // Extract new organizations from produced certificate assets
                for asset in &all_assets {
                    if asset.asset_type == AssetType::Certificate {
                        if let Some(org) = asset.metadata.get("organization").and_then(|v| v.as_str()) {
                            let org_trimmed = org.trim();
                            if !org_trimmed.is_empty() && !visited_orgs.contains(org_trimmed) && !org_queue.contains(&org_trimmed.to_string()) {
                                org_queue.push_back(org_trimmed.to_string());
                            }
                        }
                    }
                }
            } else if let Some(org_value) = org_queue.pop_front() {
                // Organization pivot
                if !visited_orgs.insert(org_value.clone()) { continue; }

                // TO DO: add feature to allow skipping organizations
                if org_value.to_uppercase().contains("SALE") || org_value.to_uppercase().contains("FORCE") {
                    tracing::info!("Skipping organization: {}", org_value);
                    continue;
                }

                let result = self.discover_from_organization(&org_value).await?;

                // Merge
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
                        
                        if !visited_domains.contains(&top_domain) && !domain_queue.contains(&top_domain) {
                            tracing::debug!("New Top domain found: {}", top_domain);
                            domain_queue.push_back(top_domain);
                        }
                    }
                    all_assets.push(asset.clone());
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
    async fn discover_from_organization_recursive(&self, root_org: &str) -> Result<DiscoveryResult, ApiError> {
        let mut all_assets: Vec<AssetCreate> = Vec::new();
        let mut all_confidence: HashMap<String, f64> = HashMap::new();
        let mut all_sources: HashMap<String, Vec<String>> = HashMap::new();

        let mut visited_domains: HashSet<String> = HashSet::new();
        let mut visited_orgs: HashSet<String> = HashSet::new();

        let mut domain_queue: VecDeque<String> = VecDeque::new();
        let mut org_queue: VecDeque<String> = VecDeque::new();
        org_queue.push_back(root_org.to_string());

        loop {
            if let Some(domain_value) = domain_queue.pop_front() {
                if !visited_domains.insert(domain_value.clone()) { continue; }

                let result = self.discover_from_domain(&domain_value).await?;

                for asset in &result.assets { all_assets.push(asset.clone()); }
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

                // Discover new organizations from certificate assets
                for asset in &all_assets {
                    if asset.asset_type == AssetType::Certificate {
                        if let Some(org) = asset.metadata.get("organization").and_then(|v| v.as_str()) {
                            let org_trimmed = org.trim();
                            if !org_trimmed.is_empty() && !visited_orgs.contains(org_trimmed) && !org_queue.contains(&org_trimmed.to_string()) {
                                org_queue.push_back(org_trimmed.to_string());
                            }
                        }
                    }
                }
            } else if let Some(org_value) = org_queue.pop_front() {
                if !visited_orgs.insert(org_value.clone()) { continue; }

                // TO DO: add feature to allow skipping organizations
                if org_value.to_uppercase().contains("SALE") || org_value.to_uppercase().contains("FORCE") {
                    tracing::info!("Skipping organization: {}", org_value);
                    continue;
                }

                let result = self.discover_from_organization(&org_value).await?;

                for asset in &result.assets {
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
                        
                        if !visited_domains.contains(&top_domain) && !domain_queue.contains(&top_domain) {
                            tracing::debug!("New Top domain found: {}", top_domain);
                            domain_queue.push_back(top_domain);
                        }
                    }
                    all_assets.push(asset.clone());
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
    async fn discover_from_domain(&self, domain: &str) -> Result<DiscoveryResult, ApiError> {
        let mut assets = Vec::new();
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
                    
                    let asset = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: subdomain.clone(),
                        confidence,
                        sources: json!(subdomain_result.sources.keys().collect::<Vec<_>>()),
                        metadata: json!({
                            "parent_domain": domain,
                            "discovery_method": "subdomain_enumeration",
                            "sources": subdomain_result.sources
                        }),
                    };
                    
                    assets.push(asset);
                    confidence_scores.insert(subdomain.clone(), confidence);
                    sources.insert(subdomain.clone(), subdomain_result.sources.keys().cloned().collect());
                }
            }
            Err(e) => {
                tracing::warn!("Subdomain enumeration failed for {}: {}", domain, e);
            }
        }

        // Step 3: Process IPs extracted from Shodan
        for ip in &shodan_extracted.ips {
            let confidence = 0.8; // High confidence for Shodan IPs
            let asset = AssetCreate {
                asset_type: AssetType::Ip,
                identifier: ip.clone(),
                confidence,
                sources: json!(["shodan"]),
                metadata: json!({
                    "discovered_from": domain,
                    "discovery_method": "shodan_comprehensive",
                    "source": "shodan_domain_search"
                }),
            };
            assets.push(asset);
            confidence_scores.insert(ip.clone(), confidence);
            sources.insert(ip.clone(), vec!["shodan".to_string()]);
        }

        // Step 4: Process certificates extracted from Shodan
        for cert in &shodan_extracted.certificates {
            if let Some(ref org) = cert.organization {
                let confidence = 0.7;
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
                };
                assets.push(cert_asset);
                confidence_scores.insert(cert.subject.clone(), confidence);
                sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
            }
        }

        // Step 2: DNS resolution for discovered domains
        let mut resolved_ips = HashSet::new();
        let domain_assets: Vec<_> = assets.iter()
            .filter(|asset| asset.asset_type == AssetType::Domain)
            .cloned()
            .collect();
            
        for asset in domain_assets {
            match self.dns_resolver.resolve_hostname(&asset.identifier).await {
                Ok(ips) => {
                    for ip in ips {
                        resolved_ips.insert(ip);
                        
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
                        };
                        
                        assets.push(ip_asset);
                        confidence_scores.insert(ip.to_string(), ip_confidence);
                        sources.insert(ip.to_string(), vec!["dns_resolution".to_string()]);
                    }
                }
                Err(e) => {
                    tracing::debug!("DNS resolution failed for {}: {}", asset.identifier, e);
                }
            }
        }

        // Step 3: Certificate analysis for HTTPS domains
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
                                    "discovery_method": "certificate_analysis"
                                }),
                            };
                            
                            assets.push(cert_asset);
                            confidence_scores.insert(cert_info.subject.clone(), cert_confidence);
                            sources.insert(cert_info.subject.clone(), vec!["tls_certificate".to_string()]);
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
    async fn discover_from_organization(&self, org: &str) -> Result<DiscoveryResult, ApiError> {
        let mut assets = Vec::new();
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
                    let confidence = 0.7;
                    let asset = AssetCreate {
                        asset_type: AssetType::Ip,
                        identifier: ip.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "organization": org,
                            "discovery_method": "shodan_org_comprehensive"
                        }),
                    };
                    assets.push(asset);
                    confidence_scores.insert(ip.clone(), confidence);
                    sources.insert(ip.clone(), vec!["shodan".to_string()]);
                }
                
                // Process domains found in Shodan
                for domain in &extracted.domains {
                    let confidence = 0.6;
                    let asset = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "organization": org,
                            "discovery_method": "shodan_org_comprehensive"
                        }),
                    };
                    assets.push(asset);
                    confidence_scores.insert(domain.clone(), confidence);
                    sources.insert(domain.clone(), vec!["shodan".to_string()]);
                }
                
                // Process certificates
                for cert in &extracted.certificates {
                    if let Some(ref cert_org) = cert.organization {
                        let confidence = 0.7;
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
                        };
                        assets.push(cert_asset);
                        confidence_scores.insert(cert.subject.clone(), confidence);
                        sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
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

                    let asset = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["crt.sh"]),
                        metadata: json!({
                            "organization": org,
                            "discovery_method": "crtsh_org_search"
                        }),
                    };

                    assets.push(asset);
                    confidence_scores.insert(domain.clone(), confidence);
                    sources.insert(domain, vec!["crt.sh".to_string()]);
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
    async fn discover_from_asn(&self, asn: &str) -> Result<DiscoveryResult, ApiError> {
        let mut assets = Vec::new();
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
                    let confidence = 0.8;
                    let asset = AssetCreate {
                        asset_type: AssetType::Ip,
                        identifier: ip.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "asn": asn,
                            "discovery_method": "shodan_asn_comprehensive"
                        }),
                    };
                    assets.push(asset);
                    confidence_scores.insert(ip.clone(), confidence);
                    sources.insert(ip.clone(), vec!["shodan".to_string()]);
                }
                
                // Process domains
                for domain in &extracted.domains {
                    let confidence = 0.7;
                    let asset = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "asn": asn,
                            "discovery_method": "shodan_asn_comprehensive"
                        }),
                    };
                    assets.push(asset);
                    confidence_scores.insert(domain.clone(), confidence);
                    sources.insert(domain.clone(), vec!["shodan".to_string()]);
                }
                
                // Process certificates
                for cert in &extracted.certificates {
                    let confidence = 0.7;
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
                    };
                    assets.push(cert_asset);
                    confidence_scores.insert(cert.subject.clone(), confidence);
                    sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
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
    async fn discover_from_cidr(&self, cidr: &str) -> Result<DiscoveryResult, ApiError> {
        let mut assets = Vec::new();
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
            let confidence = 0.8; // High confidence for CIDR-based discovery
            
            let asset = AssetCreate {
                asset_type: AssetType::Ip,
                identifier: ip.to_string(),
                confidence,
                sources: json!(["cidr_expansion"]),
                metadata: json!({
                    "cidr": cidr,
                    "discovery_method": "cidr_expansion"
                }),
            };
            
            assets.push(asset);
            confidence_scores.insert(ip.to_string(), confidence);
            sources.insert(ip.to_string(), vec!["cidr_expansion".to_string()]);
        }

        Ok(DiscoveryResult {
            assets,
            confidence_scores,
            sources,
        })
    }

    /// Discover assets from a keyword seed
    /// Uses comprehensive Shodan extraction to find ALL asset types matching the keyword
    async fn discover_from_keyword(&self, keyword: &str) -> Result<DiscoveryResult, ApiError> {
        let mut assets = Vec::new();
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
                    let confidence = 0.5; // Lower confidence for keyword searches
                    let asset = AssetCreate {
                        asset_type: AssetType::Ip,
                        identifier: ip.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "keyword": keyword,
                            "discovery_method": "shodan_keyword_comprehensive"
                        }),
                    };
                    assets.push(asset);
                    confidence_scores.insert(ip.clone(), confidence);
                    sources.insert(ip.clone(), vec!["shodan".to_string()]);
                }
                
                // Process domains
                for domain in &extracted.domains {
                    let confidence = 0.5;
                    let asset = AssetCreate {
                        asset_type: AssetType::Domain,
                        identifier: domain.clone(),
                        confidence,
                        sources: json!(["shodan"]),
                        metadata: json!({
                            "keyword": keyword,
                            "discovery_method": "shodan_keyword_comprehensive"
                        }),
                    };
                    assets.push(asset);
                    confidence_scores.insert(domain.clone(), confidence);
                    sources.insert(domain.clone(), vec!["shodan".to_string()]);
                }
                
                // Process certificates
                for cert in &extracted.certificates {
                    let confidence = 0.5;
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
                    };
                    assets.push(cert_asset);
                    confidence_scores.insert(cert.subject.clone(), confidence);
                    sources.insert(cert.subject.clone(), vec!["shodan".to_string()]);
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

    // Confidence scoring algorithms
    fn calculate_domain_confidence(&self, domain: &str, parent_domain: &str, sources: &HashMap<String, Vec<String>>) -> f64 {
        let mut confidence = self.settings.related_asset_confidence_default;
        
        // Boost confidence based on number of sources
        let source_count = sources.len() as f64;
        confidence += (source_count - 1.0) * 0.1;
        
        // Boost confidence for direct subdomains
        if domain.ends_with(&format!(".{}", parent_domain)) {
            confidence += 0.2;
        }
        
        // Boost confidence for certificate transparency sources
        if sources.contains_key("crt.sh") {
            confidence += 0.1;
        }
        
        confidence.min(1.0)
    }

    fn calculate_ip_confidence(&self, _ip: &str, _resolved_from: &str) -> f64 {
        0.8 // High confidence for DNS-resolved IPs
    }

    fn calculate_certificate_confidence(&self, org: &str, _domain: &str) -> f64 {
        if org.is_empty() {
            0.3
        } else {
            0.7 // Good confidence for certificate-based discovery
        }
    }

    fn calculate_shodan_confidence(&self, _result: &crate::services::external::ShodanResult, _org: &str) -> f64 {
        0.6 // Medium confidence for Shodan-based discovery
    }

    fn calculate_asn_confidence(&self, _result: &crate::services::external::ShodanResult, _asn: &str) -> f64 {
        0.7 // Good confidence for ASN-based discovery
    }

    fn calculate_keyword_confidence(&self, _result: &crate::services::external::ShodanResult, _keyword: &str) -> f64 {
        0.4 // Lower confidence for keyword-based discovery
    }

    fn calculate_crtsh_org_confidence(&self, _domain: &str, _organization: &str) -> f64 {
        0.6 // Medium confidence for domains discovered via organization in CT logs
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
                if !seed.value.starts_with("AS") && !seed.value.parse::<u32>().is_ok() {
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
        }
    }
}
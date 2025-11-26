use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use crate::{
    config::{Settings, SharedSettings, COMMON_PORTS},
    error::ApiError,
    models::{Asset, AssetCreate, AssetType, FindingCreate, Scan, ScanCreate, ScanStatus},
    repositories::{AssetRepository, FindingRepository, ScanRepository},
    services::{
        external::{
            DnsResolver, ExternalServicesManager, HttpProbeResult, HttpProber,
            SubdomainEnumerationResult, ThreatIntelligenceResult, TlsAnalyzer,
        },
        task_manager::{TaskContext, TaskManager, TaskType},
    },
    utils::network::{expand_cidr, scan_ports},
};

pub struct ScanService {
    scan_repo: Arc<dyn ScanRepository + Send + Sync>,
    finding_repo: Arc<dyn FindingRepository + Send + Sync>,
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_prober: Arc<HttpProber>,
    tls_analyzer: Arc<TlsAnalyzer>,
    task_manager: Arc<TaskManager>,
    settings: SharedSettings,
}

impl ScanService {
    pub fn new(
        scan_repo: Arc<dyn ScanRepository + Send + Sync>,
        finding_repo: Arc<dyn FindingRepository + Send + Sync>,
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        external_services: Arc<ExternalServicesManager>,
        dns_resolver: Arc<DnsResolver>,
        http_prober: Arc<HttpProber>,
        tls_analyzer: Arc<TlsAnalyzer>,
        task_manager: Arc<TaskManager>,
        settings: SharedSettings,
    ) -> Self {
        Self {
            scan_repo,
            finding_repo,
            asset_repo,
            external_services,
            dns_resolver,
            http_prober,
            tls_analyzer,
            task_manager,
            settings,
        }
    }

    fn current_settings(&self) -> Arc<Settings> {
        self.settings.load_full()
    }

    pub async fn create_scan(&self, scan_create: ScanCreate) -> Result<Scan, ApiError> {
        let scan = self.scan_repo.create(&scan_create).await?;

        // Submit scan processing task to TaskManager
        let scan_service = Arc::new(self.clone());
        let scan_id = scan.id;
        let target = scan.target.clone();

        let task_metadata = json!({
            "scan_id": scan_id,
            "target": target,
            "scan_type": "background_scan"
        });

        let _task_id = self
            .task_manager
            .submit_task(TaskType::Scan, task_metadata, move |ctx| {
                let scan_service = scan_service.clone();
                let target = target.clone();
                Box::pin(async move {
                    scan_service
                        .process_scan_with_context(ctx, scan_id, &target)
                        .await
                })
            })
            .await?;

        tracing::info!(
            "Created scan {} for target {} and submitted to task manager",
            scan.id,
            scan.target
        );

        Ok(scan)
    }

    pub async fn get_scan(&self, id: &Uuid) -> Result<Option<Scan>, ApiError> {
        self.scan_repo.get_by_id(id).await
    }

    pub async fn list_scans(&self) -> Result<Vec<Scan>, ApiError> {
        self.scan_repo.list().await
    }

    /// Get scan list with findings count for API compatibility
    pub async fn list_scans_with_findings_count(
        &self,
    ) -> Result<Vec<crate::models::ScanListResponse>, ApiError> {
        use crate::models::ScanListResponse;

        let scans = self.scan_repo.list().await?;
        let mut scan_responses = Vec::new();

        for scan in scans {
            let findings_count = self.finding_repo.count_by_scan(&scan.id).await?;

            scan_responses.push(ScanListResponse {
                id: scan.id,
                target: scan.target,
                note: scan.note,
                status: scan.status,
                created_at: scan.created_at,
                updated_at: scan.updated_at,
                findings_count,
            });
        }

        Ok(scan_responses)
    }

    /// Get scan with findings array for API compatibility
    pub async fn get_scan_with_findings(
        &self,
        id: &Uuid,
    ) -> Result<Option<crate::models::ScanDetailResponse>, ApiError> {
        use crate::models::ScanDetailResponse;

        let scan = match self.scan_repo.get_by_id(id).await? {
            Some(scan) => scan,
            None => return Ok(None),
        };

        let findings = self.finding_repo.list_by_scan(&scan.id).await?;
        let findings_count = findings.len() as i64;

        Ok(Some(ScanDetailResponse {
            id: scan.id,
            target: scan.target,
            note: scan.note,
            status: scan.status,
            created_at: scan.created_at,
            updated_at: scan.updated_at,
            findings_count,
            findings,
        }))
    }

    pub async fn update_scan_status(&self, id: &Uuid, status: ScanStatus) -> Result<(), ApiError> {
        self.scan_repo.update_status(id, status).await
    }

    /// Background scan processing workflow with task context
    async fn process_scan_with_context(
        &self,
        ctx: TaskContext,
        scan_id: Uuid,
        target: &str,
    ) -> Result<(), ApiError> {
        tracing::info!(
            "Starting background scan processing for {} with target {}",
            scan_id,
            target
        );

        // Update scan status to running
        self.scan_repo
            .update_status(&scan_id, ScanStatus::Running)
            .await?;
        ctx.update_progress(0.1, Some("Scan started".to_string()))
            .await?;

        // Check for cancellation
        ctx.check_cancellation().await?;

        // Create or get the root asset for the scan target to establish lineage
        let root_asset_id = self.create_scan_root_asset(target).await?;

        // Determine target type and process accordingly
        if target.contains('/') {
            // CIDR range
            ctx.update_progress(0.2, Some("Processing CIDR range".to_string()))
                .await?;
            self.process_cidr_scan_with_context(&ctx, scan_id, target, root_asset_id)
                .await?;
        } else if target.parse::<IpAddr>().is_ok() {
            // IP address
            ctx.update_progress(0.2, Some("Processing IP address".to_string()))
                .await?;
            self.process_ip_scan_with_context(&ctx, scan_id, target, root_asset_id)
                .await?;
        } else {
            // Domain
            ctx.update_progress(0.2, Some("Processing domain".to_string()))
                .await?;
            self.process_domain_scan_with_context(&ctx, scan_id, target, root_asset_id)
                .await?;
        }

        // Update scan status to completed
        ctx.update_progress(0.9, Some("Finalizing scan".to_string()))
            .await?;
        self.scan_repo
            .update_status(&scan_id, ScanStatus::Completed)
            .await?;

        tracing::info!("Completed background scan processing for {}", scan_id);
        Ok(())
    }

    /// Create or get the root asset for a scan target to establish lineage
    async fn create_scan_root_asset(&self, target: &str) -> Result<Uuid, ApiError> {
        // Determine asset type based on target
        let (asset_type, identifier) = if target.contains('/') {
            // CIDR range - we'll create the first IP or just use identifier
            (AssetType::Ip, target.to_string())
        } else if target.parse::<IpAddr>().is_ok() {
            (AssetType::Ip, target.to_string())
        } else {
            (AssetType::Domain, target.to_string())
        };

        // Check if asset already exists (could be from discovery)
        let existing_asset = self
            .asset_repo
            .get_by_identifier(asset_type.clone(), &identifier)
            .await?;

        let metadata = if let Some(ref existing) = existing_asset {
            // Asset exists - check if it has a parent (was discovered)
            if existing.parent_id.is_some() {
                // Asset has a parent from discovery - don't mark as scan_root
                // Just add scan metadata without overwriting discovery lineage
                json!({
                    "last_scanned_at": chrono::Utc::now(),
                    "scanned_directly": true
                })
            } else {
                // Asset exists but has no parent - it was a previous scan root or seed
                json!({
                    "is_scan_root": true,
                    "last_scanned_at": chrono::Utc::now()
                })
            }
        } else {
            // New asset - this is a true scan root
            json!({
                "is_scan_root": true,
                "scanned_at": chrono::Utc::now()
            })
        };

        let asset = AssetCreate {
            asset_type,
            identifier,
            confidence: 1.0, // Scan target has maximum confidence
            sources: json!(["scan_target"]),
            metadata,
            seed_id: None,
            parent_id: None, // Don't override existing parent_id (handled by create_or_merge)
            discovery_run_id: None,
            discovery_method: Some("scan".to_string()),
        };

        let created_asset = self.asset_repo.create_or_merge(&asset).await?;
        Ok(created_asset.id)
    }

    /// Process domain scan with task context and progress updates
    async fn process_domain_scan_with_context(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        domain: &str,
        root_asset_id: Uuid,
    ) -> Result<(), ApiError> {
        tracing::info!("Processing domain scan for {}", domain);
        let settings = self.current_settings();

        // Step 1: Subdomain enumeration
        ctx.update_progress(0.3, Some("Enumerating subdomains".to_string()))
            .await?;
        let subdomain_result = timeout(
            Duration::from_secs_f64(settings.subdomain_enum_timeout),
            self.external_services.enumerate_subdomains(domain),
        )
        .await;

        let subdomains = match subdomain_result {
            Ok(Ok(result)) => {
                self.create_subdomain_finding(scan_id, domain, &result)
                    .await?;
                result.subdomains
            }
            Ok(Err(e)) => {
                tracing::warn!("Subdomain enumeration failed for {}: {}", domain, e);
                vec![domain.to_string()] // Fallback to just the main domain
            }
            Err(_) => {
                tracing::warn!("Subdomain enumeration timed out for {}", domain);
                vec![domain.to_string()]
            }
        };

        ctx.check_cancellation().await?;

        // Step 2: DNS resolution for all discovered subdomains
        ctx.update_progress(0.5, Some("Resolving DNS records".to_string()))
            .await?;
        let mut resolved_ips_with_parent = Vec::new();
        for (i, subdomain) in subdomains.iter().enumerate() {
            ctx.check_cancellation().await?;

            match self.dns_resolver.resolve_hostname(subdomain).await {
                Ok(ips) => {
                    if !ips.is_empty() {
                        self.create_dns_finding(scan_id, subdomain, &ips).await?;
                        // Create domain asset with proper lineage (parent is root domain)
                        let subdomain_asset = self
                            .create_domain_asset_with_parent(
                                scan_id,
                                subdomain,
                                Some(root_asset_id),
                            )
                            .await?;
                        // Store IPs with their parent subdomain asset for lineage
                        for ip in ips {
                            resolved_ips_with_parent.push((ip, subdomain_asset.id));
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("DNS resolution failed for {}: {}", subdomain, e);
                }
            }

            // Update progress during DNS resolution
            let dns_progress = 0.5 + (i as f32 / subdomains.len() as f32) * 0.2;
            ctx.update_progress(
                dns_progress,
                Some(format!(
                    "Resolved {} of {} domains",
                    i + 1,
                    subdomains.len()
                )),
            )
            .await?;
        }

        // Step 3: Process discovered IPs with proper parent tracking
        ctx.update_progress(0.7, Some("Scanning discovered IPs".to_string()))
            .await?;
        for (i, (ip, parent_domain_id)) in resolved_ips_with_parent.iter().enumerate() {
            ctx.check_cancellation().await?;
            self.process_ip_address_with_parent(scan_id, *ip, Some(*parent_domain_id))
                .await?;

            // Update progress during IP processing
            let ip_progress = 0.7 + (i as f32 / resolved_ips_with_parent.len() as f32) * 0.15;
            ctx.update_progress(
                ip_progress,
                Some(format!(
                    "Scanned {} of {} IPs",
                    i + 1,
                    resolved_ips_with_parent.len()
                )),
            )
            .await?;
        }

        // Step 4: Threat intelligence for the main domain
        ctx.update_progress(0.85, Some("Gathering threat intelligence".to_string()))
            .await?;
        if let Ok(threat_intel) = self.external_services.get_domain_threat_intel(domain).await {
            self.create_threat_intel_finding(scan_id, domain, &threat_intel)
                .await?;
        }

        Ok(())
    }

    /// Process IP scan with task context
    async fn process_ip_scan_with_context(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        ip_str: &str,
        _root_asset_id: Uuid,
    ) -> Result<(), ApiError> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| ApiError::Validation(format!("Invalid IP address: {}", e)))?;

        ctx.update_progress(0.3, Some(format!("Scanning IP {}", ip)))
            .await?;
        // For direct IP scans, the root asset IS the IP, so parent is None
        self.process_ip_address_with_context_and_parent(ctx, scan_id, ip, None)
            .await
    }

    /// Process CIDR scan with task context
    async fn process_cidr_scan_with_context(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        cidr: &str,
        root_asset_id: Uuid,
    ) -> Result<(), ApiError> {
        tracing::info!("Processing CIDR scan for {}", cidr);
        let settings = self.current_settings();

        let ips = expand_cidr(cidr)?;
        let max_hosts = settings.max_cidr_hosts as usize;

        if ips.len() > max_hosts {
            return Err(ApiError::Validation(format!(
                "CIDR range {} contains {} hosts, exceeding limit of {}",
                cidr,
                ips.len(),
                max_hosts
            )));
        }

        // Create CIDR finding
        self.create_cidr_finding(scan_id, cidr, ips.len()).await?;

        ctx.update_progress(
            0.3,
            Some(format!("Scanning {} hosts in CIDR range", ips.len())),
        )
        .await?;

        // Process each IP with concurrency control
        // For CIDR scans, each IP is a child of the CIDR root asset
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            settings.tcp_scan_concurrency as usize,
        ));
        let mut tasks = Vec::new();

        for (i, ip) in ips.iter().enumerate() {
            ctx.check_cancellation().await?;

            let scan_service = self.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip = *ip;

            let task = tokio::spawn(async move {
                let _permit = permit;
                // Each IP in CIDR is child of the root CIDR asset
                scan_service
                    .process_ip_address_with_parent(scan_id, ip, Some(root_asset_id))
                    .await
            });

            tasks.push(task);

            // Update progress periodically
            if i % 10 == 0 || i == ips.len() - 1 {
                let progress = 0.3 + (i as f32 / ips.len() as f32) * 0.6;
                ctx.update_progress(
                    progress,
                    Some(format!("Submitted {} of {} IP scans", i + 1, ips.len())),
                )
                .await?;
            }
        }

        // Wait for all IP scans to complete
        let mut completed = 0;
        for task in tasks {
            ctx.check_cancellation().await?;

            if let Err(e) = task
                .await
                .unwrap_or_else(|e| Err(ApiError::ExternalService(e.to_string())))
            {
                tracing::warn!("IP scan task failed: {}", e);
            }

            completed += 1;
            let progress = 0.3 + (completed as f32 / ips.len() as f32) * 0.6;
            ctx.update_progress(
                progress,
                Some(format!("Completed {} of {} IP scans", completed, ips.len())),
            )
            .await?;
        }

        Ok(())
    }

    /// Process individual IP address with task context and optional parent for lineage
    async fn process_ip_address_with_context_and_parent(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        ip: IpAddr,
        parent_id: Option<Uuid>,
    ) -> Result<(), ApiError> {
        tracing::debug!("Processing IP address {} with parent {:?}", ip, parent_id);
        let settings = self.current_settings();

        // Step 1: Port scanning
        ctx.update_progress(0.4, Some(format!("Port scanning {}", ip)))
            .await?;
        let timeout_duration = Duration::from_secs_f64(settings.tcp_scan_timeout);
        let open_ports = scan_ports(ip, COMMON_PORTS, timeout_duration).await;

        if !open_ports.is_empty() {
            self.create_port_scan_finding(scan_id, ip, &open_ports)
                .await?;
            let ip_asset = self
                .create_ip_asset_with_parent(scan_id, ip, parent_id)
                .await?;

            ctx.update_progress(
                0.6,
                Some(format!("Found {} open ports on {}", open_ports.len(), ip)),
            )
            .await?;

            // Step 2: HTTP probing for web ports
            for &port in &open_ports {
                ctx.check_cancellation().await?;
                if matches!(port, 80 | 443 | 8080 | 8443) {
                    self.probe_http_service(scan_id, ip, port).await?;
                }
            }

            ctx.update_progress(0.7, Some(format!("Completed HTTP probing for {}", ip)))
                .await?;

            // Step 3: TLS analysis for HTTPS ports
            for &port in &open_ports {
                ctx.check_cancellation().await?;
                if matches!(port, 443 | 8443) {
                    self.analyze_tls_service_with_parent(scan_id, ip, port, ip_asset.id)
                        .await?;
                }
            }

            ctx.update_progress(0.8, Some(format!("Completed TLS analysis for {}", ip)))
                .await?;

            // Step 4: Reverse DNS lookup - domains discovered from IP should have IP as parent
            if let Ok(hostnames) = self.dns_resolver.reverse_lookup(&ip).await {
                if !hostnames.is_empty() {
                    self.create_reverse_dns_finding(scan_id, ip, &hostnames)
                        .await?;

                    // Create domain assets for discovered hostnames with IP as parent
                    for hostname in hostnames {
                        self.create_domain_asset_with_parent(scan_id, &hostname, Some(ip_asset.id))
                            .await?;
                    }
                }
            }
        }

        // Step 5: Threat intelligence for IP
        if let Ok(threat_intel) = self
            .external_services
            .get_ip_threat_intel(&ip.to_string())
            .await
        {
            self.create_threat_intel_finding(scan_id, &ip.to_string(), &threat_intel)
                .await?;
        }

        Ok(())
    }

    /// Process individual IP address with port scanning and service detection (with optional parent for lineage)
    async fn process_ip_address_with_parent(
        &self,
        scan_id: Uuid,
        ip: IpAddr,
        parent_id: Option<Uuid>,
    ) -> Result<(), ApiError> {
        tracing::debug!("Processing IP address {} with parent {:?}", ip, parent_id);
        let settings = self.current_settings();

        // Step 1: Port scanning
        let timeout_duration = Duration::from_secs_f64(settings.tcp_scan_timeout);
        let open_ports = scan_ports(ip, COMMON_PORTS, timeout_duration).await;

        if !open_ports.is_empty() {
            self.create_port_scan_finding(scan_id, ip, &open_ports)
                .await?;
            let ip_asset = self
                .create_ip_asset_with_parent(scan_id, ip, parent_id)
                .await?;

            // Step 2: HTTP probing for web ports
            for &port in &open_ports {
                if matches!(port, 80 | 443 | 8080 | 8443) {
                    self.probe_http_service(scan_id, ip, port).await?;
                }
            }

            // Step 3: TLS analysis for HTTPS ports - certificates are children of the IP
            for &port in &open_ports {
                if matches!(port, 443 | 8443) {
                    self.analyze_tls_service_with_parent(scan_id, ip, port, ip_asset.id)
                        .await?;
                }
            }

            // Step 4: Reverse DNS lookup - domains discovered from IP should have IP as parent
            if let Ok(hostnames) = self.dns_resolver.reverse_lookup(&ip).await {
                if !hostnames.is_empty() {
                    self.create_reverse_dns_finding(scan_id, ip, &hostnames)
                        .await?;

                    // Create domain assets for discovered hostnames with IP as parent
                    for hostname in hostnames {
                        self.create_domain_asset_with_parent(scan_id, &hostname, Some(ip_asset.id))
                            .await?;
                    }
                }
            }
        }

        // Step 5: Threat intelligence for IP
        if let Ok(threat_intel) = self
            .external_services
            .get_ip_threat_intel(&ip.to_string())
            .await
        {
            self.create_threat_intel_finding(scan_id, &ip.to_string(), &threat_intel)
                .await?;
        }

        Ok(())
    }

    /// Probe HTTP service and extract information
    async fn probe_http_service(
        &self,
        scan_id: Uuid,
        ip: IpAddr,
        port: u16,
    ) -> Result<(), ApiError> {
        let scheme = if port == 443 || port == 8443 {
            "https"
        } else {
            "http"
        };
        let url = format!("{}://{}:{}", scheme, ip, port);

        let response = self.http_prober.probe_url(&url).await;
        self.create_http_finding(scan_id, &url, &response).await?;

        Ok(())
    }

    /// Analyze TLS service and extract certificate information (with parent for lineage)
    async fn analyze_tls_service_with_parent(
        &self,
        scan_id: Uuid,
        ip: IpAddr,
        port: u16,
        parent_id: Uuid,
    ) -> Result<(), ApiError> {
        use crate::utils::crypto::get_tls_certificate_info;

        let hostname = ip.to_string(); // Use IP as hostname for direct IP connections

        match get_tls_certificate_info(&hostname, port).await {
            Ok(cert_info) => {
                let cert_info_json = serde_json::to_value(&cert_info).unwrap_or_else(|_| json!({}));

                self.create_tls_finding(scan_id, &format!("{}:{}", ip, port), &cert_info_json)
                    .await?;

                // Create certificate asset if organization is found - certificate is child of the IP
                if let Some(org) = &cert_info.organization {
                    if !org.is_empty() {
                        self.create_certificate_asset_with_parent(
                            scan_id,
                            &cert_info_json,
                            Some(parent_id),
                        )
                        .await?;
                    }
                }
            }
            Err(e) => {
                tracing::debug!("TLS analysis failed for {}:{}: {}", ip, port, e);
            }
        }

        Ok(())
    }

    // Finding creation methods
    async fn create_subdomain_finding(
        &self,
        scan_id: Uuid,
        domain: &str,
        result: &SubdomainEnumerationResult,
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "subdomain_enumeration".to_string(),
            data: json!({
                "domain": domain,
                "subdomains": result.subdomains,
                "sources": result.sources,
                "count": result.subdomains.len()
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_dns_finding(
        &self,
        scan_id: Uuid,
        hostname: &str,
        ips: &[IpAddr],
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "dns_resolution".to_string(),
            data: json!({
                "hostname": hostname,
                "ips": ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                "count": ips.len()
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_port_scan_finding(
        &self,
        scan_id: Uuid,
        ip: IpAddr,
        ports: &[u16],
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({
                "ip": ip.to_string(),
                "open_ports": ports,
                "count": ports.len()
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_http_finding(
        &self,
        scan_id: Uuid,
        url: &str,
        response: &HttpProbeResult,
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "http_probe".to_string(),
            data: serde_json::to_value(response).unwrap_or_else(|_| {
                json!({
                    "url": url,
                    "error": "Failed to serialize response"
                })
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_tls_finding(
        &self,
        scan_id: Uuid,
        address: &str,
        cert_info: &Value,
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "tls_analysis".to_string(),
            data: json!({
                "address": address,
                "certificate": cert_info
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_reverse_dns_finding(
        &self,
        scan_id: Uuid,
        ip: IpAddr,
        hostnames: &[String],
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "reverse_dns".to_string(),
            data: json!({
                "ip": ip.to_string(),
                "hostnames": hostnames,
                "count": hostnames.len()
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_threat_intel_finding(
        &self,
        scan_id: Uuid,
        target: &str,
        threat_intel: &ThreatIntelligenceResult,
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "threat_intelligence".to_string(),
            data: json!({
                "target": target,
                "is_malicious": threat_intel.is_malicious,
                "reputation_score": threat_intel.reputation_score,
                "threat_sources": threat_intel.threat_sources,
                "additional_info": threat_intel.additional_info
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    async fn create_cidr_finding(
        &self,
        scan_id: Uuid,
        cidr: &str,
        host_count: usize,
    ) -> Result<(), ApiError> {
        let finding = FindingCreate {
            scan_id,
            finding_type: "cidr_expansion".to_string(),
            data: json!({
                "cidr": cidr,
                "host_count": host_count
            }),
        };

        self.finding_repo.create(&finding).await?;
        Ok(())
    }

    // Asset creation methods with lineage tracking
    async fn create_domain_asset_with_parent(
        &self,
        _scan_id: Uuid,
        domain: &str,
        parent_id: Option<Uuid>,
    ) -> Result<Asset, ApiError> {
        let asset = AssetCreate {
            asset_type: AssetType::Domain,
            identifier: domain.to_string(),
            confidence: 0.9, // High confidence for directly discovered domains
            sources: json!(["scan"]),
            metadata: json!({
                "discovered_via": "scan"
            }),
            seed_id: None,
            parent_id,
            discovery_run_id: None,
            discovery_method: Some("scan".to_string()),
        };

        self.asset_repo.create_or_merge(&asset).await
    }

    async fn create_ip_asset_with_parent(
        &self,
        _scan_id: Uuid,
        ip: IpAddr,
        parent_id: Option<Uuid>,
    ) -> Result<Asset, ApiError> {
        let asset = AssetCreate {
            asset_type: AssetType::Ip,
            identifier: ip.to_string(),
            confidence: 0.9, // High confidence for directly scanned IPs
            sources: json!(["scan"]),
            metadata: json!({
                "discovered_via": "scan"
            }),
            seed_id: None,
            parent_id,
            discovery_run_id: None,
            discovery_method: Some("scan".to_string()),
        };

        self.asset_repo.create_or_merge(&asset).await
    }

    async fn create_certificate_asset_with_parent(
        &self,
        _scan_id: Uuid,
        cert_info: &Value,
        parent_id: Option<Uuid>,
    ) -> Result<(), ApiError> {
        if let Some(subject) = cert_info.get("subject").and_then(|v| v.as_str()) {
            let asset = AssetCreate {
                asset_type: AssetType::Certificate,
                identifier: subject.to_string(),
                confidence: 0.8, // Good confidence for certificate-based discovery
                sources: json!(["tls_scan"]),
                metadata: cert_info.clone(),
                seed_id: None,
                parent_id,
                discovery_run_id: None,
                discovery_method: Some("tls_scan".to_string()),
            };

            self.asset_repo.create_or_merge(&asset).await?;
        }

        Ok(())
    }
}

// Implement Clone for ScanService to enable Arc sharing in background tasks
impl Clone for ScanService {
    fn clone(&self) -> Self {
        Self {
            scan_repo: Arc::clone(&self.scan_repo),
            finding_repo: Arc::clone(&self.finding_repo),
            asset_repo: Arc::clone(&self.asset_repo),
            external_services: Arc::clone(&self.external_services),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_prober: Arc::clone(&self.http_prober),
            tls_analyzer: Arc::clone(&self.tls_analyzer),
            task_manager: Arc::clone(&self.task_manager),
            settings: Arc::clone(&self.settings),
        }
    }
}

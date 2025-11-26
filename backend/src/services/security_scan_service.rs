//! Security Scan Service
//!
//! Handles active security scanning of known assets. This service is focused on
//! **security assessment**, not discovery.
//!
//! The scanning flow:
//! 1. User selects an asset to scan (or scan is auto-triggered)
//! 2. A security scan record is created
//! 3. Various security checks are performed (port scan, TLS analysis, etc.)
//! 4. Findings are created for any security issues discovered
//! 5. The scan is marked as complete with a summary

use chrono::Utc;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    config::{Settings, SharedSettings, COMMON_PORTS},
    error::ApiError,
    models::{
        Asset, AssetType, FindingSeverity, ScanResultSummary, SecurityFinding,
        SecurityFindingCreate, SecurityScan, SecurityScanCreate, SecurityScanType,
    },
    repositories::{AssetRepository, SecurityFindingRepository, SecurityScanRepository},
    services::{
        external::{DnsResolver, ExternalServicesManager, HttpProber, TlsAnalyzer},
        task_manager::{TaskContext, TaskManager, TaskType},
    },
    utils::{crypto::get_tls_certificate_info, network::scan_ports},
};

pub struct SecurityScanService {
    // Repositories
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    scan_repo: Arc<dyn SecurityScanRepository + Send + Sync>,
    finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,

    // External services
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_prober: Arc<HttpProber>,
    tls_analyzer: Arc<TlsAnalyzer>,

    // Utilities
    task_manager: Arc<TaskManager>,
    settings: SharedSettings,
}

impl SecurityScanService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        scan_repo: Arc<dyn SecurityScanRepository + Send + Sync>,
        finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
        external_services: Arc<ExternalServicesManager>,
        dns_resolver: Arc<DnsResolver>,
        http_prober: Arc<HttpProber>,
        tls_analyzer: Arc<TlsAnalyzer>,
        task_manager: Arc<TaskManager>,
        settings: SharedSettings,
    ) -> Self {
        Self {
            asset_repo,
            scan_repo,
            finding_repo,
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

    // ========================================================================
    // SCAN MANAGEMENT
    // ========================================================================

    /// Create a new security scan for an asset
    pub async fn create_scan(
        &self,
        scan_create: SecurityScanCreate,
    ) -> Result<SecurityScan, ApiError> {
        // Verify asset exists
        let asset = self
            .asset_repo
            .get_by_id(&scan_create.asset_id)
            .await?
            .ok_or_else(|| {
                ApiError::NotFound(format!("Asset {} not found", scan_create.asset_id))
            })?;

        // Create the scan record
        let scan = self.scan_repo.create(&scan_create).await?;
        let scan_id = scan.id;
        let asset_id = asset.id;

        // Submit scan task
        let scan_service = self.clone();
        let task_metadata = json!({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "asset_identifier": asset.identifier,
            "scan_type": scan.scan_type,
        });

        self.task_manager
            .submit_task(TaskType::Scan, task_metadata, move |ctx| {
                let scan_service = scan_service.clone();
                Box::pin(async move { scan_service.execute_scan(ctx, scan_id, asset_id).await })
            })
            .await?;

        tracing::info!(
            "Created security scan {} for asset {}",
            scan_id,
            asset.identifier
        );
        Ok(scan)
    }

    /// Get a scan by ID
    pub async fn get_scan(&self, id: &Uuid) -> Result<Option<SecurityScan>, ApiError> {
        self.scan_repo.get_by_id(id).await
    }

    /// Cancel a running scan
    pub async fn cancel_scan(&self, id: &Uuid) -> Result<(), ApiError> {
        use crate::models::security::SecurityScanStatus;

        // Get the current scan status
        let scan = self
            .scan_repo
            .get_by_id(id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("Scan {} not found", id)))?;

        // Only running or pending scans can be cancelled
        let cancellable_statuses = ["running", "pending"];
        if !cancellable_statuses.contains(&scan.status.as_str()) {
            return Err(ApiError::Validation(format!(
                "Scan {} is in {} state and cannot be cancelled",
                id, scan.status
            )));
        }

        // Update scan status to cancelled
        self.scan_repo
            .update_status(id, SecurityScanStatus::Cancelled)
            .await?;

        // Cancel the task in the task manager
        let _ = self.task_manager.cancel_task(*id).await;

        tracing::info!("Cancelled security scan {}", id);
        Ok(())
    }

    /// Get scan with full details including asset and findings
    pub async fn get_scan_detail(
        &self,
        id: &Uuid,
    ) -> Result<Option<crate::models::SecurityScanDetailResponse>, ApiError> {
        let scan = match self.scan_repo.get_by_id(id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let asset = self
            .asset_repo
            .get_by_id(&scan.asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("Asset not found".to_string()))?;

        let findings = self.finding_repo.list_by_scan(id).await?;
        let findings_count = findings.len() as i64;

        Ok(Some(crate::models::SecurityScanDetailResponse {
            scan,
            asset,
            findings,
            findings_count,
        }))
    }

    /// List scans for an asset
    pub async fn list_scans_for_asset(
        &self,
        asset_id: &Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        self.scan_repo.list_by_asset(asset_id, 100).await
    }

    /// List all scans
    pub async fn list_scans(&self, limit: i64, offset: i64) -> Result<Vec<SecurityScan>, ApiError> {
        self.scan_repo.list_all(limit, offset).await
    }

    /// Get pending scans
    pub async fn list_pending_scans(&self, limit: i64) -> Result<Vec<SecurityScan>, ApiError> {
        self.scan_repo.list_pending(limit).await
    }

    // ========================================================================
    // SCAN EXECUTION
    // ========================================================================

    /// Execute a security scan
    async fn execute_scan(
        &self,
        ctx: TaskContext,
        scan_id: Uuid,
        asset_id: Uuid,
    ) -> Result<(), ApiError> {
        tracing::info!("Starting security scan {}", scan_id);

        // Mark scan as running
        self.scan_repo.start(&scan_id).await?;
        ctx.update_progress(0.1, Some("Scan started".to_string()))
            .await?;

        // Get asset details
        let asset = self
            .asset_repo
            .get_by_id(&asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("Asset not found".to_string()))?;

        // Get scan config
        let scan = self
            .scan_repo
            .get_by_id(&scan_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("Scan not found".to_string()))?;

        let scan_type = SecurityScanType::from(scan.scan_type.as_str());

        // Execute appropriate scan based on asset type and scan type
        let result = self
            .execute_scan_internal(&ctx, scan_id, &asset, scan_type)
            .await;

        // Finalize scan
        match result {
            Ok(summary) => {
                let summary_json = serde_json::to_value(&summary).unwrap_or(json!({}));
                self.scan_repo.complete(&scan_id, &summary_json).await?;
                tracing::info!("Security scan {} completed successfully", scan_id);
            }
            Err(e) => {
                self.scan_repo.fail(&scan_id, &e.to_string()).await?;
                tracing::error!("Security scan {} failed: {}", scan_id, e);
                return Err(e);
            }
        }

        Ok(())
    }

    async fn execute_scan_internal(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        scan_type: SecurityScanType,
    ) -> Result<ScanResultSummary, ApiError> {
        let mut summary = ScanResultSummary::default();
        let start_time = std::time::Instant::now();

        match asset.asset_type {
            AssetType::Domain => {
                self.scan_domain(ctx, scan_id, asset, &scan_type, &mut summary)
                    .await?;
            }
            AssetType::Ip => {
                self.scan_ip(ctx, scan_id, asset, &scan_type, &mut summary)
                    .await?;
            }
            AssetType::Certificate => {
                self.scan_certificate(ctx, scan_id, asset, &mut summary)
                    .await?;
            }
            _ => {
                tracing::warn!("Scan not supported for asset type {:?}", asset.asset_type);
            }
        }

        summary.scan_duration_ms = Some(start_time.elapsed().as_millis() as i64);

        // Count findings by severity
        let findings = self.finding_repo.list_by_scan(&scan_id).await?;
        let mut by_severity: std::collections::HashMap<String, i32> =
            std::collections::HashMap::new();
        for finding in &findings {
            *by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        summary.findings_by_severity = Some(by_severity);

        Ok(summary)
    }

    // ========================================================================
    // DOMAIN SCANNING
    // ========================================================================

    async fn scan_domain(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        scan_type: &SecurityScanType,
        summary: &mut ScanResultSummary,
    ) -> Result<(), ApiError> {
        let domain = &asset.identifier;

        // Step 1: DNS checks
        ctx.update_progress(0.2, Some("Checking DNS".to_string()))
            .await?;
        self.check_dns_security(scan_id, asset).await?;

        // Step 2: Resolve to IP and scan
        ctx.update_progress(0.3, Some("Resolving DNS".to_string()))
            .await?;
        match self.dns_resolver.resolve_hostname(domain).await {
            Ok(ips) => {
                if let Some(ip) = ips.first() {
                    // Port scan
                    if matches!(
                        scan_type,
                        SecurityScanType::PortScan | SecurityScanType::Full
                    ) {
                        ctx.update_progress(0.4, Some("Scanning ports".to_string()))
                            .await?;
                        summary.open_ports =
                            Some(self.scan_ports_with_findings(scan_id, asset, *ip).await?);
                    }

                    // HTTP probing
                    if matches!(
                        scan_type,
                        SecurityScanType::HttpProbe | SecurityScanType::Full
                    ) {
                        ctx.update_progress(0.6, Some("Probing HTTP".to_string()))
                            .await?;
                        summary.http_status = self
                            .probe_http_with_findings(scan_id, asset, domain)
                            .await?;
                    }
                }
            }
            Err(e) => {
                self.create_finding(
                    scan_id,
                    asset.id,
                    "dns_resolution_failed",
                    FindingSeverity::Low,
                    "DNS Resolution Failed",
                    Some(&format!("Could not resolve domain {}: {}", domain, e)),
                    json!({ "domain": domain, "error": e.to_string() }),
                )
                .await?;
            }
        }

        // Step 3: TLS analysis
        if matches!(
            scan_type,
            SecurityScanType::TlsAnalysis | SecurityScanType::Full
        ) {
            ctx.update_progress(0.7, Some("Analyzing TLS".to_string()))
                .await?;
            summary.tls_version = self
                .analyze_tls_with_findings(scan_id, asset, domain, 443)
                .await?;
        }

        // Step 4: Threat intelligence
        if matches!(
            scan_type,
            SecurityScanType::ThreatIntel | SecurityScanType::Full
        ) {
            ctx.update_progress(0.85, Some("Checking threat intel".to_string()))
                .await?;
            self.check_threat_intel(scan_id, asset, domain).await?;
        }

        Ok(())
    }

    // ========================================================================
    // IP SCANNING
    // ========================================================================

    async fn scan_ip(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        scan_type: &SecurityScanType,
        summary: &mut ScanResultSummary,
    ) -> Result<(), ApiError> {
        let ip: IpAddr = asset
            .identifier
            .parse()
            .map_err(|e| ApiError::Validation(format!("Invalid IP: {}", e)))?;

        // Port scan
        if matches!(
            scan_type,
            SecurityScanType::PortScan | SecurityScanType::Full
        ) {
            ctx.update_progress(0.3, Some("Scanning ports".to_string()))
                .await?;
            summary.open_ports = Some(self.scan_ports_with_findings(scan_id, asset, ip).await?);
        }

        // HTTP probing on web ports
        if matches!(
            scan_type,
            SecurityScanType::HttpProbe | SecurityScanType::Full
        ) {
            ctx.update_progress(0.5, Some("Probing HTTP".to_string()))
                .await?;
            let ports = summary.open_ports.as_ref().cloned().unwrap_or_default();
            for port in &ports {
                if matches!(port, 80 | 443 | 8080 | 8443) {
                    self.probe_http_with_findings(scan_id, asset, &format!("{}:{}", ip, port))
                        .await?;
                }
            }
        }

        // TLS analysis on HTTPS ports
        if matches!(
            scan_type,
            SecurityScanType::TlsAnalysis | SecurityScanType::Full
        ) {
            ctx.update_progress(0.7, Some("Analyzing TLS".to_string()))
                .await?;
            let ports = summary.open_ports.as_ref().cloned().unwrap_or_default();
            for port in &ports {
                if matches!(port, 443 | 8443) {
                    summary.tls_version = self
                        .analyze_tls_with_findings(scan_id, asset, &ip.to_string(), *port)
                        .await?;
                }
            }
        }

        // Threat intelligence
        if matches!(
            scan_type,
            SecurityScanType::ThreatIntel | SecurityScanType::Full
        ) {
            ctx.update_progress(0.85, Some("Checking threat intel".to_string()))
                .await?;
            self.check_threat_intel(scan_id, asset, &ip.to_string())
                .await?;
        }

        Ok(())
    }

    // ========================================================================
    // CERTIFICATE SCANNING
    // ========================================================================

    async fn scan_certificate(
        &self,
        _ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        _summary: &mut ScanResultSummary,
    ) -> Result<(), ApiError> {
        // Check certificate metadata for issues
        if let Some(metadata) = asset.metadata.as_object() {
            // Check for expiration
            if let Some(not_after) = metadata.get("not_after").and_then(|v| v.as_str()) {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(not_after) {
                    let now = Utc::now();
                    let days_until_expiry = (expiry.with_timezone(&Utc) - now).num_days();

                    if days_until_expiry < 0 {
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "expired_certificate",
                            FindingSeverity::Critical,
                            "Expired SSL/TLS Certificate",
                            Some(&format!(
                                "Certificate expired {} days ago",
                                -days_until_expiry
                            )),
                            json!({ "expiry_date": not_after, "days_overdue": -days_until_expiry }),
                        )
                        .await?;
                    } else if days_until_expiry < 30 {
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "certificate_expiring_soon",
                            FindingSeverity::High,
                            "Certificate Expiring Soon",
                            Some(&format!("Certificate expires in {} days", days_until_expiry)),
                            json!({ "expiry_date": not_after, "days_remaining": days_until_expiry }),
                        ).await?;
                    } else if days_until_expiry < 90 {
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "certificate_expiring_soon",
                            FindingSeverity::Medium,
                            "Certificate Expiring Within 90 Days",
                            Some(&format!("Certificate expires in {} days", days_until_expiry)),
                            json!({ "expiry_date": not_after, "days_remaining": days_until_expiry }),
                        ).await?;
                    }
                }
            }

            // Check for self-signed
            if let (Some(issuer), Some(subject)) = (
                metadata.get("issuer").and_then(|v| v.as_str()),
                metadata.get("subject").and_then(|v| v.as_str()),
            ) {
                if issuer == subject {
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "self_signed_certificate",
                        FindingSeverity::Medium,
                        "Self-Signed Certificate",
                        Some("Certificate is self-signed and may not be trusted by browsers"),
                        json!({ "subject": subject, "issuer": issuer }),
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // SECURITY CHECK IMPLEMENTATIONS
    // ========================================================================

    async fn scan_ports_with_findings(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        ip: IpAddr,
    ) -> Result<Vec<u16>, ApiError> {
        let settings = self.current_settings();
        let timeout = Duration::from_secs_f64(settings.tcp_scan_timeout);
        let open_ports = scan_ports(ip, COMMON_PORTS, timeout).await;

        for port in &open_ports {
            // Create informational finding for open ports
            let severity = match port {
                22 | 3389 => FindingSeverity::Info, // SSH, RDP - expected
                21 | 23 | 3306 | 5432 => FindingSeverity::Medium, // FTP, Telnet, MySQL, Postgres
                _ => FindingSeverity::Info,
            };

            let title = format!("Open Port: {}", port);
            let description = get_port_description(*port);

            self.create_finding(
                scan_id,
                asset.id,
                "open_port",
                severity,
                &title,
                Some(&description),
                json!({ "port": port, "ip": ip.to_string() }),
            )
            .await?;
        }

        Ok(open_ports)
    }

    async fn probe_http_with_findings(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        target: &str,
    ) -> Result<Option<i32>, ApiError> {
        let url = if target.contains("://") {
            target.to_string()
        } else if target.contains(':') {
            let port: u16 = target
                .split(':')
                .last()
                .and_then(|p| p.parse().ok())
                .unwrap_or(80);
            let scheme = if port == 443 || port == 8443 {
                "https"
            } else {
                "http"
            };
            format!("{}://{}", scheme, target)
        } else {
            format!("https://{}", target)
        };

        let response = self.http_prober.probe_url(&url).await;
        let status = response.status_code.map(|s| s as i32);

        // Check for HTTPS redirect
        if url.starts_with("http://") {
            if let Some(code) = response.status_code {
                if code != 301 && code != 302 {
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "https_not_enforced",
                        FindingSeverity::Medium,
                        "HTTPS Not Enforced",
                        Some("HTTP requests are not automatically redirected to HTTPS"),
                        json!({ "url": url, "status_code": code }),
                    )
                    .await?;
                }
            }
        }

        // Check for error response
        if let Some(error) = &response.error {
            self.create_finding(
                scan_id,
                asset.id,
                "http_probe_error",
                FindingSeverity::Info,
                "HTTP Probe Error",
                Some(error),
                json!({ "url": url, "error": error }),
            )
            .await?;
        }

        Ok(status)
    }

    async fn analyze_tls_with_findings(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        host: &str,
        port: u16,
    ) -> Result<Option<String>, ApiError> {
        match get_tls_certificate_info(host, port).await {
            Ok(cert_info) => {
                // Check certificate expiration using the not_after string field
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&cert_info.not_after) {
                    let now = Utc::now();
                    let expiry_utc = expiry.with_timezone(&Utc);
                    let days_until_expiry = (expiry_utc - now).num_days();

                    if days_until_expiry < 0 {
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "expired_certificate",
                            FindingSeverity::Critical,
                            "Expired SSL/TLS Certificate",
                            Some(&format!(
                                "The SSL/TLS certificate expired {} days ago",
                                -days_until_expiry
                            )),
                            json!({ "expiry_date": cert_info.not_after, "host": host }),
                        )
                        .await?;
                    } else if days_until_expiry < 30 {
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "certificate_expiring_soon",
                            FindingSeverity::High,
                            "Certificate Expiring Soon",
                            Some(&format!(
                                "Certificate expires in {} days",
                                days_until_expiry
                            )),
                            json!({ "expiry_date": cert_info.not_after, "host": host }),
                        )
                        .await?;
                    } else if days_until_expiry < 90 {
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "certificate_expiring_soon",
                            FindingSeverity::Medium,
                            "Certificate Expiring Within 90 Days",
                            Some(&format!(
                                "Certificate expires in {} days",
                                days_until_expiry
                            )),
                            json!({ "expiry_date": cert_info.not_after, "host": host }),
                        )
                        .await?;
                    }
                }

                // Check for self-signed certificate
                if cert_info.subject == cert_info.issuer {
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "self_signed_certificate",
                        FindingSeverity::Medium,
                        "Self-Signed Certificate",
                        Some("Certificate is self-signed and may not be trusted by browsers"),
                        json!({ "subject": cert_info.subject, "issuer": cert_info.issuer, "host": host }),
                    ).await?;
                }

                // Return the issuer as a proxy for TLS info
                Ok(Some(cert_info.issuer))
            }
            Err(e) => {
                tracing::debug!("TLS analysis failed for {}:{}: {}", host, port, e);
                Ok(None)
            }
        }
    }

    async fn check_dns_security(&self, _scan_id: Uuid, _asset: &Asset) -> Result<(), ApiError> {
        // This would check for DNSSEC, SPF, DKIM, DMARC records
        // Simplified for now - TODO: Implement DNS security checks
        Ok(())
    }

    async fn check_threat_intel(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        target: &str,
    ) -> Result<(), ApiError> {
        // Check threat intelligence for the target
        let threat_result = if target.parse::<IpAddr>().is_ok() {
            self.external_services.get_ip_threat_intel(target).await
        } else {
            self.external_services.get_domain_threat_intel(target).await
        };

        if let Ok(intel) = threat_result {
            if intel.is_malicious {
                self.create_finding(
                    scan_id,
                    asset.id,
                    "reputation_issue",
                    FindingSeverity::High,
                    "Malicious Reputation Detected",
                    Some(&format!(
                        "Target has malicious reputation from: {:?}",
                        intel.threat_sources
                    )),
                    json!({
                        "target": target,
                        "is_malicious": true,
                        "reputation_score": intel.reputation_score,
                        "threat_sources": intel.threat_sources,
                    }),
                )
                .await?;
            } else if intel
                .reputation_score
                .map(|s| (s as i64) < 50)
                .unwrap_or(false)
            {
                self.create_finding(
                    scan_id,
                    asset.id,
                    "reputation_issue",
                    FindingSeverity::Medium,
                    "Low Reputation Score",
                    Some(&format!(
                        "Target has low reputation score: {}",
                        intel.reputation_score.unwrap_or(0) as i64
                    )),
                    json!({
                        "target": target,
                        "reputation_score": intel.reputation_score,
                    }),
                )
                .await?;
            }
        }

        Ok(())
    }

    // ========================================================================
    // FINDING CREATION
    // ========================================================================

    async fn create_finding(
        &self,
        scan_id: Uuid,
        asset_id: Uuid,
        finding_type: &str,
        severity: FindingSeverity,
        title: &str,
        description: Option<&str>,
        data: Value,
    ) -> Result<SecurityFinding, ApiError> {
        let finding = SecurityFindingCreate {
            security_scan_id: Some(scan_id),
            asset_id,
            finding_type: finding_type.to_string(),
            severity,
            title: title.to_string(),
            description: description.map(String::from),
            remediation: get_remediation(finding_type),
            data,
            cvss_score: None,
            cve_ids: None,
            tags: None,
        };

        self.finding_repo.create_or_update(&finding).await
    }

    // ========================================================================
    // FINDINGS MANAGEMENT
    // ========================================================================

    pub async fn list_findings_for_asset(
        &self,
        asset_id: &Uuid,
    ) -> Result<Vec<SecurityFinding>, ApiError> {
        self.finding_repo.list_by_asset(asset_id, 1000).await
    }

    pub async fn get_finding(&self, id: &Uuid) -> Result<Option<SecurityFinding>, ApiError> {
        self.finding_repo.get_by_id(id).await
    }

    pub async fn get_findings_summary(
        &self,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        self.finding_repo.count_by_severity().await
    }
}

// Implement Clone for async task spawning
impl Clone for SecurityScanService {
    fn clone(&self) -> Self {
        Self {
            asset_repo: Arc::clone(&self.asset_repo),
            scan_repo: Arc::clone(&self.scan_repo),
            finding_repo: Arc::clone(&self.finding_repo),
            external_services: Arc::clone(&self.external_services),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_prober: Arc::clone(&self.http_prober),
            tls_analyzer: Arc::clone(&self.tls_analyzer),
            task_manager: Arc::clone(&self.task_manager),
            settings: Arc::clone(&self.settings),
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn get_port_description(port: u16) -> String {
    match port {
        21 => "FTP - File Transfer Protocol".to_string(),
        22 => "SSH - Secure Shell".to_string(),
        23 => "Telnet - Unencrypted remote access".to_string(),
        25 => "SMTP - Simple Mail Transfer Protocol".to_string(),
        53 => "DNS - Domain Name System".to_string(),
        80 => "HTTP - Web server".to_string(),
        110 => "POP3 - Post Office Protocol".to_string(),
        143 => "IMAP - Internet Message Access Protocol".to_string(),
        443 => "HTTPS - Secure web server".to_string(),
        3306 => "MySQL - Database server".to_string(),
        3389 => "RDP - Remote Desktop Protocol".to_string(),
        5432 => "PostgreSQL - Database server".to_string(),
        6379 => "Redis - In-memory database".to_string(),
        8080 => "HTTP Alternate - Web server".to_string(),
        8443 => "HTTPS Alternate - Secure web server".to_string(),
        _ => format!("Port {}", port),
    }
}

fn _is_weak_tls_version(version: &str) -> bool {
    matches!(
        version.to_uppercase().as_str(),
        "SSLV2" | "SSLV3" | "TLSV1" | "TLSV1.0" | "TLSV1.1"
    )
}

fn get_remediation(finding_type: &str) -> Option<String> {
    match finding_type {
        "weak_tls_version" => Some("Disable support for TLS versions older than TLS 1.2. Update server configuration to only support TLS 1.2 and TLS 1.3.".to_string()),
        "expired_certificate" => Some("Renew the SSL/TLS certificate immediately. Consider using automated certificate management with Let's Encrypt or similar services.".to_string()),
        "certificate_expiring_soon" => Some("Renew the SSL/TLS certificate before expiration. Set up automated renewal if possible.".to_string()),
        "self_signed_certificate" => Some("Replace self-signed certificate with a certificate from a trusted Certificate Authority.".to_string()),
        "missing_security_header" => Some("Add the missing security header to your web server configuration.".to_string()),
        "https_not_enforced" => Some("Configure HTTP to HTTPS redirect. Add Strict-Transport-Security header.".to_string()),
        "reputation_issue" => Some("Investigate the cause of the reputation issue. Check for malware, spam, or other malicious activity.".to_string()),
        _ => None,
    }
}

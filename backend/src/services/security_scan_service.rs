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
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    config::{Settings, SharedSettings},
    error::ApiError,
    models::{
        Asset, AssetType, DetectedService, DnsIssue, DnsSecurityResult, FindingSeverity,
        MissingSecurityHeader, ProxyDetectionResult, RiskFactor, ScanResultSummary,
        SecurityFinding, SecurityFindingCreate, SecurityHeadersResult, SecurityScan,
        SecurityScanCreate, SecurityScanType, VulnerabilityResult,
    },
    repositories::{AssetRepository, SecurityFindingRepository, SecurityScanRepository},
    services::{
        external::{DnsResolver, ExternalServicesManager, HttpProber, TlsAnalyzer},
        task_manager::{TaskContext, TaskManager, TaskType},
    },
    utils::{
        crypto::get_tls_certificate_info,
        network::{
            get_known_vulnerabilities, scan_ports_with_services,
            EXTENDED_PORTS, PROXY_HEADERS, SECURITY_HEADERS, WAF_SIGNATURES, CDN_SIGNATURES,
        },
    },
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
        ctx.update_progress(0.05, Some("Scan started".to_string()))
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
        let mut risk_factors = Vec::new();

        match asset.asset_type {
            AssetType::Domain => {
                self.scan_domain(ctx, scan_id, asset, &scan_type, &mut summary, &mut risk_factors)
                    .await?;
            }
            AssetType::Ip => {
                self.scan_ip(ctx, scan_id, asset, &scan_type, &mut summary, &mut risk_factors)
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
        summary.risk_factors = if risk_factors.is_empty() {
            None
        } else {
            Some(risk_factors)
        };

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
        risk_factors: &mut Vec<RiskFactor>,
    ) -> Result<(), ApiError> {
        let domain = &asset.identifier;

        // Step 1: DNS security checks
        ctx.update_progress(0.1, Some("Checking DNS security".to_string()))
            .await?;
        if matches!(scan_type, SecurityScanType::Full) {
            let dns_result = self.check_dns_security(scan_id, asset, domain).await?;
            summary.dns_security = Some(dns_result);
        }

        // Step 2: Resolve to IP and scan ports with service detection
        ctx.update_progress(0.2, Some("Resolving DNS".to_string()))
            .await?;
        match self.dns_resolver.resolve_hostname(domain).await {
            Ok(ips) => {
                if let Some(ip) = ips.first() {
                    // Port scan with service detection
                    if matches!(
                        scan_type,
                        SecurityScanType::PortScan | SecurityScanType::Full
                    ) {
                        ctx.update_progress(0.3, Some("Scanning ports and detecting services".to_string()))
                            .await?;
                        let (open_ports, services, vulns) = self
                            .scan_ports_with_service_detection(scan_id, asset, *ip, risk_factors)
                            .await?;
                        summary.open_ports = Some(open_ports);
                        summary.services_detected = Some(services);
                        if !vulns.is_empty() {
                            summary.vulnerabilities_found = Some(vulns);
                        }
                    }

                    // HTTP security analysis (headers, proxy detection, etc.)
                    if matches!(
                        scan_type,
                        SecurityScanType::HttpProbe | SecurityScanType::Full
                    ) {
                        ctx.update_progress(0.5, Some("Analyzing HTTP security".to_string()))
                            .await?;
                        let (http_result, proxy_result) = self
                            .analyze_http_security(scan_id, asset, domain, risk_factors)
                            .await?;
                        summary.security_headers = Some(http_result);
                        summary.proxy_detection = Some(proxy_result);
                        summary.http_status = summary
                            .security_headers
                            .as_ref()
                            .and_then(|_| Some(200)); // Placeholder
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
                risk_factors.push(RiskFactor {
                    factor_type: "dns".to_string(),
                    name: "DNS Resolution Failure".to_string(),
                    severity: "low".to_string(),
                    description: "Domain could not be resolved".to_string(),
                    impact_score: 0.1,
                    data: json!({ "error": e.to_string() }),
                });
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
                .analyze_tls_with_findings(scan_id, asset, domain, 443, risk_factors)
                .await?;
        }

        // Step 4: Threat intelligence
        if matches!(
            scan_type,
            SecurityScanType::ThreatIntel | SecurityScanType::Full
        ) {
            ctx.update_progress(0.85, Some("Checking threat intel".to_string()))
                .await?;
            self.check_threat_intel(scan_id, asset, domain, risk_factors)
                .await?;
        }

        ctx.update_progress(0.95, Some("Finalizing scan".to_string()))
            .await?;

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
        risk_factors: &mut Vec<RiskFactor>,
    ) -> Result<(), ApiError> {
        let ip: IpAddr = asset
            .identifier
            .parse()
            .map_err(|e| ApiError::Validation(format!("Invalid IP: {}", e)))?;

        // Port scan with service detection
        if matches!(
            scan_type,
            SecurityScanType::PortScan | SecurityScanType::Full
        ) {
            ctx.update_progress(0.2, Some("Scanning ports and detecting services".to_string()))
                .await?;
            let (open_ports, services, vulns) = self
                .scan_ports_with_service_detection(scan_id, asset, ip, risk_factors)
                .await?;
            summary.open_ports = Some(open_ports.clone());
            summary.services_detected = Some(services);
            if !vulns.is_empty() {
                summary.vulnerabilities_found = Some(vulns);
        }

        // HTTP probing on web ports
        if matches!(
            scan_type,
            SecurityScanType::HttpProbe | SecurityScanType::Full
        ) {
                ctx.update_progress(0.5, Some("Analyzing HTTP security".to_string()))
                .await?;
                for port in &open_ports {
                    if matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 8888 | 9000) {
                        let target = format!("{}:{}", ip, port);
                        let (http_result, proxy_result) = self
                            .analyze_http_security(scan_id, asset, &target, risk_factors)
                        .await?;
                        summary.security_headers = Some(http_result);
                        summary.proxy_detection = Some(proxy_result);
                        break; // Only analyze first web port for now
                    }
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
                        .analyze_tls_with_findings(scan_id, asset, &ip.to_string(), *port, risk_factors)
                        .await?;
                    break;
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
            self.check_threat_intel(scan_id, asset, &ip.to_string(), risk_factors)
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
            // Try to get domain from certificate subject for SSL Labs URL
            let domain = metadata
                .get("subject")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    // Extract domain from CN=domain.com format
                    s.split(',')
                        .find(|part| part.trim().starts_with("CN="))
                        .map(|cn| cn.trim().trim_start_matches("CN=").to_string())
                });

            let ssl_labs_url = domain.as_ref().map(|d| {
                format!("https://www.ssllabs.com/ssltest/analyze.html?d={}", d)
            });

            // Check for expiration
            if let Some(not_after) = metadata.get("not_after").and_then(|v| v.as_str()) {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(not_after) {
                    let now = Utc::now();
                    let days_until_expiry = (expiry.with_timezone(&Utc) - now).num_days();

                    if days_until_expiry < 0 {
                        let mut data = json!({ "expiry_date": not_after, "days_overdue": -days_until_expiry });
                        if let Some(url) = &ssl_labs_url {
                            data["source_url"] = json!(url);
                            data["source_name"] = json!("SSL Labs");
                        }
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
                            data,
                        )
                        .await?;
                    } else if days_until_expiry < 30 {
                        let mut data = json!({ "expiry_date": not_after, "days_remaining": days_until_expiry });
                        if let Some(url) = &ssl_labs_url {
                            data["source_url"] = json!(url);
                            data["source_name"] = json!("SSL Labs");
                        }
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "certificate_expiring_soon",
                            FindingSeverity::High,
                            "Certificate Expiring Soon",
                            Some(&format!("Certificate expires in {} days", days_until_expiry)),
                            data,
                        ).await?;
                    } else if days_until_expiry < 90 {
                        let mut data = json!({ "expiry_date": not_after, "days_remaining": days_until_expiry });
                        if let Some(url) = &ssl_labs_url {
                            data["source_url"] = json!(url);
                            data["source_name"] = json!("SSL Labs");
                        }
                        self.create_finding(
                            scan_id,
                            asset.id,
                            "certificate_expiring_soon",
                            FindingSeverity::Medium,
                            "Certificate Expiring Within 90 Days",
                            Some(&format!("Certificate expires in {} days", days_until_expiry)),
                            data,
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
                    let mut data = json!({ "subject": subject, "issuer": issuer });
                    if let Some(url) = &ssl_labs_url {
                        data["source_url"] = json!(url);
                        data["source_name"] = json!("SSL Labs");
                    }
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "self_signed_certificate",
                        FindingSeverity::Medium,
                        "Self-Signed Certificate",
                        Some("Certificate is self-signed and may not be trusted by browsers"),
                        data,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // ENHANCED PORT SCANNING WITH SERVICE DETECTION
    // ========================================================================

    async fn scan_ports_with_service_detection(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        ip: IpAddr,
        risk_factors: &mut Vec<RiskFactor>,
    ) -> Result<(Vec<u16>, Vec<DetectedService>, Vec<VulnerabilityResult>), ApiError> {
        let settings = self.current_settings();
        let timeout = Duration::from_secs_f64(settings.tcp_scan_timeout.max(1.0));
        let concurrency = settings.tcp_scan_concurrency as usize;

        // Scan extended port list with service detection
        let port_results = scan_ports_with_services(ip, EXTENDED_PORTS, timeout, concurrency).await;

        let mut open_ports = Vec::new();
        let mut services = Vec::new();
        let mut vulnerabilities = Vec::new();

        // Build Shodan URL for IP analysis
        let shodan_url = format!("https://www.shodan.io/host/{}", ip);

        for result in port_results {
            if !result.open {
                continue;
            }

            open_ports.push(result.port);

            let service_info = result.service.as_ref();
            let service_name = service_info
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let version = service_info.and_then(|s| s.version.clone());

            // Create detected service entry
            let detected_service = DetectedService {
                port: result.port,
                protocol: "tcp".to_string(),
                service_name: service_name.clone(),
                product: service_info.and_then(|s| s.product.clone()),
                version: version.clone(),
                banner: service_info.and_then(|s| s.banner.clone()),
                cpe: service_info.and_then(|s| s.cpe.clone()),
                confidence: service_info.map(|s| s.confidence).unwrap_or(30),
                is_encrypted: matches!(result.port, 443 | 993 | 995 | 465 | 636 | 8443 | 9443),
                vulnerabilities: Vec::new(),
            };
            services.push(detected_service);

            // Determine finding severity based on port type
            let (severity, finding_type, title, description) = self.categorize_port(result.port, &service_name);

            // Create finding for the open port
            self.create_finding(
                scan_id,
                asset.id,
                &finding_type,
                severity.clone(),
                &title,
                Some(&description),
                json!({
                    "port": result.port,
                    "ip": ip.to_string(),
                    "service": service_name,
                    "version": version,
                    "banner": service_info.and_then(|s| s.banner.clone()),
                    "cpe": service_info.and_then(|s| s.cpe.clone()),
                    "response_time_ms": result.response_time_ms,
                    "source_url": shodan_url,
                    "source_name": "Shodan",
                }),
            )
            .await?;

            // Check for known vulnerabilities
            if let Some(ver) = &version {
                let vulns = get_known_vulnerabilities(&service_name, ver);
                for vuln in vulns {
                    let vuln_severity = match vuln.severity.as_str() {
                        "critical" => FindingSeverity::Critical,
                        "high" => FindingSeverity::High,
                        "medium" => FindingSeverity::Medium,
                        _ => FindingSeverity::Low,
                    };

                    self.create_finding(
                        scan_id,
                        asset.id,
                        "known_cve",
                        vuln_severity,
                        &format!("{}: {}", vuln.cve_id, vuln.title),
                        Some(&vuln.description),
                        json!({
                            "cve_id": vuln.cve_id,
                            "cvss_score": vuln.cvss_score,
                            "cvss_vector": vuln.cvss_vector,
                            "affected_service": service_name,
                            "affected_version": ver,
                            "exploitable": vuln.exploitable,
                            "has_public_exploit": vuln.has_public_exploit,
                            "references": vuln.references,
                            "source_url": format!("https://nvd.nist.gov/vuln/detail/{}", vuln.cve_id),
                            "source_name": "NVD",
                        }),
                    )
                    .await?;

                    vulnerabilities.push(VulnerabilityResult {
                        cve_id: vuln.cve_id.clone(),
                        title: vuln.title.clone(),
                        severity: vuln.severity.clone(),
                        cvss_score: vuln.cvss_score,
                        affected_service: service_name.clone(),
                        affected_version: ver.clone(),
                        exploitable: vuln.exploitable,
                        has_public_exploit: vuln.has_public_exploit,
                        description: vuln.description.clone(),
                        remediation: Some(format!("Update {} to the latest version", service_name)),
                        references: vuln.references.clone(),
                    });

                    // Add risk factor for vulnerability
                    let impact = if vuln.exploitable { 0.9 } else { 0.5 };
                    risk_factors.push(RiskFactor {
                        factor_type: "vulnerability".to_string(),
                        name: format!("Known vulnerability: {}", vuln.cve_id),
                        severity: vuln.severity.clone(),
                        description: vuln.description.clone(),
                        impact_score: impact,
                        data: json!({ "cve_id": vuln.cve_id, "cvss_score": vuln.cvss_score }),
                    });
                }
            }

            // Add risk factor for sensitive ports
            if matches!(severity, FindingSeverity::High | FindingSeverity::Critical) {
                risk_factors.push(RiskFactor {
                    factor_type: "exposed_service".to_string(),
                    name: format!("Sensitive port {} exposed", result.port),
                    severity: format!("{:?}", severity).to_lowercase(),
                    description: description.clone(),
                    impact_score: 0.6,
                    data: json!({ "port": result.port, "service": service_name }),
                });
            }
        }

        Ok((open_ports, services, vulnerabilities))
    }

    fn categorize_port(&self, port: u16, service: &str) -> (FindingSeverity, String, String, String) {
        match port {
            // Critical - Dangerous services
            23 => (
                FindingSeverity::Critical,
                "sensitive_port".to_string(),
                format!("Telnet Service Exposed (Port {})", port),
                "Telnet transmits data in plaintext including credentials. This is extremely dangerous.".to_string(),
            ),
            // High - Database ports
            3306 | 5432 | 1433 | 1521 | 27017 | 27018 => (
                FindingSeverity::High,
                "database_exposed".to_string(),
                format!("Database Port {} Open ({})", port, service),
                format!("Database service {} is exposed to the internet. This could allow unauthorized access to sensitive data.", service),
            ),
            // High - Admin/Remote access
            3389 => (
                FindingSeverity::High,
                "admin_port_exposed".to_string(),
                "Remote Desktop (RDP) Exposed".to_string(),
                "Remote Desktop Protocol is exposed to the internet, making it a target for brute force attacks.".to_string(),
            ),
            5900 | 5901 => (
                FindingSeverity::High,
                "admin_port_exposed".to_string(),
                "VNC Exposed".to_string(),
                "VNC remote access is exposed to the internet.".to_string(),
            ),
            6379 => (
                FindingSeverity::High,
                "database_exposed".to_string(),
                "Redis Exposed".to_string(),
                "Redis in-memory database is exposed. Redis often has no authentication by default.".to_string(),
            ),
            9200 | 9300 => (
                FindingSeverity::High,
                "database_exposed".to_string(),
                "Elasticsearch Exposed".to_string(),
                "Elasticsearch service is exposed to the internet.".to_string(),
            ),
            // Medium - Sensitive services
            21 => (
                FindingSeverity::Medium,
                "sensitive_port".to_string(),
                format!("FTP Service Exposed (Port {})", port),
                "FTP often transmits credentials in plaintext. Consider using SFTP instead.".to_string(),
            ),
            25 | 587 => (
                FindingSeverity::Medium,
                "open_port".to_string(),
                format!("SMTP Service Exposed (Port {})", port),
                "SMTP service detected. Ensure proper authentication is configured.".to_string(),
            ),
            445 => (
                FindingSeverity::Medium,
                "sensitive_port".to_string(),
                "SMB Service Exposed (Port 445)".to_string(),
                "SMB/CIFS file sharing is exposed. This can be a vector for ransomware and lateral movement.".to_string(),
            ),
            // Low - Common services
            22 => (
                FindingSeverity::Info,
                "open_port".to_string(),
                "SSH Service Detected".to_string(),
                "SSH service is accessible. Ensure strong authentication and key-based access.".to_string(),
            ),
            80 | 8080 | 8000 | 8888 => (
                FindingSeverity::Info,
                "open_port".to_string(),
                format!("HTTP Service (Port {})", port),
                "HTTP web server detected.".to_string(),
            ),
            443 | 8443 => (
                FindingSeverity::Info,
                "open_port".to_string(),
                format!("HTTPS Service (Port {})", port),
                "HTTPS web server detected.".to_string(),
            ),
            // Default
            _ => (
                FindingSeverity::Info,
                "open_port".to_string(),
                format!("Open Port: {} ({})", port, service),
                format!("Service {} detected on port {}", service, port),
            ),
        }
    }

    // ========================================================================
    // HTTP SECURITY ANALYSIS
    // ========================================================================

    async fn analyze_http_security(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        target: &str,
        risk_factors: &mut Vec<RiskFactor>,
    ) -> Result<(SecurityHeadersResult, ProxyDetectionResult), ApiError> {
        let mut security_result = SecurityHeadersResult::default();
        let mut proxy_result = ProxyDetectionResult::default();

        // Build URL
        let url = if target.contains("://") {
            target.to_string()
        } else if target.contains(':') {
            let port: u16 = target
                .split(':')
                .last()
                .and_then(|p| p.parse().ok())
                .unwrap_or(80);
            let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
            format!("{}://{}", scheme, target)
        } else {
            format!("https://{}", target)
        };

        security_result.url = url.clone();
        security_result.is_https = url.starts_with("https");

        // Make a direct HTTP request to get headers
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| ApiError::HttpClient(e))?;

        let response = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!("Failed to fetch headers for {}: {}", url, e);
                return Ok((security_result, proxy_result));
            }
        };

        // Convert headers to HashMap
        let headers_map: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()))
            .collect();

        // Check for security headers
            let mut missing_headers = Vec::new();
            let mut present_headers = Vec::new();
            let mut score: u8 = 100;

            for (header, severity, desc, rec) in SECURITY_HEADERS {
                let header_lower = header.to_lowercase();
                if headers_map.contains_key(&header_lower) {
                    present_headers.push(header.to_string());
                    
                    // Check specific header values
                    if header_lower == "strict-transport-security" {
                        if let Some(value) = headers_map.get(&header_lower) {
                            security_result.hsts_enabled = true;
                            // Parse max-age
                            if let Some(max_age_str) = value.split(';').find(|s| s.trim().starts_with("max-age")) {
                                if let Some(age) = max_age_str.split('=').nth(1) {
                                    security_result.hsts_max_age = age.trim().parse().ok();
                                }
                            }
                        }
                    }
                    if header_lower == "content-security-policy" {
                        security_result.csp_present = true;
                        security_result.csp_policy = headers_map.get(&header_lower).cloned();
                    }
                    if header_lower == "x-frame-options" {
                        security_result.x_frame_options = headers_map.get(&header_lower).cloned();
                    }
                } else {
                    let severity_impact = match *severity {
                        "critical" => 20,
                        "high" => 15,
                        "medium" => 10,
                        "low" => 5,
                        _ => 3,
                    };
                    score = score.saturating_sub(severity_impact);

                    missing_headers.push(MissingSecurityHeader {
                        name: header.to_string(),
                        severity: severity.to_string(),
                        description: desc.to_string(),
                        recommendation: rec.to_string(),
                    });

                    // Create finding for missing security header
                    let finding_severity = match *severity {
                        "critical" => FindingSeverity::High,
                        "high" => FindingSeverity::High,
                        "medium" => FindingSeverity::Medium,
                        _ => FindingSeverity::Low,
                    };

                    self.create_finding(
                        scan_id,
                        asset.id,
                        "missing_security_header",
                        finding_severity,
                        &format!("Missing Security Header: {}", header),
                        Some(desc),
                        json!({
                            "header": header,
                            "severity": severity,
                            "recommendation": rec,
                            "url": url,
                        }),
                    )
                    .await?;
                }
            }

            security_result.headers_present = present_headers;
            security_result.headers_missing = missing_headers;
            security_result.score = score;

            // Check for server version disclosure
            if let Some(server) = headers_map.get("server") {
                security_result.server_info = Some(server.clone());
                
                // Check if version is disclosed
                if server.contains('/') || regex::Regex::new(r"\d+\.\d+").unwrap().is_match(server) {
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "server_version_exposed",
                        FindingSeverity::Low,
                        "Server Version Disclosed",
                        Some(&format!("Server header reveals version information: {}", server)),
                        json!({
                            "header": "Server",
                            "value": server,
                            "url": url,
                        }),
                    )
                    .await?;

                    risk_factors.push(RiskFactor {
                        factor_type: "information_disclosure".to_string(),
                        name: "Server version exposed".to_string(),
                        severity: "low".to_string(),
                        description: format!("Server header reveals: {}", server),
                        impact_score: 0.15,
                        data: json!({ "server": server }),
                    });
                }
            }

            // Check for proxy/WAF/CDN
            proxy_result = self.detect_proxy_waf_cdn(&headers_map).await;

            if !proxy_result.waf_detected {
                self.create_finding(
                    scan_id,
                    asset.id,
                    "no_waf_detected",
                    FindingSeverity::Low,
                    "No WAF Detected",
                    Some("No Web Application Firewall was detected protecting this asset"),
                    json!({
                        "url": url,
                        "recommendation": "Consider implementing a WAF for additional protection",
                    }),
                )
                .await?;

                risk_factors.push(RiskFactor {
                    factor_type: "protection".to_string(),
                    name: "No WAF protection".to_string(),
                    severity: "low".to_string(),
                    description: "No Web Application Firewall detected".to_string(),
                    impact_score: 0.2,
                    data: json!({}),
                });
            }

            if proxy_result.cdn_detected {
                // CDN is detected - good for protection
                if let Some(provider) = &proxy_result.cdn_provider {
                    tracing::info!("CDN detected: {}", provider);
                }
            }

            // HTTPS enforcement check
            if !security_result.is_https {
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "https_not_enforced",
                        FindingSeverity::Medium,
                        "HTTPS Not Enforced",
                    Some("The asset is accessible over unencrypted HTTP"),
                    json!({
                        "url": url,
                        "recommendation": "Enforce HTTPS and implement HSTS",
                    }),
                    )
                    .await?;

                risk_factors.push(RiskFactor {
                    factor_type: "encryption".to_string(),
                    name: "Unencrypted connection".to_string(),
                    severity: "medium".to_string(),
                    description: "Traffic is not encrypted with HTTPS".to_string(),
                    impact_score: 0.4,
                    data: json!({ "url": url }),
                });
            } else if !security_result.hsts_enabled {
                risk_factors.push(RiskFactor {
                    factor_type: "encryption".to_string(),
                    name: "HSTS not enabled".to_string(),
                    severity: "low".to_string(),
                    description: "HTTP Strict Transport Security is not enabled".to_string(),
                    impact_score: 0.15,
                    data: json!({ "url": url }),
                });
            }

        Ok((security_result, proxy_result))
    }

    async fn detect_proxy_waf_cdn(&self, headers: &HashMap<String, String>) -> ProxyDetectionResult {
        let mut result = ProxyDetectionResult::default();

        // Check for proxy headers
        for header in PROXY_HEADERS {
            let header_lower = header.to_lowercase();
            if headers.contains_key(&header_lower) {
                result.behind_proxy = true;
                result.proxy_headers_found.push(header.to_string());
            }
        }

        // Check for WAF signatures
        let all_headers_text: String = headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();

        for (signature, waf_name) in WAF_SIGNATURES {
            if all_headers_text.contains(signature) {
                result.waf_detected = true;
                result.waf_type = Some(waf_name.to_string());
                result.waf_signatures.push(signature.to_string());
                break;
            }
        }

        // Check for CDN signatures
        for (signature, cdn_name) in CDN_SIGNATURES {
            if all_headers_text.contains(signature) {
                result.cdn_detected = true;
                result.cdn_provider = Some(cdn_name.to_string());
                break;
            }
        }

        // Specific header checks
        if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
            result.cdn_detected = true;
            result.cdn_provider = Some("Cloudflare".to_string());
            result.waf_detected = true;
            result.waf_type = Some("Cloudflare WAF".to_string());
        }

        if headers.contains_key("x-amz-cf-id") || headers.contains_key("x-amz-cf-pop") {
            result.cdn_detected = true;
            result.cdn_provider = Some("Amazon CloudFront".to_string());
        }

        if headers.contains_key("x-cache") {
            let x_cache = headers.get("x-cache").unwrap();
            if x_cache.contains("cloudfront") {
                result.cdn_detected = true;
                result.cdn_provider = Some("Amazon CloudFront".to_string());
            }
        }

        // Load balancer detection
        if headers.contains_key("x-served-by") || headers.contains_key("x-backend-server") {
            result.load_balancer_detected = true;
        }

        result
    }

    // ========================================================================
    // DNS SECURITY CHECKS
    // ========================================================================

    async fn check_dns_security(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        domain: &str,
    ) -> Result<DnsSecurityResult, ApiError> {
        let mut result = DnsSecurityResult {
            domain: domain.to_string(),
            ..Default::default()
        };

        // Check SPF record
        match self.dns_resolver.lookup_txt(&format!("{}.", domain)).await {
            Ok(records) => {
                for record in &records {
                    if record.starts_with("v=spf1") {
                        result.has_spf = true;
                        result.spf_record = Some(record.clone());
                        result.spf_valid = !record.contains("+all"); // +all is too permissive
                        
                        if record.contains("+all") {
                            result.spf_issues.push("SPF record contains +all which allows any IP to send mail".to_string());
                        }
                        if record.contains("~all") {
                            result.spf_issues.push("SPF record uses soft fail (~all), consider using hard fail (-all)".to_string());
                        }
                    }
                }
            }
            Err(_) => {}
        }

        if !result.has_spf {
            self.create_finding(
                scan_id,
                asset.id,
                "missing_spf",
                FindingSeverity::Medium,
                "Missing SPF Record",
                Some("No SPF record found. This allows anyone to send email pretending to be from this domain."),
                json!({
                    "domain": domain,
                    "recommendation": "Add an SPF record to specify authorized mail servers",
                }),
            )
            .await?;

            result.issues.push(DnsIssue {
                issue_type: "missing_spf".to_string(),
                severity: "medium".to_string(),
                title: "Missing SPF Record".to_string(),
                description: "No SPF record found for domain".to_string(),
                remediation: "Add an SPF record: v=spf1 include:_spf.google.com -all".to_string(),
            });
        }

        // Check DMARC record
        match self.dns_resolver.lookup_txt(&format!("_dmarc.{}.", domain)).await {
            Ok(records) => {
                for record in &records {
                    if record.starts_with("v=DMARC1") {
                        result.has_dmarc = true;
                        result.dmarc_record = Some(record.clone());
                        
                        // Parse policy
                        if let Some(policy_match) = regex::Regex::new(r"p=(\w+)")
                            .ok()
                            .and_then(|re| re.captures(record))
                        {
                            result.dmarc_policy = Some(policy_match[1].to_string());
                            
                            if &policy_match[1] == "none" {
                                result.dmarc_issues.push("DMARC policy is 'none' - emails are not rejected".to_string());
                                
                                self.create_finding(
                                    scan_id,
                                    asset.id,
                                    "weak_dmarc_policy",
                                    FindingSeverity::Low,
                                    "Weak DMARC Policy",
                                    Some("DMARC policy is set to 'none', providing monitoring only"),
                                    json!({
                                        "domain": domain,
                                        "policy": "none",
                                        "recommendation": "Consider upgrading to p=quarantine or p=reject",
                                    }),
                                )
                                .await?;
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        if !result.has_dmarc {
            self.create_finding(
                scan_id,
                asset.id,
                "missing_dmarc",
                FindingSeverity::Medium,
                "Missing DMARC Record",
                Some("No DMARC record found. Email authentication policies are not enforced."),
                json!({
                    "domain": domain,
                    "recommendation": "Add a DMARC record at _dmarc.{domain}",
                }),
            )
            .await?;

            result.issues.push(DnsIssue {
                issue_type: "missing_dmarc".to_string(),
                severity: "medium".to_string(),
                title: "Missing DMARC Record".to_string(),
                description: "No DMARC record found for domain".to_string(),
                remediation: "Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string(),
            });
        }

        // Check CAA records
        match self.dns_resolver.lookup_caa(domain).await {
            Ok(records) => {
                result.has_caa = !records.is_empty();
                result.caa_records = records;
            }
            Err(_) => {}
        }

        if !result.has_caa {
            self.create_finding(
                scan_id,
                asset.id,
                "missing_caa",
                FindingSeverity::Low,
                "Missing CAA Records",
                Some("No CAA records found. Any CA can issue certificates for this domain."),
                json!({
                    "domain": domain,
                    "recommendation": "Add CAA records to specify authorized Certificate Authorities",
                }),
            )
            .await?;
        }

        // Get nameservers
        match self.dns_resolver.lookup_ns(domain).await {
            Ok(ns) => {
                result.nameservers = ns;
            }
            Err(_) => {}
        }

        Ok(result)
    }

    // ========================================================================
    // TLS ANALYSIS
    // ========================================================================

    async fn analyze_tls_with_findings(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        host: &str,
        port: u16,
        risk_factors: &mut Vec<RiskFactor>,
    ) -> Result<Option<String>, ApiError> {
        match get_tls_certificate_info(host, port).await {
            Ok(cert_info) => {
                // Build SSL Labs URL for certificate analysis (only for domains, not IPs)
                let ssl_labs_url = if host.parse::<IpAddr>().is_err() {
                    Some(format!(
                        "https://www.ssllabs.com/ssltest/analyze.html?d={}",
                        host
                    ))
                } else {
                    None
                };

                // Check certificate expiration using the not_after string field
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(&cert_info.not_after) {
                    let now = Utc::now();
                    let expiry_utc = expiry.with_timezone(&Utc);
                    let days_until_expiry = (expiry_utc - now).num_days();

                    if days_until_expiry < 0 {
                        let mut data = json!({ "expiry_date": cert_info.not_after, "host": host });
                        if let Some(url) = &ssl_labs_url {
                            data["source_url"] = json!(url);
                            data["source_name"] = json!("SSL Labs");
                        }
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
                            data,
                        )
                        .await?;

                        risk_factors.push(RiskFactor {
                            factor_type: "certificate".to_string(),
                            name: "Expired certificate".to_string(),
                            severity: "critical".to_string(),
                            description: format!("Certificate expired {} days ago", -days_until_expiry),
                            impact_score: 0.95,
                            data: json!({ "days_expired": -days_until_expiry }),
                        });
                    } else if days_until_expiry < 30 {
                        let mut data = json!({ "expiry_date": cert_info.not_after, "host": host });
                        if let Some(url) = &ssl_labs_url {
                            data["source_url"] = json!(url);
                            data["source_name"] = json!("SSL Labs");
                        }
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
                            data,
                        )
                        .await?;

                        risk_factors.push(RiskFactor {
                            factor_type: "certificate".to_string(),
                            name: "Certificate expiring soon".to_string(),
                            severity: "high".to_string(),
                            description: format!("Certificate expires in {} days", days_until_expiry),
                            impact_score: 0.6,
                            data: json!({ "days_remaining": days_until_expiry }),
                        });
                    } else if days_until_expiry < 90 {
                        let mut data = json!({ "expiry_date": cert_info.not_after, "host": host });
                        if let Some(url) = &ssl_labs_url {
                            data["source_url"] = json!(url);
                            data["source_name"] = json!("SSL Labs");
                        }
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
                            data,
                        )
                        .await?;
                    }
                }

                // Check for self-signed certificate
                if cert_info.subject == cert_info.issuer {
                    let mut data = json!({ "subject": cert_info.subject, "issuer": cert_info.issuer, "host": host });
                    if let Some(url) = &ssl_labs_url {
                        data["source_url"] = json!(url);
                        data["source_name"] = json!("SSL Labs");
                    }
                    self.create_finding(
                        scan_id,
                        asset.id,
                        "self_signed_certificate",
                        FindingSeverity::Medium,
                        "Self-Signed Certificate",
                        Some("Certificate is self-signed and may not be trusted by browsers"),
                        data,
                    ).await?;

                    risk_factors.push(RiskFactor {
                        factor_type: "certificate".to_string(),
                        name: "Self-signed certificate".to_string(),
                        severity: "medium".to_string(),
                        description: "Certificate is self-signed".to_string(),
                        impact_score: 0.4,
                        data: json!({}),
                    });
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

    // ========================================================================
    // THREAT INTELLIGENCE
    // ========================================================================

    async fn check_threat_intel(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        target: &str,
        risk_factors: &mut Vec<RiskFactor>,
    ) -> Result<(), ApiError> {
        // Check threat intelligence for the target
        let threat_result = if target.parse::<IpAddr>().is_ok() {
            self.external_services.get_ip_threat_intel(target).await
        } else {
            self.external_services.get_domain_threat_intel(target).await
        };

        if let Ok(intel) = threat_result {
            // Build VirusTotal URL for the target
            let source_url = if target.parse::<IpAddr>().is_ok() {
                format!("https://www.virustotal.com/gui/ip-address/{}", target)
            } else {
                format!("https://www.virustotal.com/gui/domain/{}", target)
            };

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
                        "source_url": source_url,
                        "source_name": "VirusTotal",
                    }),
                )
                .await?;

                risk_factors.push(RiskFactor {
                    factor_type: "reputation".to_string(),
                    name: "Malicious reputation".to_string(),
                    severity: "high".to_string(),
                    description: "Target is flagged as malicious by threat intelligence".to_string(),
                    impact_score: 0.9,
                    data: json!({ "sources": intel.threat_sources }),
                });
            } else if intel
                .reputation_score
                .map(|s| (s as i64) < 0)
                .unwrap_or(false)
            {
                let score = intel.reputation_score.unwrap_or(0) as i64;
                let severity = if score <= -50 {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                };

                self.create_finding(
                    scan_id,
                    asset.id,
                    "reputation_issue",
                    severity,
                    "Negative Reputation Score",
                    Some(&format!(
                        "Target has negative reputation score: {} (scale: -100 to +100, negative is bad)",
                        score
                    )),
                    json!({
                        "target": target,
                        "reputation_score": intel.reputation_score,
                        "source_url": source_url,
                        "source_name": "VirusTotal",
                    }),
                )
                .await?;

                risk_factors.push(RiskFactor {
                    factor_type: "reputation".to_string(),
                    name: "Negative reputation".to_string(),
                    severity: if score <= -50 { "high" } else { "medium" }.to_string(),
                    description: format!("Reputation score: {}", score),
                    impact_score: if score <= -50 { 0.7 } else { 0.4 },
                    data: json!({ "score": score }),
                });
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

fn get_remediation(finding_type: &str) -> Option<String> {
    match finding_type {
        "weak_tls_version" => Some("Disable support for TLS versions older than TLS 1.2. Update server configuration to only support TLS 1.2 and TLS 1.3.".to_string()),
        "expired_certificate" => Some("Renew the SSL/TLS certificate immediately. Consider using automated certificate management with Let's Encrypt or similar services.".to_string()),
        "certificate_expiring_soon" => Some("Renew the SSL/TLS certificate before expiration. Set up automated renewal if possible.".to_string()),
        "self_signed_certificate" => Some("Replace self-signed certificate with a certificate from a trusted Certificate Authority.".to_string()),
        "missing_security_header" => Some("Add the missing security header to your web server configuration.".to_string()),
        "https_not_enforced" => Some("Configure HTTP to HTTPS redirect. Add Strict-Transport-Security header.".to_string()),
        "reputation_issue" => Some("Investigate the cause of the reputation issue. Check for malware, spam, or other malicious activity.".to_string()),
        "database_exposed" => Some("Restrict database access to internal networks only. Use a firewall or security group to block external access.".to_string()),
        "sensitive_port" => Some("Close unnecessary ports. If the service is required, ensure proper authentication and encryption.".to_string()),
        "admin_port_exposed" => Some("Restrict administrative access to VPN or bastion hosts. Never expose admin interfaces directly to the internet.".to_string()),
        "server_version_exposed" => Some("Configure your web server to hide version information in the Server header.".to_string()),
        "no_waf_detected" => Some("Consider implementing a Web Application Firewall (WAF) to protect against common web attacks.".to_string()),
        "missing_spf" => Some("Add an SPF record to your DNS: v=spf1 include:_spf.google.com -all (adjust based on your mail providers)".to_string()),
        "missing_dmarc" => Some("Add a DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com".to_string()),
        "missing_caa" => Some("Add CAA records to restrict which Certificate Authorities can issue certificates for your domain.".to_string()),
        "weak_dmarc_policy" => Some("Upgrade your DMARC policy from 'none' to 'quarantine' or 'reject' to actively block fraudulent emails.".to_string()),
        "known_cve" => Some("Update the affected software to the latest version to patch the known vulnerability.".to_string()),
        _ => None,
    }
}

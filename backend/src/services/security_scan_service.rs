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
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    config::{Settings, SharedSettings},
    error::ApiError,
    models::{
        Asset, AssetType, DetectedService, DnsIssue, DnsSecurityResult, FindingSeverity,
        MissingSecurityHeader, ProxyDetectionResult, RiskFactor, ScanConfig, ScanResultSummary,
        SecurityFinding, SecurityFindingCreate, SecurityHeadersResult, SecurityScan,
        SecurityScanCreate, SecurityScanStatus, SecurityScanType, TlsCertificateDetails,
        TlsCertificateInfo, VulnerabilityResult,
    },
    repositories::{AssetRepository, SecurityFindingRepository, SecurityScanRepository},
    services::{
        external::{
            http::{extract_icon_link, shodan_favicon_hash},
            DnsResolver, ExternalServicesManager, HttpProber, NvdClient, ThreatIntelClient,
            TlsAnalyzer,
        },
        risk_service::RiskService,
        scanners::{dns_scan, http_scan, tls_scan, ScanFinding},
        task_manager::{TaskContext, TaskManager, TaskType},
    },
    utils::{
        cpe::Cpe,
        crypto::get_tls_certificate_info,
        network::{
            get_known_vulnerabilities, is_internal_ip, scan_ports, scan_ports_with_services,
            CDN_SIGNATURES, EXTENDED_PORTS, PROXY_HEADERS, SECURITY_HEADERS, WAF_SIGNATURES,
        },
    },
};

const DEFAULT_IP_HTTP_FALLBACK_PORTS: [u16; 4] = [443, 8443, 80, 8080];

/// Finding types that only a deep scan can produce, because the probe that finds
/// them — sensitive-path fetching, HTTP method probing, the AXFR attempt — is
/// skipped when `ScanConfig.deep` is false.
///
/// They are excluded from auto-resolution on a shallow scan. Without that, a
/// quick sweep would close an existing critical `.env` exposure or an open zone
/// transfer purely by not having looked for it.
const DEEP_ONLY_FINDING_TYPES: &[&str] = &[
    "sensitive_data_exposed",
    "debug_endpoint_exposed",
    "security_txt_missing",
    "dangerous_http_method",
    "zone_transfer_allowed",
];

/// Cap on how many referenced JS/CSS assets we fetch per page when recovering
/// version banners for versionless technology detections.
const MAX_ASSET_FETCHES: usize = 8;
/// Skip assets larger than this (bytes) when banner-parsing — bounds work/memory.
const MAX_ASSET_BYTES: usize = 5_000_000;
/// Hard cap on how much of a page body we read. The fingerprint engine only
/// scans the first megabyte anyway; this stops a hostile or misconfigured
/// endpoint from streaming unbounded data into memory before it gets there.
const MAX_PAGE_BYTES: usize = 2_000_000;
/// Favicons are icons; anything larger is not one.
const MAX_FAVICON_BYTES: usize = 512 * 1024;
/// Cap on `robots.txt`.
const MAX_ROBOTS_BYTES: usize = 128 * 1024;

// Product banners recognised inside `Server` / `X-Powered-By` / `X-Generator`.
//
// Compiled once. These used to be rebuilt from source on every header value of
// every response, which is eight regex compilations per header per asset.
lazy_static::lazy_static! {
    static ref HEADER_BANNER_PATTERNS: Vec<(&'static str, regex::Regex, u8)> = [
        ("next.js", r"(?i)\bnext(?:\.| )?js(?:[/\s]+v?([0-9][0-9A-Za-z._-]*))?", 95u8),
        ("nginx", r"(?i)\bnginx(?:/([0-9][0-9A-Za-z._-]*))?", 90),
        ("apache", r"(?i)\bapache(?:/([0-9][0-9A-Za-z._-]*))?", 90),
        ("iis", r"(?i)\b(?:microsoft-)?iis(?:/([0-9][0-9A-Za-z._-]*))?", 90),
        ("express", r"(?i)\bexpress(?:/([0-9][0-9A-Za-z._-]*))?", 85),
        ("php", r"(?i)\bphp(?:/([0-9][0-9A-Za-z._-]*))?", 85),
        ("wordpress", r"(?i)\bwordpress(?:[/\s]+v?([0-9][0-9A-Za-z._-]*))?", 85),
        ("asp.net", r"(?i)\basp\.?net(?:[/\s]+v?([0-9][0-9A-Za-z._-]*))?", 85),
    ]
    .into_iter()
    .filter_map(|(product, pattern, confidence)| match regex::Regex::new(pattern) {
        Ok(re) => Some((product, re, confidence)),
        Err(e) => {
            tracing::error!("invalid header banner pattern for {}: {}", product, e);
            None
        }
    })
    .collect();
}

/// One fetched HTTP response, reduced to the signals fingerprinting reads.
struct FetchedPage {
    /// URL that actually answered, after redirects and any scheme fallback.
    final_url: String,
    /// Response headers, keys lowercased.
    headers: HashMap<String, String>,
    /// Raw `Set-Cookie` values.
    set_cookies: Vec<String>,
    /// Body, capped at `MAX_PAGE_BYTES`.
    body: String,
}
/// Browser-like User-Agent for HTTP analysis fetches. Many WAFs/CDNs serve a
/// challenge or reduced page to obvious bot agents (e.g. the default
/// `reqwest/x`), which hides the very markup we fingerprint. Presenting a real
/// browser UA gets the actual page so detection sees what a browser would.
const BROWSER_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/124.0.0.0 Safari/537.36";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HttpTechnologyFingerprint {
    product: String,
    version: Option<String>,
    header_name: String,
    raw_evidence: String,
    confidence: u8,
}

#[derive(Debug, Default)]
struct HttpSecurityAnalysisOutcome {
    security_headers: SecurityHeadersResult,
    proxy_detection: ProxyDetectionResult,
    vulnerabilities: Vec<VulnerabilityResult>,
    technology_stack: Vec<String>,
    /// The deep HTTP assessment. `None` when the endpoint did not answer.
    http: Option<http_scan::HttpScanResult>,
}

pub struct SecurityScanService {
    // Repositories
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    scan_repo: Arc<dyn SecurityScanRepository + Send + Sync>,
    finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
    risk_service: Arc<RiskService>,

    // External services
    external_services: Arc<ExternalServicesManager>,
    dns_resolver: Arc<DnsResolver>,
    http_prober: Arc<HttpProber>,
    tls_analyzer: Arc<TlsAnalyzer>,
    nvd_client: Arc<NvdClient>,
    threat_intel: Arc<ThreatIntelClient>,

    // Utilities
    task_manager: Arc<TaskManager>,
    settings: SharedSettings,
}

impl SecurityScanService {
    pub fn new(
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
        scan_repo: Arc<dyn SecurityScanRepository + Send + Sync>,
        finding_repo: Arc<dyn SecurityFindingRepository + Send + Sync>,
        risk_service: Arc<RiskService>,
        external_services: Arc<ExternalServicesManager>,
        dns_resolver: Arc<DnsResolver>,
        http_prober: Arc<HttpProber>,
        tls_analyzer: Arc<TlsAnalyzer>,
        task_manager: Arc<TaskManager>,
        settings: SharedSettings,
    ) -> Self {
        // Create NVD client for vulnerability lookups
        let nvd_client = Arc::new(NvdClient::new().expect("Failed to create NVD client"));
        // CISA KEV + FIRST EPSS, for ranking the CVEs NVD returns.
        let threat_intel = Arc::new(ThreatIntelClient::new());

        Self {
            asset_repo,
            scan_repo,
            finding_repo,
            risk_service,
            external_services,
            dns_resolver,
            http_prober,
            nvd_client,
            threat_intel,
            tls_analyzer,
            task_manager,
            settings,
        }
    }

    fn current_settings(&self) -> Arc<Settings> {
        self.settings.load_full()
    }

    fn should_block_internal(&self, settings: &Settings) -> bool {
        settings.block_internal_ip_scans
            || (settings.environment.eq_ignore_ascii_case("production")
                && !settings.allow_internal_scans)
    }

    fn is_domain_allowed(&self, settings: &Settings, domain: &str) -> bool {
        if settings.scan_allowlist_domains.is_empty() {
            return true;
        }
        let candidate = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        settings.scan_allowlist_domains.iter().any(|allowed| {
            let allowed = allowed.trim().trim_end_matches('.').to_ascii_lowercase();
            candidate == allowed || candidate.ends_with(&format!(".{}", allowed))
        })
    }

    fn is_ip_allowed(&self, settings: &Settings, ip: IpAddr) -> bool {
        if self.should_block_internal(settings) && is_internal_ip(ip) {
            return false;
        }
        if !settings.scan_allowlist_cidrs.is_empty()
            && !settings
                .scan_allowlist_cidrs
                .iter()
                .any(|net| net.contains(&ip))
        {
            return false;
        }
        true
    }

    fn validate_asset_target(&self, settings: &Settings, asset: &Asset) -> Result<(), ApiError> {
        match asset.asset_type {
            AssetType::Domain => {
                if !self.is_domain_allowed(settings, &asset.identifier) {
                    return Err(ApiError::Validation(
                        "Domain target not permitted by scan policy".to_string(),
                    ));
                }
            }
            AssetType::Ip => {
                let ip: IpAddr = asset
                    .identifier
                    .parse()
                    .map_err(|_| ApiError::Validation("Invalid IP asset identifier".to_string()))?;
                if !self.is_ip_allowed(settings, ip) {
                    return Err(ApiError::Validation(
                        "IP target not permitted by scan policy".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ========================================================================
    // SCAN MANAGEMENT
    // ========================================================================

    /// Create a new security scan for an asset
    /// Create a new security scan for an asset
    pub async fn create_scan(
        &self,
        scan_create: SecurityScanCreate,
        company_id: Uuid,
        requested_by: Option<Uuid>,
    ) -> Result<SecurityScan, ApiError> {
        if let Some(user_id) = requested_by {
            let settings = self.current_settings();
            let active = self
                .task_manager
                .count_active_tasks_by_requester(&user_id.to_string(), TaskType::Scan)
                .await;
            if active >= settings.max_active_scans_per_user as usize {
                return Err(ApiError::RateLimit(format!(
                    "Too many active scan tasks (limit {})",
                    settings.max_active_scans_per_user
                )));
            }
        }

        // Verify asset exists
        let asset = self
            .asset_repo
            .get_by_id(company_id, &scan_create.asset_id)
            .await?
            .ok_or_else(|| {
                ApiError::NotFound(format!("Asset {} not found", scan_create.asset_id))
            })?;

        let settings = self.current_settings();
        self.validate_asset_target(&settings, &asset)?;

        // Create the scan record
        let scan = self.scan_repo.create(&scan_create, company_id).await?;
        let scan_id = scan.id;
        let asset_id = asset.id;

        // Submit scan task.
        //
        // `scan_id` and `discovery_run_id` go in as strings because that is what
        // `cancel_tasks_by_metadata` compares against: they are how a stop --
        // of one scan, or of the whole run that queued it -- finds the task
        // still executing this scan.
        let scan_service = self.clone();
        let task_metadata = json!({
            "scan_id": scan_id.to_string(),
            "asset_id": asset_id.to_string(),
            "asset_identifier": asset.identifier,
            "scan_type": scan.scan_type,
            "company_id": company_id.to_string(),
            "discovery_run_id": scan.discovery_run_id.map(|id| id.to_string()),
            "requested_by": requested_by.map(|id| id.to_string()),
        });

        self.task_manager
            .submit_task(TaskType::Scan, task_metadata, move |ctx| {
                let scan_service = scan_service.clone();
                Box::pin(async move {
                    scan_service
                        .execute_scan(ctx, scan_id, asset_id, company_id)
                        .await
                })
            })
            .await?;

        tracing::info!(
            scan_id = %scan_id,
            asset = %asset.identifier,
            company_id = %company_id,
            requested_by = ?requested_by,
            "Created security scan"
        );
        Ok(scan)
    }

    /// Get a scan by ID
    pub async fn get_scan(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityScan>, ApiError> {
        self.scan_repo.get_by_id(id, company_id).await
    }

    /// Cancel a running scan
    pub async fn cancel_scan(&self, id: &Uuid, company_id: Uuid) -> Result<(), ApiError> {
        // Get the current scan status
        let scan = self
            .scan_repo
            .get_by_id(id, company_id)
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

        // Stop the task before writing the status, not after. `execute_scan`
        // marks the scan `running` on its way in, so a task still live when the
        // row is written can overwrite `cancelled` a moment later; taking the
        // task down first means anything that slipped through is caught by the
        // update rather than racing it.
        //
        // Task ids are minted by the task manager and are not scan ids, so this
        // used to pass the scan id to `cancel_task` and silently match nothing
        // -- the row read "cancelled" while the scan carried on probing.
        let stopped = self
            .task_manager
            .cancel_tasks_by_metadata("scan_id", &id.to_string(), Some(TaskType::Scan))
            .await;

        self.scan_repo
            .update_status(id, SecurityScanStatus::Cancelled, company_id)
            .await?;

        tracing::info!(
            scan_id = %id,
            tasks_stopped = stopped.len(),
            "Cancelled security scan"
        );
        Ok(())
    }

    /// Cancel every unfinished scan a discovery run queued.
    ///
    /// Called when a run is stopped: its auto-scans are its own work, and
    /// leaving them running means "stop" stopped the enumeration but not the
    /// probing it had already fanned out.
    pub async fn cancel_scans_for_discovery_run(
        &self,
        discovery_run_id: &Uuid,
        company_id: Uuid,
    ) -> Result<usize, ApiError> {
        // Tasks first, rows second -- see `cancel_scan`. Sweeping by run rather
        // than per scan also catches a scan submitted a moment ago whose row the
        // update below has not reached yet.
        let stopped = self
            .task_manager
            .cancel_tasks_by_metadata(
                "discovery_run_id",
                &discovery_run_id.to_string(),
                Some(TaskType::Scan),
            )
            .await;

        let cancelled = self
            .scan_repo
            .cancel_active_by_discovery_run(
                discovery_run_id,
                company_id,
                "Cancelled: discovery run stopped",
            )
            .await?;

        if !cancelled.is_empty() || !stopped.is_empty() {
            tracing::info!(
                discovery_run_id = %discovery_run_id,
                company_id = %company_id,
                scans_cancelled = cancelled.len(),
                tasks_stopped = stopped.len(),
                "Cancelled scans queued by discovery run"
            );
        }

        Ok(cancelled.len())
    }

    /// Cancel every unfinished scan against `asset_ids`.
    ///
    /// Used when assets are blacklisted: a scan already in flight against a
    /// host the operator has just excluded has to stop, whatever queued it.
    pub async fn cancel_scans_for_assets(
        &self,
        asset_ids: &[Uuid],
        company_id: Uuid,
        reason: &str,
    ) -> Result<usize, ApiError> {
        if asset_ids.is_empty() {
            return Ok(0);
        }

        // Tasks first, rows second -- see `cancel_scan`. Swept by asset rather
        // than by scan id, so a scan submitted against one of these assets a
        // moment ago is caught even though the update below has not seen it.
        for asset_id in asset_ids {
            self.task_manager
                .cancel_tasks_by_metadata("asset_id", &asset_id.to_string(), Some(TaskType::Scan))
                .await;
        }

        let cancelled = self
            .scan_repo
            .cancel_active_for_assets(asset_ids, company_id, reason)
            .await?;

        if !cancelled.is_empty() {
            tracing::info!(
                company_id = %company_id,
                scans_cancelled = cancelled.len(),
                assets = asset_ids.len(),
                "{}",
                reason
            );
        }

        Ok(cancelled.len())
    }

    /// Get scan with full details including asset and findings
    pub async fn get_scan_detail(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<crate::models::SecurityScanDetailResponse>, ApiError> {
        let scan = match self.scan_repo.get_by_id(id, company_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let asset = self
            .asset_repo
            .get_by_id(company_id, &scan.asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("Asset not found".to_string()))?;

        let findings = self.finding_repo.list_by_scan(id, company_id).await?;
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
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        self.scan_repo
            .list_by_asset(asset_id, 100, company_id)
            .await
    }

    /// List all scans
    pub async fn list_scans(
        &self,
        limit: i64,
        offset: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        self.scan_repo.list_all(limit, offset, company_id).await
    }

    /// Get pending scans
    pub async fn list_pending_scans(
        &self,
        limit: i64,
        company_id: Uuid,
    ) -> Result<Vec<SecurityScan>, ApiError> {
        self.scan_repo.list_pending(limit, company_id).await
    }

    // ========================================================================
    // SCAN EXECUTION
    // ========================================================================

    /// Execute a security scan
    /// Execute a security scan
    async fn execute_scan(
        &self,
        ctx: TaskContext,
        scan_id: Uuid,
        asset_id: Uuid,
        company_id: Uuid,
    ) -> Result<(), ApiError> {
        tracing::info!("Starting security scan {}", scan_id);

        // A queued scan can be cancelled before it ever gets a concurrency
        // permit -- stopping the discovery run that queued it does exactly
        // that. Marking it running here would undo that, so check first.
        if ctx.check_cancellation().await.is_err() {
            tracing::info!("Security scan {} cancelled before it started", scan_id);
            return Ok(());
        }

        // Mark scan as running
        let scan_started_at = Utc::now();
        self.scan_repo.start(&scan_id, company_id).await?;
        ctx.update_progress(0.05, Some("Scan started".to_string()))
            .await?;

        // Get asset details
        let asset = self
            .asset_repo
            .get_by_id(company_id, &asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("Asset not found".to_string()))?;

        // Get scan config
        let scan = self
            .scan_repo
            .get_by_id(&scan_id, company_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("Scan not found".to_string()))?;

        let scan_type = SecurityScanType::from(scan.scan_type.as_str());
        // A malformed config must not fail the scan; the defaults are the ones a
        // caller who sent nothing would get.
        let config: ScanConfig = serde_json::from_value(scan.config.clone()).unwrap_or_default();

        // Execute appropriate scan based on asset type and scan type
        let result = self
            .execute_scan_internal(&ctx, scan_id, &asset, &scan_type, &config, company_id)
            .await;

        // Finalize scan. A cancelled scan keeps the `cancelled` status the
        // canceller wrote; completing or failing it here would report the stop
        // as an outcome of the scan.
        if ctx.check_cancellation().await.is_err() {
            tracing::info!("Security scan {} cancelled; leaving status as is", scan_id);
            return Ok(());
        }

        match result {
            Ok(summary) => {
                if let Err(e) = self
                    .resolve_stale_findings(
                        scan_id,
                        asset.id,
                        &scan_type,
                        config.deep.unwrap_or(true),
                        scan_started_at,
                        company_id,
                    )
                    .await
                {
                    tracing::warn!(
                        "Failed to resolve stale findings for asset {}: {}",
                        asset.id,
                        e
                    );
                }

                let summary_json = serde_json::to_value(&summary).unwrap_or(json!({}));
                self.scan_repo
                    .complete(&scan_id, &summary_json, company_id)
                    .await?;
                tracing::info!("Security scan {} completed successfully", scan_id);

                if let Err(e) = self
                    .risk_service
                    .calculate_asset_risk(company_id, asset.id)
                    .await
                {
                    tracing::warn!(
                        "Failed to recalculate risk for asset {} after scan {}: {}",
                        asset.id,
                        scan_id,
                        e
                    );
                }
            }
            Err(e) => {
                let message = e.to_string();
                if message.contains("cancelled") {
                    self.scan_repo
                        .update_status(&scan_id, SecurityScanStatus::Cancelled, company_id)
                        .await?;
                    tracing::info!("Security scan {} cancelled", scan_id);
                    return Ok(());
                }
                self.scan_repo.fail(&scan_id, &message, company_id).await?;
                tracing::error!("Security scan {} failed: {}", scan_id, e);
                return Err(e);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_scan_internal(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        scan_type: &SecurityScanType,
        config: &ScanConfig,
        company_id: Uuid,
    ) -> Result<ScanResultSummary, ApiError> {
        let mut summary = ScanResultSummary::default();
        let start_time = std::time::Instant::now();
        let mut risk_factors = Vec::new();

        match asset.asset_type {
            AssetType::Domain => {
                self.scan_domain(
                    ctx,
                    scan_id,
                    asset,
                    scan_type,
                    config,
                    &mut summary,
                    &mut risk_factors,
                    company_id,
                )
                .await?;
            }
            AssetType::Ip => {
                self.scan_ip(
                    ctx,
                    scan_id,
                    asset,
                    scan_type,
                    config,
                    &mut summary,
                    &mut risk_factors,
                    company_id,
                )
                .await?;
            }
            AssetType::Certificate => {
                self.scan_certificate(
                    ctx,
                    scan_id,
                    asset,
                    &mut summary,
                    &mut risk_factors,
                    company_id,
                )
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
        let findings = self.finding_repo.list_by_scan(&scan_id, company_id).await?;
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

    #[allow(clippy::too_many_arguments)]
    async fn scan_domain(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        scan_type: &SecurityScanType,
        config: &ScanConfig,
        summary: &mut ScanResultSummary,
        risk_factors: &mut Vec<RiskFactor>,
        company_id: Uuid,
    ) -> Result<(), ApiError> {
        let domain = &asset.identifier;
        let settings = self.current_settings();
        // Exhaustive by default: a scan that skips cipher enumeration and the
        // zone-transfer attempt is not the scan this is for.
        let deep_scan = config.deep.unwrap_or(true);
        let mut internal_only = false;

        // Step 1: DNS security checks
        ctx.update_progress(0.1, Some("Checking DNS security".to_string()))
            .await?;
        if matches!(
            scan_type,
            SecurityScanType::Full | SecurityScanType::DnsAudit
        ) {
            let (legacy, deep) = self
                .check_dns_security(scan_id, asset, domain, deep_scan, company_id)
                .await?;
            summary.dns_security = Some(legacy);
            summary.dns = Some(deep);
        }

        // Step 2: Resolve to IP and scan ports with service detection
        ctx.update_progress(0.2, Some("Resolving DNS".to_string()))
            .await?;
        match self.dns_resolver.resolve_hostname(domain).await {
            Ok(ips) => {
                let scan_target_ip = ips
                    .iter()
                    .copied()
                    .find(|ip| self.is_ip_allowed(&settings, *ip));
                internal_only = scan_target_ip.is_none() && !ips.is_empty();
                if internal_only {
                    tracing::info!(
                        "Skipping active scans for {}: only disallowed IPs resolved",
                        domain
                    );
                }

                if let Some(ip) = scan_target_ip {
                    // Port scan with service detection
                    if matches!(
                        scan_type,
                        SecurityScanType::PortScan | SecurityScanType::Full
                    ) {
                        ctx.update_progress(
                            0.3,
                            Some("Scanning ports and detecting services".to_string()),
                        )
                        .await?;
                        let (open_ports, services, vulns) = self
                            .scan_ports_with_service_detection(
                                scan_id,
                                asset,
                                ip,
                                risk_factors,
                                company_id,
                            )
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
                        let http_outcome = self
                            .analyze_http_security(
                                scan_id, asset, domain, deep_scan, risk_factors, company_id,
                            )
                            .await?;
                        summary.security_headers = Some(http_outcome.security_headers);
                        summary.proxy_detection = Some(http_outcome.proxy_detection);
                        summary.http_status = http_outcome.http.as_ref().map(|h| h.status as i32);
                        summary.http = http_outcome.http;
                        summary.vulnerabilities_found = Self::merge_vulnerability_results(
                            summary.vulnerabilities_found.take(),
                            http_outcome.vulnerabilities,
                        );
                        summary.technology_stack = Self::merge_technology_stack(
                            summary.technology_stack.take(),
                            http_outcome.technology_stack,
                        );
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
                    company_id,
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
            if internal_only {
                tracing::info!(
                    "Skipping TLS analysis for {}: only disallowed IPs resolved",
                    domain
                );
            } else {
                ctx.update_progress(0.7, Some("Analyzing TLS".to_string()))
                    .await?;
                if let Some((tls_details, deep)) = self
                    .analyze_tls_with_findings(
                        scan_id,
                        asset,
                        domain,
                        443,
                        deep_scan,
                        risk_factors,
                        company_id,
                    )
                    .await?
                {
                    summary.tls_certificates = Some(vec![tls_details]);
                    if let Some(deep) = deep {
                        summary.tls_version = deep.highest_protocol.clone();
                        summary.tls = Some(deep);
                    }
                }
            }
        }

        // Step 4: Threat intelligence
        if matches!(
            scan_type,
            SecurityScanType::ThreatIntel | SecurityScanType::Full
        ) {
            ctx.update_progress(0.85, Some("Checking threat intel".to_string()))
                .await?;
            self.check_threat_intel(scan_id, asset, domain, risk_factors, company_id)
                .await?;
        }

        ctx.update_progress(0.95, Some("Finalizing scan".to_string()))
            .await?;

        Ok(())
    }

    // ========================================================================
    // IP SCANNING
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn scan_ip(
        &self,
        ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        scan_type: &SecurityScanType,
        config: &ScanConfig,
        summary: &mut ScanResultSummary,
        risk_factors: &mut Vec<RiskFactor>,
        company_id: Uuid,
    ) -> Result<(), ApiError> {
        let ip: IpAddr = asset
            .identifier
            .parse()
            .map_err(|e| ApiError::Validation(format!("Invalid IP: {}", e)))?;
        let settings = self.current_settings();
        let deep_scan = config.deep.unwrap_or(true);

        if !self.is_ip_allowed(&settings, ip) {
            tracing::info!(
                "Skipping disallowed IP scan for asset {} ({})",
                asset.id,
                ip
            );
            return Ok(());
        }

        let mut discovered_open_ports = Vec::new();

        // Port scan with service detection
        if matches!(
            scan_type,
            SecurityScanType::PortScan | SecurityScanType::Full
        ) {
            ctx.update_progress(
                0.2,
                Some("Scanning ports and detecting services".to_string()),
            )
            .await?;
            let (open_ports, services, vulns) = self
                .scan_ports_with_service_detection(scan_id, asset, ip, risk_factors, company_id)
                .await?;
            discovered_open_ports = open_ports.clone();
            summary.open_ports = Some(open_ports.clone());
            summary.services_detected = Some(services);
            summary.vulnerabilities_found =
                Self::merge_vulnerability_results(summary.vulnerabilities_found.take(), vulns);
        }

        // HTTP probing on web ports
        if matches!(
            scan_type,
            SecurityScanType::HttpProbe | SecurityScanType::Full
        ) {
            ctx.update_progress(0.5, Some("Analyzing HTTP security".to_string()))
                .await?;

            if let Some(target) = self
                .select_http_target_for_ip(ip, &discovered_open_ports)
                .await
            {
                let http_outcome = self
                    .analyze_http_security(
                        scan_id, asset, &target, deep_scan, risk_factors, company_id,
                    )
                    .await?;
                summary.security_headers = Some(http_outcome.security_headers);
                summary.proxy_detection = Some(http_outcome.proxy_detection);
                summary.http_status = http_outcome.http.as_ref().map(|h| h.status as i32);
                summary.http = http_outcome.http;
                summary.vulnerabilities_found = Self::merge_vulnerability_results(
                    summary.vulnerabilities_found.take(),
                    http_outcome.vulnerabilities,
                );
                summary.technology_stack = Self::merge_technology_stack(
                    summary.technology_stack.take(),
                    http_outcome.technology_stack,
                );
            } else {
                tracing::debug!("No HTTP port found for IP target {}", ip);
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
                    if let Some((tls_details, deep)) = self
                        .analyze_tls_with_findings(
                            scan_id,
                            asset,
                            &ip.to_string(),
                            *port,
                            deep_scan,
                            risk_factors,
                            company_id,
                        )
                        .await?
                    {
                        summary.tls_certificates = Some(vec![tls_details]);
                        if let Some(deep) = deep {
                            summary.tls_version = deep.highest_protocol.clone();
                            summary.tls = Some(deep);
                        }
                    }
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
            self.check_threat_intel(scan_id, asset, &ip.to_string(), risk_factors, company_id)
                .await?;
        }

        Ok(())
    }

    async fn select_http_target_for_ip(
        &self,
        ip: IpAddr,
        discovered_ports: &[u16],
    ) -> Option<String> {
        if let Some(target) = Self::resolve_http_target_from_ports(ip, discovered_ports, &[]) {
            return Some(target);
        }

        let settings = self.current_settings();
        let timeout = Duration::from_secs_f64(settings.tcp_scan_timeout.max(0.2));
        for port in DEFAULT_IP_HTTP_FALLBACK_PORTS {
            let open = scan_ports(ip, &[port], timeout).await;
            if open.contains(&port) {
                return Some(format!("{}:{}", ip, port));
            }
        }

        None
    }

    fn resolve_http_target_from_ports(
        ip: IpAddr,
        discovered_ports: &[u16],
        fallback_ports: &[u16],
    ) -> Option<String> {
        discovered_ports
            .iter()
            .copied()
            .find(|port| Self::is_web_port(*port))
            .or_else(|| {
                fallback_ports
                    .iter()
                    .copied()
                    .find(|port| Self::is_web_port(*port))
            })
            .map(|port| format!("{}:{}", ip, port))
    }

    fn is_web_port(port: u16) -> bool {
        matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 8888 | 9000)
    }

    fn merge_vulnerability_results(
        existing: Option<Vec<VulnerabilityResult>>,
        additional: Vec<VulnerabilityResult>,
    ) -> Option<Vec<VulnerabilityResult>> {
        let mut merged = existing.unwrap_or_default();
        merged.extend(additional);
        let deduped = Self::dedupe_vulnerability_results(merged);
        if deduped.is_empty() {
            None
        } else {
            Some(deduped)
        }
    }

    fn merge_technology_stack(
        existing: Option<Vec<String>>,
        additional: Vec<String>,
    ) -> Option<Vec<String>> {
        let mut seen = std::collections::BTreeSet::new();
        for value in existing.unwrap_or_default().into_iter().chain(additional) {
            if !value.trim().is_empty() {
                seen.insert(value);
            }
        }
        if seen.is_empty() {
            None
        } else {
            Some(seen.into_iter().collect())
        }
    }

    fn dedupe_vulnerability_results(
        mut vulnerabilities: Vec<VulnerabilityResult>,
    ) -> Vec<VulnerabilityResult> {
        vulnerabilities.sort_by_cached_key(|v| {
            (
                v.cve_id.to_ascii_lowercase(),
                v.affected_service.to_ascii_lowercase(),
                v.affected_version.to_ascii_lowercase(),
            )
        });
        vulnerabilities.dedup_by(|a, b| {
            a.cve_id.eq_ignore_ascii_case(&b.cve_id)
                && a.affected_service.eq_ignore_ascii_case(&b.affected_service)
                && a.affected_version.eq_ignore_ascii_case(&b.affected_version)
        });
        vulnerabilities
    }

    // ========================================================================
    // CERTIFICATE SCANNING
    // ========================================================================

    async fn scan_certificate(
        &self,
        _ctx: &TaskContext,
        scan_id: Uuid,
        asset: &Asset,
        summary: &mut ScanResultSummary,
        risk_factors: &mut Vec<RiskFactor>,
        company_id: Uuid,
    ) -> Result<(), ApiError> {
        // Attempt live TLS analysis using a hostname from metadata if available
        let mut tls_details = None;
        if let Some(metadata) = asset.metadata.as_object() {
            let mut host_candidates: Vec<String> = Vec::new();

            if let Some(sans) = metadata.get("san_domains").and_then(|v| v.as_array()) {
                for entry in sans {
                    if let Some(domain) = entry.as_str() {
                        host_candidates.push(domain.to_string());
                    }
                }
            }

            if let Some(common_name) = metadata.get("common_name").and_then(|v| v.as_str()) {
                host_candidates.push(common_name.to_string());
            }

            if host_candidates.is_empty() {
                if let Some(subject) = metadata.get("subject").and_then(|v| v.as_str()) {
                    if let Some(cn) = subject
                        .split(',')
                        .find(|part| part.trim().starts_with("CN="))
                        .map(|cn| cn.trim().trim_start_matches("CN=").to_string())
                    {
                        host_candidates.push(cn);
                    }
                }
            }

            if let Some(host) = host_candidates.first() {
                if let Some((details, deep)) = self
                    .analyze_tls_with_findings(
                        scan_id,
                        asset,
                        host,
                        443,
                        true,
                        risk_factors,
                        company_id,
                    )
                    .await?
                {
                    tls_details = Some(details);
                    if let Some(deep) = deep {
                        summary.tls_version = deep.highest_protocol.clone();
                        summary.tls = Some(deep);
                    }
                }
            }
        }

        if let Some(details) = tls_details {
            summary.tls_certificates = Some(vec![details]);
            return Ok(());
        }

        // Fallback: Check certificate metadata for issues
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

            let ssl_labs_url = domain
                .as_ref()
                .map(|d| format!("https://www.ssllabs.com/ssltest/analyze.html?d={}", d));

            // Check for expiration
            if let Some(not_after) = metadata.get("not_after").and_then(|v| v.as_str()) {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(not_after) {
                    let now = Utc::now();
                    let days_until_expiry = (expiry.with_timezone(&Utc) - now).num_days();

                    if days_until_expiry < 0 {
                        let mut data =
                            json!({ "expiry_date": not_after, "days_overdue": -days_until_expiry });
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
                            company_id,
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
                            Some(&format!(
                                "Certificate expires in {} days",
                                days_until_expiry
                            )),
                            data,
                            company_id,
                        )
                        .await?;
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
                            Some(&format!(
                                "Certificate expires in {} days",
                                days_until_expiry
                            )),
                            data,
                            company_id,
                        )
                        .await?;
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
                        company_id,
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
        company_id: Uuid,
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
            let (severity, finding_type, title, description) =
                self.categorize_port(result.port, &service_name);

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
                company_id,
            )
            .await?;

            // Check for known vulnerabilities using NVD API
            // Use product name if available (more specific than generic service name)
            let product_for_cve = service_info
                .and_then(|s| s.product.clone())
                .unwrap_or_else(|| service_name.clone());

            if let Some(ver) = &version {
                // First, try NVD API for real-time vulnerability data
                let nvd_vulns = self
                    .lookup_vulnerabilities_from_nvd(&product_for_cve, ver, None)
                    .await;

                // Fall back to local database if NVD fails or returns nothing
                let vulns = if nvd_vulns.is_empty() {
                    get_known_vulnerabilities(&product_for_cve, ver)
                } else {
                    nvd_vulns
                };

                for vuln in vulns {
                    let vuln_severity = match vuln.severity.as_str() {
                        "critical" => FindingSeverity::Critical,
                        "high" => FindingSeverity::High,
                        "medium" => FindingSeverity::Medium,
                        _ => FindingSeverity::Low,
                    };

                    // Generate NVD link for the CVE
                    let nvd_url = NvdClient::vulnerability_url(&vuln.cve_id);

                    self.create_finding_with_cvss(
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
                            "affected_service": product_for_cve,  // Use actual product name
                            "affected_version": vuln.affected_versions,
                            "exploitable": vuln.exploitable,
                            "has_public_exploit": vuln.has_public_exploit,
                            "detection_method": "port_service_detection",
                            "references": vuln.references,
                            "source_url": nvd_url,
                            "source_name": "NVD (NIST)",
                        }),
                        vuln.cvss_score, // Pass CVSS score to the finding
                        Some(vec![vuln.cve_id.clone()]), // Pass CVE ID
                        company_id,
                    )
                    .await?;

                    vulnerabilities.push(VulnerabilityResult {
                        cve_id: vuln.cve_id.clone(),
                        title: vuln.title.clone(),
                        severity: vuln.severity.clone(),
                        cvss_score: vuln.cvss_score,
                        affected_service: product_for_cve.clone(), // Use actual product name
                        affected_version: vuln.affected_versions.join(", "),
                        exploitable: vuln.exploitable,
                        has_public_exploit: vuln.has_public_exploit,
                        description: vuln.description.clone(),
                        remediation: Some(format!(
                            "Update {} to the latest version",
                            product_for_cve
                        )),
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
                        data: json!({ "cve_id": vuln.cve_id, "cvss_score": vuln.cvss_score, "nvd_url": nvd_url }),
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

        Ok((
            open_ports,
            services,
            Self::dedupe_vulnerability_results(vulnerabilities),
        ))
    }

    fn categorize_port(
        &self,
        port: u16,
        service: &str,
    ) -> (FindingSeverity, String, String, String) {
        match port {
            // Critical - Dangerous services
            23 => (
                FindingSeverity::Critical,
                "sensitive_port".to_string(),
                format!("Telnet Service Exposed (Port {})", port),
                "Telnet transmits data in plaintext including credentials. This is extremely dangerous.".to_string(),
            ),
            // Critical - Database ports.
            //
            // A production database reachable from the internet is at least as severe
            // as the Telnet case above: it is the data itself, one authentication step
            // away, and several of these ship with no authentication by default. It sat
            // at High while scoring keyed off the finding type, so the severity was
            // inert; now that severity drives the score, High under-rated it badly
            // enough that a handful of missing response headers outweighed it.
            3306 | 5432 | 1433 | 1521 | 27017 | 27018 => (
                FindingSeverity::Critical,
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
                FindingSeverity::Critical,
                "database_exposed".to_string(),
                "Redis Exposed".to_string(),
                "Redis in-memory database is exposed. Redis often has no authentication by default.".to_string(),
            ),
            9200 | 9300 => (
                FindingSeverity::Critical,
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

    #[allow(clippy::too_many_arguments)]
    async fn analyze_http_security(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        target: &str,
        deep: bool,
        risk_factors: &mut Vec<RiskFactor>,
        company_id: Uuid,
    ) -> Result<HttpSecurityAnalysisOutcome, ApiError> {
        let mut security_result = SecurityHeadersResult::default();
        let mut proxy_result = ProxyDetectionResult::default();
        let mut vulnerabilities = Vec::new();
        let mut technology_stack = Vec::new();

        // Build URL
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

        security_result.url = url.clone();
        security_result.is_https = url.starts_with("https");

        // Make a direct HTTP request to get headers
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent(BROWSER_USER_AGENT)
            .build()
            .map_err(ApiError::HttpClient)?;

        // Try the derived scheme first, then the other one. A host that only
        // answers on plain HTTP used to yield no fingerprint data at all,
        // because the domain path always built an `https://` URL.
        let page = match Self::fetch_page(&client, &url).await {
            Some(page) => Some(page),
            None => match Self::alternate_scheme_url(&url) {
                Some(alt) => {
                    tracing::debug!("Retrying {} over the alternate scheme: {}", url, alt);
                    Self::fetch_page(&client, &alt).await
                }
                None => None,
            },
        };

        let page = match page {
            Some(page) => page,
            None => {
                tracing::debug!("Failed to fetch {} over either scheme", url);
                return Ok(HttpSecurityAnalysisOutcome {
                    security_headers: security_result,
                    proxy_detection: proxy_result,
                    vulnerabilities,
                    technology_stack,
                    http: None,
                });
            }
        };

        // Report on what actually answered, which after a redirect or a scheme
        // fallback need not be what we asked for.
        security_result.url = page.final_url.clone();
        security_result.is_https = page.final_url.starts_with("https");

        let headers_map = page.headers.clone();
        let set_cookies = page.set_cookies.clone();
        let body = page.body.clone();

        // Secondary passive signals. Each is best-effort and independently
        // bounded: a host that does not serve one still gets scanned on the rest.
        let (favicon_hash, robots_txt) = tokio::join!(
            Self::fetch_favicon_hash_for_page(&client, &page),
            Self::fetch_robots_txt(&client, &page.final_url),
        );
        let cert_issuer = Self::certificate_issuer(&page.final_url).await;

        let fingerprints = Self::extract_http_technology_fingerprints(&headers_map);

        // Wappalyzer-style detection across headers, cookies, HTML body, meta
        // tags and script sources — broader than the header-only fingerprints.
        let header_pairs: Vec<(String, String)> = headers_map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let detection_input = crate::services::fingerprint::DetectionInput::new(
            &page.final_url,
            &body,
        )
        .with_headers(&header_pairs)
        .with_cookies(&set_cookies)
        .with_cert_issuer(cert_issuer.as_deref())
        .with_favicon_hash(favicon_hash)
        .with_robots_txt(robots_txt.as_deref());

        let mut detections = crate::services::fingerprint::engine().detect_with(&detection_input);

        // Thoroughness pass: for JS libraries detected *without* a version (e.g. a
        // bare `jquery.min.js`), fetch the referenced asset and recover the
        // version from its embedded banner. This unlocks CVE matching for libs
        // whose version is only inside the file, not in the URL or HTML.
        self.enrich_versions_from_assets(&page.final_url, &body, &mut detections)
            .await;

        // Build the combined technology stack summary (header + body sources).
        technology_stack = {
            let mut stack: std::collections::BTreeSet<String> =
                Self::technology_stack_from_fingerprints(&fingerprints)
                    .into_iter()
                    .collect();
            for det in &detections {
                let label = match &det.version {
                    Some(v) => format!("{} {}", det.product, v),
                    None => det.product.clone(),
                };
                stack.insert(label);
            }
            stack.into_iter().collect()
        };

        let mut looked_up_versions: HashSet<(String, String)> = HashSet::new();
        let mut unknown_version_disclosures: HashSet<String> = HashSet::new();

        for fingerprint in &fingerprints {
            if let Some(version) = &fingerprint.version {
                let lookup_key = (
                    fingerprint.product.to_ascii_lowercase(),
                    version.to_ascii_lowercase(),
                );
                if !looked_up_versions.insert(lookup_key) {
                    continue;
                }

                let fingerprint_cpe =
                    crate::services::fingerprint::engine().cpe_for(&fingerprint.product);
                self.record_cves_for_technology(
                    scan_id,
                    asset,
                    &fingerprint.product,
                    version,
                    fingerprint_cpe.as_ref(),
                    "http_header_fingerprint",
                    &fingerprint.header_name,
                    &fingerprint.raw_evidence,
                    &mut vulnerabilities,
                    risk_factors,
                    company_id,
                )
                .await?;
            } else {
                let product_key = fingerprint.product.to_ascii_lowercase();
                if !unknown_version_disclosures.insert(product_key) {
                    continue;
                }

                self.create_finding(
                    scan_id,
                    asset.id,
                    "server_version_exposed",
                    FindingSeverity::Low,
                    &format!(
                        "Web Technology Fingerprint Exposed: {}",
                        fingerprint.product
                    ),
                    Some(&format!(
                        "Detected '{}' via HTTP header '{}' but no precise version was exposed.",
                        fingerprint.product, fingerprint.header_name
                    )),
                    json!({
                        "header": fingerprint.header_name.clone(),
                        "value": fingerprint.raw_evidence.clone(),
                        "technology": fingerprint.product.clone(),
                        "detection_method": "http_header_fingerprint",
                        "url": url,
                    }),
                    company_id,
                )
                .await?;

                risk_factors.push(RiskFactor {
                    factor_type: "information_disclosure".to_string(),
                    name: format!("{} fingerprint exposed", fingerprint.product),
                    severity: "low".to_string(),
                    description: format!(
                        "Header '{}' reveals use of {}",
                        fingerprint.header_name, fingerprint.product
                    ),
                    impact_score: 0.1,
                    data: json!({
                        "technology": fingerprint.product.clone(),
                        "header": fingerprint.header_name.clone(),
                        "detection_method": "http_header_fingerprint",
                    }),
                });
            }
        }

        // Body / cookie / meta / script technology detections: feed versioned
        // hits into the same CVE lookup and assemble the stack inventory.
        let mut detected_technologies: Vec<Value> = Vec::new();
        let mut seen_tech: HashSet<(String, Option<String>)> = HashSet::new();

        for det in &detections {
            seen_tech.insert((det.product.to_ascii_lowercase(), det.version.clone()));
            detected_technologies.push(json!({
                "product": det.product,
                "name": det.display_name,
                "version": det.version,
                "categories": det.categories,
                "cpe": det.cpe,
                "confidence": det.confidence,
                "source": det.source,
                "sources": det.sources,
                "evidence": det.evidence,
                "reliable": det.is_reliable(),
            }));

            // Only a corroborated detection may open a vulnerability finding.
            // A weak or purely-implied hit still appears in the inventory —
            // where being wrong costs nothing — but asserting "this asset is
            // vulnerable to CVE-X" off a single ambiguous marker is how a
            // scanner loses its reader's trust.
            if !det.is_reliable() {
                if det.version.is_some() {
                    tracing::debug!(
                        "Skipping CVE lookup for {} {:?}: confidence {} below threshold",
                        det.product,
                        det.version,
                        det.confidence
                    );
                }
                continue;
            }

            if let Some(version) = &det.version {
                let lookup_key =
                    (det.product.to_ascii_lowercase(), version.to_ascii_lowercase());
                if looked_up_versions.insert(lookup_key) {
                    let detection_cpe = det.cpe.as_deref().and_then(Cpe::parse);
                    self.record_cves_for_technology(
                        scan_id,
                        asset,
                        &det.product,
                        version,
                        detection_cpe.as_ref(),
                        "technology_fingerprint",
                        &det.source,
                        &det.evidence,
                        &mut vulnerabilities,
                        risk_factors,
                        company_id,
                    )
                    .await?;
                }
            }
        }

        // Include any header-only fingerprints not already covered above.
        for fp in &fingerprints {
            if seen_tech.insert((fp.product.to_ascii_lowercase(), fp.version.clone())) {
                detected_technologies.push(json!({
                    "product": fp.product,
                    "version": fp.version,
                    "source": fp.header_name,
                    "confidence": fp.confidence,
                }));
            }
        }

        if !technology_stack.is_empty() {
            self.create_finding(
                scan_id,
                asset.id,
                "technology_detected",
                FindingSeverity::Info,
                "Detected technology stack",
                Some(&format!(
                    "Identified {} technologies: {}",
                    technology_stack.len(),
                    technology_stack.join(", ")
                )),
                json!({
                    "technologies": detected_technologies,
                    "stack": technology_stack,
                    "count": technology_stack.len(),
                    "url": url,
                    "detection_method": "technology_fingerprint",
                }),
                company_id,
            )
            .await?;
        }

        // Security-header inventory for the summary panel.
        //
        // The *findings* for these now come from `http_scan`, which grades a
        // header's value rather than its presence — the difference between "CSP
        // present" and "CSP that permits 'unsafe-inline' and so stops nothing".
        // This loop only fills in the summary shape the UI already renders.
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
                        if let Some(max_age_str) =
                            value.split(';').find(|s| s.trim().starts_with("max-age"))
                        {
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
            }
        }

        security_result.headers_present = present_headers;
        security_result.headers_missing = missing_headers;
        security_result.score = score;

        // Server banner, for the summary. The `server_version_exposed` finding
        // itself comes from `http_scan`, which only raises it when the header
        // actually carries a version rather than a bare product name.
        if let Some(server) = headers_map.get("server") {
            security_result.server_info = Some(server.clone());
            if server.contains('/') && server.chars().any(|c| c.is_ascii_digit()) {
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

        // ------------------------------------------------------------------
        // Deep HTTP assessment.
        //
        // The fingerprinting above answers "what software is this"; the scanner
        // below answers "how is it configured", which is a different question and
        // was previously reduced to a seven-entry presence check over header
        // names. Its findings are written directly, and its structured result
        // rides along in the summary.
        // ------------------------------------------------------------------
        let plain_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent(BROWSER_USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(ApiError::HttpClient)?;

        // The original target, not `page.final_url`: the fingerprinting fetch above
        // has its own scheme fallback, so handing over its result would mean the
        // HTTP scanner never attempts HTTPS itself — and could not tell a site
        // that has no HTTPS from one whose HTTPS this scanner failed to reach.
        let http_outcome =
            http_scan::scan(&client, &plain_client, target, Duration::from_secs(10), deep).await;
        self.record_scan_findings(scan_id, asset.id, http_outcome.findings, company_id)
            .await?;
        let deep_http = http_outcome.result;

        // The header grade drives risk the way a reader would weight it.
        if deep_http.observatory.score < 50 {
            risk_factors.push(RiskFactor {
                factor_type: "http".to_string(),
                name: format!("HTTP security headers graded {}", deep_http.observatory.grade),
                severity: if deep_http.observatory.score < 25 {
                    "medium"
                } else {
                    "low"
                }
                .to_string(),
                description: format!(
                    "Mozilla Observatory score {} ({})",
                    deep_http.observatory.score, deep_http.observatory.grade
                ),
                impact_score: if deep_http.observatory.score < 25 { 0.35 } else { 0.2 },
                data: json!({
                    "score": deep_http.observatory.score,
                    "grade": deep_http.observatory.grade,
                }),
            });
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
                company_id,
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

        // HTTPS enforcement: the finding is `http_scan`'s, which can tell a
        // server that only speaks HTTP from one the scanner could not reach over
        // HTTPS. The risk factor stays here.
        if !security_result.is_https {
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

        // Prefer the scanner's own view of what was present and missing: it looks
        // at more headers, and at their values.
        if deep_http.status != 0 {
            security_result.headers_present = deep_http.headers_present.clone();
            security_result.headers_missing = deep_http
                .headers_missing
                .iter()
                .map(|name| MissingSecurityHeader {
                    name: name.clone(),
                    severity: "low".to_string(),
                    description: format!("{} is not sent", name),
                    recommendation: "Add the header with a restrictive value.".to_string(),
                })
                .collect();
            // One number, from the published Observatory modifiers, instead of the
            // ad-hoc subtraction this used to do.
            security_result.score = deep_http.observatory.score.clamp(0, 100) as u8;
            security_result.hsts_enabled = deep_http.hsts.present;
            security_result.hsts_max_age = deep_http.hsts.max_age;
            security_result.csp_present = deep_http.csp.present;
            security_result.cookies_analyzed = deep_http
                .cookies
                .iter()
                .map(|cookie| crate::models::CookieSecurityIssue {
                    cookie_name: cookie.name.clone(),
                    issues: cookie.issues.clone(),
                    secure_flag: cookie.secure,
                    http_only_flag: cookie.http_only,
                    same_site: cookie.same_site.clone(),
                })
                .collect();
        }

        Ok(HttpSecurityAnalysisOutcome {
            security_headers: security_result,
            proxy_detection: proxy_result,
            vulnerabilities: Self::dedupe_vulnerability_results(vulnerabilities),
            technology_stack,
            http: (deep_http.status != 0).then_some(deep_http),
        })
    }

    /// Look up known CVEs for a detected (product, version) via NVD (with a
    /// local fallback) and record `known_cve` findings, vulnerability results
    /// and risk factors. Shared by the header- and body-based detectors.
    #[allow(clippy::too_many_arguments)]
    async fn record_cves_for_technology(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        product: &str,
        version: &str,
        cpe: Option<&Cpe>,
        detection_method: &str,
        detection_source: &str,
        detection_evidence: &str,
        vulnerabilities: &mut Vec<VulnerabilityResult>,
        risk_factors: &mut Vec<RiskFactor>,
        company_id: Uuid,
    ) -> Result<(), ApiError> {
        let nvd_vulns = self
            .lookup_vulnerabilities_from_nvd(product, version, cpe)
            .await;
        let matched_vulns = if nvd_vulns.is_empty() {
            get_known_vulnerabilities(product, version)
        } else {
            nvd_vulns
        };

        // Rank what NVD returned. A CVSS score alone does not distinguish the
        // handful of CVEs on this asset that attackers are actually using from
        // the rest, so every finding carries CISA KEV membership and the FIRST
        // EPSS probability alongside it. One batched lookup covers the set.
        let cve_ids: Vec<String> = matched_vulns.iter().map(|v| v.cve_id.clone()).collect();
        let threat = if cve_ids.is_empty() {
            HashMap::new()
        } else {
            self.threat_intel.context_for(&cve_ids).await
        };

        // Most CMSes publish only a major version — Drupal's generator tag says
        // "Drupal 11" and nothing more. The CVEs found for such a version affect
        // *some* build in that series, and the asset may already be on a patched
        // one. Reporting them is right (reporting nothing is what the old
        // point-version query did), but presenting them as confirmed is not.
        let version_is_series = NvdClient::is_series_version(version);

        for vuln in matched_vulns {
            let vuln_severity = match vuln.severity.as_str() {
                "critical" => FindingSeverity::Critical,
                "high" => FindingSeverity::High,
                "medium" => FindingSeverity::Medium,
                _ => FindingSeverity::Low,
            };

            let nvd_url = NvdClient::vulnerability_url(&vuln.cve_id);
            let ctx = threat
                .get(&vuln.cve_id.to_uppercase())
                .cloned()
                .unwrap_or_default();
            let known_exploited = ctx.is_known_exploited() || vuln.exploitable;
            // Rank an unconfirmed match below an otherwise identical confirmed
            // one, without burying it: the uncertainty is about whether the CVE
            // applies here, not about how bad it is.
            let priority = if version_is_series {
                ctx.priority_score(vuln.cvss_score) * 0.8
            } else {
                ctx.priority_score(vuln.cvss_score)
            };

            self.create_finding_with_cvss(
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
                    "affected_service": product,
                    "affected_cpe": cpe.map(|c| c.to_formatted_string()),
                    "affected_version": vuln.affected_versions,
                    "exploitable": known_exploited,
                    "has_public_exploit": vuln.has_public_exploit,
                    "known_exploited": ctx.is_known_exploited(),
                    "kev_date_added": ctx.kev.as_ref().map(|k| k.date_added.clone()),
                    "kev_due_date": ctx.kev.as_ref().and_then(|k| k.due_date.clone()),
                    "known_ransomware_campaign_use": ctx
                        .kev
                        .as_ref()
                        .is_some_and(|k| k.known_ransomware_campaign_use),
                    "epss_probability": ctx.epss.map(|e| e.probability),
                    "epss_percentile": ctx.epss.map(|e| e.percentile),
                    "priority_score": priority,
                    "detection_method": detection_method,
                    "detection_source": detection_source,
                    "fingerprint_header": detection_source,
                    "fingerprint_value": detection_evidence,
                    "detected_version": version,
                    "version_precision": if version_is_series { "series" } else { "exact" },
                    "version_confirmed": !version_is_series,
                    "references": vuln.references,
                    "source_url": nvd_url,
                    "source_name": "NVD (NIST)",
                }),
                vuln.cvss_score,
                Some(vec![vuln.cve_id.clone()]),
                company_id,
            )
            .await?;

            vulnerabilities.push(VulnerabilityResult {
                cve_id: vuln.cve_id.clone(),
                title: vuln.title.clone(),
                severity: vuln.severity.clone(),
                cvss_score: vuln.cvss_score,
                affected_service: product.to_string(),
                affected_version: vuln.affected_versions.join(", "),
                exploitable: vuln.exploitable,
                has_public_exploit: vuln.has_public_exploit,
                description: vuln.description.clone(),
                remediation: Some(format!("Update {} to the latest version", product)),
                references: vuln.references.clone(),
            });

            // Impact tracks the priority score rather than a bare boolean, so a
            // KEV-listed CVE and an unexploited one of the same CVSS no longer
            // contribute identically to the asset's risk.
            let impact = (priority / 10.0).clamp(0.1, 1.0);
            risk_factors.push(RiskFactor {
                factor_type: "vulnerability".to_string(),
                name: format!("Known vulnerability: {}", vuln.cve_id),
                severity: vuln.severity.clone(),
                description: vuln.description.clone(),
                impact_score: impact,
                data: json!({
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "priority_score": priority,
                    "known_exploited": ctx.is_known_exploited(),
                    "epss_probability": ctx.epss.map(|e| e.probability),
                    "detection_method": detection_method,
                    "product": product,
                    "version": version,
                    "nvd_url": nvd_url,
                }),
            });
        }

        Ok(())
    }

    /// One fetched page, with every signal the fingerprint engine reads.
    async fn fetch_page(client: &reqwest::Client, url: &str) -> Option<FetchedPage> {
        let response = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!("Failed to fetch {}: {}", url, e);
                return None;
            }
        };

        let final_url = response.url().to_string();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let set_cookies: Vec<String> = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();

        let body = Self::read_body_capped(response, MAX_PAGE_BYTES).await;

        Some(FetchedPage {
            final_url,
            headers,
            set_cookies,
            body,
        })
    }

    /// Read a response body, stopping once `cap` bytes have arrived.
    ///
    /// `Response::text()` buffers whatever the server sends, so a multi-hundred
    /// megabyte "page" — or an endpoint that streams forever — would be read
    /// into memory in full before the engine's own 1 MB truncation ever applies.
    async fn read_body_capped(response: reqwest::Response, cap: usize) -> String {
        let mut response = response;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = cap.saturating_sub(buf.len());
                    if remaining == 0 {
                        break;
                    }
                    let take = remaining.min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                    if buf.len() >= cap {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!("Truncated body read: {}", e);
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// The same URL with `http` and `https` swapped, for the scheme fallback.
    fn alternate_scheme_url(url: &str) -> Option<String> {
        if let Some(rest) = url.strip_prefix("https://") {
            Some(format!("http://{}", rest))
        } else {
            url.strip_prefix("http://")
                .map(|rest| format!("https://{}", rest))
        }
    }

    /// Shodan-convention MurmurHash3 of the site's favicon.
    ///
    /// An exact favicon hash is one of the few passive signals that identifies
    /// an appliance's *product* even when its login page has been rebranded and
    /// every version banner stripped.
    async fn fetch_favicon_hash_for_page(
        client: &reqwest::Client,
        page: &FetchedPage,
    ) -> Option<i32> {
        let declared = extract_icon_link(&page.body)
            .and_then(|href| Self::resolve_asset_url(&page.final_url, &href));
        let default = url::Url::parse(&page.final_url)
            .ok()
            .and_then(|u| u.join("/favicon.ico").ok())
            .map(|u| u.to_string());

        for candidate in [declared, default].into_iter().flatten() {
            if Self::asset_host_is_internal(&candidate) {
                continue;
            }
            let Ok(resp) = client.get(&candidate).send().await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let Ok(bytes) = resp.bytes().await else {
                continue;
            };
            if bytes.is_empty() || bytes.len() > MAX_FAVICON_BYTES {
                continue;
            }
            return Some(shodan_favicon_hash(&bytes));
        }
        None
    }

    /// `robots.txt`, which frequently names the admin paths of the product
    /// running the site even when the homepage gives nothing away.
    async fn fetch_robots_txt(client: &reqwest::Client, page_url: &str) -> Option<String> {
        let url = url::Url::parse(page_url).ok()?.join("/robots.txt").ok()?;
        let resp = client.get(url.as_str()).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        // A "robots.txt" that comes back as HTML is a soft-404 catch-all page,
        // not a robots file; matching signatures against it invents detections.
        let is_text = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|ct| ct.starts_with("text/plain"));
        if !is_text {
            return None;
        }
        let body = Self::read_body_capped(resp, MAX_ROBOTS_BYTES).await;
        if body.trim().is_empty() {
            None
        } else {
            Some(body)
        }
    }

    /// Issuer of the leaf TLS certificate, for signatures keyed on it (managed
    /// platforms and appliances issue recognisable certificates).
    async fn certificate_issuer(page_url: &str) -> Option<String> {
        let parsed = url::Url::parse(page_url).ok()?;
        if parsed.scheme() != "https" {
            return None;
        }
        let host = parsed.host_str()?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        match get_tls_certificate_info(&host, port).await {
            Ok(info) => Some(info.issuer),
            Err(e) => {
                tracing::debug!("No certificate issuer for {}: {}", page_url, e);
                None
            }
        }
    }

    /// For technology detections that lack a version but whose product can be
    /// banner-parsed (e.g. jQuery, Bootstrap, Vue), fetch the referenced JS/CSS
    /// assets from the page and recover the version from the file's embedded
    /// banner. Mutates `detections` in place, filling `version` where found.
    ///
    /// Bounded for safety: only http(s) assets, internal-IP hosts skipped, at
    /// most `MAX_ASSET_FETCHES` fetches per page, `MAX_ASSET_BYTES` per asset.
    async fn enrich_versions_from_assets(
        &self,
        page_url: &str,
        body: &str,
        detections: &mut [crate::services::fingerprint::TechDetection],
    ) {
        use crate::services::fingerprint::engine;

        // Which versionless detections can we recover a version for?
        let targets: Vec<usize> = detections
            .iter()
            .enumerate()
            .filter(|(_, d)| d.version.is_none() && engine().supports_asset_version(&d.product))
            .map(|(i, _)| i)
            .collect();
        if targets.is_empty() {
            return;
        }

        // Resolve candidate asset URLs from the page (absolute, http(s), external).
        let mut srcs: Vec<String> = Vec::new();
        for raw in Self::extract_asset_urls(body) {
            if let Some(abs) = Self::resolve_asset_url(page_url, &raw) {
                if !Self::asset_host_is_internal(&abs) && !srcs.contains(&abs) {
                    srcs.push(abs);
                }
            }
        }
        if srcs.is_empty() {
            return;
        }

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .danger_accept_invalid_certs(true)
            .user_agent(BROWSER_USER_AGENT)
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut fetched = 0usize;
        let mut cache: HashMap<String, String> = HashMap::new();

        for idx in targets {
            let product = detections[idx].product.clone();
            for src in &srcs {
                if fetched >= MAX_ASSET_FETCHES {
                    return;
                }
                // Only fetch assets whose URL references this product.
                if !src.to_lowercase().contains(&product) {
                    continue;
                }
                let content = if let Some(c) = cache.get(src) {
                    c.clone()
                } else {
                    fetched += 1;
                    let c = Self::fetch_asset_body(&client, src).await.unwrap_or_default();
                    cache.insert(src.clone(), c.clone());
                    c
                };
                if content.is_empty() {
                    continue;
                }
                if let Some(version) = engine().version_from_asset(&product, &content) {
                    tracing::info!(
                        "Recovered {} version '{}' from asset banner: {}",
                        product,
                        version,
                        src
                    );
                    detections[idx].version = Some(version);
                    detections[idx].source = format!("{}+banner", detections[idx].source);
                    detections[idx].evidence = format!("version banner in {}", src);
                    break;
                }
            }
        }
    }

    /// Extract referenced asset URLs from an HTML body — both `<script src>`
    /// and `<link href>` (stylesheets), so CSS-delivered libraries (Bootstrap,
    /// Font Awesome) can be banner-parsed alongside JS ones.
    fn extract_asset_urls(body: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for pat in [
            r#"(?i)<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<link\b[^>]*?\bhref\s*=\s*["']([^"']+)["']"#,
        ] {
            let re = match regex::Regex::new(pat) {
                Ok(re) => re,
                Err(_) => continue,
            };
            for caps in re.captures_iter(body) {
                if let Some(m) = caps.get(1) {
                    let s = m.as_str().trim();
                    if !s.is_empty() && !out.iter().any(|x| x == s) {
                        out.push(s.to_string());
                    }
                }
            }
        }
        out
    }

    /// Resolve a possibly-relative asset URL against the page URL, keeping only
    /// http(s) results.
    fn resolve_asset_url(base: &str, src: &str) -> Option<String> {
        let base = url::Url::parse(base).ok()?;
        let joined = base.join(src.trim()).ok()?;
        match joined.scheme() {
            "http" | "https" => Some(joined.to_string()),
            _ => None,
        }
    }

    /// Guard against SSRF to internal hosts: skip assets whose host is an
    /// internal IP literal.
    fn asset_host_is_internal(asset_url: &str) -> bool {
        url::Url::parse(asset_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .and_then(|h| h.parse::<IpAddr>().ok())
            .map(is_internal_ip)
            .unwrap_or(false)
    }

    /// Fetch an asset body (bounded by size), returning its text.
    async fn fetch_asset_body(client: &reqwest::Client, url: &str) -> Option<String> {
        let resp = client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        if let Some(len) = resp.content_length() {
            if len > MAX_ASSET_BYTES as u64 {
                return None;
            }
        }
        let text = resp.text().await.ok()?;
        if text.len() > MAX_ASSET_BYTES {
            Some(text.chars().take(MAX_ASSET_BYTES).collect())
        } else {
            Some(text)
        }
    }

    fn extract_http_technology_fingerprints(
        headers_map: &HashMap<String, String>,
    ) -> Vec<HttpTechnologyFingerprint> {
        let mut fingerprints = Vec::new();
        let mut seen: HashSet<(String, Option<String>, String)> = HashSet::new();

        for header_name in ["server", "x-powered-by", "x-generator"] {
            if let Some(value) = headers_map.get(header_name) {
                Self::push_fingerprints_from_value(
                    header_name,
                    value,
                    &mut fingerprints,
                    &mut seen,
                );
            }
        }

        for marker in ["x-nextjs-cache", "x-nextjs-data", "x-nextjs-matched-path"] {
            if let Some(value) = headers_map.get(marker) {
                let product = "next.js".to_string();
                let key = (product.clone(), None, marker.to_string());
                if seen.insert(key) {
                    fingerprints.push(HttpTechnologyFingerprint {
                        product,
                        version: None,
                        header_name: marker.to_string(),
                        raw_evidence: value.clone(),
                        confidence: 80,
                    });
                }
            }
        }

        fingerprints
    }

    fn push_fingerprints_from_value(
        header_name: &str,
        header_value: &str,
        fingerprints: &mut Vec<HttpTechnologyFingerprint>,
        seen: &mut HashSet<(String, Option<String>, String)>,
    ) {
        for (product, regex, confidence) in HEADER_BANNER_PATTERNS.iter() {
            for captures in regex.captures_iter(header_value) {
                let version = captures
                    .get(1)
                    .and_then(|m| Self::normalize_fingerprint_version(m.as_str()));
                let key = (
                    product.to_string(),
                    version.clone(),
                    header_name.to_string(),
                );
                if seen.insert(key) {
                    fingerprints.push(HttpTechnologyFingerprint {
                        product: product.to_string(),
                        version,
                        header_name: header_name.to_string(),
                        raw_evidence: header_value.to_string(),
                        confidence: *confidence,
                    });
                }
            }
        }
    }

    fn normalize_fingerprint_version(version: &str) -> Option<String> {
        let normalized = version.trim().trim_start_matches('v').trim().to_string();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    }

    fn technology_stack_from_fingerprints(
        fingerprints: &[HttpTechnologyFingerprint],
    ) -> Vec<String> {
        let mut stack = std::collections::BTreeSet::new();
        for fingerprint in fingerprints {
            if let Some(version) = &fingerprint.version {
                stack.insert(format!("{} {}", fingerprint.product, version));
            } else {
                stack.insert(fingerprint.product.clone());
            }
        }
        stack.into_iter().collect()
    }

    async fn detect_proxy_waf_cdn(
        &self,
        headers: &HashMap<String, String>,
    ) -> ProxyDetectionResult {
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

    /// Deep DNS assessment, delegated to `scanners::dns_scan`.
    ///
    /// What this replaced asked five questions — is there an SPF record, a DMARC
    /// record, a CAA record, any MX, any NS — and answered them with substring
    /// matches. It could not tell `+all` from `-all`, could not count the RFC 7208
    /// lookups that decide whether a policy works at all, never attempted a zone
    /// transfer, and read CAA records through `format!("{:?}")` of the raw record.
    async fn check_dns_security(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        domain: &str,
        deep: bool,
        company_id: Uuid,
    ) -> Result<(DnsSecurityResult, dns_scan::DnsScanResult), ApiError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(BROWSER_USER_AGENT)
            .build()
            .map_err(ApiError::HttpClient)?;

        let outcome = dns_scan::scan(
            &self.dns_resolver,
            &client,
            domain,
            Duration::from_secs(6),
            deep,
        )
        .await;

        self.record_scan_findings(scan_id, asset.id, outcome.findings, company_id)
            .await?;

        Ok((Self::legacy_dns_summary(&outcome.result), outcome.result))
    }

    /// Project the deep result onto the `DnsSecurityResult` shape the scan
    /// summary has always carried, so existing consumers keep working while the
    /// richer `dns` field carries everything new.
    fn legacy_dns_summary(result: &dns_scan::DnsScanResult) -> DnsSecurityResult {
        DnsSecurityResult {
            domain: result.domain.clone(),
            has_mx: result.email.has_mx,
            mx_records: result.records.mx.clone(),
            has_spf: result.email.spf.present,
            spf_record: result.email.spf.record.clone(),
            spf_valid: result.email.spf.valid,
            spf_issues: result.email.spf.issues.clone(),
            has_dkim: !result.email.dkim_selectors_found.is_empty(),
            dkim_selectors_found: result.email.dkim_selectors_found.clone(),
            has_dmarc: result.email.dmarc.present,
            dmarc_record: result.email.dmarc.record.clone(),
            dmarc_policy: result.email.dmarc.policy.clone(),
            dmarc_issues: result.email.dmarc.issues.clone(),
            has_dnssec: result.dnssec.zone_signed,
            dnssec_valid: result
                .dnssec
                .checked
                .then_some(result.dnssec.zone_signed && result.dnssec.delegation_signed),
            has_caa: result.caa_present,
            caa_records: result
                .records
                .caa
                .iter()
                .map(|caa| format!("{} {}", caa.tag, caa.value))
                .collect(),
            zone_transfer_possible: result.zone_transfer_possible,
            nameservers: result
                .nameservers
                .nameservers
                .iter()
                .map(|ns| ns.hostname.clone())
                .collect(),
            issues: result
                .nameservers
                .issues
                .iter()
                .map(|issue| DnsIssue {
                    issue_type: "nameserver_misconfigured".to_string(),
                    severity: issue.severity.clone(),
                    title: "Nameserver configuration".to_string(),
                    description: issue.message.clone(),
                    remediation: "Delegate at least two nameservers on separate networks."
                        .to_string(),
                })
                .collect(),
        }
    }

    // ========================================================================
    // TLS ANALYSIS
    // ========================================================================

    /// Deep TLS/SSL assessment, delegated to `scanners::tls_scan`.
    ///
    /// What this replaced fetched one certificate through `rustls` and checked its
    /// dates, its issuer string and its key size. It could not report a single
    /// protocol version or cipher suite, because `rustls` refuses to negotiate the
    /// deprecated ones this is meant to find; it accepted any certificate rather
    /// than validating the chain, so "untrusted" was unreachable; and the finding
    /// types `weak_tls_version` and `weak_cipher_suite` existed in the taxonomy
    /// with nothing able to emit them.
    ///
    /// The legacy `TlsCertificateDetails` is still produced so the scan summary
    /// keeps its existing shape; the deep result rides alongside it.
    #[allow(clippy::too_many_arguments)]
    async fn analyze_tls_with_findings(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        host: &str,
        port: u16,
        deep: bool,
        risk_factors: &mut Vec<RiskFactor>,
        company_id: Uuid,
    ) -> Result<Option<(TlsCertificateDetails, Option<tls_scan::TlsScanResult>)>, ApiError> {
        let normalized = host.trim().trim_end_matches('.');
        let addr = match tokio::net::lookup_host((normalized, port)).await {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                tracing::debug!("Could not resolve {}:{} for TLS analysis: {}", host, port, e);
                None
            }
        };

        let Some(addr) = addr else {
            // Without an address there is nothing to hand the prober; fall back to
            // the certificate-only path so a scan still reports what it can.
            return Ok(self
                .certificate_only_analysis(scan_id, asset, host, port, company_id)
                .await);
        };

        // Enforce the same target policy the rest of the scan does: a hostname
        // that resolves inside the perimeter must not be probed just because the
        // TLS path reached it by a different route.
        let settings = self.current_settings();
        if !self.is_ip_allowed(&settings, addr.ip()) {
            tracing::info!(
                "Skipping TLS analysis for {}:{}: {} is not permitted by scan policy",
                host,
                port,
                addr.ip()
            );
            return Ok(None);
        }

        let result = tls_scan::scan(normalized, addr, port, Duration::from_secs(8), deep).await;

        if !result.reachable() {
            // The hand-built ClientHello was not answered. That is usually
            // "this port speaks no TLS" — but it is also what a middlebox that
            // rejects an unfamiliar hello looks like, and `rustls` may still
            // complete a handshake where the raw prober could not.
            //
            // Returning here unconditionally would be a regression: the endpoint
            // would get a populated certificate chain and *no* certificate
            // findings, and because every certificate type is in the
            // auto-resolution set, an already-open `expired_certificate` would be
            // closed as fixed. So the fallback chain, when there is one, still
            // goes through the certificate analysis.
            return Ok(self
                .certificate_only_analysis(scan_id, asset, host, port, company_id)
                .await);
        }

        self.record_scan_findings(
            scan_id,
            asset.id,
            tls_scan::build_findings(&result),
            company_id,
        )
        .await?;

        // The grade drives the asset's risk the way a human reader would weight
        // it: an F is a live exposure, an A is nothing to do.
        let impact = match result.grade.grade.as_str() {
            "F" | "T" | "M" => 0.9,
            "E" => 0.7,
            "D" => 0.55,
            "C" => 0.4,
            "B" => 0.25,
            _ => 0.0,
        };
        if impact > 0.0 {
            risk_factors.push(RiskFactor {
                factor_type: "tls".to_string(),
                name: format!("TLS configuration graded {}", result.grade.grade),
                severity: match result.grade.grade.as_str() {
                    "F" | "T" | "M" => "high",
                    "E" | "D" => "medium",
                    _ => "low",
                }
                .to_string(),
                description: if result.grade.caps.is_empty() {
                    format!("TLS endpoint {}:{} graded {}", host, port, result.grade.grade)
                } else {
                    result.grade.caps.join("; ")
                },
                impact_score: impact,
                data: json!({
                    "grade": result.grade.grade,
                    "score": result.grade.score,
                    "caps": result.grade.caps,
                    "warnings": result.grade.warnings,
                }),
            });
        }

        let details = TlsCertificateDetails {
            host: host.to_string(),
            port,
            certificate_chain: result
                .chain
                .chain
                .iter()
                .map(Self::map_parsed_certificate)
                .collect(),
            error: result.errors.first().cloned(),
        };

        Ok(Some((details, Some(result))))
    }

    /// Analyse whatever certificate `rustls` can retrieve, when the raw prober
    /// could not complete a handshake.
    ///
    /// Produces certificate findings but no protocol, cipher or grade — those
    /// genuinely were not measured, and inventing them would be worse than
    /// omitting them.
    async fn certificate_only_analysis(
        &self,
        scan_id: Uuid,
        asset: &Asset,
        host: &str,
        port: u16,
        company_id: Uuid,
    ) -> Option<(TlsCertificateDetails, Option<tls_scan::TlsScanResult>)> {
        let details = self.build_tls_details_from_fallback(host, port).await?;
        if details.certificate_chain.is_empty() {
            return Some((details, None));
        }

        let chain_der = match crate::utils::crypto::get_tls_certificate_chain_der(host, port).await {
            Ok(chain) if !chain.is_empty() => chain,
            _ => return Some((details, None)),
        };

        let result = tls_scan::certificate_only_result(host, port, &chain_der);
        if let Err(e) = self
            .record_scan_findings(
                scan_id,
                asset.id,
                tls_scan::build_findings(&result),
                company_id,
            )
            .await
        {
            tracing::warn!("Failed to record certificate findings for {}: {}", host, e);
        }
        Some((details, Some(result)))
    }

    /// Project a deeply-parsed certificate onto the summary shape the UI reads.
    fn map_parsed_certificate(
        cert: &crate::services::scanners::cert_analysis::ParsedCertificate,
    ) -> TlsCertificateInfo {
        TlsCertificateInfo {
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            organization: cert.organization.clone(),
            common_name: cert.common_name.clone(),
            san_domains: cert.san_domains.clone(),
            not_before: cert.not_before.clone(),
            not_after: cert.not_after.clone(),
            serial_number: cert.serial_number.clone(),
            signature_algorithm: cert.signature_algorithm.clone(),
            public_key_type: cert.public_key_type.clone(),
            public_key_bits: cert.public_key_bits,
        }
    }

    async fn build_tls_details_from_fallback(
        &self,
        host: &str,
        port: u16,
    ) -> Option<TlsCertificateDetails> {
        match get_tls_certificate_info(host, port).await {
            Ok(cert_info) => Some(TlsCertificateDetails {
                host: host.to_string(),
                port,
                certificate_chain: vec![Self::map_raw_tls_info(cert_info)],
                error: None,
            }),
            Err(e) => Some(TlsCertificateDetails {
                host: host.to_string(),
                port,
                certificate_chain: Vec::new(),
                error: Some(e.to_string()),
            }),
        }
    }

    fn map_raw_tls_info(info: crate::utils::crypto::TlsCertificateInfo) -> TlsCertificateInfo {
        TlsCertificateInfo {
            subject: info.subject,
            issuer: info.issuer,
            organization: info.organization,
            common_name: info.common_name,
            san_domains: info.san_domains,
            not_before: info.not_before,
            not_after: info.not_after,
            serial_number: info.serial_number,
            signature_algorithm: info.signature_algorithm,
            public_key_type: info.public_key_type,
            public_key_bits: info.public_key_bits,
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
        company_id: Uuid,
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
                    company_id,
                )
                .await?;

                risk_factors.push(RiskFactor {
                    factor_type: "reputation".to_string(),
                    name: "Malicious reputation".to_string(),
                    severity: "high".to_string(),
                    description: "Target is flagged as malicious by threat intelligence"
                        .to_string(),
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
                    company_id,
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
    // NVD VULNERABILITY LOOKUP
    // ========================================================================

    /// Check if a service name is a generic protocol name (not a specific software product)
    fn is_generic_protocol(service: &str) -> bool {
        const GENERIC_PROTOCOLS: &[&str] = &[
            "http",
            "https",
            "ftp",
            "ftps",
            "sftp",
            "ssh",
            "telnet",
            "smtp",
            "smtps",
            "pop3",
            "pop3s",
            "imap",
            "imaps",
            "dns",
            "dhcp",
            "ntp",
            "snmp",
            "ldap",
            "ldaps",
            "mysql",
            "postgresql",
            "postgres",
            "redis",
            "mongodb",
            "mssql",
            "oracle",
            "rdp",
            "vnc",
            "sip",
            "rtsp",
            "mqtt",
            "amqp",
            "ws",
            "wss",
            "tcp",
            "udp",
            "icmp",
            "ssl",
            "tls",
            "kerberos",
            "smb",
            "nfs",
            "iscsi",
            "http-proxy",
            "socks",
            "socks5",
            "unknown",
        ];

        let normalized = service.to_lowercase();
        GENERIC_PROTOCOLS.contains(&normalized.as_str())
    }

    /// Check if a version string is worth a CVE lookup.
    ///
    /// This only filters out non-version junk (empty, "unknown", "n/a", a bare
    /// protocol token). It deliberately accepts *major-only* versions like Drupal
    /// "10" or PHP "8" — those are real product versions, and NVD matches them.
    /// Generic protocol *services* (ssh, http, …) are already excluded upstream by
    /// `is_generic_protocol`, so we don't second-guess "simple" version numbers
    /// here (doing so wrongly skipped real products such as Drupal 10).
    fn is_valid_software_version(version: &str) -> bool {
        let v = version.trim();
        if v.is_empty() {
            return false;
        }

        // Parses as a numeric version (e.g. "10", "8", "1.0", "2.4.63", "7.4-p1").
        if crate::utils::version_rs::Version::from(v).is_some() {
            return true;
        }

        // Otherwise accept odd-but-real formats that carry a digit plus a letter
        // or build/patch qualifier (e.g. "8u202", "1.0.2k"), while still rejecting
        // pure text like "unknown" / "n/a".
        let has_digit = v.chars().any(|c| c.is_ascii_digit());
        let has_letter = v.chars().any(|c| c.is_alphabetic());
        let has_qualifier = v.contains('-') || v.contains('_') || v.contains('+');
        has_digit && (has_letter || has_qualifier)
    }

    /// Lookup vulnerabilities from NVD (NIST National Vulnerability Database).
    ///
    /// Delegates to a version-aware CPE query (`virtualMatchString`), so NVD
    /// returns only the CVEs whose affected version ranges cover the detected
    /// version of this product.
    /// Look up CVEs for a detected product at a detected version.
    ///
    /// `cpe` is the product's CPE 2.3 base when the detection knows it (every
    /// fingerprint signature with a `cpe` field does). When present it is used
    /// verbatim, which is both more precise — right vendor, right CPE part —
    /// and safe to run for names the protocol denylist would otherwise reject,
    /// because a CPE identifies a product rather than a protocol.
    async fn lookup_vulnerabilities_from_nvd(
        &self,
        product: &str,
        version: &str,
        cpe: Option<&Cpe>,
    ) -> Vec<crate::utils::network::VulnerabilityInfo> {
        use crate::utils::network::VulnerabilityInfo;

        // Skip CVE search for generic protocol names — unless we hold a CPE,
        // which names a concrete product ("mysql" the service banner is
        // ambiguous; cpe:2.3:a:oracle:mysql is not).
        if cpe.is_none() && Self::is_generic_protocol(product) {
            tracing::debug!(
                "Skipping NVD lookup for generic protocol '{}' (version '{}')",
                product,
                version
            );
            return Vec::new();
        }

        // Skip if version looks like a protocol version rather than software version
        if !Self::is_valid_software_version(version) {
            tracing::debug!(
                "Skipping NVD lookup for '{}' - version '{}' appears to be a protocol version",
                product,
                version
            );
            return Vec::new();
        }

        // Normalize product name for the NVD CPE lookup
        let normalized_product = product.to_lowercase();

        tracing::info!(
            "Searching NVD for vulnerabilities in '{}' version '{}'",
            normalized_product,
            version
        );

        // NVD performs the version-range matching server-side (via a
        // virtualMatchString CPE query); the CPE path additionally re-verifies
        // every hit against the CVE's own cpeMatch tree before we believe it.
        let query = match cpe {
            Some(c) => self.nvd_client.search_affecting_cpe(c, version).await,
            None => {
                self.nvd_client
                    .search_affecting(&normalized_product, version)
                    .await
            }
        };
        match query {
            Ok(nvd_vulns) => {
                let mut results = Vec::new();

                for nvd_vuln in nvd_vulns {
                    tracing::info!(
                        "Found vulnerability in '{}' version '{}' - {}",
                        normalized_product,
                        version,
                        nvd_vuln.id
                    );

                    let cve_id = nvd_vuln.id.clone();

                    // Determine severity from CVSS score (fall back to label)
                    let severity = match nvd_vuln.base_score {
                        Some(score) if score >= 9.0 => "critical".to_string(),
                        Some(score) if score >= 7.0 => "high".to_string(),
                        Some(score) if score >= 4.0 => "medium".to_string(),
                        Some(_) => "low".to_string(),
                        None => nvd_vuln
                            .base_severity
                            .clone()
                            .unwrap_or_else(|| "medium".to_string())
                            .to_lowercase(),
                    };

                    // Build references list, with the NVD link as primary reference
                    let mut references = nvd_vuln.references.clone();
                    references.insert(0, NvdClient::vulnerability_url(&cve_id));

                    // Extract title from description or use CVE ID
                    let title = nvd_vuln
                        .description
                        .as_ref()
                        .map(|d| {
                            // Take first sentence or first 100 chars as title
                            let first_sentence = d.split('.').next().unwrap_or(d);
                            if first_sentence.len() > 100 {
                                format!("{}...", &first_sentence[..97])
                            } else {
                                first_sentence.to_string()
                            }
                        })
                        .unwrap_or_else(|| format!("{} Vulnerability", cve_id));

                    // Show the actual affected version range(s) reported by NVD
                    let ranges = match cpe {
                        Some(c) => {
                            NvdClient::affected_version_ranges_for_cpe(&nvd_vuln, c, version)
                        }
                        None => NvdClient::affected_version_ranges(
                            &nvd_vuln,
                            &normalized_product,
                            version,
                        ),
                    };
                    let affected_versions_display = match ranges {
                        ranges if ranges.is_empty() => vec!["Unknown".to_string()],
                        ranges => {
                            tracing::info!("Affected versions: {}", ranges.join(", "));
                            ranges
                        }
                    };

                    results.push(VulnerabilityInfo {
                        cve_id,
                        title,
                        description: nvd_vuln
                            .description
                            .unwrap_or_else(|| "No description available".to_string()),
                        severity,
                        cvss_score: nvd_vuln.base_score,
                        cvss_vector: nvd_vuln.base_score_vector,
                        affected_versions: affected_versions_display,
                        references,
                        exploitable: nvd_vuln.exploited,
                        has_public_exploit: nvd_vuln.exploited,
                    });
                }

                if !results.is_empty() {
                    tracing::info!(
                        "NVD returned {} matching vulnerabilities for product '{}' version '{}'",
                        results.len(),
                        product,
                        version
                    );
                }

                results
            }
            Err(e) => {
                tracing::warn!("NVD lookup failed for {}: {}", product, e);
                Vec::new()
            }
        }
    }

    // ========================================================================
    // FINDING CREATION
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn resolve_stale_findings(
        &self,
        scan_id: Uuid,
        asset_id: Uuid,
        scan_type: &SecurityScanType,
        deep: bool,
        scan_started_at: chrono::DateTime<Utc>,
        company_id: Uuid,
    ) -> Result<u64, ApiError> {
        let types_checked = Self::finding_types_for_scan(scan_type);
        if types_checked.is_empty() {
            return Ok(0);
        }

        let mut type_set: HashSet<&str> = types_checked.into_iter().collect();
        if !deep {
            // A shallow scan skips path probing, method probing and the zone
            // transfer attempt entirely. Leaving those types in scope would let a
            // scan that never looked mark a critical exposure as fixed simply by
            // not re-reporting it.
            for finding_type in DEEP_ONLY_FINDING_TYPES {
                type_set.remove(finding_type);
            }
        }

        let current_findings = self.finding_repo.list_by_scan(&scan_id, company_id).await?;
        let mut seen_keys: HashSet<(String, String)> = HashSet::new();
        for finding in current_findings {
            if finding.finding_type == "known_cve"
                && !Self::is_known_cve_in_scope(scan_type, &finding.data)
            {
                continue;
            }
            seen_keys.insert((finding.finding_type, finding.title));
        }

        let asset_findings = self
            .finding_repo
            .list_by_asset(&asset_id, 5000, company_id)
            .await?;

        let mut stale_ids = Vec::new();
        for finding in asset_findings {
            if !type_set.contains(finding.finding_type.as_str()) {
                continue;
            }
            if finding.finding_type == "known_cve"
                && !Self::is_known_cve_in_scope(scan_type, &finding.data)
            {
                continue;
            }
            if finding.status == "resolved" || finding.status == "false_positive" {
                continue;
            }
            if finding.last_seen_at >= scan_started_at {
                continue;
            }

            if seen_keys.contains(&(finding.finding_type.clone(), finding.title.clone())) {
                continue;
            }

            stale_ids.push(finding.id);
        }

        self.finding_repo
            .resolve_by_ids(&stale_ids, company_id)
            .await
    }

    fn is_known_cve_in_scope(scan_type: &SecurityScanType, finding_data: &Value) -> bool {
        if !matches!(
            scan_type,
            SecurityScanType::PortScan | SecurityScanType::HttpProbe
        ) {
            return true;
        }

        let detection_method = finding_data
            .get("detection_method")
            .and_then(|value| value.as_str());

        match scan_type {
            SecurityScanType::PortScan => detection_method != Some("http_header_fingerprint"),
            SecurityScanType::HttpProbe => detection_method == Some("http_header_fingerprint"),
            _ => true,
        }
    }

    /// The finding types a given scan is authoritative for.
    ///
    /// This drives auto-resolution: a type listed here that a fresh scan did *not*
    /// re-report is treated as fixed and closed. A type the scanners emit but that
    /// is missing from this list therefore stays open forever, long after it was
    /// remediated — so these lists have to track the scanners exactly.
    fn finding_types_for_scan(scan_type: &SecurityScanType) -> Vec<&'static str> {
        const PORT_TYPES: [&str; 6] = [
            "open_port",
            "sensitive_port",
            "database_exposed",
            "admin_port_exposed",
            "known_cve",
            "dns_resolution_failed",
        ];
        const HTTP_TYPES: [&str; 14] = [
            "missing_security_header",
            "weak_security_header",
            "https_not_enforced",
            "server_version_exposed",
            "no_waf_detected",
            "technology_detected",
            "insecure_cookies",
            "cors_misconfiguration",
            "dangerous_http_method",
            "directory_listing",
            "mixed_content",
            "missing_sri",
            "security_txt_missing",
            "sensitive_data_exposed",
        ];
        /// Emitted by the HTTP scanner but shared with other sources, so listed
        /// separately to keep the per-scan-type sets honest.
        const HTTP_SHARED_TYPES: [&str; 2] = ["debug_endpoint_exposed", "information_disclosure"];
        const TLS_TYPES: [&str; 18] = [
            "expired_certificate",
            "certificate_expiring_soon",
            "self_signed_certificate",
            "certificate_not_yet_valid",
            "weak_signature_algorithm",
            "weak_key_strength",
            "certificate_missing_san",
            "certificate_hostname_mismatch",
            "certificate_chain_incomplete",
            "certificate_untrusted",
            "certificate_lifetime_excessive",
            "certificate_transparency_missing",
            "weak_tls_version",
            "weak_cipher_suite",
            "no_forward_secrecy",
            "tls_vulnerability",
            "tls_misconfiguration",
            "missing_ocsp_stapling",
        ];
        const DNS_TYPES: [&str; 19] = [
            "missing_spf",
            "weak_spf_policy",
            "spf_lookup_limit_exceeded",
            "multiple_spf_records",
            "missing_dmarc",
            "weak_dmarc_policy",
            "missing_dkim",
            "missing_caa",
            "caa_incomplete",
            "missing_dnssec",
            "dnssec_misconfigured",
            "zone_transfer_allowed",
            "dangling_dns",
            "nameserver_misconfigured",
            "dns_misconfiguration",
            "soa_misconfigured",
            "missing_mta_sts",
            "mta_sts_misconfigured",
            "missing_tls_rpt",
        ];
        const THREAT_TYPES: [&str; 1] = ["reputation_issue"];

        let mut types = Vec::new();
        match scan_type {
            SecurityScanType::Full => {
                types.extend_from_slice(&PORT_TYPES);
                types.extend_from_slice(&HTTP_TYPES);
                types.extend_from_slice(&HTTP_SHARED_TYPES);
                types.extend_from_slice(&TLS_TYPES);
                types.extend_from_slice(&DNS_TYPES);
                types.extend_from_slice(&THREAT_TYPES);
            }
            SecurityScanType::PortScan => {
                types.extend_from_slice(&PORT_TYPES);
            }
            SecurityScanType::HttpProbe => {
                types.extend_from_slice(&HTTP_TYPES);
                types.extend_from_slice(&HTTP_SHARED_TYPES);
                types.push("known_cve");
                types.push("dns_resolution_failed");
            }
            SecurityScanType::TlsAnalysis => {
                types.extend_from_slice(&TLS_TYPES);
                types.push("dns_resolution_failed");
            }
            SecurityScanType::DnsAudit => {
                types.extend_from_slice(&DNS_TYPES);
            }
            SecurityScanType::ThreatIntel => {
                types.extend_from_slice(&THREAT_TYPES);
            }
        }

        types
    }

    /// Persist the findings a scanner produced.
    ///
    /// The deep scanners return `ScanFinding` values rather than writing rows
    /// themselves, so company scoping, deduplication and the remediation text all
    /// stay in one place — and so a scanner's entire output can be asserted in a
    /// unit test without a database.
    async fn record_scan_findings(
        &self,
        scan_id: Uuid,
        asset_id: Uuid,
        findings: Vec<ScanFinding>,
        company_id: Uuid,
    ) -> Result<usize, ApiError> {
        let mut recorded = 0usize;
        for finding in findings {
            let create = SecurityFindingCreate {
                security_scan_id: Some(scan_id),
                asset_id,
                finding_type: finding.finding_type.clone(),
                severity: finding.severity,
                title: finding.title,
                description: Some(finding.description),
                // The scanner writes remediation specific to what it found, which
                // is always better than the per-type fallback; the fallback still
                // covers a scanner that leaves it empty.
                remediation: if finding.remediation.is_empty() {
                    get_remediation(&finding.finding_type)
                } else {
                    Some(finding.remediation)
                },
                data: finding.data,
                cvss_score: None,
                cve_ids: None,
                tags: None,
            };
            match self.finding_repo.create_or_update(&create, company_id).await {
                Ok(_) => recorded += 1,
                Err(e) => tracing::warn!(
                    "Failed to record {} finding for asset {}: {}",
                    create.finding_type,
                    asset_id,
                    e
                ),
            }
        }
        Ok(recorded)
    }

    async fn create_finding(
        &self,
        scan_id: Uuid,
        asset_id: Uuid,
        finding_type: &str,
        severity: FindingSeverity,
        title: &str,
        description: Option<&str>,
        data: Value,
        company_id: Uuid,
    ) -> Result<SecurityFinding, ApiError> {
        self.create_finding_with_cvss(
            scan_id,
            asset_id,
            finding_type,
            severity,
            title,
            description,
            data,
            None,
            None,
            company_id,
        )
        .await
    }

    async fn create_finding_with_cvss(
        &self,
        scan_id: Uuid,
        asset_id: Uuid,
        finding_type: &str,
        severity: FindingSeverity,
        title: &str,
        description: Option<&str>,
        data: Value,
        cvss_score: Option<f64>,
        cve_ids: Option<Vec<String>>,
        company_id: Uuid,
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
            cvss_score,
            cve_ids,
            tags: None,
        };

        self.finding_repo
            .create_or_update(&finding, company_id)
            .await
    }

    // ========================================================================
    // FINDINGS MANAGEMENT
    // ========================================================================

    pub async fn list_findings_for_asset(
        &self,
        asset_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<SecurityFinding>, ApiError> {
        self.finding_repo
            .list_by_asset(asset_id, 1000, company_id)
            .await
    }

    pub async fn get_finding(
        &self,
        id: &Uuid,
        company_id: Uuid,
    ) -> Result<Option<SecurityFinding>, ApiError> {
        self.finding_repo.get_by_id(id, company_id).await
    }

    pub async fn get_findings_summary(
        &self,
        company_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>, ApiError> {
        self.finding_repo.count_by_severity(company_id).await
    }
}

// Implement Clone for async task spawning
impl Clone for SecurityScanService {
    fn clone(&self) -> Self {
        Self {
            asset_repo: Arc::clone(&self.asset_repo),
            scan_repo: Arc::clone(&self.scan_repo),
            finding_repo: Arc::clone(&self.finding_repo),
            risk_service: Arc::clone(&self.risk_service),
            external_services: Arc::clone(&self.external_services),
            dns_resolver: Arc::clone(&self.dns_resolver),
            http_prober: Arc::clone(&self.http_prober),
            tls_analyzer: Arc::clone(&self.tls_analyzer),
            nvd_client: Arc::clone(&self.nvd_client),
            threat_intel: Arc::clone(&self.threat_intel),
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
        "certificate_not_yet_valid" => Some("Adjust system time or reissue the certificate so its validity period starts immediately.".to_string()),
        "self_signed_certificate" => Some("Replace self-signed certificate with a certificate from a trusted Certificate Authority.".to_string()),
        "weak_signature_algorithm" => Some("Reissue the certificate using a modern signature algorithm (SHA-256 or stronger).".to_string()),
        "weak_key_strength" => Some("Reissue the certificate with a stronger key (RSA 2048+ or ECDSA P-256+).".to_string()),
        "certificate_missing_san" => Some("Reissue the certificate with Subject Alternative Names (SAN) matching the hostnames.".to_string()),
        "certificate_hostname_mismatch" => Some("Reissue or configure the certificate so it matches the requested hostname.".to_string()),
        "certificate_chain_incomplete" => Some("Install the full certificate chain, including intermediate certificates.".to_string()),
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
        // The deep scanners write remediation specific to what they found, which
        // is always better than a per-type default. These cover the case where a
        // finding of one of these types arrives from somewhere else.
        "weak_cipher_suite" => Some("Restrict the cipher list to AEAD suites with forward secrecy (ECDHE with AES-GCM or ChaCha20-Poly1305).".to_string()),
        "no_forward_secrecy" => Some("Offer only ECDHE or DHE key exchange and remove static RSA cipher suites.".to_string()),
        "tls_vulnerability" => Some("Apply the vendor patch for the affected TLS stack, then remove the protocol or cipher the attack depends on.".to_string()),
        "tls_misconfiguration" => Some("Review the TLS server configuration against the Mozilla SSL Configuration Generator.".to_string()),
        "certificate_untrusted" => Some("Install the complete certificate chain from a publicly trusted CA, including every intermediate.".to_string()),
        "certificate_lifetime_excessive" => Some("Reissue with a lifetime of 398 days or less and automate renewal.".to_string()),
        "certificate_transparency_missing" => Some("Use a CA that submits to Certificate Transparency logs, and monitor crt.sh for unexpected issuance.".to_string()),
        "missing_ocsp_stapling" => Some("Enable OCSP stapling (ssl_stapling on in nginx, SSLUseStapling on in Apache).".to_string()),
        "weak_security_header" => Some("Tighten the header's value; its presence alone does not provide the protection it implies.".to_string()),
        "insecure_cookies" => Some("Set Secure and SameSite on every cookie and HttpOnly on every session cookie.".to_string()),
        "cors_misconfiguration" => Some("Validate the Origin header against an allowlist; never combine a reflected or wildcard origin with Allow-Credentials.".to_string()),
        "dangerous_http_method" => Some("Disable TRACE and restrict write methods to authenticated routes.".to_string()),
        "mixed_content" => Some("Serve every subresource over HTTPS and add upgrade-insecure-requests to the CSP.".to_string()),
        "missing_sri" => Some("Add integrity and crossorigin attributes to every externally hosted script.".to_string()),
        "security_txt_missing" => Some("Publish /.well-known/security.txt with Contact: and Expires: fields (RFC 9116).".to_string()),
        "sensitive_data_exposed" => Some("Remove the file from the web root and rotate every credential it disclosed.".to_string()),
        "debug_endpoint_exposed" => Some("Disable the endpoint in production, or restrict it to localhost behind authentication.".to_string()),
        "directory_listing" => Some("Disable automatic directory indexing (Options -Indexes in Apache, autoindex off in nginx).".to_string()),
        "weak_spf_policy" => Some("End the SPF record in -all once every legitimate sender is listed.".to_string()),
        "spf_lookup_limit_exceeded" => Some("Flatten or consolidate include: chains so the policy stays within ten DNS lookups (RFC 7208 §4.6.4).".to_string()),
        "multiple_spf_records" => Some("Merge the SPF records into a single TXT record at the apex.".to_string()),
        "missing_dkim" => Some("Confirm the selector in use from a signed message's DKIM-Signature s= tag, and enable DKIM signing if none is set.".to_string()),
        "missing_mta_sts" => Some("Publish an _mta-sts TXT record and serve a policy in enforce mode at https://mta-sts.<domain>/.well-known/mta-sts.txt.".to_string()),
        "mta_sts_misconfigured" => Some("Set mode: enforce in the MTA-STS policy and max_age to at least 604800.".to_string()),
        "missing_tls_rpt" => Some("Publish v=TLSRPTv1; rua=mailto:tlsrpt@<domain> at _smtp._tls.<domain>.".to_string()),
        "missing_dnssec" => Some("Enable DNSSEC at the DNS provider and publish the DS record through the registrar.".to_string()),
        "dnssec_misconfigured" => Some("Complete the chain of trust: publish the DS record at the registrar, or remove it if the zone is no longer signed.".to_string()),
        "caa_incomplete" => Some("Add issuewild and iodef records to complete the CAA policy.".to_string()),
        "zone_transfer_allowed" => Some("Restrict AXFR to the secondary nameservers' IP addresses, and prefer TSIG authentication.".to_string()),
        "dangling_dns" => Some("Remove the DNS record, or reclaim the resource at the provider before someone else does.".to_string()),
        "nameserver_misconfigured" => Some("Delegate at least two nameservers on separate networks, each answering authoritatively for the zone.".to_string()),
        "soa_misconfigured" => Some("Adjust the SOA refresh, retry, expire and minimum values to the ranges in RFC 1912 §2.2.".to_string()),
        "dns_misconfiguration" => Some("Correct the DNS record so it conforms to the relevant RFC.".to_string()),
        "information_disclosure" => Some("Stop publishing the information, or restrict it to an authenticated context.".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vuln(cve_id: &str, service: &str, version: &str) -> VulnerabilityResult {
        VulnerabilityResult {
            cve_id: cve_id.to_string(),
            title: format!("{} test vuln", cve_id),
            severity: "high".to_string(),
            cvss_score: Some(8.5),
            affected_service: service.to_string(),
            affected_version: version.to_string(),
            exploitable: true,
            has_public_exploit: false,
            description: "test".to_string(),
            remediation: None,
            references: vec![],
        }
    }

    #[test]
    fn extracts_nextjs_version_from_powered_by_header() {
        let mut headers = HashMap::new();
        headers.insert("x-powered-by".to_string(), "Next.js 14.2.3".to_string());

        let fingerprints = SecurityScanService::extract_http_technology_fingerprints(&headers);

        assert!(fingerprints.iter().any(|f| {
            f.product == "next.js"
                && f.version.as_deref() == Some("14.2.3")
                && f.header_name == "x-powered-by"
        }));
    }

    #[test]
    fn extracts_nextjs_marker_without_version() {
        let mut headers = HashMap::new();
        headers.insert("x-nextjs-cache".to_string(), "HIT".to_string());

        let fingerprints = SecurityScanService::extract_http_technology_fingerprints(&headers);

        assert!(fingerprints.iter().any(|f| {
            f.product == "next.js" && f.version.is_none() && f.header_name == "x-nextjs-cache"
        }));
    }

    #[test]
    fn extracts_common_server_tokens() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.25.3".to_string());
        headers.insert("x-generator".to_string(), "WordPress 6.5.3".to_string());

        let fingerprints = SecurityScanService::extract_http_technology_fingerprints(&headers);

        assert!(fingerprints.iter().any(|f| {
            f.product == "nginx"
                && f.version.as_deref() == Some("1.25.3")
                && f.header_name == "server"
        }));
        assert!(fingerprints.iter().any(|f| {
            f.product == "wordpress"
                && f.version.as_deref() == Some("6.5.3")
                && f.header_name == "x-generator"
        }));
    }

    #[test]
    fn dedupes_vulnerabilities_deterministically() {
        let vulns = vec![
            sample_vuln("CVE-2024-1234", "next.js", "14.2.3"),
            sample_vuln("cve-2024-1234", "Next.js", "14.2.3"),
            sample_vuln("CVE-2023-9999", "nginx", "1.25.3"),
        ];

        let deduped = SecurityScanService::dedupe_vulnerability_results(vulns);

        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].cve_id, "CVE-2023-9999");
        assert_eq!(deduped[1].cve_id, "CVE-2024-1234");
    }

    #[test]
    fn every_scanner_finding_type_can_be_auto_resolved() {
        // A finding type a scanner emits but this list omits stays open forever
        // after it is remediated, because nothing ever closes it. The scanners
        // declare what they emit; this proves the scopes cover all of it.
        use crate::services::scanners::{dns_scan, http_scan, tls_scan};

        let full: HashSet<&str> = scope_for(&SecurityScanType::Full);
        for finding_type in dns_scan::EMITTED_FINDING_TYPES
            .iter()
            .chain(tls_scan::EMITTED_FINDING_TYPES)
            .chain(http_scan::EMITTED_FINDING_TYPES)
        {
            assert!(
                full.contains(finding_type),
                "{} is emitted by a scanner but a full scan cannot resolve it",
                finding_type
            );
        }

        // And each focused scan type must cover its own scanner.
        let dns: HashSet<&str> = scope_for(&SecurityScanType::DnsAudit);
        for finding_type in dns_scan::EMITTED_FINDING_TYPES {
            // `information_disclosure` is shared with the HTTP scanner, so a
            // DNS-only scan deliberately does not claim authority over it.
            if *finding_type == "information_disclosure" {
                continue;
            }
            assert!(dns.contains(finding_type), "DNS audit cannot resolve {}", finding_type);
        }

        let tls: HashSet<&str> = scope_for(&SecurityScanType::TlsAnalysis);
        for finding_type in tls_scan::EMITTED_FINDING_TYPES {
            assert!(tls.contains(finding_type), "TLS scan cannot resolve {}", finding_type);
        }

        let http: HashSet<&str> = scope_for(&SecurityScanType::HttpProbe);
        for finding_type in http_scan::EMITTED_FINDING_TYPES {
            assert!(http.contains(finding_type), "HTTP probe cannot resolve {}", finding_type);
        }
    }

    fn scope_for(scan_type: &SecurityScanType) -> HashSet<&'static str> {
        SecurityScanService::finding_types_for_scan(scan_type)
            .into_iter()
            .collect()
    }


    #[test]
    fn known_cve_scope_filtering_is_source_aware() {
        let header_data = json!({ "detection_method": "http_header_fingerprint" });
        let port_data = json!({ "detection_method": "port_service_detection" });
        let legacy_data = json!({});

        assert!(SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::Full,
            &header_data
        ));
        assert!(!SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::PortScan,
            &header_data
        ));
        assert!(SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::PortScan,
            &port_data
        ));
        assert!(SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::PortScan,
            &legacy_data
        ));
        assert!(SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::HttpProbe,
            &header_data
        ));
        assert!(!SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::HttpProbe,
            &port_data
        ));
        assert!(!SecurityScanService::is_known_cve_in_scope(
            &SecurityScanType::HttpProbe,
            &legacy_data
        ));
    }

    #[test]
    fn resolves_ip_http_target_from_fallback_ports() {
        let ip: IpAddr = "127.0.0.1".parse().expect("valid localhost IP");
        let target = SecurityScanService::resolve_http_target_from_ports(ip, &[], &[8080]);
        assert_eq!(target, Some("127.0.0.1:8080".to_string()));
    }

    #[test]
    fn version_gate_accepts_major_only_and_rejects_junk() {
        // Major-only versions are real product versions (Drupal 10, PHP 8) and
        // must be looked up — this was the regression that hid Drupal 10 CVEs.
        assert!(SecurityScanService::is_valid_software_version("10"));
        assert!(SecurityScanService::is_valid_software_version("8"));
        assert!(SecurityScanService::is_valid_software_version("1.0"));
        assert!(SecurityScanService::is_valid_software_version("2.4.63"));
        assert!(SecurityScanService::is_valid_software_version("7.4-p1"));
        assert!(SecurityScanService::is_valid_software_version("8u202"));
        assert!(SecurityScanService::is_valid_software_version("1.0.2k"));

        // Non-version junk is still skipped.
        assert!(!SecurityScanService::is_valid_software_version(""));
        assert!(!SecurityScanService::is_valid_software_version("unknown"));
        assert!(!SecurityScanService::is_valid_software_version("n/a"));
    }

    #[test]
    fn extracts_asset_urls_from_body() {
        let body = r#"
            <script src="js/lib/jquery.min.js"></script>
            <script type="text/javascript" src='https://cdn.example.com/vue.min.js'></script>
            <script>var x = 1; // inline, no src</script>
            <script defer src="js/lib/jquery.min.js"></script>
            <link rel="stylesheet" href="/css/bootstrap.min.css">
        "#;
        let srcs = SecurityScanService::extract_asset_urls(body);
        // Inline script excluded; duplicate jquery deduped; stylesheet included.
        assert_eq!(srcs.len(), 3);
        assert!(srcs.iter().any(|s| s == "js/lib/jquery.min.js"));
        assert!(srcs.iter().any(|s| s == "https://cdn.example.com/vue.min.js"));
        assert!(srcs.iter().any(|s| s == "/css/bootstrap.min.css"));
    }

    #[test]
    fn resolves_relative_and_absolute_asset_urls() {
        assert_eq!(
            SecurityScanService::resolve_asset_url(
                "https://site.test/some/page",
                "js/lib/jquery.min.js"
            ),
            Some("https://site.test/some/js/lib/jquery.min.js".to_string())
        );
        assert_eq!(
            SecurityScanService::resolve_asset_url("https://site.test/", "/static/jquery.js"),
            Some("https://site.test/static/jquery.js".to_string())
        );
        assert_eq!(
            SecurityScanService::resolve_asset_url("https://site.test/", "https://cdn.x/vue.js"),
            Some("https://cdn.x/vue.js".to_string())
        );
        // Non-http(s) schemes are rejected.
        assert_eq!(
            SecurityScanService::resolve_asset_url("https://site.test/", "data:application/js,1"),
            None
        );
    }

    #[test]
    fn asset_internal_host_guard_blocks_internal_ips() {
        assert!(SecurityScanService::asset_host_is_internal(
            "http://127.0.0.1/jquery.js"
        ));
        assert!(SecurityScanService::asset_host_is_internal(
            "http://10.0.0.5/jquery.min.js"
        ));
        assert!(SecurityScanService::asset_host_is_internal(
            "http://192.168.1.1/x.js"
        ));
        // Public CDN host (non-IP) is allowed.
        assert!(!SecurityScanService::asset_host_is_internal(
            "https://code.jquery.com/jquery-3.6.0.min.js"
        ));
    }
}

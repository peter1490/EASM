use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================================
// Security Scan - Active security assessment of an asset
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityScanType {
    PortScan,
    TlsAnalysis,
    HttpProbe,
    ThreatIntel,
    Full,
}

impl Default for SecurityScanType {
    fn default() -> Self {
        Self::Full
    }
}

impl std::fmt::Display for SecurityScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityScanType::PortScan => write!(f, "port_scan"),
            SecurityScanType::TlsAnalysis => write!(f, "tls_analysis"),
            SecurityScanType::HttpProbe => write!(f, "http_probe"),
            SecurityScanType::ThreatIntel => write!(f, "threat_intel"),
            SecurityScanType::Full => write!(f, "full"),
        }
    }
}

impl From<&str> for SecurityScanType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "port_scan" | "ports" => SecurityScanType::PortScan,
            "tls_analysis" | "tls" | "ssl" => SecurityScanType::TlsAnalysis,
            "http_probe" | "http" | "web" => SecurityScanType::HttpProbe,
            "threat_intel" | "threat" | "intel" => SecurityScanType::ThreatIntel,
            _ => SecurityScanType::Full,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl Default for SecurityScanStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for SecurityScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityScanStatus::Pending => write!(f, "pending"),
            SecurityScanStatus::Running => write!(f, "running"),
            SecurityScanStatus::Completed => write!(f, "completed"),
            SecurityScanStatus::Failed => write!(f, "failed"),
            SecurityScanStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanTriggerType {
    Manual,
    Scheduled,
    Discovery,
    OnChange,
}

impl Default for ScanTriggerType {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityScan {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub trigger_type: String,
    pub priority: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
    pub config: Value,
    pub result_summary: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityScanCreate {
    pub asset_id: Uuid,
    pub scan_type: Option<SecurityScanType>,
    pub trigger_type: Option<ScanTriggerType>,
    pub priority: Option<i32>,
    pub note: Option<String>,
    pub config: Option<Value>,
}

/// Response DTO for scan list with asset info
#[derive(Debug, Clone, Serialize)]
pub struct SecurityScanListResponse {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub asset_identifier: String,
    pub asset_type: String,
    pub scan_type: String,
    pub status: String,
    pub trigger_type: String,
    pub priority: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub findings_count: i64,
    pub created_at: DateTime<Utc>,
}

/// Response DTO for scan detail with findings
#[derive(Debug, Clone, Serialize)]
pub struct SecurityScanDetailResponse {
    pub scan: SecurityScan,
    pub asset: crate::models::Asset,
    pub findings: Vec<SecurityFinding>,
    pub findings_count: i64,
}

// ============================================================================
// Security Finding - Issues found during scans
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Default for FindingSeverity {
    fn default() -> Self {
        Self::Info
    }
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Critical => write!(f, "critical"),
            FindingSeverity::High => write!(f, "high"),
            FindingSeverity::Medium => write!(f, "medium"),
            FindingSeverity::Low => write!(f, "low"),
            FindingSeverity::Info => write!(f, "info"),
        }
    }
}

impl From<&str> for FindingSeverity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => FindingSeverity::Critical,
            "high" => FindingSeverity::High,
            "medium" => FindingSeverity::Medium,
            "low" => FindingSeverity::Low,
            _ => FindingSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
    Accepted,
}

impl Default for FindingStatus {
    fn default() -> Self {
        Self::Open
    }
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Open => write!(f, "open"),
            FindingStatus::Acknowledged => write!(f, "acknowledged"),
            FindingStatus::InProgress => write!(f, "in_progress"),
            FindingStatus::Resolved => write!(f, "resolved"),
            FindingStatus::FalsePositive => write!(f, "false_positive"),
            FindingStatus::Accepted => write!(f, "accepted"),
        }
    }
}

/// Predefined finding types for consistency
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    // Port scan findings
    OpenPort,
    UnexpectedService,
    // TLS findings
    WeakTlsVersion,
    WeakCipherSuite,
    ExpiredCertificate,
    SelfSignedCertificate,
    CertificateExpiringSoon,
    MismatchedCertificate,
    // HTTP security findings
    MissingSecurityHeader,
    InsecureCookies,
    HttpsNotEnforced,
    SensitiveDataExposed,
    DirectoryListing,
    // Threat intelligence
    MalwareDetected,
    ReputationIssue,
    BlocklistedIp,
    SuspiciousBehavior,
    // DNS findings
    DnsMisconfiguration,
    DanglingDns,
    ZoneTransferAllowed,
    // Generic
    ConfigurationIssue,
    VulnerabilityDetected,
    ComplianceViolation,
    Other,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FindingType::OpenPort => "open_port",
            FindingType::UnexpectedService => "unexpected_service",
            FindingType::WeakTlsVersion => "weak_tls_version",
            FindingType::WeakCipherSuite => "weak_cipher_suite",
            FindingType::ExpiredCertificate => "expired_certificate",
            FindingType::SelfSignedCertificate => "self_signed_certificate",
            FindingType::CertificateExpiringSoon => "certificate_expiring_soon",
            FindingType::MismatchedCertificate => "mismatched_certificate",
            FindingType::MissingSecurityHeader => "missing_security_header",
            FindingType::InsecureCookies => "insecure_cookies",
            FindingType::HttpsNotEnforced => "https_not_enforced",
            FindingType::SensitiveDataExposed => "sensitive_data_exposed",
            FindingType::DirectoryListing => "directory_listing",
            FindingType::MalwareDetected => "malware_detected",
            FindingType::ReputationIssue => "reputation_issue",
            FindingType::BlocklistedIp => "blocklisted_ip",
            FindingType::SuspiciousBehavior => "suspicious_behavior",
            FindingType::DnsMisconfiguration => "dns_misconfiguration",
            FindingType::DanglingDns => "dangling_dns",
            FindingType::ZoneTransferAllowed => "zone_transfer_allowed",
            FindingType::ConfigurationIssue => "configuration_issue",
            FindingType::VulnerabilityDetected => "vulnerability_detected",
            FindingType::ComplianceViolation => "compliance_violation",
            FindingType::Other => "other",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecurityFinding {
    pub id: Uuid,
    pub security_scan_id: Option<Uuid>,
    pub asset_id: Uuid,
    pub finding_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub data: Value,
    pub status: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<Uuid>,
    pub cvss_score: Option<f64>,
    pub cve_ids: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityFindingCreate {
    pub security_scan_id: Option<Uuid>,
    pub asset_id: Uuid,
    pub finding_type: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub data: Value,
    pub cvss_score: Option<f64>,
    pub cve_ids: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityFindingUpdate {
    pub status: Option<FindingStatus>,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Filter criteria for security findings
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SecurityFindingFilter {
    #[serde(default)]
    pub asset_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub scan_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub finding_types: Option<Vec<String>>,
    #[serde(default)]
    pub severities: Option<Vec<String>>,
    #[serde(default)]
    pub statuses: Option<Vec<String>>,
    #[serde(default)]
    pub search_text: Option<String>,
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,
    #[serde(default = "default_sort_by")]
    pub sort_by: String,
    #[serde(default = "default_sort_direction")]
    pub sort_direction: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_sort_by() -> String {
    "first_seen_at".to_string()
}

fn default_sort_direction() -> String {
    "desc".to_string()
}

fn default_limit() -> i64 {
    100
}

/// Response for paginated findings
#[derive(Debug, Clone, Serialize)]
pub struct SecurityFindingListResponse {
    pub findings: Vec<SecurityFinding>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

// ============================================================================
// Scan Configuration
// ============================================================================

/// Configuration for security scans
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Custom ports to scan (empty = use defaults)
    pub ports: Option<Vec<u16>>,
    /// Timeout for connections in seconds
    pub timeout_seconds: Option<f64>,
    /// Whether to do deep TLS analysis
    pub deep_tls_analysis: Option<bool>,
    /// Whether to check threat intelligence
    pub check_threat_intel: Option<bool>,
    /// HTTP paths to probe
    pub http_paths: Option<Vec<String>>,
    /// User agent string for HTTP requests
    pub user_agent: Option<String>,
}

/// Result summary stored after scan completion
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanResultSummary {
    pub open_ports: Option<Vec<u16>>,
    pub tls_version: Option<String>,
    pub http_status: Option<i32>,
    pub findings_by_severity: Option<std::collections::HashMap<String, i32>>,
    pub scan_duration_ms: Option<i64>,
    pub errors: Option<Vec<String>>,
}

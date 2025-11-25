pub mod auth_service;
pub mod confidence;
pub mod discovery_service;
pub mod drift_service;
pub mod external;
pub mod metrics_service;
pub mod risk_service;
pub mod scan_service;
pub mod search_service;
pub mod security_scan_service;
pub mod task_manager;

// Re-export commonly used types
pub use auth_service::AuthService;
pub use confidence::ConfidenceScorer;
pub use discovery_service::{DiscoveryService, DiscoveryStatus};
pub use drift_service::{DriftService, DriftServiceImpl};
pub use metrics_service::MetricsService;
pub use risk_service::RiskService;
pub use scan_service::ScanService;
pub use search_service::{SearchService, ElasticsearchService, SearchQuery, IndexedAsset, IndexedFinding};
pub use security_scan_service::SecurityScanService;
pub use task_manager::TaskManager;

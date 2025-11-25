pub mod asset_handlers;
pub mod discovery_handlers;
pub mod drift_handlers;
pub mod evidence_handlers;
pub mod finding_handlers;
pub mod health_handlers;
pub mod metrics_handlers;
pub mod risk_handlers;
pub mod scan_handlers;
pub mod search_handlers;
pub mod static_handlers;
pub mod auth_handlers;
pub mod admin_handlers; // Added

pub use health_handlers::{health_check, health_check_simple, readiness_check, liveness_check};
pub use static_handlers::{serve_evidence_file, static_files_health_check};

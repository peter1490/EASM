pub mod asset_repo;
pub mod discovery_repo;
pub mod evidence_repo;
pub mod finding_repo;
pub mod scan_repo;
pub mod security_repo;
pub mod seed_repo;
pub mod user_repo;

// Re-export commonly used types
pub use asset_repo::{AssetRepository, SqlxAssetRepository};
pub use discovery_repo::{
    DiscoveryRunRepository, SqlxDiscoveryRunRepository,
    DiscoveryQueueRepository, SqlxDiscoveryQueueRepository,
    AssetSourceRepository, SqlxAssetSourceRepository,
    AssetRelationshipRepository, SqlxAssetRelationshipRepository,
};
pub use evidence_repo::EvidenceRepository;
pub use finding_repo::FindingRepository;
pub use scan_repo::ScanRepository;
pub use security_repo::{
    SecurityScanRepository, SqlxSecurityScanRepository,
    SecurityFindingRepository, SqlxSecurityFindingRepository,
};
pub use seed_repo::SeedRepository;
pub use user_repo::UserRepository;

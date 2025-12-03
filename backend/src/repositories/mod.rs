pub mod asset_repo;
pub mod blacklist_repo;
pub mod discovery_repo;
pub mod evidence_repo;
pub mod finding_repo;
pub mod finding_type_config_repo;
pub mod scan_repo;
pub mod security_repo;
pub mod seed_repo;
pub mod settings_repo;
pub mod tag_repo;
pub mod user_repo;

// Re-export commonly used types
pub use asset_repo::{AssetRepository, SqlxAssetRepository};
pub use blacklist_repo::{BlacklistRepository, SqlxBlacklistRepository};
pub use discovery_repo::{
    AssetRelationshipRepository, AssetSourceRepository, DiscoveryQueueRepository,
    DiscoveryRunRepository, SqlxAssetRelationshipRepository, SqlxAssetSourceRepository,
    SqlxDiscoveryQueueRepository, SqlxDiscoveryRunRepository,
};
pub use evidence_repo::EvidenceRepository;
pub use finding_repo::FindingRepository;
pub use scan_repo::ScanRepository;
pub use security_repo::{
    SecurityFindingRepository, SecurityScanRepository, SqlxSecurityFindingRepository,
    SqlxSecurityScanRepository,
};
pub use seed_repo::SeedRepository;
pub use settings_repo::SettingsRepository;
pub use tag_repo::{SqlxTagRepository, TagRepository};
pub use user_repo::UserRepository;
pub use finding_type_config_repo::{FindingTypeConfigRepository, SqlxFindingTypeConfigRepository};

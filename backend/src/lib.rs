use crate::{
    config::{Settings, SettingsService, SharedSettings},
    database::DatabasePool,
    repositories::{
        asset_repo::SqlxAssetRepository,
        blacklist_repo::SqlxBlacklistRepository,
        company_repo::SqlxCompanyRepository,
        discovery_repo::{
            SqlxAssetRelationshipRepository, SqlxAssetSourceRepository,
            SqlxDiscoveryQueueRepository, SqlxDiscoveryRunRepository,
        },
        evidence_repo::SqlxEvidenceRepository,
        finding_repo::SqlxFindingRepository,
        finding_type_config_repo::SqlxFindingTypeConfigRepository,
        scan_repo::SqlxScanRepository,
        security_repo::{SqlxSecurityFindingRepository, SqlxSecurityScanRepository},
        seed_repo::SqlxSeedRepository,
        tag_repo::SqlxTagRepository,
        user_repo::SqlxUserRepository,
        AssetRelationshipRepository, AssetRepository, AssetSourceRepository, BlacklistRepository,
        CompanyRepository, DiscoveryQueueRepository, DiscoveryRunRepository, EvidenceRepository,
        FindingRepository, FindingTypeConfigRepository, ScanRepository,
        SecurityFindingRepository, SecurityScanRepository, SeedRepository, TagRepository,
        UserRepository,
    },
    services::external::{DnsResolver, ExternalServicesManager, HttpAnalyzer},
    services::{
        AuthService, DiscoveryService, DriftService, DriftServiceImpl, ElasticsearchService,
        MetricsService, RiskService, ScanService, SearchService, SecurityScanService, TagService,
        TaskManager,
    },
};
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use std::sync::Arc;

pub mod auth;
pub mod config;
pub mod database;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod repositories;
pub mod services;
pub mod utils;

/// Shared application state containing all dependencies
#[derive(Clone)]
pub struct AppState {
    pub config: SharedSettings,
    pub settings_service: Arc<SettingsService>,
    pub db_pool: DatabasePool,
    pub scan_service: Arc<ScanService>,
    pub discovery_service: Arc<DiscoveryService>,
    pub security_scan_service: Arc<SecurityScanService>,
    pub drift_service: Arc<dyn DriftService + Send + Sync>,
    pub search_service: Option<Arc<dyn SearchService + Send + Sync>>,
    pub metrics_service: Arc<MetricsService>,
    pub auth_service: Arc<AuthService>,
    pub risk_service: Arc<RiskService>,
    pub tag_service: Arc<TagService>,
    // Repositories
    pub scan_repository: Arc<dyn ScanRepository + Send + Sync>,
    pub finding_repository: Arc<dyn FindingRepository + Send + Sync>,
    pub asset_repository: Arc<dyn AssetRepository + Send + Sync>,
    pub evidence_repository: Arc<dyn EvidenceRepository + Send + Sync>,
    pub seed_repository: Arc<dyn SeedRepository + Send + Sync>,
    pub user_repository: Arc<dyn UserRepository + Send + Sync>,
    pub discovery_run_repository: Arc<dyn DiscoveryRunRepository + Send + Sync>,
    pub discovery_queue_repository: Arc<dyn DiscoveryQueueRepository + Send + Sync>,
    pub asset_source_repository: Arc<dyn AssetSourceRepository + Send + Sync>,
    pub asset_relationship_repository: Arc<dyn AssetRelationshipRepository + Send + Sync>,
    pub security_scan_repository: Arc<dyn SecurityScanRepository + Send + Sync>,
    pub security_finding_repository: Arc<dyn SecurityFindingRepository + Send + Sync>,
    pub tag_repository: Arc<dyn TagRepository + Send + Sync>,
    pub blacklist_repository: Arc<dyn BlacklistRepository + Send + Sync>,
    pub finding_type_config_repo: Arc<dyn FindingTypeConfigRepository + Send + Sync>,
    pub company_repository: Arc<dyn CompanyRepository + Send + Sync>,
    // Convenience accessors for handlers
    pub scan_repo: Arc<dyn ScanRepository + Send + Sync>,
    pub finding_repo: Arc<dyn FindingRepository + Send + Sync>,
    pub key: Key,
}

// Implement FromRef to allow extracting Key from AppState
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

impl AppState {
    /// Create new application state with dependency injection
    pub async fn new(config: Settings) -> Result<Self, crate::error::ApiError> {
        let db_pool = crate::database::create_connection_pool(&config.database_url).await?;
        Self::new_with_pool(config, db_pool).await
    }

    /// Create new application state with existing database pool
    pub async fn new_with_pool(
        config: Settings,
        db_pool: DatabasePool,
    ) -> Result<Self, crate::error::ApiError> {
        let settings_service =
            Arc::new(SettingsService::initialize(db_pool.clone(), config).await?);
        let shared_settings = settings_service.shared_settings();
        let settings_snapshot = shared_settings.load();

        // Create cookie key
        let key = Key::from(settings_snapshot.auth_secret.as_bytes());

        // Create repositories
        let scan_repository: Arc<dyn ScanRepository + Send + Sync> =
            Arc::new(SqlxScanRepository::new(db_pool.clone()));
        let finding_repository: Arc<dyn FindingRepository + Send + Sync> =
            Arc::new(SqlxFindingRepository::new(db_pool.clone()));
        let asset_repository: Arc<dyn AssetRepository + Send + Sync> =
            Arc::new(SqlxAssetRepository::new(db_pool.clone()));
        let evidence_repository: Arc<dyn EvidenceRepository + Send + Sync> =
            Arc::new(SqlxEvidenceRepository::new(db_pool.clone()));
        let seed_repository: Arc<dyn SeedRepository + Send + Sync> =
            Arc::new(SqlxSeedRepository::new(db_pool.clone()));
        let user_repository: Arc<dyn UserRepository + Send + Sync> =
            Arc::new(SqlxUserRepository::new(db_pool.clone()));
        let company_repository: Arc<dyn CompanyRepository + Send + Sync> =
            Arc::new(SqlxCompanyRepository::new(db_pool.clone()));

        // Create new discovery repositories
        let discovery_run_repository: Arc<dyn DiscoveryRunRepository + Send + Sync> =
            Arc::new(SqlxDiscoveryRunRepository::new(db_pool.clone()));
        let discovery_queue_repository: Arc<dyn DiscoveryQueueRepository + Send + Sync> =
            Arc::new(SqlxDiscoveryQueueRepository::new(db_pool.clone()));
        let asset_source_repository: Arc<dyn AssetSourceRepository + Send + Sync> =
            Arc::new(SqlxAssetSourceRepository::new(db_pool.clone()));
        let asset_relationship_repository: Arc<dyn AssetRelationshipRepository + Send + Sync> =
            Arc::new(SqlxAssetRelationshipRepository::new(db_pool.clone()));

        // Create security scan repositories
        let security_scan_repository: Arc<dyn SecurityScanRepository + Send + Sync> =
            Arc::new(SqlxSecurityScanRepository::new(db_pool.clone()));
        let security_finding_repository: Arc<dyn SecurityFindingRepository + Send + Sync> =
            Arc::new(SqlxSecurityFindingRepository::new(db_pool.clone()));

        // Create tag repository
        let tag_repository: Arc<dyn TagRepository + Send + Sync> =
            Arc::new(SqlxTagRepository::new(db_pool.clone()));

        // Create blacklist repository
        let blacklist_repository: Arc<dyn BlacklistRepository + Send + Sync> =
            Arc::new(SqlxBlacklistRepository::new(db_pool.clone()));

        // Create finding type config repository
        let finding_type_config_repo: Arc<dyn FindingTypeConfigRepository + Send + Sync> =
            Arc::new(SqlxFindingTypeConfigRepository::new(db_pool.clone()));

        // Create external services and utilities
        let external_services = Arc::new(ExternalServicesManager::new(shared_settings.clone())?);

        // Create DNS resolver with settings configuration
        use crate::services::external::{DnsConfig, HttpConfig};
        let dns_config = DnsConfig {
            query_timeout: std::time::Duration::from_secs(5),
            max_concurrent: settings_snapshot.dns_concurrency as usize,
            rate_limit: settings_snapshot.dns_concurrency,
        };
        let dns_resolver = Arc::new(DnsResolver::with_config(dns_config).await?);

        // Create HTTP analyzer with settings configuration
        let http_config = HttpConfig {
            request_timeout: std::time::Duration::from_secs_f64(
                settings_snapshot.http_timeout_seconds,
            ),
            tls_timeout: std::time::Duration::from_secs_f64(settings_snapshot.tls_timeout_seconds),
            max_redirects: 5,
            max_concurrent: 20,
            rate_limit: 50,
            user_agent: "EASM-Scanner/1.0".to_string(),
        };
        let http_analyzer = Arc::new(HttpAnalyzer::with_config(http_config)?);

        let task_manager = Arc::new(TaskManager::new(shared_settings.clone()));

        // Create services with dependency injection
        let scan_service = Arc::new(ScanService::new(
            scan_repository.clone(),
            finding_repository.clone(),
            asset_repository.clone(),
            external_services.clone(),
            dns_resolver.clone(),
            http_analyzer.clone(),
            http_analyzer.clone(), // TlsAnalyzer is an alias for HttpAnalyzer
            task_manager.clone(),
            shared_settings.clone(),
        ));

        // Create security scan service FIRST (discovery service depends on it)
        let security_scan_service = Arc::new(SecurityScanService::new(
            asset_repository.clone(),
            security_scan_repository.clone(),
            security_finding_repository.clone(),
            external_services.clone(),
            dns_resolver.clone(),
            http_analyzer.clone(), // HttpProber
            http_analyzer.clone(), // TlsAnalyzer
            task_manager.clone(),
            shared_settings.clone(),
        ));

        // Create discovery service with security scan service for auto-scan functionality
        let discovery_service = Arc::new(
            DiscoveryService::new(
                asset_repository.clone(),
                seed_repository.clone(),
                discovery_run_repository.clone(),
                discovery_queue_repository.clone(),
                asset_source_repository.clone(),
                asset_relationship_repository.clone(),
                blacklist_repository.clone(),
                external_services.clone(),
                dns_resolver.clone(),
                http_analyzer.clone(),
                task_manager.clone(),
                shared_settings.clone(),
            )
            .with_security_scan_service(security_scan_service.clone()),
        );

        // Create drift service
        let drift_service: Arc<dyn DriftService + Send + Sync> = Arc::new(DriftServiceImpl::new(
            finding_repository.clone(),
            scan_repository.clone(),
        ));

        // Create search service (optional, only if Elasticsearch is configured)
        let search_service = if settings_snapshot.elasticsearch_url.is_some() {
            match ElasticsearchService::new(settings_snapshot.clone()) {
                Ok(service) => {
                    let service: Arc<dyn SearchService + Send + Sync> = Arc::new(service);
                    // Initialize indices on startup
                    if let Err(e) = service.initialize_indices().await {
                        tracing::warn!("Failed to initialize search indices: {}", e);
                    }
                    Some(service)
                }
                Err(e) => {
                    tracing::warn!("Failed to create search service: {}", e);
                    None
                }
            }
        } else {
            tracing::info!("Elasticsearch not configured, search service disabled");
            None
        };

        // Create metrics service
        let metrics_service = Arc::new(MetricsService::new());

        // Create auth service
        let auth_service = Arc::new(AuthService::new(
            shared_settings.clone(),
            user_repository.clone(),
        ));

        // Create risk service (uses security findings for proper risk calculation)
        let risk_service = Arc::new(RiskService::new(
            asset_repository.clone(),
            security_finding_repository.clone(),
            db_pool.clone(),
        ));

        // Create tag service
        let tag_service = Arc::new(TagService::new(
            tag_repository.clone(),
            asset_repository.clone(),
        ));

        Ok(Self {
            config: shared_settings.clone(),
            settings_service,
            db_pool,
            scan_service,
            discovery_service,
            security_scan_service,
            drift_service,
            search_service,
            metrics_service,
            auth_service,
            risk_service,
            tag_service,
            // Repositories
            scan_repository: scan_repository.clone(),
            finding_repository: finding_repository.clone(),
            asset_repository,
            evidence_repository,
            seed_repository,
            user_repository,
            discovery_run_repository,
            discovery_queue_repository,
            asset_source_repository,
            asset_relationship_repository,
            security_scan_repository,
            security_finding_repository,
            tag_repository,
            blacklist_repository,
            finding_type_config_repo,
            company_repository,
            // Convenience accessors for handlers
            scan_repo: scan_repository,
            finding_repo: finding_repository,
            key,
        })
    }
}

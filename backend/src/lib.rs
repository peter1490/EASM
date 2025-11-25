use std::sync::Arc;
use crate::{
    config::Settings,
    database::DatabasePool,
    repositories::{
        ScanRepository, FindingRepository, AssetRepository, EvidenceRepository, SeedRepository, UserRepository,
        scan_repo::SqlxScanRepository,
        finding_repo::SqlxFindingRepository,
        asset_repo::SqlxAssetRepository,
        evidence_repo::SqlxEvidenceRepository,
        seed_repo::SqlxSeedRepository,
        user_repo::SqlxUserRepository,
    },
    services::{ScanService, DiscoveryService, TaskManager, DriftService, DriftServiceImpl, SearchService, ElasticsearchService, MetricsService, AuthService, RiskService},
    services::external::{ExternalServicesManager, DnsResolver, HttpAnalyzer},
};
use axum_extra::extract::cookie::Key;
use axum::extract::FromRef;

pub mod config;
pub mod database;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod repositories;
pub mod services;
pub mod utils;
pub mod auth;

/// Shared application state containing all dependencies
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Settings>,
    pub settings: Settings, // For compatibility with handlers
    pub db_pool: DatabasePool,
    pub scan_service: Arc<ScanService>,
    pub discovery_service: Arc<DiscoveryService>,
    pub drift_service: Arc<dyn DriftService + Send + Sync>,
    pub search_service: Option<Arc<dyn SearchService + Send + Sync>>,
    pub metrics_service: Arc<MetricsService>,
    pub auth_service: Arc<AuthService>,
    pub risk_service: Arc<RiskService>, // Added
    pub scan_repository: Arc<dyn ScanRepository + Send + Sync>,
    pub finding_repository: Arc<dyn FindingRepository + Send + Sync>,
    pub asset_repository: Arc<dyn AssetRepository + Send + Sync>,
    pub evidence_repository: Arc<dyn EvidenceRepository + Send + Sync>,
    pub seed_repository: Arc<dyn SeedRepository + Send + Sync>,
    pub user_repository: Arc<dyn UserRepository + Send + Sync>,
    // Add convenience accessors for handlers
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
    pub async fn new_with_pool(config: Settings, db_pool: DatabasePool) -> Result<Self, crate::error::ApiError> {
        let config_arc = Arc::new(config.clone());
        
        // Create cookie key
        let key = Key::from(config.auth_secret.as_bytes());
        
        // Create repositories
        let scan_repository: Arc<dyn ScanRepository + Send + Sync> = Arc::new(
            SqlxScanRepository::new(db_pool.clone())
        );
        let finding_repository: Arc<dyn FindingRepository + Send + Sync> = Arc::new(
            SqlxFindingRepository::new(db_pool.clone())
        );
        let asset_repository: Arc<dyn AssetRepository + Send + Sync> = Arc::new(
            SqlxAssetRepository::new(db_pool.clone())
        );
        let evidence_repository: Arc<dyn EvidenceRepository + Send + Sync> = Arc::new(
            SqlxEvidenceRepository::new(db_pool.clone())
        );
        let seed_repository: Arc<dyn SeedRepository + Send + Sync> = Arc::new(
            SqlxSeedRepository::new(db_pool.clone())
        );
        let user_repository: Arc<dyn UserRepository + Send + Sync> = Arc::new(
            SqlxUserRepository::new(db_pool.clone())
        );
        
        // Create external services and utilities
        let external_services = Arc::new(ExternalServicesManager::new(config_arc.clone())?);
        
        // Create DNS resolver with settings configuration
        use crate::services::external::{DnsConfig, HttpConfig};
        let dns_config = DnsConfig {
            query_timeout: std::time::Duration::from_secs(5),
            max_concurrent: config_arc.dns_concurrency as usize,
            rate_limit: config_arc.dns_concurrency,
        };
        let dns_resolver = Arc::new(DnsResolver::with_config(dns_config).await?);
        
        // Create HTTP analyzer with settings configuration
        let http_config = HttpConfig {
            request_timeout: std::time::Duration::from_secs_f64(config_arc.http_timeout_seconds),
            tls_timeout: std::time::Duration::from_secs_f64(config_arc.tls_timeout_seconds),
            max_redirects: 5,
            max_concurrent: 20,
            rate_limit: 50,
            user_agent: "EASM-Scanner/1.0".to_string(),
        };
        let http_analyzer = Arc::new(HttpAnalyzer::with_config(http_config)?);
        
        let task_manager = Arc::new(TaskManager::new(config_arc.clone()));
        
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
            config_arc.clone(),
        ));
        
        let discovery_service = Arc::new(DiscoveryService::new(
            asset_repository.clone(),
            seed_repository.clone(),
            external_services.clone(),
            dns_resolver.clone(),
            http_analyzer.clone(),
            task_manager.clone(),
            config_arc.clone(),
            scan_service.clone(),
        ));
        
        // Create drift service
        let drift_service: Arc<dyn DriftService + Send + Sync> = Arc::new(
            DriftServiceImpl::new(
                finding_repository.clone(),
                scan_repository.clone(),
            )
        );
        
        // Create search service (optional, only if Elasticsearch is configured)
        let search_service = if config_arc.elasticsearch_url.is_some() {
            match ElasticsearchService::new(config_arc.clone()) {
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
            config_arc.clone(),
            user_repository.clone(),
        ).await?);

        // Create risk service
        let risk_service = Arc::new(RiskService::new(
            asset_repository.clone(),
            finding_repository.clone(),
        ));
        
        Ok(Self {
            config: config_arc,
            settings: config,
            db_pool,
            scan_service,
            discovery_service,
            drift_service,
            search_service,
            metrics_service,
            auth_service,
            risk_service,
            scan_repository: scan_repository.clone(),
            finding_repository: finding_repository.clone(),
            asset_repository,
            evidence_repository,
            seed_repository,
            user_repository,
            // Add convenience accessors for handlers
            scan_repo: scan_repository,
            finding_repo: finding_repository,
            key,
        })
    }
}

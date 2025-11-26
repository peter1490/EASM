use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde_json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::{managed::ManagedSettings, secure_store::SecretCrypto, Settings},
    error::ApiError,
    repositories::SettingsRepository,
};

pub type SharedSettings = Arc<ArcSwap<Settings>>;

#[derive(Debug, Clone)]
pub struct ManagedSettingsRecord {
    pub managed: ManagedSettings,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

pub struct SettingsService {
    repo: SettingsRepository,
    crypto: SecretCrypto,
    shared: SharedSettings,
}

impl SettingsService {
    /// Initialize the settings store using existing DB values or seed from the provided base settings.
    /// Returns a SettingsService plus the live shared settings handle.
    pub async fn initialize(pool: PgPool, base_settings: Settings) -> Result<Self, ApiError> {
        let repo = SettingsRepository::new(pool);
        let crypto = SecretCrypto::new(&base_settings.auth_secret)?;

        let managed_record = if let Some(row) = repo.get_latest().await? {
            let plaintext = crypto.decrypt(&row.encrypted_payload, &row.nonce)?;
            let managed: ManagedSettings = serde_json::from_slice(&plaintext)
                .map_err(|e| ApiError::Internal(format!("Failed to parse stored settings: {e}")))?;

            ManagedSettingsRecord {
                managed,
                updated_at: row.updated_at,
                updated_by: row.updated_by,
            }
        } else {
            let managed = ManagedSettings::from(&base_settings).normalized();
            let serialized = serde_json::to_vec(&managed)
                .map_err(|e| ApiError::Internal(format!("Failed to serialize settings: {e}")))?;
            let (ciphertext, nonce) = crypto.encrypt(&serialized)?;

            repo.upsert_payload(ciphertext, nonce, None).await?;

            ManagedSettingsRecord {
                managed,
                updated_at: Utc::now(),
                updated_by: None,
            }
        };

        let mut effective_settings = base_settings.clone();
        managed_record
            .managed
            .apply_to_settings(&mut effective_settings);
        effective_settings
            .validate()
            .map_err(|e| ApiError::Configuration(e.to_string()))?;

        let shared = Arc::new(ArcSwap::from_pointee(effective_settings));

        Ok(Self {
            repo,
            crypto,
            shared,
        })
    }

    pub fn shared_settings(&self) -> SharedSettings {
        self.shared.clone()
    }

    pub fn snapshot(&self) -> Arc<Settings> {
        self.shared.load_full()
    }

    pub async fn get_managed(&self) -> Result<ManagedSettingsRecord, ApiError> {
        if let Some(row) = self.repo.get_latest().await? {
            let plaintext = self.crypto.decrypt(&row.encrypted_payload, &row.nonce)?;
            let managed: ManagedSettings = serde_json::from_slice(&plaintext)
                .map_err(|e| ApiError::Internal(format!("Failed to parse stored settings: {e}")))?;

            Ok(ManagedSettingsRecord {
                managed,
                updated_at: row.updated_at,
                updated_by: row.updated_by,
            })
        } else {
            // Should not happen after initialize; reseed from defaults to stay operational
            let managed = ManagedSettings::default();
            let serialized = serde_json::to_vec(&managed)
                .map_err(|e| ApiError::Internal(format!("Failed to serialize settings: {e}")))?;
            let (ciphertext, nonce) = self.crypto.encrypt(&serialized)?;
            self.repo.upsert_payload(ciphertext, nonce, None).await?;

            Ok(ManagedSettingsRecord {
                managed,
                updated_at: Utc::now(),
                updated_by: None,
            })
        }
    }

    pub async fn update_managed(
        &self,
        incoming: ManagedSettings,
        updated_by: Option<Uuid>,
    ) -> Result<Arc<Settings>, ApiError> {
        let managed = incoming.normalized();

        let mut next_settings = self.shared.load().as_ref().clone();
        managed.apply_to_settings(&mut next_settings);
        next_settings
            .validate()
            .map_err(|e| ApiError::Configuration(e.to_string()))?;

        let serialized = serde_json::to_vec(&managed)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize settings: {e}")))?;
        let (ciphertext, nonce) = self.crypto.encrypt(&serialized)?;
        self.repo
            .upsert_payload(ciphertext, nonce, updated_by)
            .await?;

        let arc = Arc::new(next_settings);
        self.shared.store(arc.clone());
        Ok(arc)
    }
}

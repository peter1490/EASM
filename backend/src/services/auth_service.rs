use std::sync::Arc;
use crate::config::Settings;
use crate::auth::identity_provider::OidcProvider;
use crate::repositories::user_repo::UserRepository;
use crate::error::ApiError;
use anyhow::{Result, Context};
use crate::auth::rbac::Role;
use uuid::Uuid;
use crate::auth::session::UserSession;
use crate::utils::crypto::{hash_password, verify_password};
use chrono::{Utc, Duration};

pub struct AuthService {
    settings: Arc<Settings>,
    user_repo: Arc<dyn UserRepository + Send + Sync>,
    google_provider: Option<OidcProvider>,
    keycloak_provider: Option<OidcProvider>,
}

impl AuthService {
    pub async fn new(
        settings: Arc<Settings>,
        user_repo: Arc<dyn UserRepository + Send + Sync>,
    ) -> Result<Self> {
        let google_provider = if settings.google_client_id.is_some() {
             Some(OidcProvider::google(&settings).await?)
        } else {
             None
        };
        
        let keycloak_provider = if settings.keycloak_client_id.is_some() {
             Some(OidcProvider::keycloak(&settings).await?)
        } else {
             None
        };

        Ok(Self {
            settings,
            user_repo,
            google_provider,
            keycloak_provider,
        })
    }

    pub fn get_google_auth_url(&self) -> Result<(reqwest::Url, String, String), ApiError> {
        if let Some(provider) = &self.google_provider {
            let (url, csrf_token, nonce) = provider.get_authorization_url();
            Ok((url, csrf_token.secret().clone(), nonce.secret().clone()))
        } else {
            Err(ApiError::Configuration("Google Auth not configured".to_string()))
        }
    }
    
    pub fn get_keycloak_auth_url(&self) -> Result<(reqwest::Url, String, String), ApiError> {
        if let Some(provider) = &self.keycloak_provider {
            let (url, csrf_token, nonce) = provider.get_authorization_url();
            Ok((url, csrf_token.secret().clone(), nonce.secret().clone()))
        } else {
             Err(ApiError::Configuration("Keycloak Auth not configured".to_string()))
        }
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<UserSession, ApiError> {
        let provider = self.google_provider.as_ref().ok_or_else(|| ApiError::Configuration("Google Auth not configured".to_string()))?;
        let claims = provider.exchange_code(code).await.map_err(|e| ApiError::Authentication(format!("Failed to exchange code: {}", e)))?;
        
        let email = claims.email().ok_or_else(|| ApiError::Authentication("No email in claims".to_string()))?.to_string();
        let sub = claims.subject().to_string();
        
        self.login_or_register_sso("google", &sub, &email).await
    }
    
    pub async fn handle_keycloak_callback(&self, code: String) -> Result<UserSession, ApiError> {
        let provider = self.keycloak_provider.as_ref().ok_or(ApiError::Configuration("Keycloak not configured".to_string()))?;
        let claims = provider.exchange_code(code).await.map_err(|e| ApiError::ExternalService(e.to_string()))?;
        
        let email = claims.email().ok_or(ApiError::ExternalService("No email in ID token".to_string()))?.to_string();
        let provider_id = claims.subject().to_string();
        
        self.login_or_register_sso("keycloak", &provider_id, &email).await
    }

    pub async fn login_local(&self, email: &str, password: &str) -> Result<UserSession, ApiError> {
        let user = self.user_repo.find_by_email(email).await?;
        
        let user = match user {
            Some(u) => u,
            None => return Err(ApiError::Authentication("Invalid email or password".to_string())),
        };
        
        // Verify password
        let valid = if let Some(hash) = &user.password_hash {
            verify_password(password, hash)?
        } else {
            // User exists but has no password (SSO only user trying to login locally)
            return Err(ApiError::Authentication("Account uses SSO login".to_string()));
        };
        
        if !valid {
            return Err(ApiError::Authentication("Invalid email or password".to_string()));
        }
        
        // Update last login
        self.user_repo.update_last_login(user.id).await?;
        
        // Get roles
        let roles = self.user_repo.get_user_roles(user.id).await?;
        
        // Create session
        let session = UserSession {
            user_id: user.id,
            email: user.email,
            roles,
            expires_at: Utc::now() + Duration::seconds(self.settings.auth_session_expiry_seconds as i64),
            session_id: Uuid::new_v4().to_string(),
        };
        
        Ok(session)
    }

    async fn login_or_register_sso(&self, provider: &str, provider_id: &str, email: &str) -> Result<UserSession, ApiError> {
        // Check if identity exists
        if let Some(identity) = self.user_repo.find_identity(provider, provider_id).await? {
            // Identity exists, update last login and get user
            let user = self.user_repo.find_by_id(identity.user_id).await?.ok_or_else(|| ApiError::Internal("User not found for identity".to_string()))?;
            self.user_repo.update_last_login(user.id).await?;
            
            let roles = self.user_repo.get_user_roles(user.id).await?;
            
            Ok(self.create_session(user.id, user.email, roles))
        } else {
            // New identity
            let user_id = if let Some(existing_user) = self.user_repo.find_by_email(email).await? {
                // User with this email already exists, link new identity to it
                self.user_repo.create_identity(existing_user.id, provider, provider_id, email).await?;
                existing_user.id
            } else {
                // Create new user and link identity
                let new_user = self.user_repo.create_user(email, None).await?;
                // Default role for new users: Viewer
                self.user_repo.add_user_role(new_user.id, Role::Viewer, None).await?;
                self.user_repo.create_identity(new_user.id, provider, provider_id, email).await?;
                new_user.id
            };
            
            // Get the user after potential creation/linking
            let user = self.user_repo.find_by_id(user_id).await?.ok_or_else(|| ApiError::Internal("User not found after creation/linking".to_string()))?;
            self.user_repo.update_last_login(user.id).await?;
            
            let roles = self.user_repo.get_user_roles(user.id).await?;
            
            Ok(self.create_session(user.id, user.email, roles))
        }
    }

    fn create_session(&self, user_id: Uuid, email: String, roles: Vec<Role>) -> UserSession {
        UserSession {
            user_id,
            email,
            roles,
            expires_at: Utc::now() + Duration::seconds(self.settings.auth_session_expiry_seconds as i64),
            session_id: Uuid::new_v4().to_string(),
        }
    }
}

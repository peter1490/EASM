use crate::auth::rbac::Role;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: Uuid,
    pub email: String,
    pub roles: Vec<Role>,
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
}

impl UserSession {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    pub fn has_permission(&self, permission: &crate::auth::rbac::Permission) -> bool {
        self.roles.iter().any(|r| r.has_permission(permission))
    }
}

pub struct SessionManager {
    secret: String,
}

impl SessionManager {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    // JWT logic would go here if using JWTs, or cookie signing logic via axum-extra
}

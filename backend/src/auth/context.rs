use uuid::Uuid;
use crate::auth::rbac::Role;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: Option<Uuid>, // None for API Key (or service user)
    pub email: Option<String>,
    pub roles: Vec<Role>,
    pub is_api_key: bool,
}

impl UserContext {
    pub fn new_user(user_id: Uuid, email: String, roles: Vec<Role>) -> Self {
        Self {
            user_id: Some(user_id),
            email: Some(email),
            roles,
            is_api_key: false,
        }
    }

    pub fn new_api_key() -> Self {
        // API Keys treated as Admin for now, or we can have granular scopes later
        Self {
            user_id: None,
            email: None,
            roles: vec![Role::Admin], // API keys have full access by default in this design
            is_api_key: true,
        }
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    pub fn has_permission(&self, permission: &crate::auth::rbac::Permission) -> bool {
        self.roles.iter().any(|r| r.has_permission(permission))
    }
}

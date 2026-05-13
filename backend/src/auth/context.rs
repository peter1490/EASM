use crate::auth::rbac::Role;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: Option<Uuid>, // None for API Key (or service user)
    pub email: Option<String>,
    pub roles: Vec<Role>,
    pub company_id: Option<Uuid>, // Current active company
    pub is_api_key: bool,
    pub api_key_id: Option<String>,
}

impl UserContext {
    pub fn new_user(
        user_id: Uuid,
        email: String,
        roles: Vec<Role>,
        company_id: Option<Uuid>,
    ) -> Self {
        Self {
            user_id: Some(user_id),
            email: Some(email),
            roles,
            company_id,
            is_api_key: false,
            api_key_id: None,
        }
    }

    pub fn new_api_key(role: Role, company_id: Option<Uuid>, api_key_id: Option<String>) -> Self {
        // API Keys treated as Admin for now, or we can have granular scopes later
        Self {
            user_id: None,
            email: None,
            roles: vec![role],
            company_id,
            is_api_key: true,
            api_key_id,
        }
    }

    /// Role check with hierarchy: GlobalAdmin implicitly satisfies every role check,
    /// so existing `has_role(Role::Admin)` / `has_role(Role::Operator)` gates continue to
    /// work for global super-admins.
    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&Role::GlobalAdmin) || self.roles.contains(&role)
    }

    pub fn is_global_admin(&self) -> bool {
        self.roles.contains(&Role::GlobalAdmin)
    }

    pub fn has_permission(&self, permission: &crate::auth::rbac::Permission) -> bool {
        self.roles.iter().any(|r| r.has_permission(permission))
    }
}

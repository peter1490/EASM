use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Analyst,
    Viewer,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Analyst => "analyst",
            Role::Viewer => "viewer",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "analyst" => Some(Role::Analyst),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    // Scan Management
    CreateScan,
    StopScan,
    DeleteScan,
    ViewScan,

    // Discovery Control
    StartDiscovery,
    StopDiscovery,
    ConfigureDiscovery,

    // Evidence
    DownloadEvidence,
    ViewEvidence,

    // Config
    EditConfig,
    ViewConfig,

    // User Management
    ManageUsers,
    ViewUsers,

    // Risk Management
    EditRiskScore,
}

impl Role {
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            Role::Admin => vec![
                Permission::CreateScan,
                Permission::StopScan,
                Permission::DeleteScan,
                Permission::ViewScan,
                Permission::StartDiscovery,
                Permission::StopDiscovery,
                Permission::ConfigureDiscovery,
                Permission::DownloadEvidence,
                Permission::ViewEvidence,
                Permission::EditConfig,
                Permission::ViewConfig,
                Permission::ManageUsers,
                Permission::ViewUsers,
                Permission::EditRiskScore,
            ],
            Role::Operator => vec![
                Permission::CreateScan,
                Permission::StopScan,
                Permission::ViewScan,
                Permission::StartDiscovery,
                Permission::StopDiscovery,
                Permission::DownloadEvidence,
                Permission::ViewEvidence,
                Permission::ViewConfig,
                Permission::ViewUsers,
                Permission::EditRiskScore,
            ],
            Role::Analyst => vec![
                Permission::ViewScan,
                Permission::DownloadEvidence,
                Permission::ViewEvidence,
                Permission::ViewConfig,
                Permission::EditRiskScore,
            ],
            Role::Viewer => vec![Permission::ViewScan, Permission::ViewEvidence],
        }
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions().contains(permission)
    }
}

#[macro_export]
macro_rules! require_role {
    ($user:expr, $role:expr) => {
        if !$user.has_role($role) {
            return Err(crate::error::ApiError::Forbidden(format!(
                "Role {} required",
                $role
            )));
        }
    };
}

#[macro_export]
macro_rules! require_permission {
    ($user:expr, $perm:expr) => {
        if !$user.has_permission($perm) {
            return Err(crate::error::ApiError::Forbidden(format!(
                "Permission {:?} required",
                $perm
            )));
        }
    };
}

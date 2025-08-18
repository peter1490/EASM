use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "scan_status", rename_all = "lowercase")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub target: String,
    pub note: Option<String>,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanCreate {
    pub target: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanUpdate {
    pub status: Option<ScanStatus>,
    pub note: Option<String>,
}

/// Response DTO for scan list endpoint with findings count
#[derive(Debug, Clone, Serialize)]
pub struct ScanListResponse {
    pub id: Uuid,
    pub target: String,
    pub note: Option<String>,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub findings_count: i64,
}

/// Response DTO for scan get endpoint with findings array
#[derive(Debug, Clone, Serialize)]
pub struct ScanDetailResponse {
    pub id: Uuid,
    pub target: String,
    pub note: Option<String>,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub findings_count: i64,
    pub findings: Vec<crate::models::Finding>,
}
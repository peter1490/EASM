use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub file_size: i64,
    pub file_path: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceCreate {
    pub scan_id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub file_size: i64,
    pub file_path: String,
}
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CompanyEvolutionPoint {
    pub timestamp: DateTime<Utc>,
    pub risk_score: Option<f64>,
    pub active_findings: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompanyEvolutionResponse {
    pub series: Vec<CompanyEvolutionPoint>,
}

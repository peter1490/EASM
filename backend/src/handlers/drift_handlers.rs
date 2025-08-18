use axum::{
    extract::{Path, State},

    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::ApiError,

    AppState,
};

#[derive(Debug, Serialize)]
pub struct DriftDetectionResponse {
    pub scan_id: Uuid,
    pub target: String,
    pub drift_count: usize,
    pub findings_created: usize,
}

#[derive(Debug, Deserialize)]
pub struct DriftDetectionRequest {
    pub target: String,
}

/// Detect port drift for a completed scan
pub async fn detect_port_drift(
    State(app_state): State<AppState>,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<DriftDetectionResponse>, ApiError> {
    // Get the scan to verify it exists and get the target
    let scan = app_state
        .scan_repo
        .get_by_id(&scan_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Scan with id {} not found", scan_id)))?;

    // Ensure the scan is completed
    if scan.status != crate::models::ScanStatus::Completed {
        return Err(ApiError::validation(
            "Port drift detection can only be performed on completed scans"
        ));
    }

    // Detect port drift
    let drifts = app_state
        .drift_service
        .detect_port_drift(&scan_id, &scan.target)
        .await?;

    // Generate drift findings
    let findings = app_state
        .drift_service
        .generate_drift_findings(&drifts)
        .await?;

    // Update asset metadata for each drift
    for drift in &drifts {
        // Extract current port state from findings
        let current_findings = app_state
            .finding_repo
            .list_by_scan(&scan_id)
            .await?;

        let mut current_ports = std::collections::HashSet::new();
        for finding in current_findings {
            if finding.finding_type == "port_scan" {
                if let Some(asset) = finding.data.get("asset").and_then(|v| v.as_str()) {
                    if asset == drift.asset_identifier {
                        if let Some(port) = finding.data.get("port").and_then(|v| v.as_u64()) {
                            if port <= u16::MAX as u64 {
                                current_ports.insert(port as u16);
                            }
                        }
                    }
                }
            }
        }

        app_state
            .drift_service
            .update_asset_metadata(&drift.asset_identifier, &current_ports)
            .await?;
    }

    Ok(Json(DriftDetectionResponse {
        scan_id,
        target: scan.target,
        drift_count: drifts.len(),
        findings_created: findings.len(),
    }))
}

/// Get drift findings for a specific scan
pub async fn get_drift_findings(
    State(app_state): State<AppState>,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<Vec<crate::models::Finding>>, ApiError> {
    let findings = app_state
        .finding_repo
        .list_by_type("port_drift")
        .await?;

    // Filter findings for the specific scan
    let scan_findings: Vec<_> = findings
        .into_iter()
        .filter(|f| f.scan_id == scan_id)
        .collect();

    Ok(Json(scan_findings))
}

#[cfg(test)]
mod tests {}
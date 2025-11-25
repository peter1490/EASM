use async_trait::async_trait;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{Finding, FindingCreate},
    repositories::{FindingRepository, ScanRepository},
};

#[derive(Debug, Clone)]
pub struct PortDrift {
    pub asset_identifier: String,
    pub added_ports: Vec<u16>,
    pub removed_ports: Vec<u16>,
    pub previous_scan_id: Uuid,
    pub current_scan_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct AssetPortState {
    pub asset_identifier: String,
    pub ports: HashSet<u16>,
    pub scan_id: Uuid,
}

#[async_trait]
pub trait DriftService {
    async fn detect_port_drift(&self, current_scan_id: &Uuid, target: &str) -> Result<Vec<PortDrift>, ApiError>;
    async fn generate_drift_findings(&self, drifts: &[PortDrift]) -> Result<Vec<Finding>, ApiError>;
    async fn update_asset_metadata(&self, asset_identifier: &str, port_state: &HashSet<u16>) -> Result<(), ApiError>;
}

pub struct DriftServiceImpl {
    finding_repo: Arc<dyn FindingRepository + Send + Sync>,
    scan_repo: Arc<dyn ScanRepository + Send + Sync>,
}

impl DriftServiceImpl {
    pub fn new(
        finding_repo: Arc<dyn FindingRepository + Send + Sync>,
        scan_repo: Arc<dyn ScanRepository + Send + Sync>,
    ) -> Self {
        Self {
            finding_repo,
            scan_repo,
        }
    }

    /// Extract port information from scan findings
    async fn extract_port_states(&self, scan_id: &Uuid) -> Result<HashMap<String, AssetPortState>, ApiError> {
        let findings = self.finding_repo.list_by_scan(scan_id).await?;
        let mut asset_ports: HashMap<String, HashSet<u16>> = HashMap::new();

        for finding in findings {
            if finding.finding_type == "port_scan" {
                if let Some(asset) = finding.data.get("asset").and_then(|v| v.as_str()) {
                    if let Some(port) = finding.data.get("port").and_then(|v| v.as_u64()) {
                        if port <= u16::MAX as u64 {
                            asset_ports
                                .entry(asset.to_string())
                                .or_insert_with(HashSet::new)
                                .insert(port as u16);
                        }
                    }
                }
            }
        }

        Ok(asset_ports
            .into_iter()
            .map(|(asset, ports)| {
                (
                    asset.clone(),
                    AssetPortState {
                        asset_identifier: asset,
                        ports,
                        scan_id: *scan_id,
                    },
                )
            })
            .collect())
    }

    /// Find the most recent completed scan for the same target
    async fn find_previous_scan(&self, current_scan_id: &Uuid, target: &str) -> Result<Option<Uuid>, ApiError> {
        let scans = self.scan_repo.list().await?;
        
        // Find completed scans for the same target, excluding the current scan
        let mut previous_scans: Vec<_> = scans
            .into_iter()
            .filter(|scan| {
                scan.id != *current_scan_id
                    && scan.target == target
                    && scan.status == crate::models::ScanStatus::Completed
            })
            .collect();

        // Sort by creation time, most recent first
        previous_scans.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(previous_scans.first().map(|scan| scan.id))
    }

    /// Compare port states between two scans to detect drift
    fn compare_port_states(
        &self,
        previous_states: &HashMap<String, AssetPortState>,
        current_states: &HashMap<String, AssetPortState>,
        previous_scan_id: Uuid,
        current_scan_id: Uuid,
    ) -> Vec<PortDrift> {
        let mut drifts = Vec::new();

        // Check for assets that exist in both scans
        for (asset_identifier, current_state) in current_states {
            if let Some(previous_state) = previous_states.get(asset_identifier) {
                let added_ports: Vec<u16> = current_state
                    .ports
                    .difference(&previous_state.ports)
                    .copied()
                    .collect();

                let removed_ports: Vec<u16> = previous_state
                    .ports
                    .difference(&current_state.ports)
                    .copied()
                    .collect();

                if !added_ports.is_empty() || !removed_ports.is_empty() {
                    drifts.push(PortDrift {
                        asset_identifier: asset_identifier.clone(),
                        added_ports,
                        removed_ports,
                        previous_scan_id,
                        current_scan_id,
                    });
                }
            }
        }

        drifts
    }
}

#[async_trait]
impl DriftService for DriftServiceImpl {
    async fn detect_port_drift(&self, current_scan_id: &Uuid, target: &str) -> Result<Vec<PortDrift>, ApiError> {
        // Find the previous scan for comparison
        let previous_scan_id = match self.find_previous_scan(current_scan_id, target).await? {
            Some(id) => id,
            None => return Ok(Vec::new()), // No previous scan to compare against
        };

        // Extract port states from both scans
        let current_states = self.extract_port_states(current_scan_id).await?;
        let previous_states = self.extract_port_states(&previous_scan_id).await?;

        // Compare states to detect drift
        let drifts = self.compare_port_states(
            &previous_states,
            &current_states,
            previous_scan_id,
            *current_scan_id,
        );

        Ok(drifts)
    }

    async fn generate_drift_findings(&self, drifts: &[PortDrift]) -> Result<Vec<Finding>, ApiError> {
        let mut findings = Vec::new();

        for drift in drifts {
            let drift_data = json!({
                "asset": drift.asset_identifier,
                "previous_scan_id": drift.previous_scan_id,
                "current_scan_id": drift.current_scan_id,
                "added_ports": drift.added_ports,
                "removed_ports": drift.removed_ports,
                "drift_type": "port_change"
            });

            let finding_create = FindingCreate {
                scan_id: drift.current_scan_id,
                finding_type: "port_drift".to_string(),
                data: drift_data,
            };

            let finding = self.finding_repo.create(&finding_create).await?;
            findings.push(finding);
        }

        Ok(findings)
    }

    async fn update_asset_metadata(&self, _asset_identifier: &str, _port_state: &HashSet<u16>) -> Result<(), ApiError> {
        // This would update asset metadata in the asset repository
        // For now, we'll leave this as a placeholder since we need to integrate with AssetRepository
        // In a full implementation, this would:
        // 1. Find the asset by identifier
        // 2. Update its metadata with current port state
        // 3. Update the last_seen timestamp
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use serde_json::json;
    use std::collections::HashMap;
    use uuid::Uuid;

    use crate::models::{Finding, FindingCreate, Scan, ScanCreate, ScanStatus};

    // Mock implementations for testing
    struct MockFindingRepository {
        findings: HashMap<Uuid, Vec<Finding>>,
    }

    impl MockFindingRepository {
        fn new() -> Self {
            Self {
                findings: HashMap::new(),
            }
        }

        fn add_port_finding(&mut self, scan_id: Uuid, asset: &str, port: u16) {
            let finding = Finding {
                id: Uuid::new_v4(),
                scan_id,
                finding_type: "port_scan".to_string(),
                data: json!({
                    "asset": asset,
                    "port": port,
                    "service": "unknown"
                }),
                created_at: Utc::now(),
            };

            self.findings.entry(scan_id).or_insert_with(Vec::new).push(finding);
        }
    }

    #[async_trait]
    impl FindingRepository for MockFindingRepository {
        async fn create(&self, _finding: &FindingCreate) -> Result<Finding, ApiError> {
            Ok(Finding {
                id: Uuid::new_v4(),
                scan_id: Uuid::new_v4(),
                finding_type: "test".to_string(),
                data: json!({}),
                created_at: Utc::now(),
            })
        }

        async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<Finding>, ApiError> {
            Ok(self.findings.get(scan_id).cloned().unwrap_or_default())
        }

        async fn list_by_asset(&self, _asset_identifier: &str) -> Result<Vec<Finding>, ApiError> {
            Ok(Vec::new())
        }

        async fn list_by_type(&self, _finding_type: &str) -> Result<Vec<Finding>, ApiError> {
            Ok(Vec::new())
        }

        async fn search(&self, _query: &str) -> Result<Vec<Finding>, ApiError> {
            Ok(Vec::new())
        }

        async fn count_by_scan(&self, scan_id: &Uuid) -> Result<i64, ApiError> {
            Ok(self.findings.get(scan_id).map(|v| v.len() as i64).unwrap_or(0))
        }

        async fn filter(&self, _filter: &crate::models::FindingFilter) -> Result<crate::models::FindingListResponse, ApiError> {
            // Mock implementation returns empty results
            Ok(crate::models::FindingListResponse {
                findings: Vec::new(),
                total_count: 0,
                limit: 100,
                offset: 0,
            })
        }
    }

    struct MockScanRepository {
        scans: Vec<Scan>,
    }

    impl MockScanRepository {
        fn new() -> Self {
            Self { scans: Vec::new() }
        }

        fn add_scan(&mut self, id: Uuid, target: &str, status: ScanStatus, created_at: chrono::DateTime<Utc>) {
            self.scans.push(Scan {
                id,
                target: target.to_string(),
                note: None,
                status,
                created_at,
                updated_at: created_at,
            });
        }
    }

    #[async_trait]
    impl ScanRepository for MockScanRepository {
        async fn create(&self, _scan: &ScanCreate) -> Result<Scan, ApiError> {
            Ok(Scan {
                id: Uuid::new_v4(),
                target: "test".to_string(),
                note: None,
                status: ScanStatus::Queued,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
        }

        async fn get_by_id(&self, id: &Uuid) -> Result<Option<Scan>, ApiError> {
            Ok(self.scans.iter().find(|s| s.id == *id).cloned())
        }

        async fn list(&self) -> Result<Vec<Scan>, ApiError> {
            Ok(self.scans.clone())
        }

        async fn list_by_status(&self, _status: Option<ScanStatus>) -> Result<Vec<Scan>, ApiError> {
            Ok(self.scans.clone())
        }

        async fn update_status(&self, _id: &Uuid, _status: ScanStatus) -> Result<(), ApiError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_detect_port_drift_no_previous_scan() {
        let finding_repo = MockFindingRepository::new();
        let scan_repo = MockScanRepository::new();
        let service = DriftServiceImpl::new(Arc::new(finding_repo), Arc::new(scan_repo));

        let current_scan_id = Uuid::new_v4();
        let drifts = service.detect_port_drift(&current_scan_id, "example.com").await.unwrap();

        assert!(drifts.is_empty());
    }

    #[tokio::test]
    async fn test_detect_port_drift_with_changes() {
        let mut finding_repo = MockFindingRepository::new();
        let mut scan_repo = MockScanRepository::new();

        let previous_scan_id = Uuid::new_v4();
        let current_scan_id = Uuid::new_v4();
        let target = "example.com";

        // Set up scans
        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(1);
        
        scan_repo.add_scan(previous_scan_id, target, ScanStatus::Completed, earlier);
        scan_repo.add_scan(current_scan_id, target, ScanStatus::Completed, now);

        // Set up findings - previous scan had ports 80, 443
        finding_repo.add_port_finding(previous_scan_id, "192.168.1.1", 80);
        finding_repo.add_port_finding(previous_scan_id, "192.168.1.1", 443);

        // Current scan has ports 80, 8080 (443 removed, 8080 added)
        finding_repo.add_port_finding(current_scan_id, "192.168.1.1", 80);
        finding_repo.add_port_finding(current_scan_id, "192.168.1.1", 8080);

        let service = DriftServiceImpl::new(Arc::new(finding_repo), Arc::new(scan_repo));
        let drifts = service.detect_port_drift(&current_scan_id, target).await.unwrap();

        assert_eq!(drifts.len(), 1);
        let drift = &drifts[0];
        assert_eq!(drift.asset_identifier, "192.168.1.1");
        assert_eq!(drift.added_ports, vec![8080]);
        assert_eq!(drift.removed_ports, vec![443]);
        assert_eq!(drift.previous_scan_id, previous_scan_id);
        assert_eq!(drift.current_scan_id, current_scan_id);
    }

    #[tokio::test]
    async fn test_detect_port_drift_no_changes() {
        let mut finding_repo = MockFindingRepository::new();
        let mut scan_repo = MockScanRepository::new();

        let previous_scan_id = Uuid::new_v4();
        let current_scan_id = Uuid::new_v4();
        let target = "example.com";

        // Set up scans
        let now = Utc::now();
        let earlier = now - chrono::Duration::hours(1);
        
        scan_repo.add_scan(previous_scan_id, target, ScanStatus::Completed, earlier);
        scan_repo.add_scan(current_scan_id, target, ScanStatus::Completed, now);

        // Both scans have the same ports
        finding_repo.add_port_finding(previous_scan_id, "192.168.1.1", 80);
        finding_repo.add_port_finding(previous_scan_id, "192.168.1.1", 443);
        finding_repo.add_port_finding(current_scan_id, "192.168.1.1", 80);
        finding_repo.add_port_finding(current_scan_id, "192.168.1.1", 443);

        let service = DriftServiceImpl::new(Arc::new(finding_repo), Arc::new(scan_repo));
        let drifts = service.detect_port_drift(&current_scan_id, target).await.unwrap();

        assert!(drifts.is_empty());
    }

    #[tokio::test]
    async fn test_extract_port_states() {
        let mut finding_repo = MockFindingRepository::new();
        let scan_repo = MockScanRepository::new();

        let scan_id = Uuid::new_v4();
        
        // Add port findings for different assets
        finding_repo.add_port_finding(scan_id, "192.168.1.1", 80);
        finding_repo.add_port_finding(scan_id, "192.168.1.1", 443);
        finding_repo.add_port_finding(scan_id, "192.168.1.2", 22);

        let service = DriftServiceImpl::new(Arc::new(finding_repo), Arc::new(scan_repo));
        let states = service.extract_port_states(&scan_id).await.unwrap();

        assert_eq!(states.len(), 2);
        
        let asset1_state = states.get("192.168.1.1").unwrap();
        assert_eq!(asset1_state.ports.len(), 2);
        assert!(asset1_state.ports.contains(&80));
        assert!(asset1_state.ports.contains(&443));

        let asset2_state = states.get("192.168.1.2").unwrap();
        assert_eq!(asset2_state.ports.len(), 1);
        assert!(asset2_state.ports.contains(&22));
    }
}
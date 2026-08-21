//! Deep protocol scanners.
//!
//! Each module here answers the question a dedicated tool would answer — what
//! `sslscan`/`testssl.sh` say about TLS, what `dig`/`dnsrecon`/Hardenize say about
//! DNS, what Mozilla Observatory and `nuclei` say about HTTP — and turns the
//! answer into findings. They own the protocol work; `security_scan_service` owns
//! orchestration, policy and persistence.
//!
//! The split matters for testing: everything in here that decides *whether
//! something is wrong* is a pure function over parsed input, so the rules are
//! covered by unit tests rather than by pointing the scanner at the internet and
//! hoping.

pub mod dns_wire;
pub mod cert_analysis;
pub mod cipher_suites;
pub mod dns_scan;
pub mod email_auth;
pub mod http_headers;
pub mod http_scan;
pub mod takeover;
pub mod tls_probe;
pub mod tls_scan;

use serde_json::Value;

use crate::models::FindingSeverity;

/// A finding a scanner wants recorded, before it becomes a database row.
///
/// Scanners return these instead of writing findings themselves. That keeps
/// company scoping, deduplication and the risk recalculation in one place, and
/// it makes a scanner's whole output assertable in a unit test.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub finding_type: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub data: Value,
}

impl ScanFinding {
    pub fn new(
        finding_type: impl Into<String>,
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        remediation: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            finding_type: finding_type.into(),
            severity,
            title: title.into(),
            description: description.into(),
            remediation: remediation.into(),
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{dns_scan, http_scan, tls_scan};
    use std::collections::HashSet;

    /// Finding types seeded into `finding_type_config` by the migrations.
    fn configured_finding_types() -> HashSet<String> {
        let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut entries: Vec<_> = std::fs::read_dir(&migrations)
            .expect("migrations directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
            .collect();
        entries.sort();

        let mut configured = HashSet::new();
        for path in entries {
            let sql = std::fs::read_to_string(&path).expect("read migration");
            // Rows are seeded as `('finding_type', 'Display Name', 'category', …)`,
            // so the first quoted value on an INSERT value line is the type.
            for line in sql.lines() {
                let trimmed = line.trim_start();
                if !trimmed.starts_with("('") {
                    continue;
                }
                if let Some(name) = trimmed
                    .strip_prefix("('")
                    .and_then(|rest| rest.split('\'').next())
                {
                    configured.insert(name.to_string());
                }
            }
            // A DELETE retires a type; honour it so a removed row is not counted.
            for line in sql.lines() {
                if let Some(rest) = line.trim().strip_prefix("DELETE FROM finding_type_config WHERE finding_type = '") {
                    if let Some(name) = rest.split('\'').next() {
                        configured.remove(name);
                    }
                }
            }
        }
        configured
    }

    /// Every type a scanner emits must have a `finding_type_config` row.
    ///
    /// Without one, the type still scores — at a neutral multiplier — but no
    /// operator can see it in the settings UI or weight it, which is how seven
    /// types went missing before migration 029 went looking for them.
    #[test]
    fn every_emitted_finding_type_is_configurable() {
        let configured = configured_finding_types();
        assert!(
            configured.len() > 40,
            "migration parsing found only {} types, which cannot be right",
            configured.len()
        );

        let mut missing: Vec<&str> = Vec::new();
        for finding_type in dns_scan::EMITTED_FINDING_TYPES
            .iter()
            .chain(tls_scan::EMITTED_FINDING_TYPES)
            .chain(http_scan::EMITTED_FINDING_TYPES)
        {
            if !configured.contains(*finding_type) {
                missing.push(finding_type);
            }
        }
        missing.sort_unstable();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "these finding types are emitted but have no finding_type_config row, so no admin \
             can see or weight them: {:?}",
            missing
        );
    }

    /// No scanner may declare a type it cannot actually produce: an entry here
    /// that nothing emits shows up in the settings UI as a control over nothing.
    #[test]
    fn declared_type_lists_have_no_duplicates() {
        for (name, list) in [
            ("dns_scan", dns_scan::EMITTED_FINDING_TYPES),
            ("tls_scan", tls_scan::EMITTED_FINDING_TYPES),
            ("http_scan", http_scan::EMITTED_FINDING_TYPES),
        ] {
            let mut seen = HashSet::new();
            for finding_type in list {
                assert!(
                    seen.insert(*finding_type),
                    "{} declares {} twice",
                    name,
                    finding_type
                );
            }
        }
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
/// Advanced confidence scoring system for asset discovery
///
/// This module provides a sophisticated, multi-factor confidence scoring system that replaces
/// the previous hard-coded confidence values with dynamic calculations based on multiple factors.
///
/// # Overview
///
/// The confidence scoring system evaluates assets based on:
///
/// 1. **Discovery Method Reliability**: Different discovery methods have different base confidence scores.
///    For example, direct seeds and CIDR expansions have high confidence (0.85-1.0), while keyword
///    searches have lower confidence (0.4).
///
/// 2. **Source Quality and Quantity**: Assets discovered by multiple sources receive a bonus.
///    High-quality sources (DNS, crt.sh) are weighted more heavily than lower-quality sources.
///
/// 3. **Cross-Validation**: When both high-reliability and low-reliability sources agree on an asset,
///    it receives a cross-validation bonus (typically +0.12).
///
/// 4. **Network Topology**: Assets closer to their seed have higher confidence. Each hop away from
///    the seed incurs a small penalty (default 0.05 per hop).
///
/// 5. **Temporal Factors**:
///    - Fresh assets (< 7 days) receive a freshness bonus (+0.1)
///    - Old assets (> 90 days) receive age penalties (-0.02 per month)
///
/// 6. **Scan Validation**: Assets that pass security scans receive a validation bonus (+0.15),
///    while assets that fail scans receive a penalty (-0.2).
///
/// 7. **Rediscovery Bonus**: When assets are rediscovered, they receive a small bonus for each
///    new source (up to +0.15 total).
///
/// # Example
///
/// ```rust
/// use easm::services::confidence::{ConfidenceScorer, ConfidenceFactors};
///
/// let scorer = ConfidenceScorer::new();
///
/// let factors = ConfidenceFactors {
///     base_confidence: 0.7,
///     sources: vec!["shodan".to_string(), "crt.sh".to_string()],
///     is_direct_subdomain: true,
///     distance_from_seed: 1,
///     age_days: Some(5.0),
///     validated_by_scan: true,
///     scan_success_rate: Some(1.0),
///     ..Default::default()
/// };
///
/// let confidence = scorer.calculate_confidence(&factors);
/// // Result: ~0.97 (base 0.7 + multi-source 0.08 + subdomain 0.15 + freshness 0.1 + validation 0.15)
/// ```
///
/// # Improvements Over Previous System
///
/// The previous system used hard-coded confidence values:
/// - DNS resolution: 0.8
/// - Certificate with org: 0.7
/// - Keyword search: 0.4
/// - etc.
///
/// The new system:
/// - Considers multiple factors dynamically
/// - Rewards assets discovered by multiple sources
/// - Penalizes assets that are far from seeds or old
/// - Updates confidence based on scan results
/// - Provides transparency through configurable parameters
/// - Supports time-based decay for better asset lifecycle management
use std::collections::HashMap;

/// Source reliability weights (0.0 - 1.0)
/// Higher values indicate more reliable sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceWeights {
    // High reliability sources (verified infrastructure)
    pub seed: f64,           // 1.0 - Direct seed input
    pub scan_target: f64,    // 1.0 - Direct scan target
    pub dns_resolution: f64, // 0.95 - Active DNS record
    pub cidr_expansion: f64, // 0.9 - Direct IP ownership

    // Good reliability sources (external verification)
    pub crt_sh: f64,          // 0.85 - Certificate Transparency logs
    pub shodan: f64,          // 0.8 - Active host scanning
    pub tls_certificate: f64, // 0.8 - Live TLS certificate

    // Medium reliability sources (indirect discovery)
    pub subdomain_enum: f64, // 0.7 - Enumeration tools
    pub wayback: f64,        // 0.6 - Historical records
    pub urlscan: f64,        // 0.65 - URL scanning
    pub otx: f64,            // 0.6 - AlienVault OTX

    // Lower reliability sources (keyword/fuzzy matching)
    pub keyword_search: f64,    // 0.4 - Keyword-based discovery
    pub certificate_pivot: f64, // 0.5 - Certificate organization pivot
    pub org_search: f64,        // 0.55 - Organization-based search
}

impl Default for SourceWeights {
    fn default() -> Self {
        Self {
            seed: 1.0,
            scan_target: 1.0,
            dns_resolution: 0.95,
            cidr_expansion: 0.9,
            crt_sh: 0.85,
            shodan: 0.8,
            tls_certificate: 0.8,
            subdomain_enum: 0.7,
            urlscan: 0.65,
            wayback: 0.6,
            otx: 0.6,
            org_search: 0.55,
            certificate_pivot: 0.5,
            keyword_search: 0.4,
        }
    }
}

impl SourceWeights {
    /// Get weight for a specific source
    pub fn get_weight(&self, source: &str) -> f64 {
        match source.to_lowercase().as_str() {
            "seed" => self.seed,
            "scan_target" => self.scan_target,
            "dns_resolution" => self.dns_resolution,
            "cidr_expansion" => self.cidr_expansion,
            "crt.sh" | "crtsh" => self.crt_sh,
            "shodan" => self.shodan,
            "tls_certificate" | "certificate" => self.tls_certificate,
            "subdomain_enum" | "subdomain_enumeration" => self.subdomain_enum,
            "wayback" => self.wayback,
            "urlscan" => self.urlscan,
            "otx" => self.otx,
            "org_search"
            | "organization"
            | "shodan_org_comprehensive"
            | "shodan_asn_comprehensive" => self.org_search,
            "certificate_pivot" => self.certificate_pivot,
            "keyword" | "keyword_search" | "shodan_keyword_comprehensive" => self.keyword_search,
            _ => 0.5, // Default medium reliability for unknown sources
        }
    }
}

/// Discovery method base confidence scores
#[derive(Debug, Clone)]
pub struct MethodConfidence {
    pub base: f64,
    pub description: &'static str,
}

impl MethodConfidence {
    pub const SEED: Self = Self {
        base: 1.0,
        description: "Direct seed input",
    };
    pub const SCAN_TARGET: Self = Self {
        base: 1.0,
        description: "Direct scan target",
    };
    pub const CIDR_EXPANSION: Self = Self {
        base: 0.85,
        description: "Direct IP ownership",
    };
    pub const DNS_RESOLUTION: Self = Self {
        base: 0.85,
        description: "Active DNS record",
    };
    pub const SHODAN_ASN: Self = Self {
        base: 0.8,
        description: "Shodan ASN member",
    };
    pub const TLS_CERT_WITH_ORG: Self = Self {
        base: 0.7,
        description: "Verified certificate",
    };
    pub const SHODAN_ORG: Self = Self {
        base: 0.7,
        description: "Shodan org match",
    };
    pub const SUBDOMAIN_ENUM: Self = Self {
        base: 0.6,
        description: "Subdomain enumeration",
    };
    pub const CRTSH_ORG: Self = Self {
        base: 0.6,
        description: "CT log organization",
    };
    pub const KEYWORD_SEARCH: Self = Self {
        base: 0.4,
        description: "Keyword match",
    };
    pub const TLS_CERT_NO_ORG: Self = Self {
        base: 0.3,
        description: "Unverified certificate",
    };
}

/// Confidence calculation parameters
#[derive(Debug, Clone)]
pub struct ConfidenceFactors {
    /// Base confidence from discovery method
    pub base_confidence: f64,

    /// Sources that discovered this asset
    pub sources: Vec<String>,

    /// Whether this is a direct subdomain of parent
    pub is_direct_subdomain: bool,

    /// Distance from seed (number of hops)
    pub distance_from_seed: usize,

    /// Asset age (time since creation)
    pub age_days: Option<f64>,

    /// Whether asset has been validated by scan
    pub validated_by_scan: bool,

    /// Scan success rate (0.0 - 1.0) if scanned
    pub scan_success_rate: Option<f64>,

    /// Asset metadata for additional context
    pub metadata: HashMap<String, String>,
}

impl Default for ConfidenceFactors {
    fn default() -> Self {
        Self {
            base_confidence: 0.5,
            sources: Vec::new(),
            is_direct_subdomain: false,
            distance_from_seed: 0,
            age_days: None,
            validated_by_scan: false,
            scan_success_rate: None,
            metadata: HashMap::new(),
        }
    }
}

/// Confidence scoring engine
#[derive(Debug, Clone)]
pub struct ConfidenceScorer {
    source_weights: SourceWeights,

    // Configurable parameters
    multi_source_bonus: f64, // Bonus per additional source (default: 0.08)
    max_multi_source_bonus: f64, // Max total multi-source bonus (default: 0.3)
    direct_subdomain_bonus: f64, // Bonus for direct subdomain (default: 0.15)
    cross_validation_bonus: f64, // Bonus when high+low reliability sources agree (default: 0.12)
    distance_penalty_per_hop: f64, // Penalty per hop from seed (default: 0.05)
    max_distance_penalty: f64, // Max total distance penalty (default: 0.25)

    // Time-based factors
    freshness_bonus_days: f64, // Days to apply freshness bonus (default: 7)
    freshness_bonus: f64,      // Bonus for fresh assets (default: 0.1)
    age_penalty_start_days: f64, // Days before age penalty starts (default: 90)
    age_penalty_per_month: f64, // Penalty per month after threshold (default: 0.02)
    max_age_penalty: f64,      // Max total age penalty (default: 0.2)

    // Validation factors
    scan_validation_bonus: f64, // Bonus for successful scan validation (default: 0.15)
    scan_failure_penalty: f64,  // Penalty for failed scan (default: 0.2)
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self {
            source_weights: SourceWeights::default(),
            multi_source_bonus: 0.08,
            max_multi_source_bonus: 0.3,
            direct_subdomain_bonus: 0.15,
            cross_validation_bonus: 0.12,
            distance_penalty_per_hop: 0.05,
            max_distance_penalty: 0.25,
            freshness_bonus_days: 7.0,
            freshness_bonus: 0.1,
            age_penalty_start_days: 90.0,
            age_penalty_per_month: 0.02,
            max_age_penalty: 0.2,
            scan_validation_bonus: 0.15,
            scan_failure_penalty: 0.2,
        }
    }
}

impl ConfidenceScorer {
    /// Create a new confidence scorer with default parameters
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new confidence scorer with custom source weights
    pub fn with_source_weights(source_weights: SourceWeights) -> Self {
        Self {
            source_weights,
            ..Default::default()
        }
    }

    /// Calculate comprehensive confidence score based on multiple factors
    pub fn calculate_confidence(&self, factors: &ConfidenceFactors) -> f64 {
        let mut confidence = factors.base_confidence;

        // 1. Multi-source bonus (weighted by source quality)
        if factors.sources.len() > 1 {
            let source_quality = self.calculate_source_quality(&factors.sources);
            let source_bonus =
                ((factors.sources.len() - 1) as f64 * self.multi_source_bonus * source_quality)
                    .min(self.max_multi_source_bonus);
            confidence += source_bonus;
        }

        // 2. Direct subdomain bonus
        if factors.is_direct_subdomain {
            confidence += self.direct_subdomain_bonus;
        }

        // 3. Cross-validation bonus (high and low reliability sources agree)
        if self.has_cross_validation(&factors.sources) {
            confidence += self.cross_validation_bonus;
        }

        // 4. Distance penalty (assets far from seed are less confident)
        if factors.distance_from_seed > 0 {
            let distance_penalty = (factors.distance_from_seed as f64
                * self.distance_penalty_per_hop)
                .min(self.max_distance_penalty);
            confidence -= distance_penalty;
        }

        // 5. Time-based factors
        if let Some(age_days) = factors.age_days {
            // Freshness bonus for very recent discoveries
            if age_days <= self.freshness_bonus_days {
                confidence += self.freshness_bonus;
            }

            // Age penalty for old assets
            if age_days > self.age_penalty_start_days {
                let age_months = (age_days - self.age_penalty_start_days) / 30.0;
                let age_penalty =
                    (age_months * self.age_penalty_per_month).min(self.max_age_penalty);
                confidence -= age_penalty;
            }
        }

        // 6. Scan validation adjustment
        if factors.validated_by_scan {
            if let Some(success_rate) = factors.scan_success_rate {
                if success_rate >= 0.5 {
                    // Successful validation increases confidence
                    confidence += self.scan_validation_bonus * success_rate;
                } else {
                    // Failed validation decreases confidence
                    confidence -= self.scan_failure_penalty * (1.0 - success_rate);
                }
            } else {
                // Scanned but no success rate - give partial bonus
                confidence += self.scan_validation_bonus * 0.5;
            }
        }

        // Ensure confidence stays within valid range [0.0, 1.0]
        confidence.clamp(0.0, 1.0)
    }

    /// Calculate domain-specific confidence (for subdomain enumeration)
    pub fn calculate_domain_confidence(
        &self,
        domain: &str,
        parent_domain: &str,
        sources: &HashMap<String, Vec<String>>,
    ) -> f64 {
        let source_list: Vec<String> = sources.keys().cloned().collect();
        let is_direct_subdomain = domain.ends_with(&format!(".{}", parent_domain));

        // Determine base confidence from strongest source
        let base_confidence = source_list
            .iter()
            .map(|s| self.source_weights.get_weight(s))
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.5);

        let factors = ConfidenceFactors {
            base_confidence,
            sources: source_list,
            is_direct_subdomain,
            distance_from_seed: 1, // Subdomains are typically 1 hop from parent
            age_days: None,
            validated_by_scan: false,
            scan_success_rate: None,
            metadata: HashMap::new(),
        };

        self.calculate_confidence(&factors)
    }

    /// Calculate IP confidence (for DNS-resolved IPs)
    pub fn calculate_ip_confidence(&self, sources: Vec<String>) -> f64 {
        let base_confidence = if sources.contains(&"dns_resolution".to_string()) {
            self.source_weights.dns_resolution
        } else if sources.contains(&"cidr_expansion".to_string()) {
            self.source_weights.cidr_expansion
        } else if sources.contains(&"shodan".to_string()) {
            self.source_weights.shodan
        } else {
            0.7
        };

        let factors = ConfidenceFactors {
            base_confidence,
            sources,
            is_direct_subdomain: false,
            distance_from_seed: 1,
            age_days: None,
            validated_by_scan: false,
            scan_success_rate: None,
            metadata: HashMap::new(),
        };

        self.calculate_confidence(&factors)
    }

    /// Calculate certificate confidence
    pub fn calculate_certificate_confidence(
        &self,
        has_organization: bool,
        sources: Vec<String>,
    ) -> f64 {
        let base_confidence = if has_organization {
            MethodConfidence::TLS_CERT_WITH_ORG.base
        } else {
            MethodConfidence::TLS_CERT_NO_ORG.base
        };

        let factors = ConfidenceFactors {
            base_confidence,
            sources,
            is_direct_subdomain: false,
            distance_from_seed: 1,
            age_days: None,
            validated_by_scan: false,
            scan_success_rate: None,
            metadata: HashMap::new(),
        };

        self.calculate_confidence(&factors)
    }

    /// Update confidence based on scan results
    pub fn update_confidence_from_scan(
        &self,
        current_confidence: f64,
        scan_successful: bool,
        created_at: DateTime<Utc>,
    ) -> f64 {
        let age_days = (Utc::now() - created_at).num_days() as f64;

        // Apply only scan and time adjustments to existing confidence
        let mut adjusted = current_confidence;

        // Time decay
        if age_days > self.age_penalty_start_days {
            let age_months = (age_days - self.age_penalty_start_days) / 30.0;
            let age_penalty = (age_months * self.age_penalty_per_month).min(self.max_age_penalty);
            adjusted -= age_penalty;
        }

        // Scan validation
        if scan_successful {
            adjusted += self.scan_validation_bonus;
        } else {
            adjusted -= self.scan_failure_penalty;
        }

        adjusted.clamp(0.0, 1.0)
    }

    /// Merge confidence scores when asset is discovered multiple times
    pub fn merge_confidence(
        &self,
        existing_confidence: f64,
        new_confidence: f64,
        existing_sources: &[String],
        new_sources: &[String],
    ) -> f64 {
        // Combine sources
        let mut all_sources: Vec<String> = existing_sources.to_vec();
        for source in new_sources {
            if !all_sources.contains(source) {
                all_sources.push(source.clone());
            }
        }

        // Start with the higher of the two base confidences
        let base = existing_confidence.max(new_confidence);

        // Calculate bonus from having multiple confirmations
        let confirmation_bonus = if all_sources.len() > existing_sources.len() {
            let new_source_count = all_sources.len() - existing_sources.len();
            let source_quality = self.calculate_source_quality(new_sources);
            (new_source_count as f64 * self.multi_source_bonus * source_quality * 0.5) // 50% bonus for re-discovery
                .min(0.15) // Cap re-discovery bonus
        } else {
            0.0
        };

        (base + confirmation_bonus).min(1.0)
    }

    /// Calculate overall quality score for a list of sources
    fn calculate_source_quality(&self, sources: &[String]) -> f64 {
        if sources.is_empty() {
            return 0.0;
        }

        let total_weight: f64 = sources
            .iter()
            .map(|s| self.source_weights.get_weight(s))
            .sum();

        total_weight / sources.len() as f64
    }

    /// Check if sources include both high and low reliability sources (cross-validation)
    fn has_cross_validation(&self, sources: &[String]) -> bool {
        let weights: Vec<f64> = sources
            .iter()
            .map(|s| self.source_weights.get_weight(s))
            .collect();

        let has_high = weights.iter().any(|&w| w >= 0.8);
        let has_medium_low = weights.iter().any(|&w| w <= 0.6);

        has_high && has_medium_low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_confidence_calculation() {
        let scorer = ConfidenceScorer::new();

        let factors = ConfidenceFactors {
            base_confidence: 0.7,
            sources: vec!["shodan".to_string()],
            ..Default::default()
        };

        let confidence = scorer.calculate_confidence(&factors);
        assert!(confidence >= 0.7 && confidence <= 1.0);
    }

    #[test]
    fn test_multi_source_bonus() {
        let scorer = ConfidenceScorer::new();

        let single_source = ConfidenceFactors {
            base_confidence: 0.6,
            sources: vec!["crt.sh".to_string()],
            ..Default::default()
        };

        let multi_source = ConfidenceFactors {
            base_confidence: 0.6,
            sources: vec![
                "crt.sh".to_string(),
                "shodan".to_string(),
                "dns_resolution".to_string(),
            ],
            ..Default::default()
        };

        let single_conf = scorer.calculate_confidence(&single_source);
        let multi_conf = scorer.calculate_confidence(&multi_source);

        assert!(
            multi_conf > single_conf,
            "Multi-source should have higher confidence"
        );
    }

    #[test]
    fn test_subdomain_bonus() {
        let scorer = ConfidenceScorer::new();

        let non_subdomain = ConfidenceFactors {
            base_confidence: 0.6,
            sources: vec!["crt.sh".to_string()],
            is_direct_subdomain: false,
            ..Default::default()
        };

        let subdomain = ConfidenceFactors {
            base_confidence: 0.6,
            sources: vec!["crt.sh".to_string()],
            is_direct_subdomain: true,
            ..Default::default()
        };

        let non_sub_conf = scorer.calculate_confidence(&non_subdomain);
        let sub_conf = scorer.calculate_confidence(&subdomain);

        assert!(
            sub_conf > non_sub_conf,
            "Direct subdomain should have higher confidence"
        );
    }

    #[test]
    fn test_distance_penalty() {
        let scorer = ConfidenceScorer::new();

        let close = ConfidenceFactors {
            base_confidence: 0.8,
            sources: vec!["shodan".to_string()],
            distance_from_seed: 1,
            ..Default::default()
        };

        let far = ConfidenceFactors {
            base_confidence: 0.8,
            sources: vec!["shodan".to_string()],
            distance_from_seed: 4,
            ..Default::default()
        };

        let close_conf = scorer.calculate_confidence(&close);
        let far_conf = scorer.calculate_confidence(&far);

        assert!(
            far_conf < close_conf,
            "Assets far from seed should have lower confidence"
        );
    }

    #[test]
    fn test_scan_validation_bonus() {
        let scorer = ConfidenceScorer::new();

        let unvalidated = ConfidenceFactors {
            base_confidence: 0.6,
            sources: vec!["crt.sh".to_string()],
            validated_by_scan: false,
            ..Default::default()
        };

        let validated = ConfidenceFactors {
            base_confidence: 0.6,
            sources: vec!["crt.sh".to_string()],
            validated_by_scan: true,
            scan_success_rate: Some(1.0),
            ..Default::default()
        };

        let unval_conf = scorer.calculate_confidence(&unvalidated);
        let val_conf = scorer.calculate_confidence(&validated);

        assert!(
            val_conf > unval_conf,
            "Validated assets should have higher confidence"
        );
    }

    #[test]
    fn test_age_penalty() {
        let scorer = ConfidenceScorer::new();

        let fresh = ConfidenceFactors {
            base_confidence: 0.7,
            sources: vec!["shodan".to_string()],
            age_days: Some(5.0),
            ..Default::default()
        };

        let old = ConfidenceFactors {
            base_confidence: 0.7,
            sources: vec!["shodan".to_string()],
            age_days: Some(180.0), // 6 months
            ..Default::default()
        };

        let fresh_conf = scorer.calculate_confidence(&fresh);
        let old_conf = scorer.calculate_confidence(&old);

        assert!(
            fresh_conf > old_conf,
            "Fresh assets should have higher confidence than old ones"
        );
    }

    #[test]
    fn test_merge_confidence() {
        let scorer = ConfidenceScorer::new();

        let existing_sources = vec!["crt.sh".to_string()];
        let new_sources = vec!["shodan".to_string(), "dns_resolution".to_string()];

        let merged = scorer.merge_confidence(0.6, 0.7, &existing_sources, &new_sources);

        assert!(
            merged >= 0.7,
            "Merged confidence should be at least the max of the two"
        );
        assert!(merged <= 1.0, "Merged confidence should not exceed 1.0");
    }
}

pub mod active_dns;
pub mod asn;
pub mod certspotter;
pub mod crtsh;
pub mod dns;
pub mod http;
pub mod manager;
pub mod nvd;
pub mod passive_sources;
pub mod rate_limited_client;
pub mod shodan;
pub mod threat_intel;
pub mod virustotal;

#[cfg(test)]
pub mod integration_tests;

pub use active_dns::{
    ActiveDnsConfig, ActiveDnsDiscovery, ActiveDnsResult, ResolvedHost, WildcardProfile,
};
pub use asn::{AsnClient, AsnPrefixes, IpAttribution, RdapRecord};
pub use certspotter::{CertSpotterCertificate, CertSpotterClient, CertSpotterIssuance};
pub use crtsh::CrtShClient;
pub use dns::{DnsConfig, DnsResolver, DnsResult, ReverseDnsResult};
pub use http::{HttpAnalyzer, HttpConfig, HttpProbeResult, TlsCertificateResult, TlsInfo};
pub use manager::{ExternalServicesManager, SubdomainEnumerationResult, ThreatIntelligenceResult};
pub use nvd::{NvdClient, NvdCpeMatch, NvdVulnerability};
pub use passive_sources::{
    OsintCredentials, PassiveContext, PassiveSource, PassiveSourceOutcome, SourceStatus,
};
pub use rate_limited_client::RateLimitedClient;
pub use shodan::{
    ShodanCertificateInfo, ShodanClient, ShodanExtractedAssets, ShodanHostInfo, ShodanResult,
};
pub use threat_intel::{EpssScore, KevEntry, ThreatContext, ThreatIntelClient};
pub use virustotal::{VirusTotalClient, VirusTotalDomainReport, VirusTotalIpReport};

// Type aliases for convenience
pub type HttpProber = HttpAnalyzer;
pub type TlsAnalyzer = HttpAnalyzer;

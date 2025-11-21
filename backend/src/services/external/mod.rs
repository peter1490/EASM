pub mod crtsh;
pub mod shodan;
pub mod dns;
pub mod http;
pub mod virustotal;
pub mod certspotter;
pub mod rate_limited_client;
pub mod manager;

#[cfg(test)]
pub mod integration_tests;

pub use crtsh::CrtShClient;
pub use shodan::{ShodanClient, ShodanResult, ShodanExtractedAssets, ShodanCertificateInfo};
pub use dns::{DnsResolver, DnsResult, ReverseDnsResult, DnsConfig};
pub use http::{HttpAnalyzer, HttpProbeResult, TlsInfo, TlsCertificateResult, HttpConfig};
pub use virustotal::{VirusTotalClient, VirusTotalDomainReport, VirusTotalIpReport};
pub use certspotter::{CertSpotterClient, CertSpotterIssuance, CertSpotterCertificate};
pub use rate_limited_client::RateLimitedClient;
pub use manager::{ExternalServicesManager, SubdomainEnumerationResult, ThreatIntelligenceResult};

// Type aliases for convenience
pub type HttpProber = HttpAnalyzer;
pub type TlsAnalyzer = HttpAnalyzer;
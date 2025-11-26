pub mod certspotter;
pub mod crtsh;
pub mod dns;
pub mod http;
pub mod manager;
pub mod rate_limited_client;
pub mod shodan;
pub mod virustotal;

#[cfg(test)]
pub mod integration_tests;

pub use certspotter::{CertSpotterCertificate, CertSpotterClient, CertSpotterIssuance};
pub use crtsh::CrtShClient;
pub use dns::{DnsConfig, DnsResolver, DnsResult, ReverseDnsResult};
pub use http::{HttpAnalyzer, HttpConfig, HttpProbeResult, TlsCertificateResult, TlsInfo};
pub use manager::{ExternalServicesManager, SubdomainEnumerationResult, ThreatIntelligenceResult};
pub use rate_limited_client::RateLimitedClient;
pub use shodan::{ShodanCertificateInfo, ShodanClient, ShodanExtractedAssets, ShodanResult};
pub use virustotal::{VirusTotalClient, VirusTotalDomainReport, VirusTotalIpReport};

// Type aliases for convenience
pub type HttpProber = HttpAnalyzer;
pub type TlsAnalyzer = HttpAnalyzer;

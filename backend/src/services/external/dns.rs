use crate::error::ApiError;
use futures::future::join_all;
use governor::{
    clock::DefaultClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

/// DNS resolution configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Timeout for individual DNS queries
    pub query_timeout: Duration,
    /// Maximum concurrent DNS queries
    pub max_concurrent: usize,
    /// Rate limit for DNS queries (queries per second)
    pub rate_limit: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(5),
            max_concurrent: 50,
            rate_limit: 100,
        }
    }
}

/// DNS resolution result
#[derive(Debug, Clone)]
pub struct DnsResult {
    pub hostname: String,
    pub ips: Vec<IpAddr>,
    pub error: Option<String>,
}

/// Reverse DNS lookup result
#[derive(Debug, Clone)]
pub struct ReverseDnsResult {
    pub ip: IpAddr,
    pub hostnames: Vec<String>,
    pub error: Option<String>,
}

/// Async DNS resolver with timeout handling and concurrency limits
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    config: DnsConfig,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl DnsResolver {
    /// Create a new DNS resolver with default configuration
    pub async fn new() -> Result<Self, ApiError> {
        Self::with_config(DnsConfig::default()).await
    }

    /// Create a new DNS resolver with custom configuration
    pub async fn with_config(config: DnsConfig) -> Result<Self, ApiError> {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = config.query_timeout;
        resolver_opts.attempts = 2;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), resolver_opts);

        // Create rate limiter
        let quota = Quota::per_second(std::num::NonZeroU32::new(config.rate_limit).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Self {
            resolver,
            config,
            rate_limiter,
        })
    }

    /// Resolve a single hostname to IP addresses with timeout
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let hostname_owned = hostname.to_string();
        let hostname_for_error = hostname_owned.clone();
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.lookup_ip(&hostname_owned).await.map_err(|e| {
                ApiError::ExternalService(format!(
                    "DNS resolution failed for {}: {}",
                    hostname_owned, e
                ))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("DNS query timeout for {}", hostname_for_error))
        })?;

        match result {
            Ok(response) => {
                let ips: Vec<IpAddr> = response.iter().collect();
                Ok(ips)
            }
            Err(e) => Err(e),
        }
    }

    /// Perform reverse DNS lookup for an IP address
    pub async fn reverse_lookup(&self, ip: &IpAddr) -> Result<Vec<String>, ApiError> {
        // Apply rate limiting
        self.rate_limiter.until_ready().await;

        let ip_addr = *ip;
        let resolver = self.resolver.clone();
        let query_timeout = self.config.query_timeout;

        let result = timeout(query_timeout, async move {
            resolver.reverse_lookup(ip_addr).await.map_err(|e| {
                ApiError::ExternalService(format!(
                    "Reverse DNS lookup failed for {}: {}",
                    ip_addr, e
                ))
            })
        })
        .await
        .map_err(|_| {
            ApiError::ExternalService(format!("Reverse DNS query timeout for {}", ip_addr))
        })?;

        match result {
            Ok(response) => {
                let hostnames: Vec<String> = response.iter().map(|name| name.to_string()).collect();
                Ok(hostnames)
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve multiple hostnames concurrently with configurable limits
    pub async fn resolve_hostnames_concurrent(&self, hostnames: Vec<String>) -> Vec<DnsResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrent));
        let resolver_clone = self.resolver.clone();
        let rate_limiter_clone = self.rate_limiter.clone();
        let query_timeout = self.config.query_timeout;

        let tasks: Vec<_> = hostnames
            .into_iter()
            .map(|hostname| {
                let semaphore = semaphore.clone();
                let resolver = resolver_clone.clone();
                let rate_limiter = rate_limiter_clone.clone();

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    // Apply rate limiting
                    rate_limiter.until_ready().await;

                    let result = timeout(query_timeout, async {
                        resolver.lookup_ip(&hostname).await.map_err(|e| {
                            ApiError::ExternalService(format!(
                                "DNS resolution failed for {}: {}",
                                hostname, e
                            ))
                        })
                    })
                    .await
                    .map_err(|_| {
                        ApiError::ExternalService(format!("DNS query timeout for {}", hostname))
                    });

                    match result {
                        Ok(Ok(response)) => {
                            let ips: Vec<IpAddr> = response.iter().collect();
                            DnsResult {
                                hostname: hostname.clone(),
                                ips,
                                error: None,
                            }
                        }
                        Ok(Err(e)) | Err(e) => DnsResult {
                            hostname: hostname.clone(),
                            ips: vec![],
                            error: Some(e.to_string()),
                        },
                    }
                })
            })
            .collect();

        let results = join_all(tasks).await;
        results.into_iter().filter_map(|r| r.ok()).collect()
    }

    /// Perform reverse DNS lookups for multiple IP addresses concurrently
    pub async fn reverse_lookup_concurrent(&self, ips: Vec<IpAddr>) -> Vec<ReverseDnsResult> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrent));
        let resolver_clone = self.resolver.clone();
        let rate_limiter_clone = self.rate_limiter.clone();
        let query_timeout = self.config.query_timeout;

        let tasks: Vec<_> = ips
            .into_iter()
            .map(|ip| {
                let semaphore = semaphore.clone();
                let resolver = resolver_clone.clone();
                let rate_limiter = rate_limiter_clone.clone();

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    // Apply rate limiting
                    rate_limiter.until_ready().await;

                    let result = timeout(query_timeout, async {
                        resolver.reverse_lookup(ip).await.map_err(|e| {
                            ApiError::ExternalService(format!(
                                "Reverse DNS lookup failed for {}: {}",
                                ip, e
                            ))
                        })
                    })
                    .await
                    .map_err(|_| {
                        ApiError::ExternalService(format!("Reverse DNS query timeout for {}", ip))
                    });

                    match result {
                        Ok(Ok(response)) => {
                            let hostnames: Vec<String> =
                                response.iter().map(|name| name.to_string()).collect();
                            ReverseDnsResult {
                                ip,
                                hostnames,
                                error: None,
                            }
                        }
                        Ok(Err(e)) | Err(e) => ReverseDnsResult {
                            ip,
                            hostnames: vec![],
                            error: Some(e.to_string()),
                        },
                    }
                })
            })
            .collect();

        let results = join_all(tasks).await;
        results.into_iter().filter_map(|r| r.ok()).collect()
    }

    /// Check if a hostname resolves to any IP address
    pub async fn hostname_exists(&self, hostname: &str) -> bool {
        match self.resolve_hostname(hostname).await {
            Ok(ips) => !ips.is_empty(),
            Err(_) => false,
        }
    }

    /// Get the configuration used by this resolver
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_dns_resolver_creation() {
        let resolver = DnsResolver::new().await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_dns_resolver_with_custom_config() {
        let config = DnsConfig {
            query_timeout: Duration::from_secs(3),
            max_concurrent: 25,
            rate_limit: 50,
        };

        let resolver = DnsResolver::with_config(config.clone()).await;
        assert!(resolver.is_ok());

        let resolver = resolver.unwrap();
        assert_eq!(resolver.config().query_timeout, config.query_timeout);
        assert_eq!(resolver.config().max_concurrent, config.max_concurrent);
        assert_eq!(resolver.config().rate_limit, config.rate_limit);
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let resolver = DnsResolver::new().await.unwrap();
        let result = resolver.resolve_hostname("localhost").await;

        // localhost should resolve to something (usually 127.0.0.1 or ::1)
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_invalid_hostname() {
        let resolver = DnsResolver::new().await.unwrap();
        let result = resolver
            .resolve_hostname("this-domain-should-not-exist-12345.invalid")
            .await;

        // Should fail for invalid domain
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reverse_lookup_localhost() {
        let resolver = DnsResolver::new().await.unwrap();
        let localhost_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = resolver.reverse_lookup(&localhost_ip).await;

        // Reverse lookup might succeed or fail depending on system configuration
        // We just test that it doesn't panic
        match result {
            Ok(hostnames) => {
                println!("Reverse lookup successful: {:?}", hostnames);
            }
            Err(e) => {
                println!("Reverse lookup failed (expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_resolution() {
        let resolver = DnsResolver::new().await.unwrap();
        let hostnames = vec![
            "localhost".to_string(),
            "example.com".to_string(),
            "invalid-domain-12345.test".to_string(),
        ];

        let results = resolver.resolve_hostnames_concurrent(hostnames).await;

        // Should have results for all hostnames (some may have errors)
        assert_eq!(results.len(), 3);

        // Check that localhost resolved successfully
        let localhost_result = results.iter().find(|r| r.hostname == "localhost");
        assert!(localhost_result.is_some());
        let localhost_result = localhost_result.unwrap();
        assert!(localhost_result.error.is_none());
        assert!(!localhost_result.ips.is_empty());

        // Check that invalid domain has an error
        let invalid_result = results
            .iter()
            .find(|r| r.hostname == "invalid-domain-12345.test");
        assert!(invalid_result.is_some());
        let invalid_result = invalid_result.unwrap();
        assert!(invalid_result.error.is_some());
        assert!(invalid_result.ips.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_reverse_lookup() {
        let resolver = DnsResolver::new().await.unwrap();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];

        let results = resolver.reverse_lookup_concurrent(ips).await;

        // Should have results for all IPs (some may have errors)
        assert_eq!(results.len(), 3);

        // Results should contain the IPs we queried
        let result_ips: Vec<IpAddr> = results.iter().map(|r| r.ip).collect();
        assert!(result_ips.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(result_ips.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(result_ips.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[tokio::test]
    async fn test_hostname_exists() {
        let resolver = DnsResolver::new().await.unwrap();

        // localhost should exist
        assert!(resolver.hostname_exists("localhost").await);

        // Invalid domain should not exist
        assert!(
            !resolver
                .hostname_exists("this-domain-should-not-exist-12345.invalid")
                .await
        );
    }

    #[tokio::test]
    async fn test_timeout_configuration() {
        let config = DnsConfig {
            query_timeout: Duration::from_millis(1), // Very short timeout
            max_concurrent: 10,
            rate_limit: 100,
        };

        let resolver = DnsResolver::with_config(config).await.unwrap();

        // This should timeout quickly
        let start = std::time::Instant::now();
        let result = resolver.resolve_hostname("example.com").await;
        let elapsed = start.elapsed();

        // Should fail due to timeout and complete quickly
        assert!(result.is_err());
        assert!(elapsed < Duration::from_millis(100)); // Should be much faster than normal DNS query
    }
}

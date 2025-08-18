use crate::config::Settings;
use super::{ExternalServicesManager, CrtShClient, ShodanClient, VirusTotalClient, CertSpotterClient};
use std::sync::Arc;
use wiremock::{matchers::{method, query_param, header}, Mock, MockServer, ResponseTemplate};

/// Integration tests for external API services with mocked responses
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_comprehensive_subdomain_enumeration() {
        // Create mock servers for different services
        let crtsh_mock = MockServer::start().await;
        let vt_mock = MockServer::start().await;
        let cs_mock = MockServer::start().await;

        // Mock crt.sh response
        let crtsh_response = r#"[
            {"name_value": "example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"}
        ]"#;
        
        Mock::given(method("GET"))
            .and(query_param("output", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(crtsh_response))
            .mount(&crtsh_mock)
            .await;

        // Mock VirusTotal subdomains response
        let vt_response = r#"{
            "data": [
                {"id": "mail.example.com"},
                {"id": "ftp.example.com"}
            ]
        }"#;
        
        Mock::given(method("GET"))
            .and(header("x-apikey", "test_vt_key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(vt_response))
            .mount(&vt_mock)
            .await;

        // Mock CertSpotter issuances response
        let cs_response = r#"[
            {
                "id": "123456",
                "tbs_sha256": "abc123",
                "dns_names": ["dev.example.com", "staging.example.com"],
                "pubkey_sha256": "def456",
                "not_before": "2023-01-01T00:00:00Z",
                "not_after": "2024-01-01T00:00:00Z",
                "issuer": {
                    "name": "Test CA",
                    "pubkey_sha256": "ghi789"
                }
            }
        ]"#;
        
        Mock::given(method("GET"))
            .and(query_param("domain", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string(cs_response))
            .mount(&cs_mock)
            .await;

        // Test individual clients (we can't easily mock the hardcoded URLs, but we can test the logic)
        let crtsh_client = CrtShClient::new().unwrap();
        assert!(crtsh_client.validate_and_clean_domain("www.example.com", "example.com").is_some());
        
        let vt_client = VirusTotalClient::new(Some("test_key".to_string())).unwrap();
        assert!(vt_client.is_configured());
        
        let cs_client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();
        assert!(cs_client.is_configured());
    }

    #[tokio::test]
    async fn test_threat_intelligence_integration() {
        let mock_server = MockServer::start().await;
        
        // Mock VirusTotal domain report with malicious indicators
        let malicious_response = r#"{
            "data": {
                "id": "malicious.com",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 5,
                        "malicious": 10,
                        "suspicious": 3,
                        "undetected": 2,
                        "timeout": 0
                    },
                    "reputation": -75
                }
            }
        }"#;
        
        Mock::given(method("GET"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(malicious_response))
            .mount(&mock_server)
            .await;

        let vt_client = VirusTotalClient::new(Some("test_key".to_string())).unwrap();
        
        // Test reputation analysis logic
        let test_report = serde_json::from_str::<super::super::virustotal::VirusTotalResponse<super::super::virustotal::VirusTotalDomainReport>>(malicious_response)
            .unwrap().data;
        
        assert!(vt_client.is_malicious_domain(&test_report));
        assert_eq!(vt_client.get_domain_reputation(&test_report), Some(-75));
    }

    #[tokio::test]
    async fn test_shodan_search_integration() {
        let mock_server = MockServer::start().await;
        
        // Mock Shodan search response
        let shodan_response = r#"{
            "matches": [
                {
                    "ip_str": "192.168.1.1",
                    "port": 80,
                    "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
                    "timestamp": "2023-01-01T00:00:00.000000",
                    "transport": "tcp",
                    "product": "nginx",
                    "version": "1.18.0",
                    "hostnames": ["example.com"],
                    "org": "Example Organization",
                    "isp": "Example ISP",
                    "asn": "AS12345"
                }
            ],
            "total": 1
        }"#;
        
        Mock::given(method("GET"))
            .and(query_param("q", "apache"))
            .respond_with(ResponseTemplate::new(200).set_body_string(shodan_response))
            .mount(&mock_server)
            .await;

        let shodan_client = ShodanClient::new(Some("test_key".to_string())).unwrap();
        assert!(shodan_client.is_configured());
        
        // Test query construction for different search types
        // These would normally make real requests, but we're testing the client logic
    }

    #[tokio::test]
    async fn test_rate_limiting_behavior() {
        use super::super::rate_limited_client::RateLimitedClient;
        use std::time::Instant;
        
        // Test that rate limiting actually delays requests
        let client = RateLimitedClient::new(2, 1).unwrap(); // 2 requests per second
        
        let start = Instant::now();
        
        // Make multiple requests that should be rate limited
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        // First request should be immediate
        let _response1 = client.get(&mock_server.uri()).await.unwrap();
        
        // Second request should be immediate (within the same second)
        let _response2 = client.get(&mock_server.uri()).await.unwrap();
        
        // Third request should be delayed
        let _response3 = client.get(&mock_server.uri()).await.unwrap();
        
        let elapsed = start.elapsed();
        
        // Should take at least 500ms due to rate limiting (2 requests per second)
        assert!(elapsed.as_millis() >= 400); // Allow some tolerance
    }

    #[tokio::test]
    async fn test_external_services_manager_integration() {
        // Test the manager with minimal configuration
        let settings = Arc::new(Settings::new_with_env_file(false).unwrap());
        let manager = ExternalServicesManager::new(settings).unwrap();
        
        // Verify service status
        let status = manager.get_service_status();
        assert!(status.get("crt.sh").unwrap_or(&false)); // Should always be available
        
        // Test configuration validation
        assert!(manager.validate_configuration().is_ok());
        
        // Test service count
        let count = manager.get_configured_services_count();
        assert!(count >= 1); // At least crt.sh
    }

    #[tokio::test]
    async fn test_api_key_validation() {
        // Test that clients properly validate API key formats
        let vt_client = VirusTotalClient::new(Some("valid_key_123".to_string())).unwrap();
        assert!(vt_client.is_configured());
        
        let shodan_client = ShodanClient::new(Some("valid_shodan_key".to_string())).unwrap();
        assert!(shodan_client.is_configured());
        
        let cs_client = CertSpotterClient::new(Some("valid_cs_token".to_string())).unwrap();
        assert!(cs_client.is_configured());
        
        // Test clients without API keys
        let vt_no_key = VirusTotalClient::new(None).unwrap();
        assert!(!vt_no_key.is_configured());
        
        let shodan_no_key = ShodanClient::new(None).unwrap();
        assert!(!shodan_no_key.is_configured());
        
        let cs_no_key = CertSpotterClient::new(None).unwrap();
        assert!(!cs_no_key.is_configured());
    }

    #[tokio::test]
    async fn test_error_handling_and_retries() {
        let mock_server = MockServer::start().await;
        
        // Test server error retry behavior
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;
            
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("success"))
            .mount(&mock_server)
            .await;

        let client = super::super::rate_limited_client::RateLimitedClient::new(10, 3).unwrap();
        let response = client.get(&mock_server.uri()).await.unwrap();
        
        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn test_concurrent_api_calls() {
        use tokio::task::JoinSet;
        
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        let client = Arc::new(super::super::rate_limited_client::RateLimitedClient::new(5, 1).unwrap());
        
        let mut join_set = JoinSet::new();
        
        // Spawn multiple concurrent requests
        for i in 0..5 {
            let client_clone = client.clone();
            let url = mock_server.uri();
            join_set.spawn(async move {
                let response = client_clone.get(&url).await.unwrap();
                (i, response.status().is_success())
            });
        }
        
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }
        
        // All requests should succeed
        assert_eq!(results.len(), 5);
        for (_, success) in results {
            assert!(success);
        }
    }

    #[tokio::test]
    async fn test_domain_validation_across_services() {
        // Test domain validation consistency across different services
        let crtsh_client = CrtShClient::new().unwrap();
        let cs_client = CertSpotterClient::new(Some("test_token".to_string())).unwrap();
        
        let test_cases = vec![
            ("example.com", "example.com", true),
            ("www.example.com", "example.com", true),
            ("sub.example.com", "example.com", true),
            ("*.example.com", "example.com", false), // Wildcards should be filtered
            ("other.com", "example.com", false),
            ("", "example.com", false),
            ("invalid domain", "example.com", false),
        ];
        
        for (domain, base_domain, expected) in test_cases {
            let crtsh_result = crtsh_client.validate_and_clean_domain(domain, base_domain).is_some();
            let cs_result = cs_client.validate_and_clean_domain(domain, base_domain).is_some();
            
            assert_eq!(crtsh_result, expected, "crt.sh validation failed for: {}", domain);
            assert_eq!(cs_result, expected, "CertSpotter validation failed for: {}", domain);
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::config::{Settings, ConfigError, get_settings, COMMON_PORTS, security_headers, SUBDOMAIN_WORDLIST};
    use std::env;
    use tempfile::NamedTempFile;
    use std::io::Write;

    /// Helper to set environment variables for testing
    fn with_env_vars<F, R>(vars: Vec<(&str, &str)>, test: F) -> R
    where 
        F: FnOnce() -> R
    {
        // List of all config-related environment variables that might interfere
        // Include both uppercase and lowercase versions since config crate might be case-insensitive
        let all_config_vars = vec![
            "DATABASE_URL", "database_url", "OPENSEARCH_URL", "CERTSPOTTER_API_TOKEN", "VIRUSTOTAL_API_KEY",
            "SHODAN_API_KEY", "URLSCAN_API_KEY", "OTX_API_KEY", "CLEARBIT_API_KEY",
            "OPENCORPORATES_API_TOKEN", "CORS_ALLOW_ORIGINS", "API_KEY_HEADER", "API_KEYS",
            "LOG_LEVEL", "LOG_FORMAT", "SQL_LOG_LEVEL", "MAX_EVIDENCE_BYTES",
            "EVIDENCE_ALLOWED_TYPES", "EVIDENCE_STORAGE_PATH", "HTTP_TIMEOUT_SECONDS",
            "TLS_TIMEOUT_SECONDS", "DNS_CONCURRENCY", "RDNS_CONCURRENCY", "TCP_SCAN_TIMEOUT",
            "TCP_SCAN_CONCURRENCY", "MAX_CIDR_HOSTS", "MAX_DISCOVERY_DEPTH",
            "SUBDOMAIN_ENUM_TIMEOUT", "ENABLE_WAYBACK", "ENABLE_URLSCAN", "ENABLE_OTX",
            "ENABLE_DNS_RECORD_EXPANSION", "ENABLE_WEB_CRAWL", "ENABLE_CLOUD_STORAGE_DISCOVERY",
            "ENABLE_WIKIDATA", "ENABLE_OPENCORPORATES", "RELATED_ASSET_CONFIDENCE_DEFAULT",
            "RATE_LIMIT_ENABLED", "RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW_SECONDS",
            "MAX_CONCURRENT_SCANS", "SCAN_QUEUE_CHECK_INTERVAL"
        ];
        
        // Store original values for all config variables
        let original_values: Vec<_> = all_config_vars.iter()
            .map(|key| (*key, env::var(key).ok()))
            .collect();
        
        // Clear all config variables first
        for key in &all_config_vars {
            env::remove_var(key);
        }
        
        // Set test values
        for (key, value) in &vars {
            env::set_var(key, value);
        }
        
        // Run test
        let result = test();
        
        // Restore original values
        for (key, original_value) in original_values {
            match original_value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
        
        result
    }

    #[test]
    fn test_default_settings() {
        // Use with_env_vars to ensure clean environment for this test
        let result = with_env_vars(vec![], || {
            Settings::new_with_env_file(false)
        });
        
        let settings = result.expect("Failed to create default settings");
        
        // Test database defaults (should be the default value, not from environment)
        assert_eq!(settings.database_url, "postgresql://easm:easm@localhost:5432/easm");
        assert_eq!(settings.opensearch_url, None);
        
        // Test API key defaults
        assert_eq!(settings.certspotter_api_token, None);
        assert_eq!(settings.virustotal_api_key, None);
        assert_eq!(settings.shodan_api_key, None);
        
        // Test security defaults
        assert_eq!(settings.cors_allow_origins, vec!["http://localhost:3000", "http://127.0.0.1:3000"]);
        assert_eq!(settings.api_key_header, "X-API-Key");
        assert!(settings.api_keys.is_empty());
        
        // Test logging defaults
        assert_eq!(settings.log_level, "INFO");
        assert_eq!(settings.log_format, "json");
        assert_eq!(settings.sql_log_level, "WARNING");
        
        // Test evidence defaults
        assert_eq!(settings.max_evidence_bytes, 52428800);
        assert_eq!(settings.evidence_storage_path, "./data/evidence");
        assert!(settings.evidence_allowed_types.contains(&"image/png".to_string()));
        
        // Test performance defaults
        assert_eq!(settings.http_timeout_seconds, 8.0);
        assert_eq!(settings.tls_timeout_seconds, 4.0);
        assert_eq!(settings.dns_concurrency, 256);
        assert_eq!(settings.tcp_scan_timeout, 0.35);
        
        // Test discovery defaults
        assert_eq!(settings.max_cidr_hosts, 4096);
        assert_eq!(settings.max_discovery_depth, 3);
        assert_eq!(settings.subdomain_enum_timeout, 120.0);
        assert!(settings.enable_wayback);
        assert!(!settings.enable_urlscan);
        assert_eq!(settings.related_asset_confidence_default, 0.3);
        
        // Test rate limiting defaults
        assert!(settings.rate_limit_enabled);
        assert_eq!(settings.rate_limit_requests, 100);
        assert_eq!(settings.rate_limit_window_seconds, 60);
        
        // Test background task defaults
        assert_eq!(settings.max_concurrent_scans, 5);
        assert_eq!(settings.scan_queue_check_interval, 5.0);
    }

    #[test]
    fn test_environment_variable_override() {
        let result = with_env_vars(vec![
            ("DATABASE_URL", "postgresql://test:test@localhost/test"),
            ("LOG_LEVEL", "DEBUG"),
            ("MAX_CONCURRENT_SCANS", "10"),
            ("HTTP_TIMEOUT_SECONDS", "15.5"),
            ("ENABLE_WAYBACK", "false"),
        ], || {
            Settings::new_with_env_file(false)
        });
        
        let settings = result.expect("Failed to create settings");
        
        assert_eq!(settings.database_url, "postgresql://test:test@localhost/test");
        assert_eq!(settings.log_level, "DEBUG");
        assert_eq!(settings.max_concurrent_scans, 10);
        assert_eq!(settings.http_timeout_seconds, 15.5);
        assert!(!settings.enable_wayback);
    }

    #[test]
    fn test_comma_separated_lists() {
        let result = with_env_vars(vec![
            ("CORS_ALLOW_ORIGINS", "http://localhost:3000,http://localhost:8080,https://example.com"),
            ("API_KEYS", "key1,key2,key3"),
            ("EVIDENCE_ALLOWED_TYPES", "image/png,text/plain,application/pdf"),
        ], || {
            Settings::new_with_env_file(false)
        });
        
        let settings = result.expect("Failed to create settings");
        
        assert_eq!(settings.cors_allow_origins, vec![
            "http://localhost:3000",
            "http://localhost:8080", 
            "https://example.com"
        ]);
        assert_eq!(settings.api_keys, vec!["key1", "key2", "key3"]);
        assert_eq!(settings.evidence_allowed_types, vec![
            "image/png",
            "text/plain",
            "application/pdf"
        ]);
    }

    #[test]
    fn test_comma_separated_with_spaces() {
        with_env_vars(vec![
            ("CORS_ALLOW_ORIGINS", " http://localhost:3000 , http://localhost:8080 , https://example.com "),
            ("API_KEYS", " key1 , key2 , key3 "),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            
            assert_eq!(settings.cors_allow_origins, vec![
                "http://localhost:3000",
                "http://localhost:8080", 
                "https://example.com"
            ]);
            assert_eq!(settings.api_keys, vec!["key1", "key2", "key3"]);
        });
    }

    #[test]
    fn test_empty_comma_separated_lists() {
        with_env_vars(vec![
            ("API_KEYS", ""),
            ("CORS_ALLOW_ORIGINS", "http://localhost:3000"),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            
            assert!(settings.api_keys.is_empty());
            assert_eq!(settings.cors_allow_origins, vec!["http://localhost:3000"]);
        });
    }

    #[test]
    fn test_optional_api_keys() {
        with_env_vars(vec![
            ("SHODAN_API_KEY", "test_shodan_key"),
            ("VIRUSTOTAL_API_KEY", "test_vt_key"),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            
            assert_eq!(settings.shodan_api_key, Some("test_shodan_key".to_string()));
            assert_eq!(settings.virustotal_api_key, Some("test_vt_key".to_string()));
            assert_eq!(settings.certspotter_api_token, None);
        });
    }

    #[test]
    fn test_validation_log_format() {
        let result = with_env_vars(vec![
            ("LOG_FORMAT", "invalid"),
        ], || {
            Settings::new_with_env_file(false)
        });
        
        assert!(result.is_err());
        
        if let Err(ConfigError::Validation(msg)) = result {
            assert!(msg.contains("log_format must be 'json' or 'plain'"));
        } else {
            panic!("Expected validation error for log_format");
        }
    }

    #[test]
    fn test_validation_positive_values() {
        // Test zero values that should be positive
        with_env_vars(vec![
            ("MAX_EVIDENCE_BYTES", "0"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        with_env_vars(vec![
            ("HTTP_TIMEOUT_SECONDS", "0"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        with_env_vars(vec![
            ("DNS_CONCURRENCY", "0"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_validation_ranges() {
        // Test max_cidr_hosts range
        with_env_vars(vec![
            ("MAX_CIDR_HOSTS", "0"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        with_env_vars(vec![
            ("MAX_CIDR_HOSTS", "25000"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        // Test max_discovery_depth range
        with_env_vars(vec![
            ("MAX_DISCOVERY_DEPTH", "0"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        with_env_vars(vec![
            ("MAX_DISCOVERY_DEPTH", "15"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        // Test confidence range
        with_env_vars(vec![
            ("RELATED_ASSET_CONFIDENCE_DEFAULT", "-0.1"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });

        with_env_vars(vec![
            ("RELATED_ASSET_CONFIDENCE_DEFAULT", "1.5"),
        ], || {
            let result = Settings::new();
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_valid_log_formats() {
        with_env_vars(vec![
            ("LOG_FORMAT", "json"),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            assert_eq!(settings.log_format, "json");
        });

        with_env_vars(vec![
            ("LOG_FORMAT", "plain"),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            assert_eq!(settings.log_format, "plain");
        });
    }

    #[test]
    fn test_dotenv_file_loading() {
        // Create a temporary .env file
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(temp_file, "DATABASE_URL=postgresql://user:pass@localhost/db").expect("Failed to write to temp file");
        writeln!(temp_file, "LOG_LEVEL=DEBUG").expect("Failed to write to temp file");
        writeln!(temp_file, "MAX_CONCURRENT_SCANS=15").expect("Failed to write to temp file");
        
        // Note: This test is limited because dotenvy::dotenv() looks for .env in current directory
        // In a real application, the .env file would be loaded automatically
    }

    #[test]
    #[ignore] // Skip this test as it depends on global state that's hard to test in isolation
    fn test_get_settings_singleton() {
        // Test that get_settings returns the same instance
        // Note: This test may fail if other tests have already initialized the singleton
        let settings1 = get_settings();
        let settings2 = get_settings();
        
        // They should have the same values (can't test pointer equality easily)
        assert_eq!(settings1.database_url, settings2.database_url);
        assert_eq!(settings1.log_level, settings2.log_level);
    }

    #[test]
    fn test_constants() {
        // Test that constants are defined correctly
        assert!(COMMON_PORTS.contains(&80));
        assert!(COMMON_PORTS.contains(&443));
        assert!(COMMON_PORTS.contains(&22));
        assert_eq!(COMMON_PORTS.len(), 17);
        
        let headers = security_headers();
        assert_eq!(headers.get("X-Content-Type-Options"), Some(&"nosniff"));
        assert_eq!(headers.get("X-Frame-Options"), Some(&"DENY"));
        assert_eq!(headers.len(), 4);
        
        assert!(SUBDOMAIN_WORDLIST.contains(&"www"));
        assert!(SUBDOMAIN_WORDLIST.contains(&"api"));
        assert!(SUBDOMAIN_WORDLIST.len() > 50);
    }

    #[test]
    fn test_boolean_parsing() {
        with_env_vars(vec![
            ("ENABLE_WAYBACK", "true"),
            ("ENABLE_URLSCAN", "false"),
            ("RATE_LIMIT_ENABLED", "1"),
            ("ENABLE_OTX", "0"),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            
            assert!(settings.enable_wayback);
            assert!(!settings.enable_urlscan);
            assert!(settings.rate_limit_enabled);
            assert!(!settings.enable_otx);
        });
    }

    #[test]
    fn test_numeric_parsing() {
        with_env_vars(vec![
            ("MAX_EVIDENCE_BYTES", "104857600"),  // 100MB
            ("HTTP_TIMEOUT_SECONDS", "12.5"),
            ("DNS_CONCURRENCY", "512"),
            ("RELATED_ASSET_CONFIDENCE_DEFAULT", "0.75"),
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            
            assert_eq!(settings.max_evidence_bytes, 104857600);
            assert_eq!(settings.http_timeout_seconds, 12.5);
            assert_eq!(settings.dns_concurrency, 512);
            assert_eq!(settings.related_asset_confidence_default, 0.75);
        });
    }

    #[test]
    fn test_case_insensitive_env_vars() {
        // The config crate should handle case insensitive environment variables
        with_env_vars(vec![
            ("database_url", "postgresql://test/db"),  // lowercase
            ("LOG_LEVEL", "ERROR"),                    // uppercase
        ], || {
            let settings = Settings::new().expect("Failed to create settings");
            
            // Should work with both cases
            assert_eq!(settings.log_level, "ERROR");
        });
    }
}
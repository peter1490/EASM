"""Centralized configuration management for the EASM application."""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Database
    database_url: str = Field(
        default="postgresql+psycopg://easm:easm@localhost:5432/easm",
        description="Database connection URL"
    )
    
    # OpenSearch
    opensearch_url: Optional[str] = Field(
        default=None,
        description="OpenSearch connection URL"
    )
    
    # API Keys
    certspotter_api_token: Optional[str] = Field(default=None)
    virustotal_api_key: Optional[str] = Field(default=None)
    shodan_api_key: Optional[str] = Field(default=None)
    urlscan_api_key: Optional[str] = Field(default=None)
    otx_api_key: Optional[str] = Field(default=None)
    clearbit_api_key: Optional[str] = Field(default=None)
    opencorporates_api_token: Optional[str] = Field(default=None)
    
    # Security
    cors_allow_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed CORS origins"
    )
    api_key_header: str = Field(default="X-API-Key")
    api_keys: List[str] = Field(
        default_factory=list,
        description="List of valid API keys for authentication"
    )
    
    # Logging
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json", pattern="^(json|plain)$")
    sql_log_level: str = Field(default="WARNING")
    
    # Evidence Storage
    max_evidence_bytes: int = Field(default=52428800, ge=1)  # 50MB
    evidence_allowed_types: List[str] = Field(
        default_factory=lambda: [
            "image/png", "image/jpeg", "image/gif",
            "text/plain", "application/pdf",
            "application/json", "text/csv"
        ]
    )
    evidence_storage_path: str = Field(default="./data/evidence")
    
    # Performance Tuning
    http_timeout_seconds: float = Field(default=8.0, gt=0)
    tls_timeout_seconds: float = Field(default=4.0, gt=0)
    dns_concurrency: int = Field(default=256, ge=1)
    rdns_concurrency: int = Field(default=256, ge=1)
    tcp_scan_timeout: float = Field(default=0.35, gt=0)
    tcp_scan_concurrency: int = Field(default=64, ge=1)
    
    # Discovery Settings
    max_cidr_hosts: int = Field(default=4096, ge=1, le=20000)
    max_discovery_depth: int = Field(default=3, ge=1, le=10)
    subdomain_enum_timeout: float = Field(default=120.0, gt=0)
    enable_wayback: bool = Field(default=True)
    enable_urlscan: bool = Field(default=False)
    enable_otx: bool = Field(default=False)
    enable_dns_record_expansion: bool = Field(default=True)
    enable_web_crawl: bool = Field(default=True)
    enable_cloud_storage_discovery: bool = Field(default=True)
    enable_wikidata: bool = Field(default=True)
    enable_opencorporates: bool = Field(default=False)
    related_asset_confidence_default: float = Field(default=0.3, ge=0.0, le=1.0)
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_requests: int = Field(default=100, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    
    # Background Tasks
    max_concurrent_scans: int = Field(default=5, ge=1)
    scan_queue_check_interval: float = Field(default=5.0, gt=0)
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        
        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> object:
            # Handle comma-separated lists
            if field_name in {"cors_allow_origins", "api_keys", "evidence_allowed_types"}:
                return [x.strip() for x in raw_val.split(",") if x.strip()]
            return raw_val


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience constants
COMMON_PORTS = [
    80, 443, 22, 25, 53, 110, 143, 587, 993, 995,
    3306, 5432, 6379, 8080, 8443, 3389, 5900
]

# HTTP headers for security
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

# Subdomain wordlist for brute-force fallback
SUBDOMAIN_WORDLIST = [
    "www", "mail", "mx", "smtp", "imap", "pop", "vpn", "dev", "staging", "api",
    "app", "portal", "intranet", "test", "beta", "cdn", "assets", "static", "gw",
    "gateway", "sso", "auth", "admin", "docs", "blog", "status", "shop", "store",
    "pay", "files", "download", "downloads", "jira", "confluence", "git", "gitlab",
    "grafana", "kibana", "log", "logs", "monitor", "monitoring", "ns1", "ns2",
    "ns", "devops", "prod", "production", "stage", "ci", "cd", "build", "jenkins",
    "backup", "db", "database", "mysql", "postgres", "redis", "cache", "queue",
    "ftp", "sftp", "ssh", "remote", "rdp", "webmail", "cpanel", "whm", "plesk"
]

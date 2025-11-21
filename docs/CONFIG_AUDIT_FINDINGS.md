# Configuration Audit Findings & Required Fixes

## Executive Summary

Comprehensive audit of environment configuration variables (lines 38-61 in example.env) revealed **critical implementation gaps**. While all variables are properly loaded into configuration, **many are not actually used** by the services.

## Audit Results

### ✅ FULLY IMPLEMENTED (Working Correctly)

1. **Evidence Storage Variables** ✅
   - `MAX_EVIDENCE_BYTES` - ✅ Enforced in `evidence_handlers.rs:50` and `static_handlers.rs:51`
   - `EVIDENCE_ALLOWED_TYPES` - ✅ Validated in `evidence_handlers.rs:60`

2. **Discovery Limits** ✅
   - `MAX_CIDR_HOSTS` - ✅ Used in `scan_service.rs:338` and `discovery_service.rs:1669`
   - `MAX_DISCOVERY_DEPTH` - ✅ Used in `discovery_service.rs:223`
   - `SUBDOMAIN_ENUM_TIMEOUT` - ✅ Used in `scan_service.rs:250` and `discovery_service.rs:489`
   - `MAX_CONCURRENT_SCANS` - ✅ Used in TaskManager for scan queue management

---

### ⚠️ PARTIALLY IMPLEMENTED (Needs Fixes)

3. **Performance Tuning Variables** ⚠️
   - **Problem**: HTTP/DNS clients instantiated with hardcoded defaults, not from settings
   - **Location**: `lib.rs:71-72`
   ```rust
   let dns_resolver = Arc::new(DnsResolver::new().await?); // ❌ Uses defaults
   let http_analyzer = Arc::new(HttpAnalyzer::new()?);     // ❌ Uses defaults
   ```
   
   - **Impact**:
     - `HTTP_TIMEOUT_SECONDS` (default: 8.0) → **NOT USED** (hardcoded to 10s)
     - `TLS_TIMEOUT_SECONDS` (default: 4.0) → **NOT USED** (hardcoded to 5s)
     - `DNS_CONCURRENCY` (default: 256) → **NOT USED** (hardcoded to 50)
     - `RDNS_CONCURRENCY` (default: 256) → **NOT USED** (hardcoded to 50)
   
   - **Fix Required**: Modify instantiation to pass settings

---

### ❌ NOT IMPLEMENTED (No Code Exists)

4. **OSINT Integration Toggles** ❌
   
   The following feature flags are defined in config but **NEVER checked** before execution:
   
   - `ENABLE_WAYBACK` → **NO IMPLEMENTATION** (no Wayback Machine client exists)
   - `ENABLE_URLSCAN` → **NO IMPLEMENTATION** (no URLScan client exists)
   - `ENABLE_OTX` → **NO IMPLEMENTATION** (no AlienVault OTX client exists)
   - `ENABLE_WIKIDATA` → **NO IMPLEMENTATION** (no Wikidata client exists)
   - `ENABLE_OPENCORPORATES` → **NO IMPLEMENTATION** (no OpenCorporates client exists)
   - `ENABLE_DNS_RECORD_EXPANSION` → **NOT CHECKED** (DNS records always expanded)
   - `ENABLE_WEB_CRAWL` → **NO IMPLEMENTATION** (no web crawler exists)
   - `ENABLE_CLOUD_STORAGE_DISCOVERY` → **NO IMPLEMENTATION** (no S3/bucket scanner exists)

   **Evidence**: 
   - Config defines these in `config.rs:84-91`
   - Only mentioned in `confidence.rs` for source weights
   - Zero usage found with: `grep -r "settings\.enable_" backend/src/services` → **NO MATCHES**

---

## Currently Working OSINT Sources

Based on `external/manager.rs`, only these are implemented:

✅ **Certificate Transparency (crt.sh)** - Always available (free)
✅ **Shodan** - If `SHODAN_API_KEY` is set
✅ **VirusTotal** - If `VIRUSTOTAL_API_KEY` is set  
✅ **CertSpotter** - If `CERTSPOTTER_API_TOKEN` is set

---

## Required Fixes

### Priority 1: HIGH (Performance Impact)

#### Fix 1: HTTP/DNS Configuration from Settings

**File**: `backend/src/lib.rs`

**Current (Lines 71-72)**:
```rust
let dns_resolver = Arc::new(DnsResolver::new().await?);
let http_analyzer = Arc::new(HttpAnalyzer::new()?);
```

**Required Change**:
```rust
// Create DNS resolver with settings
use crate::services::external::{DnsConfig, HttpConfig};
use std::time::Duration;

let dns_config = DnsConfig {
    query_timeout: Duration::from_secs(5),
    max_concurrent: config_arc.dns_concurrency as usize,
    rate_limit: config_arc.dns_concurrency,
};

let http_config = HttpConfig {
    request_timeout: Duration::from_secs_f64(config_arc.http_timeout_seconds),
    tls_timeout: Duration::from_secs_f64(config_arc.tls_timeout_seconds),
    max_redirects: 5,
    max_concurrent: 20,
    rate_limit: 50,
    user_agent: "EASM-Scanner/1.0".to_string(),
};

let dns_resolver = Arc::new(DnsResolver::with_config(dns_config).await?);
let http_analyzer = Arc::new(HttpAnalyzer::with_config(http_config)?);
```

**Files to modify**:
- `backend/src/lib.rs` - Update instantiation
- `backend/src/services/external/dns.rs` - Already has `with_config()` method ✅
- `backend/src/services/external/http.rs` - Already has `with_config()` method ✅

---

### Priority 2: MEDIUM (Feature Completeness)

#### Fix 2: Implement Missing OSINT Integrations

**Options**:
1. **Remove from config** if not planning to implement
2. **Implement the clients** for each service
3. **Add TODO comments** noting they're planned features

**Recommendation**: Since these are listed as "optional OSINT pivots", either:
- Remove them from `example.env` (misleading to users)
- OR add a note: `# Note: These integrations are planned but not yet implemented`

---

### Priority 3: LOW (Code Quality)

#### Fix 3: Document Frontend Discovery Source Display

**Current Status**: ✅ Frontend properly displays sources
- Location: `frontend/src/components/AssetDetailModal.tsx:125-156`
- Shows: `asset.sources` array as badges
- Works correctly with currently implemented sources

---

## Configuration Status Summary

| Variable | Loaded | Used | Working | Notes |
|----------|--------|------|---------|-------|
| `HTTP_TIMEOUT_SECONDS` | ✅ | ❌ | ❌ | Hardcoded to 10s |
| `TLS_TIMEOUT_SECONDS` | ✅ | ❌ | ❌ | Hardcoded to 5s |
| `DNS_CONCURRENCY` | ✅ | ❌ | ❌ | Hardcoded to 50 |
| `RDNS_CONCURRENCY` | ✅ | ❌ | ❌ | Hardcoded to 50 |
| `MAX_CONCURRENT_SCANS` | ✅ | ✅ | ✅ | Used in TaskManager |
| `MAX_EVIDENCE_BYTES` | ✅ | ✅ | ✅ | Enforced in handlers |
| `EVIDENCE_ALLOWED_TYPES` | ✅ | ✅ | ✅ | Validated in handlers |
| `MAX_CIDR_HOSTS` | ✅ | ✅ | ✅ | Used in scan/discovery |
| `MAX_DISCOVERY_DEPTH` | ✅ | ✅ | ✅ | Enforced in recursion |
| `SUBDOMAIN_ENUM_TIMEOUT` | ✅ | ✅ | ✅ | Used in enumeration |
| `ENABLE_WAYBACK` | ✅ | ❌ | ❌ | No implementation |
| `ENABLE_URLSCAN` | ✅ | ❌ | ❌ | No implementation |
| `ENABLE_OTX` | ✅ | ❌ | ❌ | No implementation |
| `ENABLE_DNS_RECORD_EXPANSION` | ✅ | ❌ | ⚠️ | Always enabled |
| `ENABLE_WEB_CRAWL` | ✅ | ❌ | ❌ | No implementation |
| `ENABLE_CLOUD_STORAGE_DISCOVERY` | ✅ | ❌ | ❌ | No implementation |
| `ENABLE_WIKIDATA` | ✅ | ❌ | ❌ | No implementation |
| `ENABLE_OPENCORPORATES` | ✅ | ❌ | ❌ | No implementation |

---

## Testing Recommendations

After implementing fixes:

1. **Performance Testing**
   - Test with different `HTTP_TIMEOUT_SECONDS` values (1s, 5s, 10s)
   - Verify `DNS_CONCURRENCY` impacts DNS resolution speed
   - Monitor resource usage with high concurrency values

2. **Evidence Storage Testing**
   - Upload files exceeding `MAX_EVIDENCE_BYTES`
   - Try uploading disallowed MIME types
   - Verify rejection messages are clear

3. **Discovery Limits Testing**
   - Test `MAX_DISCOVERY_DEPTH` stops recursion
   - Test `MAX_CIDR_HOSTS` limits CIDR expansion
   - Verify `SUBDOMAIN_ENUM_TIMEOUT` terminates long operations

---

## Audit Date
**Date**: November 21, 2025
**Auditor**: AI Assistant
**Scope**: Environment variables lines 38-61 in example.env
**Methodology**: Code search, grep analysis, implementation verification


# Discovery Flow Architecture

## Complete Asset Discovery Process

This document provides a comprehensive overview of the EASM discovery system architecture, showing how different seed types are processed and how Shodan's comprehensive extraction maximizes asset discovery.

---

## 📋 Table of Contents

1. [High-Level Overview](#high-level-overview)
2. [Entry Point Flow](#entry-point-flow)
3. [Seed Processing Flow](#seed-processing-flow)
4. [Shodan Comprehensive Extraction](#shodan-comprehensive-extraction)
5. [Recursive Discovery](#recursive-discovery)
6. [Data Flow Diagram](#data-flow-diagram)

---

## 🎯 High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     EASM Discovery System                        │
│                                                                  │
│  User Seeds → Discovery Engine → Asset Extraction → Database    │
│                                                                  │
│  Supports: Domains, Organizations, ASNs, CIDRs, Keywords        │
│  Sources: Shodan, VirusTotal, crt.sh, CertSpotter, DNS          │
│  Assets: IPs, Domains, Certificates, All stored with metadata   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Entry Point Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│                     API Request: POST /discovery/run                  │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  DiscoveryService::    │
                    │   run_discovery()      │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │   TaskManager          │
                    │   Submit Task          │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │ run_discovery_with_    │
                    │    context()           │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │ run_discovery_         │
                    │    internal()          │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │  Fetch all seeds       │
                    │  from database         │
                    └────────┬───────────────┘
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │  Spawn concurrent tasks for each seed  │
        │  (controlled by max_concurrent_scans)  │
        └────────────┬───────────────────────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │   For each seed:       │
        │   process_seed(seed)   │◄──── You are here
        └────────────────────────┘
```

---

## 🔄 Seed Processing Flow

### Main Process Seed Function

```
┌─────────────────────────────────────────────────────────────┐
│                    process_seed(seed)                        │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
           ┌────────────────────────┐
           │  Match seed.seed_type  │
           └────────┬───────────────┘
                    │
        ┌───────────┼───────────┬──────────┬───────────┐
        │           │           │          │           │
        ▼           ▼           ▼          ▼           ▼
    ┌──────┐   ┌──────┐    ┌──────┐   ┌──────┐   ┌──────┐
    │Domain│   │Org   │    │ ASN  │   │CIDR  │   │Keyword│
    └──┬───┘   └──┬───┘    └──┬───┘   └──┬───┘   └──┬────┘
       │          │           │          │          │
       ▼          ▼           ▼          ▼          ▼
```

### 1️⃣ Domain Seed Processing

```
discover_from_domain_recursive(domain)
    │
    ├──► Queue: [root_domain]
    │
    └──► LOOP while domains in queue:
            │
            ▼
         ┌─────────────────────────────────────────────┐
         │  discover_from_domain(domain)                │
         │                                              │
         │  STEP 1: Shodan Comprehensive Extraction    │
         │  ┌────────────────────────────────────┐     │
         │  │ search_domain_comprehensive()       │     │
         │  │                                     │     │
         │  │ Extracts from Shodan:              │     │
         │  │  ✓ IPs         → Create IP assets  │     │
         │  │  ✓ Domains     → Added to subdomains│    │
         │  │  ✓ ASNs        → Log for recursion │     │
         │  │  ✓ Organizations → Log for recursion│    │
         │  │  ✓ Certificates → Create cert assets│    │
         │  └────────────────────────────────────┘     │
         │                                              │
         │  STEP 2: Multi-Source Subdomain Enum        │
         │  ┌────────────────────────────────────┐     │
         │  │ enumerate_subdomains()              │     │
         │  │  → Shodan (PRIMARY)                 │     │
         │  │  → VirusTotal (if configured)       │     │
         │  │  → crt.sh (ALWAYS)                  │     │
         │  │  → CertSpotter (if configured)      │     │
         │  │                                     │     │
         │  │ Result: canonical dedup hostnames   │     │
         │  │ with per-host source attribution    │     │
         │  └────────────────────────────────────┘     │
         │                                              │
         │  STEP 3: DNS Resolution                     │
         │  ┌────────────────────────────────────┐     │
         │  │ For each discovered domain:         │     │
         │  │  → Resolve to IPs                   │     │
         │  │  → Create IP assets                 │     │
         │  └────────────────────────────────────┘     │
         │                                              │
         │  STEP 4: Certificate Analysis               │
         │  ┌────────────────────────────────────┐     │
         │  │ For each domain:                    │     │
         │  │  → Probe HTTPS (port 443)           │     │
         │  │  → Extract TLS certificates         │     │
         │  │  → Create certificate assets        │     │
         │  │  → Extract organizations from certs │     │
         │  └────────────────────────────────────┘     │
         │                                              │
         │  STEP 5: Store Assets to Database           │
         │  ┌────────────────────────────────────┐     │
         │  │ asset_repo.create_or_merge()        │     │
         │  └────────────────────────────────────┘     │
         └─────────────────────────────────────────────┘
            │
            ▼
         ┌─────────────────────────────────────────────┐
         │  Extract Organizations from Certificates     │
         │  → Add to organization queue                │
         └─────────────────────────────────────────────┘
            │
            ▼
         ┌─────────────────────────────────────────────┐
         │  Process Organization Queue                  │
         │  → discover_from_organization(org)           │
         │  → Extract top-level domains                │
         │  → Add new domains to domain queue           │
         └─────────────────────────────────────────────┘
            │
            └──► LOOP until all queues empty
```

### 2️⃣ Organization Seed Processing

```
discover_from_organization_recursive(org)
    │
    ├──► Queue: [root_org]
    │
    └──► LOOP while orgs/domains in queue:
            │
            ▼
         ┌─────────────────────────────────────────────────┐
         │  discover_from_organization(org)                 │
         │                                                  │
         │  STEP 1: Shodan Comprehensive Search            │
         │  ┌────────────────────────────────────────┐     │
         │  │ search_org_comprehensive(org)           │     │
         │  │                                         │     │
         │  │ Extracts from Shodan:                  │     │
         │  │  ✓ IPs → Create IP assets              │     │
         │  │  ✓ Domains → Create domain assets      │     │
         │  │  ✓ ASNs → Log for recursion            │     │
         │  │  ✓ Related Orgs → Log for recursion    │     │
         │  │  ✓ Certificates → Create cert assets   │     │
         │  │     - Extract org from certs           │     │
         │  │     - Extract SAN domains from certs   │     │
         │  └────────────────────────────────────────┘     │
         │                                                  │
         │  STEP 2: Certificate Transparency (crt.sh)      │
         │  ┌────────────────────────────────────────┐     │
         │  │ search_crtsh_by_organization(org)       │     │
         │  │  → Search CT logs for org               │     │
         │  │  → Create domain assets                 │     │
         │  └────────────────────────────────────────┘     │
         │                                                  │
         │  STEP 3: Store Assets                           │
         └─────────────────────────────────────────────────┘
            │
            ▼
         ┌─────────────────────────────────────────────────┐
         │  Extract Top-Level Domains                       │
         │  → Add to domain queue for deep enumeration     │
         └─────────────────────────────────────────────────┘
            │
            ▼
         ┌─────────────────────────────────────────────────┐
         │  Process Domain Queue                            │
         │  → discover_from_domain(domain)                  │
         │  → May discover more organizations              │
         └─────────────────────────────────────────────────┘
            │
            └──► LOOP until all queues empty
```

### 3️⃣ ASN Seed Processing

```
discover_from_asn(asn)
    │
    ▼
┌─────────────────────────────────────────────────┐
│  search_asn_comprehensive(asn)                   │
│                                                  │
│  Shodan Query: "asn:AS12345"                    │
│                                                  │
│  Extracts:                                       │
│  ┌────────────────────────────────────────┐     │
│  │  ✓ IPs (High confidence: 0.8)          │     │
│  │    → All IPs in this ASN                │     │
│  │                                         │     │
│  │  ✓ Domains (Good confidence: 0.7)      │     │
│  │    → Hostnames reverse-resolved         │     │
│  │                                         │     │
│  │  ✓ Organizations                        │     │
│  │    → Log for recursive discovery        │     │
│  │                                         │     │
│  │  ✓ Certificates (Good confidence: 0.7) │     │
│  │    → SSL/TLS certs on ASN hosts         │     │
│  │    → Extract org and domains from certs │     │
│  └────────────────────────────────────────┘     │
│                                                  │
│  Create Assets:                                  │
│   → IP assets with ASN metadata                 │
│   → Domain assets with ASN context              │
│   → Certificate assets with full details        │
└─────────────────────────────────────────────────┘
```

### 4️⃣ CIDR Seed Processing

```
discover_from_cidr(cidr)
    │
    ▼
┌─────────────────────────────────────────────────┐
│  CIDR Expansion (Local)                          │
│                                                  │
│  Input: 192.168.1.0/24                          │
│  ┌────────────────────────────────────────┐     │
│  │  Expand to individual IPs:             │     │
│  │   192.168.1.1                          │     │
│  │   192.168.1.2                          │     │
│  │   ...                                  │     │
│  │   192.168.1.254                        │     │
│  │                                         │     │
│  │  Limit: max_cidr_hosts setting         │     │
│  └────────────────────────────────────────┘     │
│                                                  │
│  Create Assets:                                  │
│   → IP asset for each address                   │
│   → High confidence (0.8)                       │
│   → Metadata includes CIDR source               │
└─────────────────────────────────────────────────┘
```

### 5️⃣ Keyword Seed Processing

```
discover_from_keyword(keyword)
    │
    ▼
┌─────────────────────────────────────────────────┐
│  search_comprehensive(keyword)                   │
│                                                  │
│  Shodan Query: "keyword_string"                 │
│                                                  │
│  Extracts ALL matching results:                 │
│  ┌────────────────────────────────────────┐     │
│  │  ✓ IPs (Medium confidence: 0.5)        │     │
│  │    → Hosts mentioning keyword           │     │
│  │                                         │     │
│  │  ✓ Domains (Medium confidence: 0.5)    │     │
│  │    → Hostnames on matching hosts        │     │
│  │                                         │     │
│  │  ✓ ASNs                                 │     │
│  │    → Log for potential recursion        │     │
│  │                                         │     │
│  │  ✓ Organizations                        │     │
│  │    → Log for potential recursion        │     │
│  │                                         │     │
│  │  ✓ Certificates (Medium conf: 0.5)     │     │
│  │    → Certs on matching hosts            │     │
│  └────────────────────────────────────────┘     │
│                                                  │
│  Note: Lower confidence due to keyword match    │
│  being less specific than other methods         │
└─────────────────────────────────────────────────┘
```

---

## 🔍 Shodan Comprehensive Extraction

### The Heart of Asset Discovery

```
┌───────────────────────────────────────────────────────────────────┐
│              Shodan Comprehensive Extraction Engine               │
│                                                                   │
│  Input: Shodan Search Query (domain/org/asn/keyword)             │
└─────────────────────────────┬─────────────────────────────────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │  Shodan API Search      │
                │  Returns: [ShodanResult]│
                └────────┬────────────────┘
                         │
                         ▼
        ┌────────────────────────────────────────┐
        │  extract_assets_from_results()         │
        │                                        │
        │  For each ShodanResult:                │
        └────────┬───────────────────────────────┘
                 │
      ┌──────────┼──────────┬──────────┬──────────┬──────────┐
      │          │          │          │          │          │
      ▼          ▼          ▼          ▼          ▼          ▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│   IPs    │ │ Domains  │ │  ASNs    │ │   Orgs   │ │  Certs   │
└────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │            │            │            │
     ▼            ▼            ▼            ▼            ▼

┌─────────────────────────────────────────────────────────────────┐
│                        IP EXTRACTION                             │
│  Source: result.ip_str                                           │
│  Action: Add to HashSet<String>                                  │
│  Example: "192.168.1.100"                                        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      DOMAIN EXTRACTION                           │
│  Sources:                                                        │
│   1. result.hostnames (Vec<String>)                              │
│   2. result.domains (Vec<String>)                                │
│                                                                  │
│  Action: Deduplicate and add to HashSet<String>                 │
│  Examples: "api.example.com", "www.example.com"                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       ASN EXTRACTION                             │
│  Source: result.asn                                              │
│  Normalization: Ensure "AS" prefix                               │
│  Action: Add to HashSet<String>                                  │
│  Example: "AS12345" (even if input was "12345")                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  ORGANIZATION EXTRACTION                         │
│  Source: result.org                                              │
│  Filter: Length > 2 characters                                   │
│  Action: Add to HashSet<String>                                  │
│  Example: "Example Corporation"                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   CERTIFICATE EXTRACTION                         │
│  Trigger: Port 443 OR data contains "ssl"/"tls"                  │
│                                                                  │
│  Parse from result.data:                                         │
│   ┌────────────────────────────────────────────┐                │
│   │  → Subject: Certificate DN                 │                │
│   │  → Issuer: CA information                  │                │
│   │  → Organization: Extracted from Subject    │                │
│   │  → SAN Domains: From hostnames             │                │
│   └────────────────────────────────────────────┘                │
│                                                                  │
│  Create: ShodanCertificateInfo struct                            │
│  Example:                                                        │
│    subject: "CN=*.example.com, O=Example Corp"                  │
│    organization: "Example Corp"                                 │
│    domains: ["example.com", "www.example.com"]                  │
└─────────────────────────────────────────────────────────────────┘

                              │
                              ▼
        ┌─────────────────────────────────────┐
        │  Return: ShodanExtractedAssets      │
        │  {                                  │
        │    ips: HashSet<String>,            │
        │    domains: HashSet<String>,        │
        │    asns: HashSet<String>,           │
        │    organizations: HashSet<String>,  │
        │    certificates: Vec<CertInfo>      │
        │  }                                  │
        └─────────────────────────────────────┘
```

---

## 🔄 Recursive Discovery

### Organization Pivoting Flow

```
┌──────────────────────────────────────────────────────────────┐
│         Recursive Discovery: Domain → Org → Domain           │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
            ┌────────────────────────┐
            │  Start: Root Domain    │
            │  (e.g., example.com)   │
            └────────┬───────────────┘
                     │
                     ▼
         ┌───────────────────────────┐
         │  Discover from Domain     │
         │  - Enumerate subdomains   │
         │  - Extract certificates   │
         └────────┬──────────────────┘
                  │
                  ▼
         ┌───────────────────────────┐
         │  Extract Organizations    │
         │  from Certificates        │
         │  (e.g., "Example Corp")   │
         └────────┬──────────────────┘
                  │
                  ▼
         ┌───────────────────────────┐
         │  Organization Queue       │
         │  - "Example Corp"         │
         │  - "Example Inc"          │
         └────────┬──────────────────┘
                  │
                  ▼
         ┌───────────────────────────┐
         │  Discover from Org        │
         │  - Shodan comprehensive   │
         │  - crt.sh CT logs         │
         └────────┬──────────────────┘
                  │
                  ▼
         ┌───────────────────────────┐
         │  Extract New Domains      │
         │  (e.g., api.example.org)  │
         └────────┬──────────────────┘
                  │
                  ▼
         ┌───────────────────────────┐
         │  Extract Top-Level Domain │
         │  (e.g., example.org)      │
         └────────┬──────────────────┘
                  │
                  ▼
         ┌───────────────────────────┐
         │  Add to Domain Queue      │
         │  (if not visited)         │
         └────────┬──────────────────┘
                  │
                  └──────► LOOP ◄──────┘


    Visited Tracking:
    ┌──────────────────────────────────┐
    │  visited_domains: HashSet         │
    │  visited_orgs: HashSet            │
    │                                   │
    │  Prevents infinite loops          │
    │  Ensures each asset processed 1x  │
    └──────────────────────────────────┘
```

---

## 📊 Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          EASM DISCOVERY SYSTEM                           │
│                        Complete Data Flow                                │
└─────────────────────────────────────────────────────────────────────────┘

                           ┌────────────┐
                           │   Seeds    │
                           │ (Database) │
                           └──────┬─────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │  Discovery Scheduler   │
                     │  - Concurrent tasks    │
                     │  - Rate limiting       │
                     │  - Progress tracking   │
                     └──────────┬─────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │  Seed Task 1 │ │  Seed Task 2 │ │  Seed Task N │
        └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
               │                │                │
               └────────────────┼────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   process_seed()      │
                    └───────────┬───────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
     ┌─────────────────┐ ┌──────────────┐ ┌──────────────┐
     │  Domain Seeds   │ │   Org Seeds  │ │  ASN Seeds   │
     └────────┬────────┘ └──────┬───────┘ └──────┬───────┘
              │                 │                │
              │                 │                │
              └─────────────────┼────────────────┘
                                │
                                ▼
           ┌────────────────────────────────────────┐
           │    External Services Manager           │
           └─────────────┬──────────────────────────┘
                         │
        ┌────────────────┼────────────────┬─────────────────┐
        │                │                │                 │
        ▼                ▼                ▼                 ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   Shodan     │ │ VirusTotal   │ │   crt.sh     │ │ CertSpotter  │
│  (PRIORITY1) │ │ (PRIORITY2)  │ │ (PRIORITY3)  │ │ (PRIORITY4)  │
│              │ │              │ │              │ │              │
│ Comprehensive│ │ CT Logs      │ │ CT Logs      │ │ Passive DNS  │
│ Extraction:  │ │ Search       │ │ Search       │ │ Subdomains   │
│ - IPs        │ │              │ │              │ │              │
│ - Domains    │ │              │ │              │ │              │
│ - ASNs       │ │              │ │              │ │              │
│ - Orgs       │ │              │ │              │ │              │
│ - Certs      │ │              │ │              │ │              │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │                │
       └────────────────┼────────────────┼────────────────┘
                        │                │
                        ▼                ▼
              ┌──────────────┐  ┌──────────────┐
              │ DNS Resolver │  │ HTTP Analyzer│
              │              │  │              │
              │ - A records  │  │ - HTTPS probe│
              │ - AAAA       │  │ - TLS certs  │
              │ - PTR        │  │ - Headers    │
              └──────┬───────┘  └──────┬───────┘
                     │                 │
                     └────────┬────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  Asset Aggregation  │
                    │  - Deduplication    │
                    │  - Confidence calc  │
                    │  - Metadata merge   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Asset Repository   │
                    │  create_or_merge()  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  PostgreSQL         │
                    │  - Assets table     │
                    │  - Metadata JSONB   │
                    │  - Confidence score │
                    │  - Source tracking  │
                    └─────────────────────┘


  Legend:
  ━━━━━ Primary data flow
  ┄┄┄┄┄ Optional/conditional flow
  (PRIORITYn) - Strict source execution order
  best effort - continue when a source is unavailable/failed
  (if config) - Only if API key configured
```

---

## 🎯 Asset Type Processing Matrix

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     Asset Types by Discovery Method                       │
├──────────────┬───────────┬────────────┬──────────┬──────────┬───────────┤
│ Seed Type    │    IPs    │  Domains   │   ASNs   │   Orgs   │   Certs   │
├──────────────┼───────────┼────────────┼──────────┼──────────┼───────────┤
│ Domain       │ ✓ Direct  │ ✓ Primary  │ ✓ Logged │ ✓ Logged │ ✓ Direct  │
│              │ (Shodan)  │ (Multi-src)│ (Recurse)│ (Recurse)│ (Shodan+  │
│              │ + DNS     │            │          │          │  HTTPS)   │
├──────────────┼───────────┼────────────┼──────────┼──────────┼───────────┤
│ Organization │ ✓ Primary │ ✓ Direct   │ ✓ Logged │ ✓ Logged │ ✓ Direct  │
│              │ (Shodan)  │ (Shodan+   │ (Recurse)│ (Related)│ (Shodan)  │
│              │           │  crt.sh)   │          │          │           │
├──────────────┼───────────┼────────────┼──────────┼──────────┼───────────┤
│ ASN          │ ✓ Primary │ ✓ Direct   │ ✓ Source │ ✓ Logged │ ✓ Direct  │
│              │ (Shodan)  │ (Shodan)   │ (Input)  │ (Recurse)│ (Shodan)  │
├──────────────┼───────────┼────────────┼──────────┼──────────┼───────────┤
│ CIDR         │ ✓ Primary │ ✗ No       │ ✗ No     │ ✗ No     │ ✗ No      │
│              │ (Expand)  │            │          │          │           │
├──────────────┼───────────┼────────────┼──────────┼──────────┼───────────┤
│ Keyword      │ ✓ Direct  │ ✓ Direct   │ ✓ Logged │ ✓ Logged │ ✓ Direct  │
│              │ (Shodan)  │ (Shodan)   │ (Noted)  │ (Noted)  │ (Shodan)  │
└──────────────┴───────────┴────────────┴──────────┴──────────┴───────────┘

✓ Direct  = Creates assets immediately
✓ Primary = Main asset type for this seed
✓ Logged  = Logged for recursive discovery
✓ Source  = The seed itself
✗ No      = Not extracted for this seed type
```

---

## 🔐 Confidence Scoring

```
┌─────────────────────────────────────────────────────────────────┐
│                    Asset Confidence Levels                       │
├──────────────────────────┬──────────────┬───────────────────────┤
│ Discovery Method         │ Confidence   │ Reasoning             │
├──────────────────────────┼──────────────┼───────────────────────┤
│ CIDR Expansion           │ 0.8 (High)   │ Direct ownership      │
│ DNS Resolution           │ 0.8 (High)   │ Active DNS record     │
│ Shodan IP (ASN)          │ 0.8 (High)   │ Confirmed ASN member  │
│ Shodan IP (Domain)       │ 0.8 (High)   │ Active host           │
├──────────────────────────┼──────────────┼───────────────────────┤
│ Certificate (with org)   │ 0.7 (Good)   │ Verified cert         │
│ Shodan Domain (ASN)      │ 0.7 (Good)   │ Confirmed hostname    │
│ Shodan Cert              │ 0.7 (Good)   │ Active certificate    │
│ Shodan IP (Org)          │ 0.7 (Good)   │ Org match             │
├──────────────────────────┼──────────────┼───────────────────────┤
│ Multi-source Domain      │ 0.6-0.9      │ Based on source count │
│ Shodan Domain (Org)      │ 0.6 (Medium) │ Org association       │
│ crt.sh Organization      │ 0.6 (Medium) │ CT log entry          │
├──────────────────────────┼──────────────┼───────────────────────┤
│ Keyword Search (any)     │ 0.5 (Medium) │ Fuzzy match           │
│ Keyword Search (cert)    │ 0.5 (Medium) │ Indirect association  │
├──────────────────────────┼──────────────┼───────────────────────┤
│ Certificate (no org)     │ 0.3 (Low)    │ Limited validation    │
└──────────────────────────┴──────────────┴───────────────────────┘

Multi-source Boost Algorithm:
  base_confidence = 0.5
  + (source_count - 1) * 0.1
  + 0.2 if direct subdomain
  + 0.1 if from crt.sh
  = Final confidence (max 1.0)
```

---

## 📈 Performance Characteristics

### Concurrent Processing

```
┌─────────────────────────────────────────────────────────────┐
│                    Concurrency Model                         │
└─────────────────────────────────────────────────────────────┘

  Configuration: max_concurrent_scans (default: 10)

  ┌────────────────────────────────────────────┐
  │  Semaphore (10 permits)                    │
  └────────────┬───────────────────────────────┘
               │
      ┌────────┼────────┬─────────┬─────────┐
      │        │        │         │         │
      ▼        ▼        ▼         ▼         ▼
   [Seed 1] [Seed 2] [Seed 3] ... [Seed 10]
      │        │        │         │         │
      │        │        │         │         │
   Running  Running  Running   Running   Running
      
      ▼
   [Seed 11] [Seed 12] ... (waiting for permit)
   Queued    Queued


  Per-Seed Processing:
    - Async/await for I/O
    - Rate limiting per API client
    - Timeout: 24 hours (configurable)
```

### Rate Limiting

```
┌─────────────────────────────────────────────────────────────┐
│                    API Rate Limits                           │
├──────────────────┬──────────────────────────────────────────┤
│ Service          │ Rate Limit                                │
├──────────────────┼──────────────────────────────────────────┤
│ Shodan (free)    │ 1 request/second (enforced in code)      │
│ Shodan (paid)    │ Higher (adjust RateLimitedClient)        │
├──────────────────┼──────────────────────────────────────────┤
│ crt.sh           │ Best effort (no official limit)           │
│ CertSpotter      │ API key dependent                        │
│ VirusTotal       │ 4 requests/minute (free)                 │
├──────────────────┼──────────────────────────────────────────┤
│ DNS Resolution   │ No enforced limit (use responsibly)      │
│ HTTPS Probes     │ Respects connection timeouts             │
└──────────────────┴──────────────────────────────────────────┘

  Implementation: RateLimitedClient with token bucket algorithm
```

---

## 🎛️ Configuration Options

```toml
# Discovery Settings
max_concurrent_scans = 10           # Parallel seed processing
subdomain_enum_timeout = 24.0       # Hours per seed (24 = 1 day)
max_cidr_hosts = 1024               # Max IPs from CIDR expansion

# Confidence Thresholds
related_asset_confidence_default = 0.5  # Base confidence for related assets

# API Keys (set in environment)
SHODAN_API_KEY = "your_key"         # Enable Shodan (REQUIRED for best results)
VIRUSTOTAL_API_KEY = "your_key"     # Optional: Additional subdomain source
CERTSPOTTER_API_TOKEN = "your_key"  # Optional: Additional CT log source
```

---

## 🚦 Status and Monitoring

### Discovery Status Object

```rust
pub struct DiscoveryStatus {
    pub is_running: bool,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub seeds_processed: usize,
    pub assets_discovered: usize,
    pub errors: Vec<String>,
}
```

### Progress Tracking

```
GET /api/discovery/status

{
  "is_running": true,
  "started_at": "2024-11-20T10:00:00Z",
  "completed_at": null,
  "seeds_processed": 5,
  "assets_discovered": 234,
  "errors": []
}
```

### Logging Levels

```
INFO  - Major steps, asset counts, source usage
DEBUG - Detailed extraction, intermediate results
WARN  - API failures, fallbacks triggered (best effort continues)
ERROR - Critical failures, task panics
```

---

## 🎓 Best Practices

### 1. Seed Selection
- **Start with Organization seeds** for broad discovery
- **Use Domain seeds** for deep enumeration of known assets
- **Add ASN seeds** if you know target network blocks
- **CIDR for precision** when you have specific IP ranges
- **Keywords sparingly** due to lower confidence

### 2. API Configuration
- **Always configure Shodan** - Primary source for comprehensive extraction
- **Add VirusTotal** for additional subdomain coverage
- **Consider CertSpotter** for real-time CT monitoring
- Canonical source names in storage are `shodan`, `virustotal`, `crtsh`, `certspotter`

### 3. Performance Tuning
- Adjust `max_concurrent_scans` based on API limits and memory
- Monitor rate limiting logs
- Use higher timeout for large organizations

### 4. Recursive Discovery
- System automatically pivots on organizations
- No manual intervention needed
- Visited tracking prevents loops

---

## 📚 Related Documentation

- [Shodan API Documentation](https://developer.shodan.io/)
- [Certificate Transparency Logs](https://certificate.transparency.dev/)
- [Task Manager Implementation](./TASK_MANAGER.md) _(if exists)_
- [Finding System](./FINDING_FILTER_IMPLEMENTATION.md)

---

**Last Updated:** 2024-11-20  
**Version:** 1.0  
**Maintained by:** EASM Development Team

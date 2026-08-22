# Discovery Flow Architecture

## Complete Asset Discovery Process

This document provides a comprehensive overview of the EASM discovery system architecture, showing how different seed types are processed and how Shodan's comprehensive extraction maximizes asset discovery.

---

## 📋 Table of Contents

1. [High-Level Overview](#high-level-overview)
2. [Entry Point Flow](#entry-point-flow)
3. [Seed Processing Flow](#seed-processing-flow)
4. [The Domain Pipeline](#the-domain-pipeline)
5. [Shodan Comprehensive Extraction](#shodan-comprehensive-extraction)
6. [Recursive Discovery](#recursive-discovery)
7. [Data Flow Diagram](#data-flow-diagram)
8. [Confidence Scoring](#confidence-scoring)
9. [Status and Monitoring](#status-and-monitoring)

---

## 🎯 High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     EASM Discovery System                        │
│                                                                  │
│  User Seeds → Discovery Engine → Asset Extraction → Database    │
│                                                                  │
│  Supports: Domains, Organizations, ASNs, CIDRs, Keywords        │
│  Layers:  Passive fan-out → Active DNS → Infra attribution      │
│  Sources: 19 passive corpora (8 key-free) + active DNS + BGP    │
│  Assets: IPs, Domains, Certificates, ASNs, with full lineage    │
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

## 🧭 The Domain Pipeline

A domain seed runs through seven stages, in this order. The order is load-bearing:
permutation needs known-good names to mutate, and wildcard detection has to
happen before any guessed name is believed.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. PASSIVE FAN-OUT                            services/external/        │
│                                               passive_sources.rs        │
│    19 corpora, queried CONCURRENTLY.                                     │
│    Cost = slowest source, not the sum.                                   │
│                                                                          │
│    No key:  crt.sh · OTX · HackerTarget · RapidDNS · AnubisDB           │
│             urlscan.io · Wayback · Columbus · Digitorus                  │
│    Keyed:   Shodan · VirusTotal · CertSpotter · SecurityTrails          │
│             Censys · Chaos · LeakIX · FullHunt · BinaryEdge · Netlas     │
│                                                                          │
│    Per source: queried | skipped (no key / disabled) | failed            │
│    None of the three aborts the run.                                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. ACTIVE DNS                                 services/external/         │
│                                               active_dns.rs              │
│    ┌──────────────────────────────────────────────────────────────┐     │
│    │ 0. WILDCARD DETECTION  ← gates everything below              │     │
│    │    Resolve 3 random labels per zone, at EVERY level.          │     │
│    │    Stable answer  → wildcard IP set recorded                  │     │
│    │    Varying answer → zone marked "rotating", nothing trusted   │     │
│    │    A host answering with the wildcard IP *plus one of its     │     │
│    │    own* is real and is KEPT.                                  │     │
│    └──────────────────────────────────────────────────────────────┘     │
│    a. NSEC zone walk   — free, complete, no guessing (RFC 4034 §4)      │
│                          reads the AUTHORITY section via dns_wire        │
│    b. SRV probe        — 61 _service._proto labels                       │
│    c. Brute force      — curated hit-rate-ordered wordlist               │
│    d. Permutation      — mutate everything found above                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. DNS RESOLUTION → 4. TLS CERTIFICATE (SAN pivot, org pivot)           │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│    For each resolved IP:  ASN ATTRIBUTION       services/external/asn.rs │
│                                                                          │
│    Team Cymru (DNS TXT)  → origin AS + BGP prefix                        │
│    RIPEstat  (HTTPS)     → every prefix that AS announces                │
│    Cloud/CDN AS?         → recorded, NOT expanded                        │
│    Otherwise             → reverse-DNS sweep the covering prefix,        │
│                            bounded per-prefix and once per run           │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. SAAS TENANCY   apex TXT verification tokens → vendor inventory        │
│                   + implied hostnames (autodiscover. / support. /        │
│                     status.), each resolved before it is kept            │
│ 6. CNAME CHAIN    every hop recorded — the takeover surface              │
│ 7. LATERAL PIVOTS favicon · JARM · analytics IDs · SPF · DMARC · MX      │
│                   Sibling infrastructure, NOT subdomains.                │
│                   Never recursed into; analyst triages in the UI.        │
└─────────────────────────────────────────────────────────────────────────┘
```

### What each layer reaches that the others cannot

| Layer | Finds | Misses |
| --- | --- | --- |
| Passive | anything already recorded by somebody | names never certificated, crawled or resolved |
| Active DNS | live names nobody indexed | names that do not resolve at all |
| Attribution | hosts with no forward DNS at all | address space announced by a shared provider |

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

Confidence answers one question: **how sure are we that this is a real asset
belonging to this company?** It is not a measure of how many sources replied.

### Why source counting broke

With four sources, `base + 0.1 per extra source` was defensible. With nineteen
it is not. crt.sh, CertSpotter, Censys and Digitorus all read the same
certificate transparency logs — four hits there is **one fact observed four
times**, not four independent facts. Under the old formula a single CT entry,
seen by four aggregators, reached the confidence cap on its own.

### Evidence classes

Every source is assigned an evidence class. Corroboration only counts *between*
classes.

```
┌────────────────────────────┬────────────────────────────────────────────────┐
│ Evidence class             │ Sources                                        │
├────────────────────────────┼────────────────────────────────────────────────┤
│ Declared                   │ seed, user_input                               │
│ CertificateTransparency    │ crt.sh, CertSpotter, Censys, Digitorus, live   │
│                            │ TLS certificate                                │
│ PassiveDns                 │ OTX, VirusTotal, SecurityTrails, HackerTarget, │
│                            │ RapidDNS, AnubisDB, Columbus, Chaos            │
│ InternetScan               │ Shodan, BinaryEdge, Netlas, FullHunt, LeakIX   │
│ WebArchive                 │ urlscan.io, Wayback Machine                    │
│ ActiveDns                  │ resolution, reverse DNS, brute force,          │
│                            │ permutation, NSEC walk, SRV, CNAME chain,      │
│                            │ TXT verification                               │
│ ActiveProbe                │ HTTP probe, port scan                          │
│ Registry                   │ CIDR expansion, ASN netblock, RDAP             │
│ SharedAttribute            │ favicon, JARM, analytics ID, SPF, DMARC, MX    │
└────────────────────────────┴────────────────────────────────────────────────┘
```

### The score

```
confidence = strongest_source_weight
           + 0.06 × (independent_evidence_classes − 1)
           capped at 0.95
```

Only a seed or an analyst reaches 1.0.

### Per-source weights

```
┌──────────────────────────────────────┬──────────────┬────────────────────────┐
│ Source                               │ Weight       │ What it proves         │
├──────────────────────────────────────┼──────────────┼────────────────────────┤
│ seed, user_input                     │ 1.00         │ The analyst said so    │
├──────────────────────────────────────┼──────────────┼────────────────────────┤
│ DNS resolution                       │ 0.90         │ It answers, now        │
│ NSEC walk                            │ 0.90         │ The zone listed it     │
│ DNS brute force, SRV, CNAME chain    │ 0.85         │ Confirmed by lookup    │
│ crt.sh, CertSpotter                  │ 0.85         │ A CA logged it         │
├──────────────────────────────────────┼──────────────┼────────────────────────┤
│ Censys, Digitorus, live certificate  │ 0.80         │ CT / live cert         │
│ Shodan, VirusTotal, SecurityTrails,  │ 0.75         │ A third party saw it   │
│ Chaos                                │              │                        │
│ BinaryEdge, Netlas, FullHunt, OTX,   │ 0.70         │ A third party saw it   │
│ LeakIX, HackerTarget, reverse DNS,   │              │                        │
│ permutation                          │              │                        │
│ RapidDNS, AnubisDB, Columbus,        │ 0.65         │ Aggregated report      │
│ urlscan.io                           │              │                        │
│ HTTP probe, port scan                │ 0.60         │ Something listened     │
│ Wayback Machine                      │ 0.55         │ It existed *once*      │
├──────────────────────────────────────┼──────────────┼────────────────────────┤
│ CIDR expansion, ASN netblock, RDAP   │ 0.50         │ Registry association   │
│ TXT verification                     │ 0.45         │ Tenancy, not hostname  │
│ favicon / JARM / analytics / SPF /   │ 0.30         │ A *shared attribute*,  │
│ DMARC / MX pivots                    │              │ ownership unproven     │
└──────────────────────────────────────┴──────────────┴────────────────────────┘
```

Lateral pivots start low on purpose: sharing a favicon, a JARM fingerprint or a
mail relay with a known asset is something unrelated SaaS tenants do constantly.
They are surfaced for analyst triage, never treated as owned.

### Worked examples

```
www.example.com  seen by crt.sh + CertSpotter + Censys + Digitorus
  → strongest 0.85, one class (CT)              → 0.85

www.example.com  seen by crt.sh + OTX
  → strongest 0.85, two classes (CT, passive)   → 0.91

old.example.com  seen only by the Wayback Machine
  → strongest 0.55, one class (archive)         → 0.55

dev-api.example.com  found by permutation, resolves
  → strongest 0.70, one class (active DNS)      → 0.70

unrelated.saas.com  matched only on favicon hash
  → strongest 0.30, one class (shared attr.)    → 0.30
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

See `example.env` for the full list with defaults. The settings that shape
discovery itself:

```bash
# Discovery
MAX_DISCOVERY_DEPTH=3                  # Recursion depth for subdomain branches
MAX_CIDR_HOSTS=4096                    # Max IPs from a CIDR seed
MAX_ASSETS_PER_DISCOVERY=5000          # Hard cap per run

# Passive fan-out — sources are queried concurrently, so enumeration costs the
# slowest source rather than the sum of all of them.
OSINT_SOURCE_CONCURRENCY=12
OSINT_SOURCE_TIMEOUT_SECONDS=25.0
OSINT_MAX_RESULTS_PER_SOURCE=5000

# Active DNS — wildcard detection runs first and gates all of it.
ENABLE_DNS_BRUTEFORCE=true
ENABLE_DNS_PERMUTATIONS=true
ENABLE_NSEC_WALK=true
ENABLE_SRV_PROBE=true
DNS_BRUTEFORCE_MAX_WORDS=2000
DNS_PERMUTATION_MAX_CANDIDATES=5000
DNS_PERMUTATION_MAX_SEEDS=50
ACTIVE_DNS_CONCURRENCY=50
# DNS_BRUTEFORCE_WORDLIST_PATH=/opt/wordlists/subdomains.txt

# Infrastructure attribution — Team Cymru and RIPEstat, neither needs a key.
ENABLE_ASN_DISCOVERY=true
ENABLE_RDAP_LOOKUP=true
ENABLE_SAAS_TENANT_DISCOVERY=true
ENABLE_CNAME_CHAIN_ANALYSIS=true
ASN_MAX_PREFIXES=64
REVERSE_DNS_SWEEP_MAX_HOSTS=256        # 0 disables the sweep
```

### API keys

Eight passive corpora need **no key at all**: crt.sh, AlienVault OTX,
HackerTarget, RapidDNS, AnubisDB, urlscan.io, the Wayback Machine, Columbus and
Digitorus. Discovery is useful with an empty configuration; a source whose key
is missing reports `skipped` and the run continues.

```bash
SHODAN_API_KEY=          VIRUSTOTAL_API_KEY=      CERTSPOTTER_API_TOKEN=
SECURITYTRAILS_API_KEY=  CENSYS_API_KEY=          CENSYS_ORG_ID=
CHAOS_API_KEY=           LEAKIX_API_KEY=          FULLHUNT_API_KEY=
BINARYEDGE_API_KEY=      NETLAS_API_KEY=
# Optional — these two sources answer anonymously, a key only raises the limit:
URLSCAN_API_KEY=         OTX_API_KEY=
```

---

## 🚦 Status and Monitoring

### Discovery Status Object

Held in memory, one per company, and only ever meaningful for the run happening
now. Anything worth keeping past the end of a run is written to the
`discovery_runs` row instead.

```rust
pub struct DiscoveryStatus {
    pub is_running: bool,
    pub run_id: Option<Uuid>,
    pub task_id: Option<Uuid>,          // not serialised
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub current_phase: String,
    pub seeds_total: usize,
    pub seeds_processed: usize,
    pub assets_discovered: usize,
    pub assets_updated: usize,
    pub queue_pending: usize,
    pub scans_queued: usize,
    pub errors: Vec<String>,
    pub auto_scan_threshold: f64,       // not serialised
}
```

### Progress Tracking

```
GET /api/discovery/status

{
  "running": true,
  "run_id": "3f7c...",
  "started_at": "2024-11-20T10:00:00Z",
  "completed_at": null,
  "current_phase": "Processing discovery queue",
  "seeds_total": 8,
  "seeds_processed": 5,
  "assets_discovered": 234,
  "assets_updated": 12,
  "queue_pending": 47,
  "scans_queued": 19,
  "errors": [],
  "error_count": 0
}
```

### Stopping a run

`POST /api/discovery/stop` takes down everything the run owns, not just the
discovery task:

| What | Why it needs stopping explicitly |
| --- | --- |
| The discovery task | Cancelled through the task manager. |
| Its auto-triggered scans | Each was submitted as its own task. `security_scans.discovery_run_id` is the link back to the run; scans still `pending` or `running` are marked `cancelled` and their tasks stopped. Manual and scheduled scans are untouched. |
| Its queue | Pending rows are deleted — nothing will dequeue that run again. |
| Its counters | Written to the `discovery_runs` row first (a stopped run would otherwise be filed as 0 seeds, 0 assets), then cleared, so the next run does not open showing the last one's numbers. |

Both `stop_discovery` and the run's own finaliser can reach this; each step is
idempotent, so whichever gets there second is a no-op.

Runs left `pending` or `running` by a process that died are reconciled at
start-up, along with their queue items and their scans.

### Exclusion enforcement

Two strengths, one table. An **exclusion** stops discovery *growing* the estate
at that object: nothing new is written for it or anything under it, but what was
already found stays, keeps its findings, keeps counting towards the risk score,
and is still auto-scanned by later runs. A **blacklist** — the `blacklisted`
column, off unless asked for — is the hard one: the assets it names are deleted
along with everything discovered through them, and never written again, so the
object reaches no score, no scan and no list.

The distinction is what each does to an asset that already exists. Neither lets
discovery find *more*.

The list is applied at three points, because a run in progress cannot be trusted
to notice a change on its own:

1. **On the way in.** Every asset discovery writes goes through one gate in
   `create_or_update_asset_with_sources`, so no discovery path — resolution,
   certificate SANs, reverse DNS, CIDR expansion, the Shodan pivots — can write
   an excluded asset. An ordinary exclusion hands the asset already in the
   inventory to the auto-scan threshold on its way past; a blacklisted one is
   left alone, because it should not exist. The list is read once per company
   and cached for ten seconds; adding, changing or removing an entry drops the
   cache immediately.
2. **On queueing.** Blacklisted seeds are never queued — the run has already
   decided not to do that work, and queueing them would report pending work
   against a progress bar that never moves. An excluded seed *is* queued: the
   run will not expand on it, but it will auto-scan the asset the seed names.
   Queue items are re-checked at dequeue.
3. **On change.** Adding an entry during a run skips the queued items it now
   covers — a domain entry reaches its subdomains, a CIDR entry reaches the
   addresses inside it. Scans in flight are cancelled only for a blacklist: an
   ordinary exclusion means "stop finding more of this", not "stop scanning
   what I have", and killing a scan halfway through an asset the operator is
   keeping would be the opposite of what they asked for.
   `POST /api/exclusions` and `POST /api/exclusions/from-asset/:id` report the
   counts as `assets_deleted`, `descendants_deleted`, `queue_items_removed` and
   `scans_cancelled`.

Blacklisting deletes the asset the entry *names* plus everything discovered
through it. A sibling that merely matches the rule — another subdomain reached
by some other path, never a descendant — is left where it is; the rule keeps
discovery from writing it again, so it goes when it is next matched rather than
being deleted out from under an operator who pointed at one asset.

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

**Last Updated:** 2026-08-22  
**Version:** 1.1  
**Maintained by:** EASM Development Team

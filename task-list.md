## Task list

### Backend data and persistence
- [ ] Introduce PostgreSQL
  - [x] Replace in‑memory `_SCANS`, `_FINDINGS`, `_SEEDS`, `_ASSETS` with DB models
  - [ ] Create database migrations
  - [x] Add CRUD repositories
  - [ ] Implement transactional boundaries

- [ ] Introduce OpenSearch
  - [x] Index `assets`, `findings`, and `evidence` for fast search
  - [x] Sync writes from PostgreSQL

- [ ] Evidence storage (local filesystem)
  - [x] Use local filesystem directory (e.g., `./data/evidence`)
  - [x] Serve artifacts via API (streaming) and static route
  - [x] Link `evidence` rows to `findings`

### Discovery and scanning
- [ ] Expand passive sources
  - [x] WHOIS
  - [ ] ASN discovery
  - [x] Additional CT log providers
  - [x] Reverse DNS at scale
  - [ ] Public repos/leak sources
  - [x] Subdomain brute force (basic built‑in list)
  - [x] Organization‑based discovery from TLS subjects and CT O= queries

- [ ] Active scanners
  - [ ] Integrate masscan
  - [ ] Integrate nmap
  - [ ] Service banner parsing
  - [ ] Protocol identification
  - [x] Basic async TCP scanner + HTTP probe + TLS summary

- [ ] HTTP fingerprinting
  - [ ] Wappalyzer‑style technology detection
  - [ ] Header and security header analysis
  - [ ] Cookie and CSP checks

- [ ] Screenshots
  - [ ] Headless Chrome capture (PNG)
  - [ ] Timeouts and throttles
  - [ ] Store to local filesystem and attach to findings

- [ ] Cloud connectors
  - [ ] Read‑only AWS resource enumeration
  - [ ] Read‑only GCP resource enumeration
  - [ ] Read‑only Azure resource enumeration
  - [ ] Map public endpoints to discovered assets

- [ ] DAST probes
  - [ ] OWASP ZAP integration for controlled checks
  - [ ] Rate limiting
  - [ ] Allow/deny list enforcement

- [ ] Scheduling and throttles
  - [ ] Configurable scan windows
  - [ ] Per‑tenant rate limits
  - [ ] Backoff and retry rules

### Risk scoring and correlation
- [ ] CVE/OSV mapping
  - [ ] Normalize software/version fingerprints to CVEs
  - [ ] Compute exploitability signals

- [ ] Explainable risk score
  - [x] Implement weighted components
  - [ ] Persist weights
  - [x] API returns component breakdown

- [ ] Threat intel ingestion
  - [ ] Normalize feeds
  - [ ] Tag assets/findings with active exploitation signals

### Worker layer and orchestration
- [ ] Queue
  - [ ] Introduce Kafka or RabbitMQ
  - [ ] Publish discovery/scan jobs

- [ ] Workers
  - [ ] Separate async worker service for discovery
  - [ ] Separate async worker service for scanning
  - [ ] Enrichment worker
  - [ ] Evidence capture worker

- [ ] Sandboxing
  - [ ] Isolated scanning VPC/subnets
  - [ ] Egress IP pools
  - [ ] Job‑scoped credentials

### API surface and integrations
- [ ] GraphQL endpoint for read models (dashboards/exports)
- [ ] Webhooks: findings lifecycle events with signed payloads
- [ ] Ticketing/chat connectors
  - [ ] Jira
  - [ ] ServiceNow
  - [ ] GitHub Issues
  - [ ] Slack/MS Teams with status sync
- [ ] SIEM/SOAR exports
  - [ ] Splunk/Elastic app or documented JSON schemas

### Auth, tenancy, and governance
- [ ] SSO/OIDC: login, refresh, logout flows
- [ ] RBAC: org → team → project scoping; roles and permissions
- [ ] Audit logging: persist admin and sensitive actions
- [ ] Multi‑tenancy: data partitioning and per‑tenant config
- [ ] Data retention: policies for findings/evidence; admin controls

### Observability and reliability
- [ ] Metrics and tracing
  - [ ] OpenTelemetry traces
  - [ ] Prometheus metrics (discovery rate, queues, worker failures)
- [ ] Centralized logs: structured logs shipped to ELK
- [x] Health/readiness endpoints per service
- [x] Structured JSON logging with request IDs

### Security, legal, and controls
- [ ] Allow/deny lists: enforce opt‑out and legal boundaries at job dispatch
- [ ] Rate limiting: per user/tenant/API and scanner actions
- [ ] Secrets management: Vault/KMS integration; remove plaintext credentials
- [ ] Encryption: mTLS between services; at‑rest encryption via KMS
- [ ] PII handling: redaction/hashing of sensitive artifacts

### Frontend/UI
- [ ] Executive dashboard: global risk, top exposures, trends
- [ ] Findings queue: prioritized triage with playbooks and status updates
- [ ] Investigation view: timelines, screenshots, headers, raw artifacts
- [ ] Settings: connectors, scan policies, rate limit profiles, notification preferences
- [ ] Reports: scheduled reports (CSV/PDF) and on‑demand export
- [ ] Risk score UI: component breakdown visualization
  
  - [x] Seeds management UI
  - [x] Assets list UI

### Testing and QA
- [ ] Unit tests
  - [ ] Scoring logic
  - [ ] Canonicalization
  - [ ] Parsers
- [ ] Integration tests
  - [ ] Connectors with VCR recordings
  - [ ] Scan pipeline with fixtures
- [ ] E2E tests: synthetic domains and end‑to‑end discovery/scan assertions
- [ ] Performance tests: high‑volume discovery/scanning; search latency SLOs
- [ ] Fuzzing: CT log and certificate parsing
  
  - [x] Basic API tests (health, scan flow)

### CI/CD and infrastructure
- [ ] CI pipeline: lint, typecheck, tests, build, image scan, SBOM, dependency audit
- [ ] Deployments: Helm charts; canary/blue‑green for workers and API
- [ ] Terraform: VPCs, NAT, EKS/GKE/AKS, S3, RDS, OpenSearch, Redis/Queue
- [ ] Cost monitoring: budgets/alerts for S3, egress, CPU

### Documentation and policy
- [ ] API docs: OpenAPI/GraphQL schemas; SDK examples
- [ ] Scanning policy: terms, consent processes, abuse handling
- [ ] Runbooks: on‑call, incident response, connector troubleshooting
- [ ] User guides: setup, connectors, dashboards, remediation workflows

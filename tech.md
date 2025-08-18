## External Attack Surface Management (EASM) — Technical Plan

### 1. High-level goal
Build a cloud-native, scalable EASM platform that continuously discovers, inventories, fingerprints, and scores an organization’s externally visible assets (domains, subdomains, IPs, cloud services, S3 buckets, exposed APIs, code leaks, third-party dependencies, shadow SaaS) from an attacker’s outside-in perspective, with prioritized remediation guidance and integrations (ticketing/CI/CMDB).

- **References**: [Rapid7](https://www.rapid7.com/), [Palo Alto Networks](https://www.paloaltonetworks.com/)

### 2. Core capabilities (MUST-HAVE)
- **Asset discovery (passive + active)**: DNS, reverse DNS, certificate transparency, WHOIS, CDN fingerprints, ASN discovery, IP range scans, cloud metadata and CSPM connectors, container endpoints; support both owned and unknown/third-party assets.
  - References: [Rapid7](https://www.rapid7.com/), [attaxion.com](https://attaxion.com)
- **Continuous monitoring**: scheduled and event-driven re-discovery, change detection, realtime alerting on new/changed public exposure.
  - References: [Microsoft Learn](https://learn.microsoft.com/)
- **Fingerprinting & classification**: tech stack detection (JS libs, frameworks), open ports & services, TLS/HTTP headers, robots/security headers, S3/bucket ACL states, exposed credentials, third-party trackers, cloud metadata exposures.
- **Vulnerability and exposure correlation**: map assets to known CVEs, misconfigurations, leaked secrets, stale certs, open admin panels; combine active scans (DAST/Nmap/masscan) and passive telemetry.
  - References: [Wiz](https://www.wiz.io/)
- **Risk scoring & prioritization**: combine exploitability, asset criticality (business context), internet exposure, CVSS, threat intel (active exploitation), and exploitability timelines; provide explainable score components.
  - References: [Palo Alto Networks](https://www.paloaltonetworks.com/), [Qualys](https://www.qualys.com/)
- **Asset inventory & lineage**: canonicalize entities (domain, subdomain, IP, host, service, app), group by business unit and environment, show lineage (cert, CDN, cloud account).
- **Alerts & workflows**: triaged alerts, remediation playbooks, SLA tracking, auto-ticket creation (Jira/ServiceNow/GitHub Issues), and remediation validation.
- **Integrations**: SIEM, SOAR, VM (Qualys, Tenable), cloud providers (AWS/GCP/Azure APIs), IAM/SSO, CDNs, DNS providers, CERT feeds, MDM/ITSM.
  - References: [Qualys](https://www.qualys.com/), [Microsoft Learn](https://learn.microsoft.com/)
- **Reporting & dashboards**: executive risk dashboard, asset heatmaps, exposure trends, time-to-remediation, exports (CSV/PDF), scheduled reports.
- **Multi-tenancy & RBAC**: org → team → project scoping, fine-grained RBAC, SSO/SAML/OIDC, audit logging.
- **Data governance & retention**: configurable retention, legal hold, PII masking, export controls.

### 3. Non-functional requirements
- **Scalability**: millions of assets; horizontally scalable discovery & scanning workers; autoscale via Kubernetes.
- **Availability**: 99.9% platform uptime, stateless API nodes, resilient DB/object store.
- **Performance**: initial discovery target ~50k unique domains/day per cluster (configurable).
- **Security & privacy**: encryption at rest (KMS) and in transit (mTLS), key rotation, secrets management, hardened images, least-privilege roles.
- **Compliance**: support SOC2/ISO27001 evidence; record audit trail for all findings.
- **Cost control**: rate limiting for active scanning; windows and throttling profiles per customer.

### 4. System architecture (recommended)
- **Frontend**: React + TypeScript, component library, charts, role-aware views.
- **Backend API**: REST + GraphQL hybrid; Go/Rust for high-concurrency or Python FastAPI for rapid prototyping; Auth via OIDC/SAML.
- **Worker layer**: Kubernetes jobs (or serverless) for discovery pipelines, fingerprinting, active scanners, and enrichment; message queue (Kafka/RabbitMQ) for orchestration.
- **Data store**:
  - Search & indexing: Elasticsearch / OpenSearch for fast search and full-text findings.
  - Primary DB: PostgreSQL for canonical asset metadata and relationships.
  - Long-term object store: local filesystem directory for raw scan artifacts, pcap, screenshots.
  - Time-series/metrics: Prometheus for internal metrics.
  - Cache/Queue: Redis for transient state and locks.
- **Threat intel & enrichment**: microservice to fetch and normalize intel feeds.
- **Scanning sandbox**: isolated scanning VPCs with egress control, ephemeral egress IP pools, throttling logic.
- **Secrets & keys**: HashiCorp Vault (or cloud KMS) for connector credentials.
- **Observability**: OpenTelemetry tracing, centralized logs (ELK), alerting on pipeline failures.
- **CI/CD**: GitHub Actions/GitLab CI with IaC (Terraform) and image scanning.

### 5. Discovery & scanning pipeline (detailed)
Stages for each asset candidate:

- **Seed ingestion**: user inputs (domains, org names, IP ranges), connectors (cloud accounts), passive data (CT), public sources (OSINT), crawling.
- **Passive discovery enrichment**: CT logs, DNS resolvers, WHOIS, ASN, reverse DNS, certificate SANs, public repos (GitHub), subdomain brute lists + wordlists.
  - References: [Amass](https://github.com/owasp-amass/amass), [attaxion.com](https://attaxion.com)
- **Active verification (controlled)**: masscan for top ports, nmap for service fingerprinting, HTTP(S) requests for headers/app-fingerprints, screenshot rendering (headless Chromium), WAF detection, DAST probes; respect rate limits and opt-outs.
- **Cloud & API connectors**: AWS/GCP/Azure read-only to enumerate cloud resources (S3/Storage buckets, IAM roles, LB endpoints, public endpoints) and map to discovered public assets.
  - References: [Microsoft Learn](https://learn.microsoft.com/)
- **Leak & brand intelligence**: search exposed credentials (GitHub tokens), paste sites, dark web sources, brand impersonation domains; heuristics/ML for FP reduction.
- **Fingerprinting & tech stack detection**: Wappalyzer-like detection, JS dependency hash matching, header/cookie analysis, CSP/SEC headers.
- **Vuln mapping & scoring**: match fingerprinted software/versions to CVEs/OSVDB; compute exploitability factors; enrich with threat intel (active campaigns).
  - References: [Wiz](https://www.wiz.io/), [Palo Alto Networks](https://www.paloaltonetworks.com/)
- **Canonicalization & dedupe**: normalized canonical asset model; merge duplicates.
- **Alerting & SLA workflow**: create/update tickets, assign to owning BU, attach remediation steps and verification checks.

### 6. Data model (short schema)
```text
asset (
  id,
  type {domain, ip, subdomain, cdn, cloud-resource},
  canonical_name,
  first_seen,
  last_seen,
  owner_id,
  tags,
  business_unit,
  environment,
  criticality_score
)

service (
  id,
  asset_id,
  port,
  protocol,
  banner,
  cert_id,
  fingerprint
)

finding (
  id,
  asset_id,
  type {vuln, leak, misconfig},
  severity,
  score_components,
  status {open, triaged, resolved, accepted},
  cvss,
  cve,
  created_by,
  created_at
)

evidence (
  id,
  finding_id,
  artifact_type {screenshot, pcap, header, raw_http},
  storage_ref
)

enrichment (
  asset_id,
  intel_source,
  confidence,
  enriched_fields
)

audit_log (
  actor,
  action,
  target_id,
  details,
  ts
)
```

### 7. Risk scoring model (explainable)
- Risk = weighted sum of:
  - External exposure factor (publicly routable, open admin ports, default creds)
  - Exploitability factor (known CVE exists, exploit code public)
  - Business criticality (owner-provided)
  - Temporal urgency (time since disclosure + active exploit intel)
  - Blast radius (accessible internal services, cloud roles)
- Provide both normalized 0–100 score and component breakdown; preserve deterministic reproducibility (record weights in DB).
  - References: [Palo Alto Networks](https://www.paloaltonetworks.com/)

### 8. API & integrations
- **REST API**: CRUD for assets, findings, owners, tags, connectors; OAuth2 bearer tokens; optional mTLS.
- **GraphQL**: flexible queries for dashboards and export.
- **Webhooks**: findings lifecycle changes (publish JSON schema).
- **Connectors**: Jira, ServiceNow, Slack, MS Teams, GitHub, PagerDuty, SIEM (Splunk/Elastic), cloud providers (AWS/GCP/Azure), VM tools (Qualys/Tenable).
- **Agent / Validation runner**: lightweight optional agent (signed) for private zones to validate remediation or run internal verification.

### 9. UI & UX (essential screens)
- Overview dashboard: global risk score, top 10 exposures, trending assets.
- Asset inventory: search, filters, ownership, history, relationship graph.
- Findings: prioritized queue, playbooks, ticket links, proof and remediation steps.
- Investigation: timelines, screenshots, raw evidence artifacts, enrichment logs.
- Settings: connector configs, scan policies, rate limits, change notification config.
- Reports: scheduled email/export, compliance templates.

### 10. Security, legal & ethical scanning controls
- Opt-out/deny lists and robots respect; maintain allow/deny lists and legal boundaries.
- Scanning consent: require customer authorization for non-owned IPs; clear ToS and scanning policy.
- Isolation: scanning from dedicated, instrumented egress IPs and ephemeral containers.
- Rate limiting, retry backoff, and monitoring to comply with provider policies.
- Data minimization: hash sensitive artifacts, redact PII, customer controls for erasure.

### 11. Observability & telemetry
- Metrics: discovery rates, findings by severity, MTTR, false-positive ratio, connector success rates.
- Traces: end-to-end tracing for discovery → finding pipeline (OpenTelemetry).
- Alerts: pipeline failures, worker crashes, anomalous scan behavior, cost spikes.

### 12. Testing & QA
- Unit tests: scoring logic, DB migrations, canonicalization.
- Integration tests: connectors using sandbox accounts and VCR-style recorded API responses.
- End-to-end tests: discovery pipelines with synthetic domains and test harness.
- Fuzz tests: parsing/CT logs and certificate parsing.
- Red-team: periodic external penetration tests and purple team exercises.
- Performance tests: simulate large discovery volume; validate linear scaling and search latencies.

### 13. Deployment, infra & infra-as-code
- Use Terraform to provision cloud infra (VPCs, NAT egress, private subnets for scanning workers).
- Kubernetes for orchestration (Helm charts).
- CI pipeline: build → unit tests → image scan → deploy to staging → automated integration tests → canary deploy to prod.
- Canary & blue/green deploys for scanning workers to avoid mass re-discovery after deploy.
- Cost monitoring: alert on disk usage, egress, and scan CPU spikes.

### 14. Privacy & compliance controls
- PII discovery flags, encryption of sensitive fields, per-tenant data partitioning.
- Support data export and deletion per GDPR/CCPA.
- Audit logs retention policy and admin access controls.

### 15. MVP scope (6–8 week target for a small team)
- **MVP goal**: continuous discovery + inventory + basic scoring + ticket integration + dashboard.
- **Deliverables**:
  - Seed ingestion and passive discovery (CT logs, DNS) + canonical asset model.
    - Acceptance: ingest 1,000 seeds and produce deduplicated assets.
    - Reference: [Rapid7](https://www.rapid7.com/)
  - Active verification engine (masscan + HTTP fingerprinting) in isolated sandbox.
    - Acceptance: fingerprint 80% of reachable seeds.
  - Fingerprinting & evidence storage (screenshots, headers).
    - Acceptance: store evidence and link to findings.
  - Simple risk scoring (exposure + CVE mapping) and explainable UI.
    - Acceptance: show top 10 exposures with score breakdown.
    - Reference: [Palo Alto Networks](https://www.paloaltonetworks.com/)
  - Jira/GitHub integration for auto-ticket creation and remediation validation.
    - Acceptance: create ticket from finding and update status on closure.
  - Basic RBAC and SSO (OIDC) and audit logging.
    - Acceptance: at least two roles with separate permissions.

### 16. Roadmap (post-MVP)
- Add cloud connectors and CSPM features.
  - Reference: [Microsoft Learn](https://learn.microsoft.com/)
- Add leaked credentials & brand-intel modules.
- Advanced ML for noise reduction and attacker-behavior simulation (ASIM).
- Multi-org multi-tenant SaaS/Enterprise editions and API-first features.
- Automated remediation (IaC PRs, S3 ACL fixes) and validation workflows.
- Marketplace of remediation playbooks and community rule sets.

### 17. Risks & mitigations
- False positives — mitigate via verification checks, confidence scoring, and feedback loop for tuning.
- Legal/abuse complaints — mitigate with opt-out, consent forms, and scanning policies.
- High costs from scanning scale — mitigate with scheduling, rate-limits, and per-tenant throttles.

### 18. KPIs to measure success
- Discovery coverage (% of internet-facing assets found vs. known baseline).
- Number of critical findings discovered per week.
- MTTR for critical findings (target < 30 days initially).
- False positive rate (target < 10% after tuning).
- Connector uptime / sync success rate.

### 19. Tech stack recommendations (concrete)
- Backend: Go or Rust.
- DB: PostgreSQL + OpenSearch.
- Queue: Kafka (high scale) or RabbitMQ (simpler).
- Orchestration: Kubernetes (EKS/GKE/AKS).
- Scanners: masscan, nmap, headless Chrome (Puppeteer), OWASP ZAP for DAST.
  - References: [attaxion.com](https://attaxion.com), [Jit](https://www.jit.io/)
- Secrets: Vault; Observability: OpenTelemetry + Prometheus + Grafana.

### 20. References & inspiration (product + attack model)
- EASM fundamentals (continuous discovery & outside-in perspective): [Rapid7](https://www.rapid7.com/)
- Cloud connector / mapping approach: [Microsoft Learn](https://learn.microsoft.com/)
- CTEM guidance for risk scoring and exposure management: [Palo Alto Networks](https://www.paloaltonetworks.com/)
- Open-source discovery building blocks (Amass, masscan): [attaxion.com](https://attaxion.com)
- Vendor comparisons / market context: Gartner / industry reviews

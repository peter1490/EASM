# EASM (External Attack Surface Management)

All‑in‑one EASM security tool with a high-performance Rust backend and a Next.js + Tailwind frontend.

## Features

- **High Performance**: Rust backend for optimal performance and memory safety
- **Async Architecture**: Fully asynchronous using Tokio runtime
- **PostgreSQL Database**: Robust data persistence with SQLx
- **External Integrations**: Support for Shodan, VirusTotal, CertSpotter, and more
- **Asset Discovery**: Automated discovery with confidence scoring
- **Deep Protocol Scanning**: SSL/TLS, DNS and HTTP assessments at the depth of the
  dedicated tools — see below
- **Evidence Management**: File upload and storage capabilities
- **Modern UI**: Next.js frontend with real-time updates

## Scanning

Three deep scanners live in `backend/src/services/scanners/`. Each aims to
produce what the well-known tool for that protocol produces, and each grades its
result on that tool's published scale rather than an invented one.

### SSL/TLS — `sslscan`, `sslyze`, `testssl.sh`, SSL Labs

`rustls` will not negotiate SSLv3, TLS 1.0/1.1, RC4, 3DES, export or anonymous
suites — correct for a client, useless for a scanner whose job is to find them.
So `tls_probe` writes the ClientHello bytes itself and speaks the record layer
directly over TCP.

- Protocol enumeration from SSLv2 to TLS 1.3, each confirmed by an exact-version
  handshake
- Cipher-suite enumeration per protocol, plus whose preference order wins
- Key-exchange strength: DH group size from ServerKeyExchange, named curve from
  the negotiated `key_share`
- Certificate chain validated against the Mozilla root program (`webpki-roots`),
  so `untrusted` means what a browser means; CT SCTs, OCSP Must-Staple, key usage,
  AIA/CRL endpoints, serial entropy, the 398-day CA/Browser Forum lifetime cap
- Vulnerabilities: DROWN, POODLE, BEAST, SWEET32, FREAK, LOGJAM, RC4, CRIME,
  Heartbleed (actively probed with a 64-byte overread that is measured and
  discarded), insecure renegotiation, missing TLS_FALLBACK_SCSV, ROBOT and
  LUCKY13. Each is reported as **confirmed** (observed) or **potential** (the
  configuration is a precondition; proving it needs an oracle test this scanner
  deliberately does not run) — the two are never conflated
- A letter grade computed from the published
  [SSL Labs Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide):
  30/30/40 across protocol, key exchange and cipher strength, with the documented
  caps and the `T`/`M` grades for trust and name-mismatch failures

### DNS — `dig`, `dnsrecon`, MXToolbox, Hardenize, internet.nl

- Full record sweep: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, DNSKEY, DS
- DNSSEC: is the zone signed, and is the delegation signed with it — an
  "island of security" (DNSKEY without a parent DS) is reported as its own defect
- **AXFR zone transfer** attempted against every authoritative nameserver, over a
  raw DNS TCP transport (`dns_wire`), because a stub resolver cannot send AXFR
- SPF to RFC 7208 including the **ten-lookup processing limit**, counted
  recursively through every `include:` and `redirect=` — the rule that silently
  breaks mail delivery and that a top-level-only check misses
- DMARC to RFC 7489: policy, subdomain policy, `pct`, alignment, report addresses
- DKIM selector probing (46 provider defaults), reported as inconclusive because
  selectors cannot be enumerated from DNS
- MTA-STS (with the HTTPS policy fetched and parsed), TLS-RPT, BIMI, DANE/TLSA
- CAA parsed properly, nameserver count/diversity/lame delegation (RFC 2182), SOA
  timer sanity (RFC 1912, RFC 2308), wildcard DNS, apex CNAME, RFC 1918 addresses
  in public DNS
- Dangling-CNAME **subdomain takeover** against 50+ provider signatures, confirmed
  by the provider's own unclaimed-tenant page rather than by the CNAME target alone

### HTTP — Mozilla Observatory, securityheaders.com, `nuclei`, `nikto`

- Security headers graded on their **value**, not their presence: a CSP that
  permits `'unsafe-inline'` in `script-src` provides no XSS protection, and is
  reported as a weak header rather than a present one
- Scored with the published
  [Mozilla HTTP Observatory](https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md)
  modifiers and letter chart
- Cookies: `Secure`, `HttpOnly`, `SameSite`, and the browser-enforced `__Host-` /
  `__Secure-` prefixes
- CORS misconfiguration including origin reflection with credentials — visible
  only when an `Origin` is actually sent, which a header table cannot do
- HTTP methods confirmed by response rather than by what `Allow:` claims (TRACE is
  verified by its echo)
- Redirect chain walked hop by hop, so "redirects to HTTPS eventually" is
  distinguished from "first hop is HTTPS on the same host"
- Sensitive file and endpoint exposure (`.git`, `.env`, actuator, phpinfo,
  `trace.axd`, …), each **validated against expected content** — a server that
  answers 200 with an SPA shell for every URL produces no findings
- Directory listing, framework stack traces, mixed content, SRI, `security.txt`,
  HTTP/2 and HTTP/3

### Scan types

`full` runs everything. `tls_analysis`, `dns_audit` and `http_probe` run one
scanner each, so a cheap DNS audit can run on a schedule against every domain
while a full scan runs less often. Pass `{"deep": false}` in a scan's config for
a fast sweep that skips cipher enumeration, AXFR and path probing.

## Quickstart (local)

### Prerequisites

- Rust 1.75 or later
- PostgreSQL 16
- Node.js 20 or later

### Backend:

```bash
cd backend
# Copy and configure environment variables
cp ../example.env ../.env
# Edit .env with your database URL and API keys

# Build and run (migrations run automatically)
cargo run
```

### Frontend (in another terminal):

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

## Docker Deployment

EASM supports both development and production environments with Docker Compose.

### Quick Start

**Development Environment** (with hot-reload):
```bash
# Using Makefile (recommended)
make dev

# Or using helper script
./deploy-dev.sh

# Or using docker compose directly
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

**Production Environment** (optimized builds):
```bash
# Using Makefile (recommended)
make prod

# Or using helper script
./deploy-prod.sh

# Or using docker compose directly
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

### Services

This will start:
- Backend API: `http://localhost:8000`
- Frontend: `http://localhost:3000`
- PostgreSQL: `localhost:5432` (dev) / internal only (prod)

### Environment Configuration

1. Copy the example environment file:
   ```bash
   cp example.env .env
   ```

2. Set the environment mode in `.env`:
   ```bash
   ENVIRONMENT=development  # or 'production'
   ```

3. Configure your API keys and other settings in `.env`

### Common Commands

```bash
make help           # Show all available commands
make dev            # Start development environment
make prod           # Start production environment
make stop           # Stop all services
make logs           # View logs from all services
make ps             # Show service status
make health         # Check health of all services
make clean          # Remove all containers and volumes
```

For detailed deployment instructions, troubleshooting, and advanced configuration, see [DEPLOYMENT.md](./DEPLOYMENT.md).

## Tests

```bash
cd backend
cargo test
```

## Configuration

Configuration is managed through environment variables. See `example.env` for all available options.

Key variables:
- `DATABASE_URL`: PostgreSQL connection string
- `VIRUSTOTAL_API_KEY`: VirusTotal API key (optional)
- `CORS_ALLOW_ORIGINS`: Comma-separated list of allowed origins

## API Endpoints

### Health & Status
- `GET /api/health` - Full health check
- `GET /api/health/simple` - Simple health check
- `GET /api/health/ready` - Readiness check
- `GET /api/health/live` - Liveness check

### Scans
- `POST /api/scans` - Create new scan `{ target, note?, options? }`
- `POST /api/assets/:id/scan` - Scan one asset `{ scan_type?, note? }`, where
  `scan_type` is `full` (default), `tls_analysis`, `dns_audit`, `http_probe`,
  `port_scan` or `threat_intel`
- `GET /api/scans` - List all scans
- `GET /api/scans/:id` - Get scan details

### Seeds & Assets
- `POST /api/seeds` - Create seed `{ seed_type, value, note? }`
- `GET /api/seeds` - List seeds
- `DELETE /api/seeds/:id` - Delete seed
- `GET /api/assets` - List assets
- `GET /api/assets/:id` - Get asset details

### Discovery
- `POST /api/discovery/run` - Start discovery process
- `GET /api/discovery/status` - Get discovery status

### Evidence
- `POST /api/scans/:scan_id/evidence` - Upload evidence
- `GET /api/scans/:scan_id/evidence` - List evidence by scan
- `GET /api/evidence/:id/download` - Download evidence

### Risk & Drift
- `GET /api/risk/calculate` - Calculate risk score
- `POST /api/scans/:id/drift/detect` - Detect port drift
- `GET /api/scans/:id/drift/findings` - Get drift findings

### Search
- `GET /api/search/assets` - Search assets
- `GET /api/search/findings` - Search findings
- `POST /api/search/reindex` - Reindex all data
- `GET /api/search/status` - Get search status

### Metrics
- `GET /api/metrics` - Get system metrics
- `GET /api/metrics/report` - Performance report
- `GET /api/metrics/health` - Health metrics

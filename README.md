# EASM (External Attack Surface Management)

All‑in‑one EASM security tool with a high-performance Rust backend and a Next.js + Tailwind frontend.

## Features

- **High Performance**: Rust backend for optimal performance and memory safety
- **Async Architecture**: Fully asynchronous using Tokio runtime
- **PostgreSQL Database**: Robust data persistence with SQLx
- **OpenSearch Integration**: Fast search and indexing capabilities
- **External Integrations**: Support for Shodan, VirusTotal, CertSpotter, and more
- **Asset Discovery**: Automated discovery with confidence scoring
- **Evidence Management**: File upload and storage capabilities
- **Modern UI**: Next.js frontend with real-time updates

## Quickstart (local)

### Prerequisites

- Rust 1.75 or later
- PostgreSQL 16
- Node.js 20 or later
- Optional: OpenSearch for enhanced search capabilities

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

## Docker

```bash
docker compose up --build
```

This will start:
- Backend API: `http://localhost:8000`
- Frontend: `http://localhost:3000`
- PostgreSQL: `localhost:5432`
- OpenSearch: `http://localhost:9200`

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
- `OPENSEARCH_URL`: OpenSearch URL (optional)
- `CORS_ALLOW_ORIGINS`: Comma-separated list of allowed origins

## API Endpoints

### Health & Status
- `GET /api/health` - Full health check
- `GET /api/health/simple` - Simple health check
- `GET /api/health/ready` - Readiness check
- `GET /api/health/live` - Liveness check

### Scans
- `POST /api/scans` - Create new scan `{ target, note?, options? }`
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

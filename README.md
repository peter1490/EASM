# EASM (External Attack Surface Management)

All‑in‑one EASM security tool with a high-performance Rust backend and a Next.js + Tailwind frontend.

## Features

- **High Performance**: Rust backend for optimal performance and memory safety
- **Async Architecture**: Fully asynchronous using Tokio runtime
- **PostgreSQL Database**: Robust data persistence with SQLx
- **External Integrations**: Support for Shodan, VirusTotal, CertSpotter, and more
- **Asset Discovery**: Automated discovery with confidence scoring
- **Evidence Management**: File upload and storage capabilities
- **Modern UI**: Next.js frontend with real-time updates

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

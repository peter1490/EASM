# Rust EASM Backend

A high-performance Rust implementation of the External Attack Surface Management (EASM) backend, designed to provide 100% functional parity with the existing Python FastAPI backend.

## Features

- **High Performance**: Built with Rust for optimal performance and memory safety
- **Async/Await**: Fully asynchronous using Tokio runtime
- **Database Support**: PostgreSQL via SQLx
- **API Compatibility**: Identical REST API endpoints as Python backend
- **External Integrations**: Support for Shodan, VirusTotal, CertSpotter, and other services
- **Network Scanning**: TCP port scanning, DNS resolution, and HTTP probing
- **Asset Discovery**: Automated asset discovery with confidence scoring
- **Evidence Management**: File upload and storage capabilities

## Architecture

- **Web Framework**: Axum with Tower middleware
- **Database**: SQLx with compile-time checked queries
- **Async Runtime**: Tokio for high-performance async operations
- **Serialization**: Serde for JSON handling
- **HTTP Client**: Reqwest for external API calls
- **Configuration**: Environment-based configuration with .env support

## Project Structure

```
src/
├── main.rs              # Application entry point
├── config.rs            # Configuration management
├── database.rs          # Database connection and migrations
├── error.rs             # Error types and handling
├── models/              # Database models and domain types
├── repositories/        # Data access layer
├── services/            # Business logic layer
├── handlers/            # HTTP request handlers
├── middleware/          # HTTP middleware (CORS, auth, logging)
└── utils/               # Utility functions
```

## Getting Started

### Prerequisites

- Rust 1.75 or later
- PostgreSQL database
- Optional: API keys for external services (Shodan, VirusTotal, etc.)

### Installation

1. Clone the repository
2. Copy `../example.env` to `../.env` and configure your settings
3. Database migrations run automatically on startup
4. Build and run: `cargo run`

### Configuration

The application uses environment variables for configuration. See `../example.env` for all available options:

- `DATABASE_URL`: PostgreSQL connection string (required)
- `VIRUSTOTAL_API_KEY`: VirusTotal API key (optional)
- `SHODAN_API_KEY`: Shodan API key (optional)
- `CERTSPOTTER_API_TOKEN`: CertSpotter API token (optional)
- `CORS_ALLOW_ORIGINS`: Comma-separated list of allowed CORS origins
- `LOG_LEVEL`: Logging level (default: INFO)
- `LOG_FORMAT`: Log format - json or plain (default: json)

### Development

```bash
# Run in development mode
cargo run

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy for linting
cargo clippy

# Optional: Install cargo-watch for auto-reload
# cargo install cargo-watch
# cargo watch -x run
```

### Docker

```bash
# Build Docker image
docker build -t rust-easm-backend .

# Run container
docker run -p 8000:8000 --env-file .env rust-easm-backend
```

## API Endpoints

The Rust backend provides identical API endpoints to the Python backend:

- `GET /api/health` - Health check
- `POST /api/scans` - Create new scan
- `GET /api/scans` - List scans
- `GET /api/scans/{id}` - Get scan details
- `POST /api/seeds` - Create seed
- `GET /api/seeds` - List seeds
- `DELETE /api/seeds/{id}` - Delete seed
- `GET /api/assets` - List assets
- `GET /api/assets/{id}` - Get asset details
- `POST /api/discovery/run` - Start discovery
- `GET /api/discovery/status` - Get discovery status

## Performance

The Rust backend is designed for high performance with:

- Async/await for non-blocking I/O operations
- Connection pooling for database operations
- Concurrent processing with configurable limits
- Memory-efficient data structures
- Zero-copy serialization where possible

## Migration from Python Backend

The Rust backend is designed for seamless migration:

1. **Database Compatibility**: Uses identical database schema
2. **API Compatibility**: Provides identical REST API endpoints
3. **Configuration Compatibility**: Uses same environment variables
4. **Feature Parity**: Implements all Python backend features

## Contributing

1. Follow Rust coding conventions
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all tests pass before submitting PRs

## License

[Add your license information here]
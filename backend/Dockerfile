# Dockerfile for backend - supports both development and production
# Build with: docker build --build-arg ENVIRONMENT=development|production

ARG ENVIRONMENT=production

# ============================================================================
# Development Stage
# ============================================================================
FROM rust:1.84 AS development

WORKDIR /app

# Install cargo-watch using nightly toolchain to avoid edition2024 issues
RUN rustup toolchain install nightly && \
    cargo +nightly install cargo-watch

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build dependencies in debug mode for faster builds
RUN cargo update -p base64ct --precise 1.7.1 && cargo fetch

# Create evidence directory
RUN mkdir -p /app/evidence

# Expose port
EXPOSE 8000

# Set environment variables for development
# Note: RUST_LOG is controlled by LOG_LEVEL from docker-compose
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8000
ENV RUST_BACKTRACE=1

# Use cargo watch for hot reload in development
# Note: cargo-watch is installed with nightly, but we run the app with stable
CMD ["cargo", "watch", "-x", "run"]

# ============================================================================
# Production Builder Stage
# ============================================================================
FROM rust:1.84 AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

ENV DATABASE_URL=postgresql://easm:easm@192.168.10.178:5432/easm

# Build the application in release mode with optimizations
RUN cargo update -p base64ct --precise 1.7.1 && cargo build --release

# ============================================================================
# Production Runtime Stage
# ============================================================================
FROM debian:bookworm-slim AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rust-backend /app/rust-backend

# Create evidence directory
RUN mkdir -p /app/evidence

# Expose port
EXPOSE 8000

# Set environment variables for production
# Note: RUST_LOG is controlled by LOG_LEVEL from docker-compose
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8000

# Run the binary
CMD ["./rust-backend"]

# ============================================================================
# Final Stage - Select based on ENVIRONMENT
# ============================================================================
FROM ${ENVIRONMENT} AS final

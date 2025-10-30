# Build stage
FROM rust:1.84 AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build the application
RUN cargo update -p base64ct --precise 1.7.1 && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

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

# Set environment variables
ENV RUST_LOG=info
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=8000

# Run the binary
CMD ["./rust-backend"]
# Multi-stage build for optimal image size
FROM rust:1.70-slim as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create src directory with dummy lib.rs for dependency caching
RUN mkdir src && echo "fn main() {}" > src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --release
RUN rm src/lib.rs

# Copy source code
COPY src ./src

# Build application
RUN cargo build --release --bin afdp-notary-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false notary

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/afdp-notary-server /usr/local/bin/afdp-notary-server

# Set ownership and permissions
RUN chown notary:notary /usr/local/bin/afdp-notary-server && \
    chmod +x /usr/local/bin/afdp-notary-server

# Switch to non-root user
USER notary

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the server
CMD ["afdp-notary-server"]
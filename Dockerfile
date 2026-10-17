# ==============================================================================
# ROKH WAF (دیواره آتش رُخ) - Official Production Dockerfile
# Multi-stage lightweight build with bundled SQLite & full zero-dependency runtime
# ==============================================================================

# --- Stage 1: Build stage ---
FROM rust:bookworm AS builder

WORKDIR /usr/src/rokh-waf

# Pre-cache dependencies layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/rokh_bench.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/rokh_waf* target/release/deps/waf_engine* target/release/deps/rokh_bench*

# Copy full source tree
COPY . .

# Compile optimized release binaries
RUN cargo build --release --bin waf_engine --bin rokh_bench

# --- Stage 2: Minimal Distroless / Slim Runtime stage ---
FROM debian:bookworm-slim AS runner

# Install essential runtime utilities (ca-certificates for HTTPS backends, curl for healthchecks)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled binaries from builder
COPY --from=builder /usr/src/rokh-waf/target/release/waf_engine /usr/local/bin/waf_engine
COPY --from=builder /usr/src/rokh-waf/target/release/rokh_bench /usr/local/bin/rokh_bench

# Create persistent storage directory for telemetry & logs
RUN mkdir -p /app/data

# Environment configuration defaults
ENV RUST_LOG=info \
    ROKH_LISTEN_ADDR=0.0.0.0:8080 \
    ROKH_BACKEND_URL=http://127.0.0.1:3000 \
    ROKH_MODE=PREVENTION \
    ROKH_RATE_LIMIT=120 \
    ROKH_DB_PATH=/app/data/waf_data.db

# Expose HTTP proxy & SOC dashboard port
EXPOSE 8080

# Expose data volume for persistent SQLite logs & forensic traces
VOLUME ["/app/data"]

# Container health check via SOC API
HEALTHCHECK --interval=20s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/rokh-api/v1/health || exit 1

ENTRYPOINT ["waf_engine"]
CMD []

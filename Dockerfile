# syntax=docker/dockerfile:1

# -------- Builder stage --------
FROM rust:1.78-slim AS builder

ARG CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
ENV CARGO_TERM_COLOR=always \
    RUSTFLAGS="-C target-cpu=native"

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates pkg-config build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs && \
    cargo build --release --bin mmf_sigil || true

# Copy full source and build real binaries
COPY . .
RUN cargo build --release --bin mmf_sigil && \
    cargo build --release --bin trainer

# -------- Runtime stage --------
FROM debian:bookworm-slim AS runtime

RUN useradd -m -u 10001 appuser && \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries
COPY --from=builder /app/target/release/mmf_sigil /app/mmf_sigil
COPY --from=builder /app/target/release/trainer /app/trainer

# Create data/logs dirs for volumes
RUN mkdir -p /app/data /app/logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

# Default: run API server
CMD ["/app/mmf_sigil", "--", "serve", "--host", "0.0.0.0", "--port", "8080"]



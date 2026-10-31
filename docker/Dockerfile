FROM rust:1.96-alpine AS builder

# Install musl tools for static linking
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./

# Copy actual source code
COPY crates ./crates

# Build the application for musl
RUN cargo build --locked --release && \
    cp target/release/gitiup /gitiup

# --- Runtime Stage ---
FROM scratch

# Copy the statically linked binary
COPY --from=builder /gitiup /gitiup

# Set entrypoint
ENTRYPOINT ["/gitiup"]

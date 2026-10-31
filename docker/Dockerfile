FROM rust:1.96-alpine AS builder

# Install musl tools for static linking
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./

# Copy actual source code
COPY crates ./crates

# Build the application for musl
RUN cargo build --release --target x86_64-unknown-linux-musl && \
    cp target/x86_64-unknown-linux-musl/release/myapp /myapp

# --- Runtime Stage ---
FROM scratch

# Copy the statically linked binary
COPY --from=builder /myapp /myapp

# Set entrypoint
ENTRYPOINT ["/myapp"]

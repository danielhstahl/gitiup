# The image gitiup *runs* in, for the "this machine is a Mac" case (and for any
# machine where the isolation you want is a kernel rather than a syscall list):
# docs/macos.md is the prose, and the short version is that Landlock, seccomp and the
# escape checks all work inside a Linux container on macOS — probed, not assumed.
#
#   docker build -f docker/Dockerfile -t gitiup .
#   docker run --rm -v "$PWD:/work" -w /work gitiup doctor --sandbox
#   docker run --rm -v "$PWD:/work" -w /work gitiup run --execute --workflow …
#
# Two things this stage is not:
#
# * It is not `FROM scratch`. A CI *step* is a `/bin/sh` script, so an image that cannot
#   run a shell cannot run a job, and a store client that cannot verify a TLS certificate
#   cannot file an attestation. The runtime stage therefore has a shell, `git`, CA
#   certificates and the escape canary, and is still a couple of tens of MB.
# * It is not the image a *confined job* runs in. That one is `GITIUP_SANDBOX_IMAGE`
#   (default `alpine:3.20`, and it must match the host's architecture — on Apple silicon,
#   an arm64 image).

FROM rust:1.96-alpine AS builder

# Install musl tools for static linking
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./

# Copy actual source code
COPY crates ./crates

# Build the application for musl. The whole workspace, because the runtime stage wants
# the canary too: a probe that cannot find `gitiup-sandbox-canary` beside its executable
# reports its checks as unchecked, and an unchecked check is the thing this crate refuses
# to pretend about.
RUN cargo build --locked --release

# --- Runtime stage ---
FROM alpine:3.20

# `git` because the store and the plain-git host drive it; `bash` and `curl` because a
# workflow step reaches for them; `openssh-client` so a job may talk to a git remote it
# was given (whether it *may* reach the network at all is the sandbox's decision, not
# this package list's).
RUN apk add --no-cache git bash curl openssh-client ca-certificates

COPY --from=builder /app/target/release/gitiup /usr/local/bin/gitiup
COPY --from=builder /app/target/release/gitiup-sandbox-canary /usr/local/bin/gitiup-sandbox-canary

# A login-less shell still needs a HOME, and the scratch is where a confined job is told
# to keep things; the runner sets both per job, this is only so `gitiup doctor` is not
# hostile when run bare.
ENV HOME=/tmp
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/gitiup"]

#!/usr/bin/env bash
# Run the host conformance matrix the way CI does, on your own machine.
#
# Everything hermetic (fs, the two git shapes, the in-memory bucket, the github
# adapter) runs by default and needs nothing. The two live hosts opt in through the
# environment, exactly as they do in CI:
#
#   ./ci/host-conformance.sh                       # hermetic hosts only
#   ./ci/host-conformance.sh --minio              # also a MinIO bucket (needs docker)
#   MINIO=http://127.0.0.1:9000 ./ci/host-conformance.sh   # an endpoint you started
#   GIT_HTTP=http://127.0.0.1:8080 GIT_HTTP_ROOT=/tmp/git-root ./ci/host-conformance.sh
#
# `--minio` starts a container; `--strict` turns every skip into a failure, which is
# what CI uses (GITIUP_CONFORMANCE_REQUIRE_HOSTS). `--quick` drops the sizes back to
# what a laptop likes.
#
# The refused-credentials steps run when the endpoint can actually answer them —
# pass `--denied` to force them. That is not a nicety: a fake that accepts any
# credentials without checking them (moto, `S3ResponseOverrides`) makes the body
# *fail*, and that failure is the suite refusing to pretend a fake is an endpoint.
# A container started by `--minio` validates signatures, so it is implied there.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

strict=0
quick=0
want_minio=0
want_denied=0
minio_endpoint="${MINIO:-}"
container=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --minio) want_minio=1; want_denied=1 ;;
        --denied) want_denied=1 ;;
        --strict) strict=1 ;;
        --quick) quick=1 ;;
        -h | --help) sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing: $1 (needed to run this script at all)" >&2
        exit 1
    }
}
require cargo
require python3

# ---------------------------------------------------------------------------
# The live bucket, if one was asked for.
# ---------------------------------------------------------------------------
if [[ $want_minio -eq 1 && -z "$minio_endpoint" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "--minio needs docker, and docker is not here; set MINIO=<url> to point at" >&2
        echo "an endpoint you already have (moto works for everything except the" >&2
        echo "refused-credentials body, which needs an endpoint that checks signatures)." >&2
        exit 1
    fi
    say "starting MinIO in a container"
    container="gitiup-conformance-minio-$$"
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker run -d --rm --name "$container" -p 9000:9000 \
        -e MINIO_ROOT_USER=gitiup-conformance \
        -e MINIO_ROOT_PASSWORD=gitiup-conformance-secret \
        minio/minio:latest server /data >/dev/null
    minio_endpoint="http://127.0.0.1:9000"
    for _ in $(seq 1 60); do
        if curl -sf "$minio_endpoint/minio/health/live" >/dev/null 2>&1; then break; fi
        sleep 1
    done
    curl -sf "$minio_endpoint/minio/health/live" >/dev/null || {
        echo "MinIO did not come up" >&2
        docker logs "$container" >&2 || true
        exit 1
    }
    trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
    export GITIUP_S3_LIVE_ENDPOINT="$minio_endpoint"
    export AWS_ACCESS_KEY_ID=gitiup-conformance
    export AWS_SECRET_ACCESS_KEY=gitiup-conformance-secret
    export GITIUP_S3_LIVE_BUCKET="${GITIUP_S3_LIVE_BUCKET:-gitiup-conformance}"
fi
if [[ -n "$minio_endpoint" && -z "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then
    export GITIUP_S3_LIVE_ENDPOINT="$minio_endpoint"
    export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-gitiup-conformance}"
    export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-gitiup-conformance-secret}"
fi

# ---------------------------------------------------------------------------
# The smart-HTTP git endpoint: an external one if named, otherwise the suite's own
# fixture (which is what it starts by itself when these two are unset).
# ---------------------------------------------------------------------------
if [[ -n "${GIT_HTTP:-}" ]]; then
    export GITIUP_CONFORMANCE_GIT_HTTP_URL="$GIT_HTTP"
    export GITIUP_CONFORMANCE_GIT_ROOT="${GIT_HTTP_ROOT:-$(mktemp -d)}"
    mkdir -p "$GITIUP_CONFORMANCE_GIT_ROOT"
fi

if [[ $strict -eq 1 ]]; then
    hosts=(fs git-file git-http s3-memory)
    [[ -n "${GITIUP_S3_LIVE_ENDPOINT:-}" ]] && hosts+=(s3-minio)
    export GITIUP_CONFORMANCE_REQUIRE_HOSTS="$(
        IFS=,
        echo "${hosts[*]}"
    )"
fi
if [[ $quick -eq 1 ]]; then
    export GITIUP_CONFORMANCE_PACK_BYTES="${GITIUP_CONFORMANCE_PACK_BYTES:-262144}"
    export GITIUP_CONFORMANCE_LIST_COUNT="${GITIUP_CONFORMANCE_LIST_COUNT:-32}"
    export GITIUP_CONFORMANCE_REF_COUNT="${GITIUP_CONFORMANCE_REF_COUNT:-8}"
fi

features=(--features s3,github)

say "format check"
cargo fmt --all -- --check

say "clippy"
cargo clippy -p gitiup-host-tests "${features[@]}" --all-targets -j 3

say "the suite"
cargo test -p gitiup-host-tests "${features[@]}" -j 3

say "the matrix"
cargo run -p gitiup-host-tests "${features[@]}" --example report -j 3

say "past a bucket's page and part boundaries (live bucket only, if any)"
if [[ -n "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then
    GITIUP_CONFORMANCE_LIST_COUNT="${GITIUP_CONFORMANCE_LIST_COUNT_CI:-2050}" \
    GITIUP_CONFORMANCE_PACK_BYTES="${GITIUP_CONFORMANCE_PACK_BYTES_CI:-33554432}" \
        cargo test -p gitiup-host-tests --features s3 -j 3 --test s3_minio -- \
        listings_are_complete_across_pages a_huge_pack_round_trips_intact
else
    echo "skipped: no live bucket (pass --minio, or set MINIO=<url>)"
fi

say "refused credentials"
if [[ $want_denied -eq 1 && -n "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then
    # Save the working credentials: this step needs the ones the endpoint refuses,
    # and the step must fail if the endpoint does not refuse them.
    good_key="$AWS_ACCESS_KEY_ID"
    good_secret="$AWS_SECRET_ACCESS_KEY"
    export GITIUP_CONFORMANCE_S3_DENIED=1
    export AWS_ACCESS_KEY_ID=gitiup-revoked-key AWS_SECRET_ACCESS_KEY=gitiup-revoked-secret
    cargo test -p gitiup-host-tests --features s3 -j 3 --test s3_minio -- \
        refused_credentials_are_denied_not_dropped --nocapture
    export GITIUP_CONFORMANCE_S3_DENIED=0
    export AWS_ACCESS_KEY_ID="$good_key" AWS_SECRET_ACCESS_KEY="$good_secret"
elif [[ -z "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then
    echo "skipped: needs a live bucket (pass --minio, or set MINIO=<url>)"
else
    echo "skipped: not said the endpoint checks signatures (--denied to insist)." >&2
    echo "A fake that accepts any credentials makes this body fail on purpose." >&2
fi

say "the git endpoint that refuses"
cargo test -p gitiup-host-tests --test git -j 3 -- \
    git_http::refused_credentials_are_denied_not_dropped --nocapture

say "done"

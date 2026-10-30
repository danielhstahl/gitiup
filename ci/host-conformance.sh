#!/usr/bin/env bash
# Run the host conformance matrix the way CI does, on your own machine.
#
# Everything hermetic (fs, the two git shapes, the in-memory bucket, the github
# adapter) runs by default and needs nothing. The two live hosts opt in through the
# environment, exactly as they do in CI:
#
#   ./ci/host-conformance.sh                       # hermetic hosts only
#   ./ci/host-conformance.sh --minio               # + a MinIO bucket (needs docker)
#   ./ci/host-conformance.sh --git-http            # + a real git-http-backend, started here
#   ./ci/host-conformance.sh --live                # what CI runs: both, demanded
#   MINIO=http://127.0.0.1:9000 ./ci/host-conformance.sh           # a bucket you started
#   GIT_HTTP=http://127.0.0.1:8080 GIT_HTTP_ROOT=/tmp/git-root ./ci/host-conformance.sh
#
# `--strict` (implied by `--live`) turns every skip into a failure, which is what CI
# uses (GITIUP_CONFORMANCE_REQUIRE_HOSTS), and it is also the mode that insists the
# services are *there*: a `--strict`/`--live` run with no bucket to reach and no way to
# start one stops here rather than reporting green over a suite that skipped MinIO. A
# git-http-backend that was named but is not answering is the same kind of failure — the
# change bodies below are the ones that care most, because the promise they test is
# exactly that a bucket and a served repository mean the same thing.
#
# `--quick` drops the sizes back to what a laptop likes.
#
# The refused-credentials steps run when the endpoint can actually answer them —
# pass `--denied` to force them. That is not a nicety: a fake that accepts any
# credentials without checking them (moto, `S3ResponseOverrides`) makes the body
# *fail*, and that failure is the suite refusing to pretend a fake is an endpoint.
# A container started by `--minio` validates signatures, so it is implied there. An
# endpoint you name yourself may need `GITIUP_S3_LIVE_ALLOW_UNVERSIONED=1` (moto does;
# MinIO and real buckets do not) — the reasons are in `hosts::live`.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

strict=0
quick=0
want_minio=0
want_git_http=0
want_denied=0
minio_endpoint="${MINIO:-}"
git_http="${GIT_HTTP:-}"
git_http_root="${GIT_HTTP_ROOT:-}"
container=""
git_http_pid=""
git_http_log=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --minio) want_minio=1; want_denied=1 ;;
        --git-http) want_git_http=1 ;;
        --live | --ci)
            want_minio=1
            want_git_http=1
            want_denied=1
            strict=1
            ;;
        --denied) want_denied=1 ;;
        --strict)
            strict=1
            want_minio=1
            want_git_http=1
            ;;
        --quick) quick=1 ;;
        -h | --help)
            sed -n '2,31p' "$0"
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            exit 2
            ;;
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

# A missing service is a failure, not a skip: say so with the thing to type.
die() {
    printf '\033[31mhost-conformance: %s\033[0m\n' "$1" >&2
    shift
    for line in "$@"; do echo "  $line" >&2; done
    exit 1
}

require cargo
require python3

cleanup() {
    if [[ -n "$container" ]]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if [[ -n "$git_http_pid" ]]; then
        kill "$git_http_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# The live bucket, if one was asked for.
# ---------------------------------------------------------------------------
if [[ $want_minio -eq 1 && -z "$minio_endpoint" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
        die "--strict/--live demands a live bucket, and there is none to start" \
            "docker is not here, and MINIO is not set to an endpoint you already have." \
            "start one:  docker run -d -p 9000:9000 -e MINIO_ROOT_USER=gitiup-conformance -e MINIO_ROOT_PASSWORD=gitiup-conformance-secret minio/minio server /data" \
            "or point at it:  MINIO=http://127.0.0.1:9000 $0 --live" \
            "or drop the demand:  $0            # hermetic hosts only"
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
if [[ $want_minio -eq 1 && -z "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then
    die "a live bucket was asked for and none is configured" \
        "MINIO was set to an empty value; unset it or name an endpoint."
fi

# ---------------------------------------------------------------------------
# The smart-HTTP git endpoint: an external one if named, otherwise the suite's own
# fixture (which is what it starts by itself when these two are unset), and under
# --strict/--live a real `git-http-backend` started right here — the deployment shape
# a repository is actually served in, not a fixture someone else maintained.
# ---------------------------------------------------------------------------
find_git_http_backend() {
    local candidate
    candidate="$(command -v git-http-backend 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
        echo "$candidate"
        return 0
    fi
    for candidate in /usr/lib/git-core/git-http-backend \
        /usr/libexec/git-core/git-http-backend \
        "$(git --exec-path 2>/dev/null || true)/git-http-backend"; do
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# Whether a URL answers HTTP at all. `python3` is already a dependency of this script,
# and any HTTP status is the answer we want: the question is whether the CGI is there,
# not whether it liked the request.
answers_http() {
    python3 - "$1" <<'PYPROBE'
import sys
import urllib.error
import urllib.request

try:
    urllib.request.urlopen(sys.argv[1], timeout=5).read(1)
except urllib.error.HTTPError:
    pass
except Exception:
    sys.exit(1)
PYPROBE
}

if [[ -n "$git_http" ]]; then
    export GITIUP_CONFORMANCE_GIT_HTTP_URL="$git_http"
    export GITIUP_CONFORMANCE_GIT_ROOT="${git_http_root:-$(mktemp -d)}"
    mkdir -p "$GITIUP_CONFORMANCE_GIT_ROOT"
elif [[ $want_git_http -eq 1 ]]; then
    backend="$(find_git_http_backend || true)"
    fixture="crates/gitiup-host/tests/fixtures/git-http-backend.py"
    if [[ -z "$backend" || ! -f "$fixture" ]]; then
        die "--strict/--live demands a real git-http-backend, and this box cannot provide one" \
            "looked for git-http-backend on PATH, in \$(git --exec-path) and in /usr/lib/git-core." \
            "name a server you already run:  GIT_HTTP=http://127.0.0.1:8080 GIT_HTTP_ROOT=/srv/git $0 --live" \
            "or drop the demand:  $0        # hermetic hosts only"
    fi
    say "serving bare repositories over $backend"
    git_http_root="$(mktemp -d)"
    export GIT_PROJECT_ROOT="$git_http_root"
    export GIT_HTTP_EXPORT_ALL=1
    export GIT_HTTP_BACKEND="$backend"
    git_http_log="$(mktemp)"
    python3 "$fixture" 0 >"$git_http_log" 2>&1 &
    git_http_pid=$!
    port=""
    for _ in $(seq 1 60); do
        port="$(head -n 1 "$git_http_log" | tr -d '[:space:]')"
        if [[ -n "$port" ]]; then break; fi
        sleep 0.5
    done
    if [[ -z "$port" ]]; then
        cat "$git_http_log" >&2 || true
        die "git-http-backend did not report a port (log above)" "fixture: $fixture"
    fi
    git_http="http://127.0.0.1:${port}"
    # The port answering a connection is not the same as the CGI working: ask it a
    # question and accept any HTTP answer, which is what a `git ls-remote` would get.
    served=0
    for _ in $(seq 1 20); do
        if answers_http "$git_http/"; then
            served=1
            break
        fi
        sleep 0.5
    done
    if [[ $served -ne 1 ]]; then
        cat "$git_http_log" >&2 || true
        die "git-http-backend is not answering on $git_http" \
            "the CGI ran and then did not serve; the log above is its own words"
    fi
    echo "git-http-backend is serving $git_http from $git_http_root"
    export GITIUP_CONFORMANCE_GIT_HTTP_URL="$git_http"
    export GITIUP_CONFORMANCE_GIT_ROOT="$git_http_root"
fi

# A bucket that was named but is not answering is a missing service, not a skip. The
# registrations would report it as required-and-absent, but the failure belongs here,
# with the words a human needs rather than a failed assertion in a test log.
if [[ $strict -eq 1 && -n "${GITIUP_S3_LIVE_ENDPOINT:-}" ]] &&
    ! answers_http "$GITIUP_S3_LIVE_ENDPOINT"; then
    die "the bucket endpoint is not answering at $GITIUP_S3_LIVE_ENDPOINT" \
        "MINIO names an endpoint that is not there, or is not up yet." \
        "start one, or point MINIO at one that is, or drop the demand:  $0"
fi

if [[ $strict -eq 1 ]]; then
    hosts=(fs git-file git-http s3-memory)
    if [[ -n "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then hosts+=(s3-minio); fi
    export GITIUP_CONFORMANCE_REQUIRE_HOSTS="$(
        IFS=,
        echo "${hosts[*]}"
    )"
    # A bucket that cannot do conditional writes cannot gate a merge, and a run that
    # measured one while believing it measured MinIO is the drift this script exists to
    # catch. (moto is the endpoint that needs the opposite: see `hosts::live`.)
    export GITIUP_CONFORMANCE_REQUIRE_CAS="${GITIUP_CONFORMANCE_REQUIRE_CAS:-1}"
fi
if [[ $quick -eq 1 ]]; then
    export GITIUP_CONFORMANCE_PACK_BYTES="${GITIUP_CONFORMANCE_PACK_BYTES:-262144}"
    export GITIUP_CONFORMANCE_LIST_COUNT="${GITIUP_CONFORMANCE_LIST_COUNT:-32}"
    export GITIUP_CONFORMANCE_REF_COUNT="${GITIUP_CONFORMANCE_REF_COUNT:-8}"
fi

features=(--features s3,github)
# The two change bodies, named so a CI log says which half of the workflow a host failed.
change_bodies=(
    a_change_goes_from_proposal_to_merge_and_merges_once
    a_stale_base_merge_is_refused_the_same_way_everywhere
)
# The two policy bodies, named for the same reason: a host that cannot serve a published
# policy is not a host a merge gate can live on, and the CI log should say that in words.
policy_bodies=(
    a_published_policy_is_read_back_from_the_store
    a_refused_policy_publish_writes_nothing
)

say "format check"
cargo fmt --all -- --check

say "clippy"
cargo clippy -p gitiup-host-tests "${features[@]}" --all-targets -j 3

say "the suite"
cargo test -p gitiup-host-tests "${features[@]}" -j 3

say "the matrix"
cargo run -p gitiup-host-tests "${features[@]}" --example report -j 3

# The change workflow, one step of its own, because it is the promise the change design
# makes and the one a single host can keep while the others do not: propose → re-attempt
# → list → show → merge → merge-again-refused, and a stale base refused with one kind on
# all four hosts. The live hosts are demanded above, so with `--strict` a bucket or a
# served repository that is not there fails this step instead of narrowing it.
say "the change workflow, on every host"
cargo test -p gitiup-host-tests "${features[@]}" -j 3 \
    --test fs --test git --test s3_memory --test github --test s3_minio \
    -- --nocapture "${change_bodies[@]}"

# The published policy, one step of its own, for the same reason the change bodies have
# one: the promise being measured is that a stranger with a fresh clone can read the rules
# from the store itself, and "the store" is whichever transport the owner happened to
# choose. The fs host alone proves nothing about a pointer commit or a conditional write.
say "the published policy, on every host"
cargo test -p gitiup-host-tests "${features[@]}" -j 3 \
    --test fs --test git --test s3_memory --test github --test s3_minio \
    -- --nocapture "${policy_bodies[@]}"

# ...and across two of them: published on the bucket, read and merged through the
# plain-git host, with identical digests from both. With a live endpoint this crosses a
# real MinIO and a real git-http-backend, which is the pair an owner and a contributor
# actually use.
say "a change published on the bucket and merged through the plain-git host"
cargo test -p gitiup-host-tests "${features[@]}" -j 3 --test change_across_hosts -- --nocapture
if [[ -n "${GITIUP_S3_LIVE_ENDPOINT:-}" ]]; then
    say "the same change across the live bucket and the served repository"
    cargo test -p gitiup-host-tests --features s3 -j 3 --test change_across_hosts -- \
        the_live_bucket_publishes_and_the_served_repository_merges --nocapture
else
    say "the same change across the live bucket and the served repository"
    echo "skipped: no live bucket to cross (pass --live or --minio, or set MINIO=<url>)." >&2
fi

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

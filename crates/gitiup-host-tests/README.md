# gitiup-host-tests

The shared host conformance suite: the one place that answers "is this really a
gitiup host?" for every host in the workspace — and the CI wiring that runs the
answer against real backends.

gitiup can be hosted by a directory, a bare repository, a bucket, or a forge. The
moment there is more than one, there is a second question: *do they mean the same
thing?* Without a shared suite the answer arrives as a lost merge or a signature
that will not verify — a bucket accepting a write the git host would have
refused, a listing one page short, an expired credential reported as "no
changes". This crate is where that gets caught instead.

## Run it

```console
$ cargo test -p gitiup-host-tests                        # hermetic hosts only
$ cargo test -p gitiup-host-tests --features s3,github   # plus the transport shapes
$ cargo run -p gitiup-host-tests --features s3,github --example report
                                                         # every host, every body, one log
$ ./ci/host-conformance.sh                               # the whole matrix, MinIO included
```

The full suite lives in CI (`.github/workflows/host-conformance.yml`), which
starts a MinIO and a `git-http-backend` service, demands both
(`GITIUP_CONFORMANCE_REQUIRE_HOSTS` — a service that failed to start fails the
job instead of skipping quietly), raises the sizes past a bucket's own 1 000-key
page and 8 MiB part boundary, and finishes with a step whose credentials are
revoked and which therefore has to be refused.

`ci/host-conformance.sh` is the same sequence locally: hermetic hosts by default,
`--minio` to start a bucket in a container, `MINIO=<url>` to point at one you
started, `--strict` to demand what CI demands. The refused-credential steps run
when the endpoint can answer them (`--denied`; implied by `--minio`) — a fake that
accepts any credentials without checking them makes that body *fail*, on purpose.

## The bodies

| edge | body |
|------|------|
| empty repository | `a_fresh_store_is_empty_then_writable` |
| ref CAS conflict | `cas_conflicts_are_reported`, `concurrent_ref_writers_never_lose_one` |
| ref deletion | `ref_deletion_is_conditional` |
| pack round-trip | `pack_round_trip_between_two_hosts`, `a_huge_pack_round_trips_intact` |
| blob listing and pagination | `blobs_round_trip`, `listings_are_complete_across_pages` |
| expired / refused credentials | `refused_credentials_are_denied_not_dropped` |
| `cas = false` degradation | `a_host_without_cas_refuses_cas_writes` |
| unsupported operations | `unsupported_operations_are_refused_by_name` |
| forgetting one object (retention) | `one_object_is_forgotten_or_the_refusal_says_why` |
| multi-ref atomicity | `multi_ref_writes_are_all_or_nothing` |
| capability honesty | `describe_and_capabilities` |

Every body runs against a **fresh** store, and each is a `#[test]` of its own, so
a diverging host shows up by name and is rerunnable with `--exact`.

## The hosts measured here

| host | shape | refused-credentials variant | `cas = false` variant |
|------|-------|-----------------------------|------------------------|
| `fs` | a scratch directory | — (auth model is the filesystem) | — (a lock file always offers CAS) |
| `git-file` | a bare repository over `file://` | — (authorised by the filesystem) | — (leases are always available) |
| `git-http` | a bare repository served by `git-http-backend` | an endpoint that answers 403 to everything | the same repository published to a static file server |
| `s3-memory` | a bucket that is a second implementation of the transport contract | a bucket that answers 403 to everything | a bucket whose endpoint ignores conditional writes |
| `s3-minio` | a live MinIO/S3 bucket (feature `s3`) | CI's revoked-credential step | the same endpoint told `conditional-writes = "off"` |
| `github` | the adapter, against the in-process mock forge (feature `github`) | a forge that answers 401 | — (the mock refuses rather than ignores) |

## Adding a host

Implement the traits, then write one `Registration` and instantiate the suite:

```ignore
// crates/my-host/tests/conformance.rs
gitiup_host_tests::test_host!(my_host, my_host_crate::conformance::MY_HOST);
```

`Registration` is where a host says what it can produce; a body it neither runs
nor explains is a failing test, and a body it skips is printed in the CI log. Add
the registration to `hosts::all`, add it to `tests/*.rs`, and add it to the CI
matrix — `tests/coverage.rs` fails if any of those three drifts.

## Environment

| variable | effect |
|----------|--------|
| `GITIUP_CONFORMANCE_REQUIRE_HOSTS` | comma-separated host names that must be available; a skip becomes a failure |
| `GITIUP_CONFORMANCE_REQUIRE_CAS` | `1`: a host that reports `cas = false` may not skip the CAS bodies (the live bucket demands CAS by default; set `0` to relax) |
| `GITIUP_CONFORMANCE_PACK_BYTES`, `GITIUP_CONFORMANCE_LIST_COUNT`, `GITIUP_CONFORMANCE_REF_COUNT` | raise the size-shaped bodies without recompiling |
| `GITIUP_CONFORMANCE_GIT_HTTP_URL`, `GITIUP_CONFORMANCE_GIT_ROOT` | a smart-HTTP server to use instead of the fixture this suite starts |
| `GITIUP_S3_LIVE_ENDPOINT`, `GITIUP_S3_LIVE_BUCKET`, `GITIUP_S3_LIVE_REGION` | the live bucket to measure (see `hosts::live`) |
| `GITIUP_CONFORMANCE_S3_DENIED` | `1`: the credentials in this process are the ones the bucket refuses |
| `GITIUP_S3_LIVE_ALLOW_UNVERSIONED` | `1`: accept a bucket whose versioning the SDK cannot confirm (moto needs this; MinIO and S3 do not) |

### The live bucket

The suite owns the bucket it is pointed at. Every store it makes lives under a
`conformance-<shape>-<process>-<n>/` prefix — unique per store, so the bodies can
run in parallel without turning each other's create-only writes into conflicts —
and the first thing a run does is clear that prefix, so a bucket that outlived the
last run cannot hand `a_fresh_store_is_empty_then_writable` a store with refs in
it. Point two runs at the same bucket at once and they will sweep each other: use
`GITIUP_S3_LIVE_BUCKET` to separate them instead.

Nothing in this crate is linked into a release build: `gitiup` does not depend on
it, and the hermetic default run touches no network and needs no credentials.

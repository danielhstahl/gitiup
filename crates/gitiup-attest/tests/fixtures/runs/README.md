# Golden run-digest vectors

The bytes here are the contract for the *computation* (ticket `giti-1rs.2`), the
way [`../v1`](../v1/README.md) is the contract for the *format*. Another
implementation of the runner must produce these digests from these reports — that
is what "a third party can recompute the RunDigest" means in practice.

## Layout

```text
cases.json                 index: per case, the note, tier, normalisation version,
                           step count, run_digest and result_digest (pretty-printed,
                           not signed)
hello/run.json             the run report: what the runner handed over
hello/manifest.json        the canonical manifest bytes that report computes to
matrix-build/…             matrix arm: pins, inputs, secrets, closure, artifacts
image-build-skipped/…      digest-pinned image, toolchain inventory, a skipped step
test-failure/…             a failing run: exit codes, stderr, a skipped follow-on
dispatch-release/…         every input type, a sha256 commit, quorum-side claims
```

`run.json` is pretty-printed and its layout means nothing: a report is a transport,
not a signed document, and the digest of the run it describes is unchanged however
it is formatted. `manifest.json` is different — those are the canonical bytes that
get signed and stored, so they are committed exactly, with no trailing newline.

## What each case is for

| case | why it is here |
|------|----------------|
| `hello` | the floor: one simulated step, workflow source and logs handed over in the clear, so the digest is checkable against the bytes you can read |
| `matrix-build` | the `result` half fully populated — matrix vector, two pins, inputs of all three types, secret names, a two-entry reusable-workflow closure, a file-set artifact, a digest-pinned image, three toolchain entries, timings as claims |
| `image-build-skipped` | a conditional step that never ran (`skipped` is not `success`), an aarch64 machine, and a pre-hashed artifact that carries its declared size |
| `test-failure` | a failing run is provable too: exit code 101, non-empty stderr, a skipped follow-on |
| `dispatch-release` | `workflow_dispatch` with an action, a `sha256`-format commit, a multipart event payload, a step-level and a claims-level timing, a validity window, a quorum challenge and a normalisation diff |

## Regenerating

```sh
GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_run_fixtures
```

Only ever with an ADR saying why
([ADR-0001 D8](../../../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
A new case is added to `examples/make_run_fixtures.rs::CASES` and stays forever;
an existing case is never edited, because old digests in other people's buckets
have to keep verifying.

## Checking them

```sh
cargo test -p gitiup-attest --test run_digest_golden    # digests + committed bytes
cargo test -p gitiup-attest --test run_digest_properties # order, whitespace, idempotence
cargo run -p gitiup -- digest hello/run.json            # the same numbers on a terminal
```

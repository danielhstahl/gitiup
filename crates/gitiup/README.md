# gitiup (CLI)

The command line. Thin on purpose: every rule about *what a digest is* lives in
[`gitiup-attest`](../gitiup-attest/README.md), and this crate only reads a run
report, calls that crate and prints. Two reasons to insist on that:

* the number printed here and the number a stranger recomputes must be the same
  number, so there is exactly one implementation of the computation;
* the format crate does no I/O (so it can run in a `pre-receive hook` and in a
  test), and the host crate owns storage — reading a report off disk belongs to
  neither, so it belongs here.

## `gitiup digest`

```console
$ gitiup digest crates/gitiup-attest/tests/fixtures/runs/hello/run.json
run            sha256:5b71fcfdccb72830d84e1423292ede463d2216fe72c2a4cab2e3b354b8deb819
result         sha256:28c73827c9a5506837c179128bca275f7f0ef42d84375f1b408573cfd62e82e4
tier           simulated
runner         gitiup 0.1.0
commit         sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
workflow       .github/workflows/hello.yml sha256:cc8c24530e48…
event          push
job            hi
environment    x86_64 · fingerprint sha256:b3bad75a23bc…
steps          1 (1 succeeded, 0 failed, 0 skipped)
normalisation  v0
```

```text
gitiup digest [OPTIONS] [REPORT]

    REPORT                 run-report JSON file, or - for stdin (default: stdin)
    --json                 machine-readable output (keys sorted, one line)
    -q, --quiet            print the RunDigest and nothing else
    --expect <digest>      exit 8 unless the RunDigest equals this
    --expect-result <d>    exit 8 unless the ResultDigest equals this
```

The input is a **run report** — the runner's record of a finished job; the format
is [documented here](../../docs/run-report.md). The two digests are the epic's
claim: `RunDigest` names the attestation, `ResultDigest` is what two independent
runs of the same change are supposed to agree on.

`--expect` is the reason this is a command and not just a library call:

```sh
# Re-run a job and prove it converged:
gitiup digest --expect "$(cat expected-digest)" run.json || echo "rerun disagrees (exit 8)"
```

Exit codes follow [ADR-0001 D7](../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
where they overlap, because gates branch on the numbers:

| exit | meaning |
|------|---------|
| 0 | digest computed (and it was the one we were told to expect) |
| 2 | usage: unknown flag, missing value, no report on stdin |
| 3 | I/O: the report could not be read |
| 6 | the report is not a valid run report, or this build cannot read it |
| 8 | digest mismatch: the rerun disagreed with `--expect` |

## What is deliberately *not* here yet

signing and key management (giti-1rs.6), storing or fetching attestations
(giti-1rs.5), `gitiup verify attestation` (giti-1rs.8), and the runner that
writes these reports in the first place. `digest` is the slice that exists once
the format does, which is the point: the computation is checkable from the command
line before any of the machinery around it is built.

## Tests

* `tests/digest_cli.rs` — runs the built binary: both digests, stdin, `--json`,
  `--quiet`, `--expect` both ways, every exit code, and the committed golden
  fixtures (so the CLI cannot drift from the pinned vectors).
* `tests/doc_examples.rs` — the worked report in `docs/run-report.md`, parsed and
  digested: the documentation example is the pinned example.
* `tests/cli_hygiene.rs` — the dependency list stays at two crates, no network or
  forge client is reachable from here, and the documented exit codes are the ones
  the code uses.

## Building

```sh
cargo build -p gitiup
cargo test -p gitiup
```

Dependencies: `gitiup-attest`, `serde_json`. No argument parser, no HTTP client,
no C toolchain.

# gitiup

Run GitHub Actions locally, and contribute without a forge.

Two goals, one tool:

1. **Local, sandboxed action execution.** Interpret workflow and action syntax and
   execute it locally, so CI output can be reproduced — and proven — off GitHub.
2. **Federated contribution.** A repo can live in a plain S3 bucket or a bare git
   repo: changes, signed attestations and merge gates are carried by refs and
   content-addressed records instead of a forge database.

`gitiup` is pronounced like spurring on a horse.

## Workspace

| crate           | what it is                                                       |
|-----------------|------------------------------------------------------------------|
| `gitiup`        | the command line: `gitiup run` plans (or, told to, runs) a workflow job, `gitiup digest` turns a local run report into the digests a stranger can check — the only crate that reads files, so the format crate can stay I/O-free |
| `gitiup-run`    | workflow planning and provenance: reads a workflow file, expands a matrix into runs, and produces either a **simulated** report (the default: nothing spawned, nothing read) or an **executed** one inside a sandbox that was probed first — which is where the tier is decided, because that is the only place the difference between "planned" and "ran" is a fact |
| `gitiup-host`   | the host abstraction: `RefStore` + `BlobStore` + `Host`, the `fs` and `s3` (bucket-as-forge) hosts, and `gitiup.toml` remote config |
| `gitiup-attest` | the attestation format: canonical manifests, digests, Ed25519 signatures and freshness policy — the bytes ADR-0001 decides, and nothing else |
| `gitiup-normalise` | output normalisation: the profile that turns the machine-specific parts of a log into placeholders so independent reruns converge on one digest, and the record of what it rewrote |

Later work adds the runner, quorum and CLI crates under `crates/`; the
workspace globs `crates/*`, so a new crate is just `members`-free.

* [ADR-0001 — attestation encoding, hash and signature format](docs/adr/0001-attestation-encoding-hash-and-signature.md) —
  the format every attestation ticket codes against (canonical JSON, SHA-256, Ed25519
  over DSSE PAE, `result`/`claims` split, freshness as policy).
  The decisions are in the ADR, the implementation is
  [`gitiup-attest`](crates/gitiup-attest/README.md).
* [ADR-0002 — roster, verifiable selection and sybil resistance](docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md) —
  who may verify, how the five are picked so anyone can audit the pick afterwards, and
  what a key has to cost to get in. The selection algorithm there has a byte-for-byte
  reference implementation and golden vectors in
  [`docs/adr/fixtures/selection-v1/`](docs/adr/fixtures/selection-v1/).
* [Provenance tiers](docs/provenance-tiers.md) — what `simulated`, `local` and `quorum`
  each claim, why simulation is the safe default, why a single run can never claim
  `quorum`, and what a policy file may insist on.
* [The run report](docs/run-report.md) — the JSON a runner writes, and the recipe
  that turns it into a `RunDigest` (`RunManifest::from_run`, `gitiup digest`).
* [Reproducibility — the contract](docs/reproducibility.md) — what a workflow must do
  so its products are the same bytes twice (pin by SHA, images by digest, sorted
  manifests, `SOURCE_DATE_EPOCH`), what the runner rewrites instead (the twelve
  rules), and how a divergence is reported.
* [Host abstraction design notes](docs/host-abstraction.md) — the contracts every
  host owes, including the ref namespaces, store layout, pack format and error
  taxonomy.
* [`gitiup-host` README](crates/gitiup-host/README.md) — the API surface.
* [`gitiup-normalise` README](crates/gitiup-normalise/README.md) — the normalisation
  profile and its version story.
* [ADR index](docs/adr/README.md) — where the decisions that several tickets depend on
  are kept.

## Building

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

The `s3` host (a repo in a plain bucket) is always compiled; the AWS transport
behind it is a feature, so a default build links no HTTP or AWS code:

```sh
cargo build -p gitiup-host --features s3
```

Try it out without any infrastructure:

```sh
cargo run -p gitiup-run --example plan      # what a workflow would run, and what it assumed
cargo run -p gitiup -- run                  # the same in your own repo (.github/workflows)
cargo run -p gitiup -- run --help           # the tiers, and what it takes to earn each
cargo run -p gitiup -- digest crates/gitiup-attest/tests/fixtures/runs/hello/run.json
cargo run -p gitiup -- digest --json crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json
cargo run -p gitiup -- normalise crates/gitiup-normalise/tests/fixtures/corpus/machine-a/run.json
cargo run -p gitiup -- normalise --compare \
    crates/gitiup-normalise/tests/fixtures/corpus/machine-a/run.json \
    crates/gitiup-normalise/tests/fixtures/corpus/machine-b/run.json
cargo run -p gitiup-host --example fs_tour        # refs, CAS, packs on a temp dir
cargo run -p gitiup-host --example s3_tour        # the same against an in-process S3 bucket
cargo run -p gitiup-host --example remote_show    # render examples/gitiup.toml
```

`gitiup run` plans a job by default — no process, no network, no secrets, and an
attestation that says `tier: simulated` — and only runs the steps when given
`--execute` inside a sandbox it could probe. See
[provenance tiers](docs/provenance-tiers.md) for what each tier licenses you to believe.

`gitiup digest` prints the `RunDigest` and `ResultDigest` of a run report — the same
two numbers a third party recomputes from the signed attestation, from the same
function. `--expect` makes "did this rerun converge?" a single command that exits 8
when it did not.

## Where the design docs live

Decisions that several tickets depend on are written down in `docs/` (or as an
ADR next to the crate they concern), so a ticket can be implemented without
re-deciding the foundations. Cross-cutting decisions live in
[`docs/adr/`](docs/adr/README.md); one-off rationale belongs in the code it explains.

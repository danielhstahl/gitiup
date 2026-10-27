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
| `gitiup-host`   | the host abstraction: `RefStore` + `BlobStore` + `Host`, the `fs` and `s3` (bucket-as-forge) hosts, and `gitiup.toml` remote config |
| `gitiup-attest` | the attestation format: canonical manifests, digests, Ed25519 signatures and freshness policy — the bytes ADR-0001 decides, and nothing else |

Later work adds the runner, quorum and CLI crates under `crates/`; the
workspace globs `crates/*`, so a new crate is just `members`-free.

* [ADR-0001 — attestation encoding, hash and signature format](docs/adr/0001-attestation-encoding-hash-and-signature.md) —
  the format every attestation ticket codes against (canonical JSON, SHA-256, Ed25519
  over DSSE PAE, `result`/`claims` split, freshness as policy).
  The decisions are in the ADR, the implementation is
  [`gitiup-attest`](crates/gitiup-attest/README.md).
* [Host abstraction design notes](docs/host-abstraction.md) — the contracts every
  host owes, including the ref namespaces, store layout, pack format and error
  taxonomy.
* [`gitiup-host` README](crates/gitiup-host/README.md) — the API surface.
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
cargo run -p gitiup-host --example fs_tour        # refs, CAS, packs on a temp dir
cargo run -p gitiup-host --example s3_tour        # the same against an in-process S3 bucket
cargo run -p gitiup-host --example remote_show    # render examples/gitiup.toml
```

## Where the design docs live

Decisions that several tickets depend on are written down in `docs/` (or as an
ADR next to the crate they concern), so a ticket can be implemented without
re-deciding the foundations. Cross-cutting decisions live in
[`docs/adr/`](docs/adr/README.md); one-off rationale belongs in the code it explains.

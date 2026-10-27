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
| `gitiup-host`   | the host abstraction: `RefStore` + `BlobStore` + `Host`, the `fs` reference host, and `gitiup.toml` remote config |

Later work adds the runner, attestation and quorum crates under `crates/`; the
workspace globs `crates/*`, so a new crate is just `members`-free.

* [Host abstraction design notes](docs/host-abstraction.md) — the contracts every
  host owes, including the ref namespaces, store layout, pack format and error
  taxonomy.
* [`gitiup-host` README](crates/gitiup-host/README.md) — the API surface.

## Building

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

Try it out without any infrastructure:

```sh
cargo run -p gitiup-host --example fs_tour        # refs, CAS, packs on a temp dir
cargo run -p gitiup-host --example remote_show    # render examples/gitiup.toml
```

## Where the design docs live

Decisions that several tickets depend on are written down in `docs/` (or as an
ADR next to the crate they concern), so a ticket can be implemented without
re-deciding the foundations.

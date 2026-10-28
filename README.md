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
| `gitiup`        | the command line: `gitiup run` plans (or, told to, runs) a workflow job, `gitiup digest` turns a local run report into the digests a stranger can check, `gitiup select` shows (or opens) the quorum for one change — the only crate that reads files, so the format crate can stay I/O-free |
| `gitiup-run`    | workflow planning and provenance: reads a workflow file, expands a matrix into runs, and produces either a **simulated** report (the default: nothing spawned, nothing read) or an **executed** one inside a sandbox that was probed first — which is where the tier is decided, because that is the only place the difference between "planned" and "ran" is a fact |
| `gitiup-host`   | the host abstraction: `RefStore` + `BlobStore` + `Host`, the `fs`, `s3` (bucket-as-forge) and plain-git hosts (a bare repo over `file://`, `ssh://` or HTTP), and `gitiup.toml` remote config |
| `gitiup-host-github` | the github adapter, behind the CLI's `hosts-github` feature: the pull request database as `ChangeRecord`s, check runs as `AttestationRecord`s, token auth, pagination and rate limits — every forge call in the workspace, in one optional crate the core does not know exists |
| `gitiup-host-tests` | the host conformance suite: one set of bodies every host must satisfy (empty store, CAS conflict, pack round-trip, huge pack, paged listings, ref deletion, refused credentials, unsupported operations, `cas = false`), run against the `fs`, plain-git, bucket and forge hosts — in CI, against real backends |
| `gitiup-attest` | the attestation format: canonical manifests, digests, Ed25519 signatures and freshness policy — the bytes ADR-0001 decides, and nothing else |
| `gitiup-keys` | signing keys and identities: an age-encrypted keystore, ssh-agent and gpg-agent backends, and the signed identity claim that says "this key is mine" — every one of them a `gitiup_attest::Signer`, so a key's origin never changes the signature it produces |
| `gitiup-normalise` | output normalisation: the profile that turns the machine-specific parts of a log into placeholders so independent reruns converge on one digest, and the record of what it rewrote |
| `gitiup-sandbox`  | the isolation ladder: container runtimes, bubblewrap, Landlock + seccomp in the child, `unshare(1)`, and an opt-in rung that admits it isolates nothing — each one probed rather than assumed, each refused rather than worked around, plus the default-deny egress proxy and the escape suite that proves the claim |
| `gitiup-quorum` | the optional quorum network: the roster, deterministic and auditable verifier selection, round records, per-seat attestation storage and the verdict (`verified` / `failed` / `insufficient`) — ADR-0002 as code, and nothing else |

The workspace globs `crates/*`, so a new crate is just `members`-free.

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
* [The sandbox](docs/sandbox.md) — what `provenance.sandbox` is allowed to claim, the
  ladder (`docker`/`podman` → `bwrap` → Landlock → `unshare` → opt-in `plain`), what each
  rung denies and what it does not, how egress is refused by default, and what the escape
  suite actually checks. `gitiup doctor --sandbox` says which of it is true on your
  machine.
* [Provenance tiers](docs/provenance-tiers.md) — what `simulated`, `local` and `quorum`
  each claim, why simulation is the safe default, why a single run can never claim
  `quorum`, and what a policy file may insist on.
* [The quorum verification network](docs/quorum.md) — how the five are picked and
  audited, what the store holds, what a verdict means, and which parts are still open
  tickets. Implementation: [`gitiup-quorum`](crates/gitiup-quorum/README.md).
* [The run report](docs/run-report.md) — the JSON a runner writes, and the recipe
  that turns it into a `RunDigest` (`RunManifest::from_run`, `gitiup digest`).
* [Signing keys and identities](docs/signing-keys.md) — where a private key lives
  (`gitiup key gen`, an age + scrypt container), how an existing ssh or gpg key is
  imported without ever being copied, what an identity claim signs and why, and which
  exit code each failure gets.
* [The environment fingerprint](docs/environment.md) — what a run says about the
  machine it ran on (OS and version, architecture, image digest *or* local toolchain
  inventory, runner, sandbox backend), how it is derived, and how `require-env-match =
  strict|major|off` turns a difference into a sentence instead of a mystery.
* [Reproducibility — the contract](docs/reproducibility.md) — what a workflow must do
  so its products are the same bytes twice (pin by SHA, images by digest, sorted
  manifests, `SOURCE_DATE_EPOCH`), what the runner rewrites instead (the twelve
  rules), and how a divergence is reported.
* [Host abstraction design notes](docs/host-abstraction.md) — the contracts every
  host owes, including the ref namespaces, store layout, pack format and error
  taxonomy.
* [`gitiup-host` README](crates/gitiup-host/README.md) — the API surface.
* [`gitiup-host-github` README](crates/gitiup-host-github/README.md) — the forge
  adapter: what a pull request and a check run become, what a forge admits it cannot
  promise, and how to build without it.
* [`gitiup-host-tests` README](crates/gitiup-host-tests/README.md) — the conformance
  suite: the bodies every host owes, the `test_host!` macro that runs them, how a host
  says "this one does not apply to me" out loud, and how CI runs the whole matrix
  against MinIO and a real `git-http-backend`.
* [`gitiup-normalise` README](crates/gitiup-normalise/README.md) — the normalisation
  profile and its version story.
* [`gitiup-keys` README](crates/gitiup-keys/README.md) — the keystore, the agent
  backends and the identity claim: what is on disk, what is never written, and which
  backend produced which signature.
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
cargo run -p gitiup -- key gen --comment ada@laptop          # a new signing key, age-encrypted
cargo run -p gitiup -- identity publish ada --email ada@example.com --passphrase-file -
cargo run -p gitiup -- identity whoami --check              # "can this machine still sign?"
cargo run -p gitiup -- normalise crates/gitiup-normalise/tests/fixtures/corpus/machine-a/run.json
cargo run -p gitiup -- normalise --compare \
    crates/gitiup-normalise/tests/fixtures/corpus/machine-a/run.json \
    crates/gitiup-normalise/tests/fixtures/corpus/machine-b/run.json
cargo run -p gitiup-host --example fs_tour        # refs, CAS, packs on a temp dir
cargo run -p gitiup-host --example s3_tour        # the same against an in-process S3 bucket
cargo run -p gitiup-host --example git_tour       # the same against a bare repo, with plain git seeing it all
cargo run -p gitiup-host --example remote_show    # render examples/gitiup.toml
```

The plain-git host drives the `git` binary, so `tests/host_git.rs` and
`tests/host_git_http.rs` need git installed (they skip themselves when it is
missing) and the HTTP ones need `python3` for `git-http-backend` and for the
static server that stands in for "a repo on a web server".

The hosts all get run against one contract instead:

```sh
cargo test -p gitiup-host-tests --features s3,github   # every hermetic host
./ci/host-conformance.sh --minio                       # plus a live MinIO bucket
```

That is what `.github/workflows/host-conformance.yml` does, with a MinIO service
and a `git-http-backend` service, and it fails rather than skips when a service
is missing. See [`gitiup-host-tests`](crates/gitiup-host-tests/README.md).

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

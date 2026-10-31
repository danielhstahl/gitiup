# gitiup

Run GitHub Actions locally, and contribute without a forge.

Two goals, one tool:

1. **Local, sandboxed action execution.** Interpret workflow and action syntax and
   execute it locally, so CI output can be reproduced — and proven — off GitHub.
2. **Federated contribution.** A repo can live in a plain S3 bucket or a bare git
   repo: changes, signed attestations and merge gates are carried by refs and
   content-addressed records instead of a forge database.

`gitiup` is pronounced like spurring on a horse.

**New here?** [The quickstart](docs/quickstart.md) is the tool in fifteen minutes — plan a
job, run it for real, sign the proof, file it, and merge a change into a repository that
has no forge — and every command line on that page is executed by
[`quickstart_doc_cli.rs`](crates/gitiup/tests/quickstart_doc_cli.rs).

## Workspace

| crate           | what it is                                                       |
|-----------------|------------------------------------------------------------------|
| `gitiup`        | the command line: `gitiup run` plans (or, told to, runs) a workflow job, `gitiup digest` turns a local run report into the digests a stranger can check, `gitiup attest push/list/show/gc/migrate` files a signed attestation in a host store and reads it back, `gitiup change new/submit/list/show` drafts and publishes a signed change record to any store — `submit` also opens the quorum rounds the store's published policy asks for, one per job per matrix arm — and `change merge` merges one under compare-and-swap, `gitiup verify attestation` decides whether a proof may be acted on (exit 0/6/7/8, `--json` for a merge gate), `gitiup select` shows (or opens) the quorum for one change, `gitiup quorum verdict` tallies every round a store holds for a change — verified / failed / insufficient, exit 0/6/7/8, `--publish` files the signed verdict, `gitiup quorum dispute` reads the evidence behind that answer out loud — the distinct result digests and their counts, the seats with the sandbox rung each used and each machine's environment fingerprint, and the losing logs as a raw diff and a normalised one side by side — and `gitiup quorum retry` escalates a disputed job to `attempt + 1` with a fresh seed and selection under the policy's attempt cap (exit 9 once it is exhausted) — `gitiup work` is the volunteer's loop (poll for rounds addressed to this key, check the invitation, lease a seat, run the job in a sandbox, sign it, publish it — and on a sealed round, commit to the bytes before revealing them), `gitiup policy publish/show` signs the policy a merge gate applies into the store and says which one is in force, `gitiup policy check/explain` asks whether one commit or change satisfies it, `gitiup hook install pre-receive` puts that answer in front of the refs themselves — a `refs/heads/**` update whose new head has no policy-satisfying proof set is refused and the ref does not move, `refs/changes/**` and `refs/gitiup/**` stay open by design, and `gitiup hook status` / `doctor --hooks` say which policy is in force and whether proof is required at all — the only crate that reads files, so the format crate can stay I/O-free |
| `gitiup-run`    | workflow planning and provenance: reads a workflow file, expands a matrix into runs, and produces either a **simulated** report (the default: nothing spawned, nothing read) or an **executed** one inside a sandbox that was probed first — which is where the tier is decided, because that is the only place the difference between "planned" and "ran" is a fact |
| `gitiup-host`   | the host abstraction: `RefStore` + `BlobStore` + `Host`, the `fs`, `s3` (bucket-as-forge) and plain-git hosts (a bare repo over `file://`, `ssh://` or HTTP), `gitiup.toml` remote config, and where attestations live — `kv/attestation/<digest>` advertised by `refs/attestations/<subject>/<digest>`, with the retention policy (`max age`, `max per commit`) and the rule above it: an object another live ref still points at is never pruned — and the credential scope: a token belongs to the one origin its own remote names, and a redirect, a rewrite or a host read out of somebody else's `gitiup.toml` is refused with exit 3 naming both hosts |
| `gitiup-host-github` | the github adapter, behind the CLI's `hosts-github` feature: the pull request database as `ChangeRecord`s, check runs as `AttestationRecord`s, token auth, pagination and rate limits — every forge call in the workspace, in one optional crate the core does not know exists |
| `gitiup-host-tests` | the host conformance suite: one set of bodies every host must satisfy (empty store, CAS conflict, pack round-trip, huge pack, paged listings, ref deletion, refused credentials, unsupported operations, forgetting one object, `cas = false`, the change workflow from proposal to merge, a stale base refused with the same kind everywhere, a public store read by a stranger with nothing to show, and a credential driven at a redirect that must never deliver it), run against the `fs`, plain-git, bucket and forge hosts — plus a change published on the bucket and merged through the plain-git host, with identical digests from both — in CI, against real backends |
| `gitiup-attest` | the attestation format: canonical manifests, digests, Ed25519 signatures, freshness policy and the verification verdict (ladder, reasons, exit codes) — the bytes ADR-0001 decides, and nothing else |
| `gitiup-keys` | signing keys and identities: an age-encrypted keystore, ssh-agent and gpg-agent backends, and the signed identity claim that says "this key is mine" — every one of them a `gitiup_attest::Signer`, so a key's origin never changes the signature it produces |
| `gitiup-normalise` | output normalisation: the profile that turns the machine-specific parts of a log into placeholders so independent reruns converge on one digest, and the record of what it rewrote |
| `gitiup-sandbox`  | the isolation ladder: container runtimes, bubblewrap, Landlock + seccomp in the child, `unshare(1)`, and an opt-in rung that admits it isolates nothing — each one probed rather than assumed, each refused rather than worked around, plus the default-deny egress proxy and the escape suite that proves the claim |
| `gitiup-quorum` | the optional quorum network: the roster, deterministic and auditable verifier selection, round records, the advertisement and the TTL lease that let a stranger find a seat and lean on it, per-seat attestation storage — open, or committed-then-revealed when the policy seals the round — the verdict (`verified` / `failed` / `insufficient`), the `tier: quorum` attestation only a verified verdict can produce, the bounded escalation and its attempt cap, plus the published policy a gate applies — its format, its trust and coherence checks, the resolution ladder and the provenance every answer carries: ADR-0002 and ADR-0004 as code, and nothing else |

The workspace globs `crates/*`, so a new crate is just `members`-free.

* [Quickstart](docs/quickstart.md) — the tool in fifteen minutes, in the order a newcomer
  should meet it: a simulated plan, a real run in a sandbox, a signed proof in a store, a
  policy, a change merged into a repository with no forge, and a push refused for having
  no proof. Every command line there is executed
  ([`quickstart_doc_cli.rs`](crates/gitiup/tests/quickstart_doc_cli.rs)).
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
* [ADR-0004 — published policy format, signing and resolution](docs/adr/0004-published-policy-format-signing-and-resolution.md) —
  the policy a merge gate applies lives in the store and is signed, not in a checkout
  where a fork could edit it; which policy was in force *when the run happened*, walked
  from the chain; and the token-and-exit-code vocabulary every refusal shares. Its
  vectors — two digests, five real signatures, a two-revision chain and 32 refusals —
  are reproduced in Rust by
  [`docs/adr/fixtures/policy-v1/`](docs/adr/fixtures/policy-v1/).
* [ADR-0005 — what a mirror may carry, and what a copy is worth](docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md) —
  decided before anyone writes a sync command, because import is one `for` loop away from
  laundering: a copy transfers bytes and never trust, the portable set is the verification
  closure (and leases, pending sign-ups and every "as of now" pointer are not in it), a
  mirror may serve bytes but may not attest to freshness it did not witness, and one
  store's `gc` is not allowed to destroy another's only copy. Its portability table and
  closure cases are generated vectors in
  [`docs/adr/fixtures/federation-v1/`](docs/adr/fixtures/federation-v1/), and the ADR's
  own tables are checked against them.
* [Federation — moving proofs between stores](docs/federation.md) — `gitiup fetch | push`:
  the two verbs that carry `refs/attestations/**`, `refs/changes/**` and the quorum records
  a proof leans on between any two hosts (a directory store, a bucket, a repository, a
  forge) using each host's own pack and CAS paths; what travels, what is refused out loud
  and by which token, why a pointer is resolved rather than copied, what an arrival record
  at `kv/import/<digest>` answers, and why the report says `trust none` on every run of
  every host pair. And `gitiup attest import`, the verb that checks what it copies: it walks
  each attestation's own citations instead of listing a namespace, runs the
  `gitiup verify attestation` ladder on every document before filing it, refuses a
  `tier: quorum` attestation whose round and reveals did not come with it, and records the
  verdict it reached here as an audit note and never as an inherited belief.
* [The sandbox](docs/sandbox.md) — what `provenance.sandbox` is allowed to claim, the
  ladder (`docker`/`podman` → `bwrap` → Landlock → `unshare` → opt-in `plain`), what each
  rung denies and what it does not, how egress is refused by default, and what the escape
  suite actually checks. `gitiup doctor --sandbox` says which of it is true on your
  machine.
* [Provenance tiers](docs/provenance-tiers.md) — what `simulated`, `local` and `quorum`
  each claim, why simulation is the safe default, why a single run can never claim
  `quorum`, and what a policy — the draft file and the published one — may insist on.
* [The published policy](docs/policy.md) — the rule a merge gate applies, in the store and
  signed by the repository's owner rather than in a checkout where a fork could edit it:
  what the document publishes, how it is signed and by whom, how a clone learns it, the
  resolution order and which sources a merge may rest on, and three worked examples — a
  personal repository accepting one local run, a project requiring four agreeing out of
  five, and a fork where the inheritance and the divergence are both visible. Every
  command line there is executed in CI
  ([`policy_doc_cli.rs`](crates/gitiup/tests/policy_doc_cli.rs)), and
  [`examples/gitiup-policy.json`](examples/gitiup-policy.json) is the policy file it
  documents.
* [The quorum verification network](docs/quorum.md) — how the five are picked and
  audited, what the store holds, the operator's tour (register → approve → open a round →
  work → verdict → merge) and the two ways it fails (nobody turned up, and they disagree),
  what a verdict means, and what is still open. Implementation:
  [`gitiup-quorum`](crates/gitiup-quorum/README.md).
* [The run report](docs/run-report.md) — the JSON a runner writes, and the recipe
  that turns it into a `RunDigest` (`RunManifest::from_run`, `gitiup digest`).
* [Verification](docs/verification.md) — what `gitiup verify attestation` checks and in
  which order, the exit codes a hook branches on (`0` accepted, `6` policy, `7` bad
  signature, `8` digest mismatch), the machine-readable verdict a merge gate reads,
  where the policy it applies comes from (the published policy first —
  [the policy document](docs/policy.md)), and what verification deliberately refuses to
  do.
* [Contributing without a forge](docs/changes.md) — `gitiup change new|submit|list|show`
  and `change merge`: the signed change record a stranger publishes when there is no pull
  request, what each command writes and in which order, why a moved base is an exit code,
  why a re-submit is an attempt rather than an overwrite, and what a merge records about
  itself when the branch has already moved.
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
* [Provable CI output](docs/provable-output.md) — the whole giti-1rs path in one place: run
  → digest → signature → store → `git fetch` → verdict; who does each part, the rules that make
  it hold, where every claim is executed as a test, and what it honestly does not promise.
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

Those are the shapes you type while working. The shapes a shipped binary passes
through are the same ones with `--release`, plus the two feature builds the code
makes promises about: `--no-default-features`, which must not link any forge code
at all (that absence is the point of the `hosts-github` feature, and it is only
auditable if the build actually compiles), and `--all-features`, which wires in
the AWS transport and the forge adapter. A gate that compiles one way is a gate
that is not real, so every one of them is built on push and on pull request, next
to the release build, the test targets, and a release build on the declared MSRV
(`rust-version = "1.88"`):

```sh
cargo build --release --locked                                # what ships
cargo build --release --locked -p gitiup --no-default-features # no forge code, as a binary
cargo +1.88 build --release --locked                          # the declared MSRV
```

All of that, with `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings`,
is what [`.github/workflows/build.yml`](.github/workflows/build.yml) runs; it exists because
"does it still compile" was otherwise a question only whoever happened to type the command
could answer.

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
cargo run -p gitiup -- verify attestation --help   # the ladder, and what each exit code means
cargo run -p gitiup -- policy show --policy examples/gitiup-policy.json   # what a policy file says
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
./ci/host-conformance.sh --live                        # what CI runs: a live MinIO and a
                                                       # real git-http-backend, demanded
```

That is what `.github/workflows/host-conformance.yml` does, with a MinIO service
and a `git-http-backend` service, and it fails rather than skips when a service
is missing — as does `--live`/`--strict` locally, which will not quietly narrow the
matrix because docker is not installed. See
[`gitiup-host-tests`](crates/gitiup-host-tests/README.md).

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

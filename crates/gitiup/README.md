# gitiup (CLI)

The command line. Thin on purpose: every rule about *what a digest is* lives in
[`gitiup-attest`](../gitiup-attest/README.md) and — since normalisation — in
[`gitiup-normalise`](../gitiup-normalise/README.md), and this crate only reads a run
report, calls those crates and prints. Two reasons to insist on that:

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
image          none
toolchain      no toolchain inventory
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
    --policy <path>        gate the run's environment against a policy file
    --require <field=value>  require one environment field (repeatable)
    --require-env-match <m>  strict | major | off (default: strict)
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

`--require` is the other question you ask of a run you already have — not *did it
converge* but *is this the machine we asked for* — and it gets its own exit code, 6,
because the fix is different too. The requirement, the `strict|major|off` knob and what
the refusal says are [documented here](../../docs/environment.md):

```sh
gitiup digest --require arch=amd64 --require toolchain:rustc=1.99 \
        --require-env-match major run.json || echo "wrong machine (exit 6)"
```

## `gitiup env`

What a run *here* would attest as, and whether a policy would accept it — the same
`Policy::check_environment` a verifier runs, before any run exists:

```console
$ gitiup env
os             linux 24.04
arch           x86_64
image          none (no container image digest was discoverable)
toolchain      git 2.43.0, make 4.3, python 3.12.3, rustc 1.88.0
runner         gitiup 0.1.0
fingerprint    sha256:9c0a…
note           distribution: ubuntu
note           no version reported by node (absent from this machine, so absent from the inventory)
requirement    none published

$ gitiup env --policy gitiup-policy.json ; echo $?
gitiup: environment: this run's arch is 'x86_64', which does not match what this change requires: arm64
6
```

`--json` for scripts, `-q` for the fingerprint alone, `--no-inventory` to answer
without spawning a single tool. The inventory itself is probed by
[`gitiup_run::env`](../gitiup-run/src/env.rs) and can be declared instead of guessed
with `GITIUP_TOOLCHAIN` / `GITIUP_IMAGE_DIGEST`.

## `gitiup normalise`

The other half of the claim: what did normalisation do to my logs, and did two runs
agree. The rules live in
[`gitiup-normalise`](../gitiup-normalise/README.md) and the contract they sit inside
is [documented here](../../docs/reproducibility.md); this prints them.

```console
$ gitiup normalise crates/gitiup-normalise/tests/fixtures/corpus/machine-b/run.json
profile        repro v1
result         sha256:00bf7ddb547f5fc3fdfde522206566b3efb8e8b65ca66464069bfd5f22ab1f0b
rewritten      24 rewrites · no progress lines dropped · 5 streams

checkout stdout: 7 rewrites
  line-ending  (stream)
    - stdout: CRLF line endings
    + stdout: LF line endings
  identity     line 1
    - Runner host: build-07.example
    + Runner host: <host>
```

```text
gitiup normalise [OPTIONS] [REPORT]
gitiup normalise [OPTIONS] --compare <OTHER> [REPORT]

    REPORT                 run-report JSON file, or - for stdin (default: stdin)
    --compare <REPORT>     compare two runs instead of describing one
    --rules <LIST>         comma-separated rule names to apply (diagnosis, not policy)
    --text                 print the normalised log text too
    --json                 machine-readable output (keys sorted, one line)
    --expect-result <d>    exit 8 unless the ResultDigest equals this
```

`--compare` is the question a reproducibility failure asks. Two runs that still
disagree produce a structured divergence — step, field, both sides, with the log
line number — and exit `8`:

```console
$ gitiup normalise broken.json --compare good.json; echo "exit $?"
converged      no (3 divergences)
result A       sha256:ee4e6946df04e79e71dae24c72fea5dd4361c4aae0b10aa0a92ab0fc5090c518
result B       sha256:00bf7ddb547f5fc3fdfde522206566b3efb8e8b65ca66464069bfd5f22ab1f0b
test             exit-code                - 101
                                          + 0
test             outcome                  - "failure"
                                          + "success"
exit 8
```

Exit codes follow [ADR-0001 D7](../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
where they overlap, because gates branch on the numbers:

| exit | meaning |
|------|---------|
| 0 | digest computed (and it was the one we were told to expect) |
| 2 | usage: unknown flag, missing value, no report on stdin |
| 3 | I/O: the report could not be read |
| 6 | the report is not a valid run report, or this build cannot read it |
| 8 | digest mismatch: the rerun disagreed with `--expect`, or two runs did not converge |

## `gitiup key` and `gitiup identity`

```console
$ gitiup key gen --comment ada@laptop
created ada-laptop
  key id  SHA256:jNV4N28TJ7ytCrDmXBu8snKgGktlHRmyR0TbXq5gHsQ
  public  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwrkrGZ+b40H+pDMpSvxdldmwJeXj9YS/bF9U9DoFUQ
  secret  encrypted with age (scrypt) in /home/ada/.config/gitiup/keys

$ gitiup identity publish ada --email ada@example.com
published ada
  key id  SHA256:jNV4N28TJ7ytCrDmXBu8snKgGktlHRmyR0TbXq5gHsQ
  signed  by ada-laptop (keystore)
  file    /home/ada/.config/gitiup/identities/ada.identity.json
  this is now the current identity

$ gitiup identity whoami --check
ada — ada
  key id  SHA256:jNV4N28TJ7ytCrDmXBu8snKgGktlHRmyR0TbXq5gHsQ
  key     ada-laptop (keystore)
  where   keystore, age-encrypted at ada-laptop.secret.age
  check   signs and verifies
```

The commands, the passphrase rules and the claim format are
[documented here](../../docs/signing-keys.md); the decisions behind them are
[`gitiup-keys`](../gitiup-keys/README.md). Everything works from a script —
`--passphrase-file -`, `--key`, `--json` — and nothing here requires a terminal.

| exit | `key` and `identity` |
|------|----------------------|
| 0 | done |
| 2 | usage |
| 3 | I/O, no such key or identity, or an agent that cannot be reached |
| 6 | refused: wrong passphrase, name taken, a claim that is unsigned or malformed |
| 7 | a signature does not verify (a tampered claim, a broken endorsement) |

## What is deliberately *not* here yet

storing or fetching attestations
(giti-1rs.5), `gitiup verify attestation` (giti-1rs.8), and the runner that
writes these reports in the first place. `digest` is the slice that exists once
the format does, which is the point: the computation is checkable from the command
line before any of the machinery around it is built.

## Tests

* `tests/digest_cli.rs` — runs the built binary: both digests, stdin, `--json`,
  `--quiet`, `--expect` both ways, every exit code, and the committed golden
  fixtures (so the CLI cannot drift from the pinned vectors).
* `tests/normalise_cli.rs` — the same for `normalise`: the rewrite record, `--json`
  agreeing with the library, two machines converging, a real divergence as exit `8`
  naming step, field and both sides, `--rules`, and every exit code.
* `tests/keys_cli.rs` — `gitiup key` and `gitiup identity` as command lines, with a
  temp `GITIUP_CONFIG_HOME` each: generate, import a real OpenSSH file, publish,
  endorse, use, whoami, verify, move a claim between two config homes — all driven
  through stdin and `--json`, no terminal; exit `3` for a missing agent, `6` for a
  wrong passphrase or a duplicate name, `7` for a tampered claim; and nothing on disk
  but the age container.
* `tests/doc_examples.rs` — the worked report in `docs/run-report.md`, parsed and
  digested: the documentation example is the pinned example.
* `tests/cli_hygiene.rs` — the dependency list stays at three crates, no network or
  forge client is reachable from here, and the documented exit codes are the ones
  the code uses.

## Building

```sh
cargo build -p gitiup
cargo test -p gitiup
```

Dependencies: `gitiup-attest`, `gitiup-normalise`, `gitiup-keys`, `serde_json`. No
argument parser, no HTTP client, no C toolchain.

# The environment fingerprint

Ticket `giti-1rs.4`. Every attestation says *what ran* and *on what change*; this
document is about the third thing it has to say: **what sort of machine did it**. Not
the hostname — the class. And, just as importantly, what it means for a run to
*match* the machine class a change asked for.

The type is [`gitiup_attest::Environment`](../crates/gitiup-attest/src/manifest.rs)
(the manifest's `result.environment`), the requirement half is
[`gitiup_attest::EnvironmentRequirement`](../crates/gitiup-attest/src/envreq.rs), and
the collector is
[`gitiup_run::env`](../crates/gitiup-run/src/env.rs). The command that shows you all
of it is `gitiup env`.

## Why this exists at all

Without an environment, two honest runs on two different machines differ in a way
that arrives as a *mystery*: the digests differ, and the only evidence is two hex
strings. Every hour then goes into finding out that one box had `rustc 1.88` and the
other `1.99`, which is a fact a runner could have stated in one line.

So the environment is recorded, hashed, and — this is the half that makes it useful —
**compared against a requirement the repo publishes next to the change it gates**.
The difference between the two halves is the difference between a clue and a gate:

| | without | with |
|---|---|---|
| evidence | `environment` in the manifest, a digest nobody diffs | the same, plus `require_arch` / `require_toolchain` / … in `gitiup-policy.json` |
| failure | "the digests differ" | `this run's arch is 'aarch64', which does not match what this change requires: amd64` |
| exit code | 8 (digest mismatch) | 6 (refused: this is a policy decision you can read) |

## What the fingerprint covers

Everything in `result.environment`, digested together with
`provenance.runner` beside it (the runner implementation and version) and
`provenance.sandbox` (the backend that confined it):

| field | where it comes from | note |
|-------|--------------------|------|
| `os` | `std::env::consts::OS` | the *family*: `linux`, `macos`, `windows`. The same word a plan derives from `runs-on`, so `require_os = linux` means the same thing on a plan and on a run |
| `os_version` | `VERSION_ID` from `/etc/os-release` | `24.04`. The field `major` rounds |
| `arch` | `std::env::consts::ARCH` | stored as Rust spells it; a policy may say `amd64`/`arm64` because [`Arch`] canonicalises aliases |
| `image.digest` | `GITIUP_IMAGE_DIGEST`, then `/run/.containerenv` | the supply-chain pin of the machine. Never invented: resolving a tag is a network call, and a forged digest would be the most load-bearing lie in the manifest |
| `image.reference` | `GITIUP_IMAGE_REFERENCE`, then `/run/.containerenv` | `ubuntu:24.04` — what was asked for, evidence only |
| `toolchain[]` | `rustc`, `node`, `python`, `git`, `make` `--version`, or `GITIUP_TOOLCHAIN` | the inventory a bare host has instead of an image digest |
| `provider` | the sandbox backend that ran the job | the same word `provenance.sandbox` carries, so a filter on `provider` cannot be fooled by a `local` tier alone |
| `fingerprint` | derived | `sha256(canonical(this object with fingerprint cleared))` |

Two rules make the fingerprint worth having:

* **It is derived, never asserted.** `RunManifest::validate` re-derives it, so a
  manifest that describes one machine and names another is refused as an integrity
  failure (exit 8) before any policy runs. `RunManifest::from_run` calls
  `Environment::fix_fingerprint`; there is no supported way to build a manifest that
  skips it, which is why **every manifest carries one**.
* **It identifies a class, not a machine.** No hostname, no uid, no `$PWD`, no
  timestamps. Those belong to `claims` (volatile, never compared for equality), and in
  the fingerprint they would make every pair of honest runs disagree forever.

The image *or* the toolchain, then both anyway: a run inside a digest-pinned container
has already described itself completely, because the image digest *is* its toolchain.
A run on a bare host has no such handle, and the local inventory is all there is. The
inventory is collected either way — a handful of `--version` calls, and the difference
between "the digests differ" and "the digests differ because one box had `rustc 1.88`".

### What the probe will not do

The collector lives in `gitiup-run` (not the format crate, which is I/O-free) and runs
only where a run really happened or where the user asked:

* it **invents no image digest** — no network, no `docker inspect`, no guessing from a
  tag; if nothing published one, `image` is absent and a note says why;
* it **records no version it did not read** — a tool that is not installed is *absent*
  from the inventory, not `unknown`, because `unknown` would match a requirement of
  `unknown` and read as a machine that has everything;
* it **does not run on the simulated path** — `gitiup run` with no `--execute` still
  spawns nothing (that is giti-1rs.7's contract, pinned by
  `crates/gitiup-run/tests/no_side_effects.rs`); a plan's environment is the workflow's
  `runs-on` and this host's architecture, and it says so;
* it **can be replaced** by `GITIUP_TOOLCHAIN=name=version,…` for a hermetic build that
  already knows which tools its steps saw, and switched off with `GITIUP_ENV_PROBE=off`
  (which is recorded in the manifest's notes, not silently done).

## The requirement, and the knob

A repo publishes what it needs in `gitiup-policy.json`, next to the change it gates:

```json
{
  "require_env_match": "major",
  "require_arch": "amd64",
  "require_os": "linux",
  "require_toolchain": { "rustc": "1.99" },
  "require_image_digest": "sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54"
}
```

Every key is optional and every key is *a question*, not a vibe: a policy that names
nothing compares nothing. The keys also accept the kebab-case spelling
(`require-env-match`) because that is how people type them.

`require_env_match` decides how generously a version is read:

| setting | rule | promise it keeps |
|---------|------|-------------------|
| `strict` (default) | every required field must be exactly as required | bit-for-bit reproducibility: a pinned toolchain, a pinned image |
| `major` | version-bearing fields must agree **as far as the requirement states them**; everything else exactly | "same major version as the change was verified on": a patch release of `rustc` is not a new machine |
| `off` | nothing is compared | the environment is recorded for debugging and gated by nothing |

`major` needs one sentence of precision, because "major" is a promise and not an
algorithm: a requirement of `rustc = 1` accepts `1.100.2`; `rustc = 1.99` accepts
`1.99.4`; `rustc = 1.99.1` is an exact pin and accepts nothing else. The coarseness
lives in the *requirement*; the setting means "do not punish a run for knowing more
than you promised".

Fields that carry no version — `arch`, `image_digest`, `image_reference`, `provider`,
`fingerprint` — are compared exactly under both settings. There is no major version of
a hash, and guessing which characters of `ubuntu:24.04` count as a version is how a
policy ends up accepting `alpine:24.04`.

Two refusals of self-contradiction, both exit 6, both deliberate:

* `require_env_match: off` together with any `require_*` key is refused. A requirement
  nobody enforces is a requirement nobody reviewed — same rule as
  `allow_simulated` vs `allowed_tiers`.
* A policy file with an unknown key is refused, so `require_archh` cannot read as
  "no architecture requirement".

## Where the check runs

`Policy::check_environment(environment, provenance)` is the one call, and it is called
at every point where the answer is useful — so that "what the gate will say" and "what
the tool told me beforehand" cannot drift:

| where | who calls it | on what |
|-------|--------------|---------|
| `AttestationDoc::verify` | every verifier, merge gate and quorum vote | the signed manifest, after the digest bindings and before freshness |
| `gitiup run --policy` | the runner, before it keeps anything | the manifest it is about to produce |
| `gitiup digest --policy` / `--require` | whoever has a run report and a question | the manifest the report computes to |
| `gitiup env --policy` / `--require` | a human, before any run exists | this machine, as a manifest would record it |

`gitiup run` holds a *plan* to less of the requirement, and says so out loud: a plan
executes nothing, so it claims no image digest and inventories no toolchain, and
refusing a plan for the fields it honestly refuses to invent would make an image-pinned
policy refuse every plan. Architecture, OS, provider and runner are still checked.

A refusal is `ErrorKind::Policy` — exit 6, "we refuse this", never 8, "these bytes are
not what they claim". It names the field, what the run reported, and what was required:

```text
gitiup: environment: this run's arch is 'aarch64', which does not match what this change requires: amd64
hint: —
gitiup: environment: this run's toolchain:rustc is 'not reported by this run', which does not match what this change requires: 1.99
hint: this run reported 1 toolchain entry (buildah 1.38.0); a tool the runner never saw cannot be matched — name more of them with $GITIUP_TOOLCHAIN
```

A `fingerprint` requirement is the one case that cannot explain itself — a hash cannot
say which field moved — so its refusal prints the environment it saw instead, which is
the next best thing and the reason `describe()` exists.

## Command line

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

$ gitiup env --require arch=arm64 ; echo $?
gitiup: environment: this run's arch is 'x86_64', which does not match what this change requires: arm64
6
```

`--json` gives the same facts as one sorted-key line, `-q` prints the fingerprint alone
(for `$(gitiup env -q)`), and `--no-inventory` answers without spawning a single tool.
`gitiup digest` grew `--policy`, `--require` and `--require-env-match` for the same
question about a run you already have, and prints the requirement it applied:

```console
$ gitiup digest --require arch=amd64 --require toolchain:rustc=1.99 --require-env-match major run.json
run            sha256:50792b87…
result         sha256:85d5a664…
…
environment    x86_64 · fingerprint sha256:b3bad75a…
image          sha256:3cafcfa8… (ghcr.io/gitiup/ci:ubuntu-24.04)
toolchain      cargo 1.99.1, git 2.47.0, rustc 1.99.1
requirement    arch=amd64 toolchain:rustc=1.99 (major) · matched
```

Note what is *not* merged here: "did the rerun converge?" (`--expect`, exit 8) and "is
this the machine we asked for?" (`--require`, exit 6) are different questions with
different fixes, and one exit code each.

## Tests that hold this down

| file | what it proves |
|------|----------------|
| `crates/gitiup-attest/tests/env_match.rs` | every manifest carries a *derived* fingerprint; an arm64 attestation is refused where amd64 is required; `strict`/`major`/`off` on the same mismatch; the policy file's keys, aliases and self-contradictions |
| `crates/gitiup-attest/src/envreq.rs` (unit) | arch alias table, version rounding, quoting, merge, and what a refusal says |
| `crates/gitiup-run/src/env.rs` (unit) | version extraction per tool, `GITIUP_TOOLCHAIN`, container-env parsing, "absent, not unknown", and that collecting on this machine yields a valid environment |
| `crates/gitiup/tests/environment_cli.rs` | `gitiup env`, `gitiup digest --require/--policy` and `gitiup run --policy` behave as documented, including the plan-claims-less note |
| `crates/gitiup-attest/tests/run_digest_golden.rs` | the environments of the five golden runs hash to the committed digests — i.e. this ticket changed no digest |

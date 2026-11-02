# ADR-0006 — Running workflows with `act`: what is delegated, and what the report may say

* **Status**: accepted
* **Decides**: whether gitiup grows a GitHub-Actions runtime of its own or hands execution to [nektos/act](https://nektosact.com); how an external engine is integrated into a Rust workspace that promises a small auditable dependency set; what a `tier: local` attestation may claim when the thing that ran the job was not gitiup; which engine flags gitiup may never be talked into; which workflow features act ignores and therefore which workflows this engine refuses; and how a log stream that is not a result schema gets read without inventing facts
* **Ticket**: `giti-ic0` — *"consider using the act library to run github actions. This would prevent re-inventing the wheel for execution of github workflows"*
* **Blocks**: `giti-bgy.4` (pin and fetch `uses:` actions — D7 names `--local-repository` as the seam the vendored action set plugs into, and D5's "unpinned ref" annotation as the thing pinning removes); any future engine (`--engine podman-compose`, a Windows runner) inherits D1's discovery contract and D3's policy rule; `giti-bgy.1`'s "a policy may name the rungs it will accept" gains a second kind of name — a ladder backend *or* an engine
* **Depends on**: [ADR-0001](0001-attestation-encoding-hash-and-signature.md) — the attestation's field set, which is where `provenance.sandbox` and `runner` live and which this ADR deliberately does **not** change; the ban on floats in signed payloads (which is why a parsed duration is rounded to an integer before it goes anywhere near a digest); [`docs/sandbox.md`](../sandbox.md) — the ladder, the probe-before-run rule, and the guarantees-sentence format D3 borrows; [`docs/policy.md`](../policy.md) — `allowed_sandboxes` and the "empty means anything the format accepts" reading D3 pins down
* **Implemented by**: [`crates/gitiup-run/src/act.rs`](../../crates/gitiup-run/src/act.rs) (the engine: discovery, argv, refusals, log parsing, report construction), `gitiup run --engine act --act-image` ([`crates/gitiup/src/run.rs`](../../crates/gitiup/src/run.rs) — flag parsing, the always-gated rule, the engine line in `--sandboxes`), and the proofs in [`crates/gitiup-run/tests/act.rs`](../../crates/gitiup-run/tests/act.rs) and [`crates/gitiup/tests/run_act_cli.rs`](../../crates/gitiup/tests/run_act_cli.rs). **What is not built, on purpose**: act is not in the sandbox ladder (D3), there is no engine autodetection (D2), no `--act-arg` passthrough (D4), no vendoring of action repositories (D7 → `giti-bgy.4`), and no CI job that runs a real act — every test here drives a stub that speaks act's protocol, because the CI runners have no container runtime and the claims being proved are about gitiup's report, not act's container.

> The ticket is right that execution of GitHub workflows is a wheel. `act` is roughly
> eight years of it: action fetching, node and docker action runtimes, `services:`,
> the expression language, the `GITHUB_*` environment, the checkout behaviour. gitiup
> re-implements none of that today and says so — [`exec`] refuses every `uses:` step
> rather than guessing at it.
>
> But the product is not the run, it is the **attestation about the run**, and an
> attestation is a statement about who observed what. When gitiup runs a step it knows
> the exit code from `waitpid`, the environment from a table it built from nothing, the
> confinement from a probe it ran milliseconds before, and the log bytes it normalised
> and hashed itself. When act runs a job, gitiup is a parent process that read a log
> file. Those are not the same evidence, and the honest options are to say so in the
> bytes or to refuse to write them. This document takes the first option everywhere a
> claim can be qualified and the second everywhere it cannot.

---

## Context

| # | constraint | who forces it |
|---|------------|---------------|
| C1 | act is Go. There is no library to link: its `pkg/runner` packages are internal Go code with no stability promise, no C ABI and no wire protocol. "Use the act library" can only mean "run the act binary and read what it prints". | the shape of [nektos/act](https://github.com/nektos/act), whose own docs describe installing a released binary |
| C2 | The workspace's dependency policy is small, pure Rust and C-toolchain-free so a shipped binary cross-compiles and fits a static image ([`dependency_hygiene.rs`](../../crates/gitiup-attest/tests/dependency_hygiene.rs)); gitiup already shells out to tools it does not own — `git`, `curl`, `docker`, `podman`, `bwrap` — and probes each one instead of assuming it. | the existing crates, and the same rule `gitiup-sandbox` applies to container runtimes |
| C3 | A `local` attestation names a sandbox that was **probed on that machine moments before the step**, and a name nobody probed is a forgery a verifier cannot tell from a real run. | [ADR-0001 D5](0001-attestation-encoding-hash-and-signature.md), [`docs/sandbox.md`](../sandbox.md) |
| C4 | An attestation must be checkable by a stranger: every field is either a byte, a digest of bytes, or a sentence about the machine it ran on, and nothing may be quietly inferred from an unknown binary's output. | the verification ladder, [`docs/verification.md`](../verification.md) |
| C5 | One attestation is one result: one job, one matrix arm, and every step the plan named present in the report. | the CLI's own checks, `giti run`'s refusals |
| C6 | A checkout must never be able to steer the runner that attests it: a workflow file, a `.actrc`, a build script or a stray `git remote` is an input, not a co-author. | the sandbox's default-deny posture, `gitiup-sandbox`'s "refuse rather than work around" rule |
| C7 | Reproducibility demands pinning: an image referenced by tag, an action referenced by `@v4`, or an engine of unknown version all make "the same run twice" a coincidence. | [`docs/reproducibility.md`](../reproducibility.md) |
| C8 | A quorum verdict may not rest on a containment gitiup cannot name and probe; a policy for stranger's jobs is narrowed against the ladder. | [ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md), [`gitiup_sandbox::policy`](../../crates/gitiup-sandbox/src/policy.rs) |
| C9 | The engine's own behaviour is not stable across releases (act's flags, log fields and support matrix move), so anything the engine reads must be parsed tolerantly and anything it does must be recorded, not assumed. | act's own [unsupported list](https://nektosact.com/not_supported.html), and the CVE notices act has published against its own old releases |

The wheel is real; so are C3, C4 and C8. That is the whole tension, and it is resolved
by separating *running* from *claiming*.

## Decision at a glance

| # | decision | rejected alternative |
|---|----------|----------------------|
| D1 | act is an **external binary the operator installs**, discovered and version-recorded like `git` and `docker` | vendoring act and building it in CI; a Go sidecar in the image; a Go FFI shim |
| D2 | the gitiup runner stays the **engine of record**; act is opt-in per command line (`--engine act`), never autodetected | "replace `exec` with act"; "prefer act when present" |
| D3 | an act run attests `tier: local` with **`sandbox: act`** — a name outside the ladder that a policy must name explicitly, that the producer refuses to file without one, and that no quorum policy can list | a new `tier`; act as a `gitiup_sandbox::Backend` rung; act attestations indistinguishable from probed ones |
| D4 | the argv is built in **one place with no operator escape hatch**; a `.actrc` in the checkout is a refusal | `--act-arg` passthrough; trusting act's defaults (docker socket mounted, host network) |
| D5 | workflow features act ignores are **refused when they change the result** and annotated when they do not | running them anyway (a green/red that disagrees with GitHub); refusing act for all but toy workflows |
| D6 | act's `--json` log is parsed **tolerantly**, and what the log does not say is recorded as absence | inventing exit codes; parsing the human log; demanding act grow a result schema |
| D7 | what gitiup takes from act beyond execution is its **documented semantics** and its **`--local-repository` hook** as the pinning seam | re-deriving Actions semantics from scratch in tests; growing an action vendoring tool inside this ticket |

---

## D1 — an external binary, found and versioned, never linked

`Engine::discover` is the whole integration surface: a path (from `$GITIUP_ACT`, or
`act` on `PATH`), one `--version` call, a parsed version, and the container endpoint act
was told about. A missing or unrecognisable binary is `ErrorKind::Policy` — exit 6 — with
the install URL and `$GITIUP_ACT` in the hint. Nothing falls back: an attestation
produced by a different engine than the one asked for is worse than no attestation.

The version is not decoration. It goes into `provenance.runner` (`act 0.2.94`) and into
`claims.annotations.x_engine_version`, because a run performed by an unnamed binary is
not repeatable (C7), and because act has published CVEs against its own older releases —
"we ran act" is not enough, "we ran *this* act" is a sentence a reviewer can act on.
The probe also says out loud when it cannot see a container endpoint
(`x_engine_probe`), because act will be the one to hit that wall and gitiup should have
already named it.

**Why not vendor it.** A Go toolchain in the build graph, a second lockfile, and every
upstream CVE becoming a gitiup CVE, in exchange for one optional engine — and the
result is still a process boundary at runtime, because Rust cannot link Go. **Why not
`go build` at install time**: same cost, worse reproducibility, and it breaks the static
cross-compiled binary the workspace promises.

## D2 — the gitiup engine stays the engine of record

`--engine` takes a name and defaults to `gitiup`. There is no preference order, no
"act found on PATH, using it", and no config file that sets it, because the engine
changes what the attestation can promise and a run must not silently change what it
proves. The two engines are not ranked by quality of execution — act executes far more
of Actions than gitiup does — they are ranked by **what gitiup can see**:

| | `--engine gitiup` | `--engine act` |
|---|---|---|
| step exit code | `waitpid`, observed | parsed from act's log when act printed one |
| confinement | a ladder backend probed in this process | a container act started, with flags gitiup chose |
| egress | refused unless an allowlist was granted | act's default, which is the host network |
| step environment | built from nothing by gitiup | built by act from act's defaults plus our flags |
| `uses:`, `services:`, expressions | refused (this build does not interpret them) | act runs them |
| tier | `local` | `local` |

**Why not replace `exec`.** Then every gitiup attestation would mean "act reported
these results", including the ones nobody asked act to run, and the tier would have to
be watered down for everybody to protect the case that needs it. **Why not auto-select**:
C4 — the report's meaning would depend on which binaries the host happened to have.

## D3 — `sandbox: act`, and a policy has to choose it

The report names `sandbox: "act"`. That string is chosen deliberately: it is not
`docker`, because the containment is not the `docker` rung's and the rung's sentence
("egress denied in the kernel, capabilities dropped, probed minutes ago") is one gitiup
has no right to borrow. `GUARANTEES` is the honest version, in the same shape as every
ladder backend's: *what act started with our flags* and, in the same breath, that gitiup
probed none of it.

Three consequences, each checked by a test:

* a policy that **names no sandbox** does not accept `act`. `Policy::allows_sandbox`
  reads an empty list as "any backend the format accepts", which is a sane default about
  backends gitiup can open and a hole about engines it cannot, so the **producer** closes
  it: `gitiup run --engine act -o <file>` refuses (exit 6) unless the policy in force
  lists `act`. Running without `-o` is allowed and prints a note — local experimentation
  with a stranger's workflow is the ordinary case, and nothing was filed.
* a policy for **stranger's jobs cannot list it**: `gitiup_sandbox::policy::narrow`
  refuses a sandbox name this build cannot open, so `allowed_sandboxes: ["act"]` is
  unusable where quorum narrowing happens. `gitiup work` never reaches the engine: a
  seat opens a ladder backend or refuses.
* a new tier was rejected outright. `sandbox` is the field ADR-0001 already has for "what
  confined this", it is a free-form name a policy may match, and it costs no format
  version. `tier: external` would have to be added to every reader, every ladder and
  every policy in the wild to say what one string says.

**Why not a ladder rung.** `gitiup_sandbox::Backend`'s contract is *we built the
confinement, and here is the probe that proves it here, now*. act's containment is a
list of flags we pass and hope; a `guarantees()` that translated upstream flags would be
the first rung in the ladder whose sentence was hearsay, and the ladder's value is that
none of them are.

## D4 — the argv is not negotiable

`act::argv` is the only place act's command line is built, and it always passes:
`--json` (machine-readable, not a coloured terminal), `--container-daemon-socket -` (a
job that can drive the host's docker is not a container), `--container-options-policy
restrict` (a workflow's own `--run: docker run --privileged` is not a way out) and
`--use-gitignore` (gitignored files are where a working tree keeps its `.env`). Secrets
go as `-s NAME`, never `-s NAME=value`, so the value never appears in an argv a stranger
could `ps`; act's own environment is cleared and rebuilt from eight variables plus the
named secrets. Every `runs-on` label must be mapped with `--act-image` — otherwise act
stops and asks a terminal which image to pull, and a runner that blocks on a prompt is
worse than a refusal that names the flag; `runs-on: self-hosted` is refused outright,
because a job that runs on the host confines nothing and earns no tier.

`REFUSED_ARGS` exists to be explicit about what there is no way to ask for:
`--privileged`, `--userns`, `--container-options`, `--container-cap-add`/`-drop`,
`--insecure-secrets`, `--secret-file`, `--env-file`, `--reuse`, and
`--trust-project-actrc`. And a `.actrc` **in the checkout is a refusal**, version-check
unnecessary: C6 says the tree under test is an input, and an actrc is a place where an
input chooses its own runner.

**Why not `--act-arg` passthrough.** Because the escape hatch would then be the normal
path, and the containment claim would depend on a flag nobody reviewing the attestation
can see. The escape hatch that *is* offered: run act yourself, and do not ask gitiup to
attest what it did not launch.

## D5 — what act ignores, and whether it changes the result

act documents what it does not implement. Where an ignored feature changes the
**outcome**, gitiup refuses to attest, because an attestation whose result disagrees
with the CI run it stands in for is worse than none:

| feature | engine's answer | why |
|---------|-----------------|-----|
| `jobs.<id>.environment` | **refuse** | act implements no environment secret scoping, so a secret GitHub would have withheld would run anyway |
| `continue-on-error` (job or step) | **refuse** | act ignores it, so a step GitHub would let fail makes this run red: the attested result is the wrong one |
| `steps.<n>.timeout-minutes` | **refuse** | act ignores it; gitiup can only bound the whole run, so a hung step that GitHub would cut off hangs here |
| `jobs.<id>.timeout-minutes` | run, annotated | gitiup enforces its own wall clock on the act process (default 360 min, GitHub's own default) and kills it — the enforcement is ours and is stated |
| `concurrency`, `permissions`, `run-name` | run, annotated | decoration: no step result depends on them, but a token passed with `--secret` has real scope and the workflow asked for a narrower one, so it is said |
| step summaries, annotations, problem matchers | run, annotated | act discards them; the note is permanent, so no reader mistakes the report for the GitHub UI |
| a job that calls a reusable workflow (`uses:` at job level) | **refuse** | gitiup cannot enumerate the steps, and C5 requires every step that ran to be in the report |

The general rule, which is the one to extend when act grows a feature: **refuse when the
result would differ, annotate when only the reporting would.**

## D6 — reading a log that is not a schema

`act --json` emits logrus lines: `job`, `jobID`, `step`, `stepResult`, `jobResult`,
`executionTime`, `msg`. That is a log stream with occasional structured fields, not a
result contract, so the parser is deliberately loose: a line that is not JSON is
ignored (act prints a banner and cobra prints `Error:`), unknown fields are ignored, a
missing field is `None` rather than a guess, and both `jobID` and `jobid` spellings are
accepted because act has shipped both.

The claims made out of that stream, and the honesty rule behind each:

* one report entry per **planned** step, in plan order (C5) — act's own lifecycle steps
  (`Set up job`, `Post …`, `Complete job`) are never steps of the report, only notes;
* a step act closed with `failure` gets the exit code printed in its own log (`exit
  status N`, the last one), and **1 plus a note** when act printed none — "that number
  is act's silence, not an observation";
* a step with no result in the log is `skipped` with the reason in its stderr and in the
  notes (an `if:` that was false — act logs skips at debug level only — or a run that
  stopped);
* `Set up job` failing is a **refusal, not a report**: the image was not pulled or the
  container not started, nothing of the workflow ran, and there is nothing to attest;
  act's own error lines are quoted in the refusal;
* a failing `Post`/`Complete` step, act's exit code, the image act said it started, and
  the exact argv are recorded as annotations, so the difference between "the workflow
  failed" and "the runner failed" survives into the bytes.

**Why not require better output from act.** It is not ours to demand, and C9 is the
normal state of integrating with a fast-moving upstream: parse tolerantly, record
everything, and let absence read as absence.

## D7 — the rest of the wheel worth taking

Two things beyond running one job:

* **act's semantics as the reference for gitiup's own interpreter.** Where gitiup parses
  a workflow itself it should agree with what act and GitHub do — naming of unnamed
  steps, `needs` ordering, matrix expansion, `runs-on` labels — and act's documentation
  and test data are the cheapest oracle. `act -l` is not machine-readable (a fixed-width
  table), so this stays a documentation-and-test discipline, not a CI gate.
* **`--local-repository owner/repo@ref=<path>` is where `giti-bgy.4`'s pins plug in.**
  Today an unpinned `@v4` ref is not refused — it is what GitHub does — but it is
  annotated as a moving ref (C7). When gitiup grows a vendored, content-hashed action
  set, act already has the hook that consumes one, and the digests belong in
  `RunReport::pins`, which is the field `giti-bgy.4` owns.

## Consequences

* `gitiup run --engine act` is the answer to "run my real workflow locally", including
  the parts this build has always refused — `uses:` steps, `services:`, expressions —
  and it is honest about being act: `runner: act 0.2.94`, `sandbox: act`,
  `x_engine_*` annotations, and a policy that has to say `act` by name before an
  attestation is written.
* A large chunk of Actions behaviour is no longer on this project's critical path, which
  is the ticket's point. What remains there is the parts that make an attestation mean
  something: planning, digests, signatures, normalisation, the ladder, the quorum.
* act's own failure modes are now gitiup's operational surface: a CVE in old act is
  handled by the version annotation and the refusal to guess a binary, and act's
  interactive image prompt is handled by the `--act-image` requirement (both tested).
* Nothing here weakens the ladder. An act run cannot serve a quorum, cannot satisfy a
  policy that names real backends, and does not appear in `gitiup doctor --sandbox` as a
  sandbox — `gitiup run --sandboxes` lists engines separately, under engines, with
  `docs/act.md` named.
* Not built, and deliberately: engine autodetection (D2), action vendoring (D7,
  `giti-bgy.4`), Windows host execution (`self-hosted` is refused), and any claim that a
  quorum of act runs is worth anything — the tier still refuses a single run's claim to
  be a verdict.

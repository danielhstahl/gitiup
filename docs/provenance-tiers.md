# Provenance tiers (`simulated | local | quorum`)

Ticket `giti-1rs.7`. An attestation answers one question — *what happened?* — and the
answer is only useful if you know **how hard the tool tried to make it happen**. That
is what `result.provenance.tier` says. Three tiers exist, in rising order of what they
license you to believe:

| tier         | what it claims                                                            | what it does **not** claim              | how it is earned                                        |
|--------------|---------------------------------------------------------------------------|-----------------------------------------|---------------------------------------------------------|
| `simulated`  | this is what the workflow *would* run, in order, on this commit            | that any of it ran, built, or passed    | by default: `gitiup run` with no `--execute`             |
| `local`      | these steps ran in a sandbox on one machine, with these exit codes         | that anyone else agrees                 | `gitiup run --execute --sandbox <backend>`, probed first |
| `quorum`     | independent verifiers reran it and their `ResultDigest`s agreed             | anything about *how* it was run locally | by a quorum of verifiers, never by one run               |

The tiers are ordered on purpose: `simulated < local < quorum`. Nothing in the format
lets a lower tier borrow the authority of a higher one, and the rest of this document
is mostly the machinery that keeps it true.

## Why simulation is the default

`gitiup run` with no `--execute` reads a workflow file and produces a run report whose
steps describe themselves:

```text
SIMULATED step 1 'checkout' — nothing executed
  action   actions/checkout@v4 (ref not resolved: a plan fetches nothing)
SIMULATED step 2 'Build' — nothing executed
  script   cargo build --release
```

That text is the step's log, and it is hashed like one. So a simulated attestation has
a real `RunDigest` and a real `ResultDigest`, reproducible on another machine given the
same workflow bytes, commit, event and clock — which is what makes plans comparable
("this change would add a step"), and also what makes them dangerous: a digest has
always previously meant *a run happened*. Hence two rules:

1. **the default touches nothing.** No process is spawned, no socket is opened, no
   secret is read, no file is written. A simulated attestation *cannot* be a side
   effect, because simulating has none. `crates/gitiup-run/tests/no_side_effects.rs`
   enforces this against the source as well as the behaviour, so adding
   `std::env::var("NPM_TOKEN")` to the simulator breaks the build rather than passing
   review.
2. **the tier is not a caller's choice.** There is no `--tier`, no `Simulation::tier`,
   no field to set. The function that returns a simulated report returns
   `tier: simulated, sandbox: none`; the one that returns an executed report returns
   `tier: local` plus the sandbox that ran it. A run's tier is a record of what the
   program did, which is the only kind of record worth signing.

## `quorum` cannot be claimed by a single run

This is a format rule, not a CLI rule, so it holds for every producer:

```text
policy: a single-run manifest may not carry tier `quorum`
```

* [`Provenance::check`](../crates/gitiup-attest/src/manifest.rs) refuses it during
  validation, so `RunManifest::from_run`, `require_canonical`, and
  `AttestationDoc::verify` all reject it — before any signature is even looked at. A
  quorum-tiered document is therefore *format-invalid*, not merely policy-disliked,
  and cannot be laundered by a friendly key.
* `gitiup_run::manifest_for` refuses to compute one, with a hint naming the ticket that
  owns the real thing (a quorum is a *verdict over several attestations*, and it is
  computed by comparing independent `ResultDigest`s — the tier of the verdict is a
  property of the comparison, not of any one run).
* The CLI has nothing to say: there is no flag for it, and `gitiup run --tier quorum` is
  an unknown-option error (exit 2) whose text explains why.

When giti-msi.7 computes agreement across verifiers, the thing it produces is a record
*about* attestations; whether that record itself carries `tier: quorum` or is a separate
signed object is that ticket's decision. What this ticket settles is that no amount of
local running gets a single run to claim it.

## What each tier may say about its sandbox

Tiers constrain each other, and the format checks the combination, not just the label:

| tier         | `provenance.sandbox`      | `result.secret_names`        |
|--------------|---------------------------|------------------------------|
| `simulated`  | `none` (or absent)        | must be empty                |
| `local`      | a real backend, required  | whatever the step was given  |
| `quorum`     | not reachable here        | —                            |

So `tier: local, sandbox: none` is refused ("an executed run must name the sandbox it
ran in — an unconfined run gets no tier"), and
`tier: simulated, sandbox: docker` is refused ("a simulated run executes nothing: it
may not claim a sandbox"). The `--sandbox none` case matters most, because it is the
one a user reaches for deliberately: `gitiup run --execute --sandbox none` exits 6 and
suggests either a real backend or plain simulation. An unconfined run that attested as
`local` would make the tier mean "someone typed a command", which is not worth signing.

`--execute` does not have to name the sandbox. If exactly one backend works on this
machine it is used, and the run prints which one and why ("the only one this machine
offers"); if several work, the run is refused until `--sandbox` says which confinement
the attestation is claiming. Vagueness about confinement is the thing being avoided, not
typing.

A sandbox is opened and **probed** before any step runs, and every rung of the ladder
is a real implementation rather than a name: `docker`/`podman`, `bwrap`, Landlock plus
seccomp applied in the child, `unshare(1)`, and — opt-in, and shouted about — `plain`,
which isolates nothing. An unavailable backend explains itself and offers simulation,
and `gitiup doctor --sandbox` reports the whole ladder with a fix per line. See
[the sandbox](sandbox.md) for what each rung denies and what it does not.

```console
$ gitiup run --execute
gitiup: sandbox: the `landlock` sandbox is not usable here: fs-write-outside failed — a confined write to /tmp/… succeeded
hint: until a sandbox holds up, gitiup run will only simulate — which is the safe
      default, and gitiup doctor --sandbox says what to change about this machine
$ gitiup run --execute --sandbox none
gitiup: sandbox: `--sandbox none` asks for an unconfined execution
hint: an unconfined run may not attest as `local`: pick a backend, or drop --execute and
      get a simulated attestation instead
```

A `local` report is refused in the first place if the rung it would name enforces
nothing: `--sandbox plain` needs `GITIUP_UNSANDBOXED=1` to be set at all, and even then
it may never serve a job whose result is offered to someone else.

## What `--execute` refuses outright

A `local` attestation is only worth what the runner could actually honour, so two
kinds of job are refused rather than run partially and quietly:

* **a step with `uses:`** — resolving an action means fetching it, which this build does
  not do. A skipped action step would produce a clean-looking attestation about a run
  that never checked anything out.
* **a job with `services:`** — this build starts no service containers. Running a job
  without the database it declares, and attesting the result, is the worst possible
  outcome: a green attestation of a run that was never able to pass.

Both refusals are exit 6, name the thing that is missing, and point at simulation, which
says the same thing in the attestation instead of hiding it. Nothing else about the
workflow is silently dropped: `env:` is modelled (job then step, `${{ matrix.* }}`
expanded, and a literal `${{ secrets.X }}` refused rather than handed over as if it were
a token), and what genuinely cannot be modelled — `if:` expressions, `container:` images
that are not digest-pinned, reusable-workflow calls — is printed as a note and recorded
in the attestation's annotations.

## Trust-bearing use: warn, or fail

The warning is the library's, not the CLI's, so a caller that embeds the crate hears the
same sentence:

```rust
let warning = gitiup_attest::Tier::Simulated.trust_warning();
```

```text
WARNING: SIMULATED: nothing was executed. This attestation describes a plan and proves
WARNING: intent, not behaviour: no code ran, no network was used, no artifact was
WARNING: produced.
```

`gitiup run` prints it on stderr on every simulated run — including when the user has
explicitly asked for a plan, because the person reading the digest ten minutes later
was not here for the flags. `local` and `quorum` print nothing: a warning on every run
is a warning nobody reads.

Keeping the attestation is the gated step. **`--out`** (write it for someone else) and
**`--policy`** (ask to be gated) both run the policy, and the built-in default allows
`local` only:

```console
$ gitiup run --out attestation.json
WARNING: SIMULATED: nothing was executed. …
gitiup: policy: provenance tier 'simulated' is not accepted here
hint: a simulated run plans but does not execute; run it for real
(`gitiup run --execute --sandbox <backend>`) to satisfy this gate, or set
"allow_simulated": true in the policy only if a plan is genuinely what you want to record
$ echo $?
6
```

Exit code 6 is the same "refused" code the library uses for a policy rejection
(ADR-0001 D7), so a merge gate cannot tell the two apart — which is the point.

## Policy files

A policy file is JSON (`gitiup-policy.json` by convention, `$GITIUP_POLICY` to point at
one, `--policy <path>` on the command line). Its tier-relevant members:

| member              | meaning                                                          |
|---------------------|------------------------------------------------------------------|
| `allowed_tiers`     | the tiers acceptable here, e.g. `["local"]`                       |
| `allow_simulated`   | shorthand for "add `simulated` to `allowed_tiers`"                |
| `allowed_sandboxes` | which backends count as confinement, e.g. `["docker", "unshare"]` |

```json
{
  "allowed_tiers": ["local"],
  "allowed_sandboxes": ["docker"],
  "min_signatures": 1
}
```

A policy that contradicts itself is refused rather than resolved: `allow_simulated: true`
together with `allowed_tiers: ["local"]` is an error, and so is `allow_simulated: false`
with `simulated` in the list, because the *reader* would have to guess which statement
was the stale one. Likewise an empty `allowed_tiers` (accepts nothing, so says nothing)
and `min_signatures: 0` (trust nobody and notice nothing) are refusals, not defaults.

Because a policy names sandboxes too, an organisation can say "a run inside `unshare`
counts here, a run on the runner's own shell does not" — a tier of `local` produced by a
sandbox the policy has never heard of is refused at
`Policy::check_provenance`, which is called by `AttestationDoc::verify` and so cannot be
skipped by a verifier that remembers to.

## Where the rule lives

| file                                          | what it holds                                                        |
|-----------------------------------------------|----------------------------------------------------------------------|
| `crates/gitiup-attest/src/manifest.rs`         | `Tier`, its order, `trust_warning`, and `Provenance::check`           |
| `crates/gitiup-attest/src/policy.rs`          | `allowed_tiers`, `allowed_sandboxes`, `check_provenance`, policy files |
| `crates/gitiup-attest/src/envelope.rs`        | `AttestationDoc::verify` calls the provenance check before signatures  |
| `crates/gitiup-run/src/simulate.rs`           | the simulated report: tier and sandbox are not parameters              |
| `crates/gitiup-run/src/exec.rs`               | the executed report, same rule                                          |
| `crates/gitiup-run/src/sandbox.rs`            | the sandbox vocabulary, `none` refused, probing                        |
| `crates/gitiup/src/run.rs`                    | the command line: no tier flag, the gate, the warning                  |
| `crates/gitiup-run/tests/no_side_effects.rs`  | the default path stays free of processes, sockets, env and writes       |

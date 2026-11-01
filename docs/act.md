# Running a workflow with `act`

`gitiup` plans any workflow and runs the steps it can run itself. Plenty of real
workflows are not made of steps gitiup can run: they are `uses: actions/checkout@v4`,
a postgres service, a composite action and an `${{ }}` expression or two. Interpreting
all of that is a runtime, and a runtime already exists:
[nektos/act](https://nektosact.com), which runs a GitHub Actions job in a container on
your machine.

`gitiup run --engine act` hands the job to act and turns act's report into a gitiup
attestation. The decision behind the shape of this feature — why act is not the default,
why its name appears in the signed bytes, and what it may and may not claim — is
[ADR-0006](adr/0006-running-workflows-with-act.md).

The short version of that decision:

> **act runs the job; gitiup still decides what the attestation is allowed to say.**
> The report says `sandbox: act`, because the containment was act's and gitiup only
> launched act and read its log.

## Install, then point at it

act is not bundled, and gitiup will not guess at it. Install a release binary
(<https://nektosact.com/installation/>, `brew install act`, `go install`, or drop one
somewhere), then either put it on `PATH` or say where it is:

```console
$ export GITIUP_ACT=$HOME/bin/act
$ gitiup run --sandboxes
sandboxes this build offers:
  landlock  available   writes outside the scratch refused …
  …
engines this build can hand a job to:
  gitiup    available   one process per step, in the sandbox named above
  act       available   act 0.2.94 · container endpoint /var/run/docker.sock
  (act runs the `uses:` steps and services gitiup's own runner refuses to guess at; it
   is contained by act, so an attestation from it says `sandbox: act` and a policy has
   to name that — see docs/act.md)
```

act needs a container runtime — docker, or podman over `DOCKER_HOST`. That is act's
dependency, not gitiup's: what gitiup probes is the binary and which endpoint act was
told about, and it says so when it cannot see one.

## Run one job

```console
$ gitiup run build --execute --engine act \
      --act-image 'ubuntu-latest=ghcr.io/cat-the-planet/base@sha256:0123…'
note    this run says `sandbox: act`: act contained it, gitiup only launched act and
        read its log. Nothing is filed, and a policy that does not name `act` will
        refuse it if you try
ran job build in act
   1. Checkout — exit 0
   2. Test — exit 0
note         step 'Checkout' fetches `actions/checkout@v4`, a moving ref: this run is only
             reproducible against whatever that ref pointed at today (pin it by commit SHA,
             or vendor and pin the action)
note         act discards step summaries and annotations and ignores problem matchers (its
             own unsupported list)
commit         sha1:3f2b000000000000000000000000000000000000
sandbox        act
run            sha256:37358f3bed450328e7513c773934e7bccf9a3a1dc7ae016883a1a735e51e59cf
result         sha256:71abc082b46a7dcb3af43d2d719625076075c39ffe109e9e65f5f260d1312713
tier           local
normalisation  v1
checked      2 steps planned, 2 reported: 0 failed, 0 skipped, and every step the plan
             named is in the attestation
re-hashed    the manifest's own canonical bytes re-parse, pass the format's checks, and
             give back both digests above
logs         hashed as normalised text (v1): the attestation carries the digest of each
             stream, so what was printed above is the only copy of it
engine       act 0.2.94 ran the job in its own container (/var/run/docker.sock); gitiup
             watched act's exit code and read its log, and probed none of the containment
             it used
next         nothing was written (--out names a file), so there is no attestation to
             verify yet: the digests above are what a stored one would have to reproduce
```

Two flags are the whole interface:

| flag | what it is |
|------|------------|
| `--engine act` | with `--execute`, hand the job to act. Without `--execute` it is a refusal: a plan needs no engine |
| `--act-image '<runs-on>=<image>'` | the image for a `runs-on:` label, repeatable. **Required for the label the job uses** |

`--act-image` is required because act, given a label it has no image for, stops and asks
a terminal which image to pull. A runner cannot answer a prompt, so gitiup refuses first
and names the flag. Pin by digest (`…@sha256:…`): a tag is only the same image twice by
luck, and the engine says so in the notes when you do not.

`--sandbox` and `--engine act` are refused together on purpose. `--sandbox` names a
containment gitiup built and probed; act's container is not one, and borrowing the name
`docker` for it would be the one lie this feature cannot afford.

## What the attestation says, and what it does not

An act run is `tier: local` — it happened, on this machine, and gitiup watched act do it.
What it may not do is borrow the ladder's promises:

| | `--engine gitiup` | `--engine act` |
|---|---|---|
| step exit code | observed from the process | read from act's log when act printed one, otherwise recorded as `1` with a note saying the number is act's silence |
| what confined it | a backend probed in this process, minutes before the step | a container act started with gitiup's flags; gitiup probed none of it |
| egress | refused unless an allowlist was asked for | act's default, which is the host network |
| `uses:` steps, `services:`, `${{ … }}` | refused, because this build does not interpret them | run, by act |
| `sandbox:` in the signed bytes | `docker`, `podman`, `bwrap`, `landlock`, `seatbelt`, `unshare`, `plain` | `act` |

The annotations carry the receipts: `x_engine_version`, `x_engine_exit`,
`x_engine_command` (the exact argv, so a reviewer can read the flags rather than trust a
description of them), `x_engine_container`, `x_engine_image`, and `x_run_notes` with
everything act refused to say.

**A policy has to name `act`.** The default policy allows `local` and names no sandbox —
"anything the format accepts" is a fair default about backends gitiup can open and a hole
about engines it cannot — so keeping an act attestation is refused until the policy says
so:

```console
$ gitiup run build --execute --engine act \
      --act-image 'ubuntu-latest=ghcr.io/cat-the-planet/base@sha256:0123…' -o attestation.json
gitiup: this run would attest as `sandbox: act`, which no policy has accepted
hint: an act run is contained by act, not by a gitiup sandbox: keep it only where the
      policy names it — write `"allowed_sandboxes": ["docker", "act"]` in the policy
      file you gate with, or drop --out and treat the run as local experimentation
$ echo $?
6
```

```json
{
  "allowed_tiers": ["local"],
  "allowed_sandboxes": ["act"]
}
```

That refusal is the feature: a repository accepts act's containment by typing its name,
and one that has never heard of act does not accept it by accident. A policy that goes
through `gitiup_sandbox`'s narrowing (the quorum path) cannot list `act` at all — a
stranger's verdict may not rest on a containment gitiup cannot probe, and
`gitiup work` only ever opens a ladder backend.

## What act ignores, and what gitiup does about it

act documents what it does not implement
([its list](https://nektosact.com/not_supported.html)). Where an ignored feature would
change the *result*, running the job would produce an attestation that disagrees with
the CI run it stands in for, so the engine refuses it **before act is spawned**:

| the workflow says | the engine | the sentence you get |
|-------------------|------------|---------------------|
| `environment: production` | refuses | a secret scoped to that environment would reach the job anyway, which is worse than not running |
| `continue-on-error: true` (job or step) | refuses | act ignores it, so a step GitHub would let fail makes this run red |
| `timeout-minutes` on a **step** | refuses | act ignores it; only the whole run can be bounded |
| `timeout-minutes` on a **job** | runs, annotated | gitiup puts its own wall clock on act (360 min by default, GitHub's own default) and kills it |
| `concurrency`, `permissions`, `run-name` | runs, annotated | ignored: a token you pass has whatever scope it really has |
| a job that calls a reusable workflow | refuses | gitiup cannot enumerate the steps, and an attestation that names none of them is not an attestation |
| `runs-on: self-hosted` | refuses | the job runs on the host, and an unconfined run earns no tier |
| a `.actrc` in the checkout | refuses | the tree under test must not choose its own runner |

Secrets follow the rule they follow everywhere in gitiup: `--secret NAME` passes the
*name* to act (`-s NAME`) and the value through act's environment, so a value is never
in an argv; a name that is not set in the environment is a refusal, not a step that ran
without it.

## When to use which engine

* **`--engine gitiup`** (the default with `--execute`) — the engine of record. The
  confinement is gitiup's and probed, so this is the one a policy accepts by default and
  the one a quorum seat runs. It runs plain script steps and refuses everything it would
  have to guess at.
* **`--engine act`** — a real workflow, with actions and services, run for real on your
  machine: reproducing CI output, debugging a workflow before pushing it, and keeping a
  signed record of what act reported *when your policy says that is worth recording*.
* **no `--execute`** — planning. Nothing runs, nothing is read, and the attestation is
  `tier: simulated`, which no default policy accepts and no merge should rest on.

## Troubleshooting

| what you saw | what it means |
|--------------|---------------|
| `the 'act' engine was asked for and 'act' did not run` | not installed, or not where gitiup looked: install it or set `$GITIUP_ACT` |
| `act could not set the job up: …` | act could not pull the image or start the container — nothing of your workflow ran, so there is nothing to attest; act's own error is quoted, and `gitiup doctor --sandbox` names the runtime this machine has |
| `has no image, and act would stop and ask a terminal` | pass `--act-image 'label=image'` for the job's `runs-on:` label |
| `act was killed after N minutes` | the run outlived its deadline (the job's own `timeout-minutes`, or 360); nothing about what it would have produced is claimed |
| a step that ran is recorded as `skipped` | act's log carried no `stepResult` for it — an `if:` that was false, or a name that does not line up; the note says which steps, and never guesses |

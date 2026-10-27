# The run report (`gitiup digest` input)

Ticket `giti-1rs.2`. The attestation epic needs a *result* of a CI run that a
stranger can re-derive; this document describes the hand-off between the runner
and the digest computation, and the recipe that turns one into the other.

The type is [`gitiup_attest::run::RunReport`](../crates/gitiup-attest/src/run.rs)
and the CLI that consumes it is `gitiup digest`. Nothing here is signed — the
report is an input format; the **manifest** it computes to is the signed document,
and [ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md) decides its
encoding.

## The recipe

```text
RunDigest    = sha256(canonical(RunManifest::from_run(report)?))
ResultDigest = sha256(canonical(that manifest's `result` member))
```

`from_run` is the only sanctioned way from a run to a digest, and it is a
*total* pipeline: validate the report, hash the material it handed over, sort
every list the format mandates, derive `environment.fingerprint`, validate the
resulting manifest, return it. A caller cannot sign a manifest that a verifier
would refuse, and cannot forget a step of the recipe because there is no way to
take the steps separately.

| # | step | why |
|---|------|-----|
| 1 | parse the report as ordinary JSON | a report is a transport: order and whitespace carry no meaning, so they must not be able to change a digest |
| 2 | `RunReport::validate` | a typo must produce "unknown field `toochain`", not a different digest |
| 3 | hash each [`Material`](#material-bytes-or-their-digest) | hashing happens in one place, so "the digest of a log" is never a caller's choice |
| 4 | assemble `result` + `claims`, then `RunManifest::normalize` | the mandated sorts are the format's, not the producer's |
| 5 | `Environment::fix_fingerprint` | the fingerprint is derived from the environment described, so a run cannot describe one machine and claim another |
| 6 | `RunManifest::validate` | the checks a verifier runs, run once at production time |

## Report shape

```jsonc
{
  "repo": "gitiup/gitiup",                    // optional, trusted for nothing
  "commit": "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",   // required: the run's binding
  "workflow": {                               // required: what ran
    "path": ".github/workflows/ci.yml",
    "text": "name: CI\non: push\n"            // …or "oid": "sha1:bbbb…" for a committed file
  },
  "event": {                                  // required: what triggered it
    "name": "pull_request",
    "action": "synchronize",                  // optional
    "payload": {"text": "{\"action\":\"synchronize\"}"}   // or {"digest": "sha256:…"}
  },
  "job": "build",                             // optional
  "matrix": {"os": "ubuntu-24.04"},           // order irrelevant
  "inputs": {"jobs": 4, "coverage": true, "toolchain": "1.99.1"},
  "secret_names": ["NPM_TOKEN"],              // names only, never values
  "pins": {                                   // every `uses:`, resolved
    "actions/checkout@v4": {
      "repo": "actions/checkout",
      "commit": "sha1:cccccccccccccccccccccccccccccccccccccccc",
      "ref": "v4"                             // what the user wrote; never trusted
    }
  },
  "reusable_workflows": [                     // the closure; any order
    {"path": ".github/workflows/_lint.yml",
     "oid": "sha1:dddddddddddddddddddddddddddddddddddddddd"}
  ],
  "environment": {                            // machine class, not machine identity
    "provider": "docker",
    "os": "linux",
    "arch": "x86_64",                         // required
    "image": {"reference": "ubuntu:24.04",
              "digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
    "toolchain": [{"name": "rustc", "version": "1.99.1"}]
  },
  "steps": [                                  // execution order — the one order that means something
    {
      "id": "checkout",                       // optional, unique
      "name": "Checkout",
      "uses": "actions/checkout@v4",          // optional
      "exit_code": 0,
      "outcome": "success",                   // optional: derive from exit_code if omitted
      "stdout": {"text": "Checked out\n"},
      "outputs": {"commit": "abc123"},
      "artifacts": [
        {"name": "coverage", "content": {"files": {"cov/lcov.info": {"text": "TN:\n"}}}}
      ],
      "timing": {"started_us": 1793092502500000, "duration_us": 412000}   // → claims.timing
    },
    {
      "id": "test",
      "name": "cargo test",
      "exit_code": 0,
      "stdout": {"digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
      "stderr": {"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    }
  ],
  "provenance": {
    "tier": "local",                          // simulated | local (never quorum: that is a verdict over runs)
    "runner": "gitiup 0.1.0",
    "normalisation_version": 0,               // see "normalisation" below
    "sandbox": "docker"
  },
  "claims": {
    "run_id": "0123456789abcdef",             // 16–64 lower-case hex
    "claimed_at_us": 1793092502500000,        // integer microseconds, never a string
    "not_after_us": 1793092862500000,         // optional; omit rather than write null
    "verifier_challenge": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "timings": [{"step": "test", "duration_us": 900000}],   // keyed by step id
    "normalisation_diffs": [
      {"step": "test", "kind": "hostname", "before": "runner-7.internal", "after": "<host>"}
    ],
    "annotations": {"x_ci": "local"}          // third-party fields, `x_*`, strings only
  }
}
```

Note the mix in `steps`: one step hands its log over in the clear, the other hands
over a digest. Mixing is legal — `from_run` takes the digest as given and hashes
whatever it is handed. What is *not* legal is declaring a `normalisation_version`
the profile will not honour: `RunManifest::from_run` applies the pass-through
profile (version `0`), so a report with raw log text that declares `1` is refused
rather than recorded misleadingly. See [normalisation](#normalisation).


### What goes where

`result` is what a faithful re-run reproduces; `claims` is who says so and when
([ADR-0001 D4](adr/0001-attestation-encoding-hash-and-signature.md)). The report
mirrors that split, and `from_run` keeps it:

| report field | lands in | note |
|--------------|----------|------|
| `commit`, `workflow`, `event`, `job`, `matrix` | `result.source` | the workflow's and event's payloads are hashed here |
| `inputs`, `secret_names`, `pins`, `reusable_workflows` | `result` | secret *names* only; a value here would leak and would not reproduce |
| `environment` | `result.environment` | fingerprint derived, never accepted |
| `steps[]` | `result.steps` | `timing` is siphoned off into `claims.timing` |
| `provenance` | `result.provenance` | tier is a property of how the run happened |
| `claims.*` | `claims` | signed, stored, never compared for equality |

A step's timing is the instructive case: durations never agree between machines,
so `steps[].timing` is copied into `claims.timing` and is *absent from the result
digest*. Two honest reruns disagree about how long a step took and must agree
about what it produced.

## `Material`: bytes or their digest

Anything hashable may arrive either pre-hashed or in the clear, tagged explicitly:

| form | meaning |
|------|---------|
| `{"digest": "sha256:…"}` | already hashed; taken as given |
| `{"text": "…"}` | the bytes, as UTF-8 text |
| `{"parts": ["a", "b"]}` | several blobs, hashed with **explicit lengths** so a split cannot collide with a concatenation |
| `{"files": {"path": …}}` | a set of files hashed as one artifact: paths sorted, per-entry digests, explicit lengths (`file_set_digest`) |

The tagging is not sniffed from the string shape: a log whose entire content
happens to be `sha256:…` must not be recorded as *claiming* that digest instead of
the hash of its bytes.

Use `{"digest": …}` in production (giti-1rs.3 normalises logs, and megabytes of
raw text have no business in a manifest or an attestation). Use `text`/`parts`/
`files` in fixtures and hand-checks, where the point is that a reviewer can see
the bytes that produce the recorded digest.

Normalisation reaches **step log streams only**. An event payload, a workflow
source and an artifact are hashed as handed over — they are inputs and products,
not logs — so a runner that rewrites an artifact manifest hands over the digest it
computed and declares the version that produced it.

## normalisation

`provenance.normalisation_version` says which rules produced the log digests,
because two results normalised by different rules are not comparable.

* If the report hands over **raw log text**, the declared version must equal the
  version of the [`Normaliser`](../crates/gitiup-attest/src/run.rs) that will be
  applied: `RunManifest::from_run` uses `RawText` (version `0`, "rewrote
  nothing"), and `RunManifest::from_run_with(report, &profile)` takes a profile —
  [`gitiup_normalise::Profile`](../crates/gitiup-normalise) is version `1`, `repro` —
  and records *its* version. A report that hands over raw text while
  claiming version `7` is refused rather than believed.
* If the logs arrived pre-hashed, the declared version is kept as the runner's
  claim about the profile it used.
* An empty stream needs no profile — every profile hashes it the same — which is
  why a report may omit a step's empty `stderr` whatever the declared version.

What version `1` rewrites, why, and what a workflow must do so that there is as
little as possible to rewrite is
[reproducibility — the contract](reproducibility.md); `gitiup normalise` prints the
record for one run and compares two. A `kind` is any string (the format does not
enumerate one), but the names version `1` emits are the twelve rule names plus the
field names `exit-code`, `output:<name>`, `artifact:<name>`, `input:<name>`,
`pin:<name>`, `source:*` and `step`, each suffixed `:stderr` for the error stream.

## Order, whitespace, and what is genuinely part of a digest

* **Order-free**: `matrix`, `inputs`, `pins`, `annotations` (maps), and
  `secret_names`, `reusable_workflows`, `environment.toolchain`, per-step
  `artifacts`, `claims.timings`, `claims.normalisation_diffs` — sorted by
  `normalize()` before encoding, so a producer's discovery order cannot show up in
  a digest.
* **Ordered**: `steps`. Execution order is a fact about the run.
* **Whitespace**: none of the *report's* whitespace is hash-visible, because a
  report is parsed and never encoded. Whitespace *inside a log line* is content:
  it is part of the digest unless a profile rewrites it — version `1` canonicalises
  line endings and field spacing, and the
  [reproducibility contract](reproducibility.md) (pin actions, pin images, honour
  `SOURCE_DATE_EPOCH`, sorted manifests) is what makes two machines' logs hash
  alike in the first place.
* **No floats, no nulls**: integers only in everything that reaches the manifest
  ([ADR-0001 D1](adr/0001-attestation-encoding-hash-and-signature.md)), and an
  absent field is an omitted key. `"duration_us": 5.5` is refused, not truncated.
* **Explicit lengths**: multi-part digests length-prefix each part
  (`Digest::sha256_parts`), so `["ab","c"]` and `["a","bc"]` and `"abc"` all hash
  differently.

## Command line

```console
$ gitiup digest run.json
run            sha256:5b71fcfdccb72830d84e1423292ede463d2216fe72c2a4cab2e3b354b8deb819
result         sha256:28c73827c9a5506837c179128bca275f7f0ef42d84375f1b408573cfd62e82e4
tier           simulated
runner         gitiup 0.1.0
commit         sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
workflow       .github/workflows/hello.yml sha256:cc8c24530e48059825f106519a09283febdc7d10ca8fdd6bf2857be039b1ad4a
event          push
job            hi
environment    x86_64 · fingerprint sha256:b3bad75a23bccc3e05cab514359422878a64dabb059753292538f5d41079472c
steps          1 (1 succeeded, 0 failed, 0 skipped)
normalisation  v0
```

`--json` gives the same facts as one sorted-key line for scripts, `--quiet` prints
the `RunDigest` alone, and `--expect <digest>` / `--expect-result <digest>` turn
"did this rerun converge?" into an exit status (8 on disagreement — the same class
`gitiup verify attestation` will report for a digest that does not match).

## Tests that hold this down

| file | what it proves |
|------|----------------|
| `crates/gitiup-attest/tests/run_digest_golden.rs` | five representative workflows hash to the committed digests and to the committed canonical manifest bytes |
| `crates/gitiup-attest/tests/run_digest_properties.rs` | reordering and reformatting cannot move a digest; idempotence; and one mutation per report field, so a dropped field cannot hide |
| `crates/gitiup/tests/digest_cli.rs` | the command prints the same numbers as the library, including for the committed fixtures |
| `crates/gitiup-attest/tests/golden.rs`, `format_properties.rs` | the format underneath (envelope, signatures, canonical form) |

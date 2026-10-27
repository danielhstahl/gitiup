# gitiup-normalise

Output normalisation: the layer that makes two independent runs of one workflow
converge on **one** `ResultDigest`.

The format is decided in [ADR-0001](../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
and computed by [`gitiup-attest`](../gitiup-attest/README.md); the *contract* — what
a workflow must do so its products are the same bytes twice — is
[docs/reproducibility.md](../../docs/reproducibility.md). This crate is the other
half: the parts of a log that describe the machine rather than the result, rewritten
into placeholders, and every rewrite written down.

It is a separate crate from `gitiup-attest` on purpose. The format crate does no I/O
and stays small enough to audit in one sitting; a normaliser is a pile of scanners
over untrusted log text, with a different failure mode and a different review
audience. `gitiup-attest` defines the seam — [`Normaliser`] — and this crate fills it.

```rust,ignore
use gitiup_attest::run::{Normaliser, RunReport};
use gitiup_normalise::{Profile, manifest_for};

let log = "2026-10-27T09:11:12.481392Z /tmp/build0a9f/target/debug/gitiup\n";
assert_eq!(
    Profile::standard().normalise(log),
    "<ts> <build>/target/debug/gitiup\n",
);

// The whole report at once: digests, plus the record of what was rewritten.
let report = RunReport::simple(
    "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ".github/workflows/ci.yml",
    "name: CI\n",
    "Finished in 12.5s\n",
)?;
let run = manifest_for(&report)?;
assert_eq!(run.manifest.result.provenance.normalisation_version, 1);
assert!(run.diffs.iter().any(|diff| diff.after.contains("<dur>")));
```

## The API

| item | what it is |
|------|------------|
| [`Profile::standard()`] | the `repro` profile, version `1`, all twelve rules — implement `gitiup_attest::run::Normaliser`, so `RunManifest::from_run_with` takes it |
| [`Profile::without(rule)`] / [`Profile::with_rules(rules)`] | diagnosis, not policy: a restricted rule set must be named as its own version |
| [`Profile::normalise_stream(text, stream)`] | one stream in, canonical text out (`normalise(text)` is the stdout shorthand) |
| [`Profile::normalise_recorded_stream`] | the same, plus the full per-line [`Rewrites`] record |
| [`manifest_for(report)`] | report in → validated manifest out, with normalised log digests, the version recorded, and `claims.normalisation_diffs` filled |
| [`compare_runs(a, b)`] | two runs of one workflow in → `Comparison { converged, result_a, result_b, manifests, divergences }` |
| [`Rules::parse_list`] | `"timestamp,duration"` → a rule set, refused with a message if a name is wrong |

```text
raw logs ──Profile::normalise_stream──► normalised text ──sha256──► Step { stdout, stderr }
                                                                      │
  run report ──manifest_for──► RunManifest ──canonical──► sha256 ─────► RunDigest / ResultDigest
```

## What is rewritten

Twelve rules, applied in this order: `line-ending`, `ansi`, `progress`, `path`,
`identity`, `timestamp`, `duration`, `percent`, `number`, `size`, `spacing`,
`listing`. Each has a name (which is the `kind` of the diff it produces), a
placeholder (`<ts>`, `<dur>`, `<pct>`, `<build>`, `<tmp>`, `<home>`, `<rand>`,
`<host>`, `<user>`, `<id>`, or a canonical byte count), and a reason;
[docs/reproducibility.md §3](../../docs/reproducibility.md) is the table, and
[`grammar::Rule`](src/grammar.rs) is the executable version of it.

Three properties, all tested:

* **a projection** — `normalise(normalise(x)) == normalise(x)`, so the digest does not
  depend on how many times a log was piped through;
* **conservative** — versions, commit ids, hashes and target triples survive verbatim;
  a divider line is not a progress bar;
* **honest** — every rewrite is recorded, over-cap rewrites are reported as
  `kind:truncated` rather than dropped, and a divergence is quoted with its line
  number and both sides.

Architecture is *not* normalised: the claim is per architecture, and hiding that
would make a digest look portable when it is not.

## Versioning is the contract

`provenance.normalisation_version` records which rules produced the hashed bytes:
`0` is "nothing was rewritten" ([`gitiup_attest::run::RawText`]), `1` is this
profile. A rule that changes an output is a new version and a documented format
change, because two results normalised under different versions are not comparable.

`manifest_for` rewrites the version only for streams it normalised itself, and
refuses a report that mixes pre-hashed digests with raw text — one manifest cannot
describe two rule sets.

## Tests

* `tests/corpus.rs` — the acceptance criterion as data: two machines, one
  architecture, logs that disagree about clock, durations, paths, host/user/uid,
  progress churn, locale, line endings and listing order, converging on one pinned
  `ResultDigest`; and the counterfactual, pinned too (without normalisation they do
  *not* converge, or the corpus proves nothing).
* `tests/divergence.rs` — divergence reporting: a real failure surfaces as named
  `NormalisationDiff`s, one per `(step, kind)` so `normalize()` cannot drop one, and
  a pre-hashed stream reports the digests it has instead of guessing.
* `tests/properties.rs` — idempotence over the whole corpus and per rule, inert
  output left alone, empty streams, the rewrite cap, rule selection, and "every rule
  in the list earns its place in the corpus".
* `cargo run -p gitiup-normalise --example make_corpus` regenerates the fixtures
  (`GITIUP_UPDATE_FIXTURES=1`); `--example normalise_log` is the same thing the CLI
  does, for poking at one log by hand.

[`Normaliser`]: ../gitiup-attest/src/run.rs
[`Profile::standard()`]: src/profile.rs
[`Profile::without(rule)`]: src/profile.rs
[`Profile::with_rules(rules)`]: src/profile.rs
[`Profile::normalise_stream(text, stream)`]: src/profile.rs
[`Profile::normalise_recorded_stream`]: src/profile.rs
[`manifest_for(report)`]: src/manifest.rs
[`compare_runs(a, b)`]: src/run.rs
[`Rules::parse_list`]: src/grammar.rs
[`Rewrites`]: src/rewrite.rs
[`gitiup_attest::run::RawText`]: ../gitiup-attest/src/run.rs

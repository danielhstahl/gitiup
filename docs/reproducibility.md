# Reproducibility — the contract

A digest that only the machine that produced it can reproduce is not evidence. This
document is the whole agreement that makes a rerun reproduce it, in the two places
it has to be made:

* **what a workflow must do** so its products are the same bytes twice (§2) — the
  author's side, written into the workflow, not into a library; and
* **what the runner rewrites** so the parts of a log that describe the *machine*
  rather than the *result* stop changing the digest (§3) — implemented by
  [`gitiup-normalise`](../crates/gitiup-normalise), versioned by
  `provenance.normalisation_version`.

The two halves are not interchangeable. A normaliser cannot fix an artifact whose
bytes contain a build timestamp, and must not try: the digest of an artifact is the
point of the artifact. Conversely, a workflow can be perfectly deterministic and
still print `Finished in 41.283s`, which is a fact about the machine's clock and
nothing else.

## 1. The claim

Exactly one sentence is being claimed, and it is narrower than "CI is deterministic":

> The same commit, the same workflow, the same inputs and matrix, and the same
> machine architecture, run twice independently, produce one `ResultDigest`.

Two digests exist and only one of them is expected to be stable
([ADR-0001 D4](adr/0001-attestation-encoding-hash-and-signature.md)):

| digest | covers | across two honest reruns |
|--------|--------|--------------------------|
| `ResultDigest` | `result`: source, environment fingerprint, steps, outputs, artifacts | **identical** — this is the claim |
| `RunDigest` | the whole manifest, including `claims` | **different** — run id, clock, timings and the normalisation record are one-event facts |

A verifier compares `ResultDigest`. A dispute is argued about `claims`, where
`normalisation_diffs` lives precisely because the `before` side is machine-specific
and must never enter a digest ([ADR-0001 D5](adr/0001-attestation-encoding-hash-and-signature.md)).

## 2. The workflow-side contract

Twelve rules, each stated as what to do and what it prevents. They are checks on a
workflow file, not aspirations: a workflow that violates one of them can still run,
but its reruns will not converge and the mismatch will be in an artifact rather than
in a log line, where §3 cannot help.

### 2.1 Pin by content, not by name

1. **Pin every action to a full commit SHA.**
   `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`, not
   `@v4`. A tag is a moving reference: `v4` can point at a different commit between
   two runs, and the tag owner can repoint it after the fact. The runner records
   `pins`, so a verifier can check what was *used*, not what was *asked for*.
   (Same for reusable workflows and composite action repositories.)
2. **Pin container images by digest.**
   `image: rust:1.99-bookworm@sha256:…`, not `image: rust:1.99` and never `:latest`.
   The same tag on Tuesday and Thursday can be different filesystems; the registry
   re-pushes tags without warning.
3. **Pin dependency resolution.** A lockfile that is committed and honoured
   (`cargo.lock`, `uv.lock`, `npm ci`, `go build` with a `go.sum`), not a range that
   resolves against whatever index state exists at 09:11.

### 2.2 Order things explicitly

4. **Sort every listing that becomes an artifact or an output.** `find . | sort`,
   `tar --sort=name`, `LC_ALL=C sort`, `jq -S` for JSON manifests. Directory order
   is filesystem-dependent and a `sha256` of a tarball is a sha256 of whatever order
   `readdir` returned. The normaliser sorts *log listings* (§3, `listing`), which
   makes a log readable either way; it cannot sort an artifact.
5. **Enumerate the matrix fully.** `matrix: { os: [ubuntu-24.04] }`, never a dynamic
   list built from an API call. The set of jobs is part of `result`.

### 2.3 Do not bake the clock or the machine into products

6. **Honour `SOURCE_DATE_EPOCH`.** Where the build can be told what "now" is, it must
   be told: autoconf/`make`, Sphinx, `dos2unix`, `gzip -n`, `tar --mtime=@$SOURCE_DATE_EPOCH
   --clamp-mtime`, `dpkg-buildpackage`, and the wider
   [reproducible-builds.org](https://reproducible-builds.org/docs/source-date-epoch/)
   list. Set it once in the workflow environment to a fixed value (the commit's own
   timestamp, or `0`) so every step agrees.
7. **Strip or fix build paths and build IDs.** `-ffile-prefix-map=$PWD=`,
   `-fdebug-prefix-map`, Go's `-trimpath -buildid=`, Rust's
   `--remap-path-prefix=$PWD=`, `-LC_ALL=C`. Paths that name the runner's home
   directory end up in binaries, debug sections and coverage reports.
8. **Normalise container/archive metadata.** uid/gid, owner names, mtime and file
   mode inside tarballs, cpios, OCI layers and zip entries are content. Use
   `--uid=0 --gid=0 --owner=0:0 --mtime=@…` and their equivalents.
9. **No clock, hostname or PID in a product.** Not in a version string
   (`1.2.3+20261027`), not in a generated header, not in a PDF or HTML build. If a
   version must carry a build time, derive it from the commit, not from `date`.

### 2.4 Keep formatting out of the log where you can

10. **Fix the locale and the unit system.** `LC_ALL=C` (and `LANG=C`) in the job
    environment: collation order, decimal separators, translated status lines and
    grouped digits all follow it. §3 undoes digit grouping and size spelling, but
    it cannot know whether `1,5 seconds` was a locale or a French-speaking
    developer.
11. **Do not print the machine's identity to stdout if you can avoid it.** `id`,
    `uname -a`, `hostname`, `$RUNNER_TEMP` echoed for debug all become
    placeholders under §3 — but every one of them is a rewrite that has to be
    recorded, and a rewrite is a place where a real difference can hide.
12. **Leave progress reporting to the runner.** `--quiet`, `--no-progress`,
    `CARGO_TERM_PROGRESS_WHEN=never`, `-B` for `make` and `ninja`. A redrawn bar is
    a machine's refresh rate written into a log; §3 resolves it to what the terminal
    finally showed, but the cheapest progress line to normalise is the one that was
    never printed.

A workflow that obeys all twelve produces logs where §3 has almost nothing to do —
which is the test of whether the contract is being followed. `claims.normalisation_diffs`
is the measurement: an empty list means the log was already canonical for that step.

## 3. The runner side: the `repro` profile (version 1)

`Profile::standard()` rewrites twelve kinds of incidental text in a step's stdout
and stderr. Each rule has a name (the `kind` of a diff), one placeholder where a
value was, and a reason.

| rule | rewrites | example |
|------|----------|---------|
| `line-ending` | CRLF→LF, tabs→spaces, no trailing blanks, no BOM | `a\tb  ` → `a b` |
| `ansi` | strips ANSI/VT sequences, resolves `\r` and `\b` overwrites to what the terminal finally showed | `Downloading 12%\rDownloading 100%` → `Downloading 100%` |
| `progress` | drops a line that is nothing but a bar or a spinner | `####---- 45%` → *(line deleted)* |
| `path` | machine roots → `<build>`/`<tmp>`/`<home>`, generated components → `<rand>` | `/home/runner/work/gitiup/gitiup/target` → `<build>/target` |
| `identity` | hostnames, user names, `uid=`/`gid=`/`pid=` → `<host>`/`<user>`/`<id>`; `ls -l` owner columns | `runner@fv-az1024` → `<user>@<host>` |
| `timestamp` | ISO-8601, ctime and syslog dates, RFC-2822 and git committer dates, `Day DD Month`, bare `HH:MM:SS` → `<ts>` | `2026-10-27T09:11:12.481392Z` → `<ts>` |
| `duration` | `<n>` + unit, incl. composites (`1m 2s`, `1 h and 5 m`) → `<dur>` | `finished in 41.283s` → `finished in <dur>` |
| `percent` | percentages → `<pct>` | `60%` → `<pct>` |
| `number` | locale digit grouping (`1,234,567`, `1 234 567`) → `1234567` | |
| `size` | file sizes to a canonical byte count | `1.5 KiB` → `1536B`, `4.0K` → `4096B` |
| `spacing` | one canonical separator between fields; runs of blank lines collapse to one | `Date:   X` → `Date: X` |
| `listing` | sorts a run of same-shaped listing lines (`ls -l` rows, one-path-per-line, `- item`) whose order nothing means | |

Machine-architecture facts are **not** rewritten: `x86_64-unknown-linux-gnu`, the
toolchain table, the environment fingerprint and the runner's own version string all
stay. The claim is per architecture; erasing the architecture would make a digest
look portable when it is not.

Three properties the profile has to keep, all tested in
[`tests/properties.rs`](../crates/gitiup-normalise/tests/properties.rs):

* **it is a projection**: `normalise(normalise(x)) == normalise(x)`. A normaliser
  that was not idempotent would make the version number meaningless, because the
  digest would depend on how many times somebody piped a log through;
* **it is conservative**: output with nothing machine-specific in it is untouched —
  versions, commit ids, hashes and target triples survive verbatim;
* **it is honest**: every rewrite is recorded (§4), and every rewrite beyond the
  record cap is reported as `kind:truncated` rather than dropped.

The corpus in
[`tests/fixtures/corpus/`](../crates/gitiup-normalise/tests/fixtures/corpus) is the
acceptance criterion as data: two machines, one architecture, logs that disagree
about every category above (machine B additionally speaks a comma-decimal locale and
writes CRLF), and a pinned `ResultDigest` that both produce after normalisation and
that neither produces without it.

## 4. Reporting what did not converge

When two runs still disagree, the answer is never allowed to be "the hashes differ".
A divergence is a `NormalisationDiff` — the same record
[`gitiup-attest`](../crates/gitiup-attest) defines, and the same type a dispute
report will carry:

```jsonc
{
  "step": "test",              // step id, or "-" for the run itself (source, inputs, pins)
  "kind": "stdout",            // the rule name, or the field: "exit-code", "output:<name>",
                               // "artifact:<name>", "input:<name>", "pin:<name>",
                               // "source:matrix", "step". Streams are suffixed
                               // ":stderr"; oversized records are suffixed ":truncated".
  "before": "line 3: test result: ok. 118 passed",   // run A, with a line number
  "after":  "line 3: test result: FAILED. 117 passed" // run B, or "(line absent)"
}
```

Rules that keep this usable:

* **one diff per `(step, kind)`**, because `claims.normalisation_diffs` is keyed that
  way and `RunManifest::normalize()` would otherwise silently drop all but one. Many
  rewrites collapse into one diff with up to three samples joined by ` || ` and
  `( +N more )`;
* **the stream is part of the key** (`timestamp` vs `timestamp:stderr`), for the same
  reason;
* **text is quoted with its line number**, because "somewhere in 900 lines" is not a
  diagnosis;
* **a stream that arrived pre-hashed reports the two digests** (`stdout:digest`)
  rather than pretending the contents were compared;
* **control bytes and over-long text are sanitized on the way in**, because a diff
  containing a raw ESC byte would make the *manifest* unencodable — a second bug
  inside the report of the first.

The two entry points are `gitiup_normalise::compare_runs(a, b)` in the library and:

```sh
# one run: what was rewritten, line by line, and the digest that resulted
cargo run -p gitiup -- normalise run.json
# two runs: did they converge, and if not, what differs
cargo run -p gitiup -- normalise --compare run-a.json run-b.json
```

Exit code `8` on divergence is the same verdict `--expect` gives on `gitiup digest`
([ADR-0001 D7](adr/0001-attestation-encoding-hash-and-signature.md)),
so a merge gate can branch on one number.

## 5. Versioning

`provenance.normalisation_version` records which rules produced the bytes that were
hashed. It is not a free field:

| version | profile | meaning |
|---------|---------|---------|
| `0` | `RawText` (in `gitiup-attest`) | nothing was rewritten; the digest is the digest of the bytes as written |
| `1` | `repro` (this crate) | the twelve rules above, in the order in `RULE_ORDER` |

* A rule change that alters any output is a **new version**, and a new version is a
  change to the format — documented, and pinned in a new corpus digest — not a
  refactoring. Two runs normalised under different versions are not comparable,
  which is the whole reason the number is inside the signed `result`.
* A runner that normalises a stream elsewhere must say so by writing its own version
  number; `manifest_for` rewrites the version only for streams it normalised itself,
  and refuses a report that mixes pre-hashed digests with raw text rather than
  averaging two rule sets into one claim.
* A restricted rule set (`--rules`, `Profile::with_rules`) is a different rule set.
  It is offered for diagnosis — "which rule is causing this?" — and using it in a
  runner means naming it as its own version.

## 6. What normalisation deliberately is not

* **Not a secret scrubber.** Placeholders make a log portable, not safe. Secrets are
  kept out of logs by the workflow and by `gitiup`'s own masking of
  `secrets.*` values; a normalised log is still a log a human may not be allowed to
  read.
* **Not a fix for a genuinely different result.** Normalisation never changes an exit
  code, an artifact digest, a workflow source identity, an event payload, an input
  or a matrix. If those differ, the runs differed, and §4 says so.
* **Not a rewriter of arbitrary text.** It recognises shapes — dates, durations,
  sizes, paths, `ls` rows — and leaves prose alone. Where it must guess, it does not:
  an unlabelled digit run stays put, and a divider line is not a progress bar.
* **Not silent.** Rewriting logs without recording it would be the fastest way to
  make a reproducible digest that hides a real difference. The record is mandatory,
  capped, and self-reporting when the cap bites.

## 7. Where it lives

| place | what |
|-------|------|
| [`crates/gitiup-normalise/src/grammar.rs`](../crates/gitiup-normalise/src/grammar.rs) | the rule enum and order, the placeholder vocabulary, the token scanners |
| [`…/src/values.rs`](../crates/gitiup-normalise/src/values.rs) | timestamps, durations, percentages, digit grouping, sizes |
| [`…/src/paths.rs`](../crates/gitiup-normalise/src/paths.rs) | machine paths and identity |
| [`…/src/term.rs`](../crates/gitiup-normalise/src/term.rs) | line endings, ANSI, carriage redraws, bars and spinners |
| [`…/src/log.rs`](../crates/gitiup-normalise/src/log.rs) | the pipeline, in order |
| [`…/src/rewrite.rs`](../crates/gitiup-normalise/src/rewrite.rs) | the record: full per-line, and aggregated to what a manifest can carry |
| [`…/src/manifest.rs`](../crates/gitiup-normalise/src/manifest.rs) | `manifest_for`: report in, manifest and diffs out |
| [`…/src/run.rs`](../crates/gitiup-normalise/src/run.rs) | `compare_runs`: two runs in, a verdict and the divergences |
| [`…/tests/`](../crates/gitiup-normalise/tests) | the corpus (§3), divergence behaviour, properties |
| `cargo run -p gitiup-normalise --example make_corpus` | regenerates the corpus fixtures (`GITIUP_UPDATE_FIXTURES=1`) |

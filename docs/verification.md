# Verification: what `gitiup verify attestation` decides

Ticket `giti-1rs.8`. Everything before this ticket — canonical manifests
([ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md)), the run digest,
normalisation, the environment fingerprint, the tier ladder, storage in a host,
signing keys — produces a signed document. This is the moment someone decides whether
to act on it.

```sh
gitiup verify attestation proof.json --policy gitiup-policy.json --json
```

One command, one exit code, and a report that says what was checked. It is meant to be
the line a `pre-receive` hook, a CI job, a merge gate, or a volunteer's shell runs —
which means it has to be *scriptable* first and pretty second.

## The exit codes are the interface

| exit | verdict | meaning |
|------|---------|---------|
| **0** | `pass` | accepted: everything below that was asked passed |
| 2 | — | usage: unknown flag, nothing named (not a verdict) |
| 3 | — | I/O: the file could not be read, the store could not be reached (not a verdict) |
| **6** | `policy` | refused: untrusted signer, too few signatures, tier or sandbox not allowed, stale or future-dated, wrong machine class, unparseable document |
| **7** | `bad_signature` | a signature does not verify, or a `key_id` is not the fingerprint of the key offered |
| **8** | `digest_mismatch` | the bytes are not the canonical form, the manifest does not hash to its own digest, the binding (commit / result / challenge) is not the one expected, or a store returned bytes other than the ones its name promises |

These are [ADR-0001 D7](adr/0001-attestation-encoding-hash-and-signature.md)'s
taxonomy and no other. They are computed by
[`ErrorKind::exit_code`](../crates/gitiup-attest/src/error.rs) in the format crate,
not by the CLI, so a merge gate calling
[`AttestationDoc::verify`](../crates/gitiup-attest/src/envelope.rs) and a human
running the command get the same number from the same bytes. That is the whole reason
the taxonomy lives in the library.

Two conventions fall out of that table, and both are tested
([`verify_cli.rs`](../crates/gitiup/tests/verify_cli.rs)):

* **A verdict is not an error.** 0, 6, 7 and 8 print the report on **stdout** and say
  nothing on stderr; the verdict is in the exit code. A CI step that merges the two
  streams still gets a parseable report, and one that only reads stderr does not see a
  "failure" for a proof that was accepted.
* **Only exit 0 is a success, and only 2/3 are silent about the document.** If the
  bytes could not be read at all, that is still a verdict (`6` if it is not a
  document this build speaks, `8` if it is a document whose bytes are not canonical) —
  it is printed as one, with the ladder showing what was never reached.

```sh
# A pre-receive hook: refuse the ref unless the proof for this commit is good enough.
gitiup verify attestation --store ./store --commit "$newrev" \
    --policy ./gitiup-policy.json --json >/tmp/verify.json || {
    jq -r '.reasons[] | "refused: [\(.code)] \(.detail)"' /tmp/verify.json >&2
    exit 1
}
```

## The ladder: what gets checked, in which order

The order is ADR-0001 D7's, fixed because the **first** failure decides the exit code
— an attestation that is both expired and bound to the wrong commit must not be
reported as "expired" and send somebody off to re-run a job that was never the
problem. Every check still runs (unless an earlier one made it meaningless), so one
invocation says everything that is wrong; only the first reason sets the exit code.

| code | what it establishes | fails as |
|------|---------------------|----------|
| `structure` | the bytes are a document this build speaks: canonical encoding, known `schema_version` and `payload_type`, no unknown fields, signatures sorted and one per key | 6, or 8 if they are not the canonical bytes |
| `digest` | the manifest re-hashes to `sha256(canonical(manifest))` and the algorithm is allowed | 8 |
| `commit` | with `--commit`, it is an attestation about *that* commit | 8 |
| `result` | with `--expect-result`, its `ResultDigest` is the one expected — the quorum's comparison, expressed as a flag | 8 |
| `challenge` | with `--expect-challenge`, it answers the round it is offered for (giti-msi.6) | 8 |
| `normalisation` | with `--normalisation-version`, the producer's normalisation rules are that version | 6 |
| `environment` | the run happened on a machine the change accepts (giti-1rs.4) | 6 |
| `signature` | each signature verifies over the received bytes, and its `key_id` is the fingerprint of the key offered | 7 |
| `trust` | every signer is on the trust list | 6 |
| `min_signatures` | enough distinct trusted signers signed it | 6 |
| `tier` | the provenance tier is allowed (default: `local` only — a plan is not an execution) | 6 |
| `sandbox` | a `local` run named a sandbox this policy accepts | 6 |
| `freshness` | the claimed time is within `max-age` and within the clock skew | 6 |
| `expiry` | the document's own `not_after_us` has not passed | 6 |

Checks that were not asked about are reported as `not_asked`, and checks that never
ran because something earlier failed are `not_run`. Both are shown rather than
omitted: a reader has to be able to see what was *not* established. `digest` failing
means `signature` was never checked, and saying so is the difference between a report
and a shrug.

Integrity comes before authority on purpose: `signature` (7) is checked before `trust`
(6), because "signed correctly, by someone you do not vouch for" and "not signed
correctly at all" are different incidents with different responses. An entry that
claims a famous fingerprint while carrying a different key fails at `signature` and
is never asked about trust.

## The machine-readable verdict

`--json` prints one line, keys sorted, and the shape is pinned by a test:

```jsonc
{
  "verdict": "policy",            // pass | policy | bad_signature | digest_mismatch | invalid | unsupported_schema
  "exit": 6,                      // the exit code, in the payload too
  "accepted": false,
  "source": "file proof.json",
  "stored": null,                 // the store's content address, when read from a store
  "reasons": [                    // every problem found, first one decides `exit`
    {
      "code": "environment",
      "class": "policy",
      "detail": "this run's arch is 'aarch64', which does not match what this change requires: amd64 (canonical x86_64)",
      "exit": 6
    },
    {
      "code": "tier",
      "class": "policy",
      "detail": "provenance tier 'simulated' is not accepted here",
      "hint": "a simulated run plans but does not execute; run it for real …",
      "exit": 6
    }
  ],
  "checks": [ { "code": "structure", "outcome": "passed" }, … ],
  "policy":  { "trust": "gitiup-policy.json, 1 key(s)", "trusted_key_ids": ["SHA256:…"],
               "tiers": ["local"], "min_signatures": 1, "max_age": "1d",
               "require_env_match": "strict", "environment_requirement": "arch=amd64",
               "now": "2026-10-27T10:00:00Z", … },
  "attestation": { "run_digest": "sha256:…", "result_digest": "sha256:…",
                   "commit": "sha1:…", "tier": "local", "sandbox": "landlock",
                   "signers": [{ "key_id": "SHA256:…", "algorithm": "ed25519" }],
                   "claimed_at": "2026-10-27T09:15:02Z", "steps": 3, … }
}
```

Two blocks earn their place there:

* **`policy`** — a verdict is only interpretable next to the question it answered.
  "accepted" under a policy that trusted every key on the box is not the same fact as
  "accepted" against the owner's list, so the trust source, the tiers, the window, the
  environment requirement and the clock used are all printed. A gate that logs this
  can be audited afterwards; a bare `0` cannot.
* **`attestation`** — printed for refusals too, because a rejected proof is exactly
  when a human needs to see its tier, its signers and its age. It is `null` only when
  the bytes were not a document at all. `source` names where the bytes came from, and
  `stored` carries the store's content address when they came from one — so a verdict
  can be tied to the exact object that was read, not just to the digest someone asked
  for.

`-q` is the one-word form for a shell that only tests the exit code: `ok`, or the code
of the reason that decided the verdict (`freshness`, `trust`, `signature`, …).

The same ladder in table form, for a human. This document fails two checks, and both
are printed even though only the first one sets the exit code:

```text
source        file proof.json
run           sha256:994698a11e4cbe855aedf227980bc75f74342b470e611c519dbe45bb864f1b1f
result        sha256:fee3b8e9194ff042b5725fd200f3b2360a9ab2b8c57a9b121e1aebb74d2ed88f
commit        sha1:dddddddddddddddddddddddddddddddddddddddd · job test
workflow      .github/workflows/ci.yml · pull_request
tier          local · runner gitiup 0.1.0 · sandbox landlock · normalisation v0
environment   os macos · arch aarch64 · provider shell · fingerprint sha256:d32af993…
claimed       2026-10-27T09:15:02Z (44m57s old)
signed        SHA256:3l7Z…QG3g (ed25519)
steps         3
policy        trust: --trust, 1 key(s) · tiers simulated · min 1 signature(s) · max age 1d · env arch=amd64 (strict)

checks
  structure       ok
  digest          ok
  commit          not asked
  result          not asked
  challenge       not asked
  normalisation   not asked
  environment     REFUSED    · this run's arch is 'aarch64', which does not match what this change requires: amd64 (canonical x86_64)
  signature       ok
  trust           ok
  min_signatures  ok
  tier            REFUSED    · provenance tier 'local' is not accepted here
  sandbox         not run
  freshness       ok
  expiry          not asked

verdict       POLICY (exit 6)
reason        [environment] this run's arch is 'aarch64', which does not match what this change requires: amd64 (canonical x86_64)
also          [tier] provenance tier 'local' is not accepted here
              hint: adjust the owner's allowed provenance tiers deliberately: allowed here are simulated
```

`sandbox  not run` is the ladder being honest: the tier check already decided this
attestation may not be believed, so there is nothing for the sandbox check to add — and
the report says it was not checked rather than leaving the reader to assume it passed.

## Where the policy comes from

A policy is not one flag; it is the same
[`Policy`](../crates/gitiup-attest/src/policy.rs) `gitiup run` and a hook consult,
built from three places, in this order of precedence:

1. **`--policy <path>`** (or `$GITIUP_POLICY`) — the `gitiup-policy.json` a repo
   commits next to the change: `trust_key_ids`, `allowed_tiers` / `allow_simulated`,
   `allowed_sandboxes`, `min_signatures`, `max_age_us`, `require_arch` and the rest of
   the environment requirement, `require_normalisation_version`. Written once, reviewed
   like code, read identically by the runner, the gate and the volunteer.
2. **The command line**, which overrides the file field by field: `--tier`,
   `--sandbox`, `--min-signatures`, `--max-age`, `--max-skew`, `--normalisation-version`,
   `--require <field=value>`, `--require-env-match`, `--expect-result`,
   `--expect-challenge`, `--commit`, `--now`.
3. **Trust, if nothing named it:** `--trust <key>` (a `SHA256:` fingerprint or a name
   in this machine's keystore, repeatable), else the file's `trust_key_ids`, else this
   machine's own keystore — the same local-trust rule `gitiup identity verify` and
   `gitiup participant` use, and *named in the output*, because a proof accepted
   because of a keyring nobody mentioned is a proof accepted by accident. Nothing is
   trusted silently, and an empty keystore with no `--trust` is a refusal (6), not a
   shrug.

`--trust-any-key` accepts any key whose signature verifies. It answers "is this
self-consistent?" and never "may I merge?", and it prints that in every output; it is
for diagnosis and for `gitiup doctor`, not for a gate.

Two knobs that look like conveniences and are not:

* **`--now <time>`** pins the clock. Freshness is a window against *now*, so a pinned
  clock is how a decision made last month is replayed today — and it is what makes the
  tests deterministic. It is not a way to make an old proof fresh in a gate: pin it
  there and the `policy` block says `--now … (the clock was pinned)` out loud.
* **`--max-age never`** exists because a long-lived archive is a legitimate thing to
  want, and because the honest spelling of "I am not checking freshness" should be
  longer than `--no-freshness-check`.

## Reading the document: a file, a pipe, or a store

```sh
gitiup verify attestation proof.json                      # the bytes `attest push` wrote
gitiup attest show --digest "$d" --store ./store --bytes | gitiup verify attestation -
gitiup verify attestation --store ./store --commit "$(git rev-parse HEAD)" --policy gitiup-policy.json
```

`--commit <oid>` with a store both *locates* the proof and *binds* the verdict to that
commit: an attestation about another commit is refused at 8 rather than accepted
because it was filed in the right place. A commit with more than one attestation is a
question, not a coin toss — the command refuses (6) and lists the digests, because
choosing the newest is a policy (giti-kd4.5's), not a default.

Reading from a store means trusting the store, so the store is part of what gets
checked: the bytes must re-hash to the content address they are filed under, and the
ref must have advertised them for the commit named. A store that hands back other
bytes is refused at **8** — corruption is a digest mismatch, not an I/O nuisance —
while a store that cannot be reached at all stays **3**, because no decision was made.

## The merge question: `gitiup verify change`

`verify attestation` answers a question about one proof. A reviewer and a
`pre-receive` hook need the question about a *change*:

```console
$ gitiup verify change chg-6a6a8eab778ba4d0 --store ./store --json
```

It resolves the change, reads every attestation the store advertises for its head,
reads the quorum verdicts under `refs/gitiup/verdict/<change>/**` if the store carries
any, and answers once: **0** may merge · **6** refused · **7** a signature that does not
verify · **8** a digest that is not the bytes or the commit it names. Same exit
taxonomy, same report shape, one document — with a section per attestation underneath,
so a gate reads one thing. Every failure is in the report; the first (integrity before
authority) is what the exit code carries.

Two clocks, because two questions are being asked
([ADR-0004 D6](adr/0004-published-policy-format-signing-and-resolution.md)). Each
attestation is judged by the policy revision that was in force **when that run
happened** — today's rules must not refuse last week's correct run. The merge itself —
what is demanded at all, whether the policy gates the target ref, and how many
signatures make a set — is judged by the revision in force **now**, or at `--at` for a
replay. Freshness is measured against the reader's clock (`--now` pins it), so an old
proof can be judged by old rules and still be too stale to merge today.

`min_signatures` counts **distinct trusted signers certifying one `ResultDigest`**, not
files: two attestations from one key are one signature, and two that certify different
results certify two claims. The report names the combination it accepted — the
attestations, the keys, and the result — so a gate is never told to trust a file it
cannot identify. A quorum verdict may carry the merge where the policy accepts the
`quorum` tier and the verdict's own agreement reaches the policy's number; a verdict is
believed only as far as the owner's signature on it, and one drawn against a different
head is an **8**.

What is in force is never a guess: a tree-file policy is a draft and is
*not* gate-eligible, `--policy` is an operator's act and is, and the store's published
revision is what a repository's owner signed
([ADR-0004](adr/0004-published-policy-format-signing-and-resolution.md)).

A hook that only branches on the answer takes one word instead of a document — `ok`, or
the code that decided it:

```console
$ gitiup verify change chg-6a6a --store ./store --quiet
min_signatures
```

## What it deliberately does not do

* **No network, no fetch, no key discovery.** Keys are supplied by the caller (a
  `--trust` name in the local keystore, or the policy file), exactly as the format
  crate refuses I/O so it can run inside a `pre-receive` hook under DoS. Log anchoring
  stays a separate signed record (ADR-0001 D9), never a fetch inside verification.
* **It does not decide the merge.** It answers "is this attestation good enough?" and
  exits. Whether a *merge* may proceed — how many attestations, from which quorum,
  recorded where — is [`gitiup verify change`](#the-merge-question-gitiup-verify-change)
  and the quorum verdict ([giti-msi](quorum.md)), which call this and add their own
  reasons.
  [`VerdictReport::add_reason`](../crates/gitiup-attest/src/report.rs) exists so a
  caller can extend a report ("the signature is fine and the policy is fine, and I
  still refuse it because this round closed an hour ago") without inventing a second
  verdict format.
* **No revocation list yet.** `trust_key_ids` is an allow-list, so revocation is
  "remove it from the list", which works but has no *reason* and no *date*, and cannot
  answer "was this fresh and trusted when it merged?". ADR-0001 D6 says this is the
  honest limit of a self-claimed timestamp; the merge record and a dated revocation
  list are the fix, and this ticket does not pretend otherwise.

## Where the decisions live

| thing | file |
|-------|------|
| the ladder, in order, and every reason | [`AttestationDoc::verify_report`](../crates/gitiup-attest/src/envelope.rs) |
| `Check` / `Reason` / `VerdictReport`, and `CHECK_ORDER` | [`report`](../crates/gitiup-attest/src/report.rs) |
| the exit code for a class of failure | [`ErrorKind::exit_code`](../crates/gitiup-attest/src/error.rs) |
| what a policy may demand | [`policy`](../crates/gitiup-attest/src/policy.rs) |
| argv, the keystore, the store, the two renderings | [`gitiup/src/verify.rs`](../crates/gitiup/src/verify.rs) |
| the merge gate over a change: the change-level checks, the combination rule, the verdicts | [`gitiup/src/verify_change.rs`](../crates/gitiup/src/verify_change.rs) |

`verify` (the `Result`-returning one a library caller uses) is `verify_report` with
the tail dropped — one set of checks, one order, two question shapes. A printed
verdict and a branched-on verdict cannot disagree, which is the property every consumer
here depends on: the CLI, a merge gate, and the quorum's own verification all walk the
same ladder.

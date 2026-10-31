# Verification: what `gitiup verify attestation` decides

Ticket `giti-1rs.8`. Everything before this ticket — canonical manifests
([ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md)), the run digest,
normalisation, the environment fingerprint, the tier ladder, storage in a host,
signing keys — produces a signed document. This is the moment someone decides whether
to act on it.

```sh
# one proof, judged by the rules the repository's owner published
gitiup policy explain attestation proof.json --store ./store --json

# …or, with no store in reach, by rules an operator names: the same ladder, an
# override instead of a signature
gitiup verify attestation proof.json --policy examples/gitiup-policy.json --json
```

One command, one exit code, and a report that says what was checked. It is meant to be
the line a `pre-receive` hook, a CI job, a merge gate, or a volunteer's shell runs —
which means it has to be *scriptable* first and pretty second.

The two lines above ask the same ladder two different questions, and the difference is
where the rules came from: [policy explain](policy.md) reads them out of the store, over
which the repository's owner holds a signature; `--policy` reads a file somebody named
on the command line. Both are gate-eligible, and only one of them is what a repository
*has* as a policy. See [where the policy comes from](#where-the-policy-comes-from).

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
[`ErrorKind::exit_code`](../crates/gitiup-canon/src/error.rs) — the error taxonomy
`gitiup-attest` re-exports — and not by the CLI, so a merge gate calling
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
# (`gitiup hook install pre-receive` writes this and more — see
# [the gate that runs where the refs land](#the-gate-that-runs-where-the-refs-land-gitiup-hook-install-pre-receive).)
gitiup policy check --commit "$newrev" --ref refs/heads/main \
    --store ./store --json >/tmp/check.json || {
    jq -r '.reasons[] | "refused: [\(.code)] \(.detail)"' /tmp/check.json >&2
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

## The quorum ladder (`tier: quorum`)

A `tier: quorum` attestation is not a run's proof. It is a signed statement about a
round: the round it names, the roster epoch and digest it was tallied under, the
`ResultDigest` the seats agreed on, and the seats that agreed
([`gitiup_quorum::attestation`](../crates/gitiup-quorum/src/attestation.rs),
[giti-zp1.5](quorum.md#attesting-it-gitiup-quorum-verdict---attest)). It is produced by
`gitiup quorum verdict --attest` and by nothing else — `QuorumAttestation::from_verdict`
is the only constructor and it refuses a verdict that is not `verified`.

Because it summarises other attestations rather than describing a run, it is judged on a
ladder of its own, and the difference is one question: **can the verdict be re-derived
from the evidence still in the store?** The document is never believed because of what it
says.

```sh
# a document handed over, checked against the store that ran the round
gitiup verify attestation quorum.json --tier quorum --evidence ./store --trust owner

# a document read out of the store, where the same store holds its evidence
gitiup verify attestation --store ./store --digest <hex> --tier quorum --trust owner
```

| code | what it establishes | fails as |
|------|---------------------|----------|
| `structure`, `digest` | the bytes are a canonical, self-consistent quorum attestation (its own digest re-hashes) | 6, or 8 |
| `tier` | the policy in force accepts `quorum` at all | 6 |
| `signature`, `trust`, `min_signatures` | the key that *asserts* the statement is trusted, is the selector that opened the round, and enough of them did | 7, 6 |
| `commit` | with a commit binding, it speaks about that commit | 8 |
| `round`, `roster` | the round it names is in the store, the selector's signature holds, and the roster epoch and digest match it | 8 |
| `verdict` | re-running `VerdictRecord::evaluate` over the round, the published submissions and the revocations yields the state, reason and result the document states | 6, or 8 for the result digest |
| `seats` | the seats it lists are the seats the tally counted, at the tier the roster qualifies them for | 6 |
| `freshness` | the claim is inside `max-age` of the clock, and not expired | 6 |

Three consequences are deliberate. A quorum attestation with **no store to re-derive
from** is refused (`verdict`, exit 6) even when its signature is perfect: a file can
always be labelled quorum, which proves nothing. A **seat revoked after the fact** undoes
the attestation, because the re-derivation applies revocation as of now, exactly as the
tally did. And a document whose `result_digest` is not the one the evidence produces is a
digest mismatch (**8**), not a policy refusal — a gate branches on those two differently
and should.

The same ladder runs inside `gitiup verify change`: a quorum attestation advertised for
the change's head is a section of its own, judged under the revision in force when the
claim was made, and it counts as the **seats** it lists for `min_signatures` — not as the
one key that filed the summary.

## The machine-readable verdict

`--json` prints one line, keys sorted, and the shape is pinned by a test:

```jsonc
{
  "verdict": "policy",            // pass | policy | bad_signature | digest_mismatch | invalid | unsupported_schema
  "exit": 6,                      // the exit code, in the payload too
  "accepted": false,
  "source": "file proof.json",
  "stored": null,                 // the store's content address, when read from a store
  "provenance": null,             // where these bytes came from; a block, when there was a store
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
  when a human needs to see its tier, its signers and its age. It is `null` when the
  bytes were not a document at all, and when they were a `tier: quorum` attestation:
  that document describes no run, so it has no run to describe. `source` names where the
  bytes came from, and `stored` carries the store's content address when they came from
  one — so a verdict can be tied to the exact object that was read, not just to the
  digest someone asked for.
* **`tier` and `quorum`** — present together, and only for a `tier: quorum` document:
  the tier the ladder judged, and what the document claims about its round (state,
  reason, agreement, seats) next to `rederived` — what the store's own evidence tallies
  to now, or `null` when nothing could re-derive it. A gate reading `--json` should look
  at `tier` first: the two documents are judged on different ladders and a check code
  means something different on each.
* **`provenance`** — printed for every read, and `null` when the bytes came from a file or
  a pipe because there was no store to ask. This is "did these bytes come from the origin,
  or from a copy of it", said where they are read rather than only when a policy cares,
  because a reader who is not told a proof arrived by copy cannot ask whether that
  matters. `age_us` is measured from the signed `claimed_at_us` and never from an arrival
  stamp, an mtime, a pack timestamp or a bucket's `Last-Modified`; `age_basis` is printed
  so that rule is a field a test can assert instead of a sentence to trust
  ([ADR-0005 D5](adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)). So a
  mirror cannot make a proof fresher, whatever its own clock says. `closure`,
  `verified_by` and `verify_exit` are the importing store's account of what it checked
  when the copy arrived: worth reading, and not a signature — belief is still produced by
  `gitiup verify` with *this* machine's roots.

```text
provenance    store copy · age 304764s (claimed_at_us basis) · arrived from https://origin.example.org/repo.git · closure complete · checked here by --trust, 1 key(s) (exit 0)
```

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

A policy is not one flag. The rules a verdict applies are **resolved**, in one order,
and every report says which source won
([ADR-0004 D4](adr/0004-published-policy-format-signing-and-resolution.md),
[docs/policy.md](policy.md)):

1. **`--policy <path>`**, then **`$GITIUP_POLICY`** — an operator's act, and the only
   local file a merge may rest on, precisely because naming it was deliberate. It
   *replaces* what is published — it does not merge with it — and it says so, in a note
   on the answer, because a silent override is how a policy stops being enforced.
2. **The store**: `refs/gitiup/policy/current`, walked to the revision in force, signed
   by the repository's owner, with its `rules` (`trust_key_ids`, `allowed_tiers` /
   `allow_simulated`, `allowed_sandboxes`, `min_signatures`, `max_age_us`, `require_arch`
   and the rest of the environment requirement, `require_normalisation_version`) and its
   `quorum` block. This is the source a repository *has a policy in*: written once, signed,
   reviewable, and read identically by a clone, a hook, a bucket and a build agent that
   has never seen the checkout. [docs/policy.md](policy.md) is the whole of it.
3. **The checkout's `gitiup-policy.json`** — a draft, and *not gate-eligible*. It is what
   `gitiup run` aims at and what an author commits next to the change; it is not what a
   merge may rest on, because a fork can edit it.
4. **This build's default**, which trusts nobody — the safe direction to be wrong in.

A gate that lands on 3 or 4 refuses (`no_policy_published`, exit 6) rather than deciding
a merge by a default nobody chose, and the `pre-receive` hook consults source 2 and
nothing else, so a clone and the box that accepted the push cannot answer differently.

On top of whichever policy won, two kinds of local input:

* **The command line**, which overrides the rules field by field: `--tier`,
  `--sandbox`, `--min-signatures`, `--max-age`, `--max-skew`, `--normalisation-version`,
  `--require <field=value>`, `--require-env-match`, `--expect-result`,
  `--expect-challenge`, `--commit`, `--now`. These are `verify attestation`'s, and they
  answer "what should *this run* have to prove"; the gate-shaped commands
  (`policy check`, `policy explain`, `verify change`, the hook) take no rule flags at
  all, because "what does this repository require" is the owner's signed answer and not
  the caller's.
* **Trust, if nothing named it:** `--trust <key>` (a `SHA256:` fingerprint or a name
  in this machine's keystore, repeatable), else the file's `trust_key_ids`, else this
  machine's own keystore — the same local-trust rule `gitiup identity verify` and
  `gitiup participant` use, and *named in the output*, because a proof accepted
  because of a keyring nobody mentioned is a proof accepted by accident. Nothing is
  trusted silently, and an empty keystore with no `--trust` is a refusal (6), not a
  shrug. Note the two questions this keeps apart: `--trust` says whose **policy** this
  box will apply, and the policy's own `trust_key_ids` says whose **proofs** count.

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
gitiup policy check --commit "$(git rev-parse HEAD)" --store ./store
```

The third line is the same read with the repository's rules rather than a file's:
`policy check` resolves the published policy, finds the proofs for that commit, and
answers with an exit code ([docs/policy.md](policy.md)).

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

## The policy question: `gitiup policy check` and `explain`

`verify attestation` asks about one proof and `verify change` asks about a merge. Two
more questions get asked in front of those, and neither is answerable from either one
alone:

```console
$ gitiup policy check --commit "$newrev" --store ./store --ref refs/heads/main
SATISFIED  attestations: sha256:9f2c…  ·  2 distinct trusted signer(s) of 2  ·  result sha256:77aa…
```

**does this commit satisfy the policy** — what the store holds about one commit, judged by
the revision in force now, answered in one exit code for a `pre-receive` hook that has a
commit and a ref and no change record. It is not `verify change` with the change left
out: `attestations` and `min_signatures` are asked the same way a merge gate asks them
(the same `combine` counts the signatures), and `protects` is answered only when `--ref`
is named, because a commit is not a ref and a gate that guessed which branch was meant
would be applying rules nobody signed.

```console
$ gitiup policy explain attestation proof.json --store ./store
```

**why, rule by rule** — every rule of the effective policy printed with both halves of
the evidence: what the policy demands, and what this subject claims. Passing rules are
printed, and rules that could not run are printed as *not run* rather than left out, so
an absent line is never a silent answer. For a change it is one more word:

```console
$ gitiup policy explain change chg-6a6a8eab778ba4d0 --store ./store
```

The order is the contract. Rules are printed in ADR-0001 D7's order — integrity, then
authority, then policy — so the **first failure is the reason and the exit code**, and a
CI job can post the list without re-deriving anything from it. `explain change` is
[`gitiup verify change`](#the-merge-question-gitiup-verify-change)'s own assessment with
more of it printed, not a second gate beside it: one assessment, so the two commands
cannot disagree, and the same **0 · 6 · 7 · 8** come out (`--json` for the document,
`--quiet` for one word: `satisfied`, or the code that refused).

`--json` is a stable rule document, and it is the reason the two commands share one
renderer: `rules[]` (every rule with `rule`, `outcome`, `evidence.policy`,
`evidence.claim`, and — where it failed — `detail`, `hint`, `exit`), `checks[]` as the
compact projection, `attestations[]` one entry per proof with its own ladder, then
`accepts`, `reasons`, `policy` provenance and the clock. Nothing in it is a paraphrase of
a check: the outcomes come from the report the verifier produced, and the demand and claim
strings name the values that check read.

## The gate that runs where the refs land: `gitiup hook install pre-receive`

Everything above answers a question. A question cannot stop a branch from moving — only
something running on the box that receives the push, after the objects have arrived and
before the refs are written, can say *no* in a way that leaves the repository untouched.
That is a `pre-receive` hook, and gitiup writes one:

```console
$ gitiup hook install pre-receive --repo /srv/git/repo.git --trust ada
gitiup hook pre-receive — installed in /srv/git/repo.git
  proves    required — a refs/heads/** update needs an attestation set the published policy accepts
  policy    store · revision 1 · cited sha256:7495… · signed by SHA256:zGeY… · gate-eligible
  trusts    1 key(s) [SHA256:zGeY…] — --trust, given at install time
  open      refs/changes/**, refs/attestations/**, refs/gitiup/** — writable by anyone the git transport admits
```

The hook reads git's `<old-oid> <new-oid> <ref>` lines and refuses the whole push when a
`refs/heads/**` update names a new head the repository's **published** policy does not
accept. A refused push prints [the same report](#the-policy-question-gitiup-policy-check-and-explain)
`gitiup policy check` prints — relayed through the transport, so the person who pushed
reads the reason and not just a status — and no ref moves. `gitiup hook status` answers
which policy is in force, its revision, its citation, whose signature this box believes,
and when it was read; `gitiup doctor --hooks` says the same thing at
[`0 · 6`](#the-exit-codes-are-the-interface) so a nightly check can branch on it.

**What it does not guard is the design.** `refs/changes/**`, `refs/attestations/**` and
`refs/gitiup/**` stay open to anyone the transport admits: a proposal and the evidence
offered for it cost nothing to make and are checked when read, so filing them must never
need permission — that is how a stranger submits work to a repository they have no
special rights in. A branch is what everybody else builds on, so it moves on evidence.
[ADR-0004 D5](adr/0004-published-policy-format-signing-and-resolution.md) makes this a
format rule rather than a local one: a policy whose `protects` reaches outside
`refs/heads/**` cannot be published at all. The asymmetry is written into the hook's own
`--help` (and the installed script prints it), because a gate whose exceptions are
undocumented gets worked around instead of fixed.

Two rules fall out of that, both worth knowing before the first push breaks:

* **No override.** The hook resolves `refs/gitiup/policy/current` and nothing else — no
  `--policy`, no `$GITIUP_POLICY`, no tree file, no default
  ([ADR-0004 D4](adr/0004-published-policy-format-signing-and-resolution.md)); the flags
  are refused rather than ignored. A stranger with a clone has to be able to reach the
  verdict the box that accepted their push reached. If no policy resolves, every guarded
  push is refused with `no_policy_published`: a gate with nothing to go on does not wave
  things through.
* **The proof has to be on record first.** Refs move only after the hook returns, so a
  push that files an attestation and moves the branch in the same transaction cannot be
  judged by that attestation: publish it (`gitiup attest push --remote …`), then push the
  branch. That is what "the proof was on record before the branch moved" means.

`gitiup hook install --no-proof-required` is the one escape, and it is per-repository and
loud: it keeps the script installed with the gate off, says so on every push, is printed
by `hook status`, and makes `gitiup doctor --hooks` exit 6. The record lives in the
repository's own `info/gitiup/pre-receive.json` — never a ref, because `refs/gitiup/**`
is writable by anyone the transport admits and a gate whose opt-out a contributor could
push over is not a gate.

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
| the exit code for a class of failure | [`ErrorKind::exit_code`](../crates/gitiup-canon/src/error.rs) |
| what a policy may demand | [`policy`](../crates/gitiup-attest/src/policy.rs) |
| the published policy: its format, its validator, the resolution ladder, the chain walk | [`gitiup-quorum/src/policy.rs`](../crates/gitiup-quorum/src/policy.rs), and [docs/policy.md](policy.md) |
| publish / show, the provenance block, and the refusal of a policy nobody signed | [`gitiup/src/policy.rs`](../crates/gitiup/src/policy.rs) |
| argv, the keystore, the store, the two renderings | [`gitiup/src/verify.rs`](../crates/gitiup/src/verify.rs) |
| the merge gate over a change: the change-level checks, the combination rule, the verdicts | [`gitiup/src/verify_change.rs`](../crates/gitiup/src/verify_change.rs) |
| "does this commit satisfy the policy", and every rule printed in D7 order | [`gitiup/src/policy_ask.rs`](../crates/gitiup/src/policy_ask.rs) |
| the gate that refuses a push, its install record, its opt-out and its reports | [`gitiup/src/hook.rs`](../crates/gitiup/src/hook.rs) |

`verify` (the `Result`-returning one a library caller uses) is `verify_report` with
the tail dropped — one set of checks, one order, two question shapes. A printed
verdict and a branched-on verdict cannot disagree, which is the property every consumer
here depends on: the CLI, a merge gate, and the quorum's own verification all walk the
same ladder.

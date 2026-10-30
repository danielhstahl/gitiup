# The published policy

Status: **published, signed, resolved, asked about, and gated on.** `gitiup policy
publish` puts a repository's rules in the store, `policy show` says which one is in
force and where it came from, `policy check` answers "does this commit satisfy it",
`policy explain` prints the asking, and `gitiup hook install pre-receive` refuses the
refs themselves on the same answer. What is *not* here is in
[What this does not prove](#what-a-published-policy-does-not-prove).

Decided by [ADR-0004](adr/0004-published-policy-format-signing-and-resolution.md);
implemented in [`gitiup-quorum::policy`](../crates/gitiup-quorum/src/policy.rs) (the
document, its validator, the resolution ladder and the chain walk),
[`gitiup/src/policy.rs`](../crates/gitiup/src/policy.rs) and
[`policy_ask.rs`](../crates/gitiup/src/policy_ask.rs) (the command lines), and
[`gitiup/src/hook.rs`](../crates/gitiup/src/hook.rs) (the refs). The vectors it is
checked against — five signed documents, a two-revision chain, 32 generated refusals —
are [`docs/adr/fixtures/policy-v1/`](adr/fixtures/policy-v1/).

The one-sentence version:

> **A policy is the rule a merge gate applies, and it lives in the store, signed by the
> repository's owner — not in a checkout, where a fork could edit it.**

Every command line on this page is executed in CI, in order, by
[`crates/gitiup/tests/policy_doc_cli.rs`](../crates/gitiup/tests/policy_doc_cli.rs),
which starts from an empty home and an empty store and compares the printed output. A
line marked `# exit N` is expected to exit `N`. A `…` line stands for output this page
does not repeat.

## Why a file in the tree is not the rule

`gitiup-policy.json` next to the code is a good thing to commit: it is reviewed like
code, and it says what the author *hopes* the gate will demand. It cannot be the gate,
because it is a file in the tree, and the tree is the one place every fork may edit. If
a clone's rules came from the clone's copy of the tree, the weakest fork of a
repository would set the rules for its own copies, and nobody would be able to tell.

So the tree file is a **draft**, and the published document is the **rule**. The
difference is not ceremony — it is a signature, a revision, and a place a stranger can
fetch:

| | the tree file | the published document |
|---|---|---|
| where | `gitiup-policy.json` in the checkout | `kv/policy/<hex>`, advertised by `refs/gitiup/policy/current` |
| who can change it | anyone with write access to the tree | whoever holds the owner's key, and only by signing |
| what it may decide | a question, for `gitiup run` and for humans | a merge |
| what happens on a fork | it is whatever the fork says it is | refused unless the fork's copy is byte-identical or signed by a key the reader trusts |
| its name in a report | `tree-file` | `store`, with a revision and two digests |

The word for this is in the output, not only in this document: a checkout whose draft
disagrees with the published rules is told so, in the answer itself
([Example 3](#example-3--a-fork-what-it-inherits-and-where-the-divergence-shows)
runs it).

## What a repository publishes

One signed document, `type: "gitiup-policy-1"`, twelve members, at most 32 KiB
(ADR-0004 D2, D10):

| member | what it fixes |
|--------|----------------|
| `type`, `schema_version` | the document says what it is, *inside* the signed bytes; a reader that does not know the type refuses it rather than guessing |
| `owner` | `key_id` (a fingerprint, derived and never typed) and a `principal` for humans |
| `revision`, `previous_digest` | the chain: one more than its predecessor, and the predecessor's body digest — so "which rules were in force then?" has an answer |
| `effective_from_us`, `expires_at_us` | when these rules start counting, and when they stop |
| `protects` | which refs it gates, globs inside `refs/heads/**` only (never `refs/changes/**`, never its own ref: a policy gates what is *trusted*, not what may be *offered*) |
| `rules` | the proof rules — `PolicyFile` verbatim, the same vocabulary as a tree file: `allowed_tiers`, `allowed_sandboxes`, `trust_key_ids`, `min_signatures`, `max_age_us`, and the environment requirement |
| `quorum` | the numbers a round is opened with: `default` and `by_job` selection policies, and `requirements` (what a verifier must be able to do) — [`SelectionPolicy`](../crates/gitiup-quorum/src/select.rs) and [`Requirements`](../crates/gitiup-quorum/src/capability.rs) verbatim, so opening a round is a copy and not a translation |
| `annotations` | the sanctioned hatch: `x_<producer>_<name>`, ≤ 16, ≤ 512 bytes each |
| `signatures` | exactly one, by the owner |

Two things `rules` accepts in a draft and `publish` refuses in a document:
`expected_commit` and `expected_result_digest`. They are per-decision bindings, not
standing rules — a published rule that pinned a commit could only ever be satisfied by
one commit — so the vocabulary is one vocabulary (D2) and publish says why (D5).

`quorum` is `SelectionPolicy` and `Requirements` verbatim for a reason that will bite
somebody if it is not written down: a field added to either type in
[ADR-0002](adr/0002-roster-verifier-selection-and-sybil-resistance.md)'s territory
appears in published policies the same day, and a reader that does not know it refuses
the document as an unknown field rather than ignoring it. That coupling is the point — a
second definition of "n of m, tier floor, capability floor, caps" is how a round and a
policy start disagreeing about how a quorum is counted — but it means the two crates are
now one vocabulary, and the lists inside `quorum.requirements` are normalised
(`sandboxes`, `image_digests`) exactly as the lists in `rules` are, so two owners who
wrote the same rules in a different order publish the same bytes.

Everything the validator can prove is incoherent is refused **when it is written**: a
quorum with no seats that can satisfy it, `required_agree` above `n`, a sandbox set
disjoint from the one the proof rules accept, `min_signatures: 0`, a policy that trusts
nobody, a `protects` that reaches outside `refs/heads/**`. The reason is not tidiness:
a gate nobody can satisfy is not a strict gate, it is a broken one, and an owner cannot
discover "no set satisfies this" by waiting for the first merge to fail
([ADR-0004 D5](adr/0004-published-policy-format-signing-and-resolution.md)). The full
table — 32 refusals, each with its token and exit code, each *generated* by mutating a
real policy and re-signing it — is in the ADR and in
[`cases.json`](adr/fixtures/policy-v1/cases.json).

Warnings are separate from refusals, because they are things that are legitimate and
frequently a mistake: no anchor is a key this machine holds (correct and normal — see
[Example 1](#example-1--a-personal-repository-that-accepts-one-local-run)), an expiry
within a week, a quorum that demands unanimity, and a freshness window over a week
(which is how long a policy change can be dodged with an old proof).

## How it is signed, and what the two digests are for

One Ed25519 signature, by the owner, over the canonical body with `signatures` removed
([ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md)'s framing and
normalisation: the bytes are their own canonical form or they are refused at exit 8).
Zero is a refusal and two is a refusal: a v1 policy is one owner's statement, and "two
people had to agree to change the rules" is a roster question, not a document shape.
That gives two names, and a report prints both:

* **`body_digest`** — the rules, independent of the signature over them. **This is what
  a verdict cites** and what `previous_digest` names, so a re-publish that changed
  nothing cannot move the citation in somebody's history.
* **`record_digest`** — the exact stored bytes, signature included. This is the CAS key:
  `kv/policy/<hex(record_digest)>`.

A policy change is a **new signed document**, never an edit: `revision` goes up by one,
`previous_digest` names the old `body_digest`, and the old document stays. That is what
makes the history attributable and free — the chain of signatures *is* the audit trail.

The distinction that trips everyone up once, and is worth saying twice:

| | who signs it | who is asked to believe it |
|---|---|---|
| the **policy** (the rules) | the repository's owner | the verifier, whose trust roots are its own local configuration |
| a **proof** (an attestation) | whoever ran the job — often a CI runner's key | the policy's `trust_key_ids`, which is a list the owner signed |

They are usually different keys, and nothing requires them to be the same. Getting them
the wrong way round is [Example 1](#example-1--a-personal-repository-that-accepts-one-local-run)'s
second refusal.

One name to keep straight while doing that: `min_signatures` lives **inside `rules`** and
counts signatures **on attestations** — how many distinct trusted keys have to certify
one result. The policy's own `signatures` list counts something else entirely: who signed
the rules. They are unrelated fields that share a word, and a policy with
`min_signatures: 3` is not a policy that needs three owners.

## How a clone learns it

One key, two kinds of ref, and a fixed write order (ADR-0004 D7):

```text
kv/policy/<hex(record_digest)>              the signed bytes, immutable by construction
refs/gitiup/policy/current                  → the policy in force (moved under CAS)
refs/gitiup/policy/history/<revision:06>    every revision ever published, create-only
```

Bytes first, then the history ref, then `current` — a ref naming bytes the store cannot
return is the one state a reader cannot repair, so it is never written. On a git-backed
host `current` is a pointer commit, so `git fetch refs/gitiup/policy/current` arrives
with the rules and their signature in one packfile; `refs/gitiup/policy/history/*`
arrives with the whole chain, which is what lets a clone judge a year-old run without a
listing, a pagination, or a live service.

Nothing about a policy is secret — it is published precisely so a stranger can read it
before running anything — and history is **never pruned**, because pruning is what turns
last month's merge into `policy_history_missing`.

Every read in that list is executed on every host the workspace ships — a directory, a
bare repository over `file://`, a repository served by `git-http-backend`, an in-memory
bucket, a live MinIO and the forge adapter — by
[`gitiup-host-tests/src/policy.rs`](../crates/gitiup-host-tests/src/policy.rs), because
"readable from the store" is a claim about transports the owner chose and the reader did
not, and the fs host this library was developed against is only one of them.

The revision in force at a moment is a walk, not a guess: among the documents reachable
from `current` by `previous_digest`, the newest with `effective_from_us ≤ at` that has
not expired. `--at` is how you ask that question
([Example 2](#example-2--a-project-that-requires-four-of-five) walks it); a run from
before the first policy is **refused** (`policy_history_missing`) rather than judged by
rules that did not exist.

## The resolution order, and what each source may decide

Five sources, one order, and the answer always says which one won
([ADR-0004 D4](adr/0004-published-policy-format-signing-and-resolution.md)):

| # | source | gate-eligible | who chose it |
|---|--------|---------------|--------------|
| 1 | `--policy <path>` | **yes** | whoever ran the gate, deliberately |
| 2 | `$GITIUP_POLICY` | **yes** | the same act, spelled in the environment |
| 3 | the store: `refs/gitiup/policy/current` | **yes** | the owner, by signature |
| 4 | the checkout's `gitiup-policy.json` | no | whoever last edited a file |
| 5 | this build's default | no | nobody — which is why it trusts nobody |

A merge may rest on the first three only. A gate that resolves to 4 or 5 refuses
(`no_policy_published`, exit 6) instead of deciding a merge by a default nobody chose,
and `--policy` prints a note saying it overrode something, because an override that
silently wins is how a policy stops being enforced:

```console
$ gitiup policy show --policy examples/gitiup-policy.json --at 2026-10-27T09:30:00Z
policy: --policy (examples/gitiup-policy.json)
  rules    trust 1 key(s) · tiers local · min 1 · max age 1d
  judged  2026-10-27T09:30:00Z (run-claim)
  gate    yes: a merge may rest on this
  note    the gate was run with an override nobody published (--policy); the store-published policy was ignored
```

The `pre-receive` hook is the deliberate exception: it resolves source 3 and nothing
else. No `--policy`, no environment, no tree file, no default
([docs/verification.md](verification.md#the-gate-that-runs-where-the-refs-land-gitiup-hook-install-pre-receive)) — the
whole point of a hook is that a clone and the box that accepted a push reach the same
answer, and a flag in one hook script on one machine destroys that.

Trust is not part of the ladder. `--trust` names whose *signature* this machine will act
on, and defaults to the keys in its own keystore — the same local-trust rule as
`gitiup verify attestation`, so the two commands cannot disagree about whose policy they
were willing to read. A published policy signed by a key on no list is refused
(`signer_untrusted`), not read anyway.

## Before the examples

Three identities, three stores, and two pinned clocks. Each example below runs in the
same directory, from an empty keystore; paths are relative to the repository root.

The identities are the published fixture identities of
[ADR-0003](adr/0003-change-record-format-and-merge-semantics.md) and
[ADR-0004](adr/0004-published-policy-format-signing-and-resolution.md): each seed is
derived from a public label, so no secret is committed and every digest on this page is
reproducible on your machine:

```console
$ python3 -c 'import hashlib; [open(n + ".seed", "w").write(hashlib.sha256(b"gitiup ADR-0003 change-v1 fixture key: " + n.encode()).hexdigest() + "\n") for n in ("ada", "sofia", "ci-runner")]'
```

```console
$ gitiup key import seed ada.seed --name ada
imported ada
  key id  SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0
  backend keystore
  secret  re-encrypted in the keystore (age)
$ gitiup key import seed ci-runner.seed --name ci-runner
imported ci-runner
  key id  SHA256:kHe5CTrcfnmORAqMoE3KPhY+IjO+b4k1l7fkv3mQ+aQ
  backend keystore
  secret  re-encrypted in the keystore (age)
$ gitiup key import seed sofia.seed --name sofia
imported sofia
  key id  SHA256:3cEfXue74sCZzae0WYt9ziDP/bUhY9HYPh2UiUyulOU
  backend keystore
  secret  re-encrypted in the keystore (age)
```

* **Ada** owns the repositories. **ci-runner** is the key that signs proofs. **Sofia**
  owns a fork.
* The clocks are pinned (`--at`, `--now`), because freshness is a window against *now*
  and a document that is wrong in ten years is not documentation.
* `run.json` in these examples is
  `crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json` — a `local` run in
  `docker` on `x86_64`, claimed at `2026-10-27T09:15:02Z` — and the policies are the
  vectors in `docs/adr/fixtures/policy-v1/policies/`.

## Example 1 — a personal repository that accepts one local run

Ada's own repository, in a bucket or a directory: one CI runner, and the rule she wants
is "a real run, from that runner's key, on amd64, in the last day". `personal.json` is
exactly that, and it is the smallest useful policy: `local` only, one named runner key,
`require_arch`, `require_env_match: major`, 24 hours.

```console
$ gitiup policy publish docs/adr/fixtures/policy-v1/policies/personal.json --store ./store --key ada
published revision 1: sha256:9596987498bdb9779c771ce0b6193efc57a61aca296520bc2235bec52a75c7fe (body sha256:8f2a80159b86b4d84c76d7be10d8660d538b2c155f286067846980f775c39ce3)
  store   fs store ./store
  files   kv/policy/9596987498bdb9779c771ce0b6193efc57a61aca296520bc2235bec52a75c7fe
  refs    refs/gitiup/policy/current -> sha256:9596987498bdb9779c771ce0b6193efc57a61aca296520bc2235bec52a75c7fe, refs/gitiup/policy/history/000001 -> same
  owner   SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 (Ada Hale)
  from    2026-10-01T04:26:40Z
  protects refs/heads/**
trusted here: SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 — a verifier applies this policy only if its own trust list names that key
next: anyone reading this store asks with `gitiup policy show --store ./store`
```

Four writes, in the order D7 fixes: the bytes, a create-only history ref, and `current`
moved under compare-and-swap. The digests are the point of the first line: `body` is
what a verdict will cite, `record` is where the bytes live, and both are reproducible
from the fixture bytes — this is the same `sha256:8f2a8015…` the
[vectors](adr/fixtures/policy-v1/) publish.

Read it back the way a stranger would, with the store named and Ada's key trusted:

```console
$ gitiup policy show --store ./store --trust ada --at 2026-10-27T09:30:00Z
policy: store revision 1 (refs/gitiup/policy/current)
  store   fs store ./store
  files   kv/policy/9596987498bdb9779c771ce0b6193efc57a61aca296520bc2235bec52a75c7fe
  body    sha256:8f2a80159b86b4d84c76d7be10d8660d538b2c155f286067846980f775c39ce3  (what a verdict cites)
  record  sha256:9596987498bdb9779c771ce0b6193efc57a61aca296520bc2235bec52a75c7fe
  owner   SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 (Ada Hale)
  from    2026-10-01T04:26:40Z
  rules    trust 1 key(s) · tiers local · min 1 · max age 1d
  protects refs/heads/**
  judged  2026-10-27T09:30:00Z (run-claim)
  gate    yes: a merge may rest on this
  warning none of the trust anchors is a key this machine holds: correct when a CI runner signs and the owner publishes, a mistake if you meant to sign yourself
```

That warning is the two-questions table, printed out loud: the rules were signed by Ada,
the proofs are expected from ci-runner, and this machine holds neither expectation
accidentally. It is a warning and not a refusal because it is the commonest correct setup
in the wild — a build agent signs proofs, the owner publishes rules, and the two keys
live on different machines.

Now the proof, and the question a gate asks:

```console
$ gitiup attest push --run-report crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json --sign --key ci-runner --store ./store --out proof.json
filed 873e179d…4cef for bbbbbbbbbbbb
…
$ gitiup policy check --commit sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --store ./store --ref refs/heads/main --trust ada --now 2026-10-27T09:30:00Z
SATISFIED  attestations: sha256:873e179de29e9f8e8a9ed4e1b4f26019c1611d3b54dd80b5acfa850a3f034cef  ·  1 distinct trusted signer(s) of 1  ·  result sha256:85d5a664e3b6974d11bf37e9c7fcc199c8de63cdd2987fc4372c5f22367dc0f6
subject       commit
…
policy        store revision 1 · cited sha256:8f2a80159b86b4d84c76d7be10d8660d538b2c155f286067846980f775c39ce3 · judged 2026-10-27T09:30:00Z (now) · gate-eligible · trust 1 key(s) · tiers local · min 1 · max age 1d
…
rules
  policy          ok        needs: a policy a merge may rest on: published, signed by a key you trust, and in force  ·  claims: store revision 1 · cited sha256:8f2a80159b86b4d84c76d7be10d8660d538b2c155f286067846980f775c39ce3
  protects        ok        needs: one of: refs/heads/**  ·  claims: refs/heads/main
  attestations    ok        needs: a proof the store can produce, whose bytes are the ones its name promises  ·  claims: 1 advertised, 1 accepted by the revision in force for its own run
  min_signatures  ok        needs: 1 distinct trusted signature(s)  ·  claims: 1 on sha256:85d5a664e3b6974d11bf37e9c7fcc199c8de63cdd2987fc4372c5f22367dc0f6

  [1] sha256:873e179de29e9f8e8a9ed4e1b4f26019c1611d3b54dd80b5acfa850a3f034cef  ACCEPTED (exit 0)
```

Four rules, four answers, and the citation on every line that could need it: the policy
that was used, its revision, and its `body_digest`. `--quiet` prints the one word a
shell branches on (`satisfied`), and `--json` prints the same rules as data.

And the mistake this policy exists to make impossible — the owner's own key signing the
proof, which is one person certifying themselves:

```console
$ gitiup attest push --run-report crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json --sign --key ada --store ./store --out owner-signed.json
filed 0b1887b8…0e22 for bbbbbbbbbbbb
…
$ gitiup policy explain attestation owner-signed.json --store ./store --trust ada --now 2026-10-27T09:30:00Z
REFUSED (exit 6)  [trust] SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 signed it, and that key is not trusted here
…
  trust           REFUSED   needs: 1 trusted key(s): SHA256:kHe5…Q+aQ  ·  claims: SHA256:kxdE…LiB0: none of them trusted here
                            → SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 signed it, and that key is not trusted here
                              hint: add the key id to the owner's trust list (giti-1rs.6)
  min_signatures  REFUSED   needs: 1 distinct trusted signature(s)  ·  claims: 0 trusted signatures on this document
…
  tier            ok        needs: one of: local  ·  claims: local
…
reason        [trust] SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 signed it, and that key is not trusted here
also          [min_signatures] 0 trusted signature(s), policy requires 1
# exit 6
```

`explain` is `check` with the asking printed: every rule of the effective policy, in
ADR-0001 D7's order, with both halves of the evidence — what the policy demands and what
this subject claims — and rules that could not run printed as *not run* rather than left
out. The first refusal is the exit code, and here it is `trust` (exit 6) rather than
`tier`: the run was a real run, in an accepted sandbox, on the right architecture; it
was just signed by a key the policy never asked anyone to believe.

## Example 2 — a project that requires four of five

The same repository grown up: the rule is now *a quorum*, five seats, four of them
agreeing, from endorsers or better, on `x86_64` in a digest-pinned image. `project.json`
signs that, and this is the point where "what does the policy demand" stops being a
question you can answer from a flag:

```console
$ gitiup policy publish docs/adr/fixtures/policy-v1/policies/project.json --store ./project --key ada
published revision 1: sha256:f80a3d214cb43e1050e3900bf5397db715608ebcfe4ad4ae50a0fc560fea8e19 (body sha256:c1406ed5671f7ee38585a257bec0989c4f061f9a43d3073f795d7f749be78ecb)
…
$ gitiup policy show --store ./project --trust ada --at 2026-10-25T12:00:00Z
policy: store revision 1 (refs/gitiup/policy/current)
  store   fs store ./project
  files   kv/policy/f80a3d214cb43e1050e3900bf5397db715608ebcfe4ad4ae50a0fc560fea8e19
  body    sha256:c1406ed5671f7ee38585a257bec0989c4f061f9a43d3073f795d7f749be78ecb  (what a verdict cites)
  record  sha256:f80a3d214cb43e1050e3900bf5397db715608ebcfe4ad4ae50a0fc560fea8e19
  owner   SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 (Ada Hale)
  from    2026-10-01T04:26:40Z
  rules    trust 2 key(s) · tiers quorum · min 1 · max age 12h
  protects refs/heads/**, refs/heads/stable/**
  quorum   4 of 5 seats must agree · floor endorsed · per tier anonymous 1, endorsed 4, trusted 1 · 2 reserves · 1 seat(s) per identity
  quorum   job `arm-*`: 3 of 3 seats must agree · floor endorsed · per tier anonymous 0, endorsed 3 · 2 reserves · 1 seat(s) per identity
  requires x86_64 · 8192 MiB ram · 51200 MiB disk · sandboxes docker + podman · sandbox rung >= 2 · image(s) sha256:abababababababababababababababababababababababababababababababab
  judged  2026-10-25T12:00:00Z (run-claim)
  gate    yes: a merge may rest on this
  warning quorum.by_job[arm-*] demands unanimity: one verifier that is offline is no verdict, and the escalation round asks for more
```

Five numbers, all of them owned by Ada's signature and none of them a flag: how many
seats, how many must agree, which roster tier is the floor, how the seats are capped per
tier, and what a machine has to *be able to do* to be seated at all. `gitiup change
submit` opens its rounds from exactly this block — that is the whole mechanism by which
"a quorum is required" stops being somebody's local opinion ([docs/quorum.md](quorum.md)).

One local run, however well signed, is not a quorum:

```console
$ gitiup attest push --run-report crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json --sign --key ada --store ./project --out one-local-run.json
filed 0b1887b8…0e22 for bbbbbbbbbbbb
…
$ gitiup policy explain attestation one-local-run.json --store ./project --trust ada --now 2026-10-27T09:30:00Z
REFUSED (exit 6)  [environment] this run's image_digest is 'sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54', which does not match what this change requires: sha256:abababababababababababababababababababababababababababababababab
…
  environment     REFUSED   needs: arch=amd64 image_digest=abababababababababababababababababababababababababababababababab (strict)  ·  claims: os linux · arch x86_64 · image ghcr.io/gitiup/ci:ubuntu-24.04 · provider docker · fingerprint edf4c6b0…2276
…
  tier            REFUSED   needs: one of: quorum  ·  claims: local
                            → provenance tier 'local' is not accepted here
                              hint: adjust the owner's allowed provenance tiers deliberately: allowed here are quorum
…
reason        [environment] this run's image_digest is 'sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54', which does not match what this change requires: sha256:abababababababababababababababababababababababababababababababab
also          [tier] provenance tier 'local' is not accepted here
# exit 6
$ gitiup policy check --commit sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --store ./project --ref refs/heads/main --trust ada --now 2026-10-27T09:30:00Z --quiet
environment
# exit 6
```

Two refusals, both printed, the first one the exit code: this proof came from a different
image than the policy pins (`environment`), and it is a single run in a repository that
admits only `quorum` (`tier`). Neither can be talked round: the image digest and the
tier are both in the signed document, and a `tier: quorum` attestation exists only as
the output of a `verified` tally
([`gitiup quorum verdict --attest`](quorum.md#attesting-it-gitiup-quorum-verdict---attest))
and is believed only by re-deriving that tally from the store
([docs/verification.md](verification.md#the-quorum-ladder-tier-quorum)). That is the
shape of what would satisfy this policy: a round of five, four agreeing, whose verdict
Ada's own key files — and `gitiup verify change` is the command that believes it.

Now the part a flag can never do. Ada tightens the rules — 5 of 7 instead of 4 of 5,
`min_sandbox_level` 3 instead of 2, and half the freshness window — by publishing
revision 2, whose `previous_digest` is revision 1's `body_digest`:

```console
$ gitiup policy publish docs/adr/fixtures/policy-v1/policies/project-tightened.json --store ./project --key ada
published revision 2: sha256:911a34a38a7880a5a6fa9918504cac062c43c5435a883275ac4d5b8605e552a0 (body sha256:33b304ccf382a9fbdaed40f132c6b595a77104eebb7032c4c4c936e72b887b80)
  store   fs store ./project
  files   kv/policy/911a34a38a7880a5a6fa9918504cac062c43c5435a883275ac4d5b8605e552a0
  refs    refs/gitiup/policy/current -> sha256:911a34a38a7880a5a6fa9918504cac062c43c5435a883275ac4d5b8605e552a0, refs/gitiup/policy/history/000002 -> same
  owner   SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0 (Ada Hale)
  from    2026-10-20T03:33:20Z
  protects refs/heads/**
…
```

And the two clocks separate, which is the whole reason the chain exists:

```console
$ gitiup policy show --store ./project --trust ada --at 2026-10-07T00:00:00Z
policy: store revision 1 (refs/gitiup/policy/current)
…
  rules    trust 2 key(s) · tiers quorum · min 1 · max age 12h
  protects refs/heads/**, refs/heads/stable/**
  quorum   4 of 5 seats must agree · floor endorsed · per tier anonymous 1, endorsed 4, trusted 1 · 2 reserves · 1 seat(s) per identity
…
  judged  2026-10-07T00:00:00Z (run-claim)
  gate    yes: a merge may rest on this
  note    the chain was walked 2 links to revision 1
…
$ gitiup policy show --store ./project --trust ada --at 2026-10-25T12:03:20Z
policy: store revision 2 (refs/gitiup/policy/current)
…
  rules    trust 2 key(s) · tiers quorum · min 1 · max age 6h
  protects refs/heads/**
  quorum   5 of 7 seats must agree · floor endorsed · per tier anonymous 1, endorsed 4, trusted 1 · 2 reserves · 1 seat(s) per identity
…
  judged  2026-10-25T12:03:20Z (run-claim)
  gate    yes: a merge may rest on this
…
$ gitiup policy show --store ./project --trust ada --at 2026-09-01T00:00:00Z
gitiup: policy_history_missing: nothing in the policy chain had taken effect at 2026-09-01T00:00:00Z
hint: there was no policy yet, and inventing one is not the same as having none (ADR-0004 D6). A run made before the first published policy is refused, not judged by rules that did not exist
# exit 6
```

A run from 2026-10-07 is judged by the rules that existed on 2026-10-07 — four of five,
twelve hours — and the report says it walked two links to get there. Today's rules do not
retroactively refuse last week's correct work, and last week's rules do not quietly pass
today's change. Before the first policy there were no rules, and the honest answer is a
refusal: inventing a policy for a run that had none would be inventing a fact.

## Example 3 — a fork: what it inherits, and where the divergence shows

Sofia copies Ada's repository. A fork is a copy, so she gets the policy with it —
literally the same bytes, and the same history:

```console
$ cp -r ./project ./fork
$ gitiup policy show --store ./fork --trust ada --at 2026-10-07T00:00:00Z
policy: store revision 1 (refs/gitiup/policy/current)
  store   fs store ./fork
  files   kv/policy/f80a3d214cb43e1050e3900bf5397db715608ebcfe4ad4ae50a0fc560fea8e19
  body    sha256:c1406ed5671f7ee38585a257bec0989c4f061f9a43d3073f795d7f749be78ecb  (what a verdict cites)
  record  sha256:f80a3d214cb43e1050e3900bf5397db715608ebcfe4ad4ae50a0fc560fea8e19
…
  quorum   4 of 5 seats must agree · floor endorsed · per tier anonymous 1, endorsed 4, trusted 1 · 2 reserves · 1 seat(s) per identity
…
  note    the chain was walked 2 links to revision 1
…
```

Same `body_digest` (`sha256:c1406ed5…`) and same `record_digest` as upstream, because it
is the same document: `fork-inherited` in the
[vectors](adr/fixtures/policy-v1/) is `project` byte for byte. Nothing weakened, and
this is checkable rather than hoped — the digests are the proof. A fork inherits a policy
by inheriting the bytes, and it cannot weaken a policy it cannot re-sign convincingly.

She can of course re-sign a weaker one with her own key. `fork-weakened.json` is
Sofia's own repository: `local` allowed, seven-day freshness, a 1-of-1 anonymous
quorum. Everything about it is well-formed, the signature is real, and it is published
into her own store:

```console
$ gitiup policy publish docs/adr/fixtures/policy-v1/policies/fork-weakened.json --store ./sofia --key sofia
published revision 1: sha256:2e3cbcaa4af8a441d162ba90c5200e3a9942028e132703ca97789c77b8f01775 (body sha256:97edf3584fe02f712d637133670209a6ee49f993d2be9446f3179ffffa9816b5)
  store   fs store ./sofia
  files   kv/policy/2e3cbcaa4af8a441d162ba90c5200e3a9942028e132703ca97789c77b8f01775
  refs    refs/gitiup/policy/current -> sha256:2e3cbcaa4af8a441d162ba90c5200e3a9942028e132703ca97789c77b8f01775, refs/gitiup/policy/history/000001 -> same
  owner   SHA256:3cEfXue74sCZzae0WYt9ziDP/bUhY9HYPh2UiUyulOU (Sofia Marin)
  from    2026-10-01T04:26:40Z
  protects refs/heads/**, refs/heads/stable/**
trusted here: SHA256:3cEfXue74sCZzae0WYt9ziDP/bUhY9HYPh2UiUyulOU — a verifier applies this policy only if its own trust list names that key
…
```

This is a correct policy for a repository Sofia owns — which is exactly why it must be
*Sofia's*:

```console
$ gitiup policy show --store ./sofia --trust sofia --at 2026-10-25T12:00:00Z
policy: store revision 1 (refs/gitiup/policy/current)
  store   fs store ./sofia
  files   kv/policy/2e3cbcaa4af8a441d162ba90c5200e3a9942028e132703ca97789c77b8f01775
  body    sha256:97edf3584fe02f712d637133670209a6ee49f993d2be9446f3179ffffa9816b5  (what a verdict cites)
  record  sha256:2e3cbcaa4af8a441d162ba90c5200e3a9942028e132703ca97789c77b8f01775
  owner   SHA256:3cEfXue74sCZzae0WYt9ziDP/bUhY9HYPh2UiUyulOU (Sofia Marin)
  from    2026-10-01T04:26:40Z
  rules    trust 1 key(s) · tiers local+quorum · min 1 · max age 7d
  protects refs/heads/**, refs/heads/stable/**
  quorum   1 of 1 seats must agree · floor anonymous · per tier anonymous 1, endorsed 4, trusted 1 · 2 reserves · 1 seat(s) per identity
  judged  2026-10-25T12:00:00Z (run-claim)
  gate    yes: a merge may rest on this
  warning quorum.default demands unanimity: one verifier that is offline is no verdict, and the escalation round asks for more
```

And a verifier whose trust roots are Ada's — anyone who cloned the fork still believing
upstream — refuses it outright:

```console
$ gitiup policy show --store ./sofia --trust ada --at 2026-10-25T12:00:00Z
gitiup: signer_untrusted: this policy is signed by SHA256:3cEfXue74sCZzae0WYt9ziDP/bUhY9HYPh2UiUyulOU, which is not a key you trust
hint: the signer must be one of your trust roots (--owner, else this machine's keystore). A fork's weaker policy signed with its own key is refused here, and that is the whole inheritance mechanism (ADR-0004 D3)
# exit 6
```

Refused, not distrusted-and-used, not used-with-a-warning. That single row — `fork-weakened`
in the vectors, and this command line — is the reason the epic exists: the fork is not
distrusted because it is a fork, and the policy is not obeyed because it is in a store.
Both are decided by whose signature is on them, and the answer is a refusal a script can
branch on rather than a feeling.

The other divergence is the everyday one, and gitiup says it out loud. A fork's checkout
carries a draft that does not match what is published — here the example file from
[below](#the-policy-you-commit-examplesgitiup-policyjson), copied in as the checkout's
`gitiup-policy.json`:

```console
$ cp examples/gitiup-policy.json gitiup-policy.json
$ gitiup policy show --store ./fork --trust ada --at 2026-10-07T00:00:00Z
policy: store revision 1 (refs/gitiup/policy/current)
…
  note    the chain was walked 2 links to revision 1
  note    the checkout's gitiup-policy.json (sha256:5eff83133ba2afb3ff93cf54cc2b8b838e2bebdcf39439d352bb39acd785017f) is not the published policy (sha256:c1406ed5671f7ee38585a257bec0989c4f061f9a43d3073f795d7f749be78ecb) and is not in force: editing a file is not publishing a policy (ADR-0004 D1)
…
```

Two digests, both named, and the sentence that says which one decides. The same draft,
with no store to contradict it, is still only a draft:

```console
$ gitiup policy show --trust ada --at 2026-10-07T00:00:00Z
policy: tree-file (gitiup-policy.json)
  rules    trust 1 key(s) · tiers local · min 1 · max age 1d
  judged  2026-10-07T00:00:00Z (run-claim)
  gate    no: this answers a question, it does not decide a merge
  note    the checkout's gitiup-policy.json is a draft: it is not signed, it is not versioned, and it is not in force for a merge (ADR-0004 D1)
```

And ask the same proof of Sofia's store, with Sofia's rules and Sofia's trust roots, and
the answer changes — `trust` this time, because that proof was signed by Ada and her
policy trusts only Sofia. That is not a bug to fix: two repositories, two rules, two
honest answers, each saying which of the two it gave.

```console
$ gitiup policy explain attestation one-local-run.json --store ./sofia --trust sofia --now 2026-10-27T09:30:00Z --quiet
trust
# exit 6
```

## The policy you commit: `examples/gitiup-policy.json`

[`examples/gitiup-policy.json`](../examples/gitiup-policy.json) is the draft form — what
you commit next to the code, what `$GITIUP_POLICY` points at, and what `--policy`
accepts. ADR-0004 chose JSON, deliberately: the signed document is canonical JSON
([ADR-0001 D1](adr/0001-attestation-encoding-hash-and-signature.md)), so the draft and
the rule speak one vocabulary and `rules` is copied into the document verbatim rather
than translated. A TOML or YAML front-end would be a second parser for the same
vocabulary, which is how two of them start disagreeing.

```json
{
  "schema_version": 1,
  "allowed_tiers": ["local"],
  "allowed_sandboxes": ["docker", "landlock", "podman", "unshare"],
  "trust_key_ids": ["SHA256:kHe5CTrcfnmORAqMoE3KPhY+IjO+b4k1l7fkv3mQ+aQ"],
  "min_signatures": 1,
  "max_age_us": 86400000000,
  "require_arch": "amd64",
  "require_env_match": "major",
  "require_toolchain": { "rustc": "1.99" }
}
```

It is [Example 1](#example-1--a-personal-repository-that-accepts-one-local-run)'s rules —
byte-equal, after normalisation, to the `rules` block of the signed `personal` policy,
which is what the test asserts. `trust_key_ids` is the *runner's* key, not Ada's: this
file decides who may sign a proof, and the key that signs the rules is somebody else
entirely.

The draft is not the document, and `publish` says so by name if you try to publish it
directly:

```console
$ gitiup policy publish examples/gitiup-policy.json --store ./throwaway --key ada
gitiup: 'examples/gitiup-policy.json' is not a policy document: unknown field `allowed_sandboxes`, expected one of `type`, `schema_version`, `owner`, `revision`, `previous_digest`, `effective_from_us`, `expires_at_us`, `protects`, `rules`, `quorum`, `annotations`, `signatures`
hint: `gitiup policy publish help` lists the fields; every one of them is checked before anything is written (ADR-0004 D2, D5)
# exit 6
```

That refusal is the whole design in one line: the twelve members on the right are the
document — the draft's rules go in `rules`, and the rest is who signed it, what it
gates, and where it sits in the chain. A first policy from flags is the other way in
(`gitiup policy publish --store ./store --allow-tier local --trust ada`), and
`gitiup policy publish --dry-run --json` prints the `body_digest` it is about to sign,
which is the answer to "what exactly am I committing to?" before committing to it.

## What a published policy does not prove

It proves that the owner said these rules, in these words, on this date, under this
signature. It does not prove:

* **that the rules are good.** They are the owner's to choose; a policy that demands a
  quorum of strangers who never turn up is a legal document and a stalled repository. The
  validator refuses what is *unsatisfiable*, not what is unwise — that is what the
  warnings are for.
* **that the store is telling you the truth about `current`.** A `policy show` that
  fetched a stale ref is a stale answer. Transparency-log anchoring of the current
  pointer is [ADR-0001 D9](adr/0001-attestation-encoding-hash-and-signature.md)'s
  optional layer, and until something builds it, "what does this store advertise?" is
  answered by the transport you used to ask.
* **that the owner's key is intact.** Revocation is
  [ADR-0002 D9](adr/0002-roster-verifier-selection-and-sybil-resistance.md)'s, and the
  operational answer to a leaked owner key is revocation plus a new revision — never
  deleting history, which D6 forbids.
* **that a verifier applied it.** The defence is that a verdict is reproducible: every
  report prints the revision and the `body_digest` it used, so anyone with `git fetch`
  can reach the same answer without believing the box that produced it.
* **that a merge is allowed.** That is `policy check` / `verify change` / the hook — this
  document only tells you what the rules are. Which proofs exist, whether they are fresh,
  and whether their signatures are trusted are different questions with their own
  answers.

## Where every claim on this page is executed

| claim | the test |
|-------|----------|
| every command line and every printed line above | [`gitiup/tests/policy_doc_cli.rs`](../crates/gitiup/tests/policy_doc_cli.rs) |
| `examples/gitiup-policy.json` parses, is accepted by `--policy`, and equals the signed `personal` policy's rules | the same file |
| the digests quoted above are the ones the vectors publish | the same file, against [`cases.json`](adr/fixtures/policy-v1/cases.json) |
| the format, the 32 refusals, the chain walk, the normalisations | [`gitiup-quorum/tests/policy_vectors.rs`](../crates/gitiup-quorum/tests/policy_vectors.rs) and [`generate.py --selftest`](adr/fixtures/policy-v1/generate.py) |
| publish/show semantics: store writes, `--dry-run`, self-trust, refusals | [`gitiup/tests/policy_cli.rs`](../crates/gitiup/tests/policy_cli.rs) |
| `check` and `explain`: rules in D7 order, first failure is the exit code | [`gitiup/tests/policy_ask_cli.rs`](../crates/gitiup/tests/policy_ask_cli.rs) |
| the same ladder under `verify change` | [`gitiup/tests/verify_change_cli.rs`](../crates/gitiup/tests/verify_change_cli.rs) |
| the same policy read back from a directory, a bare repository, a served repository, a bucket and a forge | [`gitiup-host-tests/src/policy.rs`](../crates/gitiup-host-tests/src/policy.rs), as `a_published_policy_is_read_back_from_the_store` — bytes byte-for-byte, both refs, the history glob, the chain walk and the walk's refusal, run on every host in CI |
| a publish that was refused left nothing behind, on a host where a write is a push | the same file, as `a_refused_policy_publish_writes_nothing` |
| the same answer from a bucket, a directory, a repository and a forge | [`gitiup-host-tests`](../crates/gitiup-host-tests/README.md), run in CI with `GITIUP_CONFORMANCE_REQUIRE_HOSTS` |

Related: [provenance tiers](provenance-tiers.md) (what `simulated`, `local` and `quorum`
each claim), [verification](verification.md) (the ladder a proof walks, and the exit
codes a hook branches on), [the quorum network](quorum.md) (what fills the five seats),
and [ADR-0004](adr/0004-published-policy-format-signing-and-resolution.md), which decides
all of the above in the order the code runs it.

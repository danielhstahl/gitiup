# ADR-0004 — The published policy: where it lives, who signs it, and which one was in force

* **Status**: accepted
* **Decides** where a repository's verification policy lives and which copy wins when they disagree, who is allowed to sign one and what an unsigned one does, the order the sources are resolved in and the provenance every verdict must carry, the minimum field set Epic 3 can hang off, what a repository may *not* demand of a verifier, and how a policy change is dated so a verdict is judged against the rules in force when the run happened
* **Ticket**: `giti-91m.1` (parent epic `giti-91m`, *the owner's trust, published*)
* **Blocks**: `giti-91m.2` (read, verify and resolve a published policy; `gitiup policy publish`), `giti-91m.3` (`gitiup policy show|check|explain`), `giti-91m.4` (`gitiup verify change`), `giti-91m.5` (`gitiup hook install pre-receive`), `giti-91m.6` (policy docs, executed in CI), `giti-zp1.2` (a round's quorum numbers come from the policy, not from a flag)
* **Depends on**: [ADR-0001](0001-attestation-encoding-hash-and-signature.md) — canonical JSON (D1), `sha256:` digests (D2), Ed25519 + SSH key ids + PAE (D3), claimed microseconds and freshness-as-policy (D6), the verification order, limits and the exit-code taxonomy (D7), versioning discipline (D8); [ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md) — signed-record framing (`record::body_bytes`), the roster tiers and `SelectionPolicy` this document re-uses verbatim (D5, D7), `kv/` namespaces and hex storage slots (D10), owner trust roots as `--owner` plus the local keystore (D4); [ADR-0003](0003-change-record-format-and-merge-semantics.md) — two digests with different jobs (D4), bytes-then-refs write order under CAS (D5), `ChangeRecord::policy_digest` reserved for exactly this (D2), one canonicaliser (D11)
* **Reference vectors**: [`fixtures/policy-v1/`](fixtures/policy-v1/) — `generate.py` is a stdlib-only second implementation of D2, D3, D5, D6 and D9; `policies/*.json` are the signed bytes, `cases.json` is the index, the refusal table, the history walk and the normalisation table
* **Not implemented yet**: this is a decision document. The code lands in `giti-91m.2/.3/.4/.5`; the vectors exist so those four tickets cannot each invent a slightly different "the policy the owner signed".

> Four tickets are about to read a repository's policy, and none of them owns the
> question of what it *is*. Without an answer each invents one: a file in the tree one
> ticket trusts and another ignores, a signature someone checks and someone else treats
> as advice, a verdict that cannot say which rules it applied. The dangerous version of
> that failure is silent — an unsigned policy, quietly applied — because nothing fails;
> the merge just stops being gated by anything the owner said. This document decides the
> format, the trust rule, the precedence and the dating, once, with vectors, so the four
> tickets disagree loudly if they disagree at all.

---

## Context

Today the rules live in a file somebody remembers to pass:
`gitiup verify attestation --policy gitiup-policy.json`. [`Policy`] and [`PolicyFile`]
exist in `gitiup-attest`, the exit-code taxonomy exists (0/6/7/8), and every individual
check exists — tier, sandbox rung, key, age, environment match, signature count. What
does not exist is a place a *repository*'s rules live, so a fresh clone cannot answer
"what will be demanded of this change, and who said so?".

The constraints any answer has to satisfy:

| # | constraint | who forces it |
|---|------------|---------------|
| C1 | A clone must be able to learn the rules **before** it runs anything, using only the store it can already reach — no web service, no forge API, no human in the loop. | epic (`"any clone can read it"`), [host abstraction](../host-abstraction.md) |
| C2 | The rules must be attributable: shown to have been said **in advance** by a key the reader already trusts, not merely present in the repository being judged. A fork is the adversarial case, not an exotic one. | epic ("the owner can be shown to have said so in advance"), `.4`, `.5` |
| C3 | A policy cannot certify itself, and the trust roots cannot come from the policy. Trust roots are local config (`--owner`, else this machine's keystore), exactly as `gitiup participant verify-roster` and `gitiup select` already resolve them. | epic ("deliberately not here"), ADR-0002 D4 |
| C4 | The tier a repository demands is **data**, not a flag: `local` from a named runner key and `quorum` with 5 seats / 4 agreeing are the same kind of statement in the same document. | epic, `giti-zp1.2`, ADR-0002 |
| C5 | A verdict must be debuggable: it has to name which source was in force, which digest, which key signed it, and which revision. A merge gate that cannot say where its rules came from is undebuggable. | `.3`, `.4`, `.5` |
| C6 | A run must be judged against the rules **in force when it happened**, not against today's — and "in force" must be answerable from bytes already fetched, with no call to a live service. | `.4` ("the effective policy *as it was* in force at the run's timestamp") |
| C7 | A policy may ask for things a verifier can actually do. Asking for an impossible capability is a refusal **when the policy is made or the round is seated**, never a mystery after somebody has paid for a run. | `gitiup select`, ADR-0002 D7, `gitiup-sandbox`'s ladder |
| C8 | A policy may gate what is *trusted*. `refs/changes/**` and `refs/gitiup/**` must stay writable by anyone the transport admits — that asymmetry is `giti-91m.5`'s whole design and the policy ref itself cannot be gated by the policy it would gate. | `.5` |
| C9 | The same document and the same refusals must work against `fs`, a bucket, a bare repo and a forge, so no caller branches on the transport. | `giti-xdw` conformance, [host abstraction](../host-abstraction.md) |
| C10 | A volunteer's machine parses this. Every bound must be finite, every refusal named, and nothing in the format may require a reader to fetch the world to check it. | ADR-0001 C7, D7 |

Two things were **not** in tension, and saying so keeps them out of the debate. Size is
not a constraint: a policy is a kilobyte (the biggest fixture is 1638 bytes) in a store
that deduplicates. And crypto is not a constraint: ADR-0001's signature machinery is
used unchanged, so this document adds no key type, no algorithm and no framing. The
choices below are about **authority** — whose word counts, when it started counting, and
what a reader does when it doesn't.

## Decision at a glance

| id | question | decision | rejected |
|----|----------|----------|----------|
| D1 | where a policy lives | **both, with a precedence**: the authority is a signed record in the store (`kv/policy/<hex>` advertised by `refs/gitiup/policy/current`); the committed `gitiup-policy.json` is a *draft* — the input to `policy publish`, and never the rules of record where something is published. On disagreement the published record wins and the difference is printed, never merged field-by-field | tree file only (a fork weakens it and a clone cannot tell), well-known URL outside the store (re-centralises what this epic de-centralises), store-only with no tree file (nothing to review in a diff), "merge the two", "the fresher one wins" |
| D2 | the document | one Gitiup Canonical JSON record, `type: "gitiup-policy-1"`, `application/vnd.gitiup.policy+json`, signed in place with exactly one signature; a closed set of twelve members; `rules` is `PolicyFile` **verbatim** and `quorum` is `SelectionPolicy` + `Requirements` **verbatim**; two digests (body, record); publish normalises, readers refuse non-normalised bytes | a second rule vocabulary for "published" rules, `TOML`/`YAML`, the ADR-0001 envelope, many signatures (v1), lenient reading, "readers re-normalise what they read" |
| D3 | trust | the signer is the `owner` named in the document, **and** must be in the verifier's own trust roots (`--owner`, else the local keystore). An unsigned policy is **refused** (exit 6, `unsigned`), not trusted-by-default, not used-and-flagged. The signer's key and the policy's `trust_key_ids` are different questions: the first is who may set the rules, the second who may supply a proof | "untrusted but used", signing with the key that signs the attestations (the producer choosing its own rules), trusting the document's own `trust_key_ids` as the policy's authority, a web of trust, `--trust-any-key` reaching a policy decision |
| D4 | resolution order | `--policy`/`$GITIUP_POLICY` → store-published → tree file → this build's default. The first two are **gate-eligible**; the last two are **local-only** and a merge gate with nothing gate-eligible refuses (`no_policy_published`, 6). The report names the source, the digests, the revision, the signer and the timestamp the walk used | "the tree file wins because it's local", "first one found wins" (order-dependent), a silent default for a gate, merging sources |
| D5 | field set, and what may not be demanded | the fields Epic 3 needs: required tiers + anchors + `min_signatures`, freshness, the sandbox ladder, the environment match, the quorum numbers and the capability floor. What is refused at publish/selection: a floor below the ladder's first real rung, an unsatisfiable or self-contradictory requirement set, `required_agree` of 0 or > n, a requirement published with the comparison switched off, and any `protects` outside `refs/heads/**` | allowing a policy to demand an unrunnable job, accepting an incoherent policy and resolving it "by precedence", letting a policy gate `refs/changes/**` |
| D6 | dating | `revision` + `previous_digest` (a chain, genesis = the zero digest) + `effective_from_us` (+ optional `expires_at_us`); a change is a **new signed document**, never an edit; the walk picks the newest policy in the fetched chain that had taken effect, and **refuses** (`policy_history_missing`) rather than fall back to today's rules | mutating the policy in place, a `policy_version` integer with no chain, judging every run against `current`, consulting a live service for "what was in force" |
| D7 | storage | `kv/policy/<hex(record_digest)>` (namespace `policy`, shared with verdicts), advertised by `refs/gitiup/policy/current`, with one create-only ref per revision at `refs/gitiup/policy/history/<revision>` so a single `git fetch` carries the whole chain; bytes first, then the history ref, then a CAS move of `current` | one ref per policy with no `current`, a commit chain only (`refs/gitiup/kv/policy`), storing the policy in a ref name, rewriting `current` without CAS |
| D8 | publishing | `policy publish` runs the whole validator before it signs, prints the body digest it is about to sign (`--dry-run`), refuses a `previous_digest` that does not name what `current` advertises (a lost-update guard), and prints warnings that are legitimate-but-usually-a-mistake — and never refuses on a warning | "warn about everything, refuse nothing", refusing on a warning, publishing without checking what `current` says now |
| D9 | validation order and refusals | one fixed order (bytes → structure → trust → rules → quorum → chain → normalisation), the ADR-0001 exit codes with no new class, and a named token per refusal; 32 of them are enumerated and *generated* in the vectors | lenient reading, per-crate idioms, "the first check that happens to run decides" |
| D10 | limits and versioning | a published policy is capped at 32 KiB — far below ADR-0001's 1 MiB, because every clone fetches one and a human reads it; `type` + `schema_version`, additive-only v1, unknown fields refused; no migration, because nothing is published yet | inheriting the 1 MiB ceiling, "unknown fields ignored forward-compatibly", a schema bump for a new optional field |

---

## D1 — Where a policy lives: the store publishes, the tree proposes

**Decision.** There are two places a policy can be, and they have different jobs.

1. **The published policy — the authority.** A signed `gitiup-policy-1` record in the
   repository's own store: bytes in the CAS under `kv/policy/<hex>`
   ([`Namespace::POLICY`](../../crates/gitiup-host/src/blob.rs)), advertised by the
   single ref `refs/gitiup/policy/current` (D7). This is what a clone reads, and it is
   the only copy that can be *attributed*: it carries a signature over its own bytes
   and a digest a verdict can cite.
2. **The tree file — a draft.** `gitiup-policy.json` at the repository root
   ([`POLICY_FILE_NAME`](../../crates/gitiup-attest/src/policy.rs)), or wherever
   `--policy` / `$GITIUP_POLICY` points. It is unsigned, it is un-versioned, and it is
   the thing a human edits and a pull request reviews. It is the *input* to
   `gitiup policy publish`; it is not the rules of record.

**Which wins when they disagree.** The published record. There is no field-level merge,
no "most specific wins", no freshness contest: two documents that disagree are two
policies and one of them is in force (D4). When a tree file exists and differs from the
published record, `policy show`, `policy check` and `verify change` all print one line
naming both — the tree file's digest and the published `body_digest` — and say the tree
file is not in force. That line is the whole answer to "why didn't my change obey the
rule I just edited": it did not, because editing a file is not publishing a policy, and
it will keep not obeying it until `gitiup policy publish` signs it.

They will disagree. The cases worth naming, because they are the ones that get argued
about later:

* **A fork clones a tree file it did not write.** The tree file travels with the code,
  so a fork inherits upstream's rules as *text* and can edit them with no key
  involved. That is exactly why the text cannot be the authority: a fork's tree file is
  unverified bytes from the point of view of anyone judging the fork's changes with
  upstream's trust roots.
* **A fork publishes upstream's policy unchanged** ([the `fork-inherited` vector](fixtures/policy-v1/)).
  Same bytes, same `body_digest`, same `record_digest` — because it is the same
  document, still signed by the same key. Nothing weakens, nothing needs explaining.
* **A fork publishes its own weaker policy, signed by its own key**
  ([`fork-weakened`](fixtures/policy-v1/)). Perfectly well-formed, correctly signed,
  and **refused** with `signer_untrusted` by a verifier whose roots are upstream's
  (D3). A fork cannot weaken a policy it cannot re-sign *convincingly*, which is the
  only sense in which "the owner's trust" can be inherited at all.

**What a policy may gate.** Only what is *trusted*: every `protects` glob must be inside
`refs/heads/**` (D5). `refs/changes/**` and `refs/gitiup/**` stay open to anyone the
transport admits — that asymmetry is what makes the store usable without the owner, and
it is also load-bearing here: if a policy could gate `refs/gitiup/policy/current`, a
policy could fence off the ref through which it is replaced, and the only repair would
be out of band (C8, `giti-91m.5`).

**Why not the alternatives.**

* **A committed file in the tree, trusted as the policy** (the ticket's first rejected
  alternative). Rejected because a fork can weaken it and a clone cannot tell — not in
  principle: a *text diff* tells, but only to someone who reads it, and a merge gate is
  not someone. The tree file keeps every virtue it has (reviewable, diffable, editable,
  already implemented as `PolicyFile`) and loses only the authority it never had.
* **A policy fetched from a well-known URL outside the store** (the ticket's second
  rejected alternative). Rejected, and the ticket is right: it re-centralises the thing
  the epic exists to remove, makes C1 a network dependency on somebody else's uptime,
  and puts the policy somewhere a `git fetch` does not carry, so proof and rules arrive
  by two paths with two failure modes.
* **Store-only, no tree file.** Rejected for a workflow reason rather than a security
  one: `policy publish` has to publish *from* somewhere reviewable. A signed blob with
  no textual source is a policy nobody can propose a change to. The tree file is that
  source, and D2's normalisation rule makes "the file" and "the published bytes" a
  mechanical relation rather than a second hand-maintained artifact.
* **"Both, merged, most-specific field wins."** Rejected because it makes a policy a
  union of two documents with no digest: nothing to cite, nothing to sign, and a
  reviewer cannot tell which rules were actually applied (C5). Precedence between whole
  documents is decidable and printable; precedence between fields of two documents is
  folklore.
* **"Whichever is newer."** Rejected: it makes an *unpublished* edit able to outrank a
  *published* policy purely by mtime, which is C2 inverted — it would make the loudest
  voice win rather than the signed one.

**Consequences.** `giti-91m.2` owns one function — `resolve` — that returns a policy
plus provenance, and every other ticket calls it rather than reading a file. The tree
file's schema does not change, so `gitiup verify attestation --policy` keeps working
exactly as it does today (source 1 stays gate-eligible in D4; it is the *discovered* tree
file that becomes local-only). And `gitiup policy publish` becomes the only way to change
what a repository demands, which is a phrase worth stealing for `.6`'s documentation.

---

## D2 — The document: `gitiup-policy-1`, canonical bytes, two digests

**Decision.** A published policy is one JSON document in
[ADR-0001 D1](0001-attestation-encoding-hash-and-signature.md)'s Gitiup Canonical JSON
(keys sorted ascending, no whitespace, integers only, no `null`, the restricted escape
set, depth ≤ 32), signed in place:

```text
body_bytes(policy)    = canonical(policy with `signatures` removed)
signature             = Ed25519( PAE("application/vnd.gitiup.policy+json", body_bytes) )
stored_bytes(policy)  = canonical(policy with `signatures`: [entry])
```

That is `gitiup-quorum`'s
[`record::body_bytes`](../../crates/gitiup-quorum/src/record.rs) rule, unchanged — the
fourth record type to use it, after the attestation, the roster and the change. The
`type` is `gitiup-policy-1`, `schema_version` is `1`, and the payload type is
`application/vnd.gitiup.policy+json` (both spelled out in
[`cases.json`](fixtures/policy-v1/cases.json), which is where a reader should check
them rather than here).

**The members.** A closed set of twelve, and — as in ADR-0003 D2 — the canonical
(alphabetical) order is also the order a person reads one in: who set these rules, when
they started, what they cover, what they demand, who signed.

| member | required? | what it is |
|--------|-----------|------------|
| `type` | yes | `gitiup-policy-1`, always |
| `schema_version` | yes | `1`; the only version a v1 reader accepts |
| `owner` | yes | `{key_id, principal}` — the identity whose signature is required and whose key id a report prints |
| `revision` | yes | ≥ 1, strictly +1 along the chain (D6) |
| `previous_digest` | yes | `body_digest` of the predecessor, or the zero digest for the first policy ever published |
| `effective_from_us` | yes | when these rules started counting (integer microseconds, ADR-0001 D6) |
| `expires_at_us` | no | when they stop counting; must be after `effective_from_us` and, on the read path, in the future |
| `protects` | yes | 1–32 globs, all inside `refs/heads/**` (D1, D5) |
| `rules` | yes | the proof-acceptance rules: `PolicyFile` verbatim (below) |
| `quorum` | no | the tier-`quorum` block: `default`, `by_job`, `requirements` (D5) |
| `annotations` | no | `x_<producer>_<name>` only, ≤ 16 entries, ≤ 512 bytes each — the sanctioned hatch and nothing else |
| `signatures` | yes | **exactly one** entry, from `owner.key_id` |

Unknown fields at any level are refused (`field_unknown`), which is ADR-0001 D8's version
negotiation: a v1 reader that meets a v2 field refuses rather than ignores it, so a new
field is a version bump and not a silent downgrade of the rules.

**`rules` is `PolicyFile` verbatim.** The same twenty-one keys the local file already
accepts ([`PolicyFile::KEYS`](../../crates/gitiup-attest/src/policy.rs)) and nothing
else. This is deliberate duplication-by-reuse: there must not be two vocabularies for
"what a proof must satisfy", one for the file a human writes and one for the record a
fork publishes, or the flag and the store disagree about what can even be asked and the
disagreement surfaces as a refusal nobody can reproduce locally. `--policy` and a
published policy express the same rules; only their authority differs (D4).

**`quorum` is `SelectionPolicy` and `Requirements` verbatim.** `quorum.default` and each
`quorum.by_job[<glob>]` are a
[`SelectionPolicy`](../../crates/gitiup-quorum/src/select.rs) (`n`, `reserves`,
`required_agree`, `tier_floor`, `tier_caps`, `max_per_identity`) exactly as ADR-0002
D5/D7 defines them, and `quorum.requirements` is a
[`Requirements`](../../crates/gitiup-quorum/src/capability.rs) (`arch`, `ram_mb`,
`disk_mb`, `image_digests`, `sandboxes`, `min_sandbox_level`). Epic 3 reads its round
inputs out of the policy rather than out of a flag (`giti-zp1.2`), so re-using those
types *is* the decision — a field added to `SelectionPolicy` appears in policies
automatically and refuses the same way in both places.

**Two digests, same names and same jobs as ADR-0003 D4.**

```text
body_digest   = sha256(body_bytes)     # the rules: cited by verdicts, named by previous_digest
record_digest = sha256(stored_bytes)   # the bytes: the kv/policy/<hex> key
```

`body_digest` is computable before anyone signs, which is what lets `policy publish
--dry-run` print what it is about to sign (D8) and what keeps a chain link (`previous_digest`)
stable across a re-encode of the signature list. `record_digest` covers the stored bytes
including the signature, so the CAS key identifies the artifact a reader fetched. Both
appear in every report (D4); the one that is cited as *the policy* is `body_digest`.

**Exactly one signature.** `signatures` has length 1 (`signature_count` refuses 0 and
refuses > 1). v1's policy is one owner's statement; "two people had to agree to change
the rules" is a roster question (ADR-0002), not a document-shape question, and refusing
the second signature keeps the trust check one predicate (`D3`) instead of a quorum over
who may set quorums. The `min_signatures` field inside `rules` counts signatures *of
attestations* and is unrelated — a name collision worth a sentence in `.6`'s docs.

**Normalisation: one spelling per fact.** `gitiup policy publish` normalises before it
signs:

* the `allow_simulated` shorthand is resolved into `allowed_tiers` (`true` with no tier
  list ⇒ `["local","simulated"]`; `false` ⇒ `["local"]`, the shorthand disappears);
* every list field is sorted and deduplicated — `rules.allowed_tiers`,
  `rules.allowed_sandboxes`, `protects`, `quorum.requirements.sandboxes`,
  `quorum.requirements.image_digests`.

A **reader refuses a document that is not already normalised** (`not_normalised`, exit 6)
rather than normalising what it reads. That is the opposite of what a lenient parser
does, and deliberately: the bytes signed are the bytes read, so normality is a property
of the signed bytes, and a reader that "fixed" formatting would be recomputing a digest
over bytes nobody signed. The payoff is the one that matters for D6: two authors who
wrote the same rules in a different order publish **byte-identical** bytes, and a
re-publish that changed nothing cannot move the digest a verdict already cited.
[`cases.json:normalisations`](fixtures/policy-v1/cases.json) is that table, and the
Rust reader must reproduce it field for field.

**Why not the alternatives.**

* **A separate "published policy" schema** with its own richer vocabulary. Rejected: it
  is two rule languages that drift, and the drift is invisible until a rule is enforced
  by the store and not by the flag, or vice versa. Duplication by re-use is the cheap
  option; two `require_arch` spellings is the expensive one.
* **TOML / YAML** (`gitiup.toml` exists, so TOML is "the house format" for config).
  Rejected for the reason ADR-0001 D1 rejects them for the attestation: this document is
  *hashed*. Canonical form is the entire basis of D3 and D6, and TOML has none. The tree
  file stays JSON so the file and the published bytes differ only by normalisation, not
  by parser.
* **The ADR-0001 envelope** (manifest + separate signature envelope). Rejected for the
  same arithmetic as ADR-0003 D1: two objects, two keys, and every read becomes a join.
  A policy is not exported to Sigstore tooling and is not co-signed in v1.
* **Many signatures.** Rejected above; note the vectors *test* the refusal
  (`signature_count`), so the decision is checkable rather than implied.
* **Readers re-normalise.** Rejected: it is "digest mismatch but friendlier", and it
  makes `body_digest` mean "whatever you computed", which is the hole every other
  decision here is built to close.

**Consequences.** `giti-91m.2` adds a `policy` module (probably in `gitiup-attest`, next
to `policy.rs`, since it *is* `PolicyFile` plus a signature and a date) with
`PolicyDocument` — `canonical_bytes`, `body_bytes`, `body_digest`, `record_digest`,
`verify(&Trust, now)`, `to_policy()`. `gitiup-host` stays free of it: the store stores
bytes (D7), and the dependency direction ADR-0003 D11 protects does not change.

---

## D3 — Trust: a policy cannot certify itself

**Decision.** Three checks, all of them refusals, in this order:

1. **The document is signed at all.** No `signatures` ⇒ `unsigned`, exit 6. There is no
   third state: an unsigned policy is *not* applied with a warning, *not* applied with a
   flag, and *not* applied "just for now". This is the failure the whole document exists
   to prevent, and the ticket names the reason: the dangerous answer is the silent one.
   A store that holds an unsigned policy blob has a defect, and every reader says so.
2. **The signature verifies and the identity is derived, not typed.** `key_id` must be
   the SSH-fingerprint derivation of the `public_key` offered (ADR-0001 D3), or the
   refusal is `key_id_derivation` (exit 7 — it is an identity claim that does not hold,
   the same class ADR-0003 D11 assigns it), and the Ed25519 signature over the PAE bytes
   must verify (`bad_signature`, exit 7) with `verify_strict` semantics.
3. **The signer is somebody.** Exactly one signature (`signature_count`), by the key
   `owner.key_id` names (`owner_mismatch`), and that key must be in the **verifier's own
   trust roots** (`signer_untrusted`, exit 6).

**Where the trust roots come from, and only from.** The same rule `gitiup select` and
`gitiup participant verify-roster` already use
([`resolve_trust` in `gitiup/src/select.rs`](../../crates/gitiup/src/select.rs),
[`owner_trust` in `participant.rs`](../../crates/gitiup/src/participant.rs)): `--owner
<key-or-keystore-name>`, repeatable, and if nothing is named, this machine's keystore.
The epic says this explicitly ("no web of trust and no key directory"), and re-using the
resolver is what makes it true rather than aspirational: one notion of "whose signature
counts as the owner's", one flag, one default, one failure message when the keystore is
empty. An empty trust-root set is not a special case — it is `signer_untrusted` for every
policy, which is the correct answer for a machine that trusts nobody.

`--trust-any-key` (the diagnostic escape hatch on
[`Trust::AnyKeyForTests`](../../crates/gitiup-attest/src/policy.rs)) may never reach a
policy decision: `policy publish`, `policy show`, `policy explain` and `verify change`
refuse the flag as a usage error (exit 2). A verdict about *the rules* cannot rest on
"any key that was lying around".

**The two questions, kept apart.** A policy names keys twice, and conflating them is the
subtlest way to break this design:

| | who may **set** the rules | who may **supply a proof** |
|---|---|---|
| named by | the verifier's trust roots: `--owner`, else the local keystore | the policy's own `rules.trust_key_ids` (the anchors) |
| checked by | the policy reader, before the rules are believed (this ADR, D3) | `Policy::verify`, i.e. the existing `gitiup verify attestation` machinery (ADR-0001 D6/D7) |
| refusal | `signer_untrusted`, `owner_mismatch`, `unsigned` | `policy` / untrusted signer on the attestation |
| lives in | the verifier's configuration | the signed document |

Note what is therefore **not** checked: a policy is *not* required to be signed by a key
it lists in `trust_key_ids`, and a policy is *not* required to be signed by a key this
machine happens to hold in its keystore. The normal, correct arrangement is the
[`personal` vector](fixtures/policy-v1/): the owner (Ada) publishes rules whose anchors
are the CI runner's key, because the runner signs the proofs and the owner sets the
rules. `policy publish` prints a warning when none of the anchors is a key this machine
holds (D8) — a reminder, not a refusal — because the opposite arrangement is the one this
ADR refuses.

**Why not the alternatives.**

* **"Untrusted but used"** (apply the policy, warn in the log). Rejected by the ticket
  and by arithmetic: a warning in a CI log is read by nobody, and the resulting system
  has the security properties of *no* policy with the appearance of one. Refusing means
  a fork's weaker policy stops the merge, which is the behaviour an owner can actually
  rely on. `fork-weakened` exists to keep this from being re-litigated: it is
  well-formed, correctly signed by a real key, and exits 6.
* **The policy signed by the same key that signs the attestations it judges** (the
  ticket's third rejected alternative). Rejected: the producer must not choose its own
  rules. Under that rule any signer of an attestation could publish "tier `simulated`,
  any key, no freshness limit" and be believed by its own gate — the policy stops being
  a constraint and becomes a claim in the attestation, at which point verify has nothing
  to verify against. The two-questions table above is the structural version of this
  rejection, and `rules.trust_key_ids` is checked against proofs, never against the
  policy that carries it.
* **Trusting the document's own `trust_key_ids` as the authority for itself.** Rejected:
  that is C2 violated by construction — the policy vouches for itself, which is the
  definition of "cannot certify itself". The anchors are *required to be non-empty*
  (`no_trust_anchors`: a policy that trusts nobody can never be satisfied) but they are
  never consulted to decide whether the policy is believed.
* **A web of trust, a key directory, a transparency log of policy publishes.** All
  rejected by the epic's "deliberately not here". ADR-0001 D9's log anchoring stays
  available as an *optional, separate, additive* layer over policy digests; nothing here
  depends on it, and nothing here prevents `.6` from documenting it as hardening.
* **An owner-key rotation story.** Out of scope, deliberately: ADR-0002 D9's revocation
  matrix applies unchanged — a `compromised` key voids the claims made with it, which
  includes policies published with it, and the chain (D6) means the revocation is
  auditable rather than a rewrite.

**Consequences.** Every read path in this epic — `.2`'s resolve, `.3`'s show/check/
explain, `.4`'s verify change, `.5`'s hook — runs the same three checks with the same
resolver, so "who do you trust to set the rules?" has one answer per machine and that
answer is printed in every report (D4). `giti-91m.2` gets the refusal tokens for free
from the shared taxonomy, and `.5`'s hook gets a rule it can state in `--help`: *a policy
nobody signed is not a policy.*

---

## D4 — Resolution order, and the provenance a verdict must carry

**Decision.** Four sources, one order, and a line drawn through the middle of it:

```text
 1. --policy <file> / $GITIUP_POLICY ............ explicit, operator-supplied   ┐
 2. store-published: refs/gitiup/policy/current, signed, verified, then         ┘ gate-eligible
    walked to the revision in force at the run's timestamp (D6)
 3. gitiup-policy.json discovered in the checkout  unsigned, unverified          ┐
 4. this build's built-in default: Policy::default()  nothing published anywhere ┘ local-only
```

**Gate-eligible** means a merge decision may rest on it: `gitiup verify change` (`.4`)
and `gitiup hook install pre-receive` (`.5`). **Local-only** means the source may be used
to answer "what would happen?" — `gitiup run`'s own pre-flight (`would the owner's policy
accept what I'm about to produce?`), `gitiup doctor`, `policy show`, `policy check` in
dry-run, `policy explain` — and never to decide a merge. A gate with nothing gate-eligible
refuses:

```text
exit 6 · no_policy_published
       no policy is published in this store and none was named with --policy;
       refusing rather than deciding a merge by a default nobody chose
```

`no_policy_published` is a *resolution* failure, not a refusal of a document, which is
why it is not in D9's table: nothing was read, so there is nothing to point at. It exits
6 because 6 already means "refused, and this build understands what you asked".

**The pre-receive hook takes no override.** `.5`'s hook resolves source 2 and nothing
else — no `--policy`, no tree file, no default. That is not a limitation: the hook's
entire value is that a stranger with a clone reaches the same verdict the box that
accepted the push reached, and an override in a hook script on one machine destroys
that. `gitiup hook status` therefore always answers "which policy is in force, when was
it read, by which key" (D7 of `.5`), and `--no-proof-required` remains the only escape,
which announces itself and appears in `gitiup doctor`.

**`--policy` still wins, and says so.** The explicit flag is an operator's act, ahead of
anything published, so a maintainer can debug a gate or run a stricter one on one box.
It *replaces* rather than merges, and the report carries both: which file was used, and
which published digest it overrode, with a `notes` line saying the gate was run with an
override nobody published. `verify attestation`'s existing behaviour is unchanged — it
remains the primitive, and it keeps accepting `--policy`, `$GITIUP_POLICY` and discovery
as it does today; what changes is that its `policy` block must now also say *which of the
four* it used.

**Every report names the policy in force.** The `policy` object `gitiup verify
attestation --json` already prints
([`PolicySpec::json`](../../crates/gitiup/src/verify.rs): `file`, `trust`,
`trusted_key_ids`, `tiers`, `sandboxes`, `min_signatures`, `max_age_us`, `notes`) gains
provenance, with these members when the source is a published record:

| field | meaning |
|-------|---------|
| `source` | `"--policy"` · `"$GITIUP_POLICY"` · `"store"` · `"tree-file"` · `"built-in-default"` |
| `file` or `ref` | the path, or `refs/gitiup/policy/current` |
| `body_digest` | **the policy's identity**: what a verdict cites and what `previous_digest` names |
| `record_digest` | the stored bytes' digest, and so the `kv/policy/<hex>` key it came from |
| `revision` | which link of the chain was applied (D6) |
| `signed_by` | `owner.key_id`, with the principal next to it in human output |
| `effective_from_us` | when these rules started counting |
| `at_us` | the timestamp the walk used, and how it was obtained (`run-claim`, `merge-record`, `now`) |
| `notes` | why anything surprising happened: an override, a tree file ignored, a chain walked `n` links, a chain that could not be walked |

and `ChangeRecord::policy_digest` — reserved for exactly this by
[ADR-0003 D2](0003-change-record-format-and-merge-semantics.md) — is defined to be the
**`body_digest`** of the policy in force at merge time, not the record digest. ADR-0003
D4's rule generalises: citations name the signed body, storage keys name the stored
bytes.

**Why not the alternatives.**

* **"The tree file wins, because the caller is standing in the checkout."** Rejected:
  that is D1's rejected alternative wearing a different hat, and it makes a fork's
  unsigned edit outrank an owner's signed record. It stays in the ladder as source 3
  because a human standing in a checkout legitimately wants "what would this repo's
  file demand", and it is local-only because that is a question, not a verdict.
* **"First source found wins", order otherwise unspecified.** Rejected: it produces the
  same verdict by accident on one machine and a different one on another, and the
  disagreement is invisible from the output. C5 is the whole point of this section.
* **A silent built-in default for gates.** Rejected: it is D3's silent failure from the
  other direction. `Policy::default()` fails closed — `Trust::None` — so a gate using it
  would refuse *everything* while appearing configured; `no_policy_published` at least
  says what is missing.
* **Recording `record_digest` as the policy citation.** Rejected because it ties a
  verdict to a signature envelope rather than to the rules: two publications of
  identical rules differ only in the signature bytes, and D6's whole promise is that
  "did the rules change?" is answerable by comparing digests.
* **Letting the hook take `--policy`.** Rejected above, and note the ticket for `.5`
  already asks for the hook's `--help` to explain the asymmetry — the policy half of
  that sentence is this paragraph.

**Consequences.** `giti-91m.2` exposes one entry point — resolve a policy for a store,
a timestamp and a set of trust roots, returning `{policy, provenance}` — and `.3`, `.4`,
`.5` all render its output; no ticket gets to open a policy file on its own. `gitiup
policy show` is a thin wrapper over it, which is what makes "the effective policy, and
where it came from" a one-liner rather than a design. And every existing report gains
eight fields, which is a compatibility question only in the sense that adding fields to
`--json` has always been: additive, and refused by nothing.

---

## D5 — The field set Epic 3 hangs off, and what a repository may not demand

**Decision.** The minimum field set is exactly what a merge gate, a quorum round and a
selection run all need, and nothing else. Grouped by who consumes it:

| group | fields | consumed by |
|-------|--------|-------------|
| **the tier, as data** | `rules.allowed_tiers` (one or more of `simulated` · `local` · `quorum`), `rules.allowed_sandboxes` (the ladder rungs a `local` run may name) | `.4`, `.5`, `gitiup run`'s pre-flight |
| **who may prove it** | `rules.trust_key_ids` (anchors, non-empty), `rules.min_signatures` (distinct trusted signatures) | `Policy::verify`, `.4` |
| **freshness** | `rules.max_age_us`, `rules.max_clock_skew_us` (default 24 h and 5 min, ADR-0001 D6) | `Policy::verify`, and D6's clock-skew rule |
| **the machine class** | `rules.require_env_match` (`strict` · `major` · `off`) plus the `require_*` block: `require_arch`, `require_os`, `require_os_version`, `require_image_digest`, `require_image_reference`, `require_provider`, `require_runner`, `require_toolchain`, `require_env_fingerprint`, `require_normalisation_version` | `Policy::verify` (giti-1rs.4), `.3`'s explain |
| **the quorum, when the tier allows it** | `quorum.default` and `quorum.by_job[<glob>]`: `n`, `required_agree`, `reserves`, `tier_floor`, `tier_caps`, `max_per_identity` — `SelectionPolicy` verbatim | `giti-zp1.2`, `giti-msi.7`, `.4` |
| **what a verifier must be able to do** | `quorum.requirements`: `arch`, `ram_mb`, `disk_mb`, `image_digests`, `sandboxes`, `min_sandbox_level` — `Requirements` verbatim | `gitiup select` (ADR-0002 D7's filter), `gitiup-sandbox`'s `admit` |
| **how a seat submits** *(added with giti-p1.6, below)* | `quorum.reveal_mode`: `open` (absent means this) \| `sealed` | `gitiup change submit` (it opens the round), `gitiup work` (it follows it), `store::tally` |

**Amendment (giti-p1.6, commit-reveal).** `quorum.reveal_mode` is the first addition to
the `quorum` block since this ADR was accepted, and it is an *additive optional field*:
a document published before it exists keeps its exact bytes and its `body_digest`, and a
document that names it is refused by a v1 reader as an unknown field — which is the right
behaviour, not a compatibility bug. A policy that asks for a submission rule the running
build cannot enforce (`policy` token `quorum_reveal_mode`) is refused rather than opened as
`open`, for the reason D9 states for every unknown field: no leniency, no silent default.
It belongs to the owner and not to a flag for the same reason `n` and `required_agree` do:
whoever submits a change must not choose how independent its verification is, and a fork
must not be able to un-seal an upstream's rounds. What the mode means, and the list of
things it does not buy, is [ADR-0002 D11](0002-roster-verifier-selection-and-sybil-resistance.md)
and [docs/quorum.md](../docs/quorum.md).
| **scope** | `protects` (globs inside `refs/heads/**`) | `.5`, `.4` |

That is the set the ticket asked for — required tier, trust anchors, `required_agree`/`n`
for a quorum, freshness window, allowed sandbox ladder, require-env-match, and the
capability floor — with two additions worth naming because tickets would otherwise invent
them: `min_signatures` (how many distinct trusted proofs make a set, `.4` needs it) and
`require_normalisation_version` (two normalisations that differ cannot produce comparable
digests, so a policy that compares results across verifiers has to pin it).

Two members of `PolicyFile`'s vocabulary are *bindings*, not standing rules:
`expected_commit` and `expected_result_digest`. They remain readable (the vocabulary is
one vocabulary, D2) but a caller supplies them per decision — a published rule that
pinned a commit could only ever be satisfied by one commit — so `gitiup policy publish`
refuses to write them and says why. That is a publish-side refusal (D8), not a reader
refusal, and it is the only place the two vocabularies are not interchangeable.

**What a repository may not demand of a verifier.** The principle: *a policy is a
statement of eligibility, and an impossible statement is refused when it is written, not
when somebody has paid to discover it.* A policy that asks for a capability nobody can
provide would otherwise fail at run time — after a volunteer has fetched a repo, booted a
container and produced nothing — which is the worst possible place to learn that two
fields disagreed. Each refusal below is raised by the validator at publish time **and**
by every reader (D9), and the ones that concern a *round* are also raised at selection,
so `gitiup select` refuses to seat a round that cannot be filled:

| the demand | token | why it is refused |
|------------|-------|-------------------|
| `quorum.requirements.min_sandbox_level` < 1 | `sandbox_floor` | rung 0 is "nothing confined this". The sandbox crate already refuses the `plain` backend for a quorum job; a repository may not demand less confinement of a stranger than the verifier's own floor |
| `quorum.requirements.sandboxes` empty, or disjoint from `rules.allowed_sandboxes` | `requirements_unsatisfiable`, `sandbox_disjoint` | the policy would seat a verifier that its own proof rules then refuse — an argument with itself, resolved by nobody |
| `ram_mb` or `disk_mb` of 0 | `requirements_unsatisfiable` | a zero resource floor selects any box and proves nothing (`Requirements::validate` already says this) |
| `arch` spelled differently from `require_arch`, or not canonical | `arch_conflict`, `arch_not_canonical` | `amd64` and `x86_64` are one machine; two spellings in one document is how an arm64 round satisfies an amd64 rule |
| `required_agree` of 0, or greater than `n` | `required_agree_zero`, `required_agree_unreachable` | 0 certifies anything including nothing; > `n` can never complete. (`.2`'s acceptance criterion — "refuse a policy that contradicts itself" — is this row and the two above it) |
| `tier_floor` / `tier_caps` naming an unknown roster tier | `tier_floor_unknown`, `tier_caps_unknown` | ADR-0002 D5's three tiers are the whole vocabulary; a fourth is a typo |
| `quorum` not in `allowed_tiers` while `quorum.default` is present | `tier_not_allowed` | the numbers say one thing, the tier says another |
| `quorum` in `allowed_tiers` with no `default` and no `by_job` | `quorum_without_rules` | "quorum required" with nothing to decide the quorum is a gate that can never be satisfied |
| `allowed_tiers` empty, or naming an unknown tier | `empty_tiers`, `tier_unknown` | a policy that accepts no tier accepts no proof; `cloud` is not a gitiup tier |
| `min_signatures: 0` | `min_signatures_zero` | unsigned proofs, smuggled in through a field |
| `require_env_match: "off"` while any environment requirement is published | `env_match_off` | publishing a requirement and switching off the comparison is the silent failure again, one level down |
| `allow_simulated` contradicting `allowed_tiers` | `simulated_contradiction` | already refused by `PolicyFile::from_json`; a published policy may not resolve the contradiction by precedence either |
| any `protects` glob outside `refs/heads/**` | `protects_out_of_scope` | D1's asymmetry: a policy gates what is trusted, never what is merely offered |
| `trust_key_ids` empty | `no_trust_anchors` | a policy that trusts nobody can never be satisfied, so it is refused at publication rather than merged and complained about later |

**Why not the alternatives.**

* **Accept an incoherent policy and resolve it at run time by precedence.** Rejected: it
  is the `allow_simulated` lesson (D2, `PolicyFile::from_json`) generalised — gitiup
  already refuses a policy that argues with itself rather than guessing which half the
  author meant, and a *published* policy has even less excuse, because it was signed
  deliberately and can be signed again.
* **Let a repository demand anything, and let selection fail.** Rejected for cost, and
  for C7: selection is the last moment where "nobody can do this job" is cheap to say.
  After the round is seated, a failure is a burned volunteer and a stalled change; before
  it, it is one line of output at publish time.
* **Freezing the field set at "tiers + keys + age".** Rejected because Epic 3
  (`giti-zp1.2`, `giti-msi.7`) would then hang its numbers off a flag or a second
  document, which is C4's failure mode — the tier demanded by a repository becomes
  something the caller chooses rather than something the owner signed.
* **Namespacing the quorum block under a new name (`selection:`, `epic3:`).** Rejected:
  `SelectionPolicy` and `Requirements` already exist, already validate, and already
  refuse the same nonsense; `quorum` says who consumes it and re-using the types keeps
  one definition of "n of m, tier floor, caps" in the workspace.

**Consequences.** The validator is one function with one order (D9) and it is complete:
`.2`'s "refuses a policy that contradicts itself" is a table lookup, not a design
decision, and `giti-zp1.2` can read `quorum.default` straight into `SelectionPolicy`
with no translation and no new failure mode. The cost is that `rules` and `quorum` are
now load-bearing in a second place, so a field added to `SelectionPolicy` in ADR-0002's
territory also appears in published policies — which is the desired coupling, but is
worth a sentence in `.6`'s docs and a property test in `.2`'s suite.

---

## D6 — Dating: revision, chain, and the policy in force when the run happened

**Decision.** A policy is dated with four fields, and a policy *change* is a new signed
document — never an edit of the old one.

| field | meaning |
|-------|---------|
| `revision` | an integer ≥ 1, exactly one more than its predecessor's |
| `previous_digest` | the predecessor's `body_digest`, or `sha256:000…00` for the first policy a store ever advertised |
| `effective_from_us` | the first microsecond these rules count, integer µs (ADR-0001 D6) |
| `expires_at_us` | optional; after it, the document is `expired` and no longer selectable |

Genesis uses a zero digest rather than an absent field because canonical JSON forbids
`null` (ADR-0001 D1) and "there was no predecessor" is a fact, not an absence.

**Why a new document and not an edit.** Because a verdict cites `body_digest` (D4), and a
merge that cited an edited policy would be citing a digest that no longer describes the
rules it used — the exact failure ADR-0003 D4 avoids for changes, for the same reason. It
also makes the audit trail free: the chain of signed documents *is* the policy's history,
each link attributable, and there is no "and here is the old version, we hope it was
backed up". The cost is that changing a rule costs a signature, which is the point.

**The walk.** `in_force_at(chain, at_us)` is: among the policies reachable from the
advertised one by walking `previous_digest`, take the newest with
`effective_from_us <= at_us` that has not expired. Refusals, with tokens the vectors
share:

| situation | token | why it is a refusal and not a fallback |
|-----------|-------|----------------------------------------|
| nothing in the chain had taken effect at `at_us` | `policy_history_missing` | falling back to today's rules to judge a run made under none is the worst of both: a verdict that is neither "no rules applied" nor "these applied". `.4`'s answer to a pre-policy run is a refusal it can explain |
| the selected document is expired at `at_us` | `expired_history` | the rules stopped counting before the run happened; "there were no rules then" is the truth |
| `effective_from_us` more than the skew allowance (`rules.max_clock_skew_us`, default 5 min) into the future | `future_dated` | a policy cannot be in force before it exists; the allowance is the clock-quality bound ADR-0001 D6 already accepts, not a new number |
| `expires_at_us <= effective_from_us` | `expires_before_effective` | a document that is dead on arrival |
| `expires_at_us` in the past on the read path | `expired` | a published-but-expired policy is a broken gate, and a gate that says nothing is better than one that quietly stopped |
| `previous_digest` names a document the reader cannot find | `chain_broken` | the chain is the only evidence of what came before; an unverifiable predecessor means "which rules were in force then?" has no answer. A genesis document needs no history and is not refused |
| `revision` jumps, or genesis is not revision 1 | `revision_gap` | a hole in the history is a hole in the audit |
| predecessor's `effective_from_us` is not strictly earlier | `effective_from_backwards` | time-traveling predecessors make the walk ambiguous |

**Where the timestamp comes from, and why that is not an escape.** The walk uses the
*run's* claimed time (an attestation's timestamp, or the merge record's), pinned by
`Policy::now` in tests and replays. A producer controls that claim, so the bound is not
this document's — it is the freshness window's: an attestation older than
`rules.max_age_us` (plus skew) is refused by `Policy::verify` whatever policy the walk
picks. **That is the freshness question one level up, and it is the reason `max_age_us`
is a policy field with a 24 h default: the freshness window bounds how long a policy
change can be dodged with an old proof.** Tighten the window and a revoked or weakened
rule stops being exploitable sooner; widen it and a stale attestation keeps being accepted
under the rules it was made under, which is sometimes exactly what you want (an old
release branch) and sometimes a hole. Because that trade-off is easy to get wrong
silently, `policy publish` warns when `max_age_us` exceeds a week (D8).

The walk consults **no live service** (C6): the chain is fetched as bytes (D7) and walked
locally, up to a bound of 64 links (`MAX_CHAIN_WALK`) so a volunteer's parse stays
bounded. `cases.json:history` pins the three probe points that Rust must reproduce:

| run happened at | the policy in force | why |
|-----------------|---------------------|-----|
| 2026-10-07 (`probe_before`) | `project`, revision 1 | revision 2 took effect 2026-10-20; 4-of-5 applied then |
| 2026-10-25 12:03:20 (`probe_after`) | `project-tightened`, revision 2 | 5-of-7, half the freshness window |
| one microsecond before revision 1 | refused, `policy_history_missing` | there was no policy yet, and inventing one is not the same as having none |

**Why not the alternatives.**

* **A `policy_version` integer with no chain.** Rejected: it names a version without
  binding it to bytes, so "what did revision 7 demand?" needs the old document anyway —
  and without `previous_digest` there is no way to prove the document you found is the
  one that preceded this one. The chain costs one field and turns the history into
  something a reader can verify rather than something it hopes the store kept.
* **Always judge against `current`.** Rejected by C6 and by the ordinary case: a review
  of last week's run against this week's rules produces a refusal that is true about
  today and useless about the run. ADR-0003 D8's merge record already records the
  digests a merge *believed*; a policy that cannot be re-read at the time it was believed
  makes every historical verdict unauditable.
* **Consulting a live service for the effective policy.** Rejected by C1 and C6
  together, and it would make a pre-receive hook depend on somebody's uptime at the
  moment of least patience.
* **Trusting `effective_from_us` alone, without the freshness bound.** Rejected: without
  the window in D5 a producer could sign a claim dated in a looser era indefinitely, and
  the chain would then be an oracle for anyone willing to lie about a clock.

**Consequences.** `.2`'s resolve takes an `at_us` and returns the revision it applied;
`.4` passes the run's timestamp and prints `revision` + `at_us` (D4); `.3`'s `explain`
can say "this run was judged by revision 1, which required 4 of 5" in one line because
the numbers it prints came from that document. Retention has a new invariant, stated once
here and enforced by `.2`: **policy history is never pruned.** Deleting an old revision is
what turns an old run's verdict into `policy_history_missing`, and a store that cannot
answer that question cannot defend its own merges.

---

## D7 — Storage: keys, refs, write order, and what a fetch carries

**Decision.** One CAS key, one current ref, one ref per revision.

```text
kv/policy/<hex(record_digest)>            the signed bytes, immutable by construction
refs/gitiup/policy/current               → the policy in force (moved under CAS)
refs/gitiup/policy/history/<revision:06> → every revision ever published, create-only
```

* **`Namespace::POLICY` is shared with quorum verdicts**, whose documented meaning is
  already "quorum verdicts and policy documents"
  ([`blob.rs`](../../crates/gitiup-host/src/blob.rs), ADR-0002 D10). A policy is told
  apart from a verdict by its `type` field, not by the key: the key is a digest, and
  splitting the two concepts across namespaces would mean a reader has to know which kind
  it is before it can look. Nothing here adds a namespace.
* **`current` is a pointer, not the bytes.** On a git-backed host it is a pointer commit
  the way `refs/changes/**` and `refs/attestations/**` are
  ([host abstraction](../host-abstraction.md), "the bytes travel with it"), so
  `git fetch refs/gitiup/policy/current` carries the rules and their signature in one
  packfile and a clone can answer C1 with the transport it already has. On a bucket it is
  the object key that names the current digest.
* **`history/<revision>` is create-only** (`Expect::Absent`), zero-padded so a listing is
  in order. That is what makes D6's walk one fetch: `git fetch
  'refs/gitiup/policy/history/*'` arrives with the whole chain, so a clone can judge a
  year-old run without any listing, any pagination, and any assumption that the store
  still has anything else. ADR-0002's `refs/gitiup/kv/<namespace>` append-only chain
  would also work, but a revision must be individually addressable by number and
  immutable by the transport rather than by convention — hence one ref each.
* **Write order: bytes, then history, then `current`.** The CAS blob must exist before
  any ref names it (ADR-0003 D5's rule, and the same reason as there): a ref to absent
  bytes is the state a reader cannot repair. Moving `current` is a CAS write
  (`Expect::Is(previous)`) because "a lost update here is a lost policy" — two owners
  publishing at once must produce one loser, not a policy that flickers. A crash between
  the history ref and the `current` move leaves a revision that exists and is not current,
  which is safe, is what `policy show` prints, and is repaired by re-publishing; a
  `current` whose bytes the store cannot return is a **refusal** (`digest_mismatch` /
  missing key), never a silent fall back to an older policy.
* **Nothing about a policy is secret.** It is published precisely so a stranger can read
  it before running anything; `protects` and `requirements` disclose a little about the
  owner's infrastructure, and that is a feature — ADR-0002 D11's "what is secret, until
  when" does not apply here, because the analogous secret (who will verify a given round)
  is not in this document.
* **Retention: history is forever** (D6). A `policy gc`, if one is ever written, may prune
  blobs no live ref names and must never prune a `history/**` ref or the blob it names —
  the invariant `attest gc` already owes its pinning rule
  ([`attest.rs`](../../crates/gitiup-host/src/attest.rs): an object another live ref
  points at is never pruned).
* **A forge is an advertisement, not a home.** A GitHub adapter may mirror a policy
  (check-run style) exactly as ADR-0003 D10 makes a pull request an advertisement of a
  change: it may not promise to reconstruct signed bytes, and a reader that found a policy
  only in a forge field must say which it read (D4's `source`).

**Why not the alternatives.**

* **`refs/gitiup/policy/<revision>` only, no `current`.** Rejected: every reader would
  need a listing plus a tie-break, which puts "which one is in force?" in the client,
  where four tickets would answer it four ways (C5). One ref, one answer.
* **The policy bytes in the ref name.** Rejected: refs are not digests-first in this
  store's style (ADR-0002 D10's hex-slot rule is about key ids, and a policy's identity
  is a `sha256:` string with a colon that is hostile in a ref), and it would mean the
  current policy is unmovable without a rename.
* **A single `refs/gitiup/kv/policy` chain.** Rejected above: addressable-by-number and
  create-only-per-revision are what the walk needs, and the chain gives neither cheaply.
* **Storing the policy under its `body_digest`.** Rejected for ADR-0003 D4's reason: the
  key must name the bytes a reader fetched (`record_digest`), or the "same policy"
  question becomes "same rules, plus a signature from somewhere".

**Consequences.** `.2`'s publish is four steps (canonicalise, sign, write bytes + history
ref, CAS-move `current`) and its read is three (fetch `current`, fetch history, walk);
`.5`'s hook reads the same two refs and nothing else; the conformance suite
(`giti-xdw.6`) gains one contract — a policy published to `fs` must be readable from a
`git` host and a bucket with identical digests, which is C9 made testable.

---

## D8 — What `policy publish` says before it signs

**Decision.** `gitiup policy publish [--store] [--dry-run]` reads the tree file
(or `--policy`), normalises it (D2), runs the **whole** validator (D9) against the
store's current state, signs, and publishes (D7). Four behaviours are decided here
because `.2` would otherwise guess:

1. **`--dry-run` prints the `body_digest` it is about to sign**, the rules as they will be
   written (post-normalisation), and what would change: `current` `<old body_digest> →
   <new body_digest>`, revision `n → n+1`. This is possible only because `body_digest`
   excludes the signature (D2), and it is what makes "what exactly am I committing to?"
   answerable before committing to it.
2. **Publish refuses a `previous_digest` that does not name what `current` advertises**,
   re-using `chain_broken` / `revision_gap`. That is the lost-update guard: two owners
   editing the tree file must produce one loser with a clear message ("fetch, re-sign
   against `<digest>`, publish again"), not a policy that silently drops a revision.
3. **Publish refuses the per-decision bindings** (`expected_commit`,
   `expected_result_digest`, D5) and anything D5's table refuses. This is `.2`'s
   acceptance criterion — *"refusing to publish a policy that contradicts itself"* — and
   it is discharged by the table, not by new logic.
4. **Warnings are printed and never refused.** A warning is for something legitimate that
   is frequently a mistake; the table is fixed by the vectors
   (`cases.json:policies[*].warnings`), and these are the four:

| warning | why it is a warning and not a refusal |
|---------|----------------------------------------|
| none of the trust anchors is a key this machine holds | correct and normal when a CI runner signs proofs and the owner publishes rules (`personal` does exactly this); a mistake if you meant the proofs to come from your own key |
| the policy expires within a week | deliberate short expiry is a real choice; a gate that stops on the day nobody noticed it expired is a real outage |
| a quorum block demands unanimity (`required_agree == n`) | one verifier offline is no verdict, and the escalation round asks for *more* — usually not what "4 of 4" was meant to say |
| `max_age_us` is over a week | that is how long a policy change can be dodged with an old proof (D6); fine for a release branch, a hole on a main branch |

**Why not the alternatives.** *Warn about everything, refuse nothing* — rejected: the
contradictions in D5's table are not matters of taste, and `.2` says refuse. *Refuse on a
warning* — rejected: the first row of that table would then refuse the commonest correct
setup in the wild, and a tool that cries wolf gets its output ignored, which is worse than
a tool that prints nothing. *Publish without consulting `current`* — rejected: it is a
lost update dressed as a publish, and with D6's chain it is the one place a revision can
go missing.

**Consequences.** `.2` gets its publish as a sequence of already-decided parts: D2 for
the bytes, D9 for the checks, D6 for the chain link, D7 for the writes, and this section
for what it prints. `gitiup policy publish --dry-run --json` is also the answer to "which
digest will this change produce?", which `.6`'s worked examples can then pin.

---

## D9 — One validation order, named refusals, and no new exit codes

**Decision.** Every reader — `.2`'s resolve, `.3`'s show/check/explain, `.4`'s verify
change, `.5`'s hook, and the quorum's round inputs in `giti-zp1.2` — runs the same
validator in the same order. The order is normative for the same reason ADR-0001 D7 and
ADR-0002 D7 fix theirs: a document that fails two checks must always report the same one,
or two honest implementations disagree about a document a human is auditing.

```text
1  bytes      size ≤ 32 KiB, and the bytes are their own canonical form
2  structure  fields (unknown/missing/shapes), type + schema_version, dates,
              owner, protects, annotations, signature count, key-id derivation,
              signature verification
3  trust      the signer is in the verifier's trust roots; anchors are non-empty
4  rules      PolicyFile coherence: tiers, min_signatures, anchors' shape,
              env-match, sandbox names
5  quorum     selection (n, agree, floor, caps) and requirements (the D5 table)
6  chain      previous_digest resolves, revision is +1, effective_from moves forward
7  normalised every list is sorted and deduplicated (D2)
```

Steps 1–2 are self-consistency and must precede 3: a typo in a policy should print the
typo (`field_unknown`), not "bad signature", and a document whose bytes are not their own
canonical form is refused before anything in it is believed. Step 6 precedes 7 only
because 7 is a property of the bytes rather than of their meaning; both are cheap.

**Exit codes are ADR-0001 D7's, unchanged**: 6 refused, 7 bad signature, 8 not-its-own
bytes / digest mismatch. No new class is introduced, because every refusal here is
either "this is not a valid document" (6), "the identity claim does not hold" (7), or
"these are not the bytes that were signed" (8), and the `--json` report carries the
`token` alongside the class so a script can branch on the specific reason without
inventing its own vocabulary. `key_id_derivation` is 7 rather than 6 for ADR-0003 D11's
reason: the bytes are fine and the identity claim is not. `size_exceeded` is 6 rather
than 8: an oversized document is refused, it is not a mis-hash.

**The refusal table.** [`cases.json:refusals`](fixtures/policy-v1/cases.json) holds
these 32 rows, and
[`generate.py`](fixtures/policy-v1/generate.py) *produces* them by mutating a real
vector and then **re-signing** it — a defect applied after signing is only a broken
signature, so an ungenerated table would teach "bad signature" thirty times. The three
rows that *are* post-signing defects (a body edited afterwards, a typed `key_id`, an
owner that does not match the signer) are applied after signing on purpose. `.2`'s test
list is this table, and `.3`, `.4`, `.5` must reach the same token and exit for the same
documents.

| exit | token | the case, and the mutation that produced it |
|------|-------|-------------------------------------------|
| 6 | `arch_conflict` | arch spelled two ways — `set quorum.requirements.arch = "aarch64"` |
| 6 | `chain_broken` | previous_digest names nothing — `set previous_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"` |
| 6 | `empty_tiers` | accepts no tier — `set rules.allowed_tiers = []` |
| 6 | `env_match_off` | env match off with a requirement — `set rules.require_env_match = "off"` |
| 6 | `expired` | expired — `set expires_at_us = 1793092799999999` |
| 6 | `expires_before_effective` | expiry before effect — `set expires_at_us` |
| 6 | `field_unknown` | unknown field — `set rules.require_archh = "x86_64"` |
| 6 | `future_dated` | future-dated — `set effective_from_us = 1793093800000000` |
| 6 | `min_signatures_zero` | zero signatures required — `set rules.min_signatures = 0` |
| 6 | `no_trust_anchors` | no anchors at all — `set rules.trust_key_ids = []` |
| 6 | `not_normalised` | rules not in canonical order — `set rules.allowed_tiers = ["quorum", "local"]` |
| 6 | `owner_mismatch` | signer is not the owner — `owner key` |
| 6 | `protects_out_of_scope` | gates a contributor ref — `set protects = ["refs/changes/**"]` |
| 6 | `required_agree_unreachable` | threshold above seats — `set quorum.default.required_agree = 9` |
| 6 | `required_agree_zero` | threshold of zero — `set quorum.default.required_agree = 0` |
| 6 | `requirements_unsatisfiable` | no sandbox can satisfy it — `set quorum.requirements.sandboxes = []` |
| 6 | `requirements_unsatisfiable` | zero resource floor — `set quorum.requirements.ram_mb = 0` |
| 6 | `revision_gap` | revision skips — `set revision = 9` |
| 6 | `sandbox_disjoint` | sandbox sets disjoint — `set quorum.requirements.sandboxes = ["landlock"]` |
| 6 | `sandbox_floor` | policy demands no confinement — `set quorum.requirements.min_sandbox_level = 0` |
| 6 | `sandbox_forbidden` | unconfined sandbox demanded — `add rules.allowed_sandboxes = "none"` |
| 6 | `signature_count` | two signatures — `dup signature` |
| 6 | `signer_untrusted` | signed by a stranger — `foreign signer` |
| 6 | `size_exceeded` | over the size limit — `add 64 annotations of 512 bytes, over the 32 KiB record limit` |
| 6 | `tier_floor_unknown` | unknown roster tier — `set quorum.default.tier_floor = "famous"` |
| 6 | `tier_not_allowed` | quorum rules, quorum refused — `set rules.allowed_tiers = ["local"]` |
| 6 | `tier_unknown` | unknown tier — `set rules.allowed_tiers = ["cloud"]` |
| 6 | `unknown_schema` | unknown schema — `set schema_version = 2` |
| 6 | `unsigned` | unsigned policy — `remove signatures` |
| 7 | `bad_signature` | body edited after signing — `tamper` |
| 7 | `key_id_derivation` | typed key id — `signer key id` |
| 8 | `not_canonical` | not its own bytes — `re-encode with whitespace` |

Twenty-eight distinct tokens refuse at exit 6, two at 7 (`bad_signature`,
`key_id_derivation`) and one at 8 (`not_canonical`). Two rows are about bytes rather than
about a document and so cannot be mutations of one — `not_canonical` (an encoding that is
not its own canonical form) and `size_exceeded` — but they are step 1 for the same reason
everything else is: refuse the container before believing the contents. `digest_mismatch`
(8) is in the taxonomy and is used by the index checks (a stored object whose bytes are
not the bytes `kv/policy/<hex>` promises), which is a property of the store rather than of
a document, so it is not produced by a mutation either.

**Why not the alternatives.**

* **Lenient reading** (unknown fields ignored, lists sorted on read, a bad date treated as
  absent). Rejected by ADR-0001 D8's arithmetic: leniency is how a policy stops being
  enforced without anybody deciding to stop enforcing it, and it makes `body_digest` a
  function of the reader.
* **A per-crate idiom** (`.4` returns a verdict struct, `.5` returns a hook decline
  string, `.2` a `Result<_, Error>` with free-text messages). Rejected by C5 and by the
  vectors' existence: four implementations of one rule set that agree on the *decision*
  but not on the *reason* are indistinguishable in CI and maddening in a bug report. The
  token is the interface.
* **A new exit code** for "no policy" or "unsigned". Rejected: 6 already means "refused,
  and understood", and a new code breaks every existing gate script for information that
  belongs in `token`. (`no_policy_published`, D4, is a token at exit 6 for exactly this
  reason.)
* **Ordering by cheapness.** Rejected: the cheap checks happen to be first anyway (bytes
  before crypto), but the order is *because* of what a reader should believe first, not
  because of cycles, and saying "sort by cost" would invite a reordering that changes
  which error a user sees.

**Consequences.** One `validate(document, roots, history, now)` in `.2`, called by
everyone, and a table that is a test rather than a paragraph. The generator is the
executable specification: `python3 generate.py --selftest` proves all 32 refusals, the
normalisations, the walk and the fork rules against the vectors, and the Rust test `.2`
owes is to reproduce the same 32 tokens from `policies/*.json` alone.

---

## D10 — Limits, versioning, and how we change our minds

**Decision.**

| limit | value | why |
|-------|-------|-----|
| `MAX_POLICY_BYTES` | 32 KiB | ADR-0001's 1 MiB is a *document* ceiling; a policy is fetched by every clone and read by a human, so the tighter bound is the honest one. The biggest fixture is 1638 bytes; a policy that needs more was writing prose into `annotations` |
| annotations | ≤ 16 entries, `x_<producer>_<name>`, ≤ 512 bytes each | ADR-0001 D5's hatch, with the same containment: an extension can never be richer than a typed field |
| `protects` | ≤ 32 globs, ≤ 128 bytes each | a pre-receive hook evaluates these per push |
| `by_job` | ≤ 64 globs, ≤ 128 bytes each | a matrix with more arms than that is more than one repository |
| `owner.principal` | ≤ 128 bytes | it is printed, and it is not a free-text body |
| sandboxes / image digests | ≤ 32 each | ADR-0001 D7's list discipline |
| chain walk | ≤ 64 links | bounds D6's work for a volunteer (a store with more history is a store that should have squashed a release train, and says so) |
| signatures | exactly 1 | D2 |

Versioning follows ADR-0001 D8 and needs no new machinery: the document self-describes
inside the signed payload (`type: "gitiup-policy-1"`, `schema_version: 1`), v1 is
additive-only, unknown fields are refused (which *is* the negotiation), readers accept a
set of types while producers write one, and the canonicaliser, the PAE framing and the
key-id derivation are never changed in place. `unknown_schema` (6) is the refusal that
makes a future `gitiup-policy-2` safe today: a v1 reader cannot mistake it for a v1
document.

**There is no migration**, which is worth stating because this ADR changes bytes that do
not exist yet: nothing has ever been published, so `giti-91m.2` writes the first ones and
every chain starts at revision 1 with the zero `previous_digest`. The one compatibility
promise is to the tree file: `PolicyFile`'s current shape is unchanged, and `gitiup verify
attestation --policy` behaves as it does today, including `$GITIUP_POLICY` discovery and
`--trust`.

**How we change our minds.** (1) Amend this ADR's numbered decision or supersede it, and
name what is invalidated. (2) A new rule *vocabulary* is a `schema_version` bump and a new
fixture directory; `fixtures/policy-v1/` stays forever, because old published policies
must keep verifying in old stores. (3) A new *field* is allowed only if a v1 reader
refusing it is the right behaviour — otherwise it is also a bump. (4) Changing the
canonicaliser, the payload type string, or the key-id derivation is not a version bump; it
is a different format that would silently invalidate every digest in existence, and the
shared vectors exist to make that hard to do by accident. (5) Emergency invalidation of a
bad policy (a leaked owner key) is operational: ADR-0002 D9 revocation plus publishing a
new revision that supersedes it — never deleting history, which D6 forbids.

---

## Worked example

[`fixtures/policy-v1/`](fixtures/policy-v1/) is this example:
[`generate.py`](fixtures/policy-v1/generate.py) is a stdlib-only Python that is the
executable copy of D2, D3, D5, D6 and D9 — importing the canonicaliser, the PAE framing,
the Ed25519 code and the fixture keys from [`change-v1/generate.py`](fixtures/change-v1/generate.py)
rather than copying them, because ADR-0003 D11 says there is one canonicaliser and a
second one in a fixture directory is exactly the failure that rule exists to prevent.
Its `--check` mode fails if the committed vectors and this document ever drift apart.

Three identities, derived the documented way from the shared fixture labels:
**Ada** `SHA256:kxdEn5…iB0` (the owner), **Sofia** `SHA256:3cEf…lOU` (a fork's owner),
**ci-runner** `SHA256:kHe5…+aQ` (the key that signs proofs). The verifier's trust roots
are `{Ada}` and the clock is pinned to 2026-10-25T12:00:00Z, because D6 refuses a
future-dated policy and a regeneration must not depend on when it ran.

| case | rev | signed by | `protects` | tiers demanded | `body_digest` | `record_digest` | filed under |
| `personal` | 1 | `SHA256:kxdEn…LiB0` | `refs/heads/**` | `local` | `sha256:8f2a80159…39ce3` | `sha256:959698749…5c7fe` | ``kv/policy/9596987498bd…75c7fe`` + ``refs/gitiup/policy/current`` |
| `project` | 1 | `SHA256:kxdEn…LiB0` | `refs/heads/**` · `refs/heads/stable/**` | `quorum` | `sha256:c1406ed56…78ecb` | `sha256:f80a3d214…a8e19` | ``kv/policy/f80a3d214cb4…ea8e19`` + ``refs/gitiup/policy/current`` |
| `project-tightened` | 2 | `SHA256:kxdEn…LiB0` | `refs/heads/**` | `quorum` | `sha256:33b304ccf…87b80` | `sha256:911a34a38…552a0` | ``kv/policy/911a34a38a78…e552a0`` + ``refs/gitiup/policy/current`` |
| `fork-inherited` | 1 | `SHA256:kxdEn…LiB0` | `refs/heads/**` · `refs/heads/stable/**` | `quorum` | `sha256:c1406ed56…78ecb` | `sha256:f80a3d214…a8e19` | ``kv/policy/f80a3d214cb4…ea8e19`` + ``refs/gitiup/policy/current`` |
| `fork-weakened` | 1 | `SHA256:3cEfX…ulOU` | `refs/heads/**` · `refs/heads/stable/**` | `local` + `quorum` | `sha256:97edf3584…816b5` | `sha256:2e3cbcaa4…01775` | ``kv/policy/2e3cbcaa4af8…f01775`` + ``refs/gitiup/policy/current`` |

Read it against the decisions:

* **`personal`** (924 bytes) is the smallest useful policy and the cleanest illustration
  of D3's two questions: Ada signs the *rules*, and the *proofs* must come from the CI
  runner key (`trust_key_ids`), a key this machine does not hold — hence its warning. A
  reader that conflated "who signed the policy" with "who may sign a proof" could not
  express this repository at all. Tier `local`, one named runner, amd64, `major`
  environment match, 24 h.
* **`project`** (1638 bytes) makes the tier data (C4): `allowed_tiers: ["quorum"]` plus a
  `quorum` block that is `SelectionPolicy` verbatim — 5 seats, 4 agreeing, an
  `endorsed` floor, tier caps `{trusted: 1, endorsed: 4, anonymous: 1}` — and a
  `requirements` block that says what a verifier must *be able to do* (`x86_64`, 8 GiB,
  50 GiB, `docker`/`podman` at rung 2 or above, that image digest). `allowed_sandboxes`
  is `{docker, podman}` and `requirements.sandboxes` is the same pair: the coherence rule
  of D5's `sandbox_disjoint` row, satisfied rather than asserted.
* **`project-tightened`** (1606 bytes) is revision 2, and its `previous_digest` is
  `project`'s `body_digest` — the chain, one link, attributable. The bar moved from 4 of
  5 to 5 of 7, `min_sandbox_level` from 2 to 3, and the freshness window halved to 6 h.
  Note what did *not* change: `protects` narrowed from two globs to one, which D6 permits
  because a new document may say anything the old one did — the old one still exists, and
  is what runs before 2026-10-20 are judged by.
* **`fork-inherited`** is `project`, byte for byte: the same `body_digest`
  (`sha256:c1406ed5…`) and the same `record_digest`, because it is the same document. This
  is D1's claim about forks made checkable — a fork inherits the policy by inheriting the
  bytes, and nothing weakens.
* **`fork-weakened`** (1030 bytes) is the same repository re-signing a weaker policy with
  Sofia's own key: tier `local` allowed, 7-day freshness, a 1-of-1 anonymous quorum.
  Everything about it is well-formed, the signature is real, and a verifier whose roots are
  upstream's refuses it — `signer_untrusted`, exit 6. Not distrusted-and-used, not used
  with a warning: refused. That single row is D3's decision made executable, and it is
  checked twice (`--selftest`, and `--verify`, which re-derives it from the committed
  bytes).

The history walk, pinned in [`cases.json:history`](fixtures/policy-v1/cases.json):

| run at | chain | in force | verdict of the walk |
|--------|-------|----------|---------------------|
| 2026-10-01 − 1 µs | `project` → `project-tightened` | — | **refused**: `policy_history_missing` (nothing had taken effect) |
| 2026-10-07 | `project` → `project-tightened` | `project`, revision 1 | 4 of 5, 12 h window — the rules that existed then |
| 2026-10-25 12:03:20 | `project` → `project-tightened` | `project-tightened`, revision 2 | 5 of 7, 6 h window |

and the publish-time normalisations, pinned in `cases.json:normalisations`:

| tree file says | signed document says | why |
|----------------|----------------------|-----|
| `"allow_simulated": true` | `"allowed_tiers": ["local","simulated"]` | one spelling per fact, and the signed document names its tiers once |
| `"allow_simulated": false` | `"allowed_tiers": ["local"]` | `false` is the default, so the shorthand disappears entirely |
| `["quorum","local"]`, `["podman","docker"]` | `["local","quorum"]`, `["docker","podman"]` | order is normalised away, so equivalent rules are one byte string (D2) and a re-publish that changed nothing cannot move a cited digest (D6) |

`generate.py`'s four modes are the contract: default prints the table and rewrites the
vectors, `--check` fails if the committed vectors are stale, `--verify` re-derives every
committed record from its own bytes (including the refusal of `fork-weakened`), and
`--selftest` exercises the primitives, all 32 refusals and the walk. Every signature was
cross-checked against OpenSSL 3.5.5 rather than only against the Python that wrote it.
What does **not** exist yet is the Rust test that reproduces all of it from
`policies/*.json` alone — digests, tokens, walk, normalisations — and `giti-91m.2` owns it
(see the fixture README); until it lands these vectors are a strong suggestion with real
signatures, which is more than prose and less than a rule.

---

## Threats, and which decision closes each one

| # | threat | closed by |
|---|--------|-----------|
| T1 | A fork edits `gitiup-policy.json` to something weak and a clone obeys it | D1 (the tree file is a draft, never gate-eligible over a published record) + D4 (sources 3–4 are local-only) |
| T2 | A fork publishes a weak policy signed with its own key | D3 — `signer_untrusted`, exit 6, proven in `fork-weakened` |
| T3 | An unsigned policy is applied with a warning nobody reads | D3 step 1 (`unsigned`, 6) + D4 (no gate-eligible default) — the silent failure is explicitly forbidden, not merely discouraged |
| T4 | The party producing proofs chooses the rules it is judged by | D3's two-questions table; `trust_key_ids` is checked against proofs and never against the policy carrying it |
| T5 | A verdict cannot say which rules it applied, so a gate is undebuggable | D4's provenance block (`source`, both digests, `revision`, `signed_by`, `at_us`) + `ChangeRecord::policy_digest` |
| T6 | Today's rules retroactively refuse last week's correct run — or last week's rules quietly pass today's change | D6's chain and walk, `policy_history_missing` rather than a fallback |
| T7 | A producer signs a claim dated in a looser era to dodge a policy change | D6: the walk is bounded by `max_age_us` + skew, which is *why* the freshness window is a policy field; D8 warns on a window over a week |
| T8 | Two owners publish simultaneously and one policy vanishes | D7's CAS move of `current` + D8's `previous_digest` check against what `current` advertises |
| T9 | A policy that can never be satisfied is published, and jobs fail mysteriously | D5's table at publish time and at selection: `required_agree_unreachable`, `requirements_unsatisfiable`, `sandbox_floor`, `sandbox_disjoint`, `env_match_off`, `tier_not_allowed` |
| T10 | A policy gates `refs/changes/**` or the policy ref, and the store becomes unwritable to contributors (or self-locking) | D1 + D5's `protects_out_of_scope` |
| T11 | A re-publish that changed nothing moves the digest a verdict cited, so history looks rewritten | D2's normalisation + `body_digest` excluding signatures + D8's `--dry-run` printing it first |
| T12 | Bytes are edited after signing, or a `key_id` is typed rather than derived | D9 step 2 — `bad_signature` (7), `key_id_derivation` (7), `not_canonical` (8) |
| T13 | A reader "helpfully" re-canonicalises or re-sorts, so digests stop meaning anything | D2 (`not_normalised` is a refusal) + D9 step 1 (bytes are their own canonical form or exit 8) |
| T14 | The store's policy history is pruned and old merges become unauditable | D6 + D7's retention invariant (history refs are never pruned) |
| T15 | Four tickets implement four slightly different "the policy", and CI disagrees with the hook | D9's named tokens and one order, with 32 refusals as *generated* vectors |

**What a published policy does not prove.** It proves the owner said these rules in
advance, in this many words, on this date. It does not prove the rules are *good*, that
the owner's key is intact (that is ADR-0002 D9's revocation), that the store has not
withheld a newer revision (transparency-log anchoring of `current` is ADR-0001 D9's
optional layer, and a `policy show` that fetched a stale ref is a stale answer — stated
here so `.6` does not overpromise), or that a verifier that claims to have applied the
policy did. The last one is why `.4` prints the policy it used: the defence is that the
verdict is reproducible by anyone who can `git fetch`, not that anyone believes the box
that ran it.

---

## Consequences

**Unblocked, with nothing left to decide.** `.2` has the document (twelve members, one
canonical form, one signature), the digests, the validator order and the full refusal
table, the storage keys and refs with their write order, the resolve ladder with its four
sources, and publish's four behaviours including the lost-update guard — plus a generated
vector set to test against. `.3` has the provenance block to print, the tokens to
explain, and D9's order as the order `explain` reports rules in (ADR-0001 D7's "the first
line is the reason"). `.4` has the walk (`at_us` in, revision out), the citation rule
(`policy_digest` is the body digest), `no_policy_published`, and the fact that
`min_signatures` and `allowed_tiers` come from the document rather than from a flag. `.5`
has its asymmetry stated as a format rule rather than as a hook policy, the resolve
ladder minus the overrides, and the rule it can print in `--help`: an unsigned policy is
not a policy. `giti-zp1.2` has `quorum.default` and `quorum.by_job` as `SelectionPolicy`
verbatim and `quorum.requirements` as `Requirements` verbatim, so opening a round is a
copy, not a translation. `giti-91m.6` has a document whose every claim is executed by
either `generate.py` or a Rust test, and the two things it must not overpromise (T15's
last paragraph).

**Costs.** Four ref-and-blob writes per publish, and history is forever: a repository that
re-signs its rules weekly accrues 52 small immutable blobs and refs a year, which is
nothing in bytes and something in listings — so `.2` must list `policy/history/**`
without paging the world. Chain validation is mandatory, so a reader that fetched `current`
and nothing else must fetch history or refuse `chain_broken`; that is one more round trip
on a bucket host, and it is the price of C6. `rules` being `PolicyFile` verbatim means two
fields must now be refused at publish although the parser accepts them (D5's bindings
note), which is a small, deliberate wart. The refusal table is 32 rows that `.2`, `.3`,
`.4` and `.5` must all reproduce — the price of a shared vocabulary, and cheaper than four
private ones. And D3 forbids a genuinely convenient thing: pointing `gitiup policy show`
at some repository you do not trust and asking "what do *they* demand?", which would be a
policy read without trust roots and is exactly the mistake the section refuses. `.3` can
offer it as an explicitly-labelled `--insecure` display of unverified bytes if anyone
ever needs it; nothing may act on the result.

**Explicitly out of scope, decided elsewhere.** Who is trusted (the trust roots are local
config, ADR-0002 D4 and the epic's "deliberately not here"); revocation and its effect on
a policy published by a dead key (ADR-0002 D9); the quorum protocol that consumes
`quorum.*` (ADR-0002, `giti-msi.*`); *how* a hook refuses (`.5`); the
`gitiup verify change` verdict's attestation rules beyond what the policy names (`.4`);
which attestations satisfy a policy for a change with ten of them (`.4`, bounded by
`min_signatures` and `allowed_tiers` here); transparency-log anchoring of `current`
(ADR-0001 D9, optional and additive); policy retention and `gc` (forbidden from pruning
history, D6/D7, and otherwise uninteresting); the human workflow of proposing a policy
change (a tree-file edit plus `policy publish`, `.6`'s worked example); and multi-owner
policies, which are a roster question, not a signature-count question (D2).

**References.** Vectors and generator:
[`docs/adr/fixtures/policy-v1/`](fixtures/policy-v1/) — its README is the index of what
each vector and each check is for. Implementation lands next:
[`crates/gitiup-attest`](../../crates/gitiup-attest/README.md) (`PolicyDocument` beside
`policy.rs`, which already owns `Policy`, `PolicyFile` and `Trust`),
[`crates/gitiup-host`](../../crates/gitiup-host/README.md) (the `kv/policy` + refs
plumbing, beside `attest.rs`), the CLI in [`crates/gitiup`](../../crates/gitiup/README.md)
(`policy publish|show|check|explain`, `verify change`). Existing code this leans on:
[`PolicyFile`](../../crates/gitiup-attest/src/policy.rs),
[`Trust`](../../crates/gitiup-attest/src/policy.rs),
[`SelectionPolicy`](../../crates/gitiup-quorum/src/select.rs),
[`Requirements`](../../crates/gitiup-quorum/src/capability.rs),
[`record::body_bytes`](../../crates/gitiup-quorum/src/record.rs),
[`Namespace::POLICY`](../../crates/gitiup-host/src/blob.rs),
[`ChangeRecord::policy_digest`](../../crates/gitiup-host/src/change.rs),
[`ErrorKind::exit_code`](../../crates/gitiup-canon/src/error.rs), and the owner-trust
resolver in [`gitiup/src/participant.rs`](../../crates/gitiup/src/participant.rs).
Upstream decisions: [ADR-0001](0001-attestation-encoding-hash-and-signature.md),
[ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md),
[ADR-0003](0003-change-record-format-and-merge-semantics.md),
[host abstraction](../host-abstraction.md). ADR index: [`docs/adr/README.md`](README.md).

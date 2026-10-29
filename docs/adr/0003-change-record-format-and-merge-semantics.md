# ADR-0003 — The change record: bytes, identity, states and what a merge is

* **Status**: accepted
* **Decides**: the wire format of a gitiup change (fields, canonical order, limits), how a change is identified, how a force-push is recorded, what the states *open / merged / abandoned* are made of on a store with no database, what a merge is and how it is attested, and what a forge adapter may not promise
* **Ticket**: `giti-b2z.1` (parent epic `giti-b2z`, *contribute without a forge — the change is a ref*)
* **Blocks**: `giti-b2z.2` (`ChangeRecord` in `gitiup-host`: canonical bytes, refs, CAS publish), `giti-b2z.3` (`gitiup change new|submit|list|show`), `giti-b2z.4` (`gitiup change merge`), `giti-b2z.5` (`gitiup change checkout`), `giti-b2z.6` (change-workflow conformance), `giti-b2z.7` (GitHub parity), `giti-91m.4` (`gitiup verify change`), `giti-zp1.2` (submit opens quorum rounds)
* **Depends on**: [ADR-0001](0001-attestation-encoding-hash-and-signature.md) — canonical JSON (D1), `sha256:` digests (D2), Ed25519 + SSH key ids + PAE (D3), integer microseconds (D6), limits and the exit-code taxonomy (D7), versioning discipline (D8); [ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md) — signed-record framing (`record::body_bytes`), hex slots in ref names (D10), revocation semantics (D9)
* **Reference vectors**: [`fixtures/change-v1/`](fixtures/change-v1/) — `generate.py` is a stdlib-only implementation of D2–D5, and `records/*.json` + `cases.json` are the golden bytes every Rust reader must reproduce
* **Not implemented yet**: this is a decision document. The code lands in `giti-b2z.2/.3/.4`; the vectors exist so those tickets can be wrong loudly rather than differ quietly.

> Every later ticket in the epic codes against a format, which is why the format is
> decided here and not invented four times. A change is the object a stranger
> publishes when there is no forge: not a pull request, not a patch email, but a
> signed record in a content-addressed store, advertised by a ref, whose merge is a
> compare-and-swap a bucket can honour. If its bytes are not exactly specified, then
> "the same change" means a different thing to the submitter, the reviewer, the
> merger and the verifier — and the disagreement is only visible after someone has
> merged it.

---

## Context

The epic's promise is that a stranger can contribute to a repository whose owner has
an S3 bucket or a bare repo, and that a reviewer can check the contribution and its
proofs without the forge. That needs one new object, and only one: the change record.
Everything a forge does around a pull request (comments, review, labels, the merge
button) is either dropped as a product decision or pushed up into owner-side policy;
what cannot be dropped is the record itself, because it is the thing a signature
covers.

The constraints any answer has to satisfy:

| # | constraint | who forces it |
|---|------------|---------------|
| C1 | A reviewer must be able to fetch the proposal *and the bytes of the record that describes it* in one `git fetch`, on a git-backed store, with no second protocol. | `giti-b2z.5`, [host abstraction](../host-abstraction.md) ("`git fetch` carries proof") |
| C2 | A record must be immutable once published, because a merge gate and a quorum verdict are made against its digest; "immutable" has to mean something on a store that is refs plus CAS blobs and has no database, no transactions and no triggers. | `.2`, `.4`, `giti-91m.4` |
| C3 | A force-push of the same change is the normal case, not an edge case: the new attempt must not overwrite the old one, and the old attestations and verdicts must stay fetchable and still mean what they meant. | `.2`, `.3`, `giti-msi.*`, ADR-0001 D4 |
| C4 | A merge must be a compare-and-swap the weakest supported host can honour (an S3 conditional write, a `--force-with-lease`), and must not silently drop commits. | `.4`, `giti-xdw.3` |
| C5 | The ref names must be legal, boring and hostile-free on every host: git ref rules, S3 key rules, and a `Prefix` whose digest segment is hex-only all apply at once. | `.2`, `giti-xdw.1/.2`, ADR-0002 D10 |
| C6 | A merge must be explainable afterwards from the store alone: *what* was merged, from *where*, on *what proof*, by *whom* — with no log server and no reflog. | `.4`, ADR-0001 D6 ("the trusted moment the merge record has to supply") |
| C7 | The same verbs and exit codes must work against `fs`, plain git, a bucket and a forge, so a script does not branch on the transport. | `.6` conformance, [host abstraction](../host-abstraction.md) |
| C8 | A forge adapter must be able to say what it cannot do. A pull request cannot carry a signature, a microsecond timestamp or a 256-bit digest, and an adapter that quietly reconstructs them produces records that look valid and are not. | `.7` |
| C9 | Nothing in the record may be unverifiable filler that a forge rewrites: the record is what a signature protects, so a field that cannot survive a round trip through the thing being routed around belongs in the adapter, not in the format. | `.7`, ADR-0001 D5 |

Two things were **not** in tension and are worth saying so. Size is not a
constraint: a change record is a kilobyte, stored once per attempt in a store that
deduplicates and compresses. And strong identity is not a constraint either: the
signature and digest machinery already exists (ADR-0001) and this document merely
uses it. The choices below were made on *immutability without a database*, on the
weakest host's capabilities, and on how much a reviewer has to fetch and believe.

## Decision at a glance

| id | question | decision | rejected |
|----|----------|----------|----------|
| D1 | the record | one Gitiup Canonical JSON document, signed in place: `signatures` is a member, the signed body is the record with its signature fields removed, DSSE PAE framing, payload type `application/vnd.gitiup.change+json` | ADR-0001's separate envelope, the forge `ChangeRecord` as-is (ticket's own alternative), a CBOR or TOML record, "canonicalise then base64 into a container commit" |
| D2 | fields and their order | a closed set of thirteen members — `annotations`, `attempts`, `author`, `base`, `change_id`, `created_at_us`, `head`, `origin`, `schema_version`, `signatures`, `title`, `type`, `workflow` — whose canonical (sorted) order is also the reading order, with named limits and no `null`s | the forge record's optional soup (`url`, `labels`, `draft`, `head_repo`, a free-text body), a mutable `state` field, open-ended extension |
| D3 | `change_id` | content-derived and stable across re-pushes: `chg-` + 16 hex of `SHA256(domain ‖ key_id ‖ base.ref ‖ anchor)`, where the anchor is attempt 0's head; a ref-safe, bucket-safe, 20-character name that any reader re-derives from the record itself | forge PR numbers, a store-assigned sequence, deriving from `head` (unstable), the key id or a full digest in the ref name, human slugs |
| D4 | digests | two, with different jobs: `change_digest` over the signed body (what a merge record, a verdict and `attempts.previous` cite) and `record_digest` over the whole stored bytes (the `kv/change/<hex>` key) | one digest doing both jobs, "hash the file", storing the record under its `change_digest` |
| D5 | refs and keys | `refs/changes/<id>/head`, `refs/changes/<id>/attempt/<n>`, `refs/changes/<id>/{merged,abandoned}`, `kv/change/<hex>`, `kv/merge/<hex>`, `kv/abandon/<hex>`; bytes first, then the attempt ref, then `head`; on a git host a record ref is a pointer commit carrying the record and parented to the previous attempt | `refs/changes/<id>` as a leaf (directory/file conflict), Gerrit's `refs/changes/<n>/<p>` (ticket's own alternative), records in commit-message trailers |
| D6 | an attempt | a new record, a new immutable ref (`attempt/<n>`, `Expect::Absent`), and a move of `head` under `Expect::Is`; `attempts.index` plus `attempts.previous` chain the attempts; the next index is one past the highest present, so a crashed submit heals | rewriting the record in place, force-pushing `head` with no per-attempt ref, storing attempts as a growing array inside one document |
| D7 | states | `open`, `merged`, `abandoned` are **derived** from which refs exist; a transition is a new signed record (merge or abandon) plus one create-only ref, never an edit and never a deletion | a `state` field (an edit, hence a new digest), "a ref move with no record", tombstones and deleting the head ref |
| D8 | a merge | a CAS fast-forward of `refs/heads/<base>` from `base.oid` to the attempt's `head`, refused on a stale base and on a non-descendant head, followed by a signed **merge record** naming the attempt, the from/to oids and the proof digests believed | a forge-style merge commit (its tree exists only after the merge, so no attestation can cover it), an unconditional update, merging without a record, "record first, move second" |
| D9 | the workflow hint | `workflow.jobs` is a sorted, deduplicated list of `gitiup run --job` ids the author asks to be re-run: signed, so it cannot be quietly widened or narrowed, and a *hint* — Epic 2's policy decides what is required | policy in the record, free-form "run everything", a side-channel file next to the record |
| D10 | `origin`, and the forge round trip | `origin` is `{kind:"store"}` or `{kind:"pull",number}`; a pull request is an **advertisement** of a record, exactly as a check run is for an attestation, and the adapter must not promise to reconstruct one | making `origin.pull` the record's home, treating a PR body trailer as authoritative, `gh-<n>` as a change id |
| D11 | validation, limits, versioning | one validation order, the ADR-0001 exit codes (2/3/6/7/8), a published limit table, unknown fields refused, `annotations` as the only hatch — and exactly one canonicaliser implementation, shared with `gitiup-attest` | lenient reading, a second canonicaliser in `gitiup-host` (its `config::canonical_json` is *not* one), in-place format changes |

---

## D1 — The record: one canonical JSON document, signed in place

**Decision.** A change record is a single JSON document in
[ADR-0001 D1](0001-attestation-encoding-hash-and-signature.md)'s Gitiup Canonical
JSON — keys sorted ascending, no whitespace, integers only, no `null`, escapes
restricted to `\" \\ \b \t \n \f \r` and lower-case `\u00xx` for the remaining
C0 controls, depth ≤ 32, and a reader that refuses bytes which are not their own
canonical form.

The signature lives *inside* that document:

```text
body_bytes(record)   = canonical(record with `signatures` removed)
signature            = Ed25519( PAE("application/vnd.gitiup.change+json", body_bytes) )
stored_bytes(record) = canonical(record with `signatures`: [entry])
```

which is the rule `gitiup-quorum`'s
[`record::body_bytes`](../../crates/gitiup-quorum/src/record.rs) already applies to
rosters, rounds and verdicts: *"a signature covers `pae(payload_type,
canonical_bytes(record with its own signature fields removed))`"*. There is one
rule for signed gitiup records, not one per document type. Three record types share
it here: `gitiup-change-1` (`application/vnd.gitiup.change+json`), `gitiup-merge-1`
(`…change-merge+json`) and `gitiup-abandon-1` (`…change-abandon+json`).

Because the signatures are outside the signed body, a record can be built and
hashed *before* anyone signs it: `change_digest` (D4) is stable from the moment the
fields exist, so a CLI can print the id it is about to publish, and a co-signature
or a re-encoding of the signature list cannot move it. The stored bytes always
include the signature, so no consumer ever asks "these bytes were signed over
what?" — the bytes on disk are the signed bytes plus the signature list that is
excluded by rule, and `record_digest` covers the whole of them.

**Why not the alternatives.**

* **The forge `ChangeRecord` as-is** (the ticket's own first alternative,
  [`gitiup-host-github::forge::ChangeRecord`](../../crates/gitiup-host-github/src/forge.rs)).
  Rejected, and the ticket is right to name it: it is a *projection of GitHub's API*,
  with twenty-one mostly-`Option`al fields (`url`, `labels`, `draft`, `head_repo`,
  `updated_at`, a free-text `summary`), no canonical form, no digest, no signature,
  and second-precision timestamps. Every `Option` is a question a verifier would have
  to answer "the forge did not tell me", which is not an answer a bucket-forge can
  give. That type stays where it is — the adapter's translation surface — and
  `.7` maps between the two.
* **ADR-0001's envelope** (a `payload_type` + `manifest` + `signatures` document
  wrapping a separate payload). Rejected for changes on arithmetic and on
  reviewability: it is two objects, stored under two keys, with the storage key
  naming one and the identity naming the other, and every read becoming a join. The
  envelope exists in ADR-0001 because a run manifest must be exportable to
  Sigstore-style DSSE tooling and co-signed by a quorum without moving its digest;
  neither need exists here, and where the co-signing need *does* exist (rosters,
  rounds) ADR-0002 chose the same single document as this. DSSE interop remains
  available: the PAE framing is shared, so exporting one is a mechanical transform.
* **Signing the whole document including `signatures`** — impossible (a signature
  cannot contain itself), and the alternative "sign a hash of the record and put the
  signature next to it" is the envelope again with worse ergonomics.
* **CBOR / TOML / protobuf** — same rejections as ADR-0001 D1, and no new argument
  here: a change record is reviewed by a human (`gitiup change show`) and grepped in
  CI logs.
* **Carrying the record in a commit-message trailer** (the ticket's third
  alternative). Rejected, for the reason the ticket gives and one more: a trailer is
  inside a commit, so the record would be signed by whoever wrote the commit message
  and would change on every rebase — the record's identity would be owned by the
  wrong person, and an attempt (D6) would rewrite the record it is supposed to
  preserve. The trailers we *do* accept (`.7` writes one into a PR body) are
  explicitly labelled advice in D10.

**Consequences.** `gitiup-host` gets a `ChangeRecord` type next to
[`src/attest.rs`](../../crates/gitiup-host/src/attest.rs) with
`canonical_bytes()`, `body_bytes()`, `digest()`, `verify()`; the host keeps its
existing discipline of *storing bytes it does not parse* (`attest.rs` never parses an
attestation and this module must not need to either, so a store can hold changes it
cannot interpret), and `gitiup-attest` is not involved at storage time at all except
through the shared canonicaliser (D11).

## D2 — The fields, their order, and their limits

**Decision.** A change record has exactly these members. The order below is the
canonical order — ADR-0001 D1 sorts keys ascending by byte, so the order *is* the
alphabetical order of the names, and the names were chosen so that the sorted order
is the order a person reads a change in: who, where, what, when, why.

| # | field | type | rule |
|---|-------|------|------|
| 1 | `annotations` | map `x_<producer>_<name> → string` | **optional**; the only third-party extension point; ≤ 16 entries, keys lower-case `x_<producer>_<name>`, values ≤ 512 bytes of text with no control characters. Same shape as ADR-0001's `claims.annotations`, for the same reason: an extension must never be richer than a typed field. |
| 2 | `attempts` | `{ anchor, index, previous? }` | `anchor`: the `head` of attempt 0 — an oid, tagged, and the anchor of `change_id` (D3). `index`: `u32`, 0-based. `previous`: `change_digest` of attempt `index − 1`; omitted when `index == 0`, required otherwise. When `index == 0`, `anchor == head`. |
| 3 | `author` | `{ key_id, principal }` | `key_id` is an SSH fingerprint (`SHA256:…`, ADR-0001 D3) and **must equal `signatures[0].key_id`**, which is itself re-derived from the offered public key. `principal` is a display string (1…128 bytes, no control characters, same limits as `Actor`), never used for authorisation. |
| 4 | `base` | `{ ref, oid }` | `ref` must be a `refs/heads/<branch>` (a `RefName::branch`); `oid` is the algorithm-tagged point the author branched from and that a merge must find there (D8). |
| 5 | `change_id` | `"chg-" + 16 lower hex` | required, and re-derivable from fields 3, 4 and 2 (D3). A reader that cannot re-derive it refuses the record; it is a name, not a claim. |
| 6 | `created_at_us` | `i64` | integer microseconds UTC, as in ADR-0001 D6. This is a claim by the author, not a fact about the store, and freshness is policy, not format — but unlike a run manifest this one has no re-run to disagree with, so it lives in the signed body. |
| 7 | `head` | oid | the commit being proposed. A merge is a move *to* this (D8), and every attestation a gate checks is about this. |
| 8 | `origin` | `{ kind: "store" }` \| `{ kind: "pull", number }` | see D10. `number ≥ 1`; a `store` origin carries nothing else. |
| 9 | `schema_version` | `1` | inside the signed body, exactly as ADR-0001 D8 requires. |
| 10 | `signatures` | `[SignatureEntry]`, **length exactly 1** | ADR-0001 D3's entry: `algorithm`, `key_id`, `public_key`, `sig`. One signature, by the author, and a second entry is a refusal rather than a co-author — two people wanting credit is a new attempt with one author, or a follow-up change, not a quiet format fork. |
| 11 | `title` | string, 1…512 bytes | no C0 control characters and no newline (it is one line, in a table, in a terminal, forever), UTF-8 otherwise. Written once; editing a title is a new attempt, because the title is inside the digest. |
| 12 | `type` | `"gitiup-change-1"` | the discriminator, inside the signed body, as `gitiup-roster-1` is for ADR-0002. |
| 13 | `workflow` | `{ jobs: [string] }` | see D9. |

Limits, so a verifier reading a stranger's record can bound its work (ADR-0001 D7's
argument, repeated because it is the same threat): whole canonical record ≤ 32 KiB
(the manifest's 1 MiB is for manifests; a change is a kilobyte and a reader should
notice a megabyte one), ≤ 64 jobs, each job id ≤ 128 bytes, ≤ 64 `previous` links
walked when validating a chain, ≤ 16 annotations.

**Fields deliberately absent, and who asked for them.**

| absent | why |
|--------|-----|
| `state` | A state transition would be an edit, hence a new digest, hence a different record; D7 derives state from refs instead. This is the answer to the ticket's "what is a transition on a store with no database" and the reason `state` is not in the field list at all. |
| `url`, `web_url` | unverifiable, not portable between mirrors, and already derivable from the adapter's own config. A record that carries a hostname is a record that lies after a restore. |
| `labels` | a forge-side free-form database with no semantics gitiup can define; `.7` may print them from the forge, never from the record. |
| `draft` | on a forge "draft" means "the merge button is disabled", which on a store means "the owner does not merge". If a change is not ready, the attempt is not published yet; if a gate needs a ready flag, that is Epic 2's policy, not a field. |
| `summary` / body prose | prose belongs in the commit messages, which are *inside* `head` and therefore inside the digest. A second prose field outside the hash is where a forge round trip would quietly rewrite the description of the thing under review (D10). |
| `head_repo`, fork URLs | a change's head must be fetchable from the store that holds its record (D5); a pointer at someone's fork is an unreadable promise. `.7` mirrors the commits instead. |
| `merged_at`, `merged_by`, `abandoned_*` | they belong to the merge/abandon record (D7), which is the document that asserts them and carries the signature of the person who did it. |

**Why no open-ended extension map beyond `annotations`.** A change record's fields
all decide whether a merge may happen. An unbounded "extras" bag would be a second,
untyped trust surface in the middle of a signed merge decision, and the lesson of
ADR-0001 D7 is that the extension point must be *weaker* than the typed fields,
which a string map is and arbitrary JSON is not.

## D3 — `change_id`: content-derived, stable across re-pushes, ref-safe

**Decision.**

```text
change_id = "chg-" + hex(SHA256( "gitiup-change-1" ‖ 0x00 ‖ author.key_id
                                 ‖ 0x00 ‖ base.ref ‖ 0x00 ‖ attempts.anchor ))[0..16]
```

`‖` is concatenation, the separator is a single `0x00` byte (ADR-0002 D2's
convention, and the reason none of the three inputs may contain a NUL), the fields
are used **exactly as written in the record** (no case folding, no trimming, no
normalisation), and `[0..16]` means the first sixteen characters of the lower-case
hex, i.e. 8 bytes.

The three inputs are exactly the things that identify *a proposal* and that survive
every re-push:

* `author.key_id` — who is proposing;
* `base.ref` — toward which branch (the same work toward `main` and toward `stable`
  is two changes);
* `attempts.anchor` — the head the change *started* at, which is why `attempts`
  carries an anchor at all: `head` changes on every attempt and must never enter the
  id, while the anchor is fixed by attempt 0 and is present in every later record, so
  a reader can re-derive the id from one record without walking the chain.

Derivation is checked by every reader (D11), so a record cannot claim an id that its
own contents contradict.

**Properties, and the failure each one closes.**

| property | why it matters |
|----------|----------------|
| stable across attempts | a reviewer's `gitiup change show chg-6a6a…` and a gate's exclusion list keep working across a force-push; a `head`-derived id would mean a re-push creates "a new change", which is the thing C3 forbids |
| recomputable from one record | no store query, no listing, no state: `gitiup change show` on a fetched record can prove its own name |
| one per (author, base, anchor) | two different topics from the same author to the same branch get different ids because their first commits differ; two attempts of one topic get the same id because their first commit is the same |
| ref-safe and bucket-safe | `chg-` plus 16 lower hex is a legal git ref component (no `~^:?*[`, no `..`, no leading dot, no `.lock`), a legal S3 key segment, and 20 characters: `refs/changes/chg-6a6a8eab778ba4d0/head` |
| human-safe handle | a short handle a human types cannot collide with a change id: the id's grammar is fixed and prefixed (`chg-` + hex), and the forge display form is a *different* grammar (`gh-` + decimal). Commands accept any unambiguous prefix of the hex part (≥ 4 hex, like a short oid) and say so when a prefix is ambiguous, listing the candidates. |

**Why 16 hex and not more.** `change_id` is a *name*, not an integrity claim: the
thing that must be unforgeable is the record digest (D4) and the signature. Eight
bytes make an accidental collision improbable and, under deliberate grinding, they
let an attacker *squatter* a name — so the format makes squatting worthless: a
record must re-derive its own `change_id` from its author and anchor, so a squatting
record can only occupy the name with the squatter's own identity and content
attached, which is visible nonsense rather than an interception, and the real
contributor simply picks a new first commit (a new anchor) and gets a new name. The
author identity cannot be spoofed (D1: `key_id` is re-derived from the key offered).
Widening the id later is additive and cheap; narrowing is not, which is why the
domain string is inside the hash.

**Why not the alternatives.**

* **A forge number** — numbers are per-repository, renumbered by a fork or an import,
  and unavailable on a bucket at all. `.7` keeps `gh-<n>` as a *display* id for
  PR-backed changes and never as a `change_id`.
* **A store-assigned counter** (`1`, `2`, `3`, Gerrit-style) — requires a server that
  owns a sequence, which is precisely what a bucket is not; two concurrent
  contributors would race a counter, and "who is #47" would depend on timing.
* **Deriving from the current `head`** — a force-push would be a new change: old
  attestations, verdicts, and every exclusion list would be orphaned (C3).
* **The key id or a full digest in the ref name** — ADR-0002 D10 already fought this
  one and won: a key id is `SHA256:<base64 with +, / and no padding>`, which is
  illegal or hostile in a ref name and in `Prefix`'s hex-only digest segment.
* **A human slug** (`fix-ref-parser`) — invites the collisions the ticket warns
  about, is not content-derived (two people invent the same slug), and makes rename
  a format problem.
* **A random nonce, kept in the record** — works, and is what a *store-assigned id*
  would degenerate into; it buys nothing over the digest of the fields that already
  identify the proposal, and it makes the id un-re-derivable, so a reader could no
  longer check it.

**Cross-store note.** Two mirrors of the same repository show the same `change_id`
for the same change, and two forks that share history can produce the same
`change_id` for two changes that happen to share author, branch name and first
commit. That is intended and harmless: a `change_id` is unique *within* one store,
like a branch name, and nothing in gitiup compares change ids across stores. If
that ever becomes a requirement the answer is a store identifier in the digest, not
a longer truncation, and it is additive behind the domain string.

## D4 — Two digests, and what each one names

**Decision.**

```text
change_digest  = "sha256:" + hex(SHA256(body_bytes(record)))     # the record's identity
record_digest  = "sha256:" + hex(SHA256(stored_bytes(record)))   # the storage key
```

| digest | covers | cited by | why it is that one |
|--------|--------|----------|--------------------|
| `change_digest` | the record with `signatures` removed | `attempts.previous`, a merge record's `change_digest`, an abandon record's, a quorum round's `change_id`-plus-digest pair (`giti-zp1.2`), `gitiup change show --json` | it is the identity of *the proposal*, so it must not move when a signature is added or re-encoded; this is ADR-0001's `RunDigest` vs `record_digest` split, applied where ADR-0002 already applied it |
| `record_digest` | the exact bytes stored in the CAS | `kv/change/<hex>`, `kv/merge/<hex>`, `kv/abandon/<hex>` | a content-addressed store's key has to be the hash of what is stored, or `put_cas` idempotence and "refuse anything that does not re-hash to the name it is filed under" (`giti-b2z.2`'s acceptance criterion) both become lies |

Both are algorithm-tagged lower-case hex (ADR-0001 D2), and the storage key is the
bare hex body, matching `kv/attestation/<hex>` and every other host namespace.

One naming note, because the fixtures use both words and the difference has bitten
already: for a **change** record, `change_digest` *is* its body digest. A merge or
abandon record also has a body digest (the bytes its signature covers) **and** a
`change_digest` field pointing at the change it is about, so two different values
could otherwise share a name. [`cases.json`](fixtures/change-v1/cases.json) therefore
calls the uniform per-record column `body_digest`, and the field inside a merge record
stays `change_digest`.

**Why not one digest.** Making the storage key the body digest means the object at
`kv/change/X` is not the bytes that hash to `X`, which breaks `put_cas`'s contract
and the host's own rule that a blob is addressed by the hash of its bytes. Making
the cited digest the whole document means every additional signature moves the
identity every other document cites — the exact failure ADR-0001 D3's
`co_signing_keeps_the_run_digest` test exists to prevent. ADR-0001 solved this
already (`RunDigest` vs `record_digest`); the only new thing here is that the change
record has no envelope to hold the signature, which is D1's choice and does not
change the reasoning.

**Where a reader checks them.** `verify()` on the parsed record re-derives
`change_id` (D3) and the signature; the *fetch* path (`.2`'s `change_at`) checks
`record_digest` against the ref's leaf and the ref's promise, and refuses a record
whose head does not match the head the ref was filed under. `.2`'s acceptance
criteria — a record that lies about its digest, and a ref pointing at a record that
names a different head — are exactly these two checks.

## D5 — Refs, storage keys, and the order writes happen in

**Decision.** Names first, because four tickets have to agree on them:

```text
refs/changes/<change_id>/head              the current attempt (moves, under CAS)
refs/changes/<change_id>/attempt/<n>       attempt n: immutable, create-only
refs/changes/<change_id>/merged            the merge record, if merged (create-only)
refs/changes/<change_id>/abandoned         the abandon record, if abandoned (create-only)

kv/change/<record_digest>                  a change record (one object per attempt)
kv/merge/<record_digest>                   a merge record
kv/abandon/<record_digest>                 an abandon record
```

`Namespace::CHANGE` already exists
([`gitiup-host::blob`](../../crates/gitiup-host/src/blob.rs)); `merge` and `abandon`
are two new `Namespace::const_new` entries, added by the ticket that first writes
them (the same discipline ADR-0002 D10 states for `round`, `reveal`, `revocation`,
`signup`, `endorsement`). Ref construction goes through the existing
`RefName::change_head(id)` and `RefName::change(id, extra)`, so ref validation
happens at parse time as it already does.

The gitiup value of a change ref is a **record digest**, not a git oid, which is
what the pointer-commit machinery in the git and GitHub hosts exists for
([`hosts/git/plumb.rs`](../../crates/gitiup-host/src/hosts/git/plumb.rs): a ref holds
a commit, the commit holds `gitiup-ref.json` plus the record bytes). Two requirements
fall out of C1 and are `.2`'s to honour:

1. **A change ref's pointer commit has two parents when `n > 0`: the attempt's own
   head commit, and the pointer commit of attempt `n − 1`.** So
   `git fetch origin 'refs/changes/<id>/*'` brings the proposed commits *and* every
   attempt's record in one packfile, and `git log refs/changes/<id>/head` is the
   attempt history — which is already how the plain-git host describes its own
   record chain ("`git log refs/changes/c1/head` is the history of that change").
2. **`refs/changes/**` stays listable and never internal.** A host hides
   `refs/gitiup/**` from an ordinary listing; changes are the user's data and must
   appear.

**Write order for publishing one attempt** (each step is a CAS write; the host's
`Expect` is the only arbitration mechanism there is):

```text
1. put_pack            the head commit and everything it needs
2. put_cas             kv/change/<record_digest>              (idempotent by content)
3. update_ref_cas      refs/changes/<id>/attempt/<n>  Expect::Absent → record_digest
4. update_ref_cas      refs/changes/<id>/head         Expect::Is(previous) → record_digest
```

Objects before bytes before refs, in that order, because a ref that names bytes the
store cannot return is a broken promise — the same rule
[`attest.rs`](../../crates/gitiup-host/src/attest.rs) states for attestations, and
the reason `migrate` there files bytes before retiring a ref. A crash at any step
leaves an *inert* store: an object nothing advertises, or an attempt ref that `head`
does not name yet, and D6's rule for the next index is written so that the next
submit finishes the job rather than tripping over it.

**Why not the alternatives.**

* **`refs/changes/<id>` as the leaf** (no `/head`) — shorter and tempting, and it
  cannot work: on a filesystem-backed ref store `refs/changes/<id>` is a *file*, so
  the moment anything wants `refs/changes/<id>/attempt/0` the two collide (a
  directory/file conflict is a hard failure, not a fallback). `attest.rs` learned the
  same lesson the hard way with single-level attestation refs and the
  leaf-or-directory problem; the shape is the same here and the fix is the same.
* **Gerrit's `refs/changes/<n>/<p>`** (the ticket's second alternative). Rejected for
  the reason the ticket gives: patchset numbering there is owned by a server's
  database, and a bucket has no server to own a sequence. Note how much of Gerrit's
  shape this decision *does* take, because it is worth being precise: an
  immutable ref per attempt (`attempt/<n>` ≈ Gerrit's `<p>`) and a movable current
  one. What is not taken is the server-assigned numbering — ours is content-derived
  (D3) and coordinated by CAS (D6), which is the difference between a patchset number
  and a name.
* **One ref per change, no attempt refs** — then a force-push overwrites the only
  advertisement of the previous attempt, and its attestations become unreachable
  evidence (C3). Retention cannot help: `attest.rs` deliberately never prunes what a
  live ref points at, and here the ref would have moved.
* **`kv/changes/<hex>`** (plural) — the existing namespaces are singular
  (`attestation`, `roster`, `job`, `policy`), and ADR-0002 D10 already settled this
  argument for `kv/job`, not `kv/jobs`.
* **Records under `refs/gitiup/**`** — that namespace is reserved for a host's own
  bookkeeping and is hidden from listings; a change is a user's contribution and a
  stranger must be able to `git fetch` it.

## D6 — An attempt: how a force-push is recorded

**Decision.** A force-push of a change is a **new record**, at a new attempt index,
which names the record it supersedes. The fields are `attempts.index` (0-based),
`attempts.anchor` (attempt 0's head, unchanged for the life of the change) and
`attempts.previous` (the `change_digest` of attempt `index − 1`).

Publishing attempt `n` follows D5's order, and the two CAS steps are what make
concurrency safe without a lock, a queue or a server:

| step | if it conflicts |
|------|-----------------|
| `refs/changes/<id>/attempt/<n>` with `Expect::Absent` | the same author published the same attempt: if the existing value is the same digest it is an idempotent success, otherwise it is a **refusal**, exit 6, "attempt *n* already exists with a different head" — never an overwrite |
| `refs/changes/<id>/head` with `Expect::Is(what we just read)` | someone moved the change in between: re-read and retry at a higher index, or report the conflict with both digests |

**How the next index is chosen, which is the whole race story.** Not from `head`:
the next index is **one past the highest `refs/changes/<id>/attempt/*` present**, and
`attempts.previous` is that highest attempt's `change_digest`. A crashed submit that
created `attempt/3` but never moved `head` is therefore not a corrupted store — the
next submit takes index 4 with `previous` naming the orphan, and the chain is
continuous. Had the rule been "read `head`, add one", that same crash would leave
the next submit colliding with an attempt ref it does not know about, and the store
would need an operator.

Rules that follow:

* **The chain is validated when it is read, not when it is written.** Walking
  `previous` from any attempt must reach an `index == 0` record whose `anchor`
  equals its `head`, within ≤ 64 links (D2's limit). A gap is a refusal naming the
  missing digest: it means an attempt ref is gone, and "the history is shorter than
  it claims" is exactly the kind of thing a merge gate must not paper over.
* **`head` always points at the highest attempt**, and `gitiup change show` reads
  `head`; `gitiup change history` lists `attempt/*` and prints each record's digest,
  head oid, author and time. That is `change_history` in `.2`, and on a git host it
  agrees with `git log refs/changes/<id>/head` for the same reason (D5).
* **Old attempts stay advertised.** Their attestations, verdicts and quorum rounds
  cite `change_digest`s that remain fetchable, and `attest.rs`'s rule that a live
  ref's target is never pruned keeps working per attempt rather than per change.
  Closing a change does not delete its attempts (D7).
* **An attempt is not a patchset.** Nothing in gitiup asks a server to store a diff
  against a base: an attempt is an oid, and the diff is whatever the reviewer
  computes from `base.oid` to `head`. That is why an attempt costs one ref and one
  record, not a server feature.

**Why not the alternatives.** *Rewriting the record in place* — the new bytes have a
new `record_digest` and, if the head moved, a new `change_digest`, so the old record
is not updated but abandoned anyway, and every document citing it now names
something no ref advertises. *Force-pushing `head` with no attempt ref* — loses the
history that the C3 constraint exists to protect, and a force is the one write no
host can make conditional. *Keeping an array of attempts inside one growing
document* — an O(n²) total store, a new digest per attempt per every earlier
attempt's bytes, and a reader that must hold the whole history to check the last
entry; the chain of digests gives the same auditability at constant size per attempt.

## D7 — States: open, merged, abandoned — and what a transition *is*

**Decision.** The three states are **derived from which refs exist**, in this
precedence order, and are computed by listing `refs/changes/**` once:

| state | when |
|-------|------|
| `merged` | `refs/changes/<id>/merged` exists |
| `abandoned` | `refs/changes/<id>/abandoned` exists |
| `open` | neither exists |

plus one **flag, not a state**: `unrecorded: true` when `merged` does not exist but
`refs/heads/<base>` currently equals the `head` of one of the change's attempts
(that is: the fact happened and its record did not land; see D8's failure window).
A change whose base moved without being merged is still `open`, with `stale: true`
when `refs/heads/<base>` no longer equals the record's `base.oid`; staleness is a
property of an attempt, not a state, because it is cured by a new attempt.

A **state transition is a new signed record plus one create-only ref.** Two record
types, same framing as the change record (D1), same limits (D2), one signature each:

```text
gitiup-merge-1                    { schema_version, type, change_id, change_digest,
  attempt, base: { ref, from, to }, merged_at_us, via, proofs: [digest],
  policy_digest?, author, signatures }

gitiup-abandon-1                  { schema_version, type, change_id, change_digest,
  attempt, abandoned_at_us, reason, note?, author, signatures }
```

* `change_digest` is the `change_digest` of the attempt the record is *about* —
  a merge record names an attempt, never "the change", so a late-arriving
  attestation about an older attempt can be judged against the merge that
  happened.
* `base.ref/from/to` is the ref move, spelled as the CAS that it was.
* `via` is `"store"` (gitiup moved the ref, D8) or `"forge"` (a forge moved it and
  `.7` wrote this record afterwards).
* `proofs` is a list of attestation **record digests**, in the order believed, and
  may be empty; a merge that believed nothing says nothing, rather than appearing to
  have believed everything (D8).
* `policy_digest` is reserved for Epic 2 (published policy); absent means no policy
  was applied, and `.4`'s `--proof-required` refusal keeps that honest.
* `reason` is `superseded`, `withdrawn`, `rejected` or `stale` — the first two are
  the author's to write, the last two the owner's, and a reader treats the author's
  own key as the only authority for `withdrawn`/`superseded` (the same rule as
  ADR-0002 D9: a key can always revoke its own).

`author` in these records means *whoever signed this record* — the merger, the
abandoner — not the change's author.

**Why this and not the alternatives the ticket names.**

* **A `state` field, edited in place.** The ticket asks "a new record, a new ref, or
  a tombstone?" and this is the answer to why *not* an edit: on a CAS store there is
  no edit, only a new object, and a new object has a new digest. So "editing the
  state" is exactly the same work as writing a new record **plus** a broken promise:
  every attestation, verdict and exclusion list that cited the old `change_digest`
  now names a record that no ref advertises, and "was this change open when this
  attestation was signed?" becomes unanswerable. ADR-0001 D8's rule — history is
  never rewritten — is the same rule from the other side.
* **A ref move with no record.** Cheapest possible, and it fails C6: the store would
  advertise a fact ("merged") with no signed bytes behind it, so *who* merged, on
  *what proof* and *when* become reflog questions, and reflogs do not travel
  (`gitiup change merge` would be un-auditable from a clone, which is the epic's
  acceptance criterion).
* **A tombstone / deleting `refs/changes/<id>/head`.** Three losses. A deletion is
  the least CAS-able write there is (the host has `delete_ref_cas`, but "absent" is
  not a state a reviewer can distinguish from "never existed", and gc retires refs
  for reasons unrelated to a change's life). It destroys the reviewer's ability to
  fetch the proposal at all, so "why is this commit here?" — the question C6 exists
  for — becomes unanswerable exactly at the moment it is most asked. And on a bucket
  with versioning, nothing is ever really deleted anyway, so the tombstone would be
  a *lie with extra steps*.
* **A separate "state" document per change, mutated by appending.** That is what the
  attempt chain and the two state records *are*; a general per-change ledger
  document would need a per-change CAS chain and would duplicate what the refs
  already index. The store's refs are the index and the records are the facts, which
  is the same split `attest.rs` uses for `kv/gc/` (a record of a retention run, at a
  ref the operator chooses).

**Who may write what.** `refs/changes/**` is a contributor namespace: creating an
attempt is `Expect::Absent` and needs no privilege beyond being allowed to push it,
and the *signature* is what identifies the author. `refs/heads/**` is the owner's:
the store's own credentials and hooks decide whether a merge's CAS is permitted, and
`.4` passes that refusal through unedited (its acceptance criterion). `merged` and
`abandoned` are create-only, so a change can be merged exactly once and abandoned
exactly once, and a second attempt at either is a conflict rather than a surprise.
Un-merging does not exist: a revert is a new change.

## D8 — What a merge is

**Decision.** A merge is a **compare-and-swap fast-forward of a branch**, followed by
a signed record of it. In order, with the refusal and its exit code at each step:

| # | step | refusal |
|---|------|---------|
| 1 | resolve the change: read `refs/changes/<id>/head`, fetch the record, check `record_digest` against the ref's promise, verify the signature and re-derive `change_id` | 8 (digest), 7 (signature), 6 (invalid) |
| 2 | read `refs/heads/<base>` **fresh** (this read is the lease) | 6 if the branch does not exist, naming it |
| 3 | compare that oid against the record's `base.oid` and refuse if they differ | 6, naming **both** oids, hint "pull first, or submit a new attempt rebased onto *oid*" |
| 4 | check the merge is a fast-forward: `base.oid` is an ancestor of `head`, computed locally on the objects the caller already has | 6 with hint "rebase the change or merge the base into it, then re-submit"; **refuse if the objects needed for the test are not present** rather than guessing |
| 5 | apply policy if configured (`.4`'s `--proof-required` refuses with a pointer to the policy engine, Epic 2) | 6 |
| 6 | `update_ref_cas(refs/heads/<base>, Expect::Is(base.oid) → head)` | `HostError::Conflict` → 6 with both oids; a permission refusal from the store passes through **unedited** |
| 7 | write the merge record: `put_cas(kv/merge/<hex>)`, then `Expect::Absent` on `refs/changes/<id>/merged` | a failure here is reported as a named, incomplete state with the exact retry (below) |
| 8 | print what happened, and print only the plan when `--dry-run` (which touches nothing, as `attest gc --dry-run` does) | — |

**A merge is a ref move, not a merge commit.** The head commit is what every
attestation, verdict and review is about; a forge-style merge commit exists only
after the merge, so no proof can cover its tree, and a gate that "verified the merge"
would be verifying a commit nobody ran. Fast-forward-only also keeps C4 honest: the
CAS says nobody moved the branch, and the ancestry test says nobody's work is
dropped, which together are the whole safety property a bucket can offer. Where a
host has no CAS at all (`capabilities.cas = false`) the write is refused with
`UnsupportedCas`, exactly as the host abstraction already promises: a bucket without
conditional writes cannot host an owner-side merge.

**The failure window, stated plainly.** Step 6 is the fact and step 7 is its record,
in that order deliberately: a crash between them leaves a branch that moved without a
merge record, and that is a *detectable* silence (the derived `unrecorded` flag in
D7: the base tip equals an attempt head and no `merged` ref exists). The reverse
order would leave a signed record claiming a merge that did not happen — a false
statement by an honest key, which is worse than a missing one and cannot be detected
from the store at all. `.4` therefore reports the incomplete state and prints the
exact retry command rather than pretending step 7 is atomic with step 6, and
`gitiup change reconcile` (in `.4`'s scope) closes it by writing the record for the
move the store already has.

**How the merge is attested.** The merge record *is* the attestation of the merge:
signed by the key whose credential moved the branch (ADR-0001 D3 identity, PAE
framing, payload type `…change-merge+json`), naming the attempt, the from/to oids,
the time, and the proof digests it believed.

* `proofs` holds **digests**, never copies. This is the github adapter's standing rule
  for check runs ("a check run is an advertisement, not the attestation",
  [`forge.rs`](../../crates/gitiup-host-github/src/forge.rs)): a copy can be truncated,
  re-encoded or edited, and then the merge record would be evidence about a document
  nobody signed.
* Because they are digests, every element must be handed to
  [`attest::pin`](../../crates/gitiup-host/src/attest.rs) or retention can retire
  evidence a merge cited — `attest.rs` names this exact gap ("a merge record's
  attestation field… a string in a document is a claim about that document, not an
  advertisement of an object"), so `.4` closing it is a requirement, not a nicety.
* The merge record is **not** filed under `refs/attestations/**`. Tempting (it is a
  claim about a commit, and that namespace means "fetch everything proven about this
  object in one go"), and rejected: that namespace answers "what has been *run and
  proven* about this object", and a merge is a claim about a *ref move*, made by an
  owner, not a run. Mixing them would make `gitiup attest list` a lie, which is the
  same honesty rule that makes it report `unexpected_refs` rather than dropping a
  ref it cannot attribute.
* This record is ADR-0001 D6's "trusted moment": *at merge time these keys were
  trusted, these attestations were fresh, and this policy digest applied*. That is
  what a short-lived attestation finally buys, and what a year-old archive cannot
  claim without the log anchor of ADR-0001 D9.
* `via: "forge"` covers `.7`: when a human presses GitHub's merge button, gitiup
  did not make the move, so the record is written afterwards by whoever runs
  `gitiup change reconcile`/`.7`, says `via: forge`, and attests only what the forge
  reports. `list` must be able to print "merged, no gitiup merge record" for a merge
  nobody reconciled, and must not invent a record for it.

**Why not the alternatives.** *A non-fast-forward CAS update* (write `head` over
`base` whatever the history) — the CAS guarantees "nobody moved the branch" and
nothing more, so a change whose author never rebased would silently delete other
people's commits; a force-push behind a friendly flag is the one thing C4 exists to
forbid. *An unconditional update* (`Expect::Any`) — the host abstraction already bans
it for anything that gates a merge: a lost update there is a lost merge. *Recording
the merge in the commit message of a merge commit* — puts the audit trail inside a
commit whose author is whoever ran the merge, un-signed by gitiup's identity model,
and un-findable from the change without a search. *Merging into a staging branch
instead* — a fine owner-side workflow, orthogonal to this: it is what a CAS merge
into `refs/heads/try` looks like, and it needs no format change.

## D9 — The workflow hint

**Decision.** `workflow.jobs` is a sorted, deduplicated list (≤ 64, each ≤ 128 bytes,
printable ASCII, no whitespace) of job ids in the vocabulary `gitiup run --job <id>`
already uses: the `jobs.<id>` key of a `gitiup.toml` workflow. A job with a matrix is
named by its job id, and expands to one quorum round per arm, which is how
ADR-0002 D7's "one job per arch" happens without a special case here.

The hint says: *which jobs a verifier must re-run for this change*. It is signed, so
nobody downstream can widen or narrow it without producing a new attempt, and it is a
**hint**, which means exactly one thing mechanically:

| who | relationship to the hint |
|-----|--------------------------|
| the contributor | chooses it, and can only ask for jobs their `gitiup.toml` defines |
| the runner / quorum (`giti-zp1.2`) | opens one round per named job (per matrix arm), and runs nothing the hint does not name unless policy names it |
| the merge gate (`giti-91m.4`) | requires at least the named jobs, and *more* if Epic 2's policy demands it; it may never require fewer |
| Epic 2's policy | the only thing that can *compel*, and it lives in the store's policy documents, not in the record |

An empty `jobs: []` is legal and means "no re-run requested" — which is *not* "run
everything" and *not* "nothing is required" if policy says otherwise; `gitiup change
show` prints it as `(none requested)` so a reviewer never reads silence as approval.

**Why not the alternatives.** *Policy in the record* — the record is authored by the
person being checked; a contributor who can write "no checks needed" into the object
being merged has written their own gate. *Free text like `"run all"`* — cannot be
checked, cannot be diffed between attempts, and would make every workflow rename a
format change. *A side file in the repo* (`.gitiup/required.json`) — real, and it can
co-exist as an Epic 2 input, but it is unsigned-by-the-change and therefore cannot be
what the gate is *proving* about this attempt. *A richer hint with per-job images and
resource requirements* — that is `EnvRequirement` and the quorum round's required
capabilities (ADR-0002 D7), which are derived from the job by the runner, not chosen
by the contributor; putting them in the change record would let a contributor
under-declare what their own build needs.

## D10 — `origin`, and the forge round-trip budget

**Decision.** `origin` is the discriminated union the adapter already uses, with one
name changed:

```text
{"kind": "store"}                  the store is the only place this change exists
{"kind": "pull", "number": N}      a pull request carries it, and the forge's merge is the merge
```

The adapter's existing `ChangeOrigin::Ref{name}` becomes `store`, because the name
was describing the ref and the distinction that matters is whether a *forge* is in
the loop: on a forge every change is also a ref, so "it is a ref" carries no
information, while "there is a pull request, and its merge button is the merge"
changes what `.7` must do (D8's `via: "forge"`, and PR-backed merges go through the
adapter's `open_change` machinery rather than a CAS write). No repository or hostname
field: the record lives *in* the store the pull request belongs to, and a claim about
a host name is a claim a verifier cannot check and a restore breaks.

**What a pull request can carry, and what the adapter must therefore not promise.**
The rule is the adapter's own, extended: a pull request is to a change what a check
run is to an attestation — an **advertisement** with a copy that fits, not the object.

| field | on a pull request | so the adapter must not… |
|-------|-------------------|---------------------------|
| the record bytes | nowhere to put them; a PR is a database row and a text body | promise to reconstruct a record from a PR; `.7` publishes the record to the store *and* opens the PR, and reads the record back from the store |
| `author.key_id`, the signature | a PR author is an account, not a key | treat a PR opened by a human in the web UI as a change record. It is a change *observation*: `list` prints it with `origin: Pull`, `record: absent`, unsigned, and `gitiup change merge` refuses it — there is no base oid and no signature to check, so `.7` either adopts it into a record (a gitiup principal runs `change submit --pr N`, which signs) or leaves it as an observation |
| `attempts.previous`, `change_digest` | no field for a digest; force-push destroys the forge's own view of the history (`pushed_versions` is not a stable contract) | promise that a PR's history survives a force-push: `.7` writes each attempt itself, as D6's refs |
| `created_at_us` | the forge gives second precision | pretend microsecond resolution: when a record is minted from a PR, `created_at_us = created_at × 10⁶`, and `origin.pull` tells a reader the resolution is the forge's |
| `workflow.jobs` | no field | promise a verifier sees it from the PR: the PR body may *repeat* it as text, the store record is the source |
| `title` | limited to 256 characters and markdown-mangled by the UI | truncate silently at submit: a title over the forge's limit is a **refusal** naming both limits (our 512 is larger on purpose, for a store with no UI) |
| `base.oid` | the PR reports the base branch's *current* tip, which moves | read it as the author's pinned base: it is the author's `base.oid` that a merge CASes against, and the PR's `base.sha` is a fact about the forge's clock |
| `head` | may live in a fork, unreachable from the store | promise the head is fetchable: D5 requires the store to hold the head objects, so `.7` mirrors the fork's commits into a store ref or refuses to treat the PR as reviewable content |
| merged state | a human can press the button at any time | promise a merge was attested: `.7` reconciles, marks `via: "forge"`, and prints "merged with no gitiup merge record" when nobody did |
| `change_id` | can only appear in the body text, which the author can edit | treat the trailer as authoritative. `.7` writes `gitiup-change: chg-…` into the PR body as a *pointer*; a reader that finds a trailer disagreeing with the store reports the disagreement and believes the store |

**Why not the alternatives.** *Making `origin.pull` the record's home* (storing the
record in the PR body as base64) — it works, and it is the option to reach for if a
deployment must not write refs at all. Rejected because the record would then be
editable by the PR author, invisible to `list` without an API call per change,
invisible to `git fetch` (C1), and outside the CAS discipline that makes an attempt
immutable. *Two unions* (one for the adapter, one for the record) — the adapter's
`ChangeOrigin` and this one must be the same type or `.7` becomes a translation layer
that can say things the store cannot.

## D11 — Validation, limits, versioning, and who owns the canonicaliser

**Decision.** Validation runs in a fixed order, because the first thing wrong decides
the verdict and the exit code a script branches on (the codes
[`gitiup_attest::ErrorKind::exit_code`](../../crates/gitiup-attest/src/error.rs)
already defines, shared by `gitiup verify`, `run` and now `change`):

```text
1. canonical form and size          → 8 not canonical, 6 unknown schema/type/field
2. digests                          → 8 record_digest/change_digest do not match
3. derivations                      → 8 change_id does not re-derive; 7 key_id is not
                                        the fingerprint of the key offered
4. signature (self-consistency)     → 7
5. semantic bindings                → 6 base is not a branch, jobs unsorted, anchor ≠
                                        head at index 0, broken attempt chain
6. store bindings                   → 6 ref points at a record naming a different head;
                                        stale base; non-fast-forward; a create-only ref
                                        already taken (conflict)
```

| exit | meaning (unchanged from ADR-0001 D7 and `gitiup --help`) |
|------|----------------------------------------------------------|
| 0 | accepted |
| 2 | usage |
| 3 | I/O, and a store refusal the tool does not own |
| 6 | refused: bad record, unknown version, stale base, non-fast-forward, policy |
| 7 | a signature that does not verify |
| 8 | digest mismatch, or bytes that are not canonical |

The refusal table is `.2`/`.3`/`.4`'s test list as written: a record whose bytes lie
about their digest (8), a ref pointing at a record naming a different head (6), a
huge record (6), a stale base (6, naming both oids), a duplicate attempt (6), an
unparseable `change_id` (6), a record signed by a key other than its author (7), and
a `type` of `gitiup-change-2` (6, "this build does not speak it").

**Versioning**, exactly ADR-0001 D8's discipline, because the same argument applies
byte for byte: `schema_version` and `type` are inside the signed body; v1 is
additive-only and a v1 reader *refuses* an unknown field rather than ignoring it
(loud, not lenient), so a field everyone must understand is a new `type`; the
canonical encoding itself is not versioned — changing it changes every `change_id`,
`change_digest` and `record_digest` in existence and is therefore a new format, not
a new field; `fixtures/change-v1/` is never edited, a new version gets
`fixtures/change-v2/`, and old buckets keep verifying. Migration in place is not
offered: there is nothing to migrate, because the record does not mutate and a store
that holds a v1 change simply keeps advertising it.

**One canonicaliser.** The rules are ADR-0001 D1's, and so is the code:
`gitiup_attest::canon` (with its strict reader `require_canonical`, which is what
proves bytes are canonical rather than assuming it). `gitiup-host` must use it and
must not grow its own — and note the trap already in the tree:
[`gitiup_host::config::canonical_json`](../../crates/gitiup-host/src/config.rs) is
`serde_json::to_vec` and is **not** a canonicaliser (it preserves map order), so it
stays exactly where it is, for config files. `.2` therefore extracts `canon` into a
leaf crate (say `gitiup-canon`, dependencies: `serde`, `serde_json`) with
`gitiup_attest::canon` kept as a re-export so nothing else changes. Rejected:
re-implementing canonicalisation in `gitiup-host` (two canonicalisers is two digests,
which is the exact failure ADR-0001 D1 exists to prevent), and making `gitiup-host`
depend on `gitiup-attest` (the attestation crate is a wire format with crypto and a
policy engine in it, and a storage layer has no business depending on that — the
dependency direction that makes the `no_forge_deps` rule in that crate keep making
sense).

---

## Worked example

[`fixtures/change-v1/`](fixtures/change-v1/) is this example, generated by
[`generate.py`](fixtures/change-v1/generate.py) — a stdlib-only Python that is the
executable copy of D2–D5 and whose `--check` mode fails if the committed vectors and
this document ever drift apart.

ada (key `SHA256:kxdEn5…iB0`) proposes against `refs/heads/main` at
`sha1:5f3e0d0b…0e1f`; the first attempt's head is `sha1:a1b2c3d4…5678`:

| case | kind | attempt | `change_id` | `body_digest` | `record_digest` | filed under |
|------|------|---------|-------------|-----------------|-----------------|-------------|
| `open-first` | change | 0 | `chg-6a6a8eab778ba4d0` | `sha256:2ff898d0…998766` | `sha256:f9220067…97fb7f` | `kv/change/f9220067…` + `refs/changes/chg-6a6a8eab778ba4d0/attempt/0` + `…/head` |
| `open-second` | change | 1 | `chg-6a6a8eab778ba4d0` | `sha256:eee197bf…5a5799` | `sha256:ec90da2c…dbf7cf` | `kv/change/ec90da2c…` + `…/attempt/1` + `…/head` |
| `merged` | merge | — | `chg-6a6a8eab778ba4d0` | `sha256:66f42a17…06ee99` | `sha256:0f1657b5…dccce9` | `kv/merge/0f1657b5…` + `…/merged` |
| `pull-backed` | change | 0 | `chg-28b29e411598b74f` | `sha256:fc7f8e2c…936691` | `sha256:5894d702…984896` | `kv/change/5894d702…` + `refs/changes/chg-28b29e411598b74f/{attempt/0,head}` |
| `abandoned` | abandon | — | `chg-28b29e411598b74f` | `sha256:556482ab…596038` | `sha256:8ba46dee…4537ea` | `kv/abandon/8ba46dee…` + `…/abandoned` |
| `wide` | change | 0 | `chg-2946aea92e12c8d7` | `sha256:802b0d9a…581f18` | `sha256:1da10612…f71e42` | `kv/change/1da10612…` + `refs/changes/chg-2946aea92e12c8d7/{attempt/0,head}` |

Read it against the decisions:

* **`open-first` → `open-second` is a force-push**, and the `change_id` is identical
  while `head`, `attempts.index`, `attempts.previous`, `created_at_us` and both
  digests all change (D3's stability claim, made checkable). `open-second`'s
  `attempts.anchor` is `open-first`'s head, and its `attempts.previous` is
  `open-first`'s `change_digest`, so the chain is walkable from either end without
  listing refs (D6).
* **`merged` names an attempt, not a change**: its `change_digest` field is
  `open-second`'s body digest, its `base` is `from → to` with `to` equal to
  `open-second`'s
  `head`, and its `proofs` are two opaque attestation digests the merge believed
  (D8). A reader can prove the merge matches the attempt it claims, and prove that a
  merge claiming `open-first` would be a different document.
* **`pull-backed`** carries `origin.pull` with `number: 428`, a title with typographic
  quotes that must survive canonical UTF-8 untouched, and one
  `x_gitiup_host_github_pr` annotation — the sanctioned hatch, and the only place a
  producer other than gitiup may put anything (D2).
* **`abandoned`** closes `pull-backed` by its author, with a `reason`, and leaves
  every ref of that change in place (D7).
* **`wide`** carries `"`, `\`, `é` and eight jobs, so a reader that assumes short
  titles, no escapes, or fewer than two jobs is wrong loudly (D2's limits, ADR-0001
  D1's escape set).

`generate.py --selftest` cross-checks the primitives against something other than
itself: RFC 8032 sanity properties plus a two-way OpenSSL round trip for the
signatures, and the canonicaliser against ordering, escape and refusal vectors. The
fixture bytes were also checked against the real Rust code as they were written: the
canonical bytes match `gitiup_attest::canon::to_value_bytes` exactly, the key ids
match `PublicKey::key_id`'s SSH-fingerprint derivation, and every signature verifies
under `SignatureEntry::verify` (which uses `verify_strict`) over the PAE bytes —
against the record and *not* against a tampered one.

---

## Consequences

**Unblocked, with nothing left to decide.** `.2` has the bytes (`ChangeRecord` with
`canonical_bytes`/`body_bytes`/`digest`/`verify`), the ref and `kv` helpers, the
pointer-commit requirements, and the write order; `.3` has the submit sequence, the
stale-base refusal (D8 step 3), the attempt rule ("a re-submit is a new attempt and
never overwrites") and the author-is-the-signature rule; `.4` has the merge as eight
steps including the ancestry test, the record it writes, `--dry-run`, the
pass-through of store refusals, and `--proof-required`'s refusal; `.5` has the ref
prefix that makes "fetch the change and its proofs in one go" a single fetch; `.6`
has one conformance contract to run against MinIO and `git-http-backend`; `.7` has
the exact budget of what a PR cannot carry, and the `via: "forge"` reconciliation
shape; `giti-91m.4` has the digests it must check and the hint semantics it may
require; `giti-zp1.2` has `change_id`, `change_digest` and `workflow.jobs` as its
round inputs, matching ADR-0002's round record field-for-field.

**Costs.** Three ref writes and one blob write per publish, and two ref writes plus a
record per merge: a little chattier than a forge API call, on hosts whose CAS is
already the arbiter (and batchable with `update_refs_cas` where a host is atomic). A
`change list` needs the `refs/changes/**` listing rather than one call, so a store
with thousands of open changes pays a linear listing (retention of *closed* changes
is a real, unsolved question named below). Two digests per record has to be
explained once per reader, and the explanation is one sentence: the one that never
moves, and the one the store is keyed by. The attempt rule ("one past the highest
attempt present") means a store can hold an attempt that `head` never advertised,
which is intentional and must be printed as such rather than hidden. And the
canonicaliser extraction is a small, one-time structural change to `gitiup-attest`'s
public surface that every ADR-0001 consumer could theoretically notice — mitigated by
keeping `gitiup_attest::canon` as a re-export.

**Explicitly out of scope, decided elsewhere.** Whether a merge is *allowed* (Epic 2's
policy documents; this record reserves `policy_digest` and nothing more), quorum
verdicts over a change (ADR-0002, `giti-msi.7`, `giti-zp1.2`), the pointer-commit
implementation details per host (`giti-b2z.2`), retention of closed changes and
their attempt refs (`attest gc`'s sibling, which must keep D6's immutability promise
intact), review comments and any UI (the epic says no), the merge-gate's attestation
rules (`giti-91m.4`, bounded by D9's hint), and revocation's effect on a change whose
author's key died (ADR-0002 D9's matrix applies unchanged: a `compromised` key voids
the claims made with it, and D8's merge record is the trusted moment that makes the
judgement checkable).

**References.** Vectors and generator:
[`docs/adr/fixtures/change-v1/`](fixtures/change-v1/). Implementation landing here
next: [`crates/gitiup-host`](../../crates/gitiup-host/README.md) (`ChangeRecord`
beside `attest.rs`), with the CLI in [`crates/gitiup`](../../crates/gitiup/README.md).
Upstream decisions: [ADR-0001](0001-attestation-encoding-hash-and-signature.md)
(canonical bytes, digests, keys, exit codes, versioning),
[ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md) (signed-record
framing, hex in ref names, revocation),
[host abstraction](../host-abstraction.md) (CAS, namespaces, pointer commits).
ADR index: [`docs/adr/README.md`](README.md).

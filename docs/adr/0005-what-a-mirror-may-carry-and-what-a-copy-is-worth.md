# ADR-0005 — What a mirror may carry, and what a copy is worth

* **Status**: accepted
* **Decides**: which namespaces a copy may carry and which may never leave the store that made them, what a copied attestation is *worth* to a reader who did not witness it, how a stale-from-mirror proof is marked and what freshness a mirror may not attest to, which direction a copy may travel, what happens to a ref name when a store already holds the bytes, and the retention rules that stop one store's `gc` from destroying another store's only copy — all of it decided **before the transport exists**
* **Ticket**: `giti-g5c.1` (parent epic `giti-g5c`, *federation — proofs and changes travel between repositories*)
* **Blocks**: `giti-g5c.2` (`gitiup fetch|push`: D1, D2, D6, D7, D8), `giti-g5c.3` (`gitiup attest import`: D3, D4, D9, D10), `giti-g5c.4` (`gitiup migrate repo`: D1, D6, D7), `giti-g5c.5` (anonymous read and credential scoping: D1's privacy row, D6's write direction); and it grows [ADR-0004](0004-published-policy-format-signing-and-resolution.md)'s field set by one optional member (`provenance`, D5), which `giti-91m`'s `.3`/`.4` readers have to accept before a mirror is useful
* **Depends on**: [ADR-0001](0001-attestation-encoding-hash-and-signature.md) — canonical bytes and the digest that names them (D1, D2), the signature framing that makes byte identity load-bearing (D3), *freshness is policy, not a property of the document* (D6 — the whole of D5 below rests on it), the verification order and the exit-code taxonomy (D7), the volatile-field register as the template for "as of now" (D5), limits (D7); [ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md) — signed-record framing, roster epochs and the anti-rollback guard (D8), revocation voiding at verdict time (D9), `refs/gitiup/**` + hex slots as the record layout (D10), "the store's CAS *is* the arbitration" (D10, and the reason a copy cannot arbitrate); [ADR-0003](0003-change-record-format-and-merge-semantics.md) — the content-derived `chg-` id a copy re-derives identically (D3), two digests with different jobs (D4), refs and bytes-first write order (D5), attempts as create-only refs (D6), states derived from which refs exist (D7), a merge as a CAS fast-forward that cannot happen anywhere but the base's owner (D8); [ADR-0004](0004-published-policy-format-signing-and-resolution.md) — trust roots are local config and never travel in the document (C3, D3 below), the policy chain and `policy_history_missing` (D6), `policy/current` + `policy/history/**` (D7), "unknown fields refused" as the fail-closed reading rule (D10 below), the `protects` asymmetry that keeps `refs/attestations/**` and `refs/gitiup/**` open (C8); [host abstraction](../host-abstraction.md) — the CAS contract, bytes-then-ref publication, `referenced`-is-not-a-knob retention, `purge_cas` as the only honest forgetting, dumb HTTP as a legitimate read-only mirror, and `refs/gitiup/kv` as a per-store commit chain
* **Reference vectors**: [`fixtures/federation-v1/`](fixtures/federation-v1/) — `generate.py` is a stdlib-only second implementation of the portability table (D1, D2) and the closure walk (D9); `portable.json` is the namespace table with a token for every `no`, `cases.json` is the closure cases and the refusal table. `--check-ad` fails if this document's tables and the generated data disagree
* **Implemented by**: **nothing yet — deliberately.** The ticket's whole point is that the rules are written before the transport, so this row is a promise, not a report: `giti-g5c.2` lands D1/D2/D6/D7/D8 as `gitiup fetch|push`, `giti-g5c.3` lands D3/D4/D9/D10 as `gitiup attest import`, and D5's `provenance` member lands in `giti-91m`'s policy readers. What is *already* true of the code today is a real subset and it is worth naming, because those are the invariants this ADR extends rather than invents: `attest::publish` writes bytes before it writes the ref and is create-only, `attest::referenced` makes a live ref an un-prunable pin, `put_cas` refuses bytes that do not hash to the name they are filed under, `store::same_ref` refuses a record filed under the wrong ref, `gc` separates `plan` from `apply` and writes a `kv/gc/` record for what it decided, and the plain-git host already treats a dumb HTTP endpoint as a read-only mirror. What does not exist: `fetch`, `push`, `attest import`, `kv/import/`, the `provenance` policy member, and any refusal token named below that no code prints yet — see each decision's *status* line.

> A copy is the easiest feature in this product to build: the bytes are signed, the
> names are content-derived, and git already moves packs for a living. That is exactly
> why it has to be decided before it is written. A `for` loop over `list_prefix` and a
> `put_cas` per object is a *working* implementation of federation, and it launders
> trust in about twenty lines: the moment a proof arrives from a store somebody decided
> to believe, "fetched from a store I trust" is one careless `if` away from "signed by a
> key I trust". Nothing about that failure throws. The merge gate passes, the attestation
> verifies, and the only thing that changed is that the set of stores able to make a
> change look verified grew by every host on the internet.
>
> So this document separates three words the implementation wants to fuse. **Bytes**
> travel; a mirror is good for exactly that and nothing more. **Trust** is a relation
> between a signing key and the policy that accepts it, and it is computed from local
> config in the reader — never from where the bytes came from. **Authority** — which
> epoch is live, which attempt is current, who holds a seat, whether a proof is fresh —
> is a fact about one store's live refs and does not survive being copied at all.

---

## Context

Every store in gitiup is already a place proofs can be read from: `fs`, a bucket, a bare
repository, a forge adapter that translates a pull-request database into the same
[`ChangeRecord`](../../crates/gitiup-host/src/change.rs). None of them is a place proofs
can *move* between. `gitiup verify` resolves exactly one store,
[`attest::publish`](../../crates/gitiup-host/src/attest.rs) writes into exactly one, and
the epic's reason for existing is that this makes every project's signed evidence
dependent on one location somebody else may stop maintaining.

The constraints any answer has to satisfy:

| # | constraint | who forces it |
|---|------------|---------------|
| C1 | A proof must survive its origin going offline, being deleted, or being taken over by someone the project no longer trusts. That is the epic, almost verbatim: without portability, "not tied to GitHub" means "tied to one bucket someone else owns". | epic acceptance criterion |
| C2 | Trust is a property of a signing key and the accepting policy, **never** of a transport. The reader's trust list is an argument the caller supplies ([`Trust`](../../crates/gitiup-attest/src/policy.rs)), and no store is an argument. | ticket rationale, ADR-0001 D7, ADR-0004 D3 |
| C3 | Every check a reader owes must be answerable from bytes in hand. Neither selection (ADR-0002 C1) nor the trust path (ADR-0001 C2) may put a live call in it, and a mirror is precisely the case where the origin may not answer. | ADR-0001 C2, ADR-0002 C1 |
| C4 | Byte identity is load-bearing three times over: a signature covers exact bytes (ADR-0001 D1/D3), `kv/attestation/<hex>` names SHA-256 of those bytes, and `refs/attestations/<subject>/<hex>` repeats that hex as the ref leaf. Any re-encode, re-hash or re-sign on the way through a mirror destroys all three at once, and destroys them silently. | ADR-0001 D2, [host abstraction](../host-abstraction.md) "Attestations in the store" |
| C5 | Some records mean *"as of now"* — a lease with a TTL, a sign-up awaiting approval, the ref that says which roster epoch is live. A copy of one is false the moment it is made, and a copy is worse than an omission: an omission is a gap, a copy is a live-looking claim. | ticket's first bullet, ADR-0001 D5's volatile register (the same instinct, one level up) |
| C6 | Arbitration is the store's compare-and-swap, not the record's — which is why a store outage *pauses* verification instead of degrading it into guessing. A copy of a round record must not acquire the ability to arbitrate that round. | ADR-0002 D10, [`quorum::store`](../../crates/gitiup-quorum/src/store.rs) |
| C7 | A mirror may be dumb, read-only, unauthenticated and run by a stranger. A static file server with `git update-server-info` is already a legitimate release mirror today, and federation must not require a mirror to have an account anywhere. | [host abstraction](../host-abstraction.md) (dumb HTTP), `giti-g5c.5` |
| C8 | A mirror holds no key. Nothing on the mirror's side of a copy may require a signature from it — including any "this mirror vouches for this batch" wrapper, which is what laundering looks like if you get it wrong. | C2 + C7 |
| C9 | Retention is real and is not going away: `gitiup attest gc` retires advertisements by age and per-subject quota, and a bucket that keeps every proof forever is a bucket somebody eventually deletes wholesale. A rule that makes garbage collection impossible is a rule that gets switched off, and then the store loses everything. | [host abstraction](../host-abstraction.md) "Retention", `attest::gc` |
| C10 | Every rule here holds on `fs`, `git`, `s3` and the forge adapter without a `match` on the transport, and every refusal is a named token on the existing exit codes (6/7/8), not a new class. | the `giti-xdw` conformance culture, ADR-0001 D7 |
| C11 | A store's `refs/gitiup/**` is not public by accident. It names keys and per-seat slots, which is why a volunteer polls one bounded prefix ([`refs/gitiup/job`](../../crates/gitiup-quorum/src/job.rs)) instead of listing the namespace. "Mirror this store" must not silently mean "publish its key list and its volunteer roster". | `store::open_rounds` ("Finding work"), `giti-g5c.5` |

Two things were **not** in tension, and saying so keeps them out of the argument. *Crypto*
is not a constraint: this document adds no key type, no algorithm and no new signed
document — a mirror signs nothing (C8), so all of ADR-0001's machinery is used unchanged
and merely applied twice. *Size* is not a constraint either: the closure of one quorum
attestation is a dozen small records in a store that already deduplicates, and the budget
in D10 is a refusal bound against a hostile store, not a performance measure. The choices
below are all about **scope** (what may travel), **provenance** (what a reader may believe
about where bytes came from) and **authority** (which store gets to decide what is now, and
what is left).

## Decision at a glance

| id | question | decision | rejected |
|----|----------|----------|----------|
| D1 | what may be copied | the portable set is the **verification closure** of what a store serves: `refs/attestations/**`, `refs/changes/**` (attempt, merge and abandon records), the quorum records a proof leans on (`round`, `verdict`, `commit`, `reveal`, `roster/<epoch>`, `revocation`, `withdrawal`), and the policy revision plus its `previous_digest` chain. Portable means *record and advertisement together*, never one without the other | "copy the whole repository" (imports arbitration state and key listings — C5, C11), "copy only `refs/attestations/**`" (a verdict without its round is a rumour, which is `.3`'s own refusal), "whatever the transport can move" (letting the transport decide scope is the failure this ticket exists to prevent) |
| D2 | what may never be copied | **arbitration state and anything whose meaning is *"as of now"***: leases, job advertisements, sign-ups awaiting approval, every *current-pointer* (`refs/gitiup/roster`, `refs/gitiup/policy/current`, `refs/changes/<id>/head`), this store's own `kv/import/**` and `kv/gc/**`, its ref cache, its tombstones, its `refs/gitiup/kv` commit chain, and its trust roots | "copy everything and flag it", "copy `head` and fix it up later" (a pointer is a store's live state, not data), "sync `current` both ways" (D6) |
| D3 | what a copy is worth | **bytes, and nothing else.** A fetch moves a signature; it cannot move a trust decision. There is no `--trust-remote`, no `trusted` flag on a fetch or import report, no capability bit for it, and `Trust` is built only from the reader's own roots — an imported document is checked with the same code and the same list as one the store produced itself | "fetched from a mirror I trust ⇒ this proof is good" (the laundering the ticket names), per-store TOFU key pinning (it pins a *store*, which is precisely the thing that must not carry trust), a mirror's own signature over a batch of copied records (C8 — and if the mirror had such a key, that key *is* the laundering channel) |
| D4 | what is re-checked on arrival | the entire ADR-0001 D7 order, again, in this store: re-hash, canonical form, bindings, signatures, tier, freshness — plus `same_ref` and revocation against the epoch the record was signed under. Nothing is waived because it came from a mirror and nothing is waived because it is a duplicate. The one thing deliberately not re-checked is *freshness as the origin last saw it*, because a mirror cannot carry that fact (D5) | trusting the origin's verdict (the ticket's first rejected alternative), "file it and let readers check" (the ticket's second: a store that quietly serves broken bytes teaches every client to stop checking), "verify once and mark the blob as verified" (a mark on a CAS blob is a trust decision stored in the one place that must be trust-free) |
| D5 | freshness, and how a stale copy is marked | age is computed **only** from the document's own `claimed_at_us` and never from arrival, so a mirror cannot make a proof fresher — the only way it can make one *look* fresher is a reader that measures from arrival, which no gitiup code path may do. Staleness is marked in the **reading** (a `provenance` block in every verify/change report, with `age_basis` as a field) and in the local `kv/import/<digest>` record, never in the artifact. A policy may demand provenance through one new optional member: `provenance.require_origin_seen` and `provenance.mirrors` | stamping a `stale`/`expired` field into the record (needs either a re-hash or a mirror signature — both disqualifying), "mark it and let a human decide", measuring age from `fetched_at_us` (freshness laundering: every proof is fresh the instant it arrives), and refusing to mirror at all (C1) |
| D6 | direction, and what a mirror may not do | one-way: **an origin pushes to a mirror; a mirror never pushes back**, and a mirror never accepts a new claim into a copied round — no reveals, no commitments, no verdict, no lease, no sign-up. Copying a round record does not transfer arbitration (C6) | bidirectional sync (it turns "fetched from a mirror" into "filed at the origin": the same laundering pointed the other way, and it makes a stranger's mirror a merge authority), "a mirror may compute and serve its own verdicts" (it holds no seats and no roster authority) |
| D7 | republish, ref names, and identity | **the same digest, always** — CAS is why: a copy is byte-identical or it is a different attestation. Ref names are derived from content, so a name collision *is* a content match and the answer is `already` (create-only, never `-2`, never an overwrite). Pointer refs move under `Expect::Is` only, and a non-fast-forward is a **report** (`diverged`), never a mirror's decision. A legacy single-level ref is re-spelled on import and never re-created. A record's identity is its digest, never the commit oid of the `refs/gitiup/kv` chain carrying it: **a mirror builds its own chain** | re-canonicalising to this store's idioms (breaks signature, blob name and ref leaf at once — C4), "re-sign on import" (a mirror has no key, C8), resolving a diverged head for the importer, copying the kv commit chain ref-for-ref (imports one store's private topology as if it were a fact) |
| D8 | GC, and the only copy | three rules. (1) **Advertisement ⊆ possession**: a store never advertises a ref whose bytes it cannot itself serve, and never advertises less than it did before; bytes first, then the ref. (2) **Retention authority follows write authority**: age- and quota-based pruning is decided from `claimed_at_us`, which is identical on every copy — so every store's `--max-age` fires at the same instant and *correlated* pruning, not a greedy mirror, is the real "last copy" hazard. A mirror therefore evicts for **capacity**, only among digests it can name a re-fetch source for, and `--max-age` against a store that cannot write the namespace it is pruning is refused. (3) **A `kv/gc/` record is evidence, never an instruction**: importing one never authorises a local purge | a cross-store "who holds the only copy" protocol (a deletion-coordination protocol puts a liveness dependency in the path of the thing it deletes), "mirrors never purge" (C9 — a mirror you cannot clean is a mirror nobody runs), "the origin knows whether the bytes exist elsewhere" (it cannot see them, and pretending otherwise is a lie in a retention report) |
| D9 | import is a closure walk, not a loop | an import closes over *what a reader needs in order to re-verify what it took, here* — and the edges are already in the records (`round_digest`, `roster_digest`, `policy_digest`, `previous_digest`, `attempts.previous`, a merge record's `attestation` field), so the closure is a citation graph, not a guess. If an edge is absent at the source the import **refuses that record** (`closure_incomplete`, naming the missing edge) and carries on with the rest | "import everything and let the reader discover the gap later", "import only the ref that was asked for" (a proof nobody can check is a photograph of a proof), an unbounded walk (a hostile store can make an importer fetch forever) |
| D10 | refusals, limits, versioning | no new exit codes; a named token per refusal (27 of them, as generated vectors); ADR-0001's size limits unchanged; a federation budget of ≤ 4096 records, ≤ 8 closure hops, ≤ 64 policy revisions and ≤ 1 GiB of new bytes per import. `provenance` is added to ADR-0004's field set as an **optional** member, and a build that cannot honour it *refuses the policy that carries it* — ADR-0004's "unknown fields refused" is what makes that addition fail closed instead of silently ignored | a new exit-code class for "came from a mirror" (there is no such verdict, and inventing one invites using it), unlimited closure, "ignore unknown policy fields for forward compatibility" (the one reading rule that would turn a provenance demand into a no-op) |

---

## D1 — The portable set: the verification closure

**Status: decided, not built — `giti-g5c.2` writes the ref filters, `giti-g5c.3` the walk.**

**Decision.** A record is portable when a reader needs it in order to re-verify
something this store serves, and is not portable otherwise. That is one principle with
two tables under it, and the table is generated, not asserted:
[`fixtures/federation-v1/`](fixtures/federation-v1/) emits `portable.json` from the same
rules and `generate.py --check-ad` fails if the tables below disagree with it.

The unit of copying is **a record plus the ref that advertises it** — never a bare blob
and never a bare ref. D7 gives the order and D8 makes it an invariant.

| ref / record | portable | why, and what it must come with |
|---|---|---|
| `refs/attestations/<subject>/<digest>` → `kv/attestation/<hex>` | **yes** | the proof itself. Its subject must be reachable in the same import or explicitly excused (`subject_missing`, D9) |
| `refs/changes/<id>/attempt/<n>` → `kv/change/<hex>` | **yes** | an attempt is immutable and create-only (ADR-0003 D6), and `chg-…` is derived from the record's own content (D3 there), so a copy re-derives the identical id in any store |
| `refs/changes/<id>/head` | **no — it is a pointer** | "the current attempt" is an *as-of-now* fact about one store (C5). The attempt records travel; the pointer is re-derived from the highest attempt present, exactly as ADR-0003 D6 already re-derives the next index |
| `refs/changes/<id>/{merged,abandoned}` → `kv/merge\|abandon/<hex>` | **yes** | a state that *is* a signed record plus one create-only ref (ADR-0003 D7). The record is the fact; there is nothing live about it |
| `refs/heads/**` | **out of scope here** | code travels by git, and a merge is ADR-0003 D8's CAS fast-forward of the *base's* ref, which cannot happen at a mirror (D6). `--proofs-only` deliberately takes evidence without it |
| `refs/gitiup/roster/<epoch:08x>` | **yes** | an epoch is immutable and a round is auditable only against the epoch it pinned; a copy of the epoch is a copy of a signed document |
| `refs/gitiup/roster` (no epoch) | **no — pointer** | "which epoch is live *now*" is live state, and ADR-0002 D8's anti-rollback guard is a rule a store applies to its own present, not to somebody else's `now` |
| `refs/gitiup/signup/<slot>` | **no** | a sign-up is a request awaiting a human; its meaning is "pending". Anyone approved is already *inside* an epoch that travels |
| `refs/gitiup/withdrawal/<slot>`, `refs/gitiup/revocation/<slot>` | **yes** | these must travel *with* the epoch they affect, or the mirror serves a roster that looks uncompromised (D9's `revocation` edge) |
| `refs/gitiup/round/<change>/<job>/<attempt>` | **yes, as evidence only** | the round record is immutable evidence. The *round* is not re-opened at a mirror: copying the record transfers bytes, not arbitration (C6, D6) |
| `refs/gitiup/job/<change>/<job>` | **no** | an advertisement is an invitation to go arbitrate something. Serving one from a store that cannot seat anyone invites volunteers to burn a machine on a round that will never count them |
| `refs/gitiup/lease/<change>/<job>/<slot>` | **no** | the purest *"as of now"* record in the system: "someone is running this, for fifteen minutes". There is no honest copy of it |
| `refs/gitiup/commit/…`, `refs/gitiup/reveal/…` | **yes, together** | a reveal is worth nothing without the commitment behind it — `no_commitment` is an existing refusal in a *live* round — so both travel or neither does |
| `refs/gitiup/verdict/<change>/<job>` | **yes** | with its round, epoch, reveals, commitments and the policy revision it cites. `counted` names keys; the seats name slots; the closure is derivable |
| `refs/gitiup/policy/history/<rev>` | **yes** | the chain walk is how "which rules were in force when this run happened" is answered from bytes in hand (ADR-0004 D6). A copy that cannot walk the chain reproduces `policy_history_missing` rather than guessing |
| `refs/gitiup/policy/current` | **no — pointer** | same reason as the roster pointer, and ADR-0004 D6 already refuses to guess a history it was not given |
| `refs/gitiup/kv/**` (the chain commits) | **no** | on a git host the content-addressed store is an append-only commit chain *per store*. Its oids are this store's history, not a fact about the records. The records travel; the mirror appends them to **its own** chain (D7) |
| `kv/import/<digest>`, `kv/gc/<digest>` | **no** | the audit trail of *this* store's arrivals and *this* store's deletions. Readable by a human anywhere, an instruction to no store (D8) |
| ref caches, tombstones, pack layout, `host.json`, trust roots, `gitiup.toml` | **no — never** | transport furniture and local authority. A trust root that arrives over a wire is not a trust root; it is an attack (D3) |

**Why the closure and not a list.** The table above looks like a list but is generated
from a rule, and that matters for the next record type anybody invents. A `--proofs-only`
mirror of a private repository — `.2`'s headline use case — is not "copy
`refs/attestations/**`": it is "copy the closure of the attestations, which happens to
include verdicts, rounds, roster epochs, commitments, reveals and the policy chain, and
happens to exclude `refs/heads/**`". A hand-written list would have shipped the
attestations alone and produced a store full of proofs nobody can check, which is a worse
outcome than an empty one because it looks like success.

**Why not the alternatives.** *Copy the whole repository* is the tempting one — it is one
`git fetch '+refs/*:refs/*'` — and it is the worst option on this page: it copies leases
and pending sign-ups (C5), it copies the origin's kv chain topology (D7), and it publishes
`refs/gitiup/**`, which names every verifier key and every seat slot (C11). *Copy only the
attestations* is what the shortest transport does, and `.3` already refuses the resulting
artefact in the live case ("a verdict without its evidence is a rumour"); a mirror is not
a place for a different rule. *"Whatever the transport can move"* is not a decision, which
is the ticket's own framing: if the transport decides scope, then scope is decided by
whichever pack protocol shortcut was cheapest.

---

## D2 — The register of what may not be copied

**Status: decided; `giti-g5c.2` refuses each row by token.**

**Decision.** The non-portable rows above are one category, and it is worth stating
separately because the category, not the list, is what the code should check:

> **A record whose truth depends on a clock nobody signed is not data.** It is state,
> and state does not travel.

ADR-0001 D5 already made this argument *inside* a document — a run's wall clock, hostname
and temp paths are poison in `result` because two honest machines disagree. D2 is the
same register one level up, over whole records:

| record / ref | its meaning | why a copy is worse than an omission |
|---|---|---|
| a lease | "this key is running this seat for 15 more minutes" | a copy tells a volunteer a seat is taken, or tells a reader a seat was taken when nobody did; both are lies about a clock |
| a job advertisement | "this round is open *at this store*" | a volunteer does the work and its submission has nowhere to land; the round it advertises belongs to a store that may already have closed it |
| a sign-up awaiting approval | "a human has not said yes yet" | copying it to a second store invents a second pool where the owner's yes was never asked |
| `refs/gitiup/roster` | "this epoch is the live one" | the difference between a live epoch and a stale one is revocation; a copied pointer is how a dead key votes (ADR-0002 D8) |
| `refs/gitiup/policy/current` | "these are the rules now" | ADR-0004 D6 refuses to guess a history; a copied pointer with no chain is exactly that guess |
| `refs/changes/<id>/head` | "the attempt under review" | a force-push is an attempt plus a CAS move (ADR-0003 D6); a copied pointer silently rewrites which attempt a reviewer was looking at |
| `kv/import/**`, `kv/gc/**` | "how *this* store got what it has" | a mirror that copies import records imports somebody else's provenance as its own, and the audit question ("how did this get here?") gets a false answer |
| trust roots, keystore, `gitiup.toml` | "who *I* believe" | the single most dangerous thing on the list: it converts a sync into a trust grant, which is the laundering D3 forbids |

Every refusal is named, so that "we did not copy that" is always a report and never a
silence: `not_portable` with the record class and the reason. A fetch that skips a
non-portable ref says so in the same list where it counts what it took.

**Pointer refs have a second, narrower rule.** A pointer is not just un-portable; a
*reader* may resolve one. Fetching a change means resolving `head` to the attempt it
names and taking that attempt record — the resolution happens on the reader's side of the
wire and is recorded in the report (`resolved head → attempt/3`), which is what makes the
copy point at a fact instead of at a moving part. A mirror that resolved `head` by copying
it would be asserting "attempt 3 was current at the origin at the moment I copied", and
that is an attestation the mirror is not qualified to make (D5).

**Why not the alternatives.** *Copy everything and flag it* fails because a flag is read
only by code that knows to read it, and the flag would have to be checked in every place
that consumes a ref — the pre-receive hook, `verify change`, `quorum verdict`, `work`.
Refusing at the boundary is one check; filtering a blob full of "but this one doesn't
count" is a check at every use site, forever. *Copy the pointers and fix them up later*
fails on the crash window: between the copy and the fix-up the store is confidently wrong,
and gitiup does not have a class of state that is briefly wrong. *Sync `current` both
ways* is D6.

---

## D3 — A copy transfers bytes and never trust

**Status: decided; `giti-g5c.3` implements it and `giti-g5c.2` must not grow the flag.**

**Decision.** The three questions a reader asks about a proof stay in three different
places, and no code path is allowed to substitute one for another:

| question | where it is answered | who may influence it |
|---|---|---|
| *What are these bytes?* | the digest, recomputed here (`put_cas` refuses bytes that do not hash to their name) | nobody — it is arithmetic |
| *Who signed them, and do I accept that key?* | `gitiup verify` with **this reader's** `Trust`, built from `--owner`, `--trust` or the local keystore, exactly as if the document had come off a USB stick | the reader's local config and, for the quorum tier, the epoch the round pinned |
| *What was demanded of it, and does it satisfy that?* | the policy revision in force at the proof's claimed time (ADR-0004 D6) and the gate's rules | the owner's signed policy — never the fetch |
| *(and, as a footnote)* *Where did the bytes come from?* | `provenance` in the report and `kv/import/<digest>` | **nothing may act on this** except D5's staleness demands |

The last row is the whole decision, so it is spelled out as prohibitions a reviewer can
grep for:

1. **No flag.** There is no `--trust-remote`, `--trust-mirror`, `--trusted-store`,
   `--from-trusted` or any spelling where a store URL reaches a `Trust`. `Trust` is built
   by the resolver in [`gitiup/src/participant.rs`](../../crates/gitiup/src/participant.rs)
   and nowhere else.
2. **No bit.** [`Capabilities`](../../crates/gitiup-host/src/capability.rs) gets no
   `trusted`, `authoritative` or `mirror_of` field. Its four bits are all about what a
   store *can promise mechanically* (CAS, immutability, atomic batches, auth model), and a
   store that could assert "and believe me" would be the fifth bit that turns D3 into a
   comment. `mirror_of` in particular is rejected on its own terms: it asserts a
   relationship between two stores that no signature in this system attests to.
3. **No mark on the blob.** Nothing written into `kv/**` may record "verified". A CAS blob
   is shared by every consumer of it, so a trust decision stamped on it is a trust
   decision made by the first reader and inherited by the rest — including readers with
   different trust roots. Verification happens per read, per trust list, forever.
4. **No report field that a caller may branch on.** A fetch or import report says
   `arrived_from`, `objects`, `rehashed`, `refused`. It never says `ok: true` in a
   position where the caller's next step is "so we may merge". `gitiup verify` is the only
   thing that produces a belief-bearing exit code, and it takes a store as a *source of
   bytes*, never as an argument.
5. **A mirror never signs.** No batch manifest, no "these N digests came from me at time T"
   document, no re-signature. If a mirror had a key that made copies acceptable, the
   mirror's key would be the thing everyone configured trust for, and the origin's keys
   would become decorative — which is the laundered end-state, reached by a perfectly
   reasonable-looking availability feature (C8).

**Why byte identity makes this cheap to hold.** Because of D7, a copy is byte-identical
to its original. So *where a proof came from* never changes what it proves: the only thing
provenance can affect is **how much the reader believes it is the freshest copy there is**
(D5). Once a mirror allowlist is understood as a *staleness* knob rather than a *trust*
knob, it stops being tempting to let it grow.

**Why not the alternatives.** *Trust the mirror's verdict and copy only that* is the
ticket's own first rejected alternative, and it is right to reject it: it also happens to
be the *smallest* implementation, which is why it needs naming in the ADR rather than
leaving to review. *TOFU on first fetch* (pin the store's key, then believe its statements)
fails on the axis it looks safest on: what gets pinned is a store, and a store is a
service someone can register tomorrow; a pin on a store is the trust grant D3 refuses to
allow through the front door. *A mirror signature over what it served* fails C8 for a
stranger-run mirror and, for a mirror that does hold a key, creates a second, faster,
less auditable path to "this is fine" — and every incident review eventually discovers
such a path and turns it on.

---

## D4 — Arrival checks: everything, again, here

**Status: decided; `giti-g5c.3` is the implementation and reuses `gitiup verify attestation`'s code path rather than paralleling it.**

**Decision.** An imported document is verified by the same ordered checks as a locally
produced one, in the same order (ADR-0001 D7), with federation-specific steps bolted on
at the ends:

| # | step | on mismatch | new? |
|---|---|---|---|
| 0 | the bytes arrived under a ref whose leaf digest equals the blob digest they hash to | `digest_mismatch` (8), nothing written | no — `put_cas` already refuses |
| 1 | the bytes are their own canonical form | `not_canonical` (8) | no |
| 2 | the ref it arrived under is the ref its content names (`same_ref`) | `same_ref` (6) | no — new *call site*: `store::same_ref` exists for live rounds and is reused here |
| 3 | its bindings: subject oid, change id, round digest, commit it claims to describe | `binding_mismatch` (8) | no |
| 4 | signatures, self-consistency first, then against **this reader's** trust list | `bad_signature` (7) / `signer_untrusted` (6) | no |
| 5 | revocation: every key in the record set against the roster epoch it was signed under | `revoked_key` (6) | no — ADR-0002 D9 |
| 6 | tier against the policy revision in force at `claimed_at_us`, walking the chain that came with the import | `tier_not_allowed` (6), `policy_history_missing` (6) | no |
| 7 | freshness, evaluated **now**, against this reader's clock | `expired` (6) | no — and it is *recomputed*, never carried over: the origin's opinion that a proof was fresh an hour ago is not a field and must not become one (D5) |
| 8 | **closure**: everything steps 0–7 needed is present (D9) | `closure_incomplete` (6) | **yes** |
| 9 | **subject reachability**: the object the proof is about is present, or the operator excused it | `subject_missing` (6) unless `--allow-missing-subject` | **yes** (`.3`) |

**What already exists**: steps 0–7 are `gitiup verify attestation`; `.3`'s job is to call them
rather than to re-implement them, and to add 8 and 9.

Three clauses that are not obvious and will otherwise be "optimised" away:

* **No waiver for duplicates.** A blob already present is not a blob already verified: it
  was verified by whoever put it here, whose trust roots are unknown to this reader. The
  duplicate path is `already` for *writing* and still a full verify for *believing*. A
  fetch that skipped re-verification of existing blobs to save time would make this
  store's trust in a proof depend on which process downloaded it first.
* **No partial writes behind a refusal.** Step 0's "nothing written" is the rule, not a
  detail: the ref is what advertises, so a refusal must never leave a ref behind pointing
  at bytes that failed. This is the same ordering rule `publish` already holds for the
  opposite reason (bytes before refs).
* **Freshness is recomputed and not carried over.** The origin may have declared a proof
  fresh an hour ago; that declaration is not a field, and it must not become one (D5).
  A proof re-imported after its `max_age_us` has passed is `expired` here even if it was
  accepted where it came from — and that is a *feature*: it is exactly the property that
  makes D5's mirror staleness a policy question rather than a forensics question.

**Why not the alternatives.** *"File it now, let readers check"* — the ticket's second
rejected alternative, and the failure mode is cultural rather than technical: a store that
has ever served a broken proof has taught every client that checking is optional, because
for the last nine proofs checking found nothing. The cost of checking at the boundary is
one hash and one signature per record; the cost of not checking is that the store's
integrity becomes a rumour. *"Verify once and mark it"* is D3 clause 3.

---

## D5 — Authority, availability, and how a stale copy is marked

**Status: decided. `kv/import/` and the report's `provenance` block land with `giti-g5c.3`;
the `provenance` *policy* member lands with `giti-91m`'s readers and is a compatibility
change to [ADR-0004 D5](0004-published-policy-format-signing-and-resolution.md).**

**Decision.** A mirror's promise is availability: *the bytes will still be here when the
origin is not.* The thing it is forbidden to promise is freshness. Three clauses.

**1. Age is measured from `claimed_at_us`, and from nothing else.** ADR-0001 D6 decided
freshness is a policy the verifier applies to a signed timestamp, not a property of the
document. That decision quietly solves mirror staleness, and only quietly: if age is
computed from the claim, then

> a mirror **cannot** make a proof fresher, because the only input is a signed field it
> cannot change without breaking the digest — and the *only* way a mirror can make an old
> proof look fresh is a reader that measures age from arrival.

So the rule is a prohibition on that reader: **no gitiup code path may compute age from
`fetched_at_us`, `arrived_at_us`, `mtime`, pack timestamps, ref `updated_at`, or a bucket's
`Last-Modified`.** Arrival time is metadata for a human and for D8's eviction, never an
input to a verdict. To keep this checkable rather than cultural, the provenance block
carries `age_basis: "claimed_at_us"` as a literal field: a test can assert it, and a report
that says otherwise is visibly wrong.

**2. Staleness is marked in the reading, never in the artifact.** Marking a copy has to
live somewhere, and the two tempting places are disqualifying: writing a field into the
record changes bytes, hence the digest, hence the blob key and the ref leaf (C4, and exit
8), and having the mirror sign the mark requires a mirror key (C8) and manufactures exactly
the second path to "this is fine" that D3 refuses. So marking is split:

```jsonc
// in the report of any verify / verify change / import that read through a copy
"provenance": {
  "store": "origin",                        // "origin" | "copy"
  "store_url": "s3://gitiup-project/repo",  // where the bytes were read from, this run
  "read_at_us": 1793347200000000,
  "arrived_from": "https://mirror.example.org/repo.git",  // null when store == "origin"
  "arrived_at_us": 1793343600000000,        // metadata: D8 eviction, human audit only
  "origin_seen": false,                     // was this digest read from the origin itself?
  "age_us": 7200000000,
  "age_basis": "claimed_at_us",             // the invariant of clause 1, printed
  "closure": "complete"                     // "complete" | list of missing edges
}
```

and durably, in the importing store only, at `kv/import/<digest>`:

```jsonc
{
  "type": "gitiup-import-1", "schema_version": 1,
  "digest": "sha256:…",                     // the object that arrived
  "refs": ["refs/attestations/…/…"],
  "arrived_from": "https://mirror.example.org/repo.git",
  "arrived_at_us": 1793343600000000,
  "closure": "complete",
  "verified_by": "SHA256:…",                // the reader's own key: "I checked this, here"
  "verify_exit": 0
}
```

`kv/import/**` answers the question a mirror exists to make answerable — *how did this get
here* — and is local by construction (D2). It is not an attestation, it is never filed
under `refs/attestations/**`, and it grants nothing: `verified_by` is an audit note about a
machine, not an input to `verify`.

**3. A policy may demand provenance.** Because clause 1 guarantees a copy cannot be
fresher than its claim, a mirror can only ever make a proof *older or equal*. The residual
risk is not a forged proof; it is a **stale one**: a gate that accepts a proof from a copy
that happens to be the newest copy the reader can reach, while the origin has moved on. So
the policy may say how much it believes a copy. One new optional member of the ADR-0004
document:

```jsonc
"provenance": {
  "require_origin_seen": true,          // a proof may only gate a merge if it was read from the origin store
  "mirrors": [                          // stores the owner names as equally-fresh
    "https://mirror.example.org/repo.git"
  ]
}
```

and the resulting refusals: `origin_provenance_required` (6) when a gate needs
`origin_seen` and the proof arrived by copy, and `unlisted_mirror` (6) when the store
serving it is not in `mirrors`. Absent the member — the default, and what every policy
signed today looks like — a copy is fully usable for a gate: **federation is on by default
and demanding provenance is the opt-in**, because C1 is the epic and a project that cannot
be mirrored has not bought anything.

Two things `mirrors` is *not*, because both will be asked of it:

* **not a trust list.** Listing a mirror does not make its proofs acceptable; keys and
  policy do that (D3). It states only that the owner believes that store serves copies as
  fresh as its own, which is the whole of what a mirror can offer.
* **not an access-control list.** A store not listed can still fetch and still serve;
  nothing here is a secret. Who may *write* is `giti-g5c.5`'s credential question, and
  this ADR takes no position beyond D6's direction rule.

Local config may *tighten* the demand (an operator may require origin provenance that the
owner did not) and may never *loosen* it, which is ADR-0004 D4's precedence argument
re-used: the signed document is a floor, not a ceiling.

**A mirror never re-tallies.** `.3` re-verifies a copied verdict — that its digests are
its own, that its signatures count, that its seats came from the epoch it pinned — but it
does not re-run the *tally* with local knowledge, because a tally's answer would then
depend on which revocations the importer happened to fetch. A verdict is a signed
statement about a moment; a copy can be checked for being that statement and cannot be
re-decided. Where a reader needs today's revocation state, it must reach an origin — which
is precisely what `require_origin_seen` lets a policy demand.

**Why not the alternatives.** *Stamp the record with `stale: true`* is disqualified twice
over (C4, C8) and worth naming anyway because it is the option a reviewer will propose.
*Let the reader diff arrival time against the claim and decide* is clause 1's prohibition
with extra steps, and it fails the same way every "the human will notice" control fails.
*Refuse to serve anything older than N* at the mirror is tempting and wrong: the mirror
would then be *deciding* which proofs still matter — retention authority (D8) wearing a
freshness costume — and a mirror that filters by age can silently drop the one proof a
merge depends on while still claiming to be a faithful copy.

---

## D6 — Direction: an origin pushes to a mirror

**Status: decided; `giti-g5c.2` implements both verbs and the refusal.**

**Decision.** Copies travel **one way: from an origin to a mirror.** `gitiup push
--remote mirror` is origin → mirror; `gitiup fetch --remote upstream` is what a *reader*
does to pull a copy into its own store, which then becomes an origin for its own mirrors.
There is no `gitiup sync`, no bidirectional remote, and no configuration in which a mirror
writes back to the store it was copied from.

The reason is the same laundering as D3 with the arrows reversed. If a mirror could write
to an origin, then "this attestation arrived from a store I mirror" becomes "this
attestation is filed at the origin", and every reader of the origin — every gate, every
hook, every clone that trusts the origin's ref listing — now believes the origin vouches
for it. A mirror would have acquired the ability to *file*, and filing at the origin is
the closest thing this system has to speaking with the owner's voice.

A mirror also may not accept a **new** claim into a copied round:

| at a mirror, these are refused | token |
|---|---|
| a commitment or reveal into a copied round | `no_arbitration_here` (6) |
| a verdict, or a re-tally written as one | `no_arbitration_here` (6) |
| a lease, a sign-up, a job advertisement | `not_portable` (6), and `no_arbitration_here` if addressed at a specific round |
| a change attempt, a merge, an abandon | `no_arbitration_here` (6) — an attempt is a CAS move of `head` (ADR-0003 D6) and a merge is a CAS fast-forward of the base (D8 there); a store that did not own the pointer cannot move it |
| anything at all from a store flagged read-only | `read_only` (6) — the plain-git host's existing `read-only = "true"` for dumb HTTP endpoints, reused |

The test for whether a write belongs at a mirror is always the same question: **does this
write require the store to arbitrate between two claims?** If yes, it belongs at the origin,
because arbitration is compare-and-swap on the origin's refs (C6, ADR-0002 D10) and a
mirror's CAS only arbitrates the mirror's own copies.

**Idempotence and resumption are `.2`'s acceptance criteria, and D7 + D8 are what make them
achievable.** Every portable write is create-only, so re-running a fetch is `already` per
record and writes nothing; an interrupted fetch that stopped between the blob and the ref
leaves bytes nobody advertises (harmless, and repaired by the next run) and never a ref
advertising bytes that are not there — which is the half of the pair that would otherwise
strand a proof (D8's invariant).

**Why not the alternatives.** *Bidirectional sync* is the shape people reach for because
git remotes are symmetric, and the symmetry is an illusion here: a git remote is symmetric
about *branches* and gitiup's refs are not branches — leases, rounds and verdicts are
arbitration, and arbitration does not two-way. *"A mirror may compute and serve its own
verdicts"* fails before the trust argument even starts: a mirror has no roster authority
(it did not sign the epoch), no seats selected against its own store, and no claim on the
change. A verdict at a mirror would be a signature over a computation it had no standing to
perform, and its presence in the same ref namespace as real verdicts is how a reader learns
to stop reading them.

---

## D7 — Republish: same digest, same ref name, `already`

**Status: decided; `giti-g5c.2`'s write path and `gitiup attest import`'s collision
handling.**

**Decision.**

* **Rehash? No. Same digest, always.** A copy is byte-identical or it is a different
  attestation, and there is no third thing. This is not caution about canonicalisation
  styles — it is three facts stacked on one another (C4): the signature covers those exact
  bytes, `kv/attestation/<hex>` is SHA-256 of them, and `refs/attestations/<subject>/<hex>`
  repeats the hex. A store that "normalises on the way in" (pretty-prints, reorders, adds a
  newline, re-encodes an integer) does not produce a badly-formatted copy; it produces a
  blob that cannot be fetched by the name its ref advertises and a signature that fails at
  step 1 of D4 for a reason the reader cannot trace back to the transport.
* **A name collision is a content match, and the answer is `already`.** Ref names in the
  portable set are derived from content — `attempt/<n>` under a content-derived `chg-` id,
  `<subject>/<digest>` for proofs — so two stores colliding on a name have collided on the
  bytes. `publish`'s existing behaviour (create-only, and re-publishing the same bytes
  reports `already`) is therefore the *whole* collision rule: never `-2`, never a suffix,
  never an overwrite. If different bytes ever present under one name, that is a digest
  collision or a defect, and it is `digest_mismatch` (8) with nothing written, not a naming
  problem to solve.
* **Pointers move under CAS or not at all.** Where a pointer must move at all (the
  importer's own `head`, on the reader's side, from the attempts it took), the write is
  `Expect::Is` and a mismatch is `diverged`: reported, named, and left alone. A mirror
  never resolves a divergence, never force-pushes, and never picks "the newer one" —
  ADR-0003 D6's attempt chain and D8's fast-forward refusal are the arbiter, and both live
  at the origin. `Expect::Any` is not available to this code path, which is the same rule
  that keeps a merge from losing an update.
* **A legacy single-level ref is re-spelled, never re-created.** A copy of
  `refs/attestations/<subject>` (the old one-proof-per-subject shape) is filed at
  `refs/attestations/<subject>/<digest>` and reported `respelled`. The legacy shape is read
  and never written, here as in `attest::publish` and `attest::migrate`, and a mirror is not
  a place where the old spelling gets a new lease of life.
* **A record's identity is its digest, never the container's.** On a git host the record
  store is a per-store append-only commit chain under `refs/gitiup/kv/**`, and a bucket's
  kv is a flat prefix. So a mirror must not copy the chain commit-for-commit: it would
  import one store's private topology — its commit oids, its parent order, its authorship —
  as if it were a property of the records. The mirror verifies each record and appends it to
  **its own** chain, which is why the same record has the same `kv/attestation/<hex>` and
  different `refs/gitiup/kv` oids in two stores, and why nothing anywhere compares those
  oids.

**Why not the alternatives.** *Rehash to this store's canonicalisation* is disqualified by
C4 and by the fact that a mirror has no license to re-sign (D3), so a rehashed copy is not
a weaker proof, it is a *null* proof. *Content-addressed cross-store dedupe by re-signing*
("the mirror signs what it stores, so its copy is authoritative for its readers") is D3
clause 5 in a caching costume. *Resolving a diverged head on the importer's behalf* is the
one thing that turns a transport bug into a silent rewrite of what a reviewer was looking
at; `diverged` costs a human ten seconds and preserves the audit.

---

## D8 — Retention: a mirror is a cache, and no store prunes another's copy

**Status: partly built. `attest::gc`'s `plan`/`apply` split, its `kv/gc/` record, its
`referenced` pin and `purge_cas`'s honesty already exist; D8's mirror rules, and the
`--max-age` refusal, land with `giti-g5c.2`/`.3` (a store cannot tell it is a mirror until
it has import records).**

**Decision.** Three rules, in this order.

**1. Advertisement ⊆ possession, and never less than before.** A store never advertises a
ref whose bytes it cannot itself serve, and never advertises a set smaller than the one it
advertised a moment ago. This is `publish`'s bytes-first ordering generalised to the whole
transport, and it is the invariant that answers the ticket's question — *how does one
store's GC fail to destroy another's only copy?* — without any coordination:

> If every store's refs only name bytes **that store** can return, then no store's purge
> can strand another store's advertisement. Cross-store pointers do not exist, so
> cross-store breakage cannot happen.

The failure this forecloses is specific and easy to build by accident: a mirror that copies
`refs/attestations/**` ref names and then fetches bytes lazily. One `--max-age` run at the
origin later, the mirror advertises a digest it has never held and never will, and every
`gitiup verify` against it exits 8 for a reason that looks like corruption. So: no lazy
mirrors, and no "we have the ref, the bytes are somewhere".

**2. Retention authority follows write authority.** Age- and quota-based pruning is an
*authority* decision: it encodes "proofs older than this no longer matter", which only the
store whose policy gates merges may make. `claimed_at_us` is identical on every copy, so
every store's `--max-age 90d` fires at the same instant everywhere — and that, rather than
one greedy mirror, is the actual last-copy hazard. Consequences:

| rule | behaviour | token |
|---|---|---|
| a store may prune by age/quota only where it holds write authority over the namespace it prunes | `gitiup attest gc --max-age` against a store that is read-only, or whose only copies arrived by import, is refused | `mirror_may_not_prune_by_age` |
| a mirror evicts for **capacity**, never for age | a size/quota-based eviction, planning and applying like `gc`, choosing among digests it can name a source for | — |
| eviction needs a source | a digest with no `kv/import/` record naming where to get it again is not evictable: forgetting it would make this store the only copy and it has not earned the right to decide that | `eviction_needs_source` |
| eviction retires the ref first, then the bytes | the invariant of rule 1 in the destructive direction; `purge_cas` is still the only honest forgetting, and a git store still reports `retained` | — |
| a live ref outside the pruned namespace still pins forever | unchanged from `attest::referenced`: this is the rule that stops a finished round's ballots being swept out from under a published verdict, and it is not a knob | `pinned` |
| a digest named inside another record is pinned by the reader of that record | unchanged from `attest::pin` / `--keep`; and D9's closure import means a verdict's evidence is present, not merely cited | `pinned` |

The shape worth stating plainly: **an origin is a vault, a mirror is a cache.** A vault
prunes on policy and may never forget what it still advertises; a cache throws things away
freely but only things it can go and get again. A mirror that cannot name a re-fetch source
is not a cache, it is a copy with amnesia, and it may not prune at all.

**3. A GC record is evidence, never an instruction.** `kv/gc/<digest>` says what a store
removed and *what each decision was based on*. Copies may carry it to a human and never to
a machine: importing a gc record from another store never authorises a local purge
(`gc_record_not_instruction`, reported and ignored for effect). Two stores with the same
bytes and different retention policies are two healthy stores, and the moment one store's
deletion decision could propagate, the safest store in the federation becomes the one that
deletes everything — including, on the day the owner is on holiday and an automated
mirror's policy is buggy, everything everywhere.

The residual hazard this ADR does **not** pretend to remove: if every store independently
runs the same `--max-age` against the same `claimed_at_us`, coordinated pruning can still
erase a proof from the whole federation on schedule. What defends it is not a protocol but
the two non-knobs — a live ref pins forever, and the closure rule (D9) means a store that
holds a verdict holds its evidence — plus `--keep` for the case where a human knows
something the age does not. The honest statement of the tradeoff is: a proof a live
verdict still points at is safe by construction; a proof nothing points at any more is
eligible to disappear everywhere at once, and that is what a retention policy is *for*.

**Why not the alternatives.** *A cross-store "who has the only copy" protocol* (a
`gitiup whohas`, or mirrors registering with origins) makes deletion depend on the
reachability of everything it might delete, which is a liveness dependency in the worst
possible place; it also assumes the answer is knowable, and a federation of
anonymous mirrors makes that a lie. *Mirrors never purge* is C9 and would be the first rule
anyone disables. *"The origin knows"* — assuming a copy's existence elsewhere from the
origin's ref listing — puts a claim about bytes into a report that cannot have observed
them, and a retention report that can lie about what still exists is worse than a
conservative one.

---

## D9 — Import is a closure walk

**Status: decided; this is `giti-g5c.3`'s main loop.**

**Decision.** An import walks a closure, and the edges are not invented here — they are the
digest citations the records already carry:

| record | cites | so the closure must fetch |
|---|---|---|
| a run attestation | its subject oid, `claimed_at_us` | the subject object (or `subject_missing`), the policy revision in force at that time |
| a `tier: quorum` attestation | the verdict it draws its tier from | the verdict, and through it everything below |
| a verdict | `round_digest`, `roster_digest`, `policy_digest`, `counted[]` | the round record, the roster epoch, the policy revision, each counted seat's reveal — and its commitment when the round is sealed |
| a round record | `policy_digest`, its pinned roster digest, its seed and seats | the policy revision, the roster epoch, the seats' slots |
| a reveal / commitment pair | the round, the slot | the round record; a reveal without its commitment in a sealed round is `no_commitment`, so the closure carries both or refuses |
| a roster epoch | its member keys and rotations | the revocations naming any seated key, the withdrawals its rotation depends on |
| a policy revision | `previous_digest` | the whole chain to genesis, or `policy_history_missing` (6) — ADR-0004 D6's refusal, unchanged, now reachable via a copy |
| a change record | `base`, `head`, `attempts.previous` | the previous attempt (bounded by the attempt chain), the base and head objects |
| a merge record | its `attestation` field, the change | the change record and the proof digests it says it believed — via `attest::pin`, whose rule this already is |
| an abandon record | the change | the change record |

and a refusal when an edge has no foot at the source: **`closure_incomplete`, naming the
record type and the edge** — `closure_incomplete: policy_revision`,
`closure_incomplete: roster_epoch`, `closure_incomplete: commitment`. Refusal is per record
and the import continues, so one unimportable proof does not end a fetch of two hundred.

One excuse is sanctioned, because one use case needs it: `--proofs-only` (`.2`, the
read-only public mirror of a private repository) implies `--allow-missing-subject`, since
evidence without code history is the whole point. That is an *explicit* excuse, printed in
the report as `subject excused (--proofs-only)` and recorded in `kv/import/`, so a reader
can tell "the object is deliberately not here" apart from "the object is lost" — which is
the difference between a mirror and a rumour.

The bounds (D10) keep a stranger from making an importer fetch forever, and *completeness
for what was taken* is the property a reader can rely on: a mirror is allowed to be missing
things, and must not be missing them in a way that looks like having them.

Two things this replaces, both of which are how the naive implementation fails. *Import
everything, let the reader find the gap* defers the question to the worst moment — a merge
gate, under time pressure, with a verdict whose round is absent. *Import exactly the ref
that was asked for* is the twenty-line loop: it produces a store where
`gitiup verify change` finds a `tier: quorum` attestation and no verdict, which exits 6,
which teaches the operator that mirrors lie.

**Revocation suppression is not closed here, and saying so is part of the decision.** A
mirror that carries a roster epoch can carry it *without* the revocations that landed
afterwards: the bytes it serves are genuine and signed, and nothing in them is wrong. It
is not detectable in the copy, and it is bounded by exactly two things — every proof's own
freshness window (an old verdict stops gating on its own clock, D5 clause 1) and
`provenance.require_origin_seen` for whoever needs the live answer. The transparency-log
anchoring ADR-0001 D9 leaves optional is the third, if a project turns it on.

---

## D10 — Refusals, limits, and how we change our minds

**Status: decided; the token list is generated in
[`fixtures/federation-v1/cases.json`](fixtures/federation-v1/cases.json).**

**Decision.** No new exit codes. Federation refusals are tokens on the existing ladder:
**6** refused by policy, absent scope, or a document this build cannot honour; **7** a
signature that does not verify; **8** bytes that are not the bytes their name promises.
Exit **9** stays exactly what giti-zp1.7 made it (attempt cap exhausted) and has nothing to
do with federation.

Per-record versus per-command: a scope refusal on one record (`closure_incomplete`,
`not_portable`, `subject_missing`) is reported, counted, and does **not** fail the command —
`.3`'s own acceptance criterion — while an integrity failure (7, 8) always does, because a
command that "succeeded" past a bad signature is a store that now contains one. `--strict`
makes any refusal fail the command, for the CI job that would rather know.

| token | exit | from |
|---|---|---|
| `not_portable` | 6 | D2 |
| `no_arbitration_here` | 6 | D6 |
| `read_only` | 6 | D6 (existing host option, new token site) |
| `diverged` | 6 | D7 (a report as often as a refusal) |
| `digest_mismatch` | 8 | D4 step 0, D7 (existing) |
| `not_canonical` | 8 | D4 step 1 (existing) |
| `same_ref` | 6 | D4 step 2 (existing) |
| `binding_mismatch` | 8 | D4 step 3 (existing family) |
| `bad_signature` | 7 | D4 step 4 (existing) |
| `signer_untrusted` | 6 | D4 step 4 (existing) |
| `revoked_key` | 6 | D4 step 5 (existing) |
| `tier_not_allowed` | 6 | D4 step 6 (existing) |
| `policy_history_missing` | 6 | D4 step 6, D9 (existing) |
| `expired` | 6 | D4 step 7 (existing) |
| `closure_incomplete` | 6 | D9 |
| `subject_missing` | 6 | D9 (`.3`'s `--allow-missing-subject` excuses it) |
| `no_commitment` | 6 | D9 (existing in a live round; now reachable at import) |
| `mirror_may_not_prune_by_age` | 6 | D8 |
| `eviction_needs_source` | 6 | D8 |
| `gc_record_not_instruction` | 6 | D8 (reported; effect ignored) |
| `origin_provenance_required` | 6 | D5 |
| `unlisted_mirror` | 6 | D5 |
| `closure_budget_records` | 6 | D10 budget |
| `closure_budget_depth` | 6 | D10 budget |
| `closure_budget_bytes` | 6 | D10 budget |
| `policy_chain_too_long` | 6 | D10 budget (a `previous_digest` walk past 64 revisions) |
| `field_unknown` | 6 | a policy carrying `provenance` read by a build that cannot honour it (ADR-0004 D10, doing its job) |

**Limits.** ADR-0001 D7's per-document limits apply unchanged (1 MiB, 4096 entries, 64
signatures): a federation record is a gitiup record and nothing more. The new bounds are on
the *walk*, because that is where a stranger gets to choose the work:

| budget | default | meaning |
|---|---|---|
| records per import | 4096 | same number as ADR-0001's list limit, so one habit covers both |
| closure depth | 8 hops | enough for attestation → verdict → round → epoch → revocation → policy, with room; more than that is a graph, not a proof |
| policy chain length | 64 revisions | the `previous_digest` walk is its own linear budget and does **not** count toward the hop figure — a chain grows with a project's life and must not outlive its own verifiability; past 64 the import refuses rather than walking forever |
| new bytes per import | 1 GiB | the walk stops and reports rather than filling a disk |
| per-record size | 1 MiB | unchanged, and checked **before** allocation, as everywhere |

Budget exhaustion is a refusal, not a truncation: a partial import that reported
`closure_budget_depth` is distinguishable from one that found nothing.

**Versioning.** `kv/import/<digest>` is `gitiup-import-1`, `deny_unknown_fields`, additive
only, and — like every gitiup record — read strictly, because it is the file an auditor
trusts. The report `provenance` block is display, versioned with the report it appears in,
and nothing may parse it as an input to a decision (D3 clause 4). The one **compatibility**
decision in this ADR is D5's `provenance` member on the ADR-0004 policy document: it is
additive and optional, and a build that does not know it refuses a policy that carries it
rather than ignoring the demand, which is ADR-0004 D10's "unknown fields refused" producing
the only safe behaviour available. There is no migration to run, because nothing in
existence carries the member yet — the same answer ADR-0004 gave itself, for the same
reason.

**What changes our mind.** A future ADR that wants a mirror to carry something in D2's
register has to say which *signature* attests to the clock-independent version of it. That
is the bar, and it is deliberately not reachable by most things that will want in: the
honest form of "the mirror saw this at time T" is a signed statement by the mirror, and the
mirror has no key (C8), so the argument arrives back at D3 and must be answered there.

---

## Worked example

One change, one quorum proof, three stores, and every refusal in this document in one
story. Timestamps are the fixture clock; digests are abbreviated.

**1. The origin has it.** `s3://gitiup-project/repo` holds change `chg-6a6a8eab778ba4d0`,
round `attempt/0` (sealed, 5 seats), four reveals and their commitments, the verdict
(`verified`, 4-of-5), roster epoch `00000007`, policy revision 2 (revision 1 is its
`previous_digest`), and the `tier: quorum` attestation the verdict produced.

**2. A public mirror is stood up by someone who does not have an account anywhere** (C7):
`https://mirror.example.org/repo.git`, a bare repo on nginx, dumb HTTP, anonymous fetch,
`read-only = "true"`.

```console
$ gitiup push --remote mirror --proofs-only --change chg-6a6a8eab778ba4d0
objects            16 new, 3 already
refs               16 written, 0 moved
closure            complete  (attestation → verdict → round → roster/00000007 → policy rev2 → rev1)
subject            2 excused (--proofs-only implies --allow-missing-subject)
not portable        4 skipped: 2 lease, 1 job advertisement, 1 signup   (not_portable)
trust              none: a push grants nothing (D3)
```

Fifteen of those sixteen objects are not the attestation: they are its closure — the
verdict, the round, the epoch, the revocation naming one seated key, two policy revisions,
four reveals and their commitments — plus the change record itself. A `--proofs-only`
mirror of a private repository is asked for evidence without code history, so the subject
objects are the one edge excused, loudly and in the report and in `kv/import/`; `refs/heads/**`
stayed home.

**3. A contributor clones from the mirror and gates a merge** with no network path to the
origin:

```console
$ gitiup verify change chg-6a6a8eab778ba4d0 --store https://mirror.example.org/repo.git --json
{
  "verdict": "verified",
  "exit": 0,
  "attestations": [ { "digest": "sha256:9f1c…", "tier": "quorum", "accepted": true } ],
  "policy": { "source": "store", "revision": 2, "body_digest": "sha256:b410…", "walked_to_us": 1793336400000000 },
  "provenance": {
    "store": "copy", "store_url": "https://mirror.example.org/repo.git",
    "origin_seen": false, "age_us": 7200000000, "age_basis": "claimed_at_us",
    "closure": "complete"
  }
}
```

It merges. Nothing was believed *because* it came from the mirror: the attestation verified
against the reader's own owner key, the verdict's `round_digest` / `roster_digest` /
`policy_digest` each resolved to bytes in the same store (D9), and the epoch the round
pinned was the epoch that said those five keys were the roster. `origin_seen: false` is a
sentence about freshness, printed and not acted on.

**4. The same project tightens its policy** and the mirror has not been pushed to yet. With
`provenance.require_origin_seen` unset — the default, and what every signed policy contains
today — the merge in step 3 still passes on the mirror, and the policy the verdict was
judged by is revision 2, present and chain-walkable, because policy revisions are portable
(D1). Had the owner set `"require_origin_seen": true`, step 3 would instead have been:

```console
$ gitiup verify change chg-6a6a8eab778ba4d0 --store https://mirror.example.org/repo.git
refused (6): origin_provenance_required
hint: the policy demands a proof read from the origin store; this one arrived by copy
      (arrived_from https://mirror.example.org/repo.git). Fetch from the origin, or widen
      provenance.mirrors — which says "I believe this copy is as fresh as mine", never
      "believe it" (ADR-0005 D5).
```

**5. Somebody `git clone`s the mirror and copies everything,** including the refs that were
not pushed: nothing was pushed, because leases and pending sign-ups were never written
there (`not_portable`, step 2) — and had they been, they would have been a lie by the time
the clone finished (C5).

**6. The origin runs its monthly retention.**

```console
$ gitiup attest gc --store s3://gitiup-project/repo --max-age 120d --apply
retired 6 · pinned 4 (live refs) · retained 0 · kv/gc/2f8a… written
```

The mirror is untouched and does not know. Its copies are not a lie: they are the same
bytes under the same names, and the ref that advertised them is still there (D8 rule 1), so
`verify change` on the mirror keeps returning exit 0 for exactly as long as the freshness
policy allows.

**7. The mirror runs `gc` too,** because it is a directory on a small box:

```console
$ gitiup attest gc --store /srv/mirror/repo --max-age 120d --apply
refused (6): mirror_may_not_prune_by_age
hint: this store only holds copies (5 import records name an origin). Age-based retention
      is the origin's call and `claimed_at_us` is identical on every copy, so running it
      here prunes the federation in lockstep with the origin (ADR-0005 D8).
      Evict for capacity instead: gitiup attest gc --store … --max-bytes 4g --apply
```

and the capacity eviction that does run declines one digest, because its `kv/import/`
record was deleted during an earlier `rsync --delete` and it can no longer name a place to
fetch it back from (`eviction_needs_source`): that store is now the only copy of that
digest, and it has not earned the right to decide it does not matter.

---

## Threats, and which decision closes each one

| # | threat | closed by |
|---|--------|-----------|
| T1 | "Fetched from a store I trust ⇒ signed by a key I trust": a fetch becomes a trust grant, and every host on the internet can make a change look verified | D3 (no flag, no bit, no mark, no report field to branch on) + D4 step 4 (trust list is local, always) |
| T2 | The reverse arrow: a mirror writes a proof back to the origin so the origin's readers believe the origin vouched for it | D6 (one-way; `no_arbitration_here`) |
| T3 | Freshness laundering: a proof is "fresh" because it just arrived | D5 clause 1 (age from `claimed_at_us` only, `age_basis` printed and asserted) |
| T4 | A mirror vouches for a batch with its own key, and gitiup grows a second, friendlier path to "this is fine" | D3 clause 5 + C8 (the mirror has no key, and no schema slot for one) |
| T5 | A mirror advertises digests it never holds; every verify exits 8 and everyone calls it corruption | D8 rule 1 (advertisement ⊆ possession, bytes first, no lazy mirrors) + D4 step 0 |
| T6 | A store re-canonicalises on import and silently destroys the binding between bytes, blob name and ref leaf | D7 (same digest, always) + D4 steps 0–1 |
| T7 | A `tier: quorum` attestation is copied without its verdict, or a verdict without its round, reveals or epoch — a rumour in a proof's clothing | D9 (`closure_incomplete`) + D1's table |
| T8 | A mirror re-tallies a copied verdict with the revocations it happens to hold, and the answer depends on the fetcher | D5 ("a mirror never re-tallies") |
| T9 | A mirror serves an old roster epoch and suppresses the revocation that landed after it | bounded, not closed, and D9 says so: every proof's own freshness window, plus `provenance.require_origin_seen`, plus optional ADR-0001 D9 anchoring |
| T10 | A mirror's listing publishes every verifier key and seat slot in `refs/gitiup/**` | D1 (the closure, not the namespace) + C11 |
| T11 | Two independent `--max-age` runs erase a proof from the whole federation on schedule | D8 rules 2–3 (mirror refuses age pruning; a live ref pins forever; `--keep`), with the residual honestly stated in D8's last paragraph |
| T12 | One store's GC record propagates and authorises deletion everywhere | D8 rule 3 (`gc_record_not_instruction`) |
| T13 | A diverged `head` at a mirror silently changes which attempt a reviewer approved | D6 + D7 (CAS-only pointer moves, `diverged` is a report) |
| T14 | An import loop is turned into a denial of service against the importer by a store with a deep or vast citation graph | D10 budgets (`closure_budget_*`), refused rather than truncated |
| T15 | A mirror is missing half of what it serves and looks complete | D9 (refuse per record, per-record report, `--strict`) + D1's record-plus-advertisement unit |
| T16 | Federation quietly becomes "sync my trust config between machines" | D2's last row + D3 clause 1 |
| T17 | Two tickets implement two different portability tables and disagree about one namespace | [`fixtures/federation-v1/`](fixtures/federation-v1/), with `--check-ad` failing CI when the prose and the data part company |

---

## Consequences

**Unblocked, with nothing left to decide.** `giti-g5c.2` gets its ref filters (D1's table
as generated data), the list it must refuse and by which token (D2), the one-way rule and
the arbitration test for any write it is offered (D6), the collision semantics that make it
idempotent (`already`, create-only, D7) and the pointer rule that keeps an interrupted run
harmless, plus the write ordering its "no ref advertising a partial set" criterion needs
(D8 rule 1) and the shape of `--proofs-only` as a closure rather than a namespace.
`giti-g5c.3` gets the verify ladder with its two new steps (D4), the closure walk with its
edges and its budgets (D9, D10), the import record's fields (D5), the per-record versus
per-command exit rule (D10), and the rule that makes its headline refusal — *a verdict
without its evidence is a rumour* — a general principle instead of a special case.
`giti-g5c.4` gets a migration as a single fat push (D6/D7) and the answer to "what about
the forge's check runs" — they were advertisements and the attestation is the thing
(D1). `giti-g5c.5` gets the write-direction boundary and the privacy reason the portable
set is not `refs/gitiup/**`. `giti-91m`'s policy readers get one optional field, its two
refusals, and the argument for why the owner naming a mirror is a staleness statement and
not a trust one.

**Costs.** A fetch is bigger than the naive version: seventeen objects where a lazy
implementation would move one, because a proof without its closure is a photo of a proof —
and D9's edges make `.2` fetch the policy chain and the roster epoch even where nobody
asked for them, which is more round trips on a bucket host. Verification at the boundary
means an import hashes and signature-checks every record it is given, so `.3` costs CPU in
proportion to a mirror's population; that is bought back on the first `verify change` that
needs no origin. Mirrors are now subject to a *policy* rule (`mirror_may_not_prune_by_age`),
which will surprise an operator who set up cron and will read D8; the eviction path must
therefore exist when `.2`/`.3` land, or the refusal is a dead end — that is a real piece of
work this ADR creates and is not free. `provenance` is a new field in a signed document that
older builds will refuse to read *when it is used*, which is the intended fail-closed
behaviour and will still read as a bug report once. And D5's "no code path may compute age
from arrival" is the kind of rule that wants a lint: without one it survives by review, and
review is weakest exactly where a timestamp looks innocuous. One more cost is owed
forward: the vectors in [`fixtures/federation-v1/`](fixtures/federation-v1/) are run by
nothing but themselves until the transport exists, so `giti-g5c.2` owes a CI line running
`generate.py --check`, `--check-ad` and `--selftest` alongside the Rust consumers it
inherits — an unrun vector rots, and a rotted vector is worse than none because it is
believed.

**Explicitly out of scope, decided elsewhere.** *Who may write* — credentials, anonymous
read scoping, deploy keys (`giti-g5c.5`); *how a mirror is discovered* — there is no
announcement protocol, no mirror list service and no DNS for mirrors, and `mirrors` is an
owner's signed assertion rather than a discovery mechanism (naming it a discovery
mechanism would be the first step toward D3's forbidden thing); * gossip, DHT, replication
daemons, or conflict-free ref merge* — the epic's own "deliberately not here", and nothing
here needs them; *the transport itself* (`.2`); *forge import* (`giti-g5c.4`); revocation
propagation guarantees (T9's bound, ADR-0002 D9); transparency-log anchoring as the
anti-withholding answer (ADR-0001 D9, optional); retention *policy* content (which ages,
which quotas — [host abstraction](../host-abstraction.md) and `attest::gc`), as opposed to
who may apply it (D8); the `kv/import/` record's life cycle after the object it records is
gone (it goes with it, and that is plumbing); and whether a project *should* be mirrored
by a stranger — a governance question with no code in it.

**References.** Vectors and generator:
[`docs/adr/fixtures/federation-v1/`](fixtures/federation-v1/) — `portable.json` is D1/D2 as
data, `cases.json` is D9's closure cases and D10's refusal table, and `generate.py
--check-ad` is what keeps this document honest. Existing code this leans on:
[`attest::publish`](../../crates/gitiup-host/src/attest.rs) (bytes-then-ref, create-only,
`already`), [`attest::referenced` and `pin`](../../crates/gitiup-host/src/attest.rs) (the
un-prunable pin), [`Retention` and `apply`](../../crates/gitiup-host/src/attest.rs) (plan
before apply, `kv/gc/`), [`BlobStore::put_cas` and `purge_cas`](../../crates/gitiup-host/src/blob.rs)
(re-hash on write; the only honest forgetting), [`Namespace`](../../crates/gitiup-host/src/blob.rs),
[`store::same_ref` and the ref layout](../../crates/gitiup-quorum/src/store.rs),
[`VerdictRecord`'s citations](../../crates/gitiup-quorum/src/verdict.rs) (`round_digest`,
`roster_digest`, `policy_digest` — the closure edges as signed fields),
[`Round`](../../crates/gitiup-quorum/src/round.rs),
[`ChangeRecord`](../../crates/gitiup-host/src/change.rs),
[`policy`](../../crates/gitiup-quorum/src/policy.rs) (chain, `policy_history_missing`, the
`current`/`history` split), the trust resolver in
[`gitiup/src/participant.rs`](../../crates/gitiup/src/participant.rs), and the read-only dumb
HTTP path in [`hosts/git.rs`](../../crates/gitiup-host/src/hosts/git.rs). Upstream decisions:
[ADR-0001](0001-attestation-encoding-hash-and-signature.md),
[ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md),
[ADR-0003](0003-change-record-format-and-merge-semantics.md),
[ADR-0004](0004-published-policy-format-signing-and-resolution.md),
[host abstraction](../host-abstraction.md). ADR index: [`docs/adr/README.md`](README.md).

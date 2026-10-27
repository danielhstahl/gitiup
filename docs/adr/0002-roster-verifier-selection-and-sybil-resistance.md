# ADR-0002 — Roster, verifiable selection and sybil resistance

* **Status**: accepted
* **Decides**: how a verifier pool is defined and maintained, how the N verifiers for one job are chosen so that anyone can audit the choice afterwards, what makes an identity mean something, and what happens when a key is rotated or revoked
* **Ticket**: `giti-msi.1` (parent epic `giti-msi`, *Optional quorum verification network*)
* **Blocks**: `giti-msi.2` (roster + registration), `giti-msi.3` (selection), `giti-msi.4` (jobs/leases — reserve order and exclusion input), `giti-msi.6` (commit-reveal slots and handles), `giti-msi.7` (policy defaults, one-vote-per-identity), `giti-msi.8` (escalation rounds), `giti-msi.9` (threat model, rate limits); `giti-kd4.5` (merge gate re-checks revocation)
* **Depends on**: [ADR-0001](0001-attestation-encoding-hash-and-signature.md) — canonical JSON (D1), `sha256:` digest strings (D2), Ed25519 + SSH key ids (D3), freshness-as-policy (D6), limits and fail-closed reading (D7)
* **Reference vectors**: [`fixtures/selection-v1/`](fixtures/selection-v1/) — `generate.py` is a stdlib-only implementation of the algorithm in D3, and `roster.json` / `round.json` / `selection.json` are the golden vectors `gitiup select` must reproduce byte-for-byte
* **Not implemented yet**: this is a decision document. The code lands in `giti-msi.2`/.`3`; the vectors exist so those tickets can be *wrong loudly* rather than differ quietly.

> The epic asks five volunteer machines to independently re-run one change. Everything
> else in the epic — jobs, leases, commit-reveal, verdicts — is downstream of three
> choices written down here: **who is allowed to be a verifier, how the five are
> picked, and what stops the pool from being flooded.** Re-deciding them inside a
> coding ticket is how you end up with two incompatible notions of "the roster" and a
> quorum that two auditors cannot reproduce.

---

## Context

A quorum is only worth as much as the difficulty of *being in it*. Two failure modes
bookend the design, and both are cheap to get wrong:

* **Selection is predictable or influenceable.** If the proposer can compute — or
  nudge — who will check their change, they pre-arrange the answer.
* **Membership is free.** If anyone can be a verifier at zero cost, the attacker's
  share of every quorum is the number of keys they can generate, which for any
  attacker with a laptop is "all of them".

Everything below is an attempt to make those two attacks cost something a human
controls (a vouching decision, a merge review) rather than something a script
controls.

The constraints any answer has to satisfy:

| # | constraint | who forces it |
|---|------------|---------------|
| C1 | The selection must be a **pure function of published bytes**: one roster blob, one round record, and any auditor recomputes the same ordered list. No node has to be reachable, online, or trusted to answer "why me?". | `.3`, `.7`, `giti-w19.3` |
| C2 | Two honest verifiers must compute the **same** selection. Anything that depends on a node-local view of the network (a peer list, a trust graph, a routing table) guarantees they will not. | `.7`, `.8` |
| C3 | The inputs to the choice must not be **guessable in advance by the party being checked**, and must not be **re-rollable** by whoever makes the choice. | `.3`, `.9` |
| C4 | Adding an honest verifier must be cheap; adding a dishonest one must cost a human decision. The bottleneck has to be vouching, not compute. | `.2`, `.9` |
| C5 | One person, ten machines, one vote. Capability may scale *eligibility*, never *weight*. | `.7`, `.9` |
| C6 | Trust must be **one** signed, fetchable document per epoch. Every verification path already refuses to put a network round trip in the trust path (ADR-0001 C2), and the same applies to a trust *graph*. | ADR-0001 C2, `.8` |
| C7 | A verifier is a volunteer's laptop running strangers' workflow. It must be able to decide *not* to participate from what it has locally, and it must never have to hold an address book of the others. | `giti-bgy.*`, `.5` |
| C8 | Keys are lost, laptops are sold, people get busy. A roster that cannot shed and add members is a roster that is quietly wrong. | `.2`, `.9` |
| C9 | The result of *any past* selection must stay checkable after the fact, including after the roster moved on. Audit is not a live query. | `.3` AC, `.8`, `giti-kd4.5` |

Two things were **not** in tension and are worth saying so: throughput (a
kilobyte roster and a few hashes per round, on a store that is already the arbiter)
and liveness of the selector (the selector is a signing act, not a service — see D2).
The choices below were made on auditability, on the cost of a sybil, and on how much a
volunteer has to fetch and believe to say "no".

## Decision at a glance

| id | question | decision | rejected |
|----|----------|----------|----------|
| D1 | how verifiers are chosen | deterministic sortition: hash the roster with a per-round seed, order, fill under caps. The roster is a signed document in the store | gossip/DHT random-walk sampling, owner hand-picks per change, every roster member runs everything, uniform-random from all comers |
| D2 | where the seed comes from | `seed = HMAC-SHA256(secret, round_id)`, `secret` derived from the selector's existing Ed25519 seed; published in the round record. Not re-rollable | free random "owner nonce" (grindable), ECVRF/Ristretto VRF proof, drand/NIST beacon, re-rolling until a liked roster |
| D3 | the algorithm | score = `SHA256(domain ‖ seed ‖ key_id)`, sort ascending by score then by key id, greedy fill with per-tier and per-identity caps, tail is the reserve list, promotion = re-run with a longer exclusion list | reservoir sampling over an unordered list, weighted-by-capacity drawing, "ask five volunteers politely" |
| D4 | identity anchor (the sybil question) | **owner-signed roster allowlist**; an identity *is* an anchor key; per-identity vote weight exactly 1 | proof-of-work / CPU weight, staked or bonded identity, web-of-trust as the anchor, permissionless with no anchor, forge accounts |
| D5 | tiers | three named tiers (`trusted`, `endorsed`, `anonymous`) with **caps that force a mix**; reputation is an *exclusion*, never a weight | continuous reputation-weighted votes, one flat undifferentiated pool, self-declared tier |
| D6 | endorsements | signed third-party vouches, an **input to the owner's tier decision only**, never an input to selection | per-verifier WoT trust scores computed locally (breaks C2) |
| D7 | capabilities | self-attested in the roster entry, checked as an ordered filter *before* selection and re-checked *after* against the environment fingerprint they sign; a lie is a divergence and a reputation event | live probing before selection (a network dependency + an SSRF vector), trusting claims unconditionally, no capability filter at all |
| D8 | roster epochs | monotonic `u64`, `epoch = max(prev + 1, floor(now / epoch_interval))` with `epoch_interval` 7 d; one signed document per epoch, hash-chained to the previous, pinned **by digest** into every round; verifiers refuse a lower epoch than the highest they have seen | a mutable live list, content hash as the epoch, no expiry, epoch chosen by the proposer |
| D9 | revocation and mid-flight jobs | revocation is a signed record with a `reason` and an `effective_epoch`; new selections honour it immediately; whether it voids an already-submitted attestation depends on the reason (matrix in D9); the merge gate re-checks at merge time | ignore it, or void everything a key ever said |
| D10 | where the records live | `refs/gitiup/{roster,round,reveal,revocation,signup}/**` + `kv/{roster,job,round,reveal,revocation,policy}/<hex>`; storage keys are **hex slots**, never fingerprints | fingerprints in ref names (illegal characters), one mega-document, records outside the store |
| D11 | what is secret, when | the seed is unguessable *before* the round opens and public *from* the round record; the roster and the selected set are public once a round is advertised; commitment slots are keyed by hex slot, and **seed-derived handles are specified but off by default** | pretending a public content-addressed store can hide a selection, mandatory X25519-sealed grants in v1, anonymous commitments with no binding |

---

## D1 — Selection: deterministic sortition over a signed roster

**Decision.** For one job (one change head, one matrix vector) the verifier set is

```text
select(roster, round_inputs) -> (selected ordered list, reserve ordered list)
```

a pure function of (a) the **roster document for one epoch**, fetched from the store
and signature-checked, and (b) a **round record** naming the change id, head oid, job
id, attempt, required capabilities, exclusion set and selection policy. Anyone who
can fetch those two documents computes the same two lists, offline, in microseconds,
forever. `gitiup select --explain` prints exactly that derivation (D3, "auditing").

The seed is a hash, not a lottery call to anyone: there is no protocol, no
coordination, no message to send. The selector's whole job is to sign a round record
containing the seed and the derived list.

**Why not the alternatives.**

* **Gossip / DHT random-walk sampling** — the tempting answer ("sample five random
  peers") and the one this ticket was asked to compare against. Rejected on four
  counts, all of which are C1/C2: a sample from a *view* has no public justification,
  so "why you?" has no auditable answer and `.3`'s acceptance criterion cannot be
  met; the view is built by nodes the attacker also controls, so sybil resistance is
  silently outsourced to the overlay's routing table (an eclipse attack becomes a
  selection attack); two honest nodes sampling different views pick different
  quorums, and a quorum that two nodes disagree about is not a quorum; and it needs a
  live lookup path in the trust path, which ADR-0001 already refuses for signatures
  and there is no reason to grant here. A DHT also gives a *peer* list, not a *trust*
  list: it answers "who is out there", which is precisely the question C4 says is not
  worth asking.
* **The owner picks verifiers per change** — trivially auditable, zero crypto, and it
  makes the owner a synchronous bottleneck and a bribery target with N-per-day
  capacity. It also means every change's security rests on a human being awake; the
  roster's job is to move the human decision to membership (rare, remembered) instead
  of per-change selection (constant, invisible).
* **Everyone runs everything, and the seed then picks which N results count** — the
  honest rival, and the only scheme that hides the selection perfectly (nobody knows
  which submissions will matter until the seed lands). Rejected on cost: fan-out
  becomes |roster| instead of 5, which is exactly the "five volunteer machines" the
  product promises not to be, and it punishes a growing roster (more honest members =
  more wasted work) instead of rewarding it. Named here because the escalation path in
  `giti-msi.8` is a *partial* version of it — a bigger selection over a smaller pool.
* **Uniform random from all comers** (no roster at all) — see the capture table in
  D4: this is not a weakened security model, it is no security model.

**Consequences.** `.3` is a pure function plus a `--explain` printer; `.4` can derive
the reserve order without asking anyone; `.7` can re-derive a past round's selection
from the verdict record alone; a third party can audit a selection they were not
invited to (which is the point of a public store).

## D2 — The seed: a keyed hash the selector cannot re-roll

**Decision.**

```text
selection_secret = HKDF-Extract(salt = "gitiup-round-1/secret",
                                ikm  = <selector's Ed25519 seed>)
round_id = join(0x00, [ round_kind, dec(roster_epoch), hex(roster_digest),
                        change_id, head_oid, job_id, dec(attempt) ])
seed     = HMAC-SHA256(key = selection_secret, msg = round_id)
```

`round_kind` is `"gitiup-round-1"`. Every field is written in exactly one way
(`dec` = shortest decimal, no sign, no leading zeros; `hex(roster_digest)` = the
lower-case hex body of the tagged digest, `sha256:` prefix dropped; `head_oid` = the
algorithm-tagged git oid exactly as it appears in the change record). An empty field
or an embedded `0x00` is a refusal, not a fix-up.

The seed is **published in the round record** (D11), so the selection is auditable
afterwards by design, and it is **not chosen**: the selector's freedom is nil,
because the inputs are fixed by the change and the epoch and the function is
deterministic. The selector is the repo owner by default (the key that signs the
roster), and `selector_keys` may hold a small list used round-robin by
`roster_epoch mod len(selector_keys)` — additive, and defined now so adding a
co-selector later is not a re-decision.

**Why not the alternatives.**

* **A free random "owner nonce"** (the ticket's original phrasing) — a nonce the
  selector *picks* is a nonce the selector *re-rolls*: hash the inputs, if the
  resulting roster looks inconvenient, bump the nonce and try again. Grinding is
  invisible after the fact unless you also publish the rejected nonces. Deriving the
  seed instead makes grinding cost a new change id or a new commit (both visible and
  rate-limited, D4 threat table) rather than a millisecond of CPU. This is the one
  place the ticket's wording is deliberately changed: the *owner nonce is derived, not
  random*.
* **A real VRF (ECVRF P-256, Ristretto255, VRF-pairing)** — the ticket says
  "hash/VRF", and the difference matters: an HMAC is *unforgeable* (only the selector
  can produce round seeds, so nobody can farm them in advance) but not *publicly
  verifiable* (a selector could publish an arbitrary 32 bytes as this round's seed and
  nobody could tell). A VRF proof closes that gap for a second key type, a second
  signature scheme and a curve dependency — against a selector who is already the
  principal that signs the roster and can therefore hand-pick the pool anyway.
  Asymmetric: the VRF would protect against a threat the trust model already accepted.
  Additive path, defined so it is not re-litigated: add `seed_proof` and
  `seed_kind: "hmac-sha256" | "ecvrf"` to the round record; `seed_kind` defaults to
  `hmac-sha256`; a policy may demand `ecvrf` when the selector is *not* the roster
  signer (a delegated selector), which is the only case where the gap is new.
* **drand / NIST beacon** — an honest-but-curious third party in the trust path,
  network-dependent, and still grindable by whoever gets to choose when to submit.
* **Seeding from a recent commit oid, timestamp, or anything the proposer controls**
  — the proposer then shops for a friendly roster by pushing commits. `head_oid` *is*
  an input, but it is not free: it must be the head of the change being verified, and
  the verdict binds to it (D4, grinding), so a shopped head only helps a change that
  is abandoned in favour of it.

**Consequences.** Zero new key material (D3 of ADR-0001 holds: one Ed25519 identity per
participant, ssh-agent signs everything); the secret is derived, so it cannot be
mis-backuped separately from the identity key it belongs to; and `gitiup select
--explain` can *prove* a selection to a stranger with three numbers (roster digest,
round inputs, seed).

## D3 — The algorithm, precisely

This is the normative text; [`fixtures/selection-v1/generate.py`](fixtures/selection-v1/generate.py)
is an executable copy of it, and `selection.json` is what it produces for the worked
example below. A Rust implementation that disagrees with the vectors is wrong, however
reasonable it looks.

### Inputs

| input | type | notes |
|-------|------|-------|
| `roster` | signed roster document (D8, "Roster format") | the *only* trust input; every candidate comes from it |
| `roster_epoch` | `u64` | must equal `roster.epoch`, else refuse |
| `roster_digest` | `sha256:` digest of the roster's canonical bytes | recomputed from the fetched bytes, then compared to the round record; a mismatch is exit 8 (ADR-0001 D7) |
| `change_id`, `head_oid`, `job_id` | strings | `job_id` identifies the matrix vector; it is opaque here but must be stable and store-assigned |
| `attempt` | `u64` | `0` is the first round; `≥1` are escalations (`giti-msi.8`) |
| `required_capabilities` | `{arch, ram_mb, disk_mb, image_digests[], sandboxes[], min_sandbox_level}` | derived from the job, not chosen by the verifier |
| `exclusions` | set of key ids | proposer family, quarantined keys, keys excluded by escalation |
| `policy` | `{n, required_agree, reserves, tier_floor, tier_caps, max_per_identity}` | published in the round record and covered by the selector's signature, so it cannot be quietly re-interpreted later |

### Derivation

```text
seed(k)   = HMAC-SHA256(selection_secret, round_id)                  # D2, one per round
score(K)  = SHA256("gitiup-round-1/score" || 0x00 || seed || 0x00 || utf8(K))
order     = candidates sorted by ( score as a 256-bit big-endian integer ASC,
                                   then utf8(key_id) bytes ASC )
```

`K` is the **worker key id** (the SSH fingerprint string, ADR-0001 D3), exactly as it
appears in the entry — no normalisation, no case folding, no trimming. Scores are
computed for *every* entry, including excluded ones, because the audit record is
supposed to explain the near-misses too.

A tie needs 2²⁵⁶ work to find, but the tie-break is still specified because an
unspecified tie-break is a fork: `key_id` ascending by UTF-8 bytes. Key ids are unique
inside one roster epoch (duplicates make the roster invalid), so this is a total order
and no implementation may rely on sort stability.

### Fill

```text
take, skip, selected = [], [], []
for entry in order:                       # single pass, in score order
    if excluded(entry): continue          # D7 filter order; already recorded
    if identity_count[entry.identity] >= policy.max_per_identity: continue
    if tier_count[entry.tier] >= policy.tier_caps[entry.tier]: continue
    push selected; identity_count[...] += 1; tier_count[...] += 1
    if len(selected) == policy.n: break
reserves = [ e for e in order if eligible(e) and e not in selected ]   # same order
```

An implementation that serves `--explain` keeps walking after `n` is reached so every
row gets a label (`take` / `skip:identity` / `skip:tier_cap`); the selected set is
identical either way, and the fixtures record every row.

* **Caps, not weights.** `tier_caps` is a *maximum seats per tier* map, and
  `max_per_identity` is a maximum seats per identity (default **1**). Caps are the
  only way a tier influences a selection: they can only *remove* candidates, never
  make one more likely beyond the cap. That is what keeps C5 true mechanically.
* **`reserves` is a listing, not a second decision.** Reassignment never re-seeds. To
  promote, the issuer re-runs `select` with `exclusions ∪ {voided keys}` (same round,
  same seed, same epoch) and takes the head of the new list. This is the whole reason
  promotion is safe: an issuer who could pick the substitute could steer the quorum.
  The published reserve list is an optimisation and may be longer than
  `policy.reserves`; it is *advice*, the re-run is the rule.
* **Insufficient is a verdict, not a shrug.** If fewer than `policy.n` candidates
  survive, `select` returns what it has and marks `sufficient: false`; `.7` reports
  `Insufficient` with the reason (`"3 eligible x86_64 identities, need 5"`) and the
  merge gate treats that as unsatisfied. Silently lowering N is the failure mode that
  makes a quorum look satisfied while it is one honest machine wide.

### Defaults

| knob | default | meaning |
|------|---------|---------|
| `n` | 5 | seats to fill per job |
| `required_agree` | 4 | matching `ResultDigest`s needed, from *distinct identities* |
| `reserves` | 2 | how many reserves the round record publishes |
| `tier_floor` | `anonymous` | tiers below the floor are not eligible at all |
| `tier_caps` | `trusted 1, endorsed 4, anonymous 1` | with n=5 this forces at least one non-owner box and at most one unvouched box |
| `max_per_identity` | 1 | ten machines, one vote (C5) |
| escalation `n` | 7 (`n + 2`), `required_agree` 5 | `giti-msi.8`, `attempt ≥ 1`, exclusions = divergent keys + proposer |
| `epoch_interval` | 7 d | D8 |
| `roster_valid_for` | 14 d | `valid_until_us = issued_at_us + 2 × epoch_interval` |

`tier_caps.trusted = 1` deserves a word, because it caps the *owner's own* machines:
an all-owner quorum verifies that the owner's laptop is honest, which a stranger
already had no reason to doubt and which is not what the epic is for.

### Auditing

`gitiup select --change <id> --job <id> --explain --json` must print: the round inputs,
the roster epoch and digest, the seed, and **one row per roster entry** with its score,
`eligible`/`excluded_by` (the first failing filter in D7's order), the greedy verdict
(`take` / `skip:identity` / `skip:tier_cap`) and its rank if selected. That table is
part of the contract, not a debug dump: it is what a reviewer who does not trust the
selector reads, and `selection.json` in the fixtures is its shape.

## D4 — The identity anchor: an owner-signed allowlist, one identity one vote

**Decision.**

1. **An identity is an anchor key.** No names, no directories, no usernames in the
   trust path. `identity` in a roster entry is a key id — usually the entry's own key
   id, or the fingerprint of a person's/organisation's primary key when the entry is
   one of their machines.
2. **A *family* is the set of entries whose `identity` is the same key id.** Naming one
   key id in `exclusions` excludes the whole family, which is what "the proposer's
   other keys are excluded too" (`giti-msi.3` AC) means mechanically. Self-declared
   family, so it is a *floor*, not a ceiling: two colluding humans with unlinked keys
   are two identities, and the honest sentence for that is "we made sybil cost a
   vouching decision", not "we defeated sybils".
3. **Membership is the owner's signature on a roster epoch.** A participant publishes a
   self-signed sign-up record (`gitiup participant register`); the owner either lists
   that entry in the next epoch or does not. That is the whole protocol.
4. **Vote weight is exactly one per identity, forever.** No knob, no policy for it:
   `required_agree` counts distinct identities (`.7` must dedup by `identity`, not by
   `key_id`, or one principal with two boxes is two votes).

**Why an allowlist, and what it is really buying.** The cost that matters is a human's
"yes". With the anchor in place, an attacker's share of a quorum is *the fraction of the
roster they personally got approved*, and every approved identity is attributable,
revocable, rate-limited (`giti-msi.9`) and — this is the part that bites — a permanent
record of their presence. Compare capture probabilities for `n=5, required_agree=4`
(the binomial `5f⁴ − 4f⁵`, i.e. at least four of five seats attacker-held, all
agreeing):

| attacker share of eligible identities | P(a given round is captured) | attempts to capture |
|--------------------------------------|------------------------------|---------------------|
| 5 % | 3.0 × 10⁻⁵ | ~33 000 |
| 10 % | 4.6 × 10⁻⁴ | ~2 200 |
| 20 % | 6.7 × 10⁻³ | ~150 |
| 33 % | 4.4 × 10⁻² | ~23 |
| 50 % | 1.9 × 10⁻¹ | ~5 |
| 66 % | 4.5 × 10⁻¹ | ~2 |

Read the last row as the reason this decision exists: **at sybil parity, four honest
verifiers out of five is a coin flip**, and "attempts" is not a small number of
changes — each new head oid is a fresh lottery (D2). The same table read the other way
gives the honest cost, which is the point: with 4 approved attacker identities in a
roster of 40 the capture probability is 36 / C(40,5) ≈ 5 × 10⁻⁵ per round, so the
attacker's problem is not compute, it is *getting four people to say yes and staying
undiscovered while four of them vote the same way*.

**Why not the alternatives.**

* **Proof-of-work / CPU-weighted identity** — makes one vote per *flop*, which is C5
  inverted: the network's voting power would track its attackers' hardware, and the
  volunteers whose machines gitiup is trying to recruit would be outranked by the ones
  with the biggest bill. It also spends the very resource the product is trying to
  economise, on a problem a signature already solves.
* **Staked or bonded identity** — a bond needs an asset, a slashing authority and a
  dispute-resolution process, i.e. a economy and a court, none of which a bucket-as-forge
  owner can operate. And it inverts the incentive that makes volunteering work: staking
  says "risk capital to speak", the allowlist says "be known". Left open as an option
  for a *delegated* selector or a cross-repo verifier pool, where a real bond could be
  meaningful; nothing in the round format prevents a `stake` field feeding `tier`.
* **Web of trust as the anchor** — rejected as *anchor*, adopted as *input* (D6). The
  fatal part is C2: WoT trust is per-observer, so two honest verifiers would compute
  two different rosters, two different orderings, and two quorums that never meet. It
  also bootstraps nobody (an empty graph vouches for no one) and turns trust into a
  graph traversal whose parameters are a second, unstated trust policy.
* **Permissionless (any key may attest; trust is inferred from history)** — this is the
  50 % row above, arrived at by default rather than by choice. Reputation-without-anchor
  has a cold-start hole: the first ten thousand keys all have a perfect record of
  nothing, and selection must pick from *something*.
* **Forge identity (GitHub logins, OIDC)** — the ticket's premise is that GitHub is the
  thing being routed around; an identity anchor that requires an account at the forge is
  the design contradicting itself. Note this is a *policy* the owner could make later
  (a sign-up carrying an OIDC token, checked by the owner offline), not something the
  format forbids.

**Consequences.** Membership decisions are a queue, so `.2` needs `list` and
`withdraw` to be as first-class as `register`; the owner key becomes the root of a
real trust root and its compromise is addressed in D9; and every doc that says
"5 random users" should say "5 randomly chosen from the owner-approved roster",
because the second half is where the security lives.

## D5 — Tiers, caps and what reputation may do

**Decision.** Three tiers, named and owned by the roster (not by the participant):

| tier | who is here | why the tier exists |
|------|-------------|---------------------|
| `trusted` | the owner's own keys and first-party CI | the fast path for an owner who wants their own hardware in the mix, and the only tier that can satisfy a `tier_floor: trusted` policy |
| `endorsed` | vouched: an endorsement record (D6), an organisation member, a verifier with a clean history the owner checked | the default home for a real contributor |
| `anonymous` | self-signed, no vouch, may be here for one repo only | cheap on-ramp, and the tier that proves the caps work |

Tier is used in exactly two places: the `tier_floor` filter (D7) and `tier_caps` (D3).
It is **not** a vote weight, and it does not appear in the score.

**Reputation is an exclusion, never a multiplier.** `.9`'s decay feeds the `exclusions`
set and (optionally) a demotion to `anonymous`. A continuous reputation weight would
make the reputation function the real trust anchor — unverifiable, per-owner,
different every week, and un-auditable in exactly the way D1 exists to prevent. A cap
you can read in a roster is a policy; a weight in a scoring formula is a rumour.

**Rejected**: one flat pool (then `required_agree: 4` silently means "four keys", and
the owner's three boxes plus a stranger's laptop is a quorum); self-declared tier
(tier is the owner's answer to "do I vouch", so letting a candidate set it is
meaningless); reputation-weighted selection and reputation-weighted voting (above).

## D6 — Endorsements: advice with a signature on it

**Decision.** An endorsement is a signed record — `kind: endorsement`, by an endorser
key, naming `identity`, a `claim` string ("co-maintainer of X since 2024", "signed 40
kernels"), and `issued_at_us` — stored at `kv/endorsement/<hex>` and pointed at by
`refs/gitiup/endorsement/<slot>`. The owner uses endorsements as **evidence for a tier
decision**. They are never an input to `select`, and the number of endorsements a key
has does not change its score.

**Why not the alternative (trust the graph at selection time).** Because of C2, and
because transitively-computed trust is a policy expressed as a traversal: `depth ≤ 2`,
"six hops from the owner", decay per hop — every verifier re-inventing a slightly
different answer, and every difference a different selection. Endorsements-as-advice
keeps the useful part (a human signal about a stranger) and throws away the part that
breaks reproducibility.

## D7 — Capabilities: cheap to claim, expensive to lie about

**Decision.** A roster entry carries `capabilities`
(`arch[]`, `ram_mb`, `disk_mb`, `image_cache[]`, `can_pull`, `sandboxes[]`,
`sandbox_level`) — the shape `giti-msi.2` registers. Eligibility is a filter, applied
in a **fixed order**, and the first failing filter is the recorded reason:

```text
window → tier_floor → excluded → arch → ram → disk → images → sandboxes → sandbox_level
```

| filter | rule |
|--------|------|
| `window` | `entry.epochs_valid.from ≤ epoch ≤ entry.epochs_valid.to` |
| `tier_floor` | `rank(entry.tier) ≥ rank(policy.tier_floor)` |
| `excluded` | `key_id ∈ exclusions` **or** `entry.identity ∈ exclusions` (the family rule, D4) |
| `arch` | `required.arch ∈ entry.capabilities.arch` |
| `ram` / `disk` | `entry.ram_mb ≥ required.ram_mb`, `entry.disk_mb ≥ required.disk_mb` |
| `images` | if `!entry.can_pull`: every `required.image_digests[]` ∈ `entry.image_cache[]` |
| `sandboxes` | `required.sandboxes ∩ entry.sandboxes ≠ ∅` |
| `sandbox_level` | `entry.sandbox_level ≥ required.min_sandbox_level` |

The order is normative so `--explain` output is reproducible (an entry failing two
filters must always print the same one). A matrix job with several required arches is
**one job per arch**, hence one round per arch with its own seed and its own roster
check — which is how "one verifier per required arch" happens without a special case
in the ordering.

**Claims are self-attested and checked afterwards.** Before selection, claiming 64 GB
of RAM costs nothing; after the run, the attestation carries an `EnvFingerprint`
(ADR-0001 D5: machine *class*, never machine identity), and `.7` compares it against
the requirement the round advertised. A claimed-x86_64 verifier that reports aarch64
has its attestation refused (`Insufficient` for that arch, exit 6) and the mismatch is
a divergence for `.9`'s decay — and, if it is a pattern, a roster demotion at the next
epoch. This is also why `sandbox_level` matters: a policy that requires `docker` and
gets `unshare` is a *policy refusal*, not a disagreement.

**Rejected.** *Probing candidates before selection* (a live reachability + capability
probe is a network dependency in the trust path, an SSRF/scan amplification tool
pointed at whoever the roster contains, and a liveness requirement on volunteers who
are explicitly allowed to be offline — C7). *Trusting claims with no after-check* (then
the filter is decoration). *No filter* (matrix jobs would be assigned to boxes that
cannot run them and `.7` would spend its time reporting `Insufficient`).

---

## Worked example

The vectors in [`fixtures/selection-v1/`](fixtures/selection-v1/) are this example:
roster epoch 41, twelve entries belonging to nine principals, job
`build/matrix/linux-x86_64` requiring `x86_64`, 8 GB RAM, 50 GB disk, a digest-pinned
base image, `docker` or `unshare` at level ≥ 1; proposer `brin`; `gus-pi` quarantined
from a previous divergent round; policy `n=5, required_agree=4, tier_caps={trusted 1,
endorsed 4, anonymous 1}, max_per_identity=1`.

Round inputs (the seed message, `0x00`-separated; `selection.json` shows it `/`-joined
for readability — **the separators are `0x00`, not `/`**):

```text
gitiup-round-1 | 41 | e3c05974…304a74 | chg-000000000000f00d
  | sha1:e255b091aabd7e443b5d2fbeb90bc9769d07cbeb | build/matrix/linux-x86_64 | 0

roster_digest  sha256:e3c05974bea30ff0c2ad3b9b8d4219b1d41a0c45a5e1c948c8455fdc4c304a74
policy_digest  sha256:97d8d4903559f88cf8fd6ec52f2ceb24abfccdb9c788122c2348d69dc7b8f572
seed           sha256:f6bb5ca427209de28c8cc1d75d74c75f9d5b2f090be21c14f64be1557790c7eb
```

Every entry is scored, then the caps are applied in one pass in score order:

| rank | machine | principal | tier | arch | ram_mb | disk_mb | sandbox | score (first 16 hex) | outcome |
|------|---------|-----------|------|------|--------|---------|---------|----------------------|---------|
| 1 | `ada-primary` | ada | trusted | x86_64 | 65536 | 1048576 | docker | `006e1c31d53d1dde…` | **selected (rank 1)** |
| — | `ada-arm` | ada | trusted | aarch64 | 32768 | 524288 | docker+unshare | `1827070d3aa4e933…` | arch |
| 2 | `ivy-lap` | ivy | anonymous | x86_64 | 16384 | 262144 | unshare | `6bf179ee12844d63…` | **selected (rank 2)** |
| 3 | `halo-ci` | halo | endorsed | x86_64 | 32768 | 524288 | docker | `6e130241117b5566…` | **selected (rank 3)** |
| 4 | `dara-build` | dara | endorsed | x86_64 | 65536 | 1048576 | docker+unshare | `8b7545e6ee725222…` | **selected (rank 4)** |
| — | `fur-arm` | fur | endorsed | aarch64 | 32768 | 262144 | docker | `9212e20789d189cb…` | arch |
| 5 | `chen-tower` | chen | endorsed | x86_64 | 16384 | 262144 | docker | `c69b16bb212b789a…` | **selected (rank 5)** |
| — | `chen-rack` | chen | endorsed | x86_64 | 16384 | 262144 | unshare | `c9e25c4c207095ea…` | reserve (`identity`) |
| — | `evel-laptop` | evel | anonymous | x86_64 | 8192 | 61440 | unshare | `cc31f0064e2e34c3…` | reserve (`tier_cap`) |
| — | `gus-pi` | gus | endorsed | x86_64 | 4096 | 61440 | unshare | `cd21f3160a618012…` | excluded |
| — | `brin-ci` | brin | trusted | x86_64 | 32768 | 524288 | docker | `de8588ca6514cc56…` | excluded |
| — | `evel-desktop` | evel | anonymous | x86_64 | 16384 | 262144 | unshare | `e10e178f63c5f9cd…` | reserve (`tier_cap`) |

What each row is teaching:

* **`brin-ci`** is eleventh of twelve by score, so it was not going to be picked here
  anyway — but the mechanism is the point: the proposer is excluded by naming `brin`'s
  principal key id *once*, so a second `brin` box added in a later epoch is excluded
  without anyone remembering to re-add it to a list.
* **`gus-pi`** fails both `excluded` (quarantined) and `ram`; the audit prints
  `excluded`, because `excluded` precedes `ram` in D7's order. Two implementations that
  disagree about which reason to print will disagree here.
* **`ada-arm`/`fur-arm`** are the aarch64 machines; they are eligible *for the arm job*,
  a different round with a different seed.
* **`chen-rack`** loses its seat to its own principal's other box
  (`max_per_identity = 1`), and **`evel-laptop`/`evel-desktop`** lose theirs to
  `ivy-lap` under `tier_caps.anonymous = 1`. All three are reserves, and
  `selection.json` records two promotions so both outcomes are visible: voiding
  `ivy-lap` (rank 2) re-runs the same round with one more exclusion and **promotes
  `evel-laptop`** — same seed, same epoch, its own slot `77a6a6d7…` and handle
  `e491db84…`, the ordering untouched. Voiding `ada-primary` (rank 1) finds **no
  substitute at all**: the identity and anonymous caps are already saturated, so the
  round comes up 4-of-5, which `giti-msi.7` calls `Insufficient` and `giti-msi.8`
  escalates instead of accepting a thinner quorum. Promotion is not a new decision, and
  a promotion that cannot happen is not papered over.
* Handles for the five selected (used by commit-reveal slots, D11): `3efb23dee98c0bfc…`,
  `ac5b5fdf0701cbed…`, `9f5f4092fc03330c…`, `4e8d1bdfe52aae41…`, `0398b5a3b5d47b32…`.

A uniformity check on the same code — 100 000 rounds over twelve *identical* candidates
with `n=5` — gives χ² = 4.22 on 11 df for selection counts (p > 0.01 below 24.725) and
χ² = 13.32 for rank-1 counts, min/max selection counts 41 487/41 922 against an
expectation of 41 667. The order favours nobody; `.3` should re-run this as a test with
its own implementation.

---

## D8 — Roster epochs and rotation

**Roster format** (`type: "gitiup-roster-1"`, canonical JSON per ADR-0001 D1, signed
through DSSE PAE with payload type `application/vnd.gitiup.roster+json` — the framing
ADR-0001 D1/D3 already define, applied to a new document type; no attestation bytes
change):

```text
{ schema_version: 1, type: "gitiup-roster-1",
  epoch: u64, prev_roster_digest: Digest, issued_at_us: i64, valid_until_us: i64,
  epoch_interval_us: i64,
  entries: [ { key_id, public_key, identity, tier,
               capabilities: { arch[], ram_mb, disk_mb, image_cache[], can_pull,
                               sandboxes[], sandbox_level },
               epochs_valid: { from, to },
               self_signature } ],          # key ownership proof, entry-scoped
  signatures: [ { key_id, sig } ] }         # the owner's approval of this epoch
```

Entries are sorted by `key_id`, `key_id` is unique per epoch (a duplicate invalidates
the roster), and there are no `null`s (ADR-0001 D1 rule 5) — an absent field is an
omitted key, so withdrawal is a removed entry plus a revocation record, never
`"revoked": null`. **`roster_digest` = SHA-256 of these exact canonical bytes.**
`gitiup participant register` produces a sign-up record (same entry shape, self-signed,
no owner signature) at `kv/signup/<hex>` + `refs/gitiup/signup/<slot>`; the owner's act
is to include it, not to approve it through a separate channel.

**Epoch rule.**

```text
next_epoch = max(prev_epoch + 1, floor(now_us / epoch_interval_us))
```

with `epoch_interval_us` published in the roster (default 604800 × 10⁶ = 7 days). The
first term makes epochs dense and monotone; the second makes them *time-derived*, so
"which epoch should be current at time T?" is computable without asking the owner, and
an owner who goes on holiday does not freeze the pool: the stale epoch simply stops
being acceptable once `valid_until_us` passes. `epoch` never encodes content (that is
what `roster_digest` is for), and `prev_roster_digest` chains epochs so the history is
walkable and a rewritten past epoch is a different digest.

**Every round pins `roster_epoch` *and* `roster_digest`.** This is the load-bearing
rule for C9: a round's selection is reproducible only against *that* roster, so the
owner swapping rosters mid-round changes the digest and every verifier refuses the
round (exit 8). It also makes the roster part of the seed message (D2), which is what
stops an owner from re-signing a friendlier roster under the same epoch number.

**Rotation.**

| event | mechanism | effective |
|-------|-----------|-----------|
| join | sign-up record → owner adds the entry, bumps the epoch | the new epoch |
| capacity/claim change (arch, ram, sandbox) | re-submit the entry; new epoch | the new epoch |
| leave (`gitiup participant withdraw`) | self-signed `withdraw` record naming `effective_epoch`; entry removed from that epoch onward | `effective_epoch`, default next epoch |
| owner inactivity | `valid_until_us = issued_at_us + 2 × epoch_interval`; new rounds refuse an expired roster | immediately at expiry |
| revocation | D9; **always** accompanied by an epoch bump | `effective_epoch` (may be the current one) |

**Anti-rollback.** A verifier persists the highest epoch it has accepted *per store*
and refuses a lower one for new rounds, with a hint to run `gitiup doctor`. An owner
with a valid key can always sign a *higher* epoch, so the guard never blocks a
legitimate move; what it blocks is forking — replaying an old, friendlier roster to a
verifier that has moved on, which is the difference between "the roster is a list" and
"the roster is a list the operator can rewrite per audience". The same guard makes an
epoch-number collision (`epoch` reused with different content) detectable, which the
`roster_digest` pin alone would only make *unexplainable*.

**Rejected.** *A mutable live list* (no epoch): nothing to pin, so a mid-round roster
edit silently changes who two verifiers select, and C9 dies — you cannot audit a
selection against a document that no longer exists. *Content hash as the epoch* (the
digest is already the identity): epochs are the *ordering and expiry* mechanism, and a
digest has no ordering and no clock; you would end up re-inventing counters on top of
it. *Epoch chosen by whoever opens the round freely* — that is a re-roll (D2).
*Epoch per revocation with no time floor* — an owner who stops bumping freezes the
trust list at whatever it was, and a stale key keeps being selected.

## D9 — Revocation, and jobs claimed by a key that got revoked mid-flight

**Decision.** Revocation is a signed record — `{ key_id, reason, effective_epoch,
revoked_at_us, issuer, note }` — at `kv/revocation/<hex>` with one CAS slot per key
under `refs/gitiup/revocation/<slot>`, mirrored by removing the entry from the next
roster epoch. Three facts, kept separate on purpose:

* the **roster epoch** says who *may be selected* for a round (and is pinned per round),
* the **revocation record** says *from when* a key is dead, and *why*,
* the **verdict/merge check** says what to do about claims made in between.

The `reason` decides the mid-flight question the ticket asks, because "the laptop was
sold" and "the key is stolen" are not the same emergency:

| `reason` | who may issue | new rounds | attestations already submitted in an earlier, pinned round | verdicts already recorded |
|----------|---------------|------------|------------------------------------------------------------|---------------------------|
| `retired` (key's own choice: laptop sold, busy) | the key itself or the owner | excluded from `effective_epoch` | **stand** — the key was validly selected when it signed | stand |
| `compromised` | the key itself, or the owner unilaterally | excluded immediately | **void** for rounds not yet settled; the round is re-evaluated and reserves are promoted (`.4`) to refill | re-checked; a verdict that needed that key becomes `Insufficient`, never silently `Verified` |
| `removed` (owner policy: bad history, policy breach) | owner | excluded from `effective_epoch` | stand, unless `bad_faith: true` | stand unless `bad_faith: true`, which voids everything the key signed after its last clean epoch |
| `superseded` (key rotated in place) | the key itself | old key out, new key in, same `identity` | stand | stand |

Rules that fall out of the matrix:

1. **A key can always revoke itself.** Otherwise losing a key means the only way to
   remove it is to ask nicely, which is not a revocation mechanism.
2. **Voiding is evaluated at verdict time, not remembered.** `.7` excludes keys whose
   revocation record has `revoked_at_us ≤ claimed_at_us` (or reason `compromised`, which
   voids regardless of timing) when it counts, so there is no window in which a stale
   verdict can be *minted*; a verdict already minted is an immutable signed record and
   is *re-checked*, not edited (D6 of ADR-0001: history is never rewritten).
3. **The merge gate re-checks.** `giti-kd4.5` re-evaluates revocation state and roster
   membership at merge time and refuses a merge whose counted keys are now revoked for
   cause. This is the "trusted moment" ADR-0001 D6 said the merge record has to supply:
   *at merge time, these keys were trusted and these attestations were fresh*.
4. **A round that loses keys to revocation escalates rather than relaxes.** If voiding
   drops the round below `required_agree`, reserves are promoted (D3: re-run with a
   longer exclusion list); if the pool cannot fill, `Insufficient` — not a lower bar.

**Suppression, stated honestly.** A hostile store operator can *withhold* a revocation
record, and no append-only CAS trick prevents a missing write. Two things bound the
damage: revocation forces an epoch bump, so the roster itself is the belt (a revoked key
is simply not in the epoch a round pinned); and because verifiers, selector and
proposer all publish signed records naming the epoch and digest, suppression requires
censoring *everybody*, which is a liveness attack on the store — visible — rather than a
soundness attack on the verdict. For owners who want third-party detection, the roster
epochs are anchorable with ADR-0001 D9's record (`kv/anchor/<hex>` over a roster
digest): an anchored epoch that the operator later denies is provable by a stranger.

## D10 — Records, namespaces and storage keys

**Decision.** All quorum state lives in the host, under the namespaces the host already
validates (`gitiup-host::Namespace`), so there is no second source of truth and no
broker (the store's CAS is the arbiter, per `giti-msi.4`).

```text
refs/gitiup/roster                              → roster of the current epoch
refs/gitiup/roster/<epoch:08x>                  → every epoch, retained ≥ 90 days
refs/gitiup/signup/<slot>                       → pending sign-up (Expect::Absent)
refs/gitiup/round/<change>/<job>/<attempt>      → round record (inputs + seed + selection)
refs/gitiup/job/<change>/<job>                  → job/lease record (giti-msi.4)
refs/gitiup/reveal/<change>/<job>/<slot>        → phase-1 commitment (one per key)
refs/gitiup/revealed/<change>/<job>/<slot>      → phase-2 reveal
refs/gitiup/revocation/<slot>                   → revocation record (one ref per key;
                                                  a later record moves it with Expect::Is)
refs/gitiup/endorsement/<slot>                  → endorsement records (D6)
refs/gitiup/verdict/<change>/<job>              → signed verdict (giti-msi.7)

kv/roster/<hex>       kv/job/<hex>        kv/round/<hex>      kv/policy/<hex>
kv/signup/<hex>       kv/reveal/<hex>     kv/revocation/<hex> kv/endorsement/<hex>
```

* `job`, `roster`, `policy` already exist as `Namespace` consts; `job` is **singular**
  (the `kv/jobs/...` shorthand in `giti-msi.4` means this). `round`, `reveal`,
  `revocation`, `signup`, `endorsement` are five new `Namespace::const_new` entries, to
  be added by the ticket that first writes them. Verdicts go under `policy`, whose
  documented meaning is already "quorum verdicts and policy documents".
* **Storage keys are hex slots, not fingerprints.** A key id is
  `SHA256:<base64 with +, / and no padding>`, which is illegal or hostile in ref names
  and in `Prefix`'s hex-only digest segment. The slot is the public, stable, one-way
  name:

  ```text
  slot(key_id) = hex( SHA256("gitiup-keyslot-1" || 0x00 || utf8(key_id)) )
  ```

  `gitiup participant list` and every human-facing listing prints both (`slot` and the
  `ssh-keygen -lf` fingerprint); machines use the slot.
* The `refs/**` writes that gate anything are CAS writes (`Expect::Absent` for a slot,
  `Expect::Is` for a roster move), because "a lost update here is a lost merge" is
  exactly the rule the host abstraction already states.
* Retention: `refs/gitiup/roster/<epoch>` ≥ 90 days, because a verdict audit must be
  able to fetch the roster a round pinned (C9). Old attestations are `.5`'s business;
  rosters are this epic's, and are small.

## D11 — What is secret, until when, and what is not

**Decision.** Two different secrets get conflated in one sentence, so split them:

* **Unguessable-before-the-round: yes, permanently.** Nobody can compute a round's seed
  before the selector publishes it, so nobody can pre-arrange, pre-bribe or pre-DoS the
  chosen five on a change that has not been opened yet (D2).
* **Hidden-after-the-round-opens: no, and not attempted in v1.** The round record
  carries the seed and the ordered selection, and the store is public to anyone who can
  read it, so from advertisement onward the selected set is public.

The ticket's phrasing ("preimage stays secret until jobs are claimed") describes
something a public content-addressed store **cannot** do, and it is worth writing down
why: for a verifier to *learn* it was selected, it must read something public. Keying
the slots by key id leaks the set; keying them by a pseudonym derived from the seed
means nobody can find their slot without the seed — including the selected verifiers.
Only encryption to the selected keys, or a private channel to each of them, breaks that
circle, and a private channel is the broker this design refuses (D1). What is left over
after commit-reveal is a *window of minutes* between advertisement and the first
commitment — and the same identities are public again from the first reveal onward.

So the secrecy budget goes where it actually buys something, and the residual risk
(targeted DoS or exploit of a freshly-published verifier set) is met by cheaper means:
reserve promotion (a knocked-out verifier costs the round a delay, not its quorum),
submission jitter and lease TTLs in `.4`, and the rule that the store never carries a
verifier's address — a roster entry is a key and some capabilities, nothing more.

**Handles, specified but off.** For anyone who later decides the window matters, the
format already has the pieces, so it is a switch and not a re-decision:

```text
handle(seed, key_id) = first 16 bytes of HMAC-SHA256(key = seed,
                          msg = "gitiup-round-1/handle" || 0x00 || utf8(key_id))
```

`handle` is unlinkable to a key without the seed, so slots can be keyed by handle and
the selection stays closed until the seed is published, and "exactly one commitment per
key" is enforced by the CAS slot exactly as with `slot`. Using it needs a sealed grant
(the selector delivering the seed to the selected keys), which needs X25519-from-Ed25519
and an AEAD in the trust path — a new key derivation for every participant and a new
crypto surface, paid for a few minutes of untargetability. `round.reveal_mode = "open"`
(v1, default) | `"sealed"` (additive; `gitiup select` must refuse a mode it does not
implement rather than treat it as `open`). Commitment *anonymity* is not the goal of
commit-reveal in `.6` — independence is, and independence comes from committing to the
digest before anyone else reveals theirs.

**What a verifier checks before running a stranger's job** (fail-closed; all of it is
local plus two fetches):

1. fetch `refs/gitiup/roster/<round.roster_epoch>`, verify the owner signature(s),
   re-hash and compare to `round.roster_digest`;
2. epoch ≥ highest epoch ever seen for this store (D8), `now ≤ valid_until_us`;
3. the round record is signed by an accepted selector key, and its inputs recompute to
   the round id it claims;
4. recompute the selection: the published list must match byte-for-byte, and my key id
   must be in `selected` (a reserve does nothing but wait);
5. my commitment slot `refs/gitiup/reveal/<change>/<job>/<my slot>` is free
   (`Expect::Absent`);
6. the attestation carries `claims.verifier_challenge` bound to this round and
   `not_after_us` at the job deadline (ADR-0001 D4/D6), so it cannot be replayed into
   another round.

A verifier that cannot fetch the roster does not run the job. Running on a cached
roster is how a stale key ends up voting, and `--offline` in `.5` means "queue it", not
"trust my last known world".

---

## Threats, and which decision closes each one

The threat model document `giti-msi.9` must publish is this table expanded with the
exploit test that proves each row; it is here so `.9` inherits the enumeration instead
of inventing one. "Ticket" is where the mitigation is implemented and tested.

| threat | mitigation | ticket |
|--------|----------|-------|
| **Sybil flood** — attacker brings unlimited keys | membership costs an owner approval; one identity one vote (`max_per_identity`, `required_agree` counts identities); capture probability is a function of *approved* share (D4 table) | `.2`, `.7`, `.9` |
| **Selection farming** — attacker computes selections in advance to pick favourable changes, or bribe/DoS known verifiers | seed is keyed and undecidable before publication (D2); the exclusion set and policy are published with the round so a "convenient" roster is visible | `.3`, `.9` |
| **Selector grinding** — the chooser re-rolls until it likes the roster | the seed is derived, not chosen (D2); the only levers left are a new change id or a new head oid, both public, rate-limited and verdict-bound | `.3`, `.9` |
| **Proposer self-attestation / voting through their own other machines** | exclusion matches on `identity`, not just `key_id` (D4, D7); the change's committer keys join the exclusion set | `.3`, `.9` |
| **Copy-cat convergence** — first fast verifier sets the answer, others copy | commit-reveal of the digest before reveal (`.6`), which is why commitment slots exist (D10) | `.6` |
| **Roster rollback / fork** — replay an old friendly roster to a chosen audience | monotonic epoch + highest-seen guard (D8), round pins epoch *and* digest | `.2`, `.7` |
| **Roster/revocation suppression by the store operator** | epoch bump carries the revocation; verifiers publish their own records naming the epoch; optional log anchor (D9, ADR-0001 D9). Bounded as a liveness attack, stated as such | `.2`, `.9` |
| **Targeted attack on the selected verifiers** | selection is public only from advertisement; reserves + lease expiry mean a knocked-out verifier costs latency not soundness; no addresses in the store; sealed handles if it ever matters (D11) | `.4`, `.5` |
| **Capability lying** — claim `docker`/x86_64/64 GB to get seats | ordered pre-filter (D7) plus post-check against the signed `EnvFingerprint`; a mismatch is a refused attestation and a reputation event | `.7`, `.9` |
| **Reputation poisoning** — flapping, strategic divergence | reputation may only *exclude* or *demote*, never weight (D5); decay is in `.9` | `.9` |
| **Vote laundering via a friend's key** | endorsements grant no weight (D6); a colluding pair is two identities and the honest claim is only that each cost a human "yes" | `.9` |
| **Resource abuse via expensive workflows / volunteer swamping** | fan-out caps, per-key and per-change rate limits, capacity claims in the roster, lease TTLs | `.4`, `.9`, `giti-bgy.2` |
| **Exfiltration / parsing bombs through attestation fields** | ADR-0001 D7 limits and `deny_unknown_fields`; roster fields likewise bounded (entries ≤ 4096, key ids fixed shape, `annotations` strings only) | `.2`, `.9` |
| **Secrets reaching volunteers** | never shipped, by construction (`giti-bgy.3`); the round record names *secret names*, never values (ADR-0001 D4) | `giti-bgy.3` |
| **Compromised owner/selector key** | the roster is the trust root and the owner can merge anything anyway (see "what a quorum does not prove"), but a forged *roster epoch* is detectable via the chain + anchoring, and epochs already used are pinned by public round/verdict records | `.2`, `giti-kd4.5` |

### What a quorum does not prove

Three limits, said here rather than discovered later:

* **Fidelity, not safety.** Four verifiers agreeing on a `ResultDigest` proves the
  workflow ran the same way in four places. A change that reproducibly exfiltrates
  something still gets `Verified`. Reviewing what the workflow *does* is a different
  control (`giti-bgy.*` reduces what a run can reach; a human reviews the diff).
* **The owner is not an adversary in their own store.** They approve the roster and they
  merge. The quorum's value against a *compromised* store is bounded and comes from the
  roster chain, the anchors and the fact that a fabricated verdict needs the roster keys'
  signatures, not the owner's.
* **Independence has a floor of "different humans".** Two boxes on one desk are one
  identity (D4) and that is the strongest statement the format can make.

---

## Consequences

**Unblocked, with the specific thing each ticket now inherits.**

* `.2` gets the roster document (types, fields, entry self-signature, owner signature,
  `epochs_valid`), the `gitiup participant` record shapes, the namespace/ref table
  (D10), and the epoch rule including the anti-rollback guard.
* `.3` gets a function with a byte-for-byte reference vector and a χ² baseline, the
  exclusion semantics (family = `identity`), the Insufficient rule, and the
  `--explain` output contract.
* `.4` gets a deterministic promotion rule (re-run with a longer exclusion list, never a
  new seed) and the fact that a job may be addressed by slot.
* `.5` gets the six-step fail-closed participation checklist (D11, last list).
* `.6` gets hex slots for one-commitment-per-key, the handle construction for the sealed
  mode, and the reason `<key>` in its description means `<slot>`.
* `.7` gets the policy defaults, `required_agree` over *identities*, the void-at-verdict
  rules, and the escalation shape (`attempt ≥ 1`, `n + 2`, exclusions = divergent keys).
* `.8` gets escalation as a *round attempt* with an exclusion list rather than a new
  mechanism.
* `.9` gets the threat enumeration to expand into its document, and the rule that
  reputation may only exclude.
* `giti-kd4.5` gets the merge-time re-check duty and its justification.

**Costs.** The owner key is now a real trust root and must be operated like one (its
compromise is "the attacker can pick the jury", which is a serious but not unlimited
power — see above). Every round adds two store reads for a verifier (roster + round) and
one roster re-fetch per epoch, which is negligible but must be *fetched*, so a store
outage pauses verification rather than degrading it into guessing. Caps make the
selection slightly non-uniform by construction (that is what a cap *is*), so `.3`'s
uniformity test has to run on a homogeneous roster with caps off — as the fixture
does — and separately test that each cap bites. And there is a genuine new document
to get right: a roster that fails to canonicalise, chain or pin correctly is a roster
nobody can audit, which is why the vectors exist before the code does.

**Explicitly out of scope, decided elsewhere.** Commit-reveal mechanics and the reveal
window (`giti-msi.6`), lease/TTL/fan-out/back-pressure (`giti-msi.4`), verdict
computation and caching (`giti-msi.7`), disagreement and disputes (`giti-msi.8`),
rate limits and decay specifics (`giti-msi.9`), what the sandbox may reach
(`giti-bgy.*`), attestation storage and GC (`giti-1rs.5`), key storage and ssh-agent
plumbing (`giti-1rs.6`), and how a merge gate consumes a verdict (`giti-kd4.5`).

**How we change our minds.** The domain strings (`gitiup-round-1` — which is also the
first field of the seed message — plus its `/score`, `/handle` and `/secret` labels, and
`gitiup-keyslot-1`) are part of the
hashes, so changing the ordering, the score
construction or the seed message re-names every past selection: that is
`round_kind = "gitiup-round-2"` plus new fixtures, never an edit (the same rule
ADR-0001 D8 states for the canonicaliser). Additive in place: new `policy` knobs, new
`capabilities` fields, `seed_kind`/`seed_proof` (D2), `reveal_mode = "sealed"` (D11),
new revocation `reason` values. A reader must refuse a `round_kind`, `type` or
`reveal_mode` it does not know rather than guess — no leniency, no silent default.

**References.** Implementation of the format primitives:
[`crates/gitiup-attest`](../../crates/gitiup-attest/README.md). Store contracts and
namespaces: [host abstraction](../host-abstraction.md). What the tiers mean:
[provenance tiers](../provenance-tiers.md). Reference vectors:
[`fixtures/selection-v1/`](fixtures/selection-v1/). Registry of ADRs:
[`docs/adr/README.md`](README.md).

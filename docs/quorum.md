# The quorum verification network

Status: **the mechanism exists, the roster and selection commands exist, and a submitted
change opens its own rounds** —
`gitiup participant register|withdraw|list|verify-roster` (plus the owner's `approve` and
`revoke`) and `gitiup select`, which opens a round or re-derives a published one; and
`gitiup change submit`, which does that for every job of a change whose published policy
asks for a quorum ([`quorum`](../crates/gitiup/src/quorum.rs)). The
store side of jobs and leases exists too — an advertised round, a paged listing of open
rounds, and TTL leases on seats ([`store`](../crates/gitiup-quorum/src/store.rs),
[`job`](../crates/gitiup-quorum/src/job.rs)) — and so do both ends of the loop: `gitiup
work` serves a seat end to end, and `gitiup quorum verdict` tallies one, publishes it and
exits on it. Dispute reports and bounded escalation are the open tickets.
Decided by [ADR-0002](adr/0002-roster-verifier-selection-and-sybil-resistance.md),
implemented in [`crates/gitiup-quorum`](../crates/gitiup-quorum), attested in the format
[ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md) decides.

For each change, N registered participants (five by default) are chosen, run the
workflows independently on their own machines, and sign the resulting `ResultDigest`.
The owner trusts the result when enough distinct identities agree. **Both halves are
opt-in**: running a verifier is a volunteer's decision, requiring a quorum is an owner's
decision, and neither changes what a plain local run produces.

```text
 gitiup participant register ─┐
                              │ (the owner's decision, once per epoch)
                              ▼
                       Roster (signed epoch) ─────────┐
                                                      │ pins epoch + digest
 gitiup change submit ──► RoundInputs ──► Round ──────┤
        (selector: seed = HMAC(inputs))               │
                              │                       │
              selection = order ∘ caps (auditable)    ▼
                              ▼                  verdict: verified/failed/insufficient
                    five volunteers ──► one attestation per seat, in CAS
```

## What lives where

| module | the decision it implements |
|--------|----------------------------|
| [`derive`](../crates/gitiup-quorum/src/derive.rs) | the domain separation: round id message, seed, score, handle, key slot, per-key challenge. All of it HMAC-SHA-256 over a versioned domain string. |
| [`roster`](../crates/gitiup-quorum/src/roster.rs) | the trust list: epochs, key-ownership proofs, sign-ups, withdrawals, revocations, one-identity-one-vote. |
| [`capability`](../crates/gitiup-quorum/src/capability.rs) | the eligibility filters and their order — the order is a published decision, because it decides which reason a refusal names. |
| [`select`](../crates/gitiup-quorum/src/select.rs) | the selection proper: score ordering, the greedy pass over tier and identity caps, reserves, promotion, the proposer-family rule (`proposer_family`, `RoundInputs::excluding`, `ProposerExclusion`), and `explain()`, the audit trail. |
| [`round`](../crates/gitiup-quorum/src/round.rs) | the signed record that pins a round to a roster epoch and digest and publishes the seats and the seed. |
| [`job`](../crates/gitiup-quorum/src/job.rs) | what an advertisement and a lease *are*: the seat list copied out of a round, a TTL that dies, a steal that is recorded. |
| [`store`](../crates/gitiup-quorum/src/store.rs) | the ref names and CAS writes. The store is the broker: compare-and-swap does the locking, so there is no coordinator to bribe. |
| [`gate`](../crates/gitiup-quorum/src/gate.rs) | admission at submission time: is *this key* approved, for *this epoch*, in *this round*, and is *this document* its own? Every refusal has its own code. |
| [`participate`](../crates/gitiup-quorum/src/participate.rs) | the volunteer's fail-closed checklist (ADR-0002 D11). |
| [`verdict`](../crates/gitiup-quorum/src/verdict.rs) | the tally: `verified` / `failed` / `insufficient`, every rejection with its reason, and the divergent results. |
| [`ledger`](../crates/gitiup-quorum/src/ledger.rs) | the volunteer's memory of the highest epoch a store has offered — the rollback guard. |

## The four risks and the mechanism that closes each

| risk | how it is closed |
|------|------------------|
| targeted verifier / selection bias | the seed is `HMAC-SHA256(secret, round_id_fields)` and is **published** with the round, so anyone can re-derive the scores and check the published seats are the derived ones. `Round::verify` re-runs the selection and refuses a record whose seats were edited. Anyone holding the secret can pick the pool in advance, which is why the secret is the deployment's own and rotates with its key. |
| copycat verifiers | each seat has a slot (`key_slot(key_id)`, store-assigned and unguessable) and each attestation must carry `challenge = HMAC(seed ‖ 0x00 ‖ key_id)`, so an answer cannot be replayed into another round. A `sealed` round splits that same slot into a commitment and a reveal ([giti-p1.6](../README.md)), so a seat cannot read the running answer before it fixes its own — [committing before revealing](#committing-before-revealing-a-sealed-round) says what that buys and what it does not. |
| sybils and ballot stuffing | membership costs an owner signature and a key-ownership proof, one *identity* casts one vote whatever it controls, the proposer's family is excluded, and the caps limit each tier. The cost model is in ADR-0002 D4–D7; `max_per_identity` is enforced in the tally as well as in selection, so a roster cannot smuggle two boxes into two votes. |
| stale or replayed attestations | the round pins the head oid, the attestation binds the round's challenge, freshness is evaluated at verdict time, and revocation is evaluated there too — a `compromised` key voids what it signed *earlier*, which is the only useful reading of a stolen key. |

Three more, because a mechanism that can be silently rolled back is a mechanism that can be
switched off:

* **roster rollback** — epochs are dense and time-derived, every round pins epoch *and*
  digest, and a volunteer that has seen epoch 41 refuses a round pinned to epoch 40
  ([`RosterLedger`](../crates/gitiup-quorum/src/ledger.rs)).
* **an offer that cannot be met** — a volunteer checks the whole invitation before it
  runs anything ([`check_invitation`](../crates/gitiup-quorum/src/participate.rs)), and
  step 5 is "my slot is still free", enforced by a CAS write rather than by asking.
* **a seat blacked out by a volunteer that died** — the lease on a seat carries a TTL, so
  the volunteer that was rebooted mid-job costs the round a renewal window and not an hour
  ([`job`](../crates/gitiup-quorum/src/job.rs)); the lease is stealable when it dies and
  the steal is recorded, and it never gates admission, so the *slow* holder that finishes
  first still counts. A lease is coordination; the seat is the authority.

## Verdict semantics

`verified` requires `required_agree` *distinct identities* signing the same
`ResultDigest`, each of them having survived selection, freshness, revocation and the
capability post-check. Everything else is a sentence about why not:

| state | when | mergeable |
|-------|------|-----------|
| `verified` | the threshold was reached | yes |
| `failed` | the threshold cannot be reached because results disagree — the losing digests are published as evidence, not swallowed | no |
| `insufficient` | the seats were not filled, or those who voted were too few, or all agreed but not enough of them | no |

With the defaults (5 seats, 4 agreements) a single honest outlier — a flaky test, a
different CPU, a slow mirror — does not sink a change; the dissent is recorded in
`divergent` for the escalation path (giti-msi.8). An owner who wants unanimity raises
`required_agree` to 5 in the round's policy and gets `failed` on the same evidence.
Silence is never reported as failure: "nobody turned up" is `insufficient`, and that is a
different operational signal from "the machines disagree".

Refusals keep the exit codes of [ADR-0001 D7](adr/0001-attestation-encoding-hash-and-signature.md)
that the format crate already uses — `6` refused (policy, an unparseable or untrusted
record), `7` a signature that does not verify, `8` bytes that are not their own canonical
form, `3` an unreachable store — so a script branches on the same number whether the
refusal came from a quorum check or from `gitiup verify attestation`.

## Registering, approving, and refusing

Membership is four command lines and no protocol. A volunteer proves a key and describes
a machine; the owner decides whether that is on the roster and what it is worth; the
store refuses anything nobody approved.

```sh
# volunteer: claim what the box can actually do, signed by the key being registered
gitiup participant register --ram-mb 32768 --disk-mb 262144 \
    --sandbox docker --sandbox-level 2 --arch x86_64 --out signup.json

# owner: carry it into a new epoch, vouch for it, publish
gitiup participant approve --from signup.json --tier endorsed --store ./store --publish

# anyone: read the epoch the owner signed, and what each entry qualifies for
gitiup participant list --store ./store --require-arch x86_64 --require-ram-mb 16384
gitiup participant verify-roster --store ./store

# volunteer: leave from an epoch you name (default: the next one)
gitiup participant withdraw --store ./store --publish

# owner: a key is dead, and the reason says what that voids; the epoch bump that always
# accompanies a revocation is the next `approve`
gitiup participant revoke <key-id> --reason compromised --store ./store --publish
```

Four decisions live in this surface, and each is a refusal somewhere rather than a rule in
prose:

* **a sign-up claims capabilities, never a tier.** The entry's self-signature is a key
  ownership proof, so it covers the key, the principal and the capability claim — and
  deliberately *not* `tier`, which is the owner's statement about the box
  ([D5](adr/0002-roster-verifier-selection-and-sybil-resistance.md)). A volunteer that
  could grade itself would be a roster with no owner in it; an owner who retypes a
  claimed figure breaks the proof and is refused.
* **nothing is published unless the flag says so.** Every record command writes to
  `--out <path|->`; only `--publish` touches a store. An epoch approved by accident is a
  trust change.
* **a roster is only a trust root after it is checked.** `list` and `verify-roster` run
  `Roster::verify` first — canonical bytes, every ownership proof, a trusted owner
  signature, not expired — against the owners named by `--owner`, and say in the output
  where that trust came from.
* **the store refuses unapproved submissions, with a code that says which kind of
  "not approved".** [`gate::admit`](../crates/gitiup-quorum/src/gate.rs) runs before the
  slot write, in a fixed order, and each refusal names itself: `unsigned`,
  `many_signers`, `bad_signature`, `roster_expired`, `not_in_roster`, `expired`,
  `revoked`, `not_selected`, `wrong_commit`, `wrong_round`. `not_in_roster` ("the owner
  never said yes") and `expired` ("said yes for epochs that have passed") are different
  advice to a volunteer, so they are different codes; and `bad_signature` is checked
  before any lookup, so claiming an approved key id is a signature failure and not a
  policy accident. `store::publish_attestation` is the entry point that does this, and the
  same tokens reappear in a verdict's `rejected` list: a refusal at the door and a
  rejection at the tally have to be one vocabulary.

## Where the documents live in the store

```
refs/gitiup/roster                      the epoch in force
refs/gitiup/roster/<epoch:08x>          every epoch ever published (the audit trail)
refs/gitiup/signup/<slot>               a volunteer's application, signed by its key
refs/gitiup/withdrawal/<slot>           a volunteer leaving, signed by its key
refs/gitiup/revocation/<slot>           the owner's revocation (or the key's own)
refs/gitiup/round/<change>/<job>/<attempt>  the round record
refs/gitiup/job/<change>/<job>          the advertisement: this job is still open
refs/gitiup/lease/<change>/<job>/<slot> one volunteer's TTL claim on one seat
refs/gitiup/commit/<change>/<job>/<slot>    phase 1 of a sealed round: H(bytes ‖ slot ‖ challenge)
refs/gitiup/reveal/<change>/<job>/<slot>    one attestation per seat, claimed CAS
refs/gitiup/verdict/<change>/<job>      the owner's verdict
```

`<slot>` is `hex(SHA256("gitiup-keyslot-1" ‖ 0x00 ‖ key_id))`, because a key id is
`SHA256:<base64>`, which is hostile in a ref name; every human-facing listing prints the
slot and the fingerprint side by side (`gitiup participant list --json` prints both). The
blobs live in the host's content-addressed store under the namespace the ref names —
`kv/roster/<hex>` on a bucket or a git host, `cas/roster/<hex>` in the reference `fs`
host: one namespace per record class, one layout per host, see
[host abstraction](host-abstraction.md).

Every one of those is a CAS write, so a double submission is *refused* rather than
counted twice, and a roster rewrite produces a different digest rather than a quiet
edit. See [host abstraction](host-abstraction.md) for the store contracts this relies on.

One divergence from [ADR-0002 D10](adr/0002-roster-verifier-selection-and-sybil-resistance.md),
which sketches `refs/gitiup/job/<change>/<job>` as one "job/lease record": the lease got
its own ref, one per **seat**, because a lease that is worth having is one two volunteers
can race for without touching each other, and a single ref per job would make every
heartbeat on every seat contend for one CAS. The advertisement keeps the ADR's path.

## Finding work: the advertisement and the lease on a seat

A round record answers "who was picked for this job". A volunteer has the inverse
question — "what wants doing" — and there is no coordinator to ask, so the store carries
the inverse index as a ref: `store::advertise_round` publishes an
[`Advertisement`](../crates/gitiup-quorum/src/job.rs) at `refs/gitiup/job/<change>/<job>`,
naming the round, its attempt, and the seats it still wants. Listing that one prefix,
paged from `store::Cursor::START`, **is** "rounds that still need filling"
([`store::open_rounds`](../crates/gitiup-quorum/src/store.rs)); the cost is one bounded
ref query plus one blob per row returned, which is what a poll that runs every minute
from a few hundred machines needs. Listing `refs/gitiup/**` is not the way: it would show
a stranger every roster epoch, revocation and submission slot as if they were branches,
and get slower as the store fills.

An advertisement is an **index, not an authority**. It is copied from a round and it is
believed through it: fetch the round, [`Round::verify`](../crates/gitiup-quorum/src/round.rs),
[`Advertisement::matches`](../crates/gitiup-quorum/src/job.rs), and only then run anything.
It is signed anyway (by a key that signed the round — `store::advertise_round` enforces
that, so the noticeboard cannot carry someone else's invitation) because the cheap check
should be possible even when the expensive one is still to come. It carries the seats,
which is what makes `store::open_rounds_for(key)` free, and that is honest in both reveal
modes: a sealed round hides *each seat's answer until it is committed*, not the seat list
— the seats were never secret, because the advertisement is copied from a round whose
seats become public the moment it is advertised ([ADR-0002 D11](adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
An advertisement that names a `reveal_mode` this build cannot enforce is refused by the
listing, so a volunteer never takes work it would do wrongly
([commit-reveal](#committing-before-revealing-a-sealed-round)).
A round that could not fill its seats is not advertised either — a quorum that cannot
happen is `insufficient`, and recruiting volunteers for it is a worse answer than
escalating.

Who publishes the advertisement is the other half of "automatic": `gitiup change submit`
advertises every round it opens that filled its seats
([below](#submitting-opens-the-rounds-gitiup-change-submit)), so a volunteer polling
`refs/gitiup/job` sees the work a change created without anybody having to run a second
command.

A **lease** is the second half: `store::claim_lease` puts `{holder, acquired_at, ttl,
attempt}` at `refs/gitiup/lease/<change>/<job>/<slot>` so two volunteers do not burn two
machines on one seat. It is claimed by CAS, refused while alive with the holder's name
and the TTL left, **stealable once expired, and the steal is recorded** in the new lease's
`taken` trail; renewal and release are CAS too, and only the holder may do either.
Three things it is not:

* **not a lock**, because it expires: a volunteer that was rebooted mid-job costs the seat
  a TTL (15 minutes by default, one hour maximum), not an hour of nobody daring;
* **not permission**, because [`gate::admit`](../crates/gitiup-quorum/src/gate.rs) has
  never heard of leases: the **seat** is the authority, so the slow original holder that
  finishes first still gets its attestation admitted and counted — that is the difference
  between advice and a lock nobody can release, and
  [`tests/job_leases.rs`](../crates/gitiup-quorum/tests/job_leases.rs) enforces it in both
  directions (a stolen lease does not displace the holder's work; holding a lease grants
  a key with no seat exactly nothing);
* **not owner-approved**, because a lease is a key's claim about itself: it is signed by
  its holder alone, and `Lease::verify` checks that signature against the holder field and
  asks nobody else.

A lease is per **attempt**: escalating to `attempt + 1` ends the leases the dead attempt
handed out, and taking over such a seat is recorded the same way a timeout is.

## Serving it: `gitiup work`

Everything above is a volunteer's *input*. [`gitiup work`](../crates/gitiup/src/work.rs)
is the loop that turns an input into a signed attestation in a seat, so that volunteering
means running one command on a box and leaving it running:

```sh
# one pass over the queue, then exit — a cron entry, or a Tuesday afternoon
gitiup work --store ./store --key volunteer --once

# what this key is being asked for, with nothing executed, nothing leased, nothing written
gitiup work --store ./store --key volunteer --dry-run --json

# a service: keep polling, and do not take on more than one job per pass
gitiup work --store ./store --key volunteer --watch 30s --max-jobs 1
```

For each advertisement addressed to this key (`store::open_rounds_for`), one pass:

1. **believe the invitation.** Fetch the round behind the advertisement, verify it, and
   check [`Advertisement::matches`](../crates/gitiup-quorum/src/job.rs) still holds. An
   index that has fallen behind its round is a refusal with that round named, never a
   hint; a store that cannot be read at all stops the pass rather than being stepped over
   as an empty evening.
2. **run [`participate::check_invitation`](../crates/gitiup-quorum/src/participate.rs)
   end to end** against the roster epoch the *round* pinned: the key is on the roster and
   is not revoked, the epoch is at least this store's highest-seen one, the machine still
   meets the round's `requirements`, and the slot is this key's. The capability half is
   **measured here and now** (`gitiup env`), not repeated from what the roster remembers
   this box used to be: a volunteer that has since had its RAM halved is refused by the
   round's own numbers, and the measurement is printed either way. The epoch it just
   believed goes into the anti-rollback ledger (`--ledger`, one file per store, and
   `--no-ledger` skips it and says so in the output).
3. **lease the seat** (`store::claim_lease`), so a second volunteer on a second machine
   sees the seat is taken. A live lease held by somebody else is a refusal naming the
   holder and the TTL left — and `--dry-run` reports it too, without taking one.
4. **plan the job** with [`gitiup-run`](../crates/gitiup-run/src/lib.rs)'s own planner,
   from the workflow in the checkout, matching the round's `job_id` (matrix arms included)
   in a checkout whose `HEAD` *is* the round's head OID. A checkout on another commit is
   refused outright: an attestation of a run of a commit is not evidence about a commit.
5. **execute it inside a sandbox** that [`admit`](../crates/gitiup-sandbox/src/lib.rs)
   will accept for `Purpose::Quorum` — the ladder (`docker`, `podman`, `bwrap`, `landlock`,
   then refusal), never `plain` or an opt-in-only backend for a stranger's code, and the
   refusal names the ladder it tried. `SOURCE_DATE_EPOCH` is pinned before the first step
   (default `0`, because an unpinned local clock is not reproducible across volunteers;
   `--source-date-epoch` overrides, and the pin is recorded in the manifest's annotations).
6. **digest** with `gitiup_run::manifest_for`, the same call `gitiup run --attest` makes,
   and bind the round's challenge into `verifier_challenge` so the attestation is about
   *this* round and cannot be carried to another.
7. **sign and publish** through `store::publish_submission` into the seat the
   advertisement named — the slot is chosen by the round, not by the volunteer — and
   release the lease. On a `sealed` round this is two writes in a fixed order: the
   commitment first, then the bytes it commits to ([below](#committing-before-revealing-a-sealed-round)).

Two refusals are worth naming because they are the ones a volunteer expects to argue with.
A **build that fails is served, not skipped**: exit 3 is signed and published like any
other result, because a quorum agrees on *what happened* and a green tick is not the
product. And **`--dry-run` is not a lie**: it simulates the steps
(`gitiup_run::simulate_report`), digests and signs the result, and publishes nothing and
leases nothing — the tier of what it prints is `simulated`, so nobody mistakes the
rehearsal for a vote.

The pass reports every round it looked at, with the state it reached (`refused`,
`simulated`, `published`) and its own exit code, and exits with the worst of them: 0
served or nothing to do, 6 refused, 7 a signature that does not verify, 8 bytes that are
not their canonical form. `--json` prints one line for a supervisor; the text report
leads with the store, the key, what makes it trusted, the sandbox line, the ledger state,
and what this box measured — because the first question after a refusal is always "on
which machine, doing what".

What `work` has no flag for is deliberate: the quorum size, the architecture, the tier it
votes at. Those belong to the round and to the owner's policy; a volunteer that could
restate them would be voting on its own terms.

## Committing before revealing: a sealed round

An `open` round publishes each seat's attestation the moment it is ready, and the store is
readable by everyone in the quorum. So the first volunteer to finish has, in effect, told
every later volunteer what the answer is. A "verifier" that reads the store, agrees, and
signs saves an hour of building and still counts as an independent vote — and
[ADR-0002 D3/D10](adr/0002-roster-verifier-selection-and-sybil-resistance.md) assumes
*honest-but-weak* volunteers, which is exactly a machine that takes the cheap route when
one is offered.

A `sealed` round closes that by splitting submission into two phases, so that no seat can
read another's answer before it has fixed its own:

```text
phase 1  refs/gitiup/commit/<change>/<job>/<slot>   SHA256( canonical attestation bytes
                                                                  ‖ slot ‖ challenge )
phase 2  refs/gitiup/reveal/<change>/<job>/<slot>   the attestation bytes themselves
```

Both are CAS writes keyed by the seat's slot, so one promise and one reveal per seat, and
both land before the round's deadline. The order that matters is *commit before reveal*,
and it is what the code enforces: the commitment is computed from the bytes the volunteer
is about to publish, so it cannot precede the build — the attestation names outputs,
environment and timings that do not exist until the run finishes. A commitment to something
that existed beforehand (the round, the challenge) would be a hash anyone could compute for
somebody else's answer, so it would buy nothing; the property that survives is the one that
counts, namely that a seat's bytes are fixed and published as a digest before that seat is
allowed to read anybody else's reveal. The commitment is a
[`Commitment`](../crates/gitiup-quorum/src/commit.rs) record — `gitiup-commitment-1`,
`{round_digest, job_id, attempt, slot, key_id, challenge, algorithm, commitment}`, signed
by the volunteer — and it is checked, not believed: the slot must be the one that round
derives for that key, the challenge must be that round's per-key challenge, and the bytes
must hash to what it promises. `gitiup work` does both phases in that order without being
told, because the round says which flow it uses; `--dry-run` shows the commitment it
would have published and writes neither.

What the tally does with the two piles is the part a gate depends on:

| the evidence | the tally's word | exit |
|---|---|---|
| a reveal that hashes to its commitment | counted as that seat's vote | — |
| a commitment, no reveal | `missing` — a miss, like never showing up | 6 |
| a reveal that does not open its commitment | `rejected` with `commitment_mismatch`, and the seat is counted against | **8** |
| a reveal with no commitment at all | refused by `store::publish_submission`, and `no_commitment` in a tally that finds one anyway | **8** |
| a commitment signed by a key that holds no seat in this round | `foreign_commitment`, and no seat is spent on it | **8** |
| a commitment whose challenge is another round's | `stale_commitment`, and no seat is spent on it | **8** |

The mismatch rule is the interesting one, and it is why the store **publishes** a reveal
that fails to open its commitment instead of dropping it. A mismatch is the signature of
exactly the behaviour sealing exists to catch — compute one thing, commit to another, or
copy an answer after the fact — and a mismatch that is silently dropped is a mismatch
nobody has to explain. So it goes into the store as evidence, `verdict` exits 8
(ADR-0001 D7's order: integrity before authority, so a mismatch outranks even a
threshold that was met without it), and the seat is spent: a volunteer cannot try again
after the deadline by publishing a better answer into a slot it already filled. The two
defences against a reveal with no commitment are deliberate doubles — the store refuses
the write, and the tally rejects it anyway, because the store is an index, not a memory
nor a trusted party.

### What sealed does *not* buy, spelled out

This is the part a design document usually leaves implicit, and it is the part a reviewer
needs most.

* **It is not secrecy from the store's readers.** Everything a sealed round contains is
  public, to anyone with read access, from the moment the reveal lands — the store is a
  public content-addressed index
  ([ADR-0002 D11](adr/0002-roster-verifier-selection-and-sybil-resistance.md): *the public
  store is not a channel*). A commitment hides nothing; it only predates the bytes. If a
  result must be hidden *from the other verifiers*, that is encrypted submission, which
  ADR-0002 rejects outright, and this build does not pretend otherwise.
* **It does not hide who is in the round.** The round record and the advertisement carry the
  seat list, by design: selection is public once a round opens so that any auditor can
  re-derive it, and a sealed advertisement that hid the seats would cost the free
  `open_rounds_for(key)` poll for a benefit nobody can take anyway — a copycat can list the
  round and read the seats today. Sealing seals each seat's *answer* until every seat has
  committed, nothing more.
* **It cannot prove that an answer was computed before it was seen.** The residual attack is
  worth stating plainly: volunteer X builds, commits its real answer, watches the other
  reveals land, and — if they disagree with its own — simply withholds its reveal. Its
  commitment then counts as `missing` and its seat is wasted; X has traded a vote for a
  look. That is a real option, and the answer to it is not cryptography: a `missing` is a
  miss, misses are what reputation and quarantine
  ([giti-p1.9](../README.md)) count, and the protocol's job was never to make cheating
  impossible but to make it cost the cheater the thing it came for. Sealing removes the
  free copy; it does not install good faith.
* **A commitment binds bytes, not truths.** The preimage is the canonical attestation, and
  an attestation's claims are self-asserted ([ADR-0001 D9](adr/0001-attestation-encoding-hash-and-signature.md)).
  Sealing a claim does not make it true; it makes it unretractable.
* **It binds to one round, and only that one.** The challenge is inside the hash, so a
  commitment cannot be carried from an earlier attempt or a different job — which is also
  why a stale commitment is refused rather than counted: a volunteer that commits to round
  A and reveals into round B is describing neither.

The mode is chosen by the **owner's policy**, `quorum.reveal_mode`, in the signed
policy document ([giti-p1.6](../README.md)) — not by a volunteer's flag, and not by a
client default, for the same reason `n` and `required_agree` are policy: the person
submitting a change must not get to decide how independent its verification is, and a
fork must not be able to un-seal an upstream's rounds.

```bash
cat > policy.json <<'EOF'
{ "name": "example/kernel", "revision": 3,
  "quorum": { "default": { "n": 5, "required_agree": 4 },
              "reveal_mode": "sealed",
              "requirements": { "arch": "x86_64", "min_sandbox_level": 1 } } }
EOF
gitiup policy publish ./policy.json --store ./store --key ./keys/owner.key
```

Absent means `open`, and an unknown mode is refused by `policy publish`/`policy get`, by
`gitiup select --reveal-mode`, and by `gitiup work` when it reads a round that names one —
never downgraded to `open`, because silently running a stricter rule as a laxer one is the
one failure mode a security protocol may not have
— `VerdictRecord`'s own refusal is `reveal_mode_unimplemented`, kept for a mode a *future*
build would name.

Anyone can check a sealed round without trusting a volunteer or a build: the preimage is
published, so the check is one hash.

```bash
# the reveal's raw bytes, exactly as the store holds them
git -C "$STORE" cat-file blob "$(git -C "$STORE" rev-parse     refs/gitiup/reveal/chg-…/build/matrix/stable/<slot>)" \
  | sha256sum    # …equals `commitment.commitment` in the commitment blob
```

That is the whole verification, and it is why the record is JSON with a plain SHA-256
rather than a bespoke binary format: a reviewer with a shell and `sha256sum` can audit a
round that did not go the way their project hoped
([ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md)).

## Choosing the five

`seed = HMAC-SHA256(secret, round_kind ‖ roster_epoch ‖ roster_digest_body ‖ change_id ‖
head_oid ‖ job_id ‖ attempt)`, fields joined with `0x00` (the `/` you see in a round id is
display only, because `job_id` contains slashes), and then
`score = SHA256("gitiup-round-1/score" ‖ 0x00 ‖ seed ‖ 0x00 ‖ key_id)`, ordered by score
as fixed-length lowercase hex with ties broken by key id. Scores are recomputed for the
audit trail; the ordering is the whole point and it is reproducible from published
values.

The published golden vectors
([`docs/adr/fixtures/selection-v1/`](adr/fixtures/selection-v1/)) are the contract.
[`crates/gitiup-quorum/tests/selection_vectors.rs`](../crates/gitiup-quorum/tests/selection_vectors.rs)
reproduces `selection.json` from `roster.json` + `round.json` — candidates, scores,
greedy reasons, seats, reserves, promotion cases, seed and policy digest — and
[`tests/selection_properties.rs`](../crates/gitiup-quorum/tests/selection_properties.rs)
checks the statistical and structural claims over many simulated rounds: χ² uniformity over
**10 000** selections on both the seat counts and the rank-1 counts (p > 0.01), one identity
one seat, a key rotation changing the pick, and the proposer's whole family staying out of
every seat.

## Selecting, from the command line

`gitiup select` is one command with two jobs, and which one it runs depends on whether the
round already exists:

```sh
# the selector (the owner by default): open the round, then publish the audit record
gitiup select --change chg-1 --job build/matrix/linux-x86_64 \
    --head "sha1:$(git rev-parse HEAD)" --proposer ada \
    --require-arch x86_64 --store ./store --explain --publish

# anybody, including a stranger with no keys at all: re-derive it from what is published
gitiup select --change chg-1 --store ./store --explain
gitiup select --change chg-1 --store ./store --json | jq .selection

# or from bytes alone: no store, no key, no trust root
gitiup select --change chg-1 --round round.json --roster roster.json --proposer ada
```

Four things are worth naming, because each is a refusal in the code rather than a rule in
prose:

* **deriving needs a key, auditing needs none.** The seed is keyed on the selector's
  Ed25519 seed ([D2](adr/0002-roster-verifier-selection-and-sybil-resistance.md)), so only
  the selector can open a round; the seed is then *published* in the round record, so
  anybody can re-derive the ordering. An auditor with an empty keystore gets the same
  `selection` as the owner — plus a note saying whose signature was **not** believed,
  because "reproduced" and "authorised" are different claims.
* **the proposer is excluded, and then checked.** `--proposer` is required to open a round,
  is closed over the author's whole identity family (`RoundInputs::excluding`, so a second
  box anchored on the same principal leaves with the first), and the result is re-checked
  with `ProposerExclusion::check` before the command prints. Auditing a round that left an
  author's eligible box in the pool is exit 6: the exclusion set is part of the signed
  record, so such a round is refused rather than re-interpreted.
* **a published round is not re-specified.** In audit mode `--n`, `--head`, `--require-*`
  and friends are refused instead of ignored. An auditor who could restate the policy would
  not be auditing the published selection, they would be proposing a different one.
* **insufficient is an answer.** If the filters and caps fill fewer than `n` seats the
  command reports `sufficient: false` and exits 0 — deciding what that *means* is
  giti-msi.7's verdict engine, and silently lowering `n` is the failure mode ADR-0002 names
  as the dangerous one.

The `--explain` table is the audit trail ADR-0002 D3 specifies: the round id, the seed, the
policy digest, and one row per roster entry with its score, the *first* D7 filter that
failed it, and what the greedy pass decided (`take`, `skip:identity`, `skip:tier_cap`).
`--json` puts the ADR's selection document at `.selection`, with everything needed to
reproduce it — `inputs`, `seed`, roster epoch and digest — beside it, so two auditors'
output differs in provenance and never in the answer.

## Submitting opens the rounds: `gitiup change submit`

`gitiup select` is a command somebody has to remember, and a quorum nobody remembers is a
quorum that never happened. So the command that publishes a change also opens its rounds
([`quorum`](../crates/gitiup/src/quorum.rs)):

```sh
# publish the change and open one round per job per matrix arm, then advertise them
gitiup change submit --repository . --base main --store ./store

# …or publish the change alone, and say so out loud
gitiup change submit --store ./store --no-quorum

# a delegated selector, holding a secret and no Ed25519 seed
gitiup change submit --store ./store --selector selector --seed-file /run/secrets/round
```

Five rules decide what happens, and each is a refusal or a printed line rather than a
paragraph of advice:

* **the numbers are the policy's.** Whether a quorum is demanded is the resolved
  `gitiup-policy-1`'s (`allowed_tiers` contains `quorum`, and `protects` covers the branch
  the change merges into); the seats, the agreements required and the eligibility floor are
  `quorum.by_job[<glob>]` or `quorum.default` and `quorum.requirements` —
  [`SelectionPolicy`](../crates/gitiup-quorum/src/select.rs) and
  [`Requirements`](../crates/gitiup-quorum/src/capability.rs) verbatim, per
  [ADR-0004 D5](adr/0004-published-policy-format-signing-and-resolution.md). `submit` has no
  `--n` and no `--require-arch`, on purpose: the tier a repository demands is data its owner
  signed, and a flag would be a fork's way to weaken it. A policy this machine does not trust
  is **reported and never applied** (D3), and a change into such a store still publishes.
* **the job set is the planner's.** The workflow files go through `gitiup-run`'s planner, so
  a matrix is one round per arm — `build/matrix/linux-x86_64`, `build/matrix/linux-aarch64`
  — each with its own seed, because one seed for two architectures would be one jury asked
  to judge machines one of them cannot run on (D7). With no workflow file the record's own
  `workflow.jobs` hint is the job set; with no jobs at all, the submit is refused rather
  than answered with an empty quorum.
* **the submitter is the selector.** The seed is keyed on the key that signs the change
  (D2), so whoever publishes a change can derive its ordering — which is only not
  self-refereeing because **the author's whole key family is out of the pool**
  (`RoundInputs::excluding`, re-checked with `ProposerExclusion::check` before the round is
  written *and* again against the round that came back from the store). A round that left the
  author's second box eligible is refused, exit 6, and — because every round is derived
  before a single byte is written — the refusal means nothing was published, not that a bad
  round is sitting in the store.
* **a demanded quorum that cannot be opened is a refusal.** No roster in the store, no
  `quorum.requirements` to select against, no derivable selector (an agent-held key cannot
  be one), no job, several workflow files and none named: exit 6, before the change writes,
  because publishing a change that can never reach a verdict and saying `submitted` is the
  silent failure the rest of this document exists to avoid. `--no-quorum` is the explicit
  way out, and it prints what it costs.
* **an unfilled round is published, not shrunk.** Fewer than `n` eligible volunteers means the
  round goes out with `sufficient: false`, is *not* advertised (recruiting for a quorum that
  cannot happen is worse than escalating), and is reported with the tally of which D7 filter
  rejected whom — `--explain` adds the same audit table `gitiup select` prints. `n` is never
  lowered, and the exit code is still 0: this is an answer, not a crash.

Everything a submit wrote is checkable by somebody else with nothing but the store:
`gitiup select --change <id> --store ./store` re-derives each published round, and
`gitiup verify change <id>` refuses the change until those rounds produce a verdict.

## Tallying it: `gitiup quorum verdict`

The rounds are open and the seats are filled, and what an owner asks is one line long.
[`gitiup quorum verdict`](../crates/gitiup/src/verdict.rs) is that line — the one a human
types and the one a `pre-receive` hook runs:

```sh
# the whole change: one block per job, and the exit code is the worst of them
gitiup quorum verdict chg-6a6a8eab778ba4d0 --store ./store

# one matrix arm, at a clock the caller chose, machine-readable
gitiup quorum verdict chg-6a6a --store ./store --job build/matrix/linux-x86_64 \
    --json --now 2026-10-24T00:01:01Z

# …and file the signed answer beside the evidence it describes
gitiup quorum verdict chg-6a6a --store ./store --publish --key owner
```

Five rules, each of which is a line of code rather than a paragraph of advice:

* **the store is an index, not a memory.** Nothing is carried over from the last run: the
  command re-fetches the round, the roster *epoch the round pinned*, every seat's
  submission (`store::submissions`) and every revocation, and re-checks each attestation
  from scratch — canonical bytes, signature, the round's own bindings (head oid and the
  per-key challenge), freshness, tier, and the capability claim against the signed
  environment. Revocation is evaluated **as of now**
  ([ADR-0002 D9](adr/0002-roster-verifier-selection-and-sybil-resistance.md)): a key
  revoked this afternoon voids what it signed last week, and a verdict that remembered the
  old answer is a verdict nobody can audit.
* **the round is verified before anything in it is.** `Round::verify` runs first, under a
  *trusted* selector signature and the epoch it pinned: the round is the one document no
  attestation can audit, so a record whose seats were hand-picked would otherwise tally
  `verified` from perfectly good signatures. Seats that are not the ones the published
  seed derives are exit 8.
* **the numbers are the round's.** `n`, `required_agree` and the seat list come from the
  published record; there is no `--n` and no `--threshold` here, exactly as
  `gitiup change submit` has none. The flags that do exist (`--tier`, `--sandbox`,
  `--max-age`, `--max-skew`, `--now`) change only what an *attestation* has to be, which
  is the same split [`gitiup verify change`](verification.md) keeps.
* **the exit code is not always the state's.**
  `0` verified · `6` refused or not yet (`failed`, `insufficient`, no rounds, a publish
  the record refuses) · `7` a signature in this round's evidence that does not verify ·
  `8` a digest that is not what it names. 7 and 8 come from the *evidence*, and
  [ADR-0001 D7](adr/0001-attestation-encoding-hash-and-signature.md)'s order — bytes
  before signatures before policy — lets them outrank the tally: a round whose remaining
  votes still carried the threshold exits 8 anyway, because a broken thing in the
  evidence is not made whole by being outvoted, and the discarded pile is precisely what
  the owner has not yet explained. Usage (`2`) and an unreadable store (`3`) are not
  verdicts and keep their own codes.
* **a verdict is stdout, and stderr stays empty.** The report and the exit code are the
  answer, so a hook reads one stream; `--json` prints the record verbatim — what
  `--publish` filed is what `--json` printed, field for field — and `--out -` writes the
  canonical signed bytes and keeps the report off stdout entirely (it refuses to share
  the stream with `--json`, since one would corrupt the other).

### Attesting it: `gitiup quorum verdict --attest`

A verdict is the store's own record. A `tier: quorum` **attestation** is the same
conclusion in the currency a policy can ask for — `allowed_tiers: ["quorum"]` means
something only if there is a document that carries that tier
([`QuorumAttestation`](../crates/gitiup-quorum/src/attestation.rs), giti-zp1.5):

```sh
# state the verdict as a quorum attestation, filed among the attestations of the head
# the round was run on
gitiup quorum verdict chg-6a6a --store ./store --job build --attest store --key owner

# …or hand the signed bytes to someone who is not going to be given the store
gitiup quorum verdict chg-6a6a --store ./store --attest ./quorum.json --key owner
```

It binds the round id and digest, the roster epoch and digest, the agreeing
`ResultDigest` and the seats that produced the verdict, and it re-summarises none of
their bytes: the seats are *named*, their attestations are still fetched from the store.
There are two rules and both are in the library, not the CLI:

* **only a verdict makes one.** `QuorumAttestation::from_verdict` is the only way to build
  one, and it refuses a verdict that is not `verified` — a `failed` tally has no
  `ResultDigest` to carry and an `insufficient` one has no quorum. `--attest` on a round
  that did not verify writes nothing and exits with the verdict's own code.
* **only re-derivation believes one.** `gitiup verify attestation --tier quorum` re-runs
  `VerdictRecord::evaluate` — the same call, on the same records, as this command just
  made — and refuses anything the evidence does not back. See
  [the quorum ladder](verification.md#the-quorum-ladder-tier-quorum).

### Filing it: superseded, never edited

`--publish` signs the verdict with this machine's key and CAS-writes it at
`refs/gitiup/verdict/<change>/<job>` ([`store::file_verdict`](../crates/gitiup-quorum/src/store.rs)).
The ref moves in exactly two ways — nothing→something, and an earlier attempt→a later one
— so filing has four outcomes and the command says which one happened: `filed`,
`unchanged` (the same answer again, which is a retry and not an edit), `superseded` (a
later attempt's verdict replaces an earlier one's), and `refused`, with both verdicts
quoted and the ref untouched. A refusal is the point of the function: the way to launder a
disagreement out of a quorum record would be to re-run the tally after the awkward
verifier went home and write the tidy answer over the old one, so the evidence — not the
tally's convenience — decides what stays on the record, and the way out is `attempt + 1`
with a fresh seed. The verdict already at the ref is *signature-checked before it is
compared*, so a store cannot plant an unsigned record to force a conflict.

Which rounds get tallied is the same rule as escalation: the **latest attempt per job** by
default, `--attempt n` to pin one, `--job` to name one — and a job this store never
opened is a refusal that lists the jobs it did open, because that is the whole difference
between a typo and a wrong answer.

What the command will not do is as deliberate: it does not open, re-open or void a round
(that is `gitiup select`, and escalation in giti-zp1.7), and it does not decide what a
vote is worth from a flag. A verdict is an opinion about evidence, signed. That is the
whole job.

## Deferred, with the reason

The epic is the mechanism. These are its child tickets, and each has a place to plug in
that already exists:

* **policy engine and status reporting** ([giti-msi.7](../README.md)) — `VerdictRecord`
  is the input; `SelectionPolicy` is the knob.
* **disagreement handling** ([giti-msi.8](../README.md)) — `divergent`, `rejected` and
  `missing` are the dispute report's body; an escalation is `attempt + 1`, a fresh seed.
* **the rest of the CLIs** ([giti-msi.3](../README.md), [giti-msi.5](../README.md)) —
  every command in ADR-0002's "storage" sketch is a function in this crate already, and
  `store` is the layer they call; `gitiup participant` (giti-msi.2) is the first of them,
  and is how that layer is driven today.
* **quarantine and reputation decay** ([giti-msi.9](../README.md)) — the exclusions are
  inputs to selection, so quarantine is a policy that writes them.

## Trying it

```sh
cargo test -p gitiup-quorum            # vectors, properties, store, end-to-end
cargo test -p gitiup-quorum --test quorum_end_to_end -- --nocapture
cargo test -p gitiup-quorum --test job_leases -- --nocapture
cargo test -p gitiup-quorum --test verdict_filing -- --nocapture
cargo test -p gitiup --test quorum_verdict_cli -- --nocapture
```

The end-to-end test is the acceptance criterion as code: seven volunteers in the roster,
five seats filled, each publishing into its own slot, and the verdict coming out
`verified` — and then `failed` when the split cannot reach the threshold, and
`insufficient` when too few turn up.

`job_leases` is the same discipline for finding work and leaning on it: an advertisement
that pages, a lease that two volunteers race for and only one wins, a steal that leaves a
trail, and the rule that a lease never displaces an attestation.

`commit_reveal` is the same for the two-phase flow: a sealed round run end to end through
the store and verified; a reveal with no commitment refused by the store *and* rejected by
a tally that finds one anyway; a mismatched reveal published as evidence, counted against
the seat, and named `commitment_mismatch` at exit 8; a commitment with no reveal tallied as
`missing`; a commitment from a stranger's key or another round's challenge refused without
spending the seat; and a reader who trusts nobody recomputing a reveal's hash from the two
refs.

The verdict has two. The library rule — a verdict is superseded and never edited — is
[`crates/gitiup-quorum/tests/verdict_filing.rs`](../crates/gitiup-quorum/tests/verdict_filing.rs):
a first filing, a retry that moves nothing, a different answer at the same attempt
refused, an older attempt unable to overwrite a newer one, and an incumbent nobody signed
never believed enough to compare. The command is
[`crates/gitiup/tests/quorum_verdict_cli.rs`](../crates/gitiup/tests/quorum_verdict_cli.rs),
run as the built binary against a real store and a real keystore: `verified`, `failed` and
`insufficient` each with its count and threshold; a tampered signature at 7 and a
submission bound to another commit at 8 *over* a tally that still carried the threshold; a
revocation that voids a vote already cast; a capability lie named in the report and not
counted; every run asserting an empty stderr, because that is the contract a hook reads.

The command line has its own acceptance test, run as the built binary against a real
keystore, a real store and a real signed policy —
[`crates/gitiup/tests/change_quorum_cli.rs`](../crates/gitiup/tests/change_quorum_cli.rs):
a submit opens one round per job per arm and advertises the filled ones, the author's second
box is out of every round that came back from the store, `--no-quorum` opens nothing and says
so, and a round that cannot fill its `n` reports `sufficient: false` with the filters that
emptied the pool.

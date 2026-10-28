# The quorum verification network

Status: **the mechanism exists, and so do the roster commands** (`gitiup participant
register|withdraw|list|verify-roster`, plus the owner's `approve` and `revoke`); the
selection, job and verdict CLIs are open tickets.
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
| [`select`](../crates/gitiup-quorum/src/select.rs) | the selection proper: score ordering, the greedy pass over tier and identity caps, reserves, promotion, and `explain()`, the audit trail. |
| [`round`](../crates/gitiup-quorum/src/round.rs) | the signed record that pins a round to a roster epoch and digest and publishes the seats and the seed. |
| [`store`](../crates/gitiup-quorum/src/store.rs) | the ref names and CAS writes. The store is the broker: compare-and-swap does the locking, so there is no coordinator to bribe. |
| [`gate`](../crates/gitiup-quorum/src/gate.rs) | admission at submission time: is *this key* approved, for *this epoch*, in *this round*, and is *this document* its own? Every refusal has its own code. |
| [`participate`](../crates/gitiup-quorum/src/participate.rs) | the volunteer's fail-closed checklist (ADR-0002 D11). |
| [`verdict`](../crates/gitiup-quorum/src/verdict.rs) | the tally: `verified` / `failed` / `insufficient`, every rejection with its reason, and the divergent results. |
| [`ledger`](../crates/gitiup-quorum/src/ledger.rs) | the volunteer's memory of the highest epoch a store has offered — the rollback guard. |

## The four risks and the mechanism that closes each

| risk | how it is closed |
|------|------------------|
| targeted verifier / selection bias | the seed is `HMAC-SHA256(secret, round_id_fields)` and is **published** with the round, so anyone can re-derive the scores and check the published seats are the derived ones. `Round::verify` re-runs the selection and refuses a record whose seats were edited. Anyone holding the secret can pick the pool in advance, which is why the secret is the deployment's own and rotates with its key. |
| copycat verifiers | each seat has a slot (`key_slot(key_id)`, store-assigned and unguessable) and each attestation must carry `challenge = HMAC(seed ‖ 0x00 ‖ key_id)`, so an answer cannot be replayed into another round. Commit-reveal ([giti-msi.6](../README.md)) splits the same slot into a commitment and a reveal; nothing here has to change. |
| sybils and ballot stuffing | membership costs an owner signature and a key-ownership proof, one *identity* casts one vote whatever it controls, the proposer's family is excluded, and the caps limit each tier. The cost model is in ADR-0002 D4–D7; `max_per_identity` is enforced in the tally as well as in selection, so a roster cannot smuggle two boxes into two votes. |
| stale or replayed attestations | the round pins the head oid, the attestation binds the round's challenge, freshness is evaluated at verdict time, and revocation is evaluated there too — a `compromised` key voids what it signed *earlier*, which is the only useful reading of a stolen key. |

Two more, because a mechanism that can be silently rolled back is a mechanism that can be
switched off:

* **roster rollback** — epochs are dense and time-derived, every round pins epoch *and*
  digest, and a volunteer that has seen epoch 41 refuses a round pinned to epoch 40
  ([`RosterLedger`](../crates/gitiup-quorum/src/ledger.rs)).
* **an offer that cannot be met** — a volunteer checks the whole invitation before it
  runs anything ([`check_invitation`](../crates/gitiup-quorum/src/participate.rs)), and
  step 5 is "my slot is still free", enforced by a CAS write rather than by asking.

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
checks the statistical claims over 200 simulated rounds (χ² uniformity, one identity one
seat, a key rotation changing the pick).

## Deferred, with the reason

The epic is the mechanism. These are its child tickets, and each has a place to plug in
that already exists:

* **commit-reveal submission** ([giti-msi.6](../README.md)) — the slot is already
  per-seat and unguessable; `reveal_mode` is a published field and an unimplemented mode
  is *refused*, never silently downgraded to "open".
* **job advertisement and lease** ([giti-msi.4](../README.md)) — a volunteer reads its
  invitation from the round record; a TTL lease is an additional ref, not a change to the
  selection.
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
```

The end-to-end test is the acceptance criterion as code: seven volunteers in the roster,
five seats filled, each publishing into its own slot, and the verdict coming out
`verified` — and then `failed` when the split cannot reach the threshold, and
`insufficient` when too few turn up.

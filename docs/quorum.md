# The quorum verification network

Status: **the mechanism exists**; the CLIs around it are open tickets.
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

Refusals keep the exit codes of `gitiup attest` where they correspond (3 signature, 4
digest mismatch, 5 policy, 6 revoked, 7 store), so a script can branch on a quorum
failure the same way it branches on a single-run failure.

## Where the documents live in the store

```
refs/roster/current                     the roster epoch in force
refs/roster/epoch/<n>                   every epoch ever published (the audit trail)
refs/signup/<key_slot(slot)>            a volunteer's application, signed by its key
refs/withdrawal/<key_slot(key_id)>      a volunteer leaving, signed by its key
refs/revocation/<key_slot(key_id)>      the owner's revocation (or the key's own)
refs/round/<change>/<job>/<attempt>     the round record
refs/reveal/<change>/<job>/<slot>       one attestation per seat, claimed CAS
refs/verdict/<change>/<job>             the owner's verdict
```

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
* **the CLIs** ([giti-msi.2](../README.md), [giti-msi.3](../README.md),
  [giti-msi.5](../README.md)) — every command in ADR-0002's "storage" sketch is a
  function in this crate already; `store` is the layer they will call.
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

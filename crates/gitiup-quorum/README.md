# gitiup-quorum

The optional quorum verification network: who may verify, who *this* change picks,
what the pick committed to, and what the owner may believe as a result.

Decided in [ADR-0002](../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md);
the attestation bytes it signs are ADR-0001's, from
[`gitiup-attest`](../gitiup-attest/README.md); the storage is
[`gitiup-host`](../gitiup-host/README.md) refs and CAS objects. The prose is
[docs/quorum.md](../../docs/quorum.md).

For each change, N registered participants (five by default) are chosen, run the
workflows independently on their own machines, and sign the resulting `ResultDigest`.
The owner trusts the result when enough distinct identities agree. Both halves are
opt-in: volunteering is the participant's decision, requiring a quorum is the owner's,
and neither changes what a plain local run produces.

Four rules hold the crate together:

* **Every decision is a pure function.** Selection takes a roster, a round and a seed
  and returns an ordering; a stranger with those three numbers audits a quorum they
  were not invited to. No clock, no randomness, no network inside `select`.
* **The store is the only broker.** Rosters, rounds, submissions and verdicts are
  records written with compare-and-swap. There is no daemon, no queue and no
  coordinator to bribe — one attestation per seat is a CAS guarantee, not a convention.
* **Nothing is required.** Running a verifier is a volunteer's choice
  (`participate`), requiring a quorum is an owner's choice (`verdict`), how a seat submits
  is the owner's too (`quorum.reveal_mode`, `open` or `sealed` — `commit`), and an
  unimplemented option (a `reveal_mode` this build cannot honour) is refused rather
  than quietly downgraded.
* **The author never referees their own change, and the round proves it.**
  `RoundInputs::excluding` closes an exclusion set over a principal's whole key family
  before the seed is derived, and `ProposerExclusion::check` re-checks a published round
  against it — from public bytes, so an auditor runs the same check the CLI does.

```rust,ignore
use gitiup_quorum::prelude::*;
use gitiup_quorum::{sample, derive::SelectionSecret, round::Round,
                    verdict::{Evaluation, QuorumState, VerdictRecord}};

// The owner's key signs the roster and is the selector by default.
let owner = sample::owner_key();
let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
let now = sample::clock();

// A roster of seven volunteers; the policy asks for five seats and four agreements.
let roster = sample::roster_of(&owner, 7, 41);
roster.verify(&trust, now).expect("a signed, owner-approved roster verifies");

// The owner opens a round for one job of one change, and publishes it.
let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build/matrix/linux-x86_64");
let secret = SelectionSecret::from_signing_key(&owner);
let mut round = Round::open(&inputs, &roster, &secret).unwrap();
round.sign(&owner).unwrap();
round.verify(&trust, &roster).expect("the published seats are the derived ones");
assert_eq!(round.selected.len(), 5);

// The five selected volunteers re-run the job independently and sign the digest.
let seats = sample::indices_of(&round);
let attestations = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);

// Five agreeing `ResultDigest`s from five distinct identities, past the threshold
// of four: `verified`.
let verdict =
    VerdictRecord::evaluate(&round, &roster, &attestations, &[], &Evaluation::at(now)).unwrap();
assert_eq!(verdict.state, QuorumState::Verified);
assert!(verdict.state.mergeable());
```

## The modules

| module | decision |
|--------|----------|
| [`derive`](src/derive.rs) | the derivation: round id message, seed, score, handle, key slot, per-key challenge — every domain string in one file |
| [`roster`](src/roster.rs) | epochs, key-ownership proofs, sign-ups, withdrawals, revocations, one identity one vote |
| [`capability`](src/capability.rs) | the eligibility filters, and the published order they are applied in |
| [`select`](src/select.rs) | scoring, the greedy pass over tier and identity caps, reserves, promotion, and `explain()` |
| [`round`](src/round.rs) | the signed record that pins epoch + roster digest + seats, and re-verifies them without a secret; `Escalation` is the pointer from an attempt to the one it replaces |
| [`job`](src/job.rs) | the advertisement (a round's seats, copied) and the TTL lease on one seat: claimed by CAS, stealable when it dies, and the steal recorded |
| [`gate`](src/gate.rs) | admission at submission time — this key, this epoch, this round, this document — with its own refusal code for each |
| [`store`](src/store.rs) | the ref names and CAS writes: `refs/roster/*`, `refs/signup/*`, `refs/withdrawal/*`, `refs/revocation/*`, `refs/round/*`, `refs/job/*`, `refs/lease/*`, `refs/commit/*`, `refs/reveal/*`, `refs/verdict/*`, and `store::tally`, which picks the flow the round names |
| [`commit`](src/commit.rs) | phase 1 of a sealed round: `H(attestation bytes ‖ slot ‖ challenge)`, and the check that a reveal opens it |
| [`participate`](src/participate.rs) | the volunteer's fail-closed checklist, and `serve_once` |
| [`verdict`](src/verdict.rs) | the tally, every rejection with its reason, the divergent results |
| [`attestation`](src/attestation.rs) | the `tier: quorum` attestation: `from_verdict` is the only way to build one, and it refuses anything but `verified` |
| [`escalate`](src/escalate.rs) | the attempt cap: `quorum.max_attempts` from the published policy, the count read off the store's own refs, and `attempt_cap_exhausted` at exit 9 |
| [`policy`](src/policy.rs) | the published policy (ADR-0004): the document, its digests, its trust and coherence checks, the resolution ladder, and the `quorum` block a round's numbers come from |
| [`record`](src/record.rs) | the signed-record framing ADR-0001 D3 sets and every record here re-uses: canonical body bytes, PAE, the signature list kept out of the digest |
| [`ledger`](src/ledger.rs) | the anti-rollback memory: the highest epoch this store has offered |
| [`error`](src/error.rs) | the refusal taxonomy and the exit code each one carries — the same numbers `gitiup` exits with |
| [`sample`](src/sample.rs) | deterministic fixtures — published seeds, so never a production trust anchor |

## Not here

* **no sandbox** — what a volunteer's run may reach is `giti-bgy.*`; `serve_once` takes a
  `produce` callback and cannot run anything itself. giti-zp1.3 moved the *caller* of that
  callback into `gitiup work`, which supplies a sandboxed run; the crate still cannot spawn
  a process, which is what keeps it callable from a store that must not execute what it
  stores;
* **no network client** — the store is a `Host` trait object, so the fs host in a test
  and the bucket-as-forge in production take the same code path;
* **no key store** — keys are giti-1rs.6; everything here takes a `Signer`;
* **no coordinator** — nothing here polls, schedules, renews or retries on a timer. The
  advertisement is a ref, the lease is a ref, and the two loops that touch them — `gitiup
  work --watch` and `gitiup quorum retry` — are run by a volunteer and an owner respectively,
  the second of them bounded by the policy's attempt cap;
* **no memory of bad behaviour** — exclusions are an *input* to selection and a verdict
  names every `missing` and `rejected` seat with its code, but nothing here accumulates one
  key's history across verdicts. Quarantine is giti-zp1.8, and it will be a policy that
  writes exclusions;
* **no endorsement document** — ADR-0002 D6's signed endorsement record is unimplemented
  (the namespace is declared and unused), so `endorsed` is the owner's word at
  `approve --tier endorsed` and not a document a reader can check.

## Tests

```sh
cargo test -p gitiup-quorum
```

* `tests/selection_vectors.rs` reproduces the ADR-0002 golden vectors
  (`docs/adr/fixtures/selection-v1/`) byte for byte — seed, scores, greedy reasons,
  seats, reserves, promotion cases, policy digest. The vectors came from a stdlib-only
  Python reference generator, so this is a cross-implementation check.
* `tests/selection_properties.rs` checks uniformity over 200 simulated rounds (χ²),
  a further 10 000-round χ² over seat and rank-1 counts, one-identity-one-seat, that a
  key rotation changes the pick, and that the author's whole family stays out.
* `tests/quorum_end_to_end.rs` is the acceptance criterion: five volunteers publish
  into their own slots and the verdict is `verified`; then `failed` on an
  unreachatable split, and `insufficient` when too few turn up.
* `tests/roster_registration.rs` is the roster's own lifecycle: a sign-up whose capability
  claim arrives exactly as it was signed (and an owner editing one is refused), a withdrawal
  as a tombstone applied to the next epoch, a revoked key refused at the door rather than
  only at the tally, an expired entry answered with its own refusal and not "unapproved",
  and a second submission into one seat refused.
* `tests/job_leases.rs` is finding work and leaning on it: an advertisement that pages and
  that refuses a `reveal_mode` this build cannot honour, two volunteers racing one seat and
  one winning, a steal of a dead lease that leaves a trail, and the rule that a lease never
  displaces the holder's attestation — in both directions.
* `tests/commit_reveal.rs` is the sealed flow end to end: a round that commits then reveals
  and verifies; a reveal with no commitment refused by the store *and* rejected by a tally
  that finds one anyway; a mismatch published as evidence, counted against the seat and
  named at exit 8; and a stranger with two refs and `sha256sum` checking it alone.
* `tests/verdict_filing.rs` is the filing rule — a verdict is superseded, never edited: a
  first filing, a retry that moves nothing, a different answer at the same attempt refused,
  an older attempt unable to overwrite a newer one, and an incumbent nobody signed never
  believed enough to compare.
* `tests/quorum_attestation.rs` is the top tier: only a `verified` verdict makes a
  document, a document that only labels itself quorum is refused at exit 6, a seat revoked
  afterwards undoes one, and a failed verdict produces no bytes.
* `tests/policy_vectors.rs` and `tests/policy_store.rs` are ADR-0004's — the golden signed
  policies and refusals, and the store side: publish, resolution with the provenance the
  answer carries, the history walk, and an unsigned policy refused rather than applied.

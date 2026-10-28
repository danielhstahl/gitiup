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

Three rules hold the crate together:

* **Every decision is a pure function.** Selection takes a roster, a round and a seed
  and returns an ordering; a stranger with those three numbers audits a quorum they
  were not invited to. No clock, no randomness, no network inside `select`.
* **The store is the only broker.** Rosters, rounds, submissions and verdicts are
  records written with compare-and-swap. There is no daemon, no queue and no
  coordinator to bribe — one attestation per seat is a CAS guarantee, not a convention.
* **Nothing is required.** Running a verifier is a volunteer's choice
  (`participate`), requiring a quorum is an owner's choice (`verdict`), and an
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
| [`round`](src/round.rs) | the signed record that pins epoch + roster digest + seats, and re-verifies them without a secret |
| [`store`](src/store.rs) | the ref names and CAS writes: `refs/roster/*`, `refs/round/*`, `refs/reveal/*`, `refs/verdict/*` |
| [`participate`](src/participate.rs) | the volunteer's fail-closed checklist, and `serve_once` |
| [`verdict`](src/verdict.rs) | the tally, every rejection with its reason, the divergent results |
| [`ledger`](src/ledger.rs) | the anti-rollback memory: the highest epoch this store has offered |
| [`sample`](src/sample.rs) | deterministic fixtures — published seeds, so never a production trust anchor |

## Not here

* **no sandbox** — what a volunteer's run may reach is `giti-bgy.*`; `serve_once` takes
  a `produce` callback and cannot run anything itself;
* **no network client** — the store is a `Host` trait object, so the fs host in a test
  and the bucket-as-forge in production take the same code path;
* **no key store** — keys are giti-1rs.6; everything here takes a `Signer`.

## Tests

```sh
cargo test -p gitiup-quorum
```

* `tests/selection_vectors.rs` reproduces the ADR-0002 golden vectors
  (`docs/adr/fixtures/selection-v1/`) byte for byte — seed, scores, greedy reasons,
  seats, reserves, promotion cases, policy digest. The vectors came from a stdlib-only
  Python reference generator, so this is a cross-implementation check.
* `tests/selection_properties.rs` checks uniformity over 200 simulated rounds (χ²),
  one-identity-one-seat, and that rotating a key changes the pick.
* `tests/quorum_end_to_end.rs` is the acceptance criterion: five volunteers publish
  into their own slots and the verdict is `verified`; then `failed` on an
  unreachatable split, and `insufficient` when too few turn up.

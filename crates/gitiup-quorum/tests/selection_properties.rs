//! Properties that hold across *many* rounds rather than one vector.
//!
//! The ADR-0002 vectors pin the numbers; these pin the statistical and structural claims
//! the ADR makes about the mechanism — that selection is uniform over the eligible pool,
//! that rotating a key actually changes who is picked, and that an identity excluded
//! once is excluded for every key it holds. All deterministic: the "randomness" is keyed
//! on a fixed counter, so a failure reproduces exactly.

use std::collections::{BTreeMap, BTreeSet};

use gitiup_quorum::capability::RosterTier;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;

const N: usize = 5;
const EPOCH: u64 = 41;

/// `count` separate principals, one box each, identical capabilities and tier: the pool
/// where every key should win exactly `n`/`count` of the rounds and nothing else.
fn symmetric_pool(owner: &gitiup_attest::SigningKey, count: u8) -> Roster {
    let entries: Vec<RosterEntry> = (0..count)
        .map(|index| sample::entry(index, EPOCH, RosterTier::Endorsed))
        .collect();
    sample::roster_of_entries(owner, entries, EPOCH)
}

/// Caps wide enough that nothing but capacity and the identity rule bind, so any
/// concentration of seats is the hash being wrong rather than the policy being honest.
fn symmetric_policy(n: usize) -> SelectionPolicy {
    SelectionPolicy {
        n,
        required_agree: n.saturating_sub(1),
        reserves: 2,
        tier_floor: RosterTier::Anonymous,
        tier_caps: [("endorsed", n), ("trusted", n), ("anonymous", n)]
            .into_iter()
            .map(|(tier, cap)| (tier.to_string(), cap as u32))
            .collect(),
        max_per_identity: 1,
    }
}

fn round_for(roster: &Roster, policy: SelectionPolicy) -> RoundInputs {
    sample::round_inputs_with(
        roster,
        "chg-000000000000f00d",
        "build/matrix/linux-x86_64",
        policy,
    )
}

/// A different "operator secret" per simulated round. The point of the property is that
/// the *pick* changes with the secret, so what matters is that these are 200 unrelated
/// 32-byte values, not how they were minted.
fn secret_for(round: usize) -> SelectionSecret {
    let digest = gitiup_attest::Digest::sha256(
        format!("gitiup-quorum-uniformity-test round {round}").as_bytes(),
    );
    let bytes: [u8; 32] = digest
        .as_bytes()
        .try_into()
        .expect("sha256 output is 32 bytes");
    SelectionSecret::from_extracted(&bytes)
}

#[test]
fn selection_over_many_rounds_is_uniform() {
    let owner = sample::owner_key();
    let roster = symmetric_pool(&owner, 20);
    let inputs = round_for(&roster, symmetric_policy(N));
    let rounds = 200usize;
    let mut wins = vec![0usize; 20];
    for round in 0..rounds {
        let selection = Selection::select(&roster, &inputs, &secret_for(round)).unwrap();
        assert!(selection.sufficient, "round {round} filled its seats");
        assert_eq!(selection.selected.len(), N);
        for seat in &selection.selected {
            let index = (0u8..20)
                .find(|index| sample::verifier_key(*index).public_key().key_id() == seat.key_id)
                .expect("only pool keys are selected");
            wins[index as usize] += 1;
        }
    }
    let expected = (rounds * N) as f64 / 20.0;
    let chi_squared: f64 = wins
        .iter()
        .map(|observed| {
            let deviation = *observed as f64 - expected;
            (deviation * deviation) / expected
        })
        .sum();
    // chi-squared critical value at p = 0.01 with 19 degrees of freedom. A deterministic
    // test failing here means the score function is skewed, not that the run was unlucky.
    assert!(
        chi_squared < 36.19,
        "chi-squared {chi_squared:.2} over {rounds} rounds, wins {wins:?}, expected \
         {expected:.1} each: selection is not uniform over the pool"
    );
}

#[test]
fn a_key_rotation_changes_the_selection() {
    // Rotating to escape selection must work; if it did not, an operator who has been
    // picked could simply re-key and stay picked, and Sybil resistance would be decorative.
    let owner = sample::owner_key();
    let roster = symmetric_pool(&owner, 20);
    let inputs = round_for(&roster, symmetric_policy(N));
    let before = Selection::select(&roster, &inputs, &secret_for(1)).unwrap();
    let after = Selection::select(&roster, &inputs, &secret_for(2)).unwrap();
    assert_ne!(
        before.seed, after.seed,
        "the seed is keyed on the secret, so a different secret must give a different seed"
    );
    let carried = before
        .selected
        .iter()
        .filter(|seat| {
            after
                .selected
                .iter()
                .any(|later| later.key_id == seat.key_id)
        })
        .count();
    assert!(
        carried < before.selected.len(),
        "a fresh secret selected the identical roster — the scores are not keyed on the seed"
    );
}

#[test]
fn the_same_inputs_always_select_the_same_verifiers() {
    let owner = sample::owner_key();
    let roster = symmetric_pool(&owner, 12);
    let inputs = round_for(&roster, symmetric_policy(N));
    let first = Selection::select(&roster, &inputs, &secret_for(7)).unwrap();
    for _ in 0..5 {
        let again = Selection::select(&roster, &inputs, &secret_for(7)).unwrap();
        assert_eq!(first.seed, again.seed);
        let a: Vec<String> = first
            .selected
            .iter()
            .map(|seat| seat.key_id.clone())
            .collect();
        let b: Vec<String> = again
            .selected
            .iter()
            .map(|seat| seat.key_id.clone())
            .collect();
        assert_eq!(a, b);
    }
    // And the roster's own entry order is not an input: a stranger who re-publishes the
    // same roster with entries in a different order must not change the pick.
    let mut shuffled: Vec<RosterEntry> = roster.entries.iter().rev().cloned().collect();
    shuffled.sort_by(|a, b| a.identity.cmp(&b.identity));
    let resorted = sample::roster_of_entries(&owner, shuffled, EPOCH);
    let resorted_inputs = round_for(&resorted, symmetric_policy(N));
    let selection = Selection::select(&resorted, &resorted_inputs, &secret_for(7)).unwrap();
    let before: Vec<&str> = first
        .selected
        .iter()
        .map(|seat| seat.key_id.as_str())
        .collect();
    let after: Vec<&str> = selection
        .selected
        .iter()
        .map(|seat| seat.key_id.as_str())
        .collect();
    assert_eq!(
        before, after,
        "ordering the pool differently must not reorder the pick"
    );
}

#[test]
fn one_identity_never_holds_two_seats() {
    // Twenty boxes, ten principals, no caps to hide behind: if the identity rule leaks,
    // a sybil with two boxes takes two of five seats and the quorum is 2/5 of one person.
    let owner = sample::owner_key();
    let entries: Vec<RosterEntry> = (0..20)
        .map(|index| sample::entry_with(index, index / 2, EPOCH, RosterTier::Endorsed))
        .collect();
    let roster = sample::roster_of_entries(&owner, entries, EPOCH);
    let inputs = round_for(&roster, symmetric_policy(N));
    for round in 0..40 {
        let selection = Selection::select(&roster, &inputs, &secret_for(round)).unwrap();
        let identities: BTreeSet<&str> = selection
            .selected
            .iter()
            .map(|seat| &*seat.identity)
            .collect();
        assert_eq!(
            identities.len(),
            selection.selected.len(),
            "round {round} gave one principal two seats: {:?}",
            selection
                .selected
                .iter()
                .map(|seat| (&seat.key_id, &seat.identity))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn excluding_an_identity_takes_its_whole_family() {
    // This is what a revocation becomes in practice: the revocation names one key, the
    // owner publishes the identity in the round's exclusions, and every box of that
    // principal leaves the pool. ADR-0002 D4: the identity field *is* the family.
    let owner = sample::owner_key();
    let entries: Vec<RosterEntry> = (0..8)
        .map(|index| sample::entry_with(index, index / 2, EPOCH, RosterTier::Endorsed))
        .collect();
    let family = entries[0].identity.clone();
    let roster = sample::roster_of_entries(&owner, entries, EPOCH);
    let family_keys: BTreeSet<String> = roster
        .family(&family)
        .iter()
        .map(|entry| entry.key_id.clone())
        .collect();
    assert_eq!(family_keys.len(), 2, "the fixture family is two boxes");

    let mut excluded_only_family_a = round_for(&roster, symmetric_policy(N));
    excluded_only_family_a.exclusions.insert(family.clone());
    let selection = Selection::select(&roster, &excluded_only_family_a, &secret_for(3)).unwrap();
    let chosen: BTreeSet<&str> = selection
        .selected
        .iter()
        .map(|seat| &*seat.key_id)
        .collect();
    assert!(
        family_keys.iter().all(|key| !chosen.contains(&**key)),
        "excluding a principal must exclude every box it holds, not just the named one"
    );

    // And excluding one *box* leaves its sibling eligible: the two exclusion kinds are
    // different tools, and conflating them would make a single bad box unrevocable
    // without exiling a human.
    let mut one_box = round_for(&roster, symmetric_policy(N));
    let boxes: Vec<String> = roster
        .family(&family)
        .iter()
        .map(|entry| entry.key_id.clone())
        .collect();
    one_box.exclusions.insert(boxes[0].clone());
    let selection = Selection::select(&roster, &one_box, &secret_for(3)).unwrap();
    let chosen: BTreeSet<&str> = selection
        .selected
        .iter()
        .map(|seat| &*seat.key_id)
        .collect();
    assert!(!chosen.contains(&boxes[0].as_str()), "the named box is out");
    assert!(
        chosen.contains(&boxes[1].as_str()) || !selection.sufficient,
        "the sibling box stays eligible: a box exclusion is not an exile of a person"
    );
}

/// The acceptance criterion at the size the ADR quotes: **ten thousand selections**, and
/// a χ² test at p > 0.01 on both the seats and the ranks.
///
/// The pool is homogeneous on purpose — twelve `endorsed` principals with caps wide
/// enough that nothing but the ordering decides — because caps are *meant* to make a
/// heterogeneous roster non-uniform (that is what a cap is). What this measures is the
/// one thing that must not be skewed: `score`'s ordering. Two counts are checked, since
/// "selected evenly" and "ranked evenly" are different properties: a function that put
/// the same candidate first a little too often would pass the first and fail the second.
///
/// Critical value: χ²₀.₀₁(11 df) = 24.725. Deterministic, so a failure reproduces
/// exactly — the "randomness" is HMACs over a counter.
#[test]
fn ten_thousand_selections_pass_a_chi_square_test() {
    let owner = sample::owner_key();
    let candidates = 12u8;
    let roster = symmetric_pool(&owner, candidates);
    let inputs = round_for(&roster, symmetric_policy(N));
    let rounds = 10_000usize;

    let mut wins = vec![0usize; candidates as usize];
    let mut firsts = vec![0usize; candidates as usize];
    // Built once, outside the loop: deriving a `SigningKey` is a scalar multiplication,
    // and looking one up per seat per round would make this test measure key generation
    // instead of the ordering.
    let pool: BTreeMap<String, usize> = (0..candidates)
        .map(|index| {
            (
                sample::verifier_key(index).public_key().key_id(),
                index as usize,
            )
        })
        .collect();
    let index_of = |key_id: &str| -> usize {
        *pool.get(key_id).unwrap_or_else(|| {
            panic!(
                "{} is not in the pool",
                gitiup_quorum::record::short_key(key_id)
            )
        })
    };
    for round in 0..rounds {
        let selection = Selection::select(&roster, &inputs, &secret_for(round)).unwrap();
        assert!(selection.sufficient, "round {round} filled its seats");
        assert_eq!(selection.selected.len(), N);
        for seat in &selection.selected {
            wins[index_of(&seat.key_id)] += 1;
        }
        firsts[index_of(&selection.selected[0].key_id)] += 1;
    }

    let chi_square = |counts: &[usize], expected: f64| -> f64 {
        counts
            .iter()
            .map(|observed| {
                let deviation = *observed as f64 - expected;
                (deviation * deviation) / expected
            })
            .sum()
    };
    let expected_seats = (rounds * N) as f64 / candidates as f64;
    let expected_first = rounds as f64 / candidates as f64;
    let seats = chi_square(&wins, expected_seats);
    let ranks = chi_square(&firsts, expected_first);
    let df = candidates as usize - 1;
    assert!(
        seats < CRITICAL_11_DF,
        "χ² {seats:.2} on {df} degrees of freedom over {rounds} rounds (seats {wins:?}, \
         expected {expected_seats:.1} each): selection is not uniform over the pool"
    );
    assert!(
        ranks < CRITICAL_11_DF,
        "χ² {ranks:.2} on {df} degrees of freedom over {rounds} rounds (rank 1 {firsts:?}, \
         expected {expected_first:.1} each): the first seat is not uniform either"
    );
    // A sanity check on the test itself: every candidate won, and no candidate won so
    // rarely that the χ² above was computed over an essentially empty cell.
    assert_eq!(wins.iter().filter(|won| **won == 0).count(), 0);
    assert!(wins.iter().min().unwrap() > &(rounds * N / candidates as usize / 2));
}

/// The critical value of χ² at p = 0.01 with 11 degrees of freedom
/// (`candidates - 1`), quoted by ADR-0002's uniformity note.
const CRITICAL_11_DF: f64 = 24.725;

/// The acceptance criterion "the author and their other keys are always excluded", read
/// across many rounds rather than one.
///
/// One round proves the exclusion filter fired; a hundred prove it does not depend on the
/// seed, and that a second and third box of the same principal are as dead as the first
/// however the ordering falls. The author here anchors *three* boxes and is named by one
/// of them, which is the case a hand-maintained exclusion list gets wrong.
#[test]
fn the_author_and_their_other_keys_never_get_a_seat() {
    let owner = sample::owner_key();
    // Fifteen boxes, one of them the author's first; the author anchors two more under
    // the same principal, and every other box is its own principal.
    let author_boxes = [0u8, 7, 13];
    let entries: Vec<RosterEntry> = (0..15u8)
        .map(|index| {
            let principal = if author_boxes.contains(&index) {
                author_boxes[0]
            } else {
                index
            };
            sample::entry_with(index, principal, EPOCH, RosterTier::Endorsed)
        })
        .collect();
    let roster = sample::roster_of_entries(&owner, entries, EPOCH);
    let author = vec![sample::verifier_key(author_boxes[0]).public_key().key_id()];

    let family: BTreeSet<String> = gitiup_quorum::proposer_family(&roster, &author)
        .iter()
        .map(|entry| entry.key_id.clone())
        .collect();
    assert_eq!(
        family.len(),
        author_boxes.len(),
        "naming one of the author's keys has to reach every box they anchor"
    );

    let inputs = round_for(&roster, symmetric_policy(N))
        .excluding(&roster, &author)
        .unwrap();
    for round in 0..100 {
        let selection = Selection::select(&roster, &inputs, &secret_for(round)).unwrap();
        assert!(selection.sufficient, "round {round} filled its seats");
        let seated: BTreeSet<&str> = selection
            .selected
            .iter()
            .map(|seat| seat.key_id.as_str())
            .collect();
        for key in &family {
            assert!(
                !seated.contains(&**key),
                "round {round} seated {} of the author's family: {:?}",
                key,
                selection
                    .selected
                    .iter()
                    .map(|seat| &seat.key_id)
                    .collect::<Vec<_>>()
            );
        }
        // The audit check an auditor runs, on the round as published.
        let check = gitiup_quorum::ProposerExclusion::check(&roster, &inputs, &selection, &author);
        assert!(check.held(), "round {round}: {}", check.describe());
    }
}

/// The exclusion set is closed over the family before it reaches the round, so the audit
/// record says *why* each of the author's boxes is out (`excluded`, D7's order) instead
/// of leaving it to chance that a box was too slow or the wrong architecture.
#[test]
fn an_unexcluded_author_is_visible_in_the_audit_rather_than_lucky() {
    let owner = sample::owner_key();
    let entries: Vec<RosterEntry> = (0..10u8)
        .map(|index| {
            sample::entry_with(
                index,
                if index == 1 { 0 } else { index },
                EPOCH,
                RosterTier::Endorsed,
            )
        })
        .collect();
    let roster = sample::roster_of_entries(&owner, entries, EPOCH);
    let author = vec![sample::verifier_key(0).public_key().key_id()];

    // A round that forgot: same pool, no exclusion. The author's other box is still in
    // the eligible pool, and the check says so — that is the whole point of publishing
    // the exclusion list with the round.
    let forgot = round_for(&roster, symmetric_policy(N));
    let selection = Selection::select(&roster, &forgot, &secret_for(4)).unwrap();
    let check = gitiup_quorum::ProposerExclusion::check(&roster, &forgot, &selection, &author);
    assert_eq!(
        check.missing.len(),
        2,
        "both of the author's boxes were left in the pool"
    );
    assert!(!check.held());

    // The same round with the rule applied: nothing to report, and the seats it happens
    // to hold anyway are gone.
    let closed = forgot.excluding(&roster, &author).unwrap();
    let selection = Selection::select(&roster, &closed, &secret_for(4)).unwrap();
    let check = gitiup_quorum::ProposerExclusion::check(&roster, &closed, &selection, &author);
    assert!(check.held(), "{}", check.describe());
    assert_eq!(check.family.len(), 2);
}

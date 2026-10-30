//! Reputation: what a store's verdicts say about the roster, scored and never punished
//! ([giti-zp1.8](../../../README.md),
//! [ADR-0002 D5](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! [ADR-0002 D5](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)
//! allows reputation two powers — exclude, and demote — and forbids it one: to be a
//! multiplier. A continuous weight in the score would make the reputation function the
//! real trust anchor, un-auditable in exactly the way D1 exists to prevent. So nothing here
//! feeds a number into
//! [`Selection`](crate::select::Selection): this module counts what happened and prints it,
//! and the only thing a count can become is a
//! [`Quarantine`](crate::quarantine::Quarantine) that an owner signs.
//!
//! ```text
//!  verdicts (recomputed from the store, never remembered)
//!        │
//!        ├─► counted · divergent · rejected   ──► grounds a quarantine may cite
//!        └─► silent (a seat that never answered) ─► scored here, and nothing else
//! ```
//!
//! # Why silence is scored at all
//!
//! A seat that never answered is not innocent and not guilty: it is **capacity that is not
//! there**. A roster of eleven keys where four ever answer is a quorum of four wearing
//! eleven names, and the owner who believes the eleven is the one who merges at 4-of-4
//! thinking it was a wide sample. So turn-up is printed for every key and for the roster as
//! a whole ([`Report::capacity_note`]), which is the honest use of absence: a fact about the
//! roster, not a mark against a key.
//!
//! The other half of the honesty is [`Sheet::grounds`]: the counts that *may* be cited in a
//! quarantine are named, and silence is not among them. A report that let a turn-up rate
//! slide into an exclusion would be the reputation weight D5 rejects, wearing a table.
//!
//! # Recomputed, never remembered
//!
//! Every count is derived from verdict records on demand
//! ([`Report::from_verdicts`]) — the same rule every other command in this crate follows
//! ("the store is an index, not a memory"). Nothing accumulates in the background, so there
//! is no state to corrupt, no decay curve to argue about, and no second answer for two
//! auditors who ran the command a week apart: the answer is whatever the store's evidence
//! supports when asked.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::quarantine::reason_for_rejection;
use crate::roster::Roster;
use crate::verdict::{QuorumState, VerdictRecord};

/// One key's history, as the verdicts name it.
///
/// Every field is a count of something a verdict recorded, and each one can be traced back
/// to a `(change, job, attempt)` the caller can re-tally. No field is a judgement: "guilty"
/// lives in a signed [`Quarantine`](crate::quarantine::Quarantine), not in a table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sheet {
    /// The verifier key these counts are about.
    pub key_id: String,
    /// The principal it anchors, when a verdict or the roster says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Rounds this key held a seat in (`counted + divergent + rejected + silent`).
    pub seated: usize,
    /// Seats whose answer was counted toward the consensus.
    pub counted: usize,
    /// Seats whose answer was usable and disagreed with the consensus a `verified` verdict
    /// reached — the one divergence a quarantine may cite.
    pub divergent: usize,
    /// Seats that produced a result in a round that reached **no** consensus, so there is
    /// nothing for the answer to have diverged from. Scored; never a ground.
    pub contested: usize,
    /// Seats whose submission was refused, whatever the code said.
    pub rejected: usize,
    /// Seats that answered nothing. Scored, never punished.
    pub silent: usize,
    /// Refusal codes seen, with counts — the traceable half of [`Sheet::grounds`].
    pub codes: BTreeMap<String, usize>,
    /// The changes this key appeared in, so a count is never untraceable.
    pub changes: Vec<String>,
    /// The latest `issued_at_us` among the verdicts that named this key.
    pub last_seen_us: i64,
}

impl Sheet {
    /// Start a sheet for a key.
    pub fn new(key_id: impl Into<String>) -> Sheet {
        Sheet {
            key_id: key_id.into(),
            identity: None,
            seated: 0,
            counted: 0,
            divergent: 0,
            contested: 0,
            rejected: 0,
            silent: 0,
            codes: BTreeMap::new(),
            changes: Vec::new(),
            last_seen_us: 0,
        }
    }

    /// Seats that produced something the tally looked at.
    pub fn answered(&self) -> usize {
        self.counted + self.divergent + self.contested + self.rejected
    }

    /// The turn-up fraction `answered / seated`, or `None` for a key that was never seated.
    pub fn turn_up(&self) -> Option<f64> {
        if self.seated == 0 {
            return None;
        }
        Some(self.answered() as f64 / self.seated as f64)
    }

    /// `4/5` — the turn-up rate without a float's false precision.
    pub fn turn_up_text(&self) -> String {
        format!("{}/{}", self.answered(), self.seated)
    }

    /// What a quarantine could be written for, from this history, as `reason×count` tokens.
    ///
    /// Only codes [`reason_for_rejection`](crate::quarantine::reason_for_rejection)
    /// recognises appear, plus `divergence` for the seats that disagreed with a consensus
    /// that was reached. **Silence is never in this list** — a key that never turned up has
    /// no grounds against it, only a fact about the roster.
    pub fn grounds(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.divergent > 0 {
            out.push(format!("divergence\u{d7}{}", self.divergent));
        }
        // `contested` is deliberately absent: no consensus, no divergence to cite.
        for (code, count) in &self.codes {
            if let Some(reason) = reason_for_rejection(code) {
                out.push(format!("{reason}\u{d7}{count}"));
            }
        }
        out
    }
    /// Every code seen, whether or not it is a quarantine ground.
    pub fn code_text(&self) -> String {
        if self.codes.is_empty() {
            return "none".to_string();
        }
        self.codes
            .iter()
            .map(|(code, count)| format!("{code}\u{d7}{count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether the only thing wrong with this key is that it did not turn up.
    pub fn silence_only(&self) -> bool {
        self.silent > 0 && self.divergent == 0 && self.contested == 0 && self.codes.is_empty()
    }

    /// Whether it ever answered a seat at all. The theatre test, per key.
    pub fn never_answered(&self) -> bool {
        self.seated > 0 && self.answered() == 0
    }
}

/// One roster's history, read out of its verdicts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// One row per key the verdicts named, worst turn-up first (an owner reads the top).
    pub sheets: Vec<Sheet>,
    /// Verdicts read.
    pub verdicts: usize,
    /// The changes those verdicts were about.
    pub changes: Vec<String>,
    /// Roster epoch the report was read against, when a roster was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// Roster size, when a roster was supplied: the number the theatre is measured against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_entries: Option<usize>,
}

impl Report {
    /// Count what these verdicts say.
    ///
    /// `roster` is optional and used only for a key's identity and for the roster-size
    /// column: the counts come from the verdicts, because a key can be named by a verdict
    /// for an epoch the current roster no longer lists.
    pub fn from_verdicts(verdicts: &[VerdictRecord], roster: Option<&Roster>) -> Report {
        let mut sheets: BTreeMap<String, Sheet> = BTreeMap::new();
        let mut changes: Vec<String> = Vec::new();
        for verdict in verdicts {
            if !changes.iter().any(|change| change == &verdict.change_id) {
                changes.push(verdict.change_id.clone());
            }
            let mut named: Vec<&str> = Vec::new();
            for vote in &verdict.counted {
                Self::sheet(&mut sheets, &vote.key_id).counted += 1;
                let sheet = sheets.get_mut(&vote.key_id).expect("just inserted");
                if sheet.identity.is_none() {
                    sheet.identity = Some(vote.identity.clone());
                }
                named.push(&vote.key_id);
            }
            // A `failed` verdict names a minority but has no consensus for it to have
            // diverged from, so those rows are scored as contested and are not grounds.
            let divergence = counts_toward_divergence(verdict);
            for group in &verdict.divergent {
                for key_id in &group.keys {
                    let sheet = Self::sheet(&mut sheets, key_id);
                    if divergence {
                        sheet.divergent += 1;
                    } else {
                        sheet.contested += 1;
                    }
                    named.push(key_id);
                }
            }
            for rejection in &verdict.rejected {
                let sheet = Self::sheet(&mut sheets, &rejection.key_id);
                sheet.rejected += 1;
                *sheet.codes.entry(rejection.code.clone()).or_insert(0) += 1;
                if sheet.identity.is_none() {
                    sheet.identity = rejection.identity.clone();
                }
                named.push(&rejection.key_id);
            }
            for key_id in &verdict.missing {
                Self::sheet(&mut sheets, key_id).silent += 1;
                named.push(key_id);
            }
            for key_id in named {
                let sheet = sheets.get_mut(key_id).expect("named keys were inserted");
                sheet.seated += 1;
                sheet.last_seen_us = sheet.last_seen_us.max(verdict.issued_at_us);
                if !sheet.changes.iter().any(|c| c == &verdict.change_id) {
                    sheet.changes.push(verdict.change_id.clone());
                }
            }
        }
        // The roster knows identities the verdicts never had to name.
        if let Some(roster) = roster {
            for entry in &roster.entries {
                if let Some(sheet) = sheets.get_mut(&entry.key_id)
                    && sheet.identity.is_none()
                {
                    sheet.identity = Some(entry.identity.clone());
                }
            }
        }
        let mut sheets: Vec<Sheet> = sheets.into_values().collect();
        // Worst turn-up first, then most divergent, then key id: an owner reads the top of
        // this table, and the interesting rows are the ones that answered least.
        sheets.sort_by(|a, b| {
            a.turn_up()
                .unwrap_or(1.0)
                .partial_cmp(&b.turn_up().unwrap_or(1.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.divergent.cmp(&a.divergent))
                .then(a.key_id.cmp(&b.key_id))
        });
        Report {
            sheets,
            verdicts: verdicts.len(),
            changes,
            epoch: roster.map(|roster| roster.epoch),
            roster_entries: roster.map(|roster| roster.entries.len()),
        }
    }

    fn sheet<'a>(sheets: &'a mut BTreeMap<String, Sheet>, key_id: &str) -> &'a mut Sheet {
        sheets
            .entry(key_id.to_string())
            .or_insert_with(|| Sheet::new(key_id))
    }

    /// One key's row.
    pub fn sheet_for(&self, key_id: &str) -> Option<&Sheet> {
        self.sheets.iter().find(|sheet| sheet.key_id == key_id)
    }

    /// Seats handed out, and seats that went silent, across everything read.
    pub fn seats(&self) -> (usize, usize) {
        let seats: usize = self.sheets.iter().map(|sheet| sheet.seated).sum();
        let silent: usize = self.sheets.iter().map(|sheet| sheet.silent).sum();
        (seats, silent)
    }

    /// Keys that ever held a seat, and keys that ever answered one.
    pub fn keys(&self) -> (usize, usize) {
        let held = self.sheets.len();
        let answered = self
            .sheets
            .iter()
            .filter(|sheet| sheet.answered() > 0)
            .count();
        (held, answered)
    }

    /// Whether this roster is more theatre than capacity.
    ///
    /// The threshold is deliberately crude and stated in the open: **a third of the seats
    /// the quorum handed out went unanswered**. Anything subtler is a reputation weight
    /// again, and the point of a threshold this blunt is that an owner can recompute it in
    /// their head from the table printed beside it.
    pub fn theatre(&self) -> bool {
        let (seats, silent) = self.seats();
        if seats == 0 {
            return false;
        }
        silent * 3 >= seats
    }

    /// The sentence an owner has to read, in the roster's own numbers.
    pub fn capacity_note(&self) -> String {
        let (seats, silent) = self.seats();
        let (held, answered) = self.keys();
        if seats == 0 {
            return "no seat has been handed out in what this store holds, so there is no \
                    history to score — which is not the same as a clean record."
                .to_string();
        }
        let percent = (silent as f64 * 100.0 / seats as f64).round();
        let mut note = format!(
            "{held} key(s) held {seats} seat(s) across {} verdict(s); {answered} ever \
             answered, so {silent} seat(s) ({percent:.0}%) went silent.",
            self.verdicts
        );
        if let Some(entries) = self.roster_entries {
            note.push_str(&format!(
                " The roster lists {entries} entr(ies){}.",
                if held < entries {
                    " — the rest have never been seated at all"
                } else {
                    ""
                }
            ));
        }
        if self.theatre() {
            note.push_str(
                " That is more than a third of the seats: this roster is closer to theatre \
                 than capacity, and a verdict reached by the keys that do turn up should be \
                 read with that in mind.",
            );
        } else {
            note.push_str(
                " Absence is scored, not punished: nothing here is grounds for a quarantine.",
            );
        }
        note
    }
}

/// Whether a verdict is one a reputation count may use.
///
/// An `insufficient` verdict counted nobody, so its `missing` rows say something about
/// turn-up and nothing about agreement; a `failed` verdict names divergence without naming
/// a consensus, so its divergent rows are **not** counted as divergence. Kept as a
/// function so the rule is in one place, and the reason is spelled out at both call sites
/// of [`Report::from_verdicts`].
pub fn counts_toward_divergence(verdict: &VerdictRecord) -> bool {
    verdict.state == QuorumState::Verified
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample;
    use crate::verdict::Evaluation;

    fn verdict_with(diverge: usize) -> VerdictRecord {
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        let inputs = sample::round_inputs(&roster, "chg-1", "build");
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let round = {
            use crate::round::Round;
            let mut round = Round::open(&inputs, &roster, &secret).unwrap();
            round.sign(&owner).unwrap();
            round
        };
        let seats = sample::indices_of(&round);
        let attestations = sample::attest(&round, &seats, sample::claimed_at_us(), |position| {
            (position < diverge).then(|| "test result: FAILED. 41 passed".to_string())
        });
        VerdictRecord::evaluate(
            &round,
            &roster,
            &attestations,
            &[],
            &Evaluation::at(sample::clock()),
        )
        .unwrap()
    }

    #[test]
    fn divergence_is_a_ground_and_silence_is_not() {
        let verdict = verdict_with(1);
        let report = Report::from_verdicts(&[verdict.clone()], None);
        assert!(
            report
                .sheets
                .iter()
                .any(|sheet| !sheet.grounds().is_empty()),
            "a diverging seat names a ground"
        );
        // One seat never answered: it is counted, and it is not a ground.
        let silent_key = verdict.missing.first().cloned();
        if let Some(key_id) = silent_key {
            let sheet = report.sheet_for(&key_id).expect("the silent seat is a row");
            assert_eq!(sheet.silent, 1);
            assert!(
                sheet.grounds().is_empty(),
                "silence is scored, never a quarantine ground"
            );
            assert!(sheet.silence_only());
        }
    }

    #[test]
    fn an_unanswered_roster_reads_as_theatre() {
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        let inputs = sample::round_inputs(&roster, "chg-1", "build");
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let round = {
            use crate::round::Round;
            let mut round = Round::open(&inputs, &roster, &secret).unwrap();
            round.sign(&owner).unwrap();
            round
        };
        // Nobody answered: `insufficient`, and every seat is `missing`.
        let verdict =
            VerdictRecord::evaluate(&round, &roster, &[], &[], &Evaluation::at(sample::clock()))
                .unwrap();
        assert_eq!(verdict.state, QuorumState::Insufficient);
        let report = Report::from_verdicts(&[verdict], Some(&roster));
        assert!(report.theatre(), "every seat silent is the theatre case");
        assert!(report.capacity_note().contains("theatre"));
        assert!(
            report.sheets.iter().all(|sheet| sheet.grounds().is_empty()),
            "and none of it is a quarantine ground"
        );
    }
}

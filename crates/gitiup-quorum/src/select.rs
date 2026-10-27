//! The selection: who is asked, in what order, and why
//! ([ADR-0002 D3](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! One pure function, one golden vector set, and no I/O, clock or randomness. The
//! ADR's D3 is the normative text;
//! [`docs/adr/fixtures/selection-v1/`](../../../docs/adr/fixtures/selection-v1/README.md)
//! is the byte-for-byte contract, and `tests/selection_vectors.rs` here is what
//! keeps the two honest.
//!
//! ```text
//! seed(k)   = HMAC-SHA256(selection_secret, round_id)          # one per round
//! score(K)  = SHA256("gitiup-round-1/score" ‖ 0x00 ‖ seed ‖ 0x00 ‖ utf8(K))
//! order     = candidates sorted by (score as a 256-bit integer ASC, then utf8(key_id) ASC)
//! fill      = one greedy pass in that order, applying the D7 filters and the caps
//! ```
//!
//! Three properties that only hold because of how this is written:
//!
//! * **Nobody chooses the five.** The seed is keyed and derived, so the selector
//!   cannot re-roll a roster it dislikes and a proposer cannot shop for a friendly
//!   jury without pushing a new head (which the verdict is bound to anyway).
//! * **Caps only remove.** `tier_caps` and `max_per_identity` are maximum seats, never
//!   weights, so a tier can never make a candidate more likely than its cap.
//! * **Insufficient is a verdict.** If fewer than `n` candidates survive, this
//!   returns what it has with `sufficient: false`; nobody silently lowers the bar.
//!
//! Reserves are a *listing*, not a second decision: promotion re-runs the same round
//! with a longer exclusion list and takes the head of the new list, so an issuer who
//! could otherwise pick a substitute could steer the quorum.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use gitiup_attest::{Digest, GitOid};
use serde::{Deserialize, Serialize};

use crate::capability::{Requirements, RosterTier, exclusion_of};
use crate::derive::{self, SelectionSecret, handle, key_slot, require_round_kind, score};
use crate::error::{Error, Result};
use crate::record;
use crate::roster::Roster;

/// The selection document's `kind`.
pub const SELECTION_KIND: &str = "selection";
/// Schema version of the selection document.
pub const SELECTION_SCHEMA_VERSION: u32 = 1;

/// Round inputs and selection knobs for one job, one attempt
/// ([ADR-0002 D3 "Inputs"](#the-algorithm-precisely)).
///
/// This is `round.json` in the ADR-0002 fixture set, so the field names are that
/// file's: reading the vectors *is* reading this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundInputs {
    /// Must be [`SELECTION_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// `"round"` in the fixture set. Optional because a *round record* carries this
    /// in its own `type` field and must not repeat it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The selection generation; must be [`ROUND_KIND`] for this build.
    pub round_kind: String,
    /// The roster epoch this round pins. Must equal `roster.epoch`.
    pub roster_epoch: u64,
    /// Digest of the roster's canonical bytes: the pin that stops an owner editing
    /// the trust list mid-round (D8).
    pub roster_digest: Digest,
    /// The change being verified.
    pub change_id: String,
    /// The head the change points at right now. The verdict binds to it, which is
    /// what makes "push until you get friendly verifiers" cost a new change.
    pub head_oid: GitOid,
    /// The job (matrix vector) within the change. Opaque here, but it must be
    /// stable and store-assigned, or two runs of one matrix arm get two seeds.
    pub job_id: String,
    /// `0` is the first round; `≥ 1` are escalations (giti-msi.8), which change the
    /// seed and the exclusion list and nothing else.
    pub attempt: u64,
    /// What the job needs. Derived from the job, never from what a verifier wishes.
    pub required_capabilities: Requirements,
    /// Key ids *or identity key ids*; naming a principal excludes their whole family
    /// (D4). This is where the proposer and quarantined keys come in.
    pub exclusions: BTreeSet<String>,
    /// The policy in force, published with the round and covered by the selector's
    /// signature so it cannot be quietly re-interpreted later.
    pub policy: SelectionPolicy,
}

impl RoundInputs {
    /// Check the inputs, including the round kind this build implements.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SELECTION_SCHEMA_VERSION {
            return Err(Error::unsupported(
                "round",
                format!(
                    "round schema_version {} is not understood",
                    self.schema_version
                ),
            ));
        }
        if let Some(kind) = &self.kind
            && kind != "round"
        {
            return Err(Error::unsupported(
                "round",
                format!("unknown kind '{kind}'"),
            ));
        }
        require_round_kind(&self.round_kind)?;
        require_round_inputs(&self.change_id, "change id")?;
        require_round_inputs(&self.job_id, "job id")?;
        self.required_capabilities.validate()?;
        self.policy.validate()?;
        for key_id in &self.exclusions {
            crate::record::require_key_id_shape(key_id, "exclusion")?;
        }
        Ok(())
    }

    /// The seven seed-message fields (D2), in order.
    pub fn round_fields(&self) -> [String; 7] {
        [
            self.round_kind.clone(),
            self.roster_epoch.to_string(),
            self.roster_digest.hex(),
            self.change_id.clone(),
            self.head_oid.to_string(),
            self.job_id.clone(),
            self.attempt.to_string(),
        ]
    }

    /// The exact HMAC message the seed is keyed on (NUL-separated).
    pub fn round_id_message(&self) -> Result<Vec<u8>> {
        let fields = self.round_fields();
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        derive::round_id_message(&refs)
    }

    /// The readable `/`-joined form, for `--explain` and logs.
    pub fn round_id_display(&self) -> Result<String> {
        let fields = self.round_fields();
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        derive::round_id_display(&refs)
    }

    /// The seed of this round under `secret` — the selector's call.
    pub fn seed(&self, secret: &SelectionSecret) -> Result<Digest> {
        Ok(derive::round_seed(secret, &self.round_id_message()?))
    }

    /// Digest over the canonical inputs, recorded by verdicts so a reviewer can see
    /// exactly which inputs a verdict was drawn from.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&record::canonical_bytes(self)?))
    }
}

/// The keys a caller may not fiddle with per change.
///
/// `n` and `required_agree` are the two numbers the epic's acceptance criterion is
/// about: five volunteers, four agreeing, from *distinct identities*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPolicy {
    /// Seats to fill for this job.
    pub n: usize,
    /// How many reserves the round record publishes (advice; promotion is a re-run).
    pub reserves: usize,
    /// Matching `ResultDigest`s needed, from distinct identities, for `Verified`.
    pub required_agree: usize,
    /// Tiers below this are not eligible at all.
    pub tier_floor: RosterTier,
    /// Maximum seats per tier. A tier with no entry gets no seats at all, which is
    /// the conservative reading of a policy that forgot one.
    pub tier_caps: BTreeMap<String, u32>,
    /// Maximum seats per identity. Vote weight is one per identity forever (D4);
    /// this is only about *seats*, and the default of 1 is the value that makes
    /// "ten machines, one vote" true.
    pub max_per_identity: u32,
}

impl Default for SelectionPolicy {
    /// The ADR-0002 defaults: five seats, four agreeing, two reserves, no floor,
    /// one trusted seat at most, one unvouched seat at most, one seat per identity.
    fn default() -> Self {
        SelectionPolicy {
            n: 5,
            reserves: 2,
            required_agree: 4,
            tier_floor: RosterTier::Anonymous,
            tier_caps: BTreeMap::from([
                ("trusted".to_string(), 1),
                ("endorsed".to_string(), 4),
                ("anonymous".to_string(), 1),
            ]),
            max_per_identity: 1,
        }
    }
}

impl SelectionPolicy {
    /// The escalation policy for `attempt ≥ 1` (giti-msi.8): a wider selection over
    /// the same pool — `n + 2` seats, `required_agree + 1` — never a lower bar.
    pub fn escalated(&self) -> SelectionPolicy {
        SelectionPolicy {
            n: self.n + 2,
            required_agree: self.required_agree + 1,
            reserves: self.reserves + 1,
            ..self.clone()
        }
    }

    /// Structural sanity. A policy that asks for more agreement than seats is a
    /// mistake that would be found at merge time, so it is refused here instead.
    pub fn validate(&self) -> Result<()> {
        if self.n == 0 {
            return Err(Error::invalid("policy", "n must be at least 1"));
        }
        if self.required_agree == 0 {
            return Err(Error::invalid(
                "policy",
                "required_agree of 0 would certify anything, including nothing",
            ));
        }
        if self.required_agree > self.n {
            return Err(Error::invalid(
                "policy",
                format!(
                    "required_agree {} cannot be reached with n {} seats",
                    self.required_agree, self.n
                ),
            ));
        }
        if self.max_per_identity == 0 {
            return Err(Error::invalid(
                "policy",
                "max_per_identity 0 would seat nobody; one identity casts one vote",
            ));
        }
        if self.n > 64 {
            return Err(Error::invalid(
                "policy",
                format!(
                    "n {} is past the 64-seat bound this build checks signatures for",
                    self.n
                ),
            ));
        }
        for (tier, cap) in &self.tier_caps {
            RosterTier::parse(tier)
                .map_err(|e| Error::invalid("policy", format!("tier_caps: {e}")))?;
            // A cap above `n` is bounded by the seat count anyway, but it is always a
            // typo about what the policy meant, so say so where the reader is.
            if *cap > self.n as u32 {
                return Err(Error::invalid(
                    "policy",
                    format!("tier_caps['{tier}'] = {cap} exceeds n = {}", self.n),
                )
                .with_hint("a cap can only remove candidates; one at or below the seat count says the same thing"));
            }
        }
        Ok(())
    }

    /// Seats allowed for `tier` (absent means none).
    pub fn cap_for(&self, tier: RosterTier) -> u32 {
        self.tier_caps.get(tier.as_str()).copied().unwrap_or(0)
    }

    /// Digest over the canonical policy: published in the round record and in the
    /// selection, so "which policy produced this quorum" is one number a stranger
    /// can re-check against the record they read.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&record::canonical_bytes(self)?))
    }
}

/// The greedy verdict for one candidate, in the order the pass reached it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Greedy {
    /// It was eligible and had room under both caps.
    Take,
    /// Eligible, but a cap had already filled.
    Skip,
    /// Filtered out before the caps applied; see `excluded_by`.
    Ineligible,
}

impl Greedy {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Greedy::Take => "take",
            Greedy::Skip => "skip",
            Greedy::Ineligible => "ineligible",
        }
    }
}

/// One row of the audit table: every roster entry, whether it could have been picked,
/// and what the pass decided.
///
/// This is part of the contract, not a debug dump. It is what a reviewer who does not
/// trust the selector reads, so the reason recorded is the *first* failing filter
/// (D7) and the ordering is total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRow {
    /// The candidate's key id.
    pub key_id: String,
    /// Its score as 64 lower-case hex digits (the ordering key, D3).
    pub score: String,
    /// Whether it survived the D7 filters.
    pub eligible: bool,
    /// The first filter it failed, or `null` if none. `null` rather than absent
    /// because this is an audit document, not a signed record (ADR-0001 D1 rule 5
    /// forbids nulls in signed records precisely so that a signature cannot be
    /// ambiguous about a missing field; an unsigned audit table has no signature to
    /// confuse).
    pub excluded_by: Option<String>,
    /// The greedy verdict.
    pub greedy: Greedy,
    /// `identity` or `tier_cap` when `greedy` is `skip`, empty otherwise.
    pub greedy_reason: String,
    /// Whether it took one of the `n` seats.
    pub selected: bool,
}

/// A filled seat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seat {
    /// 1-based position in the score order among selected candidates.
    pub rank: u32,
    /// The verifier's key id.
    pub key_id: String,
    /// Its principal, for the one-vote-per-identity rule at verdict time.
    pub identity: String,
    /// The hex storage slot for its submission (D10).
    pub slot: String,
    /// The tier it was selected under.
    pub tier: RosterTier,
    /// The seed-derived pseudonym (D11); the address a sealed reveal would use.
    pub handle: String,
}

/// A reserve: eligible, eligible-but-unseated, listed in score order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reserve {
    /// 1-based position among reserves.
    pub rank: u32,
    /// The verifier's key id.
    pub key_id: String,
    /// Its storage slot.
    pub slot: String,
    /// Its tier.
    pub tier: RosterTier,
}

/// The selection: the seed, the audit table, the seats and the reserves.
///
/// Deriving this from a roster plus a published seed is what makes a selection
/// auditable by somebody who was not invited (D3 "Auditing").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    /// Always [`SELECTION_KIND`].
    pub kind: String,
    /// Must be [`SELECTION_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The selection generation.
    pub round_kind: String,
    /// The readable round id (`/`-joined; the HMAC message uses NUL).
    pub round_id: String,
    /// The published seed. Public from advertisement onward, and unguessable before
    /// it (D11).
    pub seed: Digest,
    /// Digest of the policy that produced this, so the policy cannot be re-read
    /// differently later.
    pub policy_digest: Digest,
    /// How many roster entries survived the D7 filters.
    pub eligible: usize,
    /// Whether `n` seats were filled. `false` is the `Insufficient` input to
    /// giti-msi.7, not a shrug.
    pub sufficient: bool,
    /// The selected verifiers, in score order.
    pub selected: Vec<Seat>,
    /// Eligible candidates that did not get a seat, in score order: the promotion
    /// order.
    pub reserves: Vec<Reserve>,
    /// Every roster entry, in score order, with its verdict.
    pub candidates: Vec<CandidateRow>,
}

impl Selection {
    /// The selection for `inputs`, deriving the seed from `secret` (the selector's
    /// path).
    pub fn select(
        roster: &Roster,
        inputs: &RoundInputs,
        secret: &SelectionSecret,
    ) -> Result<Selection> {
        let seed = inputs.seed(secret)?;
        Selection::with_seed(roster, inputs, seed)
    }

    /// The selection for `inputs` given a published `seed` — the auditor's path, and
    /// the verifier's check that the published selection is the derived one.
    pub fn with_seed(roster: &Roster, inputs: &RoundInputs, seed: Digest) -> Result<Selection> {
        inputs.validate()?;
        if inputs.kind.is_some() && inputs.kind.as_deref() != Some("round") {
            return Err(Error::unsupported(
                "round",
                "kind must be \"round\" when present",
            ));
        }
        if inputs.roster_epoch != roster.epoch {
            return Err(Error::policy(
                "selection",
                format!(
                    "this round pins roster epoch {} but the roster in hand is epoch {}; \
                     selection is only reproducible against the roster the selector used",
                    inputs.roster_epoch, roster.epoch
                ),
            ));
        }
        let digest = roster.digest()?;
        if digest != inputs.roster_digest {
            return Err(Error::digest_mismatch(
                "selection",
                format!(
                    "roster digest is {digest}, but this round pins {}; the roster was changed \
                     after the round was opened (or this is not the store the round was opened in)",
                    inputs.roster_digest
                ),
            )
            .with_hint("re-fetch refs/gitiup/roster and re-check the epoch; a round never adapts to a new roster"));
        }

        let seed_bytes = seed
            .as_bytes()
            .try_into()
            .map_err(|_| Error::invalid("selection", "a round seed is 32 bytes"))?;

        // One row per roster entry, kept next to the entry it describes so the
        // greedy pass can read tier and identity after the sort reorders them.
        let mut rows: Vec<Row<'_>> = roster
            .entries
            .iter()
            .map(|entry| {
                // Scores are computed for *every* entry, excluded ones included: the
                // audit record is supposed to explain the near-misses too (D3).
                let excluded_by = exclusion_of(
                    entry,
                    inputs.roster_epoch,
                    &inputs.required_capabilities,
                    &inputs.exclusions,
                    inputs.policy.tier_floor,
                );
                Row {
                    row: CandidateRow {
                        key_id: entry.key_id.clone(),
                        score: score(&seed_bytes, &entry.key_id),
                        eligible: excluded_by.is_none(),
                        excluded_by: excluded_by.map(|e| e.to_string()),
                        greedy: Greedy::Ineligible,
                        greedy_reason: String::new(),
                        selected: false,
                    },
                    entry,
                }
            })
            .collect();

        // Total order: score ascending as a 256-bit big-endian integer (a fixed-length
        // lower-case hex string compares the same way), then `key_id` by ascending
        // UTF-8 bytes. Key ids are unique within an epoch, so this is a total order
        // and no implementation may rely on sort stability.
        rows.sort_by(|a, b| {
            a.row
                .score
                .cmp(&b.row.score)
                .then(a.row.key_id.cmp(&b.row.key_id))
        });

        let policy = &inputs.policy;
        let mut identity_seats: BTreeMap<&str, u32> = BTreeMap::new();
        let mut tier_seats: BTreeMap<RosterTier, u32> = BTreeMap::new();
        let mut seats = 0usize;
        for row in rows.iter_mut() {
            let entry = row.entry;
            if !row.row.eligible {
                row.row.greedy = Greedy::Ineligible;
                continue;
            }
            let room_identity = identity_seats
                .get(entry.identity.as_str())
                .copied()
                .unwrap_or(0)
                < policy.max_per_identity;
            let room_tier =
                tier_seats.get(&entry.tier).copied().unwrap_or(0) < policy.cap_for(entry.tier);
            if room_identity && room_tier {
                row.row.greedy = Greedy::Take;
            } else {
                row.row.greedy = Greedy::Skip;
                row.row.greedy_reason = if !room_identity {
                    "identity".to_string()
                } else {
                    "tier_cap".to_string()
                };
            }
            // The pass keeps walking after `n` so every row gets a label, and the
            // selected set is identical either way (D3).
            if row.row.greedy == Greedy::Take && seats < policy.n {
                *identity_seats.entry(entry.identity.as_str()).or_insert(0) += 1;
                *tier_seats.entry(entry.tier).or_insert(0) += 1;
                seats += 1;
                row.row.selected = true;
            }
        }

        let selected: Vec<Seat> = rows
            .iter()
            .filter(|row| row.row.selected)
            .enumerate()
            .map(|(rank, row)| Seat {
                rank: (rank + 1) as u32,
                key_id: row.entry.key_id.clone(),
                identity: row.entry.identity.clone(),
                slot: key_slot(&row.entry.key_id),
                tier: row.entry.tier,
                handle: handle(&seed_bytes, &row.entry.key_id),
            })
            .collect();
        // The reserve list is an *advice listing* in the same score order: promotion
        // is the re-run, not this list (D3).
        let reserves: Vec<Reserve> = rows
            .iter()
            .filter(|row| row.row.eligible && !row.row.selected)
            .enumerate()
            .map(|(rank, row)| Reserve {
                rank: (rank + 1) as u32,
                key_id: row.entry.key_id.clone(),
                slot: key_slot(&row.entry.key_id),
                tier: row.entry.tier,
            })
            .collect();

        Ok(Selection {
            kind: SELECTION_KIND.to_string(),
            schema_version: SELECTION_SCHEMA_VERSION,
            round_kind: inputs.round_kind.clone(),
            round_id: inputs.round_id_display()?,
            seed,
            policy_digest: inputs.policy.digest()?,
            eligible: rows.iter().filter(|r| r.row.eligible).count(),
            sufficient: selected.len() == policy.n,
            selected,
            reserves,
            candidates: rows.into_iter().map(|row| row.row).collect(),
        })
    }

    /// Reassignment: re-run the same round with a longer exclusion list and take the
    /// head of the new list (D3). Never a new seed, because an issuer who could pick
    /// a substitute could steer the quorum.
    pub fn promote(
        roster: &Roster,
        inputs: &RoundInputs,
        seed: Digest,
        voided: &BTreeSet<String>,
    ) -> Result<Selection> {
        let mut extended = inputs.clone();
        for key_id in voided {
            crate::record::require_key_id_shape(key_id, "voided key")?;
            extended.exclusions.insert(key_id.clone());
        }
        // Same round, same seed, same epoch: only the pool changes, so the ordering is
        // untouched and a promotion is not a new decision.
        Selection::with_seed(roster, &extended, seed)
    }

    /// The seed-derived handle of a selected verifier (D11).
    pub fn handle_for(&self, key_id: &str) -> Option<String> {
        self.selected
            .iter()
            .find(|seat| seat.key_id == key_id)
            .map(|seat| seat.handle.clone())
    }

    /// Refuse a selection document that was not produced by a selection function.
    pub fn validate(&self) -> Result<()> {
        if self.kind != SELECTION_KIND || self.schema_version != SELECTION_SCHEMA_VERSION {
            return Err(Error::unsupported(
                "selection",
                format!(
                    "unknown selection document '{}' v{}",
                    self.kind, self.schema_version
                ),
            ));
        }
        require_round_kind(&self.round_kind)?;
        if self.selected.is_empty() && self.sufficient {
            return Err(Error::invalid(
                "selection",
                "a selection cannot be sufficient with no seats",
            ));
        }
        let mut ranks: Vec<u32> = self.selected.iter().map(|s| s.rank).collect();
        ranks.sort_unstable();
        if ranks.iter().enumerate().any(|(i, r)| *r != (i + 1) as u32) {
            return Err(Error::invalid(
                "selection",
                "seat ranks must be 1..=n with no gaps: a gap means a seat was decided twice",
            ));
        }
        Ok(())
    }

    /// Compare a published selection against a recomputed one, naming the first
    /// difference.
    ///
    /// This is the verifier's step 4 (D11): the published list must match
    /// byte-for-byte, or somebody is not reading the same roster.
    pub fn matches(&self, recomputed: &Selection) -> std::result::Result<(), String> {
        if self.seed != recomputed.seed {
            return Err(format!(
                "seed differs: published {}, recomputed {}",
                self.seed, recomputed.seed
            ));
        }
        if self.policy_digest != recomputed.policy_digest {
            return Err(format!(
                "policy digest differs: published {}, recomputed {}",
                self.policy_digest, recomputed.policy_digest
            ));
        }
        let mine: Vec<&str> = self.selected.iter().map(|s| s.key_id.as_str()).collect();
        let theirs: Vec<&str> = recomputed
            .selected
            .iter()
            .map(|s| s.key_id.as_str())
            .collect();
        if mine != theirs {
            return Err(format!(
                "selected set differs: published [{}], recomputed [{}]",
                mine.join(", "),
                theirs.join(", ")
            ));
        }
        Ok(())
    }

    /// The human audit table: `gitiup select --explain`.
    ///
    /// Not a debug dump. A reviewer who does not trust the selector reads exactly
    /// this, so it prints the inputs, the seed, and one row per roster entry with
    /// the reason a near-miss missed.
    pub fn explain(&self, roster: &Roster) -> String {
        let mut out = String::new();
        out.push_str(&format!("round id      {}\n", self.round_id));
        out.push_str(&format!("seed          {}\n", self.seed));
        out.push_str(&format!("policy digest {}\n", self.policy_digest));
        out.push_str(&format!(
            "eligible      {} of {} roster entries\n",
            self.eligible,
            roster.entries.len()
        ));
        out.push_str(&format!(
            "seats         {} filled, sufficient={}\n",
            self.selected.len(),
            self.sufficient
        ));
        let head = format!(
            "{:<3} {:<20} {:<20} {:<9} {:<18} {:<12} {}",
            "#", "machine", "principal", "tier", "score", "slot", "verdict"
        );
        out.push_str(&head);
        out.push('\n');
        out.push_str(&"-".repeat(head.len()));
        out.push('\n');
        let rank_of = |key_id: &str| -> String {
            self.selected
                .iter()
                .find(|s| s.key_id == key_id)
                .map(|s| s.rank.to_string())
                .or_else(|| {
                    self.reserves
                        .iter()
                        .find(|r| r.key_id == key_id)
                        .map(|r| format!("r{}", r.rank))
                })
                .unwrap_or_else(|| "-".to_string())
        };
        for row in &self.candidates {
            let verdict = match (&row.excluded_by, row.greedy) {
                (Some(reason), _) => reason.clone(),
                (None, Greedy::Skip) => format!("reserve:{}", row.greedy_reason),
                (None, Greedy::Take) if row.selected => "selected".to_string(),
                (None, Greedy::Take) => "reserve".to_string(),
                (None, Greedy::Ineligible) => "ineligible".to_string(),
            };
            out.push_str(&format!(
                "{:<3} {:<20} {:<20} {:<9} {:<18} {:<12} {}\n",
                rank_of(&row.key_id),
                crate::record::short_key(&row.key_id),
                roster
                    .entry(&row.key_id)
                    .map(|e| crate::record::short_key(&e.identity))
                    .unwrap_or_else(|| "?".to_string()),
                roster
                    .entry(&row.key_id)
                    .map(|e| e.tier.as_str())
                    .unwrap_or("?"),
                short_hex(&row.score),
                short_hex(&key_slot(&row.key_id)),
                verdict,
            ));
        }
        out
    }
}

/// Shorten a hex digest for a terminal line: the first 12 characters and an ellipsis.
/// Display only — the stored document always holds the whole digest.
fn short_hex(hex: &str) -> String {
    if hex.len() <= 12 {
        hex.to_string()
    } else {
        format!("{}\u{2026}", &hex[..12])
    }
}

/// One row of the audit table plus the entry it describes.
///
/// Internal and temporary: pairing them survives the score sort, which reorders the
/// rows but not the roster.
struct Row<'a> {
    row: CandidateRow,
    entry: &'a crate::roster::RosterEntry,
}

/// A round field must be non-empty and NUL-free (D2).
fn require_round_inputs(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() {
        return Err(Error::invalid("round", format!("{what} is required")));
    }
    if text.contains('\0') {
        return Err(Error::invalid(
            "round",
            format!("{what} contains a NUL byte, which would make the seed message ambiguous"),
        ));
    }
    Ok(())
}

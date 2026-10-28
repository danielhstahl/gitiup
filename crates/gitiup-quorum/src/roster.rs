//! The roster: who may verify, as a signed, epoch-versioned document
//! ([ADR-0002 D4, D8, D9](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! The roster is the trust root of the whole quorum, and it is deliberately boring:
//! a list of keys with capabilities, an epoch number, a validity window, and the
//! owner's signature. Membership *is* that signature. There is no protocol, no
//! handshake and no directory — a participant publishes a self-signed sign-up, the
//! owner either puts the entry in the next epoch or does not.
//!
//! Three properties the rest of the crate leans on:
//!
//! * **A round pins `roster_epoch` *and* `roster_digest`.** Selection is only
//!   reproducible against the roster the selector actually used, so an owner who
//!   edits the roster mid-round breaks every verifier's check rather than quietly
//!   changing who they are (D8).
//! * **Epochs are time-derived** (`max(prev + 1, now / interval)`), so "which epoch
//!   should be current?" is computable without asking anyone, and an owner on
//!   holiday degrades to *expiry* rather than to silent staleness.
//! * **Withdrawal is a removal plus a signed record, never a null.** The canonical
//!   form forbids nulls (ADR-0001 D1 rule 5), which is also what stops "revoked"
//!   from becoming a field a store can forget to copy.

use std::collections::BTreeSet;

use gitiup_attest::{MAX_SIGNATURES, SignatureEntry, Signer, TimeUs, Trust};
use serde::{Deserialize, Serialize};

use crate::capability::Capabilities;
use crate::error::{Error, Result};
use crate::record::{
    REVOCATION_PAYLOAD_TYPE, ROSTER_ENTRY_PAYLOAD_TYPE, ROSTER_PAYLOAD_TYPE,
    WITHDRAWAL_PAYLOAD_TYPE, body_bytes, canonical_bytes, check_signatures, from_canonical_bytes,
    require_key_id_shape, require_same_bytes, sign, verify_one,
};

/// The `type` of a v1 roster.
pub const ROSTER_TYPE: &str = "gitiup-roster-1";
/// The `type` of a sign-up record (`gitiup participant register`).
pub const SIGNUP_TYPE: &str = "gitiup-signup-1";
/// The `type` of a withdrawal record (`gitiup participant withdraw`).
pub const WITHDRAWAL_TYPE: &str = "gitiup-withdrawal-1";
/// The `type` of a revocation record (D9).
pub const REVOCATION_TYPE: &str = "gitiup-revocation-1";

/// Roster schema version this crate writes.
pub const ROSTER_SCHEMA_VERSION: u32 = 1;

/// Entries per roster. A roster is a list of humans and their boxes, not a peer
/// list; a bigger cap is a parsing-bomb budget, not a feature (D10, and the
/// "exfiltration through attestation fields" row of the threat table).
pub const MAX_ROSTER_ENTRIES: usize = 4096;

/// Default epoch interval: 7 days, in microseconds (ADR-0002 defaults table).
pub const DEFAULT_EPOCH_INTERVAL_US: i64 = 7 * 24 * 60 * 60 * 1_000_000;

/// How many epochs a roster stays valid: two, so a store outage or a holiday
/// pauses verification instead of invalidating it, and so staleness has a deadline.
pub const ROSTER_VALID_EPOCHS: u64 = 2;

/// `[from, to]`, inclusive: the epochs an entry may be selected in.
///
/// A withdrawal or a revocation moves `to` forward by removing the entry from a
/// later epoch; it never edits an old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochWindow {
    /// First epoch this entry is eligible in.
    pub from: u64,
    /// Last epoch this entry is eligible in.
    pub to: u64,
}

impl EpochWindow {
    /// The largest epoch representable in the canonical number format (which is
    /// `i64`, not `u64`: ADR-0001 D1 allows integers only, and one width). An
    /// "unbounded" `to` uses this, so a roster can be canonicalised.
    pub const NO_EXPIRY: u64 = i64::MAX as u64;

    /// A window that starts at `from` and never expires (rare; usually the epoch
    /// the roster is rotated out anyway).
    pub fn open_from(from: u64) -> EpochWindow {
        EpochWindow {
            from,
            to: EpochWindow::NO_EXPIRY,
        }
    }

    /// Is `epoch` inside?
    pub fn contains(&self, epoch: u64) -> bool {
        self.from <= epoch && epoch <= self.to
    }
}

/// One machine: a key, the principal it belongs to, the owner's tier, and what the
/// key claims the box can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterEntry {
    /// `SHA256:<unpadded base64>` — the SSH fingerprint of `public_key`, derived
    /// and checked, never asserted (ADR-0001 D3).
    pub key_id: String,
    /// The OpenSSH public-key line.
    pub public_key: String,
    /// The principal key id this box belongs to. One identity, one vote (D4) —
    /// this field *is* the family relation, so excluding it excludes every box of
    /// that human's.
    pub identity: String,
    /// The owner's vouch, not the participant's claim (D5).
    pub tier: crate::capability::RosterTier,
    /// What the box claims it can run.
    pub capabilities: Capabilities,
    /// Inclusive epoch window.
    pub epochs_valid: EpochWindow,
    /// Proof the holder controls the private half: an Ed25519 signature over the
    /// entry's own canonical bytes, made by `key_id`.
    ///
    /// Optional in the *document* because ADR-0002's selection vectors are
    /// unsigned, and required by [`Roster::verify`] — a roster without ownership
    /// proofs is a list of things someone hopes are keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_signature: Option<SignatureEntry>,
}

impl RosterEntry {
    /// The bytes the entry's self-signature covers: canonical, without `self_signature`
    /// and without `tier`.
    ///
    /// The tier is outside the signature because it is the owner's statement about the
    /// box, not the key's statement about itself ([ADR-0002 D5](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)):
    /// a proof that covered it would either make a volunteer grade its own trust or force
    /// a second signing round for a field that cannot change what the proof attests. What
    /// the proof attests is *this key, this principal, these claimed capabilities* — and
    /// the tier becomes a vouch only under the owner's signature on the whole epoch, which
    /// [`Roster::verify`] insists on. A store that rewrote a tier would be editing a
    /// document it cannot re-sign.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.self_signature = None;
        crate::record::body_bytes_without(&unsigned, &["self_signature", "tier"])
    }

    /// Attach a key-ownership proof, made by `key`.
    pub fn sign(&mut self, key: &dyn Signer) -> Result<()> {
        let body = self.body_bytes()?;
        self.self_signature = Some(sign(ROSTER_ENTRY_PAYLOAD_TYPE, &body, key)?);
        Ok(())
    }

    /// Check that this entry names a key consistently: the `key_id` must be the
    /// fingerprint of the `public_key` it carries, and a self-signature, if present,
    /// must verify.
    ///
    /// Deliberately *shape* only, not curve validity: the ADR-0002 vectors carry
    /// well-formed SSH blobs with no private half, and a selector must be able to audit
    /// them. A roster used for actual voting goes through [`Roster::verify`], which
    /// additionally demands a curve-valid key, because a key that cannot verify a
    /// signature is not an identity.
    pub fn verify_key(&self) -> Result<()> {
        require_key_id_shape(&self.key_id, "roster entry")?;
        require_key_id_shape(&self.identity, "roster identity")?;
        let fingerprint = key_id_of_openssh(&self.public_key)?;
        if fingerprint != self.key_id {
            return Err(Error::signature(
                "roster entry",
                format!(
                    "{} is not the fingerprint of the public key in this entry ({}) — a key id is derived, never typed",
                    self.key_id, fingerprint
                ),
            ));
        }
        self.capabilities.validate()?;
        match &self.self_signature {
            Some(sig) => {
                verify_one(sig, ROSTER_ENTRY_PAYLOAD_TYPE, &self.body_bytes()?).map_err(|e| {
                    Error::signature(
                        "roster entry",
                        format!("ownership proof for {} does not verify: {}", self.key_id, e),
                    )
                })
            }
            None => Ok(()),
        }
    }

    /// Whether the ownership proof is present.
    pub fn has_ownership_proof(&self) -> bool {
        self.self_signature.is_some()
    }

    /// The public key, parsed *and* curve-checked: what a signature will be verified
    /// against.
    pub fn public_key(&self) -> Result<gitiup_attest::PublicKey> {
        gitiup_attest::PublicKey::from_openssh(&self.public_key)
            .map_err(|e| Error::invalid("roster entry", e.detail()))
    }
}

/// A roster epoch: the whole trust list at one point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roster {
    /// Must be [`ROSTER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`ROSTER_TYPE`]; inside the signed bytes so a v2 roster cannot be
    /// read with v1 rules.
    #[serde(rename = "type")]
    pub roster_type: String,
    /// Monotone epoch number, time-derived (D8).
    pub epoch: u64,
    /// Digest of the previous epoch's bytes: the chain that makes a rewritten past
    /// a different digest.
    pub prev_roster_digest: gitiup_attest::Digest,
    /// Issue time, microseconds.
    pub issued_at_us: i64,
    /// Hard expiry; new rounds refuse a roster past this (`issued_at_us` plus
    /// [`ROSTER_VALID_EPOCHS`] epochs by default).
    pub valid_until_us: i64,
    /// The published epoch interval, so the epoch rule is computable by anyone.
    pub epoch_interval_us: i64,
    /// The entries, sorted by `key_id`, unique per epoch.
    pub entries: Vec<RosterEntry>,
    /// The owner's approval of this epoch. Empty means *unsigned*: legal on the
    /// wire, and refused by [`Roster::verify`].
    pub signatures: Vec<SignatureEntry>,
}

impl Roster {
    /// Build an unsigned epoch from already-signed entries.
    ///
    /// Sorts the entries (the canonical form has one order) and sets the expiry
    /// from the interval, so the expiry an owner meant and the expiry a verifier
    /// checks are the same arithmetic.
    pub fn new(
        epoch: u64,
        prev_roster_digest: gitiup_attest::Digest,
        issued_at_us: i64,
        epoch_interval_us: i64,
        mut entries: Vec<RosterEntry>,
    ) -> Result<Roster> {
        if epoch_interval_us <= 0 {
            return Err(Error::invalid(
                "roster",
                "epoch_interval_us must be positive (it is a divisor in the epoch rule)",
            ));
        }
        entries.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        let roster = Roster {
            schema_version: ROSTER_SCHEMA_VERSION,
            roster_type: ROSTER_TYPE.to_string(),
            epoch,
            prev_roster_digest,
            issued_at_us,
            valid_until_us: issued_at_us
                .saturating_add(epoch_interval_us.saturating_mul(ROSTER_VALID_EPOCHS as i64)),
            epoch_interval_us,
            entries,
            signatures: Vec::new(),
        };
        roster.validate()?;
        Ok(roster)
    }

    /// Structural validity: shape, ordering, uniqueness, bounds, and every
    /// signature that is *present*.
    ///
    /// Deliberately does **not** require an owner signature or per-entry ownership
    /// proofs — those are trust decisions, made by [`Roster::verify`] — so a
    /// selection vector (which has neither) still parses and audits.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != ROSTER_SCHEMA_VERSION {
            return Err(Error::unsupported(
                "roster",
                format!(
                    "roster schema_version {} is not understood",
                    self.schema_version
                ),
            ));
        }
        if self.roster_type != ROSTER_TYPE {
            return Err(Error::unsupported(
                "roster",
                format!("unknown roster type '{}'", self.roster_type),
            )
            .with_hint("a reader must refuse a type it does not know rather than guess at it"));
        }
        if self.issued_at_us <= 0 {
            return Err(Error::invalid(
                "roster",
                "issued_at_us must be a positive microsecond time",
            ));
        }
        if self.valid_until_us <= self.issued_at_us {
            return Err(Error::invalid(
                "roster",
                "valid_until_us must be after issued_at_us: a roster that expires before it \
                 exists authorises nothing",
            ));
        }
        if self.epoch_interval_us <= 0 {
            return Err(Error::invalid(
                "roster",
                "epoch_interval_us must be positive",
            ));
        }
        if self.entries.len() > MAX_ROSTER_ENTRIES {
            return Err(Error::invalid(
                "roster",
                format!(
                    "{} entries exceeds the {MAX_ROSTER_ENTRIES} limit",
                    self.entries.len()
                ),
            ));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::invalid(
                "roster",
                format!(
                    "{} owner signatures is past the limit",
                    self.signatures.len()
                ),
            ));
        }
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for entry in &self.entries {
            entry.verify_key()?;
            if entry.epochs_valid.from > entry.epochs_valid.to {
                return Err(Error::invalid(
                    "roster",
                    format!(
                        "{} has an empty epoch window ({}..={})",
                        entry.key_id, entry.epochs_valid.from, entry.epochs_valid.to
                    ),
                ));
            }
            if !ids.insert(entry.key_id.as_str()) {
                return Err(Error::invalid(
                    "roster",
                    format!(
                        "{} appears twice in one epoch: a duplicate entry makes the roster \
                         invalid, not the vote twice as heavy",
                        entry.key_id
                    ),
                ));
            }
        }
        if self.entries.windows(2).any(|w| w[0].key_id > w[1].key_id) {
            return Err(Error::invalid(
                "roster",
                "entries must be sorted by key_id: the canonical form has one order",
            ));
        }
        Ok(())
    }

    /// Canonical bytes: what is stored, and what [`Self::digest`] hashes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// `sha256:` digest over the exact canonical bytes.
    ///
    /// This is the `roster_digest` a round pins (D8). It covers the signature list,
    /// which is why signing an epoch changes its digest: a signed roster and an
    /// unsigned one are different documents.
    pub fn digest(&self) -> Result<gitiup_attest::Digest> {
        Ok(gitiup_attest::Digest::sha256(&self.canonical_bytes()?))
    }

    /// The body a signature covers (canonical, `signatures` removed).
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Read from storage, refusing anything that is not the canonical encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Roster> {
        let roster: Roster = from_canonical_bytes(bytes)?;
        roster.validate()?;
        require_same_bytes(&roster, bytes)?;
        Ok(roster)
    }

    /// The owner's approval: sign this epoch's body.
    pub fn sign(&mut self, key: &dyn Signer) -> Result<SignatureEntry> {
        let body = self.body_bytes()?;
        let entry = sign(ROSTER_PAYLOAD_TYPE, &body, key)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        self.validate()?;
        Ok(entry)
    }

    /// Verify an epoch as a trust root: structurally valid, every key's ownership
    /// proof intact, at least one trusted owner signature, and not expired.
    ///
    /// Returns the trusted signer key ids, so a caller can record *which* owner key
    /// authorised the epoch it selected from.
    pub fn verify(&self, trust: &Trust, now: TimeUs) -> Result<Vec<String>> {
        self.validate()?;
        for entry in &self.entries {
            // A roster that authorises votes must carry keys that can actually sign.
            entry.public_key().map_err(|e| {
                Error::signature(
                    "roster",
                    format!(
                        "{} carries a public key this build cannot use: {}",
                        entry.key_id, e
                    ),
                )
                .with_hint("a roster entry's key must be a real ed25519 key; unsigned-shaped                             blobs are selection vectors, not identities")
            })?;
            if !entry.has_ownership_proof() {
                return Err(Error::policy(
                    "roster",
                    format!(
                        "entry {} carries no key-ownership proof, so this roster is a list of \
                         claims about keys rather than a list of keys",
                        entry.key_id
                    ),
                )
                .with_hint(
                    "`gitiup participant register` produces the proof; an owner copies the \
                            entry, never retypes the key",
                ));
            }
        }
        let trusted = check_signatures(
            &self.signatures,
            ROSTER_PAYLOAD_TYPE,
            &self.body_bytes()?,
            trust,
            "roster",
            MAX_SIGNATURES,
        )?;
        if now.as_us() > self.valid_until_us {
            return Err(Error::policy(
                "roster",
                format!(
                    "roster epoch {} expired at {} and this clock says {}",
                    self.epoch,
                    TimeUs(self.valid_until_us).to_rfc3339(),
                    now.to_rfc3339()
                ),
            )
            .with_hint("fetch the current epoch (refs/gitiup/roster); running on an expired roster is how a revoked key keeps voting"));
        }
        Ok(trusted)
    }

    /// Look up an entry by key id.
    pub fn entry(&self, key_id: &str) -> Option<&RosterEntry> {
        self.entries.iter().find(|e| e.key_id == key_id)
    }

    /// Edit an entry in place — the owner's capability re-declaration (D8's rotation
    /// table: "capacity/claim change → re-submit the entry; new epoch").
    ///
    /// Deliberately narrow: this edits a claim the owner is already making, it cannot
    /// add or remove an entry (that is [`Roster::next_epoch_from`], which bumps the
    /// epoch), and the caller owes [`Roster::validate`] afterwards, exactly as the
    /// owner owes a signature.
    pub fn entry_mut(&mut self, key_id: &str) -> Option<&mut RosterEntry> {
        self.entries.iter_mut().find(|e| e.key_id == key_id)
    }

    /// The owner's next epoch: this one's entries, plus `additions`, minus `removals`,
    /// with the epoch rule and the hash chain applied
    /// ([ADR-0002 D8](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
    ///
    /// This is what "the owner approves the sign-up" means mechanically: there is no
    /// protocol and no mutable list, there is a new signed document whose predecessor is
    /// named by digest. Additions *replace* an entry with the same key id rather than
    /// sitting beside it (a re-submitted capability claim is an update).
    ///
    /// Nothing here edits a field a key signed. The ownership proof covers the whole
    /// entry — capabilities, identity and its claimed epoch window — so an owner who
    /// retyped one byte would be publishing a roster whose entry does not verify, which
    /// is exactly the corruption this command must make impossible. The owner's leverage
    /// is the thing that matters: *whether* to carry an entry into the epoch, and at
    /// which tier. A window an owner dislikes is a reason to decline the sign-up, not to
    /// edit it.
    ///
    /// The result is unsigned: the owner signs it ([`Roster::sign`]) when the human has
    /// actually looked at it, which is the step this whole design exists to make
    /// deliberate.
    pub fn next_epoch_from(
        prev: &Roster,
        now_us: i64,
        additions: impl IntoIterator<Item = RosterEntry>,
        removals: &std::collections::BTreeSet<String>,
    ) -> Result<Roster> {
        let epoch = Roster::next_epoch(prev.epoch, now_us, prev.epoch_interval_us)?;
        let mut added: std::collections::BTreeMap<String, RosterEntry> = Default::default();
        for entry in additions {
            entry.verify_key()?;
            if !entry.has_ownership_proof() {
                return Err(Error::policy(
                    "roster",
                    format!(
                        "{} arrives without a key-ownership proof, so it is a claim about a \
                         key and cannot be carried into an epoch",
                        entry.key_id
                    ),
                ));
            }
            if added.insert(entry.key_id.clone(), entry).is_some() {
                return Err(Error::invalid(
                    "roster",
                    "two additions name the same key id: one entry per key per epoch",
                ));
            }
        }
        let mut entries: Vec<RosterEntry> = prev
            .entries
            .iter()
            .filter(|e| !removals.contains(&e.key_id) && !added.contains_key(&e.key_id))
            .cloned()
            .collect();
        entries.extend(added.into_values());
        // `Roster::new` sorts, validates and rejects a duplicate key id, which is all
        // this has to guarantee: an addition arrives self-signed by the key it names, and
        // an entry kept from `prev` carries the ownership proof it already had — an
        // owner may not edit a signed entry, only decline to carry it into the next epoch.
        Roster::new(
            epoch,
            prev.digest()?,
            now_us,
            prev.epoch_interval_us,
            entries,
        )
    }

    /// Entries belonging to one principal.
    pub fn family(&self, identity: &str) -> Vec<&RosterEntry> {
        self.entries
            .iter()
            .filter(|e| e.identity == identity)
            .collect()
    }

    /// The epoch rule (D8): `max(prev + 1, floor(now / interval))`.
    ///
    /// Dense and monotone (the first term) *and* time-derived (the second), so an
    /// owner who stops publishing does not freeze the pool: the old epoch simply
    /// stops being acceptable when it expires.
    pub fn next_epoch(prev: u64, now_us: i64, interval_us: i64) -> Result<u64> {
        if interval_us <= 0 {
            return Err(Error::invalid(
                "roster",
                "epoch_interval_us must be positive",
            ));
        }
        if now_us < 0 {
            return Err(Error::invalid("roster", "now must not be before the epoch"));
        }
        let by_time = (now_us / interval_us) as u64;
        Ok((prev.saturating_add(1)).max(by_time))
    }

    /// The epoch that *should* be current at `now`, given an interval.
    ///
    /// Callers use this to refuse to *open* a round against a roster the calendar
    /// has already moved past, which is the difference between "the owner is on
    /// holiday" and "the owner is frozen".
    pub fn expected_epoch(&self, now_us: i64) -> Result<u64> {
        Roster::next_epoch(self.epoch.saturating_sub(1), now_us, self.epoch_interval_us)
    }

    /// Drop entries, used by the owner when composing the next epoch from a
    /// withdrawal or a revocation.
    pub fn without(&self, key_ids: &BTreeSet<String>) -> Result<Roster> {
        let entries: Vec<RosterEntry> = self
            .entries
            .iter()
            .filter(|e| !key_ids.contains(&e.key_id))
            .cloned()
            .collect();
        Roster::new(
            self.epoch,
            self.prev_roster_digest.clone(),
            self.issued_at_us,
            self.epoch_interval_us,
            entries,
        )
    }

    /// Every distinct principal, sorted — the denominator for "how many identities
    /// could this store actually field a quorum from".
    pub fn identities(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.entries.iter().map(|e| e.identity.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

/// A self-signed sign-up record: `gitiup participant register`'s output
/// ([ADR-0002 D8](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
///
/// The owner's act is to *include* it, not to approve it through a second channel —
/// so a sign-up is a complete, verifiable statement by itself, and copying an entry
/// into a roster cannot silently change the key it vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignUp {
    /// Must be [`ROSTER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`SIGNUP_TYPE`].
    #[serde(rename = "type")]
    pub signup_type: String,
    /// The entry, with its ownership proof.
    pub entry: RosterEntry,
}

impl SignUp {
    /// Build and sign a sign-up for `entry` (the entry's ownership proof is
    /// attached here, so a caller cannot forget it).
    pub fn new(entry: RosterEntry, key: &dyn Signer) -> Result<SignUp> {
        let mut entry = entry;
        if key.public_key().to_openssh() != entry.public_key {
            return Err(Error::signature(
                "sign-up",
                "the signing key is not the key in this entry: a sign-up proves you hold the \
                 key you are registering, nothing else",
            ));
        }
        entry.sign(key)?;
        let signup = SignUp {
            schema_version: ROSTER_SCHEMA_VERSION,
            signup_type: SIGNUP_TYPE.to_string(),
            entry,
        };
        signup.validate()?;
        Ok(signup)
    }

    /// Validate, and require the ownership proof.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != ROSTER_SCHEMA_VERSION || self.signup_type != SIGNUP_TYPE {
            return Err(Error::unsupported(
                "sign-up",
                format!(
                    "unknown sign-up type '{}' v{}",
                    self.signup_type, self.schema_version
                ),
            ));
        }
        self.entry.verify_key()?;
        if !self.entry.has_ownership_proof() {
            return Err(Error::policy(
                "sign-up",
                "a sign-up without a key-ownership proof is a claim about a key, not a registration",
            ));
        }
        Ok(())
    }

    /// Canonical bytes for storage at `refs/gitiup/signup/<slot>`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Read a sign-up back from storage and check it.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<SignUp> {
        let signup: SignUp = from_canonical_bytes(bytes)?;
        signup.validate()?;
        require_same_bytes(&signup, bytes)?;
        Ok(signup)
    }

    /// The hex storage slot for this key (D10).
    pub fn slot(&self) -> String {
        crate::derive::key_slot(&self.entry.key_id)
    }
}

/// A signed withdrawal: "stop selecting this key from epoch E" (D8's rotation
/// table, the record behind `gitiup participant withdraw`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Withdrawal {
    /// Must be [`ROSTER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`WITHDRAWAL_TYPE`].
    #[serde(rename = "type")]
    pub withdrawal_type: String,
    /// The key leaving.
    pub key_id: String,
    /// First epoch the key must not be selected in; defaults to the next epoch,
    /// because a withdrawal that voids an in-flight round is indistinguishable
    /// from an attack on it.
    pub effective_epoch: u64,
    /// Claimed time of the request.
    pub issued_at_us: i64,
    /// Signature by the key itself: the only authorisation needed. A key can
    /// always withdraw itself, or losing a key would mean asking nicely.
    pub signatures: Vec<SignatureEntry>,
}

impl Withdrawal {
    /// An unsigned withdrawal effective from `effective_epoch`.
    pub fn new(key_id: impl Into<String>, effective_epoch: u64, issued_at_us: i64) -> Withdrawal {
        Withdrawal {
            schema_version: ROSTER_SCHEMA_VERSION,
            withdrawal_type: WITHDRAWAL_TYPE.to_string(),
            key_id: key_id.into(),
            effective_epoch,
            issued_at_us,
            signatures: Vec::new(),
        }
    }

    /// The bytes the signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Sign with the key that is withdrawing.
    pub fn sign(&mut self, key: &dyn Signer) -> Result<()> {
        let entry = sign(WITHDRAWAL_PAYLOAD_TYPE, &self.body_bytes()?, key)?;
        self.signatures.push(entry);
        Ok(())
    }

    /// Verify: well-formed, and signed *by that key* (an owner who wants a key out
    /// uses a [`Revocation`], which is a different sentence with a different
    /// effect on attestations already made).
    pub fn verify(&self) -> Result<()> {
        if self.schema_version != ROSTER_SCHEMA_VERSION || self.withdrawal_type != WITHDRAWAL_TYPE {
            return Err(Error::unsupported(
                "withdrawal",
                format!("unknown withdrawal type '{}'", self.withdrawal_type),
            ));
        }
        require_key_id_shape(&self.key_id, "withdrawal")?;
        if self.signatures.len() != 1 {
            return Err(Error::policy(
                "withdrawal",
                format!(
                    "a withdrawal carries exactly one signature (the key's own); found {}",
                    self.signatures.len()
                ),
            ));
        }
        verify_one(
            &self.signatures[0],
            WITHDRAWAL_PAYLOAD_TYPE,
            &self.body_bytes()?,
        )?;
        if self.signatures[0].key_id != self.key_id {
            return Err(Error::signature(
                "withdrawal",
                format!(
                    "withdrawal for {} was signed by {}: only the key itself may withdraw it",
                    self.key_id, self.signatures[0].key_id
                ),
            ));
        }
        Ok(())
    }

    /// Canonical bytes for storage.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Read from storage.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Withdrawal> {
        let withdrawal: Withdrawal = from_canonical_bytes(bytes)?;
        withdrawal.verify()?;
        require_same_bytes(&withdrawal, bytes)?;
        Ok(withdrawal)
    }

    /// The slot this key's records live under.
    pub fn slot(&self) -> String {
        crate::derive::key_slot(&self.key_id)
    }
}

/// Why a key is dead ([ADR-0002 D9](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
///
/// The reason is not decoration: "the laptop was sold" and "the key is stolen" are
/// different emergencies, and they decide what happens to attestations already
/// submitted in a round that pinned this key as a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The key's own choice (sold, busy). Attestations already made stand.
    Retired,
    /// The key may be forged. Voids the key's claims in unsettled rounds
    /// regardless of timing — a stolen key's *old* signature is the problem.
    Compromised,
    /// The owner removed it (bad history, policy breach). Stand unless
    /// `bad_faith` is set, which voids everything it signed.
    Removed,
    /// Key rotated in place: same identity, new key.
    Superseded,
}

impl RevocationReason {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            RevocationReason::Retired => "retired",
            RevocationReason::Compromised => "compromised",
            RevocationReason::Removed => "removed",
            RevocationReason::Superseded => "superseded",
        }
    }

    /// Every reason, for `--help` and for parsing.
    pub const ALL: [RevocationReason; 4] = [
        RevocationReason::Retired,
        RevocationReason::Compromised,
        RevocationReason::Removed,
        RevocationReason::Superseded,
    ];

    /// Parse a reason name (tolerant of case and padding, because these are typed by
    /// a human in an incident), naming the vocabulary when wrong — a mistyped
    /// `compromised` must not silently become `retired`, because the two disagree about
    /// whether old attestations stand.
    pub fn parse(text: &str) -> Result<RevocationReason> {
        let trimmed = text.trim().to_ascii_lowercase();
        RevocationReason::ALL
            .iter()
            .find(|r| r.as_str() == trimmed)
            .copied()
            .ok_or_else(|| {
                Error::invalid(
                    "revocation reason",
                    format!("'{text}' is not a revocation reason"),
                )
                .with_hint(format!(
                    "reasons are {}",
                    RevocationReason::ALL
                        .iter()
                        .map(|r| r.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A signed revocation record (D9).
///
/// Three facts stay separate on purpose: the roster epoch says who may be selected,
/// this record says from when a key is dead and why, and the verdict says what to
/// do about claims made in between. Merging them is how "revoked" becomes a
/// retroactive edit of history, which ADR-0001 D6 forbids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    /// Must be [`ROSTER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`REVOCATION_TYPE`].
    #[serde(rename = "type")]
    pub revocation_type: String,
    /// The key being revoked.
    pub key_id: String,
    /// Why — decides the mid-flight rules in [`Revocation::voids`].
    pub reason: RevocationReason,
    /// First epoch the key is excluded from. Always accompanied by an epoch bump.
    pub effective_epoch: u64,
    /// Claimed time of the revocation, compared against a submission's
    /// `claimed_at_us` when the reason makes timing matter.
    pub revoked_at_us: i64,
    /// Who made the statement — the key itself, or the owner.
    pub issuer: String,
    /// Set with `reason: removed` when the key acted in bad faith: voids its
    /// existing claims too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bad_faith: bool,
    /// Free-text note (who to contact, which incident). Never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Signatures: must include the issuer's, and the issuer must be either the key
    /// itself or a key the caller trusts as an owner.
    pub signatures: Vec<SignatureEntry>,
}

impl Revocation {
    /// An unsigned revocation record.
    pub fn new(
        key_id: impl Into<String>,
        reason: RevocationReason,
        effective_epoch: u64,
        revoked_at_us: i64,
    ) -> Revocation {
        Revocation {
            schema_version: ROSTER_SCHEMA_VERSION,
            revocation_type: REVOCATION_TYPE.to_string(),
            key_id: key_id.into(),
            reason,
            effective_epoch,
            revoked_at_us,
            issuer: String::new(),
            bad_faith: false,
            note: None,
            signatures: Vec::new(),
        }
    }

    /// The bytes the issuer signs.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Sign as `issuer`. Calling this twice (key + owner) is how a `compromised`
    /// revocation looks when the owner found out first.
    pub fn sign(&mut self, issuer: &dyn Signer) -> Result<()> {
        self.issuer = issuer.key_id();
        let entry = sign(REVOCATION_PAYLOAD_TYPE, &self.body_bytes()?, issuer)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry);
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(())
    }

    /// Structural checks plus "the issuer signed it".
    ///
    /// `owner_trust` is the caller's owner/selector trust: a key may always revoke
    /// itself, and anything else needs an owner's signature.
    pub fn verify(&self, owner_trust: &Trust) -> Result<()> {
        if self.schema_version != ROSTER_SCHEMA_VERSION || self.revocation_type != REVOCATION_TYPE {
            return Err(Error::unsupported(
                "revocation",
                format!("unknown revocation type '{}'", self.revocation_type),
            ));
        }
        require_key_id_shape(&self.key_id, "revocation")?;
        if self.signatures.is_empty() {
            return Err(Error::policy(
                "revocation",
                "an unsigned revocation is a rumour about a key",
            ));
        }
        for entry in &self.signatures {
            verify_one(entry, REVOCATION_PAYLOAD_TYPE, &self.body_bytes()?)?;
        }
        let self_issued = self.issuer == self.key_id;
        let signed_by_issuer = self.signatures.iter().any(|s| s.key_id == self.issuer);
        if !signed_by_issuer {
            return Err(Error::signature(
                "revocation",
                format!(
                    "issuer {} did not sign this revocation of {}",
                    crate::record::short_key(&self.issuer),
                    crate::record::short_key(&self.key_id)
                ),
            ));
        }
        if !self_issued && !owner_trust.trusts(&self.issuer) {
            return Err(Error::policy(
                "revocation",
                format!(
                    "{} may not revoke {}: only the key itself or a trusted owner may",
                    crate::record::short_key(&self.issuer),
                    crate::record::short_key(&self.key_id)
                ),
            ));
        }
        Ok(())
    }

    /// Does this revocation void a claim made in a round that pinned roster epoch
    /// `round_epoch` ([ADR-0002 D9](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md))?
    ///
    /// The three sentences the matrix makes: a key that had already left *before
    /// the round was opened* should not have been selected (void); a compromised key
    /// is void forever, because the thief can sign tomorrow with yesterday's key;
    /// and a rotation or a retirement never retroactively distrusts work that was
    /// honest.
    pub fn voids(&self, round_epoch: u64) -> bool {
        match self.reason {
            RevocationReason::Compromised => true,
            RevocationReason::Removed => self.bad_faith || self.effective_epoch <= round_epoch,
            RevocationReason::Retired => self.effective_epoch <= round_epoch,
            RevocationReason::Superseded => false,
        }
    }

    /// Canonical bytes for storage at `refs/gitiup/revocation/<slot>`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Read from storage.
    pub fn from_canonical_bytes(bytes: &[u8], owner_trust: &Trust) -> Result<Revocation> {
        let revocation: Revocation = from_canonical_bytes(bytes)?;
        revocation.verify(owner_trust)?;
        require_same_bytes(&revocation, bytes)?;
        Ok(revocation)
    }

    /// The slot this key's revocations live under.
    pub fn slot(&self) -> String {
        crate::derive::key_slot(&self.key_id)
    }
}

/// The key id an OpenSSH public-key line implies, from its wire blob.
///
/// The same derivation as [`gitiup_attest::PublicKey::key_id`] — `SHA256:` over the
/// SSH blob — but without curve validation, so a well-formed key id can be checked
/// against a well-formed blob in a document that never signs anything (the ADR-0002
/// selection vectors). Anything that will *verify* a signature must go through
/// [`gitiup_attest::PublicKey::from_openssh`] instead.
pub fn key_id_of_openssh(line: &str) -> Result<String> {
    use gitiup_attest::encoding::{base64_decode, base64_encode_unpadded};
    let mut fields = line.split_whitespace();
    let kind = fields.next().unwrap_or_default();
    let body = fields.next().ok_or_else(|| {
        Error::invalid(
            "roster entry",
            "expected an `ssh-ed25519 <base64> [comment]` line",
        )
    })?;
    let blob = base64_decode(body).map_err(|e| Error::invalid("roster entry", e.detail()))?;
    // SSH wire format: string "ssh-ed25519", string <32 key bytes>. Checking the
    // framing here is what stops a key id being derived from an arbitrary blob.
    let tag = b"ssh-ed25519";
    let ok = blob.len() == 4 + tag.len() + 4 + 32
        && blob[..4] == [0, 0, 0, tag.len() as u8]
        && blob[4..4 + tag.len()] == tag[..]
        && blob[4 + tag.len()..8 + tag.len()] == [0, 0, 0, 32];
    if !ok || kind != "ssh-ed25519" {
        return Err(Error::invalid(
            "roster entry",
            format!(
                "'{kind}' is not an ssh-ed25519 key in SSH wire format                  (a key id is derived from the blob, so the blob has to be one)"
            ),
        ));
    }
    Ok(format!(
        "SHA256:{}",
        base64_encode_unpadded(gitiup_attest::Digest::sha256(&blob).as_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }

    fn entry_for(k: &SigningKey, tier: crate::capability::RosterTier) -> RosterEntry {
        let mut entry = RosterEntry {
            key_id: k.public_key().key_id(),
            public_key: k.public_key().to_openssh(),
            identity: k.public_key().key_id(),
            tier,
            capabilities: Capabilities {
                arch: vec!["x86_64".into()],
                ram_mb: 16384,
                disk_mb: 262144,
                image_cache: vec![],
                can_pull: true,
                sandboxes: vec!["docker".into()],
                sandbox_level: 2,
            },
            epochs_valid: EpochWindow::open_from(1),
            self_signature: None,
        };
        // A real roster entry carries its key-ownership proof; `verify` insists on it,
        // which is the difference between a trust list and a wishlist.
        entry.sign(k).unwrap();
        entry
    }

    const T0: i64 = 1_792_771_200_000_000;

    #[test]
    fn a_signed_roster_round_trips_and_digests_stably() {
        let owner = key(1);
        let box_key = key(2);
        let mut roster = Roster::new(
            41,
            gitiup_attest::Digest::sha256(b"epoch 40"),
            T0,
            DEFAULT_EPOCH_INTERVAL_US,
            vec![entry_for(&box_key, crate::capability::RosterTier::Endorsed)],
        )
        .unwrap();
        roster.sign(&owner).unwrap();
        let bytes = roster.canonical_bytes().unwrap();
        assert!(gitiup_attest::is_canonical(&bytes));
        let back = Roster::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, roster);
        assert_eq!(back.digest().unwrap(), roster.digest().unwrap());
        // Expiry is two epochs, so the number a verifier checks is the number the
        // owner's build computed.
        assert_eq!(roster.valid_until_us, T0 + 2 * DEFAULT_EPOCH_INTERVAL_US);
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        assert_eq!(
            roster.verify(&trust, TimeUs(T0 + 1000)).unwrap(),
            vec![owner.public_key().key_id()]
        );
        // And the same roster is worthless once it expires.
        let late = roster.verify(&trust, TimeUs(roster.valid_until_us + 1));
        assert!(late.is_err());
    }

    #[test]
    fn an_unsigned_or_untrusted_roster_authorises_nothing() {
        let owner = key(3);
        let box_key = key(4);
        let roster = Roster::new(
            1,
            gitiup_attest::Digest::sha256(b""),
            T0,
            DEFAULT_EPOCH_INTERVAL_US,
            vec![entry_for(
                &box_key,
                crate::capability::RosterTier::Anonymous,
            )],
        )
        .unwrap();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let err = roster.verify(&trust, TimeUs(T0)).unwrap_err();
        assert!(err.to_string().contains("unsigned"), "{err}");
        // Signed by somebody the caller does not trust for rosters: still refused,
        // with a different sentence.
        let stranger = key(5);
        let mut signed = roster.clone();
        signed.sign(&stranger).unwrap();
        let err = signed.verify(&trust, TimeUs(T0)).unwrap_err();
        assert!(err.to_string().contains("trusts"), "{err}");
        assert_eq!(err.exit_code(), 6);
    }

    #[test]
    fn missing_ownership_proof_is_refused_by_verify_not_by_validate() {
        // The ADR-0002 vectors are unsigned and must still parse and audit, so the
        // structural check and the trust check are deliberately different calls.
        let owner = key(6);
        let mut entry = entry_for(&key(7), crate::capability::RosterTier::Endorsed);
        entry.self_signature = None; // exactly the ADR-0002 vector shape
        let roster = Roster::new(
            2,
            gitiup_attest::Digest::sha256(b"x"),
            T0,
            DEFAULT_EPOCH_INTERVAL_US,
            vec![entry],
        )
        .unwrap();
        let mut roster = roster;
        roster.sign(&owner).unwrap();
        assert!(roster.validate().is_ok());
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let err = roster.verify(&trust, TimeUs(T0)).unwrap_err();
        assert!(err.to_string().contains("ownership proof"), "{err}");
    }

    #[test]
    fn a_key_id_that_is_not_a_fingerprint_is_a_refusal() {
        let mut entry = entry_for(&key(8), crate::capability::RosterTier::Endorsed);
        entry.key_id = "ada-laptop".into();
        assert!(entry.verify_key().is_err());
        // Right shape, wrong key: the fingerprint must be *derived* from the blob.
        let mut entry = entry_for(&key(9), crate::capability::RosterTier::Endorsed);
        entry.key_id = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let err = entry.verify_key().unwrap_err();
        assert_eq!(err.exit_code(), 7);
    }

    #[test]
    fn duplicates_and_disorder_are_invalid() {
        let k = key(10);
        let entries = vec![
            entry_for(&k, crate::capability::RosterTier::Endorsed),
            entry_for(&k, crate::capability::RosterTier::Endorsed),
        ];
        let err = Roster::new(
            3,
            gitiup_attest::Digest::sha256(b""),
            T0,
            DEFAULT_EPOCH_INTERVAL_US,
            entries,
        )
        .unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn the_epoch_rule_is_dense_and_time_derived() {
        let week = DEFAULT_EPOCH_INTERVAL_US;
        // Time-derived: at the fixture clock the calendar epoch is `now / interval`,
        // which dwarfs a hand-written test epoch. That is the rule, not an accident:
        // "which epoch should be current?" must be answerable without asking the owner.
        assert_eq!(
            Roster::next_epoch(41, T0, week).unwrap(),
            (T0 / week) as u64
        );
        // Dense: an owner publishing more often than the interval still gets a
        // strictly larger epoch, so nothing can slot an older roster in behind them.
        let calendar = (T0 / week) as u64;
        assert_eq!(
            Roster::next_epoch(calendar, T0, week).unwrap(),
            calendar + 1
        );
        // Three weeks of silence lands on the calendar, not on prev + 1.
        let three_weeks = T0 + 3 * week;
        assert_eq!(
            Roster::next_epoch(calendar, three_weeks, week).unwrap(),
            (three_weeks / week) as u64
        );
        assert!(Roster::next_epoch(41, T0, 0).is_err());
        assert!(Roster::next_epoch(41, -1, week).is_err());
    }

    #[test]
    fn a_signup_proves_the_key_and_carries_its_slot() {
        let k = key(11);
        let signup =
            SignUp::new(entry_for(&k, crate::capability::RosterTier::Anonymous), &k).unwrap();
        signup.validate().unwrap();
        let bytes = signup.canonical_bytes().unwrap();
        assert_eq!(SignUp::from_canonical_bytes(&bytes).unwrap(), signup);
        assert_eq!(
            signup.slot(),
            crate::derive::key_slot(&k.public_key().key_id())
        );
        assert_eq!(signup.slot().len(), 64);
        // Registering someone else's key with a different key is not a thing.
        let other = key(12);
        assert!(
            SignUp::new(
                entry_for(&k, crate::capability::RosterTier::Anonymous),
                &other
            )
            .is_err()
        );
    }

    #[test]
    fn withdrawal_needs_the_key_itself() {
        let k = key(13);
        let mut withdrawal = Withdrawal::new(k.public_key().key_id(), 42, T0);
        withdrawal.sign(&k).unwrap();
        withdrawal.verify().unwrap();
        // An owner cannot withdraw a key with the owner's own signature: that is a
        // revocation, and the difference is what happens to past claims.
        let owner = key(14);
        let mut by_owner = Withdrawal::new(k.public_key().key_id(), 42, T0);
        by_owner.sign(&owner).unwrap();
        assert!(by_owner.verify().is_err());
    }

    #[test]
    fn revocation_reasons_decide_what_they_void() {
        let k = key(15);
        let owner = key(16);
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let round_epoch = 41;
        for (reason, bad_faith, voids) in [
            (RevocationReason::Retired, false, false),
            (RevocationReason::Retired, false, true),
            (RevocationReason::Compromised, false, true),
            (RevocationReason::Removed, false, false),
            (RevocationReason::Removed, true, true),
            (RevocationReason::Superseded, false, false),
        ] {
            let effective = if voids { round_epoch } else { round_epoch + 1 };
            let mut rev = Revocation::new(k.public_key().key_id(), reason, effective, T0);
            rev.bad_faith = bad_faith;
            rev.sign(&k).unwrap();
            rev.verify(&trust).unwrap();
            assert_eq!(
                rev.voids(round_epoch),
                voids,
                "{reason} effective {effective} vs round {round_epoch}"
            );
        }
        // Self-revocation is always allowed; a stranger's is not.
        let stranger = key(17);
        let mut rev = Revocation::new(k.public_key().key_id(), RevocationReason::Removed, 42, T0);
        rev.sign(&stranger).unwrap();
        assert!(rev.verify(&trust).is_err());
        // ...while the owner may revoke unilaterally, which is the point of D9.
        let mut rev = Revocation::new(
            k.public_key().key_id(),
            RevocationReason::Compromised,
            41,
            T0,
        );
        rev.sign(&owner).unwrap();
        rev.verify(&trust).unwrap();
        assert!(rev.voids(1));
    }

    #[test]
    fn two_signatures_from_one_identity_is_one_vote_wearing_two_hats() {
        let owner = key(18);
        let mut roster = Roster::new(
            4,
            gitiup_attest::Digest::sha256(b""),
            T0,
            DEFAULT_EPOCH_INTERVAL_US,
            vec![entry_for(&key(19), crate::capability::RosterTier::Endorsed)],
        )
        .unwrap();
        roster.sign(&owner).unwrap();
        // Duplicate the owner's entry in the list: same key, two votes.
        let dup = roster.signatures[0].clone();
        roster.signatures.push(dup);
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let err = roster.verify(&trust, TimeUs(T0)).unwrap_err();
        assert!(err.to_string().contains("one vote"), "{err}");
    }
}

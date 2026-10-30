//! Commit-reveal submission: what `reveal_mode = sealed` actually is
//! ([giti-zp1.6](../../../README.md),
//! [ADR-0002 D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! # The two phases
//!
//! ```text
//! phase 1  refs/gitiup/commit/<change>/<job>/<slot>   ← H(attestation bytes ‖ slot ‖ challenge)
//! phase 2  refs/gitiup/reveal/<change>/<job>/<slot>   ← the attestation bytes (the preimage)
//! ```
//!
//! Both are CAS writes with `Expect::Absent` into a slot named by the seat's hex slot, so
//! a seat gets exactly one commitment and exactly one reveal, and neither can be edited
//! afterwards. The reveal carries its own preimage: the bytes are the blob, the slot is
//! in the ref name, and the challenge is inside the attestation's claims, so anyone who
//! can read the two refs can check that the reveal opens the commitment — nobody has to
//! take the tally's word for it.
//!
//! # What the ordering buys, and what it does not
//!
//! Phase 1 is the volunteer's **first write to the store for the round** and it precedes
//! the reveal unconditionally. It cannot precede *the run*, and it would be dishonest to
//! claim otherwise: `H(attestation bytes ‖ …)` is not computable before the attestation
//! exists. What the commit-before-reveal rule buys is *no change of mind*. Once the
//! commitment is in the store the seat is pinned to one byte-string, and a volunteer that
//! then finds a neighbour's answer differing has exactly two moves, both of them
//! evidence:
//!
//! * reveal what it committed to, and be counted as the dissenting vote it is;
//! * reveal something else and be refused with [`code::COMMITMENT_MISMATCH`], named in
//!   the verdict with both digests;
//! * say nothing, and land in `missing` with a commitment that opens nothing.
//!
//! What it does **not** buy is in [docs/quorum.md](../../../docs/quorum.md), in as few
//! words as possible: it does not hide the result from anyone who can read the store
//! after the round closes, it does not hide the seats (the round record publishes them —
//! D11), and it does not prove *when* a verifier computed its answer, only that it could
//! not change it afterwards.
//!
//! # Why a mismatch is published rather than refused at the door
//!
//! [`store::publish_submission`](crate::store::publish_submission) refuses a reveal with
//! **no** commitment — phase 1 is not optional, and an answer with nothing committed
//! behind it is not independent evidence. It deliberately does *not* refuse a reveal
//! that fails to open its commitment: that mismatch is the evidence of the one behaviour
//! sealed exists to catch, and refusing the write would replace a named rejection in a
//! signed verdict with a silent `missing` seat. The verdict refuses it, and says so.

use gitiup_attest::{AttestationDoc, Digest, SignatureEntry, Signer};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::job::check_slot;
use crate::record::{
    COMMITMENT_PAYLOAD_TYPE, body_bytes, canonical_bytes, from_canonical_bytes,
    require_key_id_shape, require_same_bytes, short_key, verify_one,
};
use crate::round::Round;
use crate::store::check_segment;

/// The `type` of a phase-1 commitment record.
pub const COMMITMENT_TYPE: &str = "gitiup-commitment-1";
/// The commitment schema version this crate writes.
pub const COMMITMENT_SCHEMA_VERSION: u32 = 1;

/// Domain separation for the preimage, so a commitment can never be confused with some
/// other SHA-256 over similar bytes (ADR-0001's habit of tagging every hash).
const COMMITMENT_TAG: &[u8] = b"gitiup-commit-1";

/// The rejection tokens a sealed tally writes into `VerdictRecord::rejected`.
///
/// They are `pub` because a script branches on them, exactly as it does on
/// [`gate::code`](crate::gate::code)'s.
pub mod code {
    /// A reveal arrived with no commitment in front of it (exit `6`: a policy refusal).
    pub const NO_COMMITMENT: &str = "no_commitment";
    /// A reveal arrived that does not hash to its commitment (exit `8`: a digest that is
    /// not the thing it names).
    pub const COMMITMENT_MISMATCH: &str = "commitment_mismatch";
    /// A commitment that does not speak about the round being tallied, so it cannot open
    /// anything in it (exit `6`).
    pub const FOREIGN_COMMITMENT: &str = "foreign_commitment";
}

/// A commitment, and the seat it was found under.
///
/// The pairing is not decoration: a commitment is read from `refs/gitiup/commit/…/<slot>`,
/// and a blob sitting in seat A's slot that claims to be authored by seat B is evidence of
/// something, but not of seat A's promise. Carrying the seat alongside the record means a
/// tally can say which seat it is refusing rather than quietly dropping the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    /// The key holding the seat whose slot this was read from.
    pub seat: String,
    /// The commitment the store held there.
    pub commitment: Commitment,
}

impl Filed {
    /// Does this speak about the round being tallied, and about the seat it was found in?
    ///
    /// `Err` is the honest answer for a stale or foreign commitment; the caller turns it
    /// into a refusal naming the seat rather than a silent absence.
    pub fn matches(&self, round: &Round) -> Result<()> {
        self.commitment.matches(round, &self.seat)
    }
}

/// The phase-1 hash: `H(attestation bytes ‖ slot ‖ challenge)`, tagged and separated.
///
/// The separators are unambiguous because canonical JSON contains no `NUL` byte
/// (ADR-0001 D1 escapes it as `\u0000`), so no attestation bytes can be read as a
/// separator, and the tag means a commitment is never the same hash as some other
/// SHA-256 over the same material.
pub fn commitment_of(attestation_bytes: &[u8], slot: &str, challenge: &Digest) -> Digest {
    let mut preimage =
        Vec::with_capacity(COMMITMENT_TAG.len() + attestation_bytes.len() + slot.len() + 32 + 3);
    preimage.extend_from_slice(COMMITMENT_TAG);
    preimage.push(0);
    preimage.extend_from_slice(attestation_bytes);
    preimage.push(0);
    preimage.extend_from_slice(slot.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(challenge.as_bytes());
    Digest::sha256(&preimage)
}

/// What a volunteer promised before it revealed anything: one hash, one seat, one round.
///
/// Written at `refs/gitiup/commit/<change>/<job>/<slot>` with `Expect::Absent`, and
/// signed by the seat's own key and by nobody else — the same rule a
/// [lease](crate::job::Lease) follows, because a commitment is a key's claim about
/// itself and the store's operator has no more say in it than they do in a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    /// Must be [`COMMITMENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`COMMITMENT_TYPE`].
    #[serde(rename = "type")]
    pub commitment_type: String,
    /// The change being verified.
    pub change_id: String,
    /// The job (matrix vector) within it.
    pub job_id: String,
    /// The round attempt the seat belongs to; a commitment does not cross attempts.
    pub attempt: u64,
    /// The seat's hex slot — the same name its reveal and its lease use.
    pub slot: String,
    /// The key holding the seat. Always the key that signed, never a key being talked
    /// about.
    pub key_id: String,
    /// Digest of the round record this commits to: a commitment is about one round, and
    /// an escalation to a new attempt needs a new one.
    pub round_digest: Digest,
    /// The per-key challenge the reveal must carry ([`Round::challenge_for`]).
    pub challenge: Digest,
    /// `H(attestation bytes ‖ slot ‖ challenge)` — the promise itself.
    pub commitment: Digest,
    /// When it was published (the audit's "who committed first", for whoever wants it).
    pub committed_at_us: i64,
    /// Exactly one signature, by [`Commitment::key_id`].
    pub signatures: Vec<SignatureEntry>,
}

impl Commitment {
    /// Commit to the bytes of an attestation `key_id` intends to reveal.
    ///
    /// `attestation_bytes` must be the **canonical** bytes the reveal will publish
    /// ([`AttestationDoc::canonical_bytes`]); a reveal is checked by re-hashing the bytes
    /// the store holds, so committing to anything else is a mismatch waiting to happen.
    /// [`Commitment::for_document`] is the constructor that cannot get it wrong.
    pub fn new(
        round: &Round,
        key_id: &str,
        attestation_bytes: &[u8],
        now: gitiup_attest::TimeUs,
    ) -> Result<Commitment> {
        let seat = round.seat(key_id).ok_or_else(|| {
            Error::policy(
                "commitment",
                format!(
                    "{} holds no seat in this round, so it has nothing to commit to",
                    short_key(key_id)
                ),
            )
        })?;
        let challenge = round.challenge_for(key_id)?;
        let commitment = commitment_of(attestation_bytes, &seat.slot, &challenge);
        let record = Commitment {
            schema_version: COMMITMENT_SCHEMA_VERSION,
            commitment_type: COMMITMENT_TYPE.to_string(),
            change_id: round.inputs.change_id.clone(),
            job_id: round.inputs.job_id.clone(),
            attempt: round.inputs.attempt,
            slot: seat.slot.clone(),
            key_id: key_id.to_string(),
            round_digest: round.digest()?,
            challenge,
            commitment,
            committed_at_us: now.as_us(),
            signatures: Vec::new(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Commit to an already-signed attestation: the bytes, the slot and the challenge are
    /// all taken from the document and the round, so the only way to get a commitment
    /// that does not open is to publish different bytes than this.
    pub fn for_document(
        round: &Round,
        doc: &AttestationDoc,
        now: gitiup_attest::TimeUs,
    ) -> Result<Commitment> {
        let [signature] = doc.signatures.as_slice() else {
            return Err(Error::policy(
                "commitment",
                format!(
                    "a commitment is made by the one key whose attestation it commits to; \
                     this document carries {} signatures",
                    doc.signatures.len()
                ),
            ));
        };
        let key_id = signature.key_id.clone();
        let expected = round.challenge_for(&key_id)?;
        match doc.manifest.claims.verifier_challenge.as_ref() {
            None => {
                return Err(Error::digest_mismatch(
                    "commitment",
                    format!(
                        "this attestation does not carry a verifier challenge, so there is \
                         nothing for a sealed commitment to bind it to ({}: the challenge is \
                         what stops one signature serving two rounds)",
                        short_key(&key_id)
                    ),
                ));
            }
            Some(carried) if *carried != expected => {
                return Err(Error::digest_mismatch(
                    "commitment",
                    format!(
                        "this attestation is bound to challenge {carried}, which is not this \
                         round's {} challenge {expected}: a commitment to another round's \
                         work is not a commitment to this one",
                        short_key(&key_id)
                    ),
                ));
            }
            Some(_) => {}
        }
        Commitment::new(round, &key_id, &doc.canonical_bytes()?, now)
    }

    /// Structural checks.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != COMMITMENT_SCHEMA_VERSION
            || self.commitment_type != COMMITMENT_TYPE
        {
            return Err(Error::unsupported(
                "commitment",
                format!(
                    "unknown commitment type '{}' (schema version {})",
                    self.commitment_type, self.schema_version
                ),
            ));
        }
        check_segment(&self.change_id, "change id")?;
        check_segment(&self.job_id, "job id")?;
        check_slot(&self.slot)?;
        require_key_id_shape(&self.key_id, "commitment key")?;
        if self.committed_at_us <= 0 {
            return Err(Error::invalid(
                "commitment",
                "a commitment records the moment it was made; without a clock it is a hash \
                 with no history",
            ));
        }
        if self.signatures.len() > 1 {
            return Err(Error::invalid(
                "commitment",
                "one commitment is made by one key; a second signature is not a stronger \
                 promise",
            ));
        }
        Ok(())
    }

    /// The bytes the seat key's signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes: what goes into `kv/commit/<hex>`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Digest of the commitment record.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Read from storage: canonical bytes, structure, and bytes-that-re-encode.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Commitment> {
        let commitment: Commitment = from_canonical_bytes(bytes)?;
        commitment.validate()?;
        require_same_bytes(&commitment, bytes)?;
        Ok(commitment)
    }

    /// Sign as the seat's key.
    pub fn sign(&mut self, key: &dyn Signer) -> Result<SignatureEntry> {
        let entry = crate::record::sign(COMMITMENT_PAYLOAD_TYPE, &self.body_bytes()?, key)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        Ok(entry)
    }

    /// Check the commitment's own signature: exactly one, by the key it names.
    ///
    /// No trust list, for the reason [`Lease::verify`](crate::job::Lease::verify) gives:
    /// a commitment is a key's claim about itself. Its *authority* in a tally comes from
    /// the seat it sits on, which the round and the roster vouch for.
    pub fn verify(&self) -> Result<Digest> {
        self.validate()?;
        let [entry] = self.signatures.as_slice() else {
            return Err(Error::signature(
                "commitment",
                format!(
                    "a commitment is signed by the key that makes it and by nobody else; this \
                     one carries {}",
                    self.signatures.len()
                ),
            ));
        };
        if entry.key_id != self.key_id {
            return Err(Error::signature(
                "commitment",
                format!(
                    "this commitment names {} as its author but is signed by {}: a promise \
                     made in somebody else's slot is a forgery or a bug, never a courtesy",
                    short_key(&self.key_id),
                    short_key(&entry.key_id)
                ),
            ));
        }
        verify_one(entry, COMMITMENT_PAYLOAD_TYPE, &self.body_bytes()?)?;
        self.digest()
    }

    /// Does this commitment speak about `round` and about the seat `key_id` holds in it?
    ///
    /// A stale commitment — same slot, different round, or an attempt that has moved on —
    /// opens nothing here, and believing it anyway would be the "the ref was there" bug.
    pub fn matches(&self, round: &Round, key_id: &str) -> Result<()> {
        let seat = round.seat(key_id).ok_or_else(|| {
            Error::policy(
                "commitment",
                format!(
                    "{} holds no seat in this round, so a commitment in its name is not about \
                     this round",
                    short_key(key_id)
                ),
            )
        })?;
        let mut differs: Vec<&str> = Vec::new();
        if self.change_id != round.inputs.change_id {
            differs.push("change id");
        }
        if self.job_id != round.inputs.job_id {
            differs.push("job id");
        }
        if self.attempt != round.inputs.attempt {
            differs.push("attempt");
        }
        if self.key_id != key_id {
            differs.push("key id");
        }
        if self.slot != seat.slot {
            differs.push("slot");
        }
        if self.challenge != round.challenge_for(key_id)? {
            differs.push("challenge");
        }
        if self.round_digest != round.digest()? {
            differs.push("round digest");
        }
        if !differs.is_empty() {
            return Err(Error::digest_mismatch(
                "commitment",
                format!(
                    "this commitment does not describe the round it is filed against ({} \
                     differ): it opens nothing here",
                    differs.join(", ")
                ),
            ));
        }
        Ok(())
    }

    /// The hash the reveal of `doc` must produce — the commitment, recomputed from the
    /// bytes actually in the store.
    ///
    /// Returns the digest rather than a boolean so a refusal can print both halves: what
    /// was promised and what was revealed.
    pub fn reveals_as(&self, doc: &AttestationDoc) -> Result<Digest> {
        Ok(commitment_of(
            &doc.canonical_bytes()?,
            &self.slot,
            &self.challenge,
        ))
    }

    /// Did `doc` open this commitment?
    pub fn opens_with(&self, doc: &AttestationDoc) -> Result<bool> {
        Ok(self.reveals_as(doc)? == self.commitment)
    }

    /// A one-line description for a terminal.
    pub fn describe(&self) -> String {
        format!(
            "{}/{} attempt {} slot …{}: {}",
            self.change_id,
            self.job_id,
            self.attempt,
            &self.slot[..6],
            self.commitment
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::SelectionSecret;
    use crate::round::REVEAL_MODE_SEALED;
    use crate::sample;
    use gitiup_attest::{AttestationDoc, Digest, SigningKey};

    /// A sealed round over the fixture roster, signed by the owner.
    fn round() -> Round {
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build/matrix/linux");
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round =
            Round::open_sealed(&inputs, &roster, &secret).expect("a round opens sealed");
        round.sign(&owner).expect("the selector signs");
        round
    }

    /// The first seat's attestation, and the key that signed it.
    fn revealed(round: &Round) -> (AttestationDoc, SigningKey) {
        let index = sample::indices_of(round)[0];
        let key = sample::verifier_key(index);
        let doc = sample::attest(round, &[index], sample::claimed_at_us(), |_| None)
            .into_iter()
            .next()
            .expect("one attestation");
        (doc, key)
    }

    #[test]
    fn a_commitment_opens_only_the_bytes_it_promised() {
        let round = round();
        assert_eq!(round.reveal_mode, REVEAL_MODE_SEALED);
        let (doc, key) = revealed(&round);
        let mut commitment =
            Commitment::for_document(&round, &doc, sample::clock()).expect("commits");
        commitment.sign(&key).expect("the seat key signs");
        assert_eq!(commitment.verify().unwrap(), commitment.digest().unwrap());
        assert!(commitment.opens_with(&doc).unwrap());
        commitment
            .matches(&round, &key.public_key().key_id())
            .unwrap();
        let bytes = commitment.canonical_bytes().unwrap();
        assert!(gitiup_attest::is_canonical(&bytes));
        assert_eq!(
            Commitment::from_canonical_bytes(&bytes).unwrap(),
            commitment
        );
        // A different answer from the same seat does not open it.
        let index = sample::indices_of(&round)[0];
        let other = sample::attest(&round, &[index], sample::claimed_at_us(), |_| {
            Some("test result: FAILED".into())
        })
        .into_iter()
        .next()
        .unwrap();
        assert!(!commitment.opens_with(&other).unwrap());
        assert_ne!(
            commitment.reveals_as(&other).unwrap(),
            commitment.commitment,
            "and the refusal can name both halves because both are computable"
        );
    }

    #[test]
    fn the_preimage_is_the_slot_and_the_challenge_as_well_as_the_bytes() {
        let round = round();
        let (doc, _) = revealed(&round);
        let bytes = doc.canonical_bytes().unwrap();
        let seat = &round.selected[0];
        let challenge = round.challenge_for(&seat.key_id).unwrap();
        let by_formula = commitment_of(&bytes, &seat.slot, &challenge);
        assert_eq!(
            by_formula,
            Commitment::for_document(&round, &doc, sample::clock())
                .unwrap()
                .commitment
        );
        // Move any of the three and the hash moves, which is what stops a commitment
        // being carried between seats or rounds.
        assert_ne!(by_formula, commitment_of(b"", &seat.slot, &challenge));
        assert_ne!(
            by_formula,
            commitment_of(&bytes, &"f".repeat(64), &challenge)
        );
        assert_ne!(
            by_formula,
            commitment_of(&bytes, &seat.slot, &Digest::sha256(b"other"))
        );
    }

    #[test]
    fn an_attestation_bound_to_another_round_is_not_committable() {
        let round = round();
        let (doc, key) = revealed(&round);
        let mut foreign = doc.manifest.clone();
        foreign.claims.verifier_challenge = Some(Digest::sha256(b"another round's challenge"));
        let mut doc = AttestationDoc::new(foreign);
        doc.sign(&key).unwrap();
        let err = Commitment::for_document(&round, &doc, sample::clock()).unwrap_err();
        assert_eq!(err.exit_code(), 8, "{err}");
    }

    #[test]
    fn a_commitment_signed_by_somebody_else_is_a_forgery() {
        let round = round();
        let (doc, _) = revealed(&round);
        let mut commitment = Commitment::for_document(&round, &doc, sample::clock()).unwrap();
        commitment.sign(&sample::verifier_key(63)).unwrap();
        let err = commitment.verify().unwrap_err();
        assert_eq!(err.exit_code(), 7, "{err}");
        assert!(err.message().contains("signed"), "{err}");
    }

    #[test]
    fn a_stale_commitment_opens_nothing() {
        let round = round();
        let (doc, key) = revealed(&round);
        let mut commitment = Commitment::for_document(&round, &doc, sample::clock()).unwrap();
        commitment.sign(&key).unwrap();
        // The same seat at a later attempt: an escalation has a new seed, a new
        // challenge and no use for this promise.
        commitment.attempt += 1;
        let err = commitment
            .matches(&round, &key.public_key().key_id())
            .unwrap_err();
        assert_eq!(err.exit_code(), 8, "{err}");
        assert!(err.message().contains("attempt"), "{err}");
    }

    #[test]
    fn an_unsigned_commitment_is_no_promise() {
        let round = round();
        let (doc, _) = revealed(&round);
        let unsigned = Commitment::for_document(&round, &doc, sample::clock()).unwrap();
        assert_eq!(unsigned.verify().unwrap_err().exit_code(), 7);
    }
}

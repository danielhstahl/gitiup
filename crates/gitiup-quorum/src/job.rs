//! Job advertisements and TTL leases: how a volunteer finds its invitation, and how
//! two volunteers avoid doing the same job twice
//! ([giti-zp1.1](../../../README.md),
//! [ADR-0002 D10, D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! # The advertisement is a round's inverse index, nothing more
//!
//! A [`Round`] answers "who was picked for this job". A volunteer
//! polling a store cannot use it: that question is addressed *from* the change, and the
//! volunteer starts *from* the store, asking "what wants doing". A reverse index would
//! be a second source of truth, so there is not one; there is a ref that names the job
//! and points at the round:
//!
//! ```text
//! refs/gitiup/job/<change>/<job>      → kv/job/<hex>: the advertisement
//! ```
//!
//! One ref per `(change, job)`, not one per attempt: an escalation *moves* the ref
//! forward, so the listing has one row per job rather than one row per round somebody
//! gave up on. Listing that prefix — and only that prefix, never `refs/gitiup/**` — is
//! what "rounds that still need filling" costs, which is the whole requirement for a
//! poll that runs every minute from a few hundred volunteers.
//!
//! **An advertisement is an index, not an authority.** It is derived from a round and it
//! is believed only through that round: a volunteer fetches the round, runs
//! [`Round::verify`] and
//! [`Advertisement::matches`], and only then believes a word of the invitation. The ad
//! carries the selector's signature so the cheap check is possible
//! ([`Advertisement::verify`]), but the cheap check was never the safety argument — the
//! re-derived selection is (D11). That is also why an advertisement copies the seats:
//! with `reveal_mode = open` the seats are public anyway, and copying them is what makes
//! "am I invited?" answerable without fetching a round per job. A sealed round
//! (giti-zp1.6) therefore must not be advertised like this, and [`Advertisement::new`]
//! refuses one rather than quietly leaking what the mode exists to hide.
//!
//! # A lease is advice, not a lock
//!
//! ```text
//! refs/gitiup/lease/<change>/<job>/<slot>   → kv/job/<hex>: {holder, acquired_at, ttl, attempt}
//! ```
//!
//! A lease is one volunteer telling the others "I am running this seat; don't burn your
//! battery on it". Three properties, and the third is the one that stops this from
//! becoming a lock nobody can release:
//!
//! 1. **It expires.** A lease carries a TTL, and an expired lease is *stealable* — the
//!    volunteer that died mid-job must not black out a seat for an hour. A steal is
//!    recorded in the new lease ([`Taken`]), so "who had this before me" is auditable
//!    rather than lost.
//! 2. **It is compare-and-swap.** A free slot is claimed, a live one is *refused* with
//!    the holder's name and the remaining TTL, and two callers racing for an expired
//!    lease get one winner and one polite refusal. The store arbitrates; there is no
//!    coordinator to bribe or to be down.
//! 3. **It grants nothing.** Admission to submit is [`gate::admit`](crate::gate::admit),
//!    and that function has never heard of leases: a key holding a seat has a vote
//!    whether or not anybody holds a lease on it, and a key holding a lease without a
//!    seat has nothing. So the volunteer that took over a dead lease may run the work —
//!    and the slow original holder that finishes *first* still counts, because the seat
//!    is the authority and the lease is only advice about it. See
//!    [`store::claim_lease`](crate::store::claim_lease) for the writes, and
//!    `tests/job_leases.rs::a_live_lease_does_not_displace_an_attestation` for the rule
//!    being enforced rather than asserted.
//!
//! A lease is signed by the key that takes it and by nobody else, so [`Lease::verify`]
//! takes no trust list: the store cannot invent a lease for a key that never made one,
//! and no owner approval is involved because nothing is being approved. A lease is
//! addressed by *attempt* too: escalating to attempt `n+1` ends attempt `n`'s rounds, so
//! attempt `n`'s leases are not anybody's property any more — and that, like a steal, is
//! recorded rather than hidden.

use gitiup_attest::{Digest, GitOid, SignatureEntry, Signer, TimeUs, Trust};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::record::{
    ADVERTISEMENT_PAYLOAD_TYPE, LEASE_PAYLOAD_TYPE, body_bytes, canonical_bytes, check_signatures,
    from_canonical_bytes, require_key_id_shape, require_same_bytes, short_key,
};
use crate::round::{REVEAL_MODE_OPEN, Round};
use crate::select::Seat;
use crate::store::check_segment;

/// The `type` of a job advertisement record.
pub const ADVERTISEMENT_TYPE: &str = "gitiup-job-advertisement-1";
/// The advertisement schema version this crate writes.
pub const ADVERTISEMENT_SCHEMA_VERSION: u32 = 1;
/// The `type` of a lease record.
pub const LEASE_TYPE: &str = "gitiup-lease-1";
/// The lease schema version this crate writes.
pub const LEASE_SCHEMA_VERSION: u32 = 1;

/// How long a lease is good for when nobody says otherwise (15 minutes).
///
/// Long enough for a real build, short enough that a volunteer that was rebooted mid-job
/// costs a coffee break and not an hour of a seat nobody may use. A holder that is still
/// working renews ([`store::renew_lease`](crate::store::renew_lease)); that is what the
/// heartbeat is for.
pub const DEFAULT_LEASE_TTL_US: i64 = 15 * 60 * 1_000_000;

/// The longest lease this build will write (1 hour).
///
/// A TTL is not a reservation. Anything longer than this is a lease that outlives the
/// round it was taken for, and the tooling to notice that is `open_rounds`, which is
/// cheap precisely so that it runs often.
pub const MAX_LEASE_TTL_US: i64 = 60 * 60 * 1_000_000;

/// How long a job keeps advertising itself when nothing closes it (24 hours).
///
/// A job that nobody fills is not an error — it is `insufficient`, and that is a verdict
/// somebody publishes — but an abandoned change should stop costing polls eventually.
/// The real close is [`store::close_job`](crate::store::close_job), which the verdict
/// publisher calls; this is the backstop for the change nobody ever tallied.
pub const DEFAULT_JOB_TTL_US: i64 = 24 * 60 * 60 * 1_000_000;

/// The longest an advertisement may ask to live (7 days).
pub const MAX_JOB_TTL_US: i64 = 7 * 24 * 60 * 60 * 1_000_000;

/// Seats an advertisement may name (a bound on one record's bytes, not a policy).
pub const MAX_ADVERTISED_SEATS: usize = 64;

/// How many prior holders one lease remembers.
///
/// Bounded because a lease is a note, not a ledger: the audit trail of a contested seat
/// is the store's reflog and each lease's own `taken` list, and either one being
/// unbounded is a blob that grows forever in a fight.
pub const MAX_LEASE_HISTORY: usize = 8;

/// A job that is open for business: the seats a round picked, published where a
/// volunteer looking for work will find them.
///
/// Constructed from a round ([`Advertisement::new`], then signed by one of the round's
/// own selectors) and stored at `refs/gitiup/job/<change>/<job>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advertisement {
    /// Must be [`ADVERTISEMENT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`ADVERTISEMENT_TYPE`].
    #[serde(rename = "type")]
    pub advertisement_type: String,
    /// The change being verified.
    pub change_id: String,
    /// The job (matrix vector) within it.
    pub job_id: String,
    /// Which round this advertises (`0` first, `≥1` escalations).
    pub attempt: u64,
    /// The head the result must be bound to.
    pub head_oid: GitOid,
    /// The roster epoch the round pins.
    pub roster_epoch: u64,
    /// Digest of that roster.
    pub roster_digest: Digest,
    /// Digest of the round record this is an index into — the link back to authority.
    pub round_digest: Digest,
    /// Digest of the policy the selection ran under.
    pub policy_digest: Digest,
    /// Copied from the round, and refused unless it is `"open"`: an index over a sealed
    /// round would publish the very set the mode exists to keep secret.
    pub reveal_mode: String,
    /// Distinct identities that must agree for this job to pass, so a volunteer knows
    /// what its one vote is worth.
    pub required_agree: usize,
    /// The seats, in score order: the invitation list.
    pub seats: Vec<Seat>,
    /// The lease TTL this job suggests, so five volunteers lease in the same units.
    pub lease_ttl_us: i64,
    /// When this was advertised.
    pub advertised_at_us: i64,
    /// When it stops being news even if nobody closed it.
    pub expires_at_us: i64,
    /// The selector's signature over the record's body.
    pub signatures: Vec<SignatureEntry>,
}

/// One lease taken over an earlier, dead one: the audit trail a steal has to have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Taken {
    /// The key whose lease this replaced.
    pub holder: String,
    /// The attempt that lease was for — a lease from a finished attempt is not
    /// anybody's property, which is a different fact from "it timed out" and is why it
    /// is recorded rather than skipped.
    pub attempt: u64,
    /// When the displaced lease was acquired.
    pub acquired_at_us: i64,
    /// When it died (or was made void by an attempt bump).
    pub expired_at_us: i64,
    /// When the new holder took the slot.
    pub taken_at_us: i64,
}

impl Taken {
    /// The record of taking `lease` over at `now`.
    pub fn of(lease: &Lease, now: TimeUs) -> Taken {
        Taken {
            holder: lease.holder.clone(),
            attempt: lease.attempt,
            acquired_at_us: lease.acquired_at_us,
            expired_at_us: lease.expires_at_us(),
            taken_at_us: now.as_us(),
        }
    }
}

/// A volunteer's advisory claim on one seat of one job.
///
/// Fields are exactly what the ticket asks for — `{holder, acquired_at, ttl, attempt}` —
/// plus the steal trail. Nothing in this struct is authority: see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    /// Must be [`LEASE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`LEASE_TYPE`].
    #[serde(rename = "type")]
    pub lease_type: String,
    /// The change the job belongs to.
    pub change_id: String,
    /// The job.
    pub job_id: String,
    /// The round attempt the seat belongs to. A lease does not cross attempts.
    pub attempt: u64,
    /// The seat's hex slot (same slot as its submission ref).
    pub slot: String,
    /// The key holding it — always the key that signed, never a key being talked about.
    pub holder: String,
    /// When it was taken (or last renewed).
    pub acquired_at_us: i64,
    /// How long it lasts from there.
    pub ttl_us: i64,
    /// The leases this one displaced, oldest first, capped at [`MAX_LEASE_HISTORY`].
    pub taken: Vec<Taken>,
    /// Exactly one signature, by [`Lease::holder`].
    pub signatures: Vec<SignatureEntry>,
}

impl Advertisement {
    /// Copy the invitation out of a round the caller has already verified.
    ///
    /// Refusals, each one a volunteer's wasted hours prevented:
    ///
    /// * a round that is not `sufficient` cannot reach its threshold whatever happens,
    ///   so it is a dispute (giti-zp1.7) and not an invitation;
    /// * a round whose `reveal_mode` this build cannot enforce is refused by
    ///   [`Round::validate`], which is also what refuses a sealed round — an
    ///   advertisement publishes the seats, and for a sealed round the seats *are* the
    ///   secret;
    /// * a TTL outside its bounds is refused rather than clamped, because a silently
    ///   shortened lease is a surprise at the worst moment.
    pub fn new(round: &Round, now: TimeUs, lease_ttl_us: i64, job_ttl_us: i64) -> Result<Self> {
        round.validate()?;
        if !round.sufficient {
            return Err(Error::policy(
                "advertisement",
                format!(
                    "{}/{} attempt {} filled {} of {} seats, so no amount of volunteers can \
                     reach its threshold: that is an insufficient round to be escalated, not a \
                     job to be advertised",
                    round.inputs.change_id,
                    round.inputs.job_id,
                    round.inputs.attempt,
                    round.selected.len(),
                    round.inputs.policy.n
                ),
            ));
        }
        check_ttl(lease_ttl_us, MAX_LEASE_TTL_US, "lease TTL")?;
        check_ttl(job_ttl_us, MAX_JOB_TTL_US, "advertisement TTL")?;
        let advertisement = Advertisement {
            schema_version: ADVERTISEMENT_SCHEMA_VERSION,
            advertisement_type: ADVERTISEMENT_TYPE.to_string(),
            change_id: round.inputs.change_id.clone(),
            job_id: round.inputs.job_id.clone(),
            attempt: round.inputs.attempt,
            head_oid: round.inputs.head_oid.clone(),
            roster_epoch: round.inputs.roster_epoch,
            roster_digest: round.inputs.roster_digest.clone(),
            round_digest: round.digest()?,
            policy_digest: round.policy_digest.clone(),
            reveal_mode: round.reveal_mode.clone(),
            required_agree: round.inputs.policy.required_agree,
            seats: round.selected.clone(),
            lease_ttl_us,
            advertised_at_us: now.as_us(),
            expires_at_us: now.as_us().saturating_add(job_ttl_us),
            signatures: Vec::new(),
        };
        advertisement.validate()?;
        Ok(advertisement)
    }

    /// Structural checks, including the ones that stop a v2 record being read as v1.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != ADVERTISEMENT_SCHEMA_VERSION
            || self.advertisement_type != ADVERTISEMENT_TYPE
        {
            return Err(Error::unsupported(
                "advertisement",
                format!(
                    "unknown job advertisement type '{}' (schema version {})",
                    self.advertisement_type, self.schema_version
                ),
            ));
        }
        check_segment(&self.change_id, "change id")?;
        check_segment(&self.job_id, "job id")?;
        if self.reveal_mode != REVEAL_MODE_OPEN {
            return Err(Error::unsupported(
                "advertisement",
                format!(
                    "reveal mode '{}' is not enforced by this build, and an advertisement \
                     lists the seats — which a round in that mode exists to keep \
                     unlistable. Advertising a sealed round needs a sealed advertisement \
                     (giti-zp1.6), not this one with the field rewritten.",
                    self.reveal_mode
                ),
            ));
        }
        if self.seats.is_empty() || self.seats.len() > MAX_ADVERTISED_SEATS {
            return Err(Error::invalid(
                "advertisement",
                format!(
                    "{} seats is not a seat list; a job advertises between 1 and \
                     {MAX_ADVERTISED_SEATS}",
                    self.seats.len()
                ),
            ));
        }
        let ranks: Vec<u32> = self.seats.iter().map(|s| s.rank).collect();
        if ranks
            .iter()
            .enumerate()
            .any(|(i, rank)| *rank != (i + 1) as u32)
        {
            return Err(Error::invalid(
                "advertisement",
                "advertised seat ranks must be 1..=n with no gaps, exactly as the round \
                 published them",
            ));
        }
        if self.expires_at_us <= self.advertised_at_us {
            return Err(Error::invalid(
                "advertisement",
                "an advertisement cannot expire at or before the moment it was made",
            ));
        }
        check_ttl(self.lease_ttl_us, MAX_LEASE_TTL_US, "lease TTL")?;
        if self.signatures.len() > gitiup_attest::MAX_SIGNATURES {
            return Err(Error::invalid(
                "advertisement",
                "too many signatures on one advertisement",
            ));
        }
        Ok(())
    }

    /// The bytes a selector signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes: what goes into `kv/job/<hex>`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Digest of the advertisement.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Read from storage: canonical bytes, structure, and bytes-that-re-encode.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let advertisement: Advertisement = from_canonical_bytes(bytes)?;
        advertisement.validate()?;
        require_same_bytes(&advertisement, bytes)?;
        Ok(advertisement)
    }

    /// Sign as a selector.
    pub fn sign(&mut self, selector: &dyn Signer) -> Result<SignatureEntry> {
        let entry = crate::record::sign(ADVERTISEMENT_PAYLOAD_TYPE, &self.body_bytes()?, selector)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(entry)
    }

    /// Check the selector signature, returning the advertisement's digest.
    ///
    /// This is the cheap belief. The full one is [`Advertisement::matches`] against a
    /// round that has itself been verified — an advertisement is an index into a signed
    /// record and is only as good as that record.
    pub fn verify(&self, selector_trust: &Trust) -> Result<Digest> {
        self.validate()?;
        check_signatures(
            &self.signatures,
            ADVERTISEMENT_PAYLOAD_TYPE,
            &self.body_bytes()?,
            selector_trust,
            "advertisement",
            gitiup_attest::MAX_SIGNATURES,
        )?;
        self.digest()
    }

    /// Does this advertisement still speak about `round`, or has it drifted?
    ///
    /// Called by whoever fetched the round. A ref moved under a poller — the job
    /// re-advertised at a new attempt while the blob was in flight — is caught here and
    /// not turned into work against a round the poller never read.
    pub fn matches(&self, round: &Round) -> Result<()> {
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
        if self.head_oid != round.inputs.head_oid {
            differs.push("head oid");
        }
        if self.roster_epoch != round.inputs.roster_epoch {
            differs.push("roster epoch");
        }
        if self.roster_digest != round.inputs.roster_digest {
            differs.push("roster digest");
        }
        if self.policy_digest != round.policy_digest {
            differs.push("policy digest");
        }
        if self.reveal_mode != round.reveal_mode {
            differs.push("reveal mode");
        }
        if self.round_digest != round.digest()? {
            differs.push("round digest");
        }
        if self.seats != round.selected {
            differs.push("seats");
        }
        if !differs.is_empty() {
            return Err(Error::digest_mismatch(
                "advertisement",
                format!(
                    "this advertisement does not describe the round it names ({} differ): \
                     believe the round, or believe neither",
                    differs.join(", ")
                ),
            ));
        }
        Ok(())
    }

    /// Still news at `now`?
    pub fn is_live(&self, now: TimeUs) -> bool {
        now.as_us() < self.expires_at_us
    }

    /// Microseconds of advertised life left (never negative).
    pub fn remaining_us(&self, now: TimeUs) -> i64 {
        self.expires_at_us.saturating_sub(now.as_us()).max(0)
    }

    /// The seat held by `key_id`, if this job has one for them.
    pub fn seat(&self, key_id: &str) -> Option<&Seat> {
        self.seats.iter().find(|s| s.key_id == key_id)
    }

    /// Is `key_id` invited?
    pub fn invites(&self, key_id: &str) -> bool {
        self.seat(key_id).is_some()
    }

    /// The lease TTL this job asks volunteers to use.
    pub fn lease_ttl(&self) -> i64 {
        self.lease_ttl_us
    }

    /// A one-line description for a terminal.
    pub fn describe(&self) -> String {
        format!(
            "{} attempt {} ({} seats, {} to agree, lease {})",
            JobAddress {
                change_id: &self.change_id,
                job_id: &self.job_id,
            },
            self.attempt,
            self.seats.len(),
            self.required_agree,
            ttl_text(self.lease_ttl_us)
        )
    }
}

impl Lease {
    /// A lease for `slot`, held by `holder`, unsigned.
    ///
    /// `taken` is the trail of the leases this one displaced; [`Taken::of`] makes the
    /// entry and [`store::claim_lease`](crate::store::claim_lease) is what supplies it.
    pub fn new(
        job: JobAddress<'_>,
        attempt: u64,
        slot: &str,
        holder: &str,
        now: TimeUs,
        ttl_us: i64,
        taken: Vec<Taken>,
    ) -> Result<Lease> {
        let lease = Lease {
            schema_version: LEASE_SCHEMA_VERSION,
            lease_type: LEASE_TYPE.to_string(),
            change_id: job.change_id.to_string(),
            job_id: job.job_id.to_string(),
            attempt,
            slot: slot.to_string(),
            holder: holder.to_string(),
            acquired_at_us: now.as_us(),
            ttl_us,
            taken,
            signatures: Vec::new(),
        };
        lease.validate()?;
        Ok(lease)
    }

    /// Structural checks. A lease that does not parse exactly as this build writes is a
    /// lease this build cannot reason about, so `deny_unknown_fields` plus these checks
    /// is the whole forward-compatibility story.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != LEASE_SCHEMA_VERSION || self.lease_type != LEASE_TYPE {
            return Err(Error::unsupported(
                "lease",
                format!(
                    "unknown lease type '{}' (schema version {})",
                    self.lease_type, self.schema_version
                ),
            ));
        }
        check_segment(&self.change_id, "change id")?;
        check_segment(&self.job_id, "job id")?;
        check_slot(&self.slot)?;
        require_key_id_shape(&self.holder, "lease holder")?;
        check_ttl(self.ttl_us, MAX_LEASE_TTL_US, "lease TTL")?;
        if self.taken.len() > MAX_LEASE_HISTORY {
            return Err(Error::invalid(
                "lease",
                format!(
                    "{} displaced leases exceeds the {MAX_LEASE_HISTORY} a lease is allowed \
                     to remember",
                    self.taken.len()
                ),
            ));
        }
        if self.signatures.len() > 1 {
            return Err(Error::invalid(
                "lease",
                "one lease is claimed by one key; a second signature is not a stronger claim",
            ));
        }
        Ok(())
    }

    /// The bytes the holder's signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes: what goes into `kv/job/<hex>`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Digest of the lease.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Read from storage.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let lease: Lease = from_canonical_bytes(bytes)?;
        lease.validate()?;
        require_same_bytes(&lease, bytes)?;
        Ok(lease)
    }

    /// Sign as the holder.
    pub fn sign(&mut self, holder: &dyn Signer) -> Result<SignatureEntry> {
        let entry = crate::record::sign(LEASE_PAYLOAD_TYPE, &self.body_bytes()?, holder)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        Ok(entry)
    }

    /// Check the lease's own signature: exactly one, by the holder it names.
    ///
    /// No trust list, deliberately. A roster entry is a claim by the owner about a key,
    /// so it needs the owner's approval; a lease is a claim by a key about itself, so the
    /// only signature that can authorise it is that key's. Checking a trust list here
    /// would mean a lease is only real if the owner said so, which turns advice back into
    /// permission and puts the owner in the loop of every volunteer's polling.
    pub fn verify(&self) -> Result<Digest> {
        self.validate()?;
        let [entry] = self.signatures.as_slice() else {
            return Err(Error::signature(
                "lease",
                format!(
                    "a lease is signed by its holder and by nobody else; this one carries {}",
                    self.signatures.len()
                ),
            ));
        };
        if entry.key_id != self.holder {
            return Err(Error::signature(
                "lease",
                format!(
                    "this lease names {} as its holder but is signed by {}: a lease is a key's \
                     claim about itself, so a lease for somebody else is a forgery or a bug, \
                     never a courtesy",
                    short_key(&self.holder),
                    short_key(&entry.key_id)
                ),
            ));
        }
        crate::record::verify_one(entry, LEASE_PAYLOAD_TYPE, &self.body_bytes()?)?;
        self.digest()
    }

    /// When this lease dies.
    pub fn expires_at_us(&self) -> i64 {
        self.acquired_at_us.saturating_add(self.ttl_us)
    }

    /// Microseconds until it dies (never negative).
    pub fn remaining_us(&self, now: TimeUs) -> i64 {
        self.expires_at_us().saturating_sub(now.as_us()).max(0)
    }

    /// Is it still alive at `now`?
    pub fn is_live(&self, now: TimeUs) -> bool {
        now.as_us() < self.expires_at_us()
    }

    /// Dead at `now` — and therefore somebody else's for the taking.
    pub fn is_expired(&self, now: TimeUs) -> bool {
        !self.is_live(now)
    }

    /// Is `key_id` the holder *and* is the lease alive?
    pub fn held_by(&self, key_id: &str, now: TimeUs) -> bool {
        self.holder == key_id && self.is_live(now)
    }

    /// The lease this one displaced, newest first, if any.
    pub fn last_taken(&self) -> Option<&Taken> {
        self.taken.last()
    }

    /// Push a displaced lease, keeping the trail inside [`MAX_LEASE_HISTORY`].
    fn push_taken(&mut self, taken: Taken) {
        self.taken.push(taken);
        let overflow = self.taken.len().saturating_sub(MAX_LEASE_HISTORY);
        if overflow > 0 {
            self.taken.drain(0..overflow);
        }
    }

    /// The job and seat this lease is about, for a log line.
    pub fn describe(&self) -> String {
        format!(
            "{} slot {} attempt {} — {} ({})",
            JobAddress {
                change_id: &self.change_id,
                job_id: &self.job_id,
            },
            short_slot(&self.slot),
            self.attempt,
            short_key(&self.holder),
            ttl_text(self.ttl_us)
        )
    }
}

/// Where a job lives: `<change>/<job>`, the pair every job and lease ref is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobAddress<'a> {
    /// The change.
    pub change_id: &'a str,
    /// The job within it.
    pub job_id: &'a str,
}

impl std::fmt::Display for JobAddress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.change_id, self.job_id)
    }
}

/// The request behind a claim, a renewal and a release: one seat, one key, one TTL.
///
/// The holder is a [`Signer`] and not a key id string on purpose: the holder of a lease
/// *is* the key that signs it, so there is no code path in which a volunteer acquires a
/// lease in somebody else's name.
#[derive(Clone)]
pub struct LeaseRequest<'a> {
    /// The change.
    pub change_id: &'a str,
    /// The job.
    pub job_id: &'a str,
    /// The attempt whose seat is wanted.
    pub attempt: u64,
    /// The seat's hex slot.
    pub slot: &'a str,
    /// The key taking the lease; its fingerprint becomes the holder.
    pub holder: &'a dyn Signer,
    /// How long to hold it for.
    pub ttl_us: i64,
    /// The clock. Pinned in tests, `TimeUs::now()` in the field.
    pub now: TimeUs,
}

impl<'a> LeaseRequest<'a> {
    /// A request for `slot`'s seat in `change/job` at `attempt`, held by `holder`.
    pub fn new(
        change_id: &'a str,
        job_id: &'a str,
        attempt: u64,
        slot: &'a str,
        holder: &'a dyn Signer,
    ) -> LeaseRequest<'a> {
        LeaseRequest {
            change_id,
            job_id,
            attempt,
            slot,
            holder,
            ttl_us: DEFAULT_LEASE_TTL_US,
            now: TimeUs::now(),
        }
    }

    /// Pin the clock (tests, replays, and anyone who wants a lease's maths to be theirs).
    pub fn at(mut self, now: TimeUs) -> Self {
        self.now = now;
        self
    }

    /// Ask for a specific TTL (refused above [`MAX_LEASE_TTL_US`]).
    pub fn ttl(mut self, ttl_us: i64) -> Self {
        self.ttl_us = ttl_us;
        self
    }

    /// The holder's key id.
    pub fn holder_id(&self) -> String {
        self.holder.key_id()
    }

    /// The job this request is about.
    pub fn job(&self) -> JobAddress<'a> {
        JobAddress {
            change_id: self.change_id,
            job_id: self.job_id,
        }
    }

    /// Check the request before the store is touched: ids, slot shape, TTL bound, holder
    /// shape. A caller with a queue of seats can reject a malformed one for free.
    pub fn validate(&self) -> Result<()> {
        check_segment(self.change_id, "change id")?;
        check_segment(self.job_id, "job id")?;
        check_slot(self.slot)?;
        check_ttl(self.ttl_us, MAX_LEASE_TTL_US, "lease TTL")?;
        require_key_id_shape(&self.holder_id(), "lease holder")?;
        Ok(())
    }
}

/// Written by hand because a [`Signer`] is a key and does not print itself; the key id is
/// the part worth logging.
impl std::fmt::Debug for LeaseRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseRequest")
            .field("job", &self.job())
            .field("attempt", &self.attempt)
            .field("slot", &short_slot(self.slot))
            .field("holder", &short_key(&self.holder_id()))
            .field("ttl", &ttl_text(self.ttl_us))
            .field("now", &self.now)
            .finish()
    }
}

/// A lease TTL, refused rather than clamped: a lease that is quietly shorter than the
/// job it protects is a seat that goes out from under a running build.
fn check_ttl(ttl_us: i64, max: i64, what: &str) -> Result<()> {
    if ttl_us <= 0 {
        return Err(Error::invalid(
            "lease",
            format!("{what} must be a positive number of microseconds, not {ttl_us}"),
        ));
    }
    if ttl_us > max {
        return Err(Error::invalid(
            "lease",
            format!(
                "{what} of {} exceeds the {} this build allows",
                ttl_text(ttl_us),
                ttl_text(max)
            ),
        )
        .with_hint(
            "a long lease is a seat held by a volunteer that is not renewing; renew instead \
             — that is what the heartbeat is for",
        ));
    }
    Ok(())
}

/// A lease slot is the seat's hex slot (ADR-0002 D10): 64 lower-case hex digits.
pub(crate) fn check_slot(slot: &str) -> Result<()> {
    if slot.is_empty()
        || slot.len() != 64
        || !slot
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::invalid(
            "lease",
            format!(
                "'{}' is not a seat slot; a lease is addressed by the 64-hex-digit slot the \
                 round derived for the seat",
                short_slot(slot)
            ),
        ));
    }
    Ok(())
}

/// `1h4m`, `15m`, `59s`, `750ms` — a duration the way a lease is read out loud.
pub fn ttl_text(us: i64) -> String {
    if us <= 0 {
        return "0s".to_string();
    }
    if us < 1_000 {
        return format!("{us}µs");
    }
    if us < 1_000_000 {
        return format!("{}ms", us / 1_000);
    }
    let hours = us / 3_600_000_000;
    let minutes = (us % 3_600_000_000) / 60_000_000;
    let seconds = (us % 60_000_000) / 1_000_000;
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    if seconds > 0 || out.is_empty() {
        out.push_str(&format!("{seconds}s"));
    }
    out
}

/// A slot shortened for a terminal: `a1b2c3…9f8e7d`.
pub fn short_slot(slot: &str) -> String {
    if slot.len() <= 12 {
        return slot.to_string();
    }
    format!("{}…{}", &slot[..6], &slot[slot.len() - 6..])
}

/// Keep a steal trail inside its bound (used by the store, which owns the transition).
pub(crate) fn record_steal(lease: &mut Lease, taken: Taken) {
    lease.push_taken(taken);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sample, store};

    fn key(n: u8) -> gitiup_attest::SigningKey {
        gitiup_attest::SigningKey::from_seed(&[n; 32])
    }

    /// A round of five seats over the fixture roster, signed by the owner.
    fn round() -> Round {
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build/matrix/linux");
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).expect("round opens");
        round.sign(&owner).expect("selector signs");
        round
    }

    fn advertisement(round: &Round) -> Advertisement {
        let owner = sample::owner_key();
        let mut ad = Advertisement::new(
            round,
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            DEFAULT_JOB_TTL_US,
        )
        .expect("advertises");
        ad.sign(&owner).expect("selector signs");
        ad
    }

    #[test]
    fn an_advertisement_round_trips_and_matches_its_round() {
        let round = round();
        let ad = advertisement(&round);
        ad.matches(&round)
            .expect("it is the round's own invitation");
        let bytes = ad.canonical_bytes().unwrap();
        assert!(gitiup_attest::is_canonical(&bytes));
        let read = Advertisement::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read, ad);
        let owner = sample::owner_key();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        assert_eq!(read.verify(&trust).unwrap(), read.digest().unwrap());
        assert_eq!(read.seats, round.selected);
        assert!(read.is_live(sample::clock()));
        assert!(!read.is_live(TimeUs(read.expires_at_us)));
        for seat in &round.selected {
            assert!(read.invites(&seat.key_id));
        }
        assert!(!read.invites(&key(250).public_key().key_id()));
    }

    #[test]
    fn an_advertisement_about_a_different_round_is_a_digest_mismatch() {
        let round = round();
        let mut ad = advertisement(&round);
        ad.attempt += 1;
        let err = ad.matches(&round).unwrap_err();
        assert_eq!(err.exit_code(), 8, "{err}");
        assert!(err.message().contains("attempt"), "{err}");
    }

    #[test]
    fn an_unsigned_or_foreign_signed_advertisement_is_not_believable() {
        let round = round();
        let unsigned = Advertisement::new(
            &round,
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            DEFAULT_JOB_TTL_US,
        )
        .unwrap();
        let owner = sample::owner_key();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        assert_eq!(unsigned.verify(&trust).unwrap_err().exit_code(), 6);
        // Signed by a key the caller does not trust for selection: the same refusal a
        // round or verdict would give.
        let stranger = key(251);
        let mut foreign = unsigned;
        foreign.sign(&stranger).unwrap();
        assert_eq!(foreign.verify(&trust).unwrap_err().exit_code(), 6);
    }

    #[test]
    fn a_sealed_or_insufficient_round_is_not_advertised() {
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build/matrix/linux");
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let mut sealed = Round::open(&inputs, &roster, &secret).unwrap();
        sealed.reveal_mode = crate::round::REVEAL_MODE_SEALED.into();
        assert!(Advertisement::new(&sealed, sample::clock(), 60, 60).is_err());

        // Two eligible volunteers cannot fill five seats: that is `insufficient`, and
        // advertising it would recruit volunteers for a quorum that cannot happen.
        let thin = sample::roster_of(&owner, 2, 41);
        let thin_inputs = sample::round_inputs(&thin, "chg-000000000000f00d", "build/matrix/linux");
        let thin_round = Round::open(
            &thin_inputs,
            &thin,
            &crate::derive::SelectionSecret::from_signing_key(&owner),
        )
        .expect("an insufficient round still opens");
        assert!(!thin_round.sufficient);
        let err = Advertisement::new(
            &thin_round,
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            DEFAULT_JOB_TTL_US,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 6, "{err}");
        assert!(err.message().contains("insufficient"), "{err}");
    }

    #[test]
    fn ttl_bounds_are_refused_and_never_clamped() {
        let round = round();
        let owner = sample::owner_key();
        assert!(Advertisement::new(&round, sample::clock(), 0, DEFAULT_JOB_TTL_US).is_err());
        let too_long = Advertisement::new(
            &round,
            sample::clock(),
            MAX_LEASE_TTL_US + 1,
            DEFAULT_JOB_TTL_US,
        );
        assert!(too_long.is_err());
        assert!(
            Advertisement::new(&round, sample::clock(), MAX_LEASE_TTL_US, MAX_JOB_TTL_US).is_ok()
        );
        // The advertisement's own lifetime is bounded the same way.
        let mut ad = Advertisement::new(
            &round,
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            DEFAULT_JOB_TTL_US,
        )
        .unwrap();
        ad.sign(&owner).unwrap();
        ad.expires_at_us = ad.advertised_at_us;
        assert!(ad.validate().is_err());
    }

    #[test]
    fn a_lease_round_trips_and_is_signed_by_its_holder() {
        let holder = key(7);
        let slot = crate::derive::key_slot(&holder.public_key().key_id());
        let mut lease = Lease::new(
            JobAddress {
                change_id: "chg-1",
                job_id: "build/linux",
            },
            0,
            &slot,
            &holder.public_key().key_id(),
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            Vec::new(),
        )
        .unwrap();
        // Unsigned is not a lease: nobody has claimed it.
        assert_eq!(lease.verify().unwrap_err().exit_code(), 7);
        lease.sign(&holder).unwrap();
        assert_eq!(lease.verify().unwrap(), lease.digest().unwrap());
        let read = Lease::from_canonical_bytes(&lease.canonical_bytes().unwrap()).unwrap();
        assert_eq!(read, lease);
        assert!(read.held_by(&holder.public_key().key_id(), sample::clock()));
        assert!(!read.held_by(&key(8).public_key().key_id(), sample::clock()));
        assert_eq!(
            read.remaining_us(sample::clock()),
            DEFAULT_LEASE_TTL_US,
            "a fresh lease has its whole TTL"
        );
        assert_eq!(
            read.remaining_us(TimeUs(read.expires_at_us() + 1)),
            0,
            "and never a negative TTL"
        );
        assert!(read.is_expired(TimeUs(read.expires_at_us())));
    }

    #[test]
    fn a_lease_signed_by_somebody_else_is_a_forgery() {
        let holder = key(7);
        let other = key(8);
        let slot = crate::derive::key_slot(&holder.public_key().key_id());
        let mut lease = Lease::new(
            JobAddress {
                change_id: "chg-1",
                job_id: "build/linux",
            },
            0,
            &slot,
            &holder.public_key().key_id(),
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            Vec::new(),
        )
        .unwrap();
        lease.sign(&other).unwrap();
        let err = lease.verify().unwrap_err();
        assert_eq!(err.exit_code(), 7, "{err}");
        assert!(err.message().contains("holder"), "{err}");
    }

    #[test]
    fn a_lease_rejects_bad_addresses_bad_slots_and_bad_clocks() {
        let holder = key(7);
        let id = holder.public_key().key_id();
        let slot = crate::derive::key_slot(&id);
        let ttl = DEFAULT_LEASE_TTL_US;
        for (change, job, bad_slot, ttl_us, what) in [
            ("", "job", slot.as_str(), ttl, "empty change"),
            ("chg", "", slot.as_str(), ttl, "empty job"),
            ("chg", "job", "not-hex", ttl, "bad slot"),
            (
                "chg",
                "job",
                slot.as_str(),
                MAX_LEASE_TTL_US * 2,
                "long ttl",
            ),
            ("chg", "job", slot.as_str(), 0, "zero ttl"),
        ] {
            let err = Lease::new(
                JobAddress {
                    change_id: change,
                    job_id: job,
                },
                0,
                bad_slot,
                &id,
                sample::clock(),
                ttl_us,
                Vec::new(),
            );
            assert!(err.is_err(), "{what} must be refused: {err:?}");
        }
    }

    #[test]
    fn a_steal_trail_stays_bounded() {
        let holder = key(7);
        let slot = crate::derive::key_slot(&holder.public_key().key_id());
        let mut lease = Lease::new(
            JobAddress {
                change_id: "chg-1",
                job_id: "build/linux",
            },
            0,
            &slot,
            &holder.public_key().key_id(),
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            Vec::new(),
        )
        .unwrap();
        let steals = MAX_LEASE_HISTORY * 3;
        for index in 0..steals {
            let mut previous = lease.clone();
            previous.acquired_at_us = sample::T0 + i64::try_from(index).unwrap();
            record_steal(
                &mut lease,
                Taken::of(
                    &previous,
                    TimeUs(sample::T0 + i64::try_from(index + 1).unwrap()),
                ),
            );
        }
        assert_eq!(lease.taken.len(), MAX_LEASE_HISTORY);
        assert_eq!(
            lease
                .taken
                .first()
                .unwrap()
                .acquired_at_us
                .saturating_sub(sample::T0),
            i64::try_from(steals - MAX_LEASE_HISTORY).unwrap(),
            "the oldest entries are the ones dropped"
        );
        lease.sign(&holder).unwrap();
        assert!(Lease::from_canonical_bytes(&lease.canonical_bytes().unwrap()).is_ok());
    }

    #[test]
    fn durations_read_the_way_a_human_reads_a_lease() {
        assert_eq!(ttl_text(0), "0s");
        assert_eq!(ttl_text(-5), "0s");
        assert_eq!(ttl_text(999), "999µs");
        assert_eq!(ttl_text(500_000), "500ms");
        assert_eq!(ttl_text(59_000_000), "59s");
        assert_eq!(ttl_text(90_000_000), "1m30s");
        assert_eq!(ttl_text(DEFAULT_LEASE_TTL_US), "15m");
        assert_eq!(ttl_text(3_661_000_000), "1h1m1s");
        assert_eq!(short_slot(&"a".repeat(64)), "aaaaaa…aaaaaa");
    }

    #[test]
    fn a_lease_request_validates_before_the_store_is_touched() {
        let holder = key(7);
        let slot = crate::derive::key_slot(&holder.public_key().key_id());
        let good = LeaseRequest::new("chg-1", "build/linux", 0, &slot, &holder);
        assert!(good.validate().is_ok());
        assert_eq!(good.holder_id(), holder.public_key().key_id());
        assert!(good.clone().ttl(MAX_LEASE_TTL_US + 1).validate().is_err());
        assert!(store::lease_ref("chg-1", "build/linux", &slot).is_ok());
    }

    /// `LeaseRequest` is `Debug` for a caller that logs what it asked for; `Clone` lets
    /// a test reuse one across claim, renew and release.
    #[allow(dead_code)]
    fn assert_traits(req: &LeaseRequest<'_>) {
        let _ = format!("{req:?}");
    }

    #[test]
    fn a_sealed_advertisement_is_refused_even_if_built_by_hand() {
        let round = round();
        let mut ad = Advertisement::new(
            &round,
            sample::clock(),
            DEFAULT_LEASE_TTL_US,
            DEFAULT_JOB_TTL_US,
        )
        .unwrap();
        ad.reveal_mode = "sealed".into();
        let err = ad.validate().unwrap_err();
        assert_eq!(err.exit_code(), 6, "{err}");
        assert!(err.message().contains("sealed"), "{err}");
    }
}

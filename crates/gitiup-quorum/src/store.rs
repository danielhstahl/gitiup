//! Where the quorum lives: signed records in the host, addressed by refs
//! ([ADR-0002 D10](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! There is no broker. The store's compare-and-swap *is* the arbitration: one ref per
//! roster epoch, one ref per key's submission slot, one ref per verdict. That is what
//! makes "one vote per identity" and "one commitment per key" properties of the store
//! rather than promises in a protocol, and it is why a store outage pauses verification
//! instead of degrading it into guessing.
//!
//! ```text
//! refs/gitiup/roster                              the current epoch
//! refs/gitiup/roster/<epoch:08x>                 every epoch, retained (a round must be
//!                                                auditable against the roster it pinned)
//! refs/gitiup/signup/<slot>                      a self-signed sign-up
//! refs/gitiup/withdrawal/<slot>                  a signed withdrawal
//! refs/gitiup/revocation/<slot>                  a revocation record
//! refs/gitiup/round/<change>/<job>/<attempt>     the round record (inputs, seed, seats)
//! refs/gitiup/job/<change>/<job>                 the job advertisement: this round is open
//! refs/gitiup/lease/<change>/<job>/<slot>        one volunteer's TTL claim on one seat
//! refs/gitiup/commit/<change>/<job>/<slot>       phase 1 of a sealed round: the promise
//! refs/gitiup/reveal/<change>/<job>/<slot>       one verifier's submission (phase 2 of a
//!                                                sealed round: the bytes it promised)
//! refs/gitiup/verdict/<change>/<job>             the signed verdict
//! refs/gitiup/quarantine/<slot>/<digest>         one owner's quarantine of one key
//! refs/gitiup/quarantine-lift/<slot>/<digest>    one owner ending one
//! ```
//!
//! Every write here is a CAS write, and every read re-checks canonical bytes and
//! signatures: a store that lies about bytes is caught at the digest, not assumed away.
//! A record filed under the wrong ref is caught too (`same_ref`), because "the store
//! said so" is not an argument this crate is allowed to make.
//!
//! # Finding work: [`open_rounds`] and nothing else
//!
//! A volunteer polls. It does not know the changes this store holds, so it needs the
//! inverse of the round record — "what wants doing" rather than "who was picked for
//! this" — and the cheap answer is one prefix: `refs/gitiup/job`. Listing
//! `refs/gitiup/**` at a stranger would show it every roster epoch, every revocation and
//! every submission slot as if they were branches to browse, which is both a privacy
//! leak (those refs name keys) and a poll that gets slower as the store fills. So the
//! advertisement ref is the only thing a poll lists, paged from [`Cursor::START`], and
//! the listing costs one ref query plus one blob per row it actually returned.
//!
//! # A lease is advice, not a lock
//!
//! [`claim_lease`] puts `{holder, acquired_at, ttl, attempt}` at
//! `refs/gitiup/lease/<change>/<job>/<slot>` so two volunteers do not burn two machines
//! on one seat. It is *advisory*, and the difference between advice and a lock is one
//! rule: **admission never consults a lease.** [`crate::gate::admit`] asks whether the signing
//! key holds a seat in a round it is really answering for, and has no idea and no
//! interest in who leased what. So the volunteer whose lease expired, or was stolen by
//! somebody impatient, still has its vote: a slow holder that finishes first still
//! counts, and a holder that died mid-job costs the round a TTL of latency instead of an
//! hour of a blacked-out seat. Turning a lease into permission would put the store in the
//! path of every submission and buy nothing that the seat does not already do.
//!
//! # A sealed round asks for two writes, in this order
//!
//! `reveal_mode = "sealed"` ([giti-zp1.6](../../../README.md), [`crate::commit`]) splits a
//! submission into a commitment and a reveal, in two refs so the store's CAS enforces the
//! order:
//!
//! ```text
//! refs/gitiup/commit/<change>/<job>/<slot>   ← Expect::Absent, one per seat, signed by it
//! refs/gitiup/reveal/<change>/<job>/<slot>   ← Expect::Absent, the bytes it promised
//! ```
//!
//! [`publish_commitment`] and then [`publish_attestation`] is the whole protocol, and
//! [`tally`] reads both back. One thing the store deliberately does *not* do: refuse a
//! reveal whose hash does not match its commitment. That mismatch is the evidence of the
//! behaviour sealing exists to catch, and refusing the write would replace a named
//! rejection in a signed verdict with a silent `missing` seat — so the bytes go in, and
//! the verdict names them ([`crate::commit`] carries the argument).

use std::collections::BTreeSet;

use gitiup_attest::{AttestationDoc, Digest, Signer, TimeUs};
use gitiup_host::{
    Actor, Expect, Host, HostErrorKind, Namespace, Oid, RefDeletion, RefName, RefQuery, RefUpdate,
};

use crate::commit::{Commitment, Filed};
use crate::error::{Error, Result};
use crate::job::{
    Advertisement, JobAddress, Lease, LeaseRequest, Taken, record_steal, short_slot, ttl_text,
};
use crate::quarantine::{Ledger, Quarantine, QuarantineLift};
use crate::record::{Record, short_key};
use crate::roster::{Revocation, Roster, SignUp, Withdrawal};
use crate::round::Round;
use crate::select::Seat;
use crate::verdict::{Evaluation, VerdictRecord};

/// Blob namespaces used by the quorum. `roster`, `job`, `policy` and `attestation`
/// already exist in the host crate; the rest are the new ones ADR-0002 D10 says the
/// ticket that first writes them adds.
pub mod ns {
    use gitiup_host::Namespace;

    /// Roster epochs.
    pub const ROSTER: Namespace = Namespace::ROSTER;
    /// Round records (inputs, seed, seats).
    pub const ROUND: Namespace = Namespace::const_new("round");
    /// Sign-up records from `gitiup participant register`.
    pub const SIGNUP: Namespace = Namespace::const_new("signup");
    /// Signed withdrawals.
    pub const WITHDRAWAL: Namespace = Namespace::const_new("withdrawal");
    /// Revocation records.
    pub const REVOCATION: Namespace = Namespace::const_new("revocation");
    /// Endorsements (advice with a signature on it — never a selection input).
    pub const ENDORSEMENT: Namespace = Namespace::const_new("endorsement");
    /// Quarantine records (giti-zp1.8): an owner keeping a key out of the pool for N
    /// epochs. One ref per record, so a quarantine is a trail and never an edit.
    pub const QUARANTINE: Namespace = Namespace::const_new("quarantine");
    /// Records ending a quarantine early (giti-zp1.8).
    pub const QUARANTINE_LIFT: Namespace = Namespace::const_new("quarantine-lift");
    /// Per-key submission slots: one attestation per seat, claimed CAS. In a sealed
    /// round this is phase 2 — the bytes the seat promised in [`COMMIT`].
    pub const REVEAL: Namespace = Namespace::const_new("reveal");
    /// Phase-1 commitments of a sealed round (giti-zp1.6): one hash per seat, written
    /// before the attestation it commits to.
    pub const COMMIT: Namespace = Namespace::const_new("commit");
    /// Job advertisements and lease records (giti-zp1.1); ADR-0002 D10 calls the
    /// namespace `job`, singular, and both record kinds travel under it.
    pub const JOB: Namespace = Namespace::JOB;
    /// Run attestations, signed by the verifier.
    pub const ATTESTATION: Namespace = Namespace::ATTESTATION;
    /// Verdicts and policy documents (the host documents this namespace that way).
    pub const VERDICT: Namespace = Namespace::POLICY;
}

/// `refs/gitiup/roster` — the epoch a fresh round should pin.
pub fn roster_ref() -> RefName {
    // `refs/gitiup/roster` is a fixed, valid name.
    RefName::gitiup("roster").expect("fixed ref name")
}

/// `refs/gitiup/roster/<epoch:08x>` — the epoch a round pinned.
pub fn roster_epoch_ref(epoch: u64) -> Result<RefName> {
    gitiup_ref(&format!("roster/{epoch:08x}"), "roster epoch ref")
}

/// `refs/gitiup/signup/<slot>`.
pub fn signup_ref(slot: &str) -> Result<RefName> {
    gitiup_ref(&format!("signup/{slot}"), "sign-up ref")
}

/// `refs/gitiup/withdrawal/<slot>`.
pub fn withdrawal_ref(slot: &str) -> Result<RefName> {
    gitiup_ref(&format!("withdrawal/{slot}"), "withdrawal ref")
}

/// `refs/gitiup/revocation/<slot>` — one ref per key, moved with `Expect::Is`.
pub fn revocation_ref(slot: &str) -> Result<RefName> {
    gitiup_ref(&format!("revocation/{slot}"), "revocation ref")
}

/// `refs/gitiup/round/<change>/<job>/<attempt>`.
pub fn round_ref(change: &str, job: &str, attempt: u64) -> Result<RefName> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    gitiup_ref(
        &format!("round/{}/{}", escape(change), escape(job)),
        "round ref",
    )
    .and_then(|name| name.join(&attempt.to_string()).map_err(host_error))
}

/// `refs/gitiup/reveal/<change>/<job>/<slot>` — one verifier's slot.
pub fn reveal_ref(change: &str, job: &str, slot: &str) -> Result<RefName> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    gitiup_ref(
        &format!("reveal/{}/{}", escape(change), escape(job)),
        "reveal ref",
    )
    .and_then(|name| name.join(slot).map_err(host_error))
}

/// `refs/gitiup/commit/<change>/<job>/<slot>` — one seat's phase-1 commitment.
///
/// Named by the same hex slot as the seat's lease and its reveal, because "did seat 3
/// promise something" has to be answerable by whoever is about to tally seat 3, and the
/// slot is the only stable public name a seat has.
pub fn commit_ref(change: &str, job: &str, slot: &str) -> Result<RefName> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    crate::job::check_slot(slot)?;
    gitiup_ref(
        &format!("commit/{}/{}", escape(change), escape(job)),
        "commitment ref",
    )
    .and_then(|name| name.join(slot).map_err(host_error))
}

/// `refs/gitiup/commit/<change>/<job>` — every commitment one job has out.
pub fn commit_prefix(change: &str, job: &str) -> Result<String> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    Ok(format!(
        "refs/gitiup/commit/{}/{}",
        escape(change),
        escape(job)
    ))
}

/// `refs/gitiup/verdict/<change>` — the directory every verdict for one change lives
/// under, relative to `refs/gitiup/`.
///
/// The merge gate (giti-91m.4) needs this and cannot be handed the job ids: a change
/// record's `workflow.jobs` is a hint about what to re-run, not the list of rounds
/// somebody actually opened, so "what does the store say about this change" has to be
/// asked of the store — listing this prefix — rather than derived from the change. A
/// reader that derived it would silently pass a change whose verdict is filed under a
/// job the record never mentioned.
pub fn verdict_dir(change: &str) -> Result<String> {
    check_segment(change, "change id")?;
    Ok(format!("verdict/{}", escape(change)))
}

/// `refs/gitiup/verdict/<change>/<job>`.
pub fn verdict_ref(change: &str, job: &str) -> Result<RefName> {
    check_segment(job, "job id")?;
    gitiup_ref(
        &format!("{}/{}", verdict_dir(change)?, escape(job)),
        "verdict ref",
    )
}

/// `refs/gitiup/job/<change>/<job>` — one job's advertisement.
///
/// One ref per `(change, job)` and *not* one per attempt, the way `refs/gitiup/roster`
/// is one ref per roster: an escalation moves it forward with [`Expect::Is`], so the
/// listing has one row per job somebody could still do rather than one row per round
/// somebody gave up on.
pub fn job_ref(change: &str, job: &str) -> Result<RefName> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    gitiup_ref(
        &format!("job/{}/{}", escape(change), escape(job)),
        "job advertisement ref",
    )
}

/// `refs/gitiup/lease/<change>/<job>/<slot>` — one seat's lease.
///
/// Keyed by the seat's slot, the same name its submission uses, because "who is doing
/// seat 3" has to be findable by the person about to *not* do seat 3, and the only
/// stable name for a seat is the slot its round derived.
pub fn lease_ref(change: &str, job: &str, slot: &str) -> Result<RefName> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    crate::job::check_slot(slot)?;
    gitiup_ref(
        &format!("lease/{}/{}", escape(change), escape(job)),
        "lease ref",
    )
    .and_then(|name| name.join(slot).map_err(host_error))
}

/// `refs/gitiup/lease/<change>/<job>` — every lease one job has out.
pub fn lease_prefix(change: &str, job: &str) -> Result<String> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    Ok(format!(
        "refs/gitiup/lease/{}/{}",
        escape(change),
        escape(job)
    ))
}

fn gitiup_ref(rel: &str, what: &'static str) -> Result<RefName> {
    RefName::gitiup(rel).map_err(|e| {
        Error::store(what, &e).with_hint(format!(
            "{what} could not be built from these ids; a ref may not contain ':' or whitespace, \
             which is why key ids are addressed by their hex slot"
        ))
    })
}

fn host_error(error: gitiup_host::HostError) -> Error {
    Error::store("ref name", &error)
}

/// A digest used as a ref component: 64 lower-case hex, the same shape rule a seat slot
/// follows, because both are hashes wearing a pathname.
fn require_hex(text: &str, what: &'static str) -> Result<()> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::invalid(
            "store",
            format!("{what} '{text}' is not 64 lower-case hex characters"),
        )
        .with_hint("a record's ref carries the hex of its own digest, never the `sha256:` form"));
    }
    Ok(())
}

/// A change or job id must survive the journey into a ref name.
pub(crate) fn check_segment(value: &str, what: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid(
            "store",
            format!("{what} is empty, and an empty path component is not a ref"),
        ));
    }
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::invalid(
                "store",
                format!("{what} '{value}' has an empty or dot path component"),
            )
            .with_hint(
                "ids become ref components; use [A-Za-z0-9._-] and '/' between components",
            ));
        }
    }
    Ok(())
}

/// Percent-encode the characters a ref cannot carry (`:` in a job id, say), so a
/// legitimate id never fails to be stored for a spelling reason.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'/' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02x}")),
        }
    }
    out
}

/// Publish a roster epoch: the blob, then its epoch ref, then a *move* of the
/// `refs/gitiup/roster` pointer.
///
/// The order matters. If the epoch ref is written and the pointer move fails, the
/// epoch exists and is auditable but not current; if the pointer moved first, a reader
/// could see an epoch whose bytes are not there. The epoch ref is `Expect::Absent`, so
/// re-publishing the same epoch is a no-op and *changing* one is a conflict — epochs are
/// append-only, which is what makes "the roster is a list the owner can rewrite" false.
pub fn publish_roster(host: &dyn Host, roster: &Roster) -> Result<Oid> {
    let bytes = roster.canonical_bytes()?;
    let oid = host
        .put_cas(&ns::ROSTER, &bytes)
        .map_err(|e| Error::store("put roster blob", &e))?;
    let epoch_ref = roster_epoch_ref(roster.epoch)?;
    let written = host.update_ref_cas(
        &RefUpdate::create(epoch_ref.clone(), oid)
            .with_actor(actor("roster"))
            .with_message(format!("roster epoch {}", roster.epoch)),
    );
    if let Err(error) = written {
        // Already published by this or another owner key: the epoch is content
        // addressed, so "same epoch twice" is only a conflict if the bytes differ,
        // and the pointer move below is what actually arbitrates.
        if error.kind() != HostErrorKind::Conflict {
            return Err(Error::store("publish roster epoch", &error));
        }
    }
    let current = host
        .get_ref(&roster_ref())
        .map_err(|e| Error::store("read roster pointer", &e))?;
    let update = match current {
        Some(existing) if existing.oid == oid => return Ok(oid),
        Some(existing) => RefUpdate::new(roster_ref(), Expect::Is(existing.oid), oid),
        None => RefUpdate::new(roster_ref(), Expect::Absent, oid),
    };
    host.update_ref_cas(&update.with_actor(actor("roster")))
        .map_err(|e| {
            Error::store("move roster pointer", &e).with_hint(
                "the pointer only moves forward to a higher, signed epoch; re-read \
                 refs/gitiup/roster and re-sign from there",
            )
        })?;
    Ok(oid)
}

/// Fetch the roster at a specific epoch (the round pin's counterpart).
pub fn roster_at(host: &dyn Host, epoch: u64) -> Result<Option<Roster>> {
    let name = roster_epoch_ref(epoch)?;
    read_record::<Roster>(host, &name, "roster").map(|found| found.map(|(_, record)| record))
}

/// Fetch the roster the store currently points at.
pub fn current_roster(host: &dyn Host) -> Result<Option<Roster>> {
    read_record::<Roster>(host, &roster_ref(), "roster")
        .map(|found| found.map(|(_, record)| record))
}

/// Publish a sign-up record. One ref per key slot: registering twice is idempotent,
/// and *changing* your registration is a new sign-up you must withdraw the old one for.
pub fn publish_signup(host: &dyn Host, signup: &SignUp) -> Result<Oid> {
    signup.validate()?;
    put_record(
        host,
        &ns::SIGNUP,
        &signup_ref(&signup.slot())?,
        &signup.canonical_bytes()?,
        "sign-up",
    )
}

/// Every pending sign-up the store holds, for the owner's queue.
pub fn list_signups(host: &dyn Host) -> Result<Vec<SignUp>> {
    let mut out = Vec::new();
    for entry in host
        .list(&ns::SIGNUP)
        .map_err(|e| Error::store("list sign-ups", &e))?
    {
        if let Some(bytes) = host
            .get(&entry.oid)
            .map_err(|e| Error::store("get sign-up", &e))?
        {
            out.push(SignUp::from_canonical_bytes(&bytes)?);
        }
    }
    Ok(out)
}

/// Publish a signed withdrawal.
pub fn publish_withdrawal(host: &dyn Host, withdrawal: &Withdrawal) -> Result<Oid> {
    withdrawal.verify()?;
    put_record(
        host,
        &ns::WITHDRAWAL,
        &withdrawal_ref(&withdrawal.slot())?,
        &withdrawal.canonical_bytes()?,
        "withdrawal",
    )
}

/// Every withdrawal the store holds, for the owner composing the next epoch.
///
/// Each one is re-verified on the way in: a withdrawal is a *claim by a key*, and an
/// owner who applied an unsigned one would be removing participants at the store's
/// say-so rather than the key's.
pub fn list_withdrawals(host: &dyn Host) -> Result<Vec<Withdrawal>> {
    let mut out = Vec::new();
    for entry in host
        .list(&ns::WITHDRAWAL)
        .map_err(|e| Error::store("list withdrawals", &e))?
    {
        if let Some(bytes) = host
            .get(&entry.oid)
            .map_err(|e| Error::store("get withdrawal", &e))?
        {
            out.push(Withdrawal::from_canonical_bytes(&bytes)?);
        }
    }
    Ok(out)
}

/// Publish a revocation. One ref per key: a later revocation moves it with
/// `Expect::Is`, so a key's history is a chain and not a pile.
pub fn publish_revocation(host: &dyn Host, revocation: &Revocation) -> Result<Oid> {
    let bytes = revocation.canonical_bytes()?;
    let oid = host
        .put_cas(&ns::REVOCATION, &bytes)
        .map_err(|e| Error::store("put revocation", &e))?;
    let name = revocation_ref(&revocation.slot())?;
    let current = host
        .get_ref(&name)
        .map_err(|e| Error::store("read revocation ref", &e))?;
    let update = match current {
        Some(existing) => RefUpdate::new(name, Expect::Is(existing.oid), oid),
        None => RefUpdate::new(name, Expect::Absent, oid),
    };
    host.update_ref_cas(&update.with_actor(actor("revocation")))
        .map_err(|e| Error::store("publish revocation", &e))?;
    Ok(oid)
}

/// Every revocation record in the store (a verifier's local view of "who is dead").
pub fn list_revocations(
    host: &dyn Host,
    owner_trust: &gitiup_attest::Trust,
) -> Result<Vec<Revocation>> {
    let mut out = Vec::new();
    for entry in host
        .list(&ns::REVOCATION)
        .map_err(|e| Error::store("list revocations", &e))?
    {
        if let Some(bytes) = host
            .get(&entry.oid)
            .map_err(|e| Error::store("get revocation", &e))?
        {
            out.push(Revocation::from_canonical_bytes(&bytes, owner_trust)?);
        }
    }
    Ok(out)
}

/// `refs/gitiup/quarantine/<slot>/<digest>` — one quarantine record, addressed by its own
/// digest.
///
/// One ref per **record** rather than one per key (the way `revocation/` works) because a
/// quarantine is a history and not a status: a second quarantine for the same key adds a
/// record instead of moving a pointer, so a quarantine cannot be laundered by being
/// overwritten and the audit trail an excluded key is entitled to read is actually there.
pub fn quarantine_ref(slot: &str, digest_hex: &str) -> Result<RefName> {
    crate::job::check_slot(slot)?;
    require_hex(digest_hex, "quarantine digest")?;
    gitiup_ref(&format!("quarantine/{slot}/{digest_hex}"), "quarantine ref")
}

/// `refs/gitiup/quarantine/<slot>` — every record one key has against it.
pub fn quarantine_prefix(slot: &str) -> Result<String> {
    crate::job::check_slot(slot)?;
    Ok(format!("refs/gitiup/quarantine/{slot}"))
}

/// `refs/gitiup/quarantine-lift/<slot>/<digest>` — one lift record.
pub fn lift_ref(slot: &str, digest_hex: &str) -> Result<RefName> {
    crate::job::check_slot(slot)?;
    require_hex(digest_hex, "quarantine lift digest")?;
    gitiup_ref(
        &format!("quarantine-lift/{slot}/{digest_hex}"),
        "quarantine lift ref",
    )
}

/// Publish a signed quarantine: CAS-create its own ref, idempotent on a retry.
///
/// The record's signatures are checked here (crypto, not trust): a store is not a trust
/// root and must not be able to accept a forged quarantine, and a later reader must never
/// have to wonder whether the store invented one. *Who is trusted as an owner* is the
/// reader's decision and belongs to [`quarantine_exclusions`].
pub fn publish_quarantine(host: &dyn Host, quarantine: &Quarantine) -> Result<Oid> {
    quarantine.verify_signatures()?;
    let bytes = quarantine.canonical_bytes()?;
    let digest = quarantine.digest()?;
    put_record(
        host,
        &ns::QUARANTINE,
        &quarantine_ref(&quarantine.slot(), &digest.hex())?,
        &bytes,
        "quarantine",
    )
}

/// Publish a signed lift, naming the quarantine it ends.
pub fn publish_lift(host: &dyn Host, lift: &QuarantineLift) -> Result<Oid> {
    lift.verify_signatures()?;
    let bytes = lift.canonical_bytes()?;
    let digest = lift.digest()?;
    put_record(
        host,
        &ns::QUARANTINE_LIFT,
        &lift_ref(&lift.slot(), &digest.hex())?,
        &bytes,
        "lift",
    )
}

/// Every quarantine record the store holds, each signature re-checked.
///
/// No trust list, for the reason [`Quarantine::verify_signatures`] gives: the trail is
/// public, and a key that has been quarantined is entitled to read why.
pub fn list_quarantines(host: &dyn Host) -> Result<Vec<Quarantine>> {
    let mut out = Vec::new();
    for reference in host
        .list_refs(&RefQuery::prefix("refs/gitiup/quarantine/"))
        .map_err(|e| Error::store("list quarantines", &e))?
    {
        let name = reference.name.as_str();
        // `refs/gitiup/quarantine-lift/**` shares the ref root; it is a different record
        // class and must not be parsed as one.
        if name.starts_with("refs/gitiup/quarantine-lift/") {
            continue;
        }
        if let Some(bytes) = host
            .get(&reference.oid)
            .map_err(|e| Error::store("get quarantine", &e))?
        {
            let record = Quarantine::from_canonical_bytes(&bytes)?;
            record.verify_signatures()?;
            out.push(record);
        }
    }
    Ok(out)
}

/// Every lift record the store holds, signature-checked.
pub fn list_lifts(host: &dyn Host) -> Result<Vec<QuarantineLift>> {
    let mut out = Vec::new();
    for reference in host
        .list_refs(&RefQuery::prefix("refs/gitiup/quarantine-lift/"))
        .map_err(|e| Error::store("list quarantine lifts", &e))?
    {
        if let Some(bytes) = host
            .get(&reference.oid)
            .map_err(|e| Error::store("get quarantine lift", &e))?
        {
            let record = QuarantineLift::from_canonical_bytes(&bytes)?;
            record.verify_signatures()?;
            out.push(record);
        }
    }
    Ok(out)
}

/// Everything the store has ever said about who is kept out.
pub fn quarantine_ledger(host: &dyn Host) -> Result<Ledger> {
    Ledger::new(list_quarantines(host)?, list_lifts(host)?)
}

/// What the store's quarantines do to a selection at roster epoch `epoch`.
#[derive(Debug, Clone)]
pub struct Applied {
    /// Names to hand [`RoundInputs::excluding`](crate::select::RoundInputs::excluding) —
    /// the record's own key id, which `excluding` closes over the identity family.
    pub named: BTreeSet<String>,
    /// Each record believed at this epoch, with the digest it is cited by.
    pub believed: Vec<(Quarantine, Digest)>,
    /// Each record **not** applied, with the sentence saying why (not trusted by this
    /// caller; lifted; expired). Never dropped quietly: a quarantine that silently stopped
    /// applying is a quarantine nobody can audit.
    pub ignored: Vec<(Quarantine, String)>,
}

impl Applied {
    /// Whether any of it changes the pool.
    pub fn empty(&self) -> bool {
        self.believed.is_empty()
    }
}

/// The store's quarantines, filtered by what *this* caller trusts and by their own clocks.
///
/// A quarantine is only a selection input when a key the caller trusts as an owner signed
/// it — exactly the rule a verdict follows, and for the same reason: "the store holds a
/// signed thing" is not an argument. Records that fail that test are reported in
/// [`Applied::ignored`] rather than skipped, because the difference between "ignored
/// because untrusted" and "does not exist" is the difference between a store bug and a
/// store lying.
pub fn quarantine_exclusions(
    host: &dyn Host,
    owner_trust: &gitiup_attest::Trust,
    epoch: u64,
    now: gitiup_attest::TimeUs,
) -> Result<Applied> {
    let ledger = quarantine_ledger(host)?;
    let mut applied = Applied {
        named: BTreeSet::new(),
        believed: Vec::new(),
        ignored: Vec::new(),
    };
    for filed in &ledger.quarantines {
        let record = &filed.quarantine;
        if record.verify(owner_trust).is_err() {
            applied.ignored.push((
                record.clone(),
                "no signature on it is from a key this machine trusts as an owner \
                 (--owner); it is public and it is not applied"
                    .to_string(),
            ));
            continue;
        }
        if let Some(lift) = ledger.lift_of(filed, epoch) {
            applied.ignored.push((
                record.clone(),
                format!(
                    "lifted by {} from epoch {}",
                    short_key(&lift.issuer),
                    lift.effective_epoch
                ),
            ));
            continue;
        }
        if !record.covers_epoch(epoch) {
            applied.ignored.push((
                record.clone(),
                if epoch < record.start_epoch {
                    format!(
                        "starts at epoch {}, which this round does not pin yet",
                        record.start_epoch
                    )
                } else {
                    format!("ran out at epoch {}", record.ends_epoch())
                },
            ));
            continue;
        }
        if !record.clock_live(now) {
            applied.ignored.push((
                record.clone(),
                format!(
                    "its clock bound {} passed while the roster sat on epoch {epoch}",
                    TimeUs(record.expires_at_us.unwrap_or(0)).to_rfc3339()
                ),
            ));
            continue;
        }
        applied.named.insert(record.key_id.clone());
        applied
            .believed
            .push((record.clone(), filed.digest.clone()));
    }
    Ok(applied)
}

/// Publish a round record. Re-publishing the same round is idempotent; publishing a
/// *different* round for the same change/job/attempt is a conflict, because that would
/// be two different quorums for one change, which is the thing the seed exists to make
/// impossible.
///
/// Publishing is not advertising: a round nobody advertises is invisible to the
/// volunteers [`advertise_round`] exists for.
pub fn publish_round(host: &dyn Host, round: &Round) -> Result<Oid> {
    let name = round_ref(
        &round.inputs.change_id,
        &round.inputs.job_id,
        round.inputs.attempt,
    )?;
    put_record(host, &ns::ROUND, &name, &round.canonical_bytes()?, "round")
}

/// `refs/gitiup/round/<change>` — every round (job × attempt) the store holds for one
/// change.
///
/// A ref *prefix* rather than a ref, so `gitiup select --change <id>` can find a round
/// without being told the job id, which is what the acceptance criterion's shortest
/// command line needs.
pub fn round_prefix(change: &str) -> Result<String> {
    check_segment(change, "change id")?;
    Ok(format!("refs/gitiup/round/{}", escape(change)))
}

/// Every round published for one change, ordered by `(job, attempt)`.
///
/// Whole records, not ref names: a round is only meaningful against the roster epoch it
/// pinned, so a caller that listed rounds is going to fetch them anyway. A blob that
/// does not parse is an error and not a skipped row — a store that holds a corrupt round
/// is a store bug, and quietly ignoring it would make "this change has no quorum" a lie.
pub fn rounds_for(host: &dyn Host, change: &str) -> Result<Vec<Round>> {
    let prefix = round_prefix(change)?;
    let mut out = Vec::new();
    for reference in host
        .list_refs(&RefQuery::prefix(&prefix))
        .map_err(|e| Error::store("list rounds", &e))?
    {
        if let Some(bytes) = host
            .get(&reference.oid)
            .map_err(|e| Error::store("fetch round", &e))?
        {
            out.push(Round::from_canonical_bytes(&bytes)?);
        }
    }
    out.sort_by(|a, b| {
        a.inputs
            .job_id
            .cmp(&b.inputs.job_id)
            .then(a.inputs.attempt.cmp(&b.inputs.attempt))
    });
    Ok(out)
}

/// Every round the store holds, up to `limit` blobs fetched.
///
/// This is the one listing that has to be bounded by a cap rather than by a key: a store
/// with ten thousand rounds cannot be summarised by fetching ten thousand records, and a
/// command that tried would look like a hung one. `limit` is the caller's budget and
/// [`Scan::truncated`] is the honest remainder — a `history` report that scanned part of
/// the store says so instead of implying it read everything.
pub fn scan_rounds(host: &dyn Host, limit: usize) -> Result<Scan> {
    let refs = host
        .list_refs(&RefQuery::prefix("refs/gitiup/round/"))
        .map_err(|e| Error::store("list rounds", &e))?;
    let seen = refs.len();
    let fetched = limit.min(seen);
    let mut rounds = Vec::new();
    for reference in refs.into_iter().take(fetched) {
        if let Some(bytes) = host
            .get(&reference.oid)
            .map_err(|e| Error::store("fetch round", &e))?
        {
            rounds.push(Round::from_canonical_bytes(&bytes)?);
        }
    }
    rounds.sort_by(|a, b| {
        a.inputs
            .change_id
            .cmp(&b.inputs.change_id)
            .then(a.inputs.job_id.cmp(&b.inputs.job_id))
            .then(a.inputs.attempt.cmp(&b.inputs.attempt))
    });
    Ok(Scan {
        rounds,
        seen,
        fetched,
        truncated: fetched < seen,
    })
}

/// What [`scan_rounds`] read: the records, how many refs exist, and how many were fetched.
#[derive(Debug, Clone)]
pub struct Scan {
    /// The rounds, ordered by `(change, job, attempt)`.
    pub rounds: Vec<Round>,
    /// Round refs the store named, whether or not they were fetched.
    pub seen: usize,
    /// How many records were fetched — less than `seen` exactly when it was truncated.
    pub fetched: usize,
    /// Whether the scan stopped early.
    pub truncated: bool,
}

/// Fetch the round for one change/job/attempt.
pub fn round_at(host: &dyn Host, change: &str, job: &str, attempt: u64) -> Result<Option<Round>> {
    let name = round_ref(change, job, attempt)?;
    read_record::<Round>(host, &name, "round").map(|found| found.map(|(_, record)| record))
}

/// A verifier publishes its attestation into **its own slot**, with `Expect::Absent`.
///
/// That single CAS write is the anti-abuse control giti-msi.9 would otherwise have to
/// implement in application code: one submission per key per round, guaranteed by the
/// store, un-raceable, and it is exactly the slot D10 reserves for commit-reveal — so
/// giti-msi.6 splits this ref into a commitment and a reveal without moving anything.
///
/// The seat is not transferable. The document must be signed by exactly the key that
/// holds it, which is checked here rather than assumed: a store that let key A publish
/// key B's signature into A's slot would be a vote-laundering service, and the roster
/// check downstream could never see the difference.
pub fn publish_submission(
    host: &dyn Host,
    round: &Round,
    key_id: &str,
    attestation: &AttestationDoc,
) -> Result<Oid> {
    let seat = round.seat(key_id).ok_or_else(|| {
        Error::policy(
            "store",
            format!(
                "{} holds no seat in this round, so it has no slot to write to",
                short_key(key_id)
            ),
        )
    })?;
    match attestation.signatures.len() {
        1 if attestation.signatures[0].key_id == key_id => {}
        1 => {
            return Err(Error::signature(
                "store",
                format!(
                    "this attestation is signed by {}, not by the seat key {} it is being \
                     published for; a slot holds its owner's own claim and nothing else",
                    short_key(&attestation.signatures[0].key_id),
                    short_key(key_id)
                ),
            ));
        }
        n => {
            return Err(Error::policy(
                "store",
                format!(
                    "a submission slot holds exactly one verifier's signature; this document \
                     carries {n}",
                ),
            ));
        }
    }
    // A sealed round's reveal must have a commitment in front of it: phase 1 is not
    // optional, and an answer with nothing promised behind it is not independent
    // evidence. What this does *not* do is compare hashes — see the module docs: a reveal
    // that fails to open its commitment is published, because the mismatch is the evidence
    // and the verdict is what names it.
    if round.is_sealed() {
        commitment_at(host, round, key_id)?.ok_or_else(|| {
            Error::policy(
                "commitment",
                format!(
                    "{} is a seat in a sealed round and has committed to nothing, so its \
                     reveal is refused: commit first, at {} (the promise is what makes a \
                     reveal mean something)",
                    short_key(key_id),
                    commit_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot,)
                        .map(|name| name.as_str().to_string())
                        .unwrap_or_else(|_| "refs/gitiup/commit/…".to_string())
                ),
            )
            .with_hint(
                "gitiup work does both phases; a hand-driven verifier publishes \
                 Commitment::for_document first and the attestation second",
            )
        })?;
    }
    let bytes = attestation.canonical_bytes()?;
    let oid = host
        .put_cas(&ns::ATTESTATION, &bytes)
        .map_err(|e| Error::store("put attestation", &e))?;
    let name = reveal_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot)?;
    host.update_ref_cas(&RefUpdate::create(name, oid).with_actor(actor("verifier")))
        .map_err(|e| {
            Error::store("claim submission slot", &e).with_hint(format!(
                "{} already has a submission in this round; one identity casts one vote, so a \
             second submission is refused rather than counted twice",
                short_key(key_id)
            ))
        })?;
    Ok(oid)
}

/// Publish a seat's phase-1 commitment: `refs/gitiup/commit/<change>/<job>/<slot>`,
/// claimed `Expect::Absent`, one per seat per round.
///
/// The seal is what makes a reveal mean something, so the checks are the seal's:
///
/// * the commitment must be signed by the key that holds the seat (a promise made in
///   somebody else's slot is a forgery, not a courtesy);
/// * it must speak about *this* round — same change, job, attempt, slot, challenge and
///   round digest — because a commitment left over from an earlier attempt opens nothing
///   here;
/// * the slot is taken once: a seat that wants to change its promise does not get to,
///   which is the entire point of committing before revealing.
pub fn publish_commitment(host: &dyn Host, round: &Round, commitment: &Commitment) -> Result<Oid> {
    commitment.verify()?;
    commitment.matches(round, &commitment.key_id)?;
    let bytes = commitment.canonical_bytes()?;
    let name = commit_ref(
        &round.inputs.change_id,
        &round.inputs.job_id,
        &commitment.slot,
    )?;
    put_record(host, &ns::COMMIT, &name, &bytes, "commitment")
}

/// The commitment filed in one seat's slot, if it has one.
///
/// Checked on the way in — its own signature, and that it is about this round and this
/// seat — so a caller can use the answer as a gate. A slot holding a commitment that
/// does not describe the round is an error, not an absence: "nothing was promised" and
/// "something was promised about a different round" are different accusations.
pub fn commitment_at(host: &dyn Host, round: &Round, key_id: &str) -> Result<Option<Commitment>> {
    let seat = round.seat(key_id).ok_or_else(|| {
        Error::policy(
            "commitment",
            format!(
                "{} holds no seat in this round, so it has no slot to commit in",
                short_key(key_id)
            ),
        )
    })?;
    let name = commit_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot)?;
    let Some((_, commitment)) = read_record::<Commitment>(host, &name, "commitment")? else {
        return Ok(None);
    };
    commitment.verify()?;
    same_ref(
        &name,
        &commit_ref(&commitment.change_id, &commitment.job_id, &commitment.slot)?,
        "commitment",
    )?;
    commitment.matches(round, key_id)?;
    Ok(Some(commitment))
}

/// What every seat filed in phase 1, in seat order, missing seats simply absent.
///
/// This is the tally's input, and it deliberately does not drop what it cannot use: a
/// commitment whose own signature is bad, or whose fields describe another round, comes
/// back in a [`Filed`] and is refused by name in the verdict. A reader that filtered
/// those out would be reporting "nothing was committed" about a seat that committed to
/// something embarrassing.
pub fn commitments(host: &dyn Host, round: &Round) -> Result<Vec<Filed>> {
    let mut out = Vec::new();
    for seat in &round.selected {
        let name = commit_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot)?;
        if let Some((_, commitment)) = read_record::<Commitment>(host, &name, "commitment")? {
            // A bad self-signature *is* fatal here: an unsigned promise is not evidence
            // about this seat at all, and a tally that counted one would be believing the
            // store about who promised what.
            commitment.verify()?;
            out.push(Filed {
                seat: seat.key_id.clone(),
                commitment,
            });
        }
    }
    Ok(out)
}

/// The verdict a round's own evidence supports, with the **flow chosen by the round**.
///
/// The point of this function is that a caller never chooses between the open and the
/// sealed tally: `round.reveal_mode` chooses, and a tool that works for one works for the
/// other without a flag. An open round's tally reads the submissions; a sealed round's
/// reads the submissions *and* every seat's commitment, because a reveal that was never
/// committed to is refused and that refusal has to be written down somewhere.
pub fn tally(
    host: &dyn Host,
    round: &Round,
    roster: &Roster,
    revocations: &[Revocation],
    evaluation: &Evaluation,
) -> Result<VerdictRecord> {
    let attestations = submissions(host, round)?;
    if round.is_sealed() {
        let filed = commitments(host, round)?;
        return VerdictRecord::evaluate_sealed(
            round,
            roster,
            &attestations,
            &filed,
            revocations,
            evaluation,
        );
    }
    VerdictRecord::evaluate(round, roster, &attestations, revocations, evaluation)
}

/// The roster-aware submission: refuse first, write second.
///
/// This is the entry point a store frontend calls, and the difference from
/// [`publish_submission`] is everything the slot write cannot see on its own — that the
/// signing key is in the approved roster for the epoch the round pinned, that its
/// approval has not lapsed, that a revocation has not voided it, and that the document
/// is this round's work and not a replay. Each refusal is [`crate::gate::admit`]'s, with its own
/// code, so a volunteer gets an answer it can act on instead of a rejected write.
///
/// `roster` must be the epoch the round pins (a round is only auditable against the
/// roster it selected from), and it is assumed to have been signature-checked by the
/// caller — [`Roster::verify`] at fetch time, which is where a trust root belongs.
pub fn publish_attestation(
    host: &dyn Host,
    round: &Round,
    roster: &Roster,
    attestation: &AttestationDoc,
    revocations: &[crate::roster::Revocation],
    now: gitiup_attest::TimeUs,
) -> Result<Oid> {
    let key_id =
        crate::gate::admit(roster, round, attestation, revocations, now).map_err(|refusal| {
            Error::policy("store", format!("{}: {}", refusal.code, refusal.detail)).with_hint(
                "the roster is the owner's approval; `gitiup participant list` shows \
                        who is on it and `gitiup participant verify-roster` says why an entry \
                        is not eligible",
            )
        })?;
    publish_submission(host, round, &key_id, attestation)
}

/// Collect what the selected verifiers published, in seat order.
///
/// A missing slot is not an error: it is a silent verifier, which the verdict records as
/// `missing` and counts as nobody-voted. Absence and refusal are different sentences, and
/// the verdict prints both.
pub fn submissions(host: &dyn Host, round: &Round) -> Result<Vec<AttestationDoc>> {
    let mut out = Vec::with_capacity(round.selected.len());
    for seat in &round.selected {
        let name = reveal_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot)?;
        if let Some((_, doc)) = read_record::<AttestationDoc>(host, &name, "attestation")? {
            out.push(doc);
        }
    }
    Ok(out)
}

/// Whether a key's slot is still free — step 5 of the fail-closed checklist (D11).
pub fn slot_is_free(host: &dyn Host, round: &Round, key_id: &str) -> Result<bool> {
    let Some(seat) = round.seat(key_id) else {
        return Ok(false);
    };
    let name = reveal_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot)?;
    host.get_ref(&name)
        .map(|found| found.is_none())
        .map_err(|e| Error::store("read submission slot", &e))
}

/// Publish a signed verdict for a change and job.
pub fn publish_verdict(host: &dyn Host, verdict: &VerdictRecord) -> Result<Oid> {
    let name = verdict_ref(&verdict.change_id, &verdict.job_id)?;
    put_record(
        host,
        &ns::VERDICT,
        &name,
        &verdict.canonical_bytes()?,
        "verdict",
    )
}

/// The verdict a change/job currently carries, if any.
///
/// Takes the owner trust because a verdict is a *claim by an owner*: loading it without
/// checking who signed it would be believing the store, and the store is not the trust
/// root.
pub fn verdict_at(
    host: &dyn Host,
    change: &str,
    job: &str,
    owner_trust: &gitiup_attest::Trust,
) -> Result<Option<VerdictRecord>> {
    let name = verdict_ref(change, job)?;
    let Some((_, verdict)) = read_record::<VerdictRecord>(host, &name, "verdict")? else {
        return Ok(None);
    };
    verdict.verify(owner_trust)?;
    Ok(Some(verdict))
}

/// What filing a verdict at `refs/gitiup/verdict/<change>/<job>` did.
///
/// Four outcomes, because there are exactly four things that can be true of a ref that
/// may already hold a signed statement: it is empty, it already says this, it says
/// something an earlier attempt said, or it says something this write has no business
/// changing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filing {
    /// The ref was empty; this verdict is now the record.
    Filed {
        /// Where the record went: the `kv/verdict/<hex>` blob the ref now names.
        oid: Oid,
    },
    /// The same verdict was already filed, so nothing moved. A retry is not an edit,
    /// and saying so is what lets a publish be re-run after a timeout.
    Unchanged {
        /// The oid the ref already pointed at — the same verdict, byte for byte.
        oid: Oid,
    },
    /// A verdict from a *later* attempt replaced one from an earlier attempt — the only
    /// way a filed verdict ever moves.
    Superseded {
        /// The new blob the ref names.
        oid: Oid,
        /// The attempt the replaced verdict spoke about.
        previous_attempt: u64,
    },
    /// The ref holds a verdict this one may not replace, with the sentence saying why.
    Refused {
        /// The verdict that stays on the record (boxed: a record is far bigger than an
        /// oid, and a refusal is the rare case, not the one every filing pays for).
        existing: Box<VerdictRecord>,
        /// Why this write was refused, in the words a human acts on.
        reason: String,
    },
}

impl Filing {
    /// Was the ref left as it was, and why (`None` when it was written or was already
    /// right)?
    pub fn refusal(&self) -> Option<&str> {
        match self {
            Filing::Refused { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// The oid the ref points at now, when the store has one.
    pub fn oid(&self) -> Option<&Oid> {
        match self {
            Filing::Filed { oid } | Filing::Unchanged { oid } | Filing::Superseded { oid, .. } => {
                Some(oid)
            }
            Filing::Refused { .. } => None,
        }
    }

    /// A short token for `--json`: `filed` · `unchanged` · `superseded` · `refused`.
    pub fn token(&self) -> &'static str {
        match self {
            Filing::Filed { .. } => "filed",
            Filing::Unchanged { .. } => "unchanged",
            Filing::Superseded { .. } => "superseded",
            Filing::Refused { .. } => "refused",
        }
    }
}

/// File a signed verdict, under the rule that a verdict is **superseded, never edited**.
///
/// A verdict is the owner's signed statement about one round, and a reviewer who cites
/// it is entitled to the version that was there when they read it. So the ref moves in
/// exactly two ways: nothing→something, and an earlier attempt→a later one (the
/// escalation path, attempt + 1 with a fresh seed). Any other difference at the same
/// attempt is a refusal, and a *good* one: the way to launder a disagreement out of a
/// quorum record would be to re-run the tally after the awkward verifier went home and
/// write the tidy answer over the old one. The evidence, not the tally's convenience,
/// decides what is on the record — which is why the caller reports a refusal instead of
/// silently keeping the stale verdict.
///
/// `owner_trust` is needed because the verdict already there is a *claim*: it is
/// signature-checked before it is compared, so a store that swapped in an unsigned
/// verdict to force a conflict is caught here rather than believed.
pub fn file_verdict(
    host: &dyn Host,
    verdict: &VerdictRecord,
    owner_trust: &gitiup_attest::Trust,
) -> Result<Filing> {
    verdict.validate()?;
    let name = verdict_ref(&verdict.change_id, &verdict.job_id)?;
    let current = host
        .get_ref(&name)
        .map_err(|e| Error::store("read verdict ref", &e))?;
    let Some(current) = current else {
        return Ok(Filing::Filed {
            oid: publish_verdict(host, verdict)?,
        });
    };
    let bytes = host
        .get(&current.oid)
        .map_err(|e| Error::store("fetch verdict", &e))?
        .ok_or_else(|| {
            Error::store(
                "fetch verdict",
                &gitiup_host::HostError::not_found("verdict", current.oid.hex()),
            )
        })?;
    let existing = VerdictRecord::from_canonical_bytes(&bytes, owner_trust)?;
    if verdict.same_answer(&existing) {
        return Ok(Filing::Unchanged { oid: current.oid });
    }
    if verdict.attempt <= existing.attempt {
        let reason = if verdict.attempt == existing.attempt {
            format!(
                "attempt {} already carries a verdict here, and it says '{}' ({}); this tally \
                 says '{}', so filing it would edit a signed record in place. A verdict is \
                 superseded by a later attempt and never rewritten: escalate to attempt {} \
                 (a fresh seed, a fresh round) if the evidence has genuinely moved, and \
                 publish nothing here.",
                existing.attempt,
                existing.state,
                existing.detail,
                verdict.state,
                existing.attempt + 1
            )
        } else {
            format!(
                "this store already carries the verdict of attempt {} for this job, which is a \
                 later attempt than this one ({}). Attempts only move forward: re-evaluating an \
                 older round cannot overwrite what the newer one decided.",
                existing.attempt, verdict.attempt
            )
        };
        return Ok(Filing::Refused {
            existing: Box::new(existing),
            reason,
        });
    }
    let oid = host
        .put_cas(&ns::VERDICT, &verdict.canonical_bytes()?)
        .map_err(|e| Error::store("put verdict", &e))?;
    let update =
        RefUpdate::new(name.clone(), Expect::Is(current.oid), oid).with_actor(actor("verdict"));
    host.update_ref_cas(&update).map_err(|e| {
        Error::store("supersede verdict", &e).with_hint(
            "the ref moved between the read and the write: somebody else filed a verdict in \
             the same instant. Re-read it rather than forcing the write.",
        )
    })?;
    Ok(Filing::Superseded {
        oid,
        previous_attempt: existing.attempt,
    })
}

/// The blob a ref points at, fetched and parsed, with the digest re-checked by the
/// record's own reader.
fn read_record<T: Record>(
    host: &dyn Host,
    name: &RefName,
    what: &'static str,
) -> Result<Option<(Oid, T)>> {
    let reference = host
        .get_ref(name)
        .map_err(|e| Error::store(format!("read {what} ref"), &e))?;
    let Some(reference) = reference else {
        return Ok(None);
    };
    let bytes = host
        .get(&reference.oid)
        .map_err(|e| Error::store(format!("fetch {what}"), &e))?
        .ok_or_else(|| {
            Error::store(
                "fetch record",
                &gitiup_host::HostError::not_found(what, reference.oid.hex()),
            )
            .with_hint(
                "the ref points at a blob the store will not return: this is a store bug \
                        or a partial write, not a missing record",
            )
        })?;
    Ok(Some((reference.oid, T::load(&bytes)?)))
}

/// Write a blob and CAS a ref to it, refusing to overwrite.
fn put_record(
    host: &dyn Host,
    namespace: &Namespace,
    name: &RefName,
    bytes: &[u8],
    what: &'static str,
) -> Result<Oid> {
    let oid = host
        .put_cas(namespace, bytes)
        .map_err(|e| Error::store(format!("put {what}"), &e))?;
    match host.update_ref_cas(&RefUpdate::create(name.clone(), oid).with_actor(actor(what))) {
        Ok(_) => Ok(oid),
        Err(error) => {
            // If the ref already points at these exact bytes, the write already
            // happened: idempotence is what makes a retried publish safe, and a
            // verifier that gave up mid-publish is a normal Tuesday.
            let current = host
                .get_ref(name)
                .map_err(|e| Error::store(format!("read {what} ref"), &e))?;
            match current {
                Some(existing) if existing.oid == oid => Ok(oid),
                _ => Err(
                    Error::store(format!("publish {what}"), &error).with_hint(format!(
                        "a {what} for this slot already exists and is different; refusing to \
                     overwrite it is the point (one slot, one record)"
                    )),
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// paging
// ---------------------------------------------------------------------------

/// `refs/gitiup/job` — the only ref prefix a volunteer polling for work should list.
///
/// Everything else under `refs/gitiup/**` is somebody's roster, revocation or submission
/// slot: not news, and not a stranger's business.
pub const ADVERTISED_PREFIX: &str = "refs/gitiup/job";

/// The default window of a paged listing.
pub const DEFAULT_PAGE: usize = 32;

/// The largest window a listing will fill. A poll is meant to be small; a caller that
/// wants everything pages.
pub const MAX_PAGE: usize = 256;

/// How many times one CAS write is retried against a contested ref before the store
/// gives up and says so out loud.
const MAX_CAS_RETRIES: usize = 4;

/// A position in a paged listing.
///
/// The cursor is an offset into the *ref listing*, not into the rows: a page can come
/// back short (an advertisement that expired is dropped rather than returned dead) and
/// still say there is more. Keep paging until `next` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    offset: usize,
}

impl Cursor {
    /// The beginning.
    pub const START: Cursor = Cursor { offset: 0 };

    /// Where this cursor points in the listing (for a progress line).
    pub fn offset(self) -> usize {
        self.offset
    }

    /// Whether this is the start of the listing.
    pub fn is_start(self) -> bool {
        self.offset == 0
    }

    fn after(self, count: usize) -> Cursor {
        Cursor {
            offset: self.offset.saturating_add(count),
        }
    }
}

/// One window of a listing, and where the next one starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The rows, in ref-name order.
    pub items: Vec<T>,
    /// The next window's position, or `None` when the listing is exhausted.
    pub next: Option<Cursor>,
}

impl<T> Page<T> {
    /// An empty, finished page.
    pub fn empty() -> Page<T> {
        Page {
            items: Vec::new(),
            next: None,
        }
    }

    /// How many rows came back.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this page carried nothing.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn clamp_page(limit: usize) -> usize {
    limit.clamp(1, MAX_PAGE)
}

// ---------------------------------------------------------------------------
// advertisements: the round's inverse index
// ---------------------------------------------------------------------------

/// Publish an advertisement: the blob first, then the ref that names the job.
pub fn advertise(host: &dyn Host, advertisement: &Advertisement) -> Result<Oid> {
    advertisement.validate()?;
    if advertisement.signatures.is_empty() {
        return Err(Error::policy(
            "advertisement",
            "an unsigned advertisement is an invitation nobody authorised; sign it as a \
             selector of the round it advertises",
        ));
    }
    let name = job_ref(&advertisement.change_id, &advertisement.job_id)?;
    let oid = host
        .put_cas(&ns::JOB, &advertisement.canonical_bytes()?)
        .map_err(|e| Error::store("put advertisement", &e))?;
    let current = host
        .get_ref(&name)
        .map_err(|e| Error::store("read job ref", &e))?;
    let update = match current {
        None => RefUpdate::create(name.clone(), oid),
        Some(existing) if existing.oid == oid => return Ok(oid),
        Some(existing) => {
            let Some((_, held)) = read_record::<Advertisement>(host, &name, "advertisement")?
            else {
                return Err(Error::store(
                    "read advertisement",
                    &gitiup_host::HostError::not_found("advertisement", existing.oid.hex()),
                ));
            };
            match held.attempt.cmp(&advertisement.attempt) {
                std::cmp::Ordering::Equal if held.round_digest == advertisement.round_digest => {
                    // The same round, re-advertised: a selector running its publish step
                    // again (a fresh TTL, a new clock, a retried command). The job is one
                    // ref and stays one ref, so this is a refresh and not a conflict.
                    RefUpdate::new(name.clone(), Expect::Is(existing.oid), oid)
                        .with_message(format!("attempt {} re-advertised", held.attempt))
                }
                std::cmp::Ordering::Equal => {
                    return Err(Error::Store(crate::error::StoreError::conflict(
                        "advertise job",
                        format!(
                            "{name} already advertises this job at attempt {}, pointing at {}; \
                             this would point at {}",
                            held.attempt, held.round_digest, advertisement.round_digest
                        ),
                    ))
                    .with_hint(
                        "one job, one round per attempt: two different rounds for one attempt \
                         is the thing the seed exists to make impossible",
                    ));
                }
                std::cmp::Ordering::Greater => {
                    return Err(Error::policy(
                        "advertisement",
                        format!(
                            "{name} is at attempt {} and this would move it back to {}; \
                             attempts only go forward",
                            held.attempt, advertisement.attempt
                        ),
                    ));
                }
                std::cmp::Ordering::Less => {
                    RefUpdate::new(name.clone(), Expect::Is(existing.oid), oid).with_message(
                        format!("attempt {} → {}", held.attempt, advertisement.attempt),
                    )
                }
            }
        }
    };
    host.update_ref_cas(&update.with_actor(actor("advertisement")))
        .map_err(|e| {
            Error::store("advertise job", &e).with_hint(
                "the job's advertisement moved under this write: re-read \
                 refs/gitiup/job/<change>/<job> and advertise from what the store says, \
                 which is the arbitration and not an obstacle",
            )
        })?;
    Ok(oid)
}

/// Advertise a published round, signed by one of the round's own selectors.
///
/// The signer must be a key that signed the round: an advertisement derives whatever
/// authority it has from the record it indexes, and letting any key publish one would
/// make `refs/gitiup/job` a noticeboard for fake invitations. (A volunteer is still
/// told to check the round itself — [`Advertisement::matches`] — this check is what makes
/// the cheap one worthwhile.)
pub fn advertise_round(
    host: &dyn Host,
    round: &Round,
    selector: &dyn Signer,
    now: TimeUs,
) -> Result<Oid> {
    round.validate()?;
    let key_id = selector.key_id();
    if !round.signatures.iter().any(|s| s.key_id == key_id) {
        return Err(Error::signature(
            "advertisement",
            format!(
                "{} did not sign the round it is advertising, so it cannot invite volunteers \
                 to it",
                short_key(&key_id)
            ),
        ));
    }
    let mut advertisement = Advertisement::new(
        round,
        now,
        crate::job::DEFAULT_LEASE_TTL_US,
        crate::job::DEFAULT_JOB_TTL_US,
    )?;
    advertisement.sign(selector)?;
    advertise(host, &advertisement)
}

/// The advertisement a job carries, if it has one.
pub fn advertisement_at(host: &dyn Host, change: &str, job: &str) -> Result<Option<Advertisement>> {
    let name = job_ref(change, job)?;
    let Some((_, advertisement)) = read_record::<Advertisement>(host, &name, "advertisement")?
    else {
        return Ok(None);
    };
    same_ref(
        &name,
        &job_ref(&advertisement.change_id, &advertisement.job_id)?,
        "advertisement",
    )?;
    Ok(Some(advertisement))
}

/// The refs that carry advertisements, paged, without fetching a single blob.
///
/// The cheapest possible poll, for a caller that remembers what it saw last time and only
/// wants to know whether anything moved: one `list_refs` bounded by `limit`, under
/// `refs/gitiup/job` and nowhere else.
pub fn advertised_refs(
    host: &dyn Host,
    cursor: Cursor,
    limit: usize,
) -> Result<Page<(RefName, Oid)>> {
    let limit = clamp_page(limit);
    let query = RefQuery::prefix(ADVERTISED_PREFIX)
        .with_limit(cursor.offset().saturating_add(limit).saturating_add(1));
    let refs = host
        .list_refs(&query)
        .map_err(|e| Error::store("list advertised jobs", &e))?;
    let items: Vec<(RefName, Oid)> = refs
        .iter()
        .skip(cursor.offset())
        .take(limit)
        .map(|reference| (reference.name.clone(), reference.oid))
        .collect();
    let more = refs.len() > cursor.offset().saturating_add(limit);
    Ok(Page {
        next: if more && items.len() == limit {
            Some(cursor.after(items.len()))
        } else {
            None
        },
        items,
    })
}

/// Rounds that still want filling, paged.
///
/// An advertisement is "open" while its ref exists and it has not expired; closing is
/// [`close_job`], which the publisher of a verdict calls, so the listing does not have to
/// re-derive "has this been tallied" from verdict refs at poll time. Expired rows are
/// dropped here rather than returned dead.
///
/// Cost, stated because a poll that lies about its cost gets slower and nobody notices:
/// one bounded ref listing plus one blob fetch per row in the window. What it does *not*
/// do is work out how full each job is — that is [`job_fill`], and it is asked one job at
/// a time precisely so a volunteer can ask it only about the job it is about to do.
///
/// A row that will not parse is an error and not a skipped row: a poll that quietly
/// drops a row can drop the one it was looking for. A caller that wants to tolerate a
/// store full of other people's rubbish is asking the wrong question, but
/// [`advertised_refs`] is the escape hatch — it diffs refs and parses nothing.
pub fn open_rounds(
    host: &dyn Host,
    now: TimeUs,
    cursor: Cursor,
    limit: usize,
) -> Result<Page<Advertisement>> {
    let page = advertised_refs(host, cursor, limit)?;
    let mut items = Vec::with_capacity(page.items.len());
    for (name, oid) in &page.items {
        let bytes = host
            .get(oid)
            .map_err(|e| Error::store("fetch advertisement", &e))?
            .ok_or_else(|| {
                Error::store(
                    "fetch advertisement",
                    &gitiup_host::HostError::not_found("advertisement", oid.hex()),
                )
            })?;
        let advertisement = Advertisement::from_canonical_bytes(&bytes)?;
        same_ref(
            name,
            &job_ref(&advertisement.change_id, &advertisement.job_id)?,
            "advertisement",
        )?;
        if advertisement.is_live(now) {
            items.push(advertisement);
        }
    }
    Ok(Page {
        items,
        next: page.next,
    })
}

/// Rounds open *and* inviting `key_id` — the volunteer's poll.
///
/// The invitation list is copied into the advertisement ([`Advertisement::invites`]), so
/// this costs exactly what [`open_rounds`] costs: no extra round trips per job. A sealed
/// round cannot be advertised at all, which is what keeps that copy honest
/// ([`Advertisement::new`]).
pub fn open_rounds_for(
    host: &dyn Host,
    key_id: &str,
    now: TimeUs,
    cursor: Cursor,
    limit: usize,
) -> Result<Page<Advertisement>> {
    let page = open_rounds(host, now, cursor, limit)?;
    Ok(Page {
        items: page
            .items
            .into_iter()
            .filter(|advertisement| advertisement.invites(key_id))
            .collect(),
        next: page.next,
    })
}

/// Take a job out of the listing: it has been tallied, abandoned, or superseded by a
/// change nobody has advertised yet.
///
/// The publisher of a verdict calls this — a tallied job needs no more volunteers — and
/// so does whoever gives up on a change. It needs no signature because it forges nothing:
/// a deletion cannot cast a vote, and the worst it does is hide a job that the selector
/// re-advertises with the next `gitiup select --publish`. The CAS is what matters here:
/// `expected` is the advertisement the caller read, and a job somebody re-advertised in
/// the meantime is not this caller's to delete.
pub fn close_job(host: &dyn Host, change: &str, job: &str, expected: Option<Oid>) -> Result<bool> {
    let name = job_ref(change, job)?;
    let current = host
        .get_ref(&name)
        .map_err(|e| Error::store("read job ref", &e))?;
    let Some(existing) = current else {
        return Ok(false);
    };
    if let Some(expected) = &expected
        && expected != &existing.oid
    {
        return Err(Error::policy(
            "advertisement",
            format!(
                "{name} is no longer the advertisement this close was asked for ({} is not \
                 {}); refusing to delete a job somebody re-advertised",
                existing.oid.hex(),
                expected.hex()
            ),
        ));
    }
    host.delete_ref_cas(
        &RefDeletion::new(name.clone(), Expect::Is(existing.oid))
            .with_actor(actor("advertisement")),
    )
    .map_err(|e| {
        Error::store("close job", &e)
            .with_hint("the job moved under this close; re-read it and decide again")
    })?;
    Ok(true)
}

/// What one seat of an advertised job looks like right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatState {
    /// The seat, as advertised.
    pub seat: Seat,
    /// Its submission ref is written: somebody (this key, or an earlier run of it) has
    /// already answered for it.
    pub submitted: bool,
    /// The lease ref, whatever it holds — an expired lease is reported and the caller
    /// decides, because "expired" is a fact about the clock and not about the store.
    pub lease: Option<Lease>,
}

impl SeatState {
    /// Whether the lease is alive at `now`.
    pub fn lease_live(&self, now: TimeUs) -> bool {
        self.lease.as_ref().is_some_and(|l| l.is_live(now))
    }

    /// Nobody has answered and nobody is working it.
    pub fn open(&self, now: TimeUs) -> bool {
        !self.submitted && !self.lease_live(now)
    }

    /// Who is working it, if the lease says so and is alive.
    pub fn holder(&self, now: TimeUs) -> Option<&str> {
        self.lease
            .iter()
            .find(|lease| lease.is_live(now))
            .map(|lease| lease.holder.as_str())
    }
}

/// Per-seat status for one advertised job.
///
/// Two point lookups per seat (the submission ref and the lease ref) and nothing else: no
/// listing, no round fetch. That is the deliberate cost of "how full is this job", and it
/// is why [`open_rounds`] does not do it for the whole page — a volunteer asks about the
/// job it is holding, not about every job in the store.
pub fn job_fill(host: &dyn Host, advertisement: &Advertisement) -> Result<Vec<SeatState>> {
    let mut out = Vec::with_capacity(advertisement.seats.len());
    for seat in &advertisement.seats {
        let slot = reveal_ref(&advertisement.change_id, &advertisement.job_id, &seat.slot)?;
        let submitted = host
            .get_ref(&slot)
            .map_err(|e| Error::store("read submission slot", &e))?
            .is_some();
        let lease = lease_at(
            host,
            &advertisement.change_id,
            &advertisement.job_id,
            &seat.slot,
        )?;
        out.push(SeatState {
            seat: seat.clone(),
            submitted,
            lease,
        });
    }
    Ok(out)
}

/// How many seats an advertised job still needs somebody for.
pub fn open_seats(host: &dyn Host, advertisement: &Advertisement, now: TimeUs) -> Result<usize> {
    Ok(job_fill(host, advertisement)?
        .iter()
        .filter(|state| state.open(now))
        .count())
}

// ---------------------------------------------------------------------------
// leases: advice with a deadline
// ---------------------------------------------------------------------------

/// The answer to "may I take this seat?".
///
/// "Somebody else is already doing it" is not an error: it is the normal answer to a
/// poll, and the caller needs the holder and the remaining TTL to print and to schedule
/// its next look. Errors are reserved for the store failing, and for renewals and
/// releases that are refused because the caller is not the holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The lease is the caller's now.
    Claimed {
        /// What was written. Boxed because a claim that lost is a handful of words and a
        /// poll should not pay for a record it will throw away.
        lease: Box<Lease>,
        /// The ref's new value.
        oid: Oid,
        /// The lease this one took over, if it did.
        took: Option<Taken>,
    },
    /// A live lease is held by somebody else.
    Held {
        /// The seat that refused.
        slot: String,
        /// Who has it.
        holder: String,
        /// When their lease dies, and it is stealable from then on.
        expires_at_us: i64,
        /// How long is left, for a volunteer deciding whether to wait.
        remaining_us: i64,
    },
}

impl Claim {
    /// Whether the caller got the seat.
    pub fn claimed(&self) -> bool {
        matches!(self, Claim::Claimed { .. })
    }

    /// The seat this claim is about.
    pub fn slot(&self) -> String {
        match self {
            Claim::Claimed { lease, .. } => lease.slot.clone(),
            Claim::Held { slot, .. } => slot.clone(),
        }
    }

    /// Who holds the seat now.
    pub fn holder(&self) -> &str {
        match self {
            Claim::Claimed { lease, .. } => &lease.holder,
            Claim::Held { holder, .. } => holder,
        }
    }

    /// How long the current holder has left.
    pub fn remaining_us(&self) -> i64 {
        match self {
            Claim::Claimed { lease, .. } => lease.ttl_us,
            Claim::Held { remaining_us, .. } => *remaining_us,
        }
    }

    /// The steal this claim recorded, if it took over from somebody.
    pub fn took(&self) -> Option<&Taken> {
        match self {
            Claim::Claimed { took, .. } => took.as_ref(),
            Claim::Held { .. } => None,
        }
    }

    /// The line to print: ours, or whose it is and for how long.
    pub fn text(&self) -> String {
        match self {
            Claim::Claimed { lease, took, .. } => match took {
                Some(taken) => format!(
                    "{} slot {} is yours for {} (took over a dead lease from {})",
                    JobAddress {
                        change_id: &lease.change_id,
                        job_id: &lease.job_id,
                    },
                    short_slot(&lease.slot),
                    ttl_text(lease.ttl_us),
                    short_key(&taken.holder)
                ),
                None => format!(
                    "{} slot {} is yours for {}",
                    JobAddress {
                        change_id: &lease.change_id,
                        job_id: &lease.job_id,
                    },
                    short_slot(&lease.slot),
                    ttl_text(lease.ttl_us)
                ),
            },
            Claim::Held {
                slot,
                holder,
                remaining_us,
                ..
            } => format!(
                "{} is held by {} for another {}; not doing it twice",
                short_slot(slot),
                short_key(holder),
                ttl_text(*remaining_us)
            ),
        }
    }
}

/// Take (or refresh) the lease on one seat.
///
/// The CAS is the whole arbitration, and there are four outcomes:
///
/// * **free** — claimed with `Expect::Absent`, so two volunteers polling the same free
///   seat get one winner; the loser re-reads and gets `Held`.
/// * **already ours, alive** — refreshed, not duplicated: a claim retried after a dropped
///   connection is not a second seat.
/// * **alive and somebody else's** — refused by returning [`Claim::Held`] naming the
///   holder and the remaining TTL.
/// * **expired, or belonging to an attempt that is over** — takeable, and the take is
///   recorded in the new lease's `taken` trail. A volunteer that died mid-job must not
///   black out a seat for a TTL, and an escalation to `attempt + 1` ends the leases the
///   dead attempt handed out; either way "who had this before me" stays auditable instead
///   of becoming a mystery.
///
/// Nothing here grants anything. See the [module docs](crate::store#a-lease-is-advice-not-a-lock)
/// and [`crate::gate::admit`], which has never heard of leases.
pub fn claim_lease(host: &dyn Host, request: &LeaseRequest<'_>) -> Result<Claim> {
    request.validate()?;
    let name = lease_ref(request.change_id, request.job_id, request.slot)?;
    let holder = request.holder_id();
    for _ in 0..MAX_CAS_RETRIES {
        let prior = read_lease(host, &name)?;
        let Some((current_oid, prior)) = prior else {
            let mut lease = Lease::new(
                request.job(),
                request.attempt,
                request.slot,
                &holder,
                request.now,
                request.ttl_us,
                Vec::new(),
            )?;
            lease.sign(request.holder)?;
            return match cas_lease(host, &name, &lease, Expect::Absent, "claim")? {
                Some(oid) => Ok(Claim::Claimed {
                    lease: Box::new(lease),
                    oid,
                    took: None,
                }),
                // Somebody wrote the free seat between the read and the write. Nothing
                // was overwritten; fall round and give the honest answer.
                None => continue,
            };
        };
        let ours = prior.holder == holder;
        let same_attempt = prior.attempt == request.attempt;
        if ours && same_attempt && prior.is_live(request.now) {
            let mut lease = Lease::new(
                request.job(),
                request.attempt,
                request.slot,
                &holder,
                request.now,
                request.ttl_us,
                prior.taken.clone(),
            )?;
            lease.sign(request.holder)?;
            if let Some(oid) = cas_lease(host, &name, &lease, Expect::Is(current_oid), "refresh")? {
                return Ok(Claim::Claimed {
                    lease: Box::new(lease),
                    oid,
                    took: None,
                });
            }
            continue;
        }
        if same_attempt && prior.is_live(request.now) {
            return Ok(Claim::Held {
                slot: prior.slot.clone(),
                holder: prior.holder.clone(),
                expires_at_us: prior.expires_at_us(),
                remaining_us: prior.remaining_us(request.now),
            });
        }
        let took = Taken::of(&prior, request.now);
        let mut lease = Lease::new(
            request.job(),
            request.attempt,
            request.slot,
            &holder,
            request.now,
            request.ttl_us,
            prior.taken.clone(),
        )?;
        record_steal(&mut lease, took.clone());
        lease.sign(request.holder)?;
        if let Some(oid) = cas_lease(host, &name, &lease, Expect::Is(current_oid), "take")? {
            return Ok(Claim::Claimed {
                lease: Box::new(lease),
                oid,
                took: Some(took),
            });
        }
    }
    Err(Error::policy(
        "lease",
        format!(
            "{} slot {} was contested {} times over; nothing was overwritten",
            JobAddress {
                change_id: request.change_id,
                job_id: request.job_id
            },
            short_slot(request.slot),
            MAX_CAS_RETRIES
        ),
    )
    .with_hint(
        "many volunteers want this seat at once, or the store is replaying reads; poll again",
    ))
}

/// Renew a lease: a heartbeat from a volunteer that is still working.
pub fn renew_lease(host: &dyn Host, request: &LeaseRequest<'_>) -> Result<Lease> {
    request.validate()?;
    let name = lease_ref(request.change_id, request.job_id, request.slot)?;
    let holder = request.holder_id();
    let Some((current_oid, prior)) = read_lease(host, &name)? else {
        return Err(Error::policy(
            "lease",
            format!(
                "{} slot {} has no lease to renew: it was released, or was never taken",
                JobAddress {
                    change_id: request.change_id,
                    job_id: request.job_id
                },
                short_slot(request.slot)
            ),
        ));
    };
    if prior.holder != holder {
        return Err(live_refusal(&prior, request.now));
    }
    if prior.attempt != request.attempt {
        return Err(Error::policy(
            "lease",
            format!(
                "the lease on {} slot {} is for attempt {}, not attempt {}; a renewal does \
                 not cross attempts, because attempt {}'s round is over",
                JobAddress {
                    change_id: request.change_id,
                    job_id: request.job_id
                },
                short_slot(request.slot),
                prior.attempt,
                request.attempt,
                prior.attempt
            ),
        ));
    }
    if prior.is_expired(request.now) {
        return Err(Error::policy(
            "lease",
            format!(
                "your lease on {} slot {} died {} ago and is nobody's to renew; claim it \
                 again if it is still free",
                JobAddress {
                    change_id: request.change_id,
                    job_id: request.job_id
                },
                short_slot(request.slot),
                ttl_text(request.now.as_us().saturating_sub(prior.expires_at_us()))
            ),
        ));
    }
    let mut lease = Lease::new(
        request.job(),
        request.attempt,
        request.slot,
        &holder,
        request.now,
        request.ttl_us,
        prior.taken.clone(),
    )?;
    lease.sign(request.holder)?;
    match cas_lease(host, &name, &lease, Expect::Is(current_oid), "renew")? {
        Some(_) => Ok(lease),
        None => match read_lease(host, &name)? {
            Some((_, now_holds)) => Err(live_refusal(&now_holds, request.now)),
            None => Err(Error::policy(
                "lease",
                "the lease was released under this renewal; nothing was written",
            )),
        },
    }
}

/// Give a lease up: the job is done, or it turned out to be impossible, and the seat
/// should not sit leased until the TTL expires.
pub fn release_lease(host: &dyn Host, request: &LeaseRequest<'_>) -> Result<bool> {
    request.validate()?;
    let name = lease_ref(request.change_id, request.job_id, request.slot)?;
    let holder = request.holder_id();
    let Some((current_oid, prior)) = read_lease(host, &name)? else {
        return Ok(false);
    };
    if prior.holder != holder {
        return Err(live_refusal(&prior, request.now));
    }
    host.delete_ref_cas(
        &RefDeletion::new(name.clone(), Expect::Is(current_oid)).with_actor(actor("lease")),
    )
    .map_err(|e| {
        Error::store("release lease", &e).with_hint(
            "the lease moved under this release; whoever holds it now is not you, and \
                 deleting their claim would be the one thing a lease cannot allow",
        )
    })?;
    Ok(true)
}

/// The lease on one seat, verified, whether or not it is alive.
pub fn lease_at(host: &dyn Host, change: &str, job: &str, slot: &str) -> Result<Option<Lease>> {
    let name = lease_ref(change, job, slot)?;
    read_lease(host, &name).map(|found| found.map(|(_, lease)| lease))
}

/// Every lease one job has out, optionally for one attempt only.
pub fn job_leases(
    host: &dyn Host,
    change: &str,
    job: &str,
    attempt: Option<u64>,
) -> Result<Vec<Lease>> {
    let prefix = lease_prefix(change, job)?;
    let mut out = Vec::new();
    for reference in host
        .list_refs(&RefQuery::prefix(&prefix))
        .map_err(|e| Error::store("list leases", &e))?
    {
        if let Some((_, lease)) = read_lease(host, &reference.name)?
            && attempt.is_none_or(|want| lease.attempt == want)
        {
            out.push(lease);
        }
    }
    out.sort_by(|a, b| {
        a.slot
            .cmp(&b.slot)
            .then(a.acquired_at_us.cmp(&b.acquired_at_us))
    });
    Ok(out)
}

/// The refusal every non-holder gets, naming who does hold the lease and for how long.
fn live_refusal(lease: &Lease, now: TimeUs) -> Error {
    let whereabout = JobAddress {
        change_id: &lease.change_id,
        job_id: &lease.job_id,
    };
    if lease.is_live(now) {
        return Error::policy(
            "lease",
            format!(
                "{} slot {} is held by {} for another {} (attempt {}); it is not yours to \
                 renew or release",
                whereabout,
                short_slot(&lease.slot),
                short_key(&lease.holder),
                ttl_text(lease.remaining_us(now)),
                lease.attempt
            ),
        );
    }
    Error::policy(
        "lease",
        format!(
            "{} slot {} carried {}'s lease, which died; it is not yours, and it is now \
             anybody's to claim",
            whereabout,
            short_slot(&lease.slot),
            short_key(&lease.holder)
        ),
    )
}

/// Read a lease and check it is what it claims: canonical bytes, the holder's own
/// signature, and a record that speaks about the ref it is filed under.
fn read_lease(host: &dyn Host, name: &RefName) -> Result<Option<(Oid, Lease)>> {
    let Some((oid, lease)) = read_record::<Lease>(host, name, "lease")? else {
        return Ok(None);
    };
    lease.verify()?;
    same_ref(
        name,
        &lease_ref(&lease.change_id, &lease.job_id, &lease.slot)?,
        "lease",
    )?;
    Ok(Some((oid, lease)))
}

/// CAS-write a lease. `Ok(None)` means the expectation failed — the ref moved, and the
/// caller must re-read and answer honestly rather than force the write.
fn cas_lease(
    host: &dyn Host,
    name: &RefName,
    lease: &Lease,
    expect: Expect,
    why: &'static str,
) -> Result<Option<Oid>> {
    let oid = host
        .put_cas(&ns::JOB, &lease.canonical_bytes()?)
        .map_err(|e| Error::store(format!("put {why} record"), &e))?;
    let update = RefUpdate::new(name.clone(), expect, oid)
        .with_actor(actor("lease"))
        .with_message(format!(
            "{why}: {} slot {}",
            short_key(&lease.holder),
            short_slot(&lease.slot)
        ));
    match host.update_ref_cas(&update) {
        Ok(reference) => Ok(Some(reference.oid)),
        Err(error) if error.kind() == HostErrorKind::Conflict => Ok(None),
        Err(error) => Err(Error::store(format!("{why} lease"), &error)),
    }
}

/// Does this ref carry the record it names?
///
/// The check behind "a store that lies is caught at the digest". A record filed under the
/// wrong ref is either a bug or an attack, and in both cases believing it is worse than
/// stopping.
fn same_ref(found: &RefName, expected: &RefName, what: &'static str) -> Result<()> {
    if found == expected {
        return Ok(());
    }
    Err(Error::digest_mismatch(
        "store",
        format!(
            "a {what} filed at {found} speaks about {expected}: the ref and the record \
             disagree, so neither can be believed",
        ),
    )
    .with_hint(format!(
        "this is a store bug or a hostile store, not a bad record to retry; report {found}"
    )))
}

fn actor(what: &str) -> Actor {
    Actor::from(format!("gitiup-quorum/{what}"))
}

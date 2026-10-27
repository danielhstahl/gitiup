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
//! refs/gitiup/reveal/<change>/<job>/<slot>       one verifier's submission
//! refs/gitiup/verdict/<change>/<job>             the signed verdict
//! ```
//!
//! Every write here is a CAS write, and every read re-checks canonical bytes and
//! signatures: a store that lies about bytes is caught at the digest, not assumed away.

use gitiup_attest::AttestationDoc;
use gitiup_host::{Actor, Expect, Host, HostErrorKind, Namespace, Oid, RefName, RefUpdate};

use crate::error::{Error, Result};
use crate::record::{Record, short_key};
use crate::roster::{Revocation, Roster, SignUp, Withdrawal};
use crate::round::Round;
use crate::verdict::VerdictRecord;

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
    /// Per-key submission slots (commit-reveal in giti-msi.6 splits this in two).
    pub const REVEAL: Namespace = Namespace::const_new("reveal");
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

/// `refs/gitiup/verdict/<change>/<job>`.
pub fn verdict_ref(change: &str, job: &str) -> Result<RefName> {
    check_segment(change, "change id")?;
    check_segment(job, "job id")?;
    gitiup_ref(
        &format!("verdict/{}/{}", escape(change), escape(job)),
        "verdict ref",
    )
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

/// A change or job id must survive the journey into a ref name.
fn check_segment(value: &str, what: &'static str) -> Result<()> {
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

/// Publish a round record. Re-publishing the same round is idempotent; publishing a
/// *different* round for the same change/job/attempt is a conflict, because that would
/// be two different quorums for one change, which is the thing the seed exists to make
/// impossible.
pub fn publish_round(host: &dyn Host, round: &Round) -> Result<Oid> {
    let name = round_ref(
        &round.inputs.change_id,
        &round.inputs.job_id,
        round.inputs.attempt,
    )?;
    put_record(host, &ns::ROUND, &name, &round.canonical_bytes()?, "round")
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

fn actor(what: &str) -> Actor {
    Actor::from(format!("gitiup-quorum/{what}"))
}

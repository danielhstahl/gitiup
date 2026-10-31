//! `gitiup participant quarantine|unquarantine|history` — verdict history as a selection
//! input (giti-zp1.8).
//!
//! The library half ([`gitiup_quorum::quarantine`], [`gitiup_quorum::reputation`]) decides
//! what may be written and what it does; this file is the three things a library cannot
//! supply: a key to sign with, a store to put the record in, and a sentence a human reads
//! before deciding.
//!
//! ```text
//!  gitiup quorum verdict ──► filed verdict ──► participant quarantine ──► refs/gitiup/quarantine/**
//!  (the owner's act)          (the evidence)         │                                    │
//!                                                    ▼                                    ▼
//!                                    select / change submit / quorum retry      participant history
//!                                    apply it as RoundInputs::excluding         (the public trail +
//!                                                                                the reputation table)
//! ```
//!
//! # The split that decides how each command reads the store
//!
//! A **quarantine** is a punishment, so it cites a document: the verdict must be *filed* at
//! `refs/gitiup/verdict/<change>/<job>` and signed by a key this machine trusts, because a
//! citation to a tally nobody signed is a citation nobody can check later.
//!
//! **Reputation** is a score, not a punishment, so it recomputes: `history` re-tallies the
//! store's rounds the way `gitiup quorum verdict` does, and prints turn-up rates that
//! authorise nothing. That asymmetry is deliberate and it is the whole ticket in one line:
//! *what is counted needs no signature, because it decides nothing; what decides needs a
//! signature, because it is someone's act.*
//!
//! Exit codes keep the usual table: 0 ok · 2 usage · 3 store unreachable · 6 refused
//! (no reason given, absence offered as a reason, no evidence cited, nothing to lift, an
//! owner this machine does not trust) · 7 a signature that does not verify · 8 a digest
//! that is not what it names.

use std::collections::BTreeMap;

use gitiup_attest::{TimeUs, Trust};
use gitiup_quorum::prelude::*;
use gitiup_quorum::quarantine::{
    DEFAULT_QUARANTINE_EPOCHS, MAX_QUARANTINE_EPOCHS, Quarantine, QuarantineLift, QuarantineReason,
    Standing,
};
use gitiup_quorum::reputation::Report;
use gitiup_quorum::store;
use gitiup_quorum::verdict::VerdictRecord;
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::{self, Opened};
use crate::verdict as verdict_cli;

/// How many round records `history` fetches before saying it stopped.
const DEFAULT_MAX_ROUNDS: usize = 500;

/// `gitiup participant quarantine <KEY-ID> [OPTIONS]` — keep a key out of the pool for N
/// epochs, on the strength of a verdict.
pub(crate) fn quarantine(args: &Args) -> Result<(), CliError> {
    let here = participant::keystore()?;
    let owner = participant::signing_key(args, &here)?;
    let (trust, trusted_by) = participant::owner_trust(args, &here)?;
    let now = TimeUs::now();
    let target = participant::key_id_of(&here, args.need("the key id to quarantine")?)?;
    let reason = QuarantineReason::parse(args.get("--reason").ok_or_else(|| {
        CliError::refused(
            "--reason is required: a quarantine is a decision, and a decision has a name",
            format!(
                "reasons are {}; `--reason absence` and friends are refused — silence is \
                 insufficient, not guilt",
                QuarantineReason::ALL
                    .iter()
                    .map(|reason| reason.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?)?;
    let epochs = match args.get("--epochs") {
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| CliError::usage(format!("--epochs wants a whole number, got '{text}'")))?,
        None => DEFAULT_QUARANTINE_EPOCHS,
    };
    if epochs > MAX_QUARANTINE_EPOCHS {
        return Err(CliError::usage(format!(
            "--epochs {epochs} is past the {MAX_QUARANTINE_EPOCHS} maximum: a longer \
             quarantine is a roster edit, and the roster is the owner's signed trust list"
        )));
    }
    let roster = participant::current_epoch(args)?;
    let start_epoch = match args.get("--start-epoch") {
        Some(text) => text.parse::<u64>().map_err(|_| {
            CliError::usage(format!("--start-epoch wants a whole number, got '{text}'"))
        })?,
        None => roster.as_ref().map(|roster| roster.epoch).ok_or_else(|| {
            CliError::refused(
                "no roster epoch is current, and a quarantine counts epochs",
                "point at the store with --store/--remote, or say which epoch it starts at \
                 with --start-epoch <n>",
            )
        })?,
    };

    // The evidence, or the honest absence of it.
    let note = args.get("--note").map(str::to_string);
    let mut record = match cited_verdict(args, &target, start_epoch, epochs, now)? {
        Some((_verdict, derived)) => {
            if derived.reason != reason {
                return Err(CliError::refused(
                    format!(
                        "the verdict you cited says `{}`, not `{}`",
                        derived.reason, reason
                    ),
                    format!(
                        "let the evidence name the reason (drop --reason and it is derived), \
                         or cite the verdict that shows `{}` — this one refused {} with `{}`",
                        reason,
                        participant::short(&target),
                        derived
                            .evidence
                            .first()
                            .map(|row| row.code.clone())
                            .unwrap_or_else(|| "divergence".to_string())
                    ),
                ));
            }
            derived
        }
        None if reason.requires_evidence() => {
            return Err(CliError::refused(
                format!(
                    "`{reason}` claims a fact a verdict recorded, and no verdict was cited",
                    reason = reason
                ),
                "cite one with --change <id> --job <id> (it must be filed: `gitiup quorum \
                 verdict <change> --job <job> --publish --key <owner>`), or use \
                 --reason owner_decision, which is your judgement and asks no measurement \
                 to launder itself as one",
            ));
        }
        None => {
            let detail = note.clone().ok_or_else(|| {
                CliError::refused(
                    "--reason owner_decision needs --note: say the reason in a sentence an \
                     appeal can answer",
                    "an owner's judgement is a legitimate thing to write down; an unnamed one \
                     is not, because nobody could disagree with it",
                )
            })?;
            let mut record = Quarantine::new(
                target.clone(),
                reason,
                detail,
                start_epoch,
                epochs,
                now,
                Vec::new(),
            );
            record.note = note.clone();
            record
        }
    };
    if reason == QuarantineReason::OwnerDecision {
        record.note = note.clone();
    }
    // The clock bound, in the roster's own epoch arithmetic — so a store whose owner stops
    // publishing epochs cannot turn "three epochs" into a life sentence.
    let expires = roster
        .as_ref()
        .and_then(|roster| Quarantine::expires_after_epochs(now, roster.epoch_interval_us, epochs));
    record.expires_at_us = expires;

    record.sign(&owner)?;
    record.verify(&trust)?;
    let bytes = record.canonical_bytes()?;
    let digest = record.digest()?;
    let slot = record.slot();
    let sink = participant::emit(args, &bytes, |host| {
        let oid = store::publish_quarantine(host, &record)?;
        Ok(format!(
            "refs/gitiup/quarantine/{slot}/{d} ({} in kv/quarantine)",
            oid.hex(),
            d = digest.hex()
        ))
    })?;
    if only_bytes(args) {
        return Ok(());
    }
    // What the one name reaches on the current roster: excluding a box excludes its
    // principal's other boxes, and an operator should see that before it is a surprise.
    let reaches: Vec<String> = roster
        .as_ref()
        .map(|roster| {
            gitiup_quorum::proposer_family_exclusions(roster, std::slice::from_ref(&target))
                .into_iter()
                .filter(|name| roster.entries.iter().any(|entry| &entry.key_id == name))
                .map(|entry| participant::short(&entry))
                .collect()
        })
        .unwrap_or_default();
    let detail = record.detail.clone();
    let evidence: Vec<Value> = record
        .evidence
        .iter()
        .map(|row| {
            json!({
                "change": row.change_id, "job": row.job_id, "attempt": row.attempt,
                "verdict": row.verdict_digest.to_string(), "code": row.code,
                "consensus": row.consensus.as_ref().map(|d| d.to_string()),
                "theirs": row.theirs.as_ref().map(|d| d.to_string()),
            })
        })
        .collect();
    if args.json() {
        participant::print_json(json!({
            "type": "quarantine",
            "key_id": target,
            "slot": slot,
            "digest": digest.to_string(),
            "reason": reason.as_str(),
            "detail": detail,
            "start_epoch": start_epoch,
            "epochs": epochs,
            "ends_epoch": record.ends_epoch(),
            "expires_at_us": expires,
            "issuer": record.issuer,
            "trusted_via": trusted_by,
            "evidence": evidence,
            "reaches": reaches,
            "where": sink.json(),
        }));
        return Ok(());
    }
    println!("quarantined {target}");
    println!("  reason    {reason} — {detail}");
    println!(
        "  epochs    {epochs} epoch(s): {start_epoch} through {} (inclusive of {start_epoch})",
        record.ends_epoch() - 1
    );
    if let Some(at) = expires {
        println!("  also out by {}", TimeUs(at).to_rfc3339());
    } else {
        println!("  clock     no bound: no roster was read, so only epochs expire it");
    }
    for row in &record.evidence {
        println!(
            "  evidence  {} · {} attempt {} · verdict {} · {}",
            row.change_id,
            row.job_id,
            row.attempt,
            participant::short(&row.verdict_digest.to_string()),
            row.code
        );
    }
    println!(
        "  owner     {} (believed via {trusted_by})",
        participant::short(&record.issuer)
    );
    if !reaches.is_empty() {
        println!(
            "  reaches   {} roster entr(y/ies): {} — one identity, one family (ADR-0002 D4)",
            reaches.len(),
            reaches.join(", ")
        );
    }
    println!(
        "  not       this is not a roster edit: no epoch moved, and rounds already open \
              keep their seats"
    );
    println!(
        "  appeal    there is no vote, no timer and no appeal command: the way back in \
              is a human with an owner key running `gitiup participant unquarantine {target} \
              --store … --publish`"
    );
    for line in sink.lines() {
        println!("{line}");
    }
    Ok(())
}

/// Whether `--out -` means "the bytes are the whole answer".
fn only_bytes(args: &Args) -> bool {
    args.get("--out").is_some_and(|path| path == "-")
}

/// The filed verdict `--change`/`--job` cites, and the quarantine it supports.
///
/// `None` when no change was named. The verdict must be **filed** and believed: a
/// punishment cites a signed document, not a tally that is currently in somebody's
/// process memory (which is also a different digest every time it is recomputed, so a
/// citation to one would be unusable).
fn cited_verdict(
    args: &Args,
    target: &str,
    start_epoch: u64,
    epochs: u64,
    now: TimeUs,
) -> Result<Option<(VerdictRecord, Quarantine)>, CliError> {
    let Some(change) = args.get("--change") else {
        if args.get("--job").is_some() {
            return Err(CliError::usage(
                "--job names a job of a change; give --change <id> too",
            ));
        }
        return Ok(None);
    };
    let job = args.get("--job").ok_or_else(|| {
        CliError::refused(
            "--change needs --job <id>: one verdict is one job of one change",
            "`gitiup quorum verdict <change> --store …` lists the jobs it has rounds for",
        )
    })?;
    let opened = participant::need_store(args)?;
    let (trust, _) = participant::owner_trust(args, &participant::keystore()?)?;
    let verdict = store::verdict_at(&*opened.host, change, job, &trust)?.ok_or_else(|| {
        CliError::refused(
            format!(
                "{} holds no filed verdict for {change} · {job}",
                opened.what
            ),
            "a quarantine cites a signed verdict, so one has to be filed first: `gitiup \
             quorum verdict {change} --job {job} --store … --publish --key <owner>`",
        )
    })?;
    if let Some(text) = args.get("--attempt") {
        let attempt = text
            .parse::<u64>()
            .map_err(|_| CliError::usage(format!("--attempt wants a number, got '{text}'")))?;
        if verdict.attempt != attempt {
            return Err(CliError::usage(format!(
                "the filed verdict for {change} · {job} is attempt {}, not attempt {attempt}",
                verdict.attempt
            )));
        }
    }
    let record = Quarantine::from_verdict(&verdict, target, start_epoch, epochs, now)?;
    Ok(Some((verdict, record)))
}

/// `gitiup participant unquarantine <KEY-ID> [OPTIONS]` — an owner ending one quarantine
/// early.
///
/// This is the appeal path, and it is a human act on purpose: there is no vote, no timer,
/// no `gitiup quarantine appeal`, because a protocol that decides who is trusted has
/// already stopped being a tool the owner can trust. The lift names the **record** it ends
/// (by digest), so two quarantines about one key are two decisions to undo and this command
/// will not guess which one you meant.
pub(crate) fn unquarantine(args: &Args) -> Result<(), CliError> {
    let here = participant::keystore()?;
    let owner = participant::signing_key(args, &here)?;
    let (trust, trusted_by) = participant::owner_trust(args, &here)?;
    let now = TimeUs::now();
    let target = participant::key_id_of(&here, args.need("the key id to unquarantine")?)?;
    let opened = participant::need_store(args)?;
    let ledger = store::quarantine_ledger(&*opened.host)?;
    let epoch = match args.get("--epoch") {
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| CliError::usage(format!("--epoch wants a number, got '{text}'")))?,
        None => participant::current_epoch(args)?
            .map(|roster| roster.epoch)
            .ok_or_else(|| {
                CliError::refused(
                    "no roster epoch is current, so there is no epoch to lift as of",
                    "say which epoch the key may serve again from with --epoch <n>",
                )
            })?,
    };

    let standing = ledger.standing(&target, epoch, now);
    let filed = match args.get("--digest") {
        Some(text) => ledger
            .for_key(&target)
            .into_iter()
            .find(|filed| filed.digest.to_string() == text || filed.digest.hex() == text)
            .ok_or_else(|| {
                CliError::refused(
                    format!("{text} is not a quarantine this store holds about {target}"),
                    "`gitiup participant history` prints every record and its digest",
                )
            })?,
        None => match &standing {
            Standing::Active { digest, .. } => ledger
                .for_key(&target)
                .into_iter()
                .find(|filed| &filed.digest == digest)
                .expect("the standing came from this record"),
            other => {
                return Err(CliError::refused(
                    format!("{target}: {}", other.describe()),
                    "there is nothing to lift. If a record exists and you want it ended, \
                     `gitiup participant history` names it; a lift only ever moves an \
                     exclusion from now on",
                ));
            }
        },
    };

    let mut lift = QuarantineLift::new(
        &filed.quarantine,
        epoch,
        now,
        args.get("--note").map(str::to_string),
    )?;
    lift.sign(&owner)?;
    lift.verify(&trust)?;
    let bytes = lift.canonical_bytes()?;
    let digest = lift.digest()?;
    let slot = lift.slot();
    let sink = participant::emit(args, &bytes, |host| {
        let oid = store::publish_lift(host, &lift)?;
        Ok(format!(
            "refs/gitiup/quarantine-lift/{slot}/{d} ({} in kv/quarantine-lift)",
            oid.hex(),
            d = digest.hex()
        ))
    })?;
    if only_bytes(args) {
        return Ok(());
    }
    let after = ledger.standing(&target, epoch, now);
    let still: Vec<String> = ledger
        .exclusions(epoch, now)
        .into_iter()
        .filter(|name| name == &target)
        .collect();
    if args.json() {
        participant::print_json(json!({
            "type": "quarantine_lift",
            "key_id": target,
            "digest": digest.to_string(),
            "lifts": filed.digest.to_string(),
            "effective_epoch": epoch,
            "issuer": lift.issuer,
            "trusted_via": trusted_by,
            "was": filed.quarantine.reason.to_string(),
            "standing_before": standing.describe(),
            "still_excluded": !still.is_empty(),
            "where": sink.json(),
        }));
        return Ok(());
    }
    println!("lifted the quarantine on {target}");
    println!(
        "  was       {} ({})",
        participant::short(&filed.digest.to_string()),
        filed.quarantine.reason
    );
    println!("  from      epoch {epoch} — rounds pinned at or after it may seat the key again");
    println!(
        "  owner     {} (believed via {trusted_by})",
        participant::short(&lift.issuer)
    );
    if !still.is_empty() {
        println!(
            "  note      another record still excludes this key at epoch {epoch}: \
             `gitiup participant history --key {target}` names it"
        );
    }
    println!("  after     {}", after.describe());
    println!(
        "  kept      nothing was deleted: the quarantine stays at its ref, and so does \
              this lift — the trail is the point"
    );
    for line in sink.lines() {
        println!("{line}");
    }
    Ok(())
}

/// `gitiup participant history [OPTIONS]` — the audit trail, and what the roster's history
/// says about itself.
///
/// Two halves, printed together because they answer one question (“should this key be here,
/// and should this roster be believed?”):
///
/// * **the quarantine trail** — every record the store holds, who signed it, what it cites,
///   and whether it is in force at the epoch asked about. This half needs no key of its
///   own: a quarantined key is entitled to read why it was quarantined, and the store is
///   public. What it cannot do without a trusted owner key is *believe* the records, and
///   the report says which is which.
/// * **the reputation table** — turn-up per key, recomputed from the store's rounds the way
///   a verdict is, with the roster's capacity read out. Nothing in this half can exclude
///   anybody: it is the scored half, and the report says so in as many words.
pub(crate) fn history(args: &Args) -> Result<(), CliError> {
    let opened = participant::need_store(args)?;
    let now = TimeUs::now();
    let here = participant::keystore()?;
    // The trust is tolerant here, unlike `owner_trust`: reading a public trail must not
    // require a keystore. What is *believed* is reported, never assumed.
    let (trust, trusted_by, trusted) = match participant::owner_trust(args, &here) {
        Ok((trust, source)) => (trust, source, true),
        Err(_) => (
            Trust::None,
            "no key here: the trail is shown and nothing is believed".to_string(),
            false,
        ),
    };
    let roster = store::current_roster(&*opened.host)?;
    let epoch = match args.get("--epoch") {
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| CliError::usage(format!("--epoch wants a number, got '{text}'")))?,
        None => roster
            .as_ref()
            .map(|roster| roster.epoch)
            .unwrap_or_default(),
    };
    let ledger = store::quarantine_ledger(&*opened.host)?;
    let only = args.all("--key");
    let in_force = store::quarantine_exclusions(&*opened.host, &trust, epoch, now)?;

    // --- the trail ---------------------------------------------------------------
    let mut rows: Vec<Value> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for filed in &ledger.quarantines {
        let record = &filed.quarantine;
        if !only.is_empty() && !only.iter().any(|named| named == &record.key_id) {
            continue;
        }
        if !keys.contains(&record.key_id) {
            keys.push(record.key_id.clone());
        }
        let standing = ledger.standing(&record.key_id, epoch, now);
        let believed = record.verify(&trust).is_ok();
        let evidence: Vec<Value> = record
            .evidence
            .iter()
            .map(|row| {
                json!({
                    "change": row.change_id, "job": row.job_id, "attempt": row.attempt,
                    "verdict": row.verdict_digest.to_string(), "code": row.code,
                })
            })
            .collect();
        rows.push(json!({
            "key_id": record.key_id,
            "slot": record.slot(),
            "digest": filed.digest.to_string(),
            "reason": record.reason.to_string(),
            "detail": record.detail,
            "note": record.note,
            "issuer": record.issuer,
            "believed": believed,
            "start_epoch": record.start_epoch,
            "epochs": record.epochs,
            "ends_epoch": record.ends_epoch(),
            "expires_at_us": record.expires_at_us,
            "issued_at_us": record.issued_at_us,
            "standing": standing.describe(),
            "evidence": evidence,
        }));
        lines.push(format!(
            "{}  {}  {} · epochs {}–{} · {}",
            participant::short(&record.key_id),
            if standing.excluded() {
                "OUT   "
            } else if believed {
                "in    "
            } else {
                "unheld"
            },
            record.reason,
            record.start_epoch,
            record.ends_epoch().saturating_sub(1),
            standing.describe(),
        ));
        lines.push(format!(
            "        {} · {} · cited {}",
            participant::short(&record.issuer),
            if believed {
                format!("believed via {trusted_by}")
            } else {
                "not believed: no trusted owner signed it".to_string()
            },
            if record.evidence.is_empty() {
                "no verdict (owner's judgement)".to_string()
            } else {
                record
                    .evidence
                    .iter()
                    .map(|row| format!("{} · {} a{}", row.change_id, row.job_id, row.attempt))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        lines.push(format!(
            "        {} · digest {}",
            record.detail,
            filed.digest.hex()
        ));
    }

    // --- the reputation ----------------------------------------------------------
    let scan_limit = match args.get("--max-rounds") {
        Some(text) => text
            .parse::<usize>()
            .map_err(|_| CliError::usage(format!("--max-rounds wants a number, got '{text}'")))?,
        None => DEFAULT_MAX_ROUNDS,
    };
    let mut reputation = None;
    let mut skipped: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut complete = true;
    if trusted {
        let evaluation = verdict_cli::evaluation_from(args)?;
        let scan = store::scan_rounds(&*opened.host, scan_limit)?;
        complete = scan.truncated;
        scanned = scan.fetched;
        let mut by_change: BTreeMap<String, Vec<&Round>> = BTreeMap::new();
        for round in &scan.rounds {
            if !args.all("--change").is_empty()
                && !args
                    .all("--change")
                    .iter()
                    .any(|c| c == &round.inputs.change_id)
            {
                continue;
            }
            by_change
                .entry(round.inputs.change_id.clone())
                .or_default()
                .push(round);
        }
        let mut revocations = None;
        let mut rosters: BTreeMap<u64, Roster> = BTreeMap::new();
        let mut verdicts: Vec<VerdictRecord> = Vec::new();
        for (change, rounds) in by_change {
            let latest = verdict_cli::latest_attempt_per_job(&rounds);
            for round in latest {
                let roster = match rosters.get(&round.inputs.roster_epoch) {
                    Some(roster) => roster.clone(),
                    None => {
                        let Some(found) =
                            store::roster_at(&*opened.host, round.inputs.roster_epoch)?
                        else {
                            skipped.push(format!(
                                "{change} · {}: no roster epoch {} in the store",
                                round.inputs.job_id, round.inputs.roster_epoch
                            ));
                            continue;
                        };
                        if let Err(error) = found.verify(&trust, now) {
                            skipped.push(format!(
                                "{change} · {}: roster epoch {} is not believed here ({})",
                                round.inputs.job_id, round.inputs.roster_epoch, error
                            ));
                            continue;
                        }
                        rosters.insert(round.inputs.roster_epoch, found.clone());
                        found.clone()
                    }
                };
                if let Err(error) = round.verify(&trust, &roster) {
                    skipped.push(format!(
                        "{change} · {} attempt {}: the round is not believed here ({})",
                        round.inputs.job_id, round.inputs.attempt, error
                    ));
                    continue;
                }
                if revocations.is_none() {
                    revocations = Some(store::list_revocations(&*opened.host, &trust)?);
                }
                verdicts.push(store::tally(
                    &*opened.host,
                    round,
                    &roster,
                    revocations.as_deref().unwrap_or_default(),
                    &evaluation,
                )?);
            }
        }
        reputation = Some(Report::from_verdicts(&verdicts, roster.as_ref()));
    }

    if args.json() {
        participant::print_json(json!({
            "store": opened.what,
            "epoch": epoch,
            "trusted_via": trusted_by,
            "quarantined_now": in_force.named.into_iter().collect::<Vec<_>>(),
            "not_applied": in_force.ignored.into_iter().map(|(record, why)| json!({
                "key_id": record.key_id, "digest": record.digest().map(|d| d.to_string()).ok(),
                "why": why,
            })).collect::<Vec<_>>(),
            "quarantines": rows,
            "lifts": ledger.lifts.iter().map(|lift| json!({
                "key_id": lift.key_id,
                "lifts": lift.quarantine_digest.to_string(),
                "effective_epoch": lift.effective_epoch,
                "issuer": lift.issuer,
                "note": lift.note,
            })).collect::<Vec<_>>(),
            "reputation": reputation.map(|report| json!({
                "verdicts": report.verdicts,
                "changes": report.changes,
                "rounds_scanned": scanned,
                "scan_complete": complete,
                "skipped": skipped,
                "capacity": report.capacity_note(),
                "theatre": report.theatre(),
                "keys": report.sheets.iter().map(|sheet| json!({
                    "key_id": sheet.key_id,
                    "identity": sheet.identity,
                    "seated": sheet.seated,
                    "counted": sheet.counted,
                    "divergent": sheet.divergent,
                    "contested": sheet.contested,
                    "rejected": sheet.rejected,
                    "silent": sheet.silent,
                    "turn_up": sheet.turn_up_text(),
                    "codes": sheet.codes,
                    "grounds": sheet.grounds(),
                    "changes": sheet.changes,
                })).collect::<Vec<_>>(),
            })),
        }));
        return Ok(());
    }

    println!("quarantine history · {}", opened.what);
    println!("  roster epoch {epoch} · trust believed via {trusted_by}");
    if rows.is_empty() {
        println!("  nothing has ever been quarantined in this store.");
    } else {
        println!("\nthe trail (public: a quarantined key reads its own row)");
        for line in &lines {
            println!("{line}");
        }
        println!(
            "\n  in force at epoch {epoch}: {}",
            if in_force.named.is_empty() {
                "nobody".to_string()
            } else {
                in_force
                    .named
                    .iter()
                    .map(|key| participant::short(key))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        for (record, why) in &in_force.ignored {
            println!(
                "  not applied: {} · {} — {why}",
                participant::short(&record.key_id),
                record.reason
            );
        }
    }
    println!(
        "\n  appeal: none of this has a vote, a timer or an appeal command. The way back in is \
         a human with an owner key running `gitiup participant unquarantine <key> --store … \
         --publish`, and the lift says who did it."
    );

    match reputation.as_ref() {
        None => println!(
            "\nreputation: not computed — re-tallying the store's rounds needs a key this \
             machine trusts as an owner (there is none here). The trail above is still public."
        ),
        Some(report) => {
            println!("\nreputation (scored, never punished)");
            println!(
                "  {} round(s) re-tallied across {} change(s){}",
                scanned,
                report.changes.len(),
                if complete {
                    String::new()
                } else {
                    format!(
                        " — the store has more; --max-rounds {} to read further",
                        scan_limit
                    )
                }
            );
            if report.sheets.is_empty() {
                println!("  no seat has been filled in what this store holds.");
            } else {
                println!(
                    "  {:<16} {:>7} {:>9} {:>9} {:>7}  WHAT A QUARANTINE COULD CITE",
                    "KEY", "SEATED", "DIVERGED", "REFUSED", "SILENT"
                );
                for sheet in &report.sheets {
                    println!(
                        "  {:<16} {:>7} {:>9} {:>9} {:>7}  {}",
                        participant::short(&sheet.key_id),
                        sheet.seated,
                        sheet.divergent,
                        sheet.rejected,
                        sheet.silent,
                        if sheet.grounds().is_empty() {
                            "—".to_string()
                        } else {
                            sheet.grounds().join(", ")
                        }
                    );
                }
                println!("  {}", report.capacity_note());
            }
            for note in skipped.iter().take(5) {
                println!("  skipped: {note}");
            }
            if skipped.len() > 5 {
                println!(
                    "  …and {} more round(s) skipped for the same kinds of reason",
                    skipped.len() - 5
                );
            }
        }
    }
    let _ = &ledger;
    Ok(())
}

/// What a selector must keep out of a round, and the sentences about every record that was
/// *not* applied.
///
/// This is the whole integration point: every command that opens a round
/// (`gitiup select`, `gitiup change submit`, `gitiup quorum retry`) asks this one question
/// and feeds the answer to [`RoundInputs::excluding`](gitiup_quorum::select::RoundInputs::excluding).
/// There is deliberately no other door — no roster edit, no filter inside the tally, no
/// weight in the score. A record that is not applied is reported rather than dropped: the
/// difference between "expired", "lifted", "not signed by anyone I trust" and "does not
/// exist" is the difference between a store that is quiet and a store that is lying.
pub(crate) fn kept_out(
    opened: &Opened,
    trust: &Trust,
    epoch: u64,
    now: TimeUs,
) -> Result<Kept, CliError> {
    let applied = store::quarantine_exclusions(&*opened.host, trust, epoch, now)?;
    let mut notes = Vec::new();
    if !applied.believed.is_empty() {
        notes.push(format!(
            "quarantine keeps {} key(s) out of every round this opens (epoch {epoch}): {}",
            applied.believed.len(),
            applied
                .believed
                .iter()
                .map(|(record, _)| format!(
                    "{} · {}",
                    participant::short(&record.key_id),
                    record.reason
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (record, why) in &applied.ignored {
        notes.push(format!(
            "quarantine of {} ({}) not applied: {why}",
            participant::short(&record.key_id),
            record.reason
        ));
    }
    Ok(Kept {
        names: applied.named,
        notes,
    })
}

/// The names, and the notes beside them.
pub(crate) struct Kept {
    pub(crate) names: std::collections::BTreeSet<String>,
    pub(crate) notes: Vec<String>,
}

impl Kept {
    /// Nothing to keep out: no store, no trust root, nothing quarantined.
    pub(crate) fn empty() -> Kept {
        Kept {
            names: Default::default(),
            notes: Vec::new(),
        }
    }

    /// The names in the form `RoundInputs::excluding` takes.
    pub(crate) fn list(&self) -> Vec<String> {
        self.names.iter().cloned().collect()
    }
}

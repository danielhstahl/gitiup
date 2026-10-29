//! `gitiup work` — the volunteer's loop, in one command (giti-zp1.3).
//!
//! Everything a volunteer needs to run a job a stranger chose for it, and nothing it
//! did not ask for:
//!
//! ```text
//!  refs/gitiup/job ──► open_rounds_for(me) ──► the round behind the advertisement
//!                                                     │
//!        roster @ the epoch the round pins ◄──────────┘
//!                     │
//!   check_invitation  │  roster signature · ledger epoch · expiry · my key ·
//!   (participate.rs)  │  revocation · capability claim still true · slot free
//!                     ▼
//!                  a lease ──► plan (gitiup-run) ──► execute in a sandbox that
//!                     │                                doctor says may serve a
//!                     │                                stranger's job, egress
//!                     │                                denied, clock pinned
//!                     ▼
//!              manifest digest ──► signature ──► store::publish_attestation
//! ```
//!
//! # The two ideas this command is built on
//!
//! **The volunteer does not decide what a vote is worth.** It decides only whether to
//! take the work; the round, the roster and the store decided who it is, what it must
//! run and what it must satisfy. So there is no `--n`, no `--require-arch` and no
//! `--tier` here: a volunteer that could restate the round would be a volunteer voting
//! on its own terms. Every number is read out of the published round and the roster
//! epoch it pinned.
//!
//! **A refusal is the point of the design, so every refusal is a code and a
//! sentence.** A volunteer that ran a stranger's build before noticing the roster had
//! been rolled back would be publishing an attestation it cannot defend, so the
//! checklist runs first and completely ([`check_invitation`]): the roster signature,
//! the anti-rollback ledger, the epoch's expiry, this key's presence, its revocation
//! status, its *measured* capabilities and whether its slot is already taken. Each
//! refusal exits with the library's own number:
//!
//! | exit | the event |
//!|------|---------|
//!| 6 | no sandbox here may serve a stranger's job (the ladder it tried is named) |
//!| 6 | an invitation in a `reveal_mode` this build cannot honour — refused, never downgraded |
//!| 6 | a roster epoch *lower* than this volunteer's ledger: a rollback, said loudly |
//!| 6 | a live lease held by somebody else, with the TTL left |
//!| 6/7/8 | the store refused the attestation: [`gate`]'s token and code, verbatim |
//!| 0 | the work happened — including a *failed* build, whose attestation says so |
//!
//! # A red build is still a result
//!
//! A quorum is not a wall of green ticks; it is several machines agreeing on what
//! happened. A test that fails on five honest boxes is the answer the owner needs, and
//! the answer to "why did this change not merge". So a non-zero step does not stop
//! this command: the run report is digested, signed and published exactly as a green
//! one would be, and the exit code reports that the *loop* worked. What the volunteer's
//! failure is *not* allowed to do is pretend: nothing here re-runs a failing step, and
//! nothing here declines to publish one.
//!
//! # What is enforced rather than hoped for
//!
//! * **the sandbox** — [`backend::admit`] with a [`Purpose::Quorum`] spec, which is the
//!   same gate `gitiup doctor --sandbox` describes: the rung must probe clean *here*,
//!   it must deny egress in the kernel, and the opt-in `plain` rung is refused outright.
//! * **egress** — default-deny, which is what [`Spec::new`] means and what `admit`
//!   insists on for a stranger's job. An allowlist would make the denial
//!   proxy-enforced rather than kernel-enforced on some backends and is therefore not
//!   this command's to offer.
//! * **the clock** — `SOURCE_DATE_EPOCH` is set in the step environment, so a build
//!   that honours it (and the ones the reproducibility document names do) produces the
//!   same bytes on two machines. It is `0` unless the operator pins one, because a
//!   default taken from *this* box's clock is a digester that cannot agree with anyone.
//! * **the logs** — the digest comes from [`gitiup_run::manifest_for`], which is the
//!   `repro` profile of [docs/reproducibility.md](../../../docs/reproducibility.md)
//!   applied, not requested: the same computation `gitiup run --execute` performs and
//!   `gitiup verify attestation` recomputes.
//!
//! # What it deliberately does not do
//!
//! * **no fetch, no checkout.** The workspace is the operator's: point `--workspace` at
//!   a checkout of the round's head and the run is attested against that commit. This
//!   command refuses a checkout whose `HEAD` is not the round's head rather than
//!   signing a result for a commit it did not run; moving commits into place is
//!   `gitiup change checkout` (giti-b2z.5).
//! * **no publishing of anything simulated.** `--dry-run` takes no lease, writes no
//!   ref and needs no sandbox: it prints the attestation it *would* sign, at
//!   `tier: simulated`, and publishes nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gitiup_attest::{AttestationDoc, Digest, Signer as _, TimeUs, run::WorkflowSource};
use gitiup_quorum::participate::Trusts;
use gitiup_quorum::prelude::*;
use gitiup_quorum::store::{Claim, Cursor};
use gitiup_quorum::{
    Advertisement, Exclusion, Invitation, LeaseRequest, RosterLedger, check_invitation,
    exclusion_of, gate, store, ttl_text,
};
use gitiup_run::{Execution, Plan, PlannedJob, Selector, Simulation, Workflow};
use gitiup_sandbox::backend::{self, Backend, Kind};
use gitiup_sandbox::doctor::Report as DoctorReport;
use gitiup_sandbox::spec::{Enforcement, Purpose, Spec};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::{self, Opened};

/// The `type` string this build implements, quoted so the refusal can name what it
/// refused.
const REVEAL_MODE_OPEN: &str = gitiup_quorum::round::REVEAL_MODE_OPEN;
/// How many advertisements one page of the poll fetches.
const PAGE: usize = 32;

/// Help for `gitiup work`.
pub const WORK_HELP: &str = "\
gitiup work — volunteer for the rounds this store has addressed to this key

USAGE:
    gitiup work [OPTIONS]

    --store <dir> | --remote <name>   where to look for work (required)
        --key <selector>              which key volunteers (default: the current identity)
        --owner <key>                 repeatable · whose signature on a roster *and on a
                                      round* counts (default: this machine's own keys,
                                      and the output says which)
        --once                        one pass and exit (the default)
        --watch <interval>            keep polling: 30s, 5m, 1h …
        --max-jobs <n>                stop after n rounds served in this pass (default: all)
        --dry-run                     plan, digest and sign — publish nothing, lease nothing,
                                      and no sandbox is needed
        --change <id> --job <id>      only rounds for this change / this job id
        --json                        the pass as one machine-readable line

FINDING THE WORK
        --page <n>                    advertisement window (default: 32, max: 256)
        --lease-ttl <interval>        how long to hold a seat for (default: the job's own)

WHERE IT RUNS
        --workspace <dir>             the checkout to run in (default: the current dir)
        --workflow <path>             the workflow file to plan the round's job from
                                      (default: the only file in <workspace>/.github/workflows)
        --sandbox <name>              the backend to run inside; by default the one this
                                      machine's doctor says may serve a stranger's job
        --source-date-epoch <secs>    the clock to hand the build (default: 0; see
                                      docs/reproducibility.md §2.3)
        --out <path|->                with --dry-run: write the attestation's bytes

REMEMBERING THE ROSTER
        --ledger <path>               where this store's highest-seen epoch is kept
                                      (default: <config home>/roster-ledger-<store>.json)
        --no-ledger                   skip the anti-rollback guard, and say so in the output

MEASURING THIS BOX
        --ram-mb <n> --disk-mb <n>    override what this command measured before it checks
                                      your roster claim against the round's requirements

Exit codes: 0 served, or nothing to do (a *failed build* is served: the attestation says
so) · 2 usage · 3 I/O, store unreachable · 6 refused (no sandbox for a stranger's job, a
reveal_mode this build cannot honour, a roster epoch below the ledger, a live lease held
by someone else, the store's own gate) · 7 a signature that does not verify · 8 bytes
that are not their own canonical form, or a result bound to the wrong commit.

The volunteer has no flag for the size of the quorum, the architecture it runs on or the
tier it votes at, on purpose: those are the round's and the owner's, and a volunteer that
could restate them would be voting on its own terms. See docs/quorum.md.
";

/// The switches `gitiup work` accepts.
const SWITCHES: &[&str] = &["--once", "--dry-run", "--no-ledger"];

/// Valued flags for `gitiup work`.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--key",
    "--owner",
    "--watch",
    "--max-jobs",
    "--change",
    "--job",
    "--page",
    "--lease-ttl",
    "--workspace",
    "--workflow",
    "--sandbox",
    "--source-date-epoch",
    "--ledger",
    "--out",
    "--ram-mb",
    "--disk-mb",
    "--passphrase",
    "--passphrase-file",
];

/// `gitiup work …`
pub fn work(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if args.help(WORK_HELP).is_some() {
        return Ok(());
    }
    let interval = watch_interval(&args)?;
    let volunteer = Volunteer::open(&args)?;
    loop {
        let pass = volunteer.serve(&args)?;
        if args.json() {
            participant::print_json(pass.json());
        } else {
            print!("{}", pass.text());
        }
        let code = pass.exit;
        match interval {
            // `--once` (the default): the pass *is* the command, so its refusals are
            // the exit code. A verdict already printed itself above; repeating it on
            // stderr would give a supervisor two places to read one decision.
            None => {
                return if code == 0 {
                    Ok(())
                } else {
                    Err(CliError::verdict(code))
                };
            }
            Some(every) => std::thread::sleep(every),
        }
    }
}

/// `--watch <interval>`, or `None` for one pass.
fn watch_interval(args: &Args) -> Result<Option<Duration>, CliError> {
    if args.on("--once") && args.get("--watch").is_some() {
        return Err(CliError::usage(
            "--once and --watch are alternatives; one pass or the daemon",
        ));
    }
    match args.get("--watch") {
        Some(text) => Ok(Some(parse_duration("--watch", text)?)),
        None => Ok(None),
    }
}

/// A duration written the way an operator writes it: `30s`, `5m`, `2h`, `1d`, or a
/// bare number of seconds.
fn parse_duration(flag: &str, text: &str) -> Result<Duration, CliError> {
    let text = text.trim();
    let usage = || {
        CliError::usage(format!(
            "{flag} wants a duration like 30s, 5m, 2h or 1d (or a bare number of seconds), \
             got '{text}'"
        ))
    };
    if text.is_empty() {
        return Err(usage());
    }
    let (digits, multiplier) = match text.chars().last() {
        Some('s') => (&text[..text.len() - 1], 1u64),
        Some('m') => (&text[..text.len() - 1], 60),
        Some('h') => (&text[..text.len() - 1], 3_600),
        Some('d') => (&text[..text.len() - 1], 86_400),
        Some(_) => (text, 1),
        None => return Err(usage()),
    };
    let seconds: u64 = digits.trim().parse().map_err(|_| usage())?;
    if seconds == 0 {
        return Err(CliError::usage(format!(
            "{flag} is a poll interval and 0 is not one; the store is not a message you can \
             read twice a microsecond"
        )));
    }
    Ok(Duration::from_secs(seconds.saturating_mul(multiplier)))
}

/// Microseconds in a duration, for the flags that speak in `s`/`m`/`h`.
fn parse_micros(flag: &str, text: &str) -> Result<i64, CliError> {
    Ok(parse_duration(flag, text)?
        .as_micros()
        .min(i64::MAX as u128) as i64)
}

// ---------------------------------------------------------------------------
// who is volunteering, and against what
// ---------------------------------------------------------------------------

/// Everything a pass needs that does not change between rounds.
///
/// Built once per pass on purpose: the sandbox probe is a process spawn per backend,
/// the roster revocations are a store walk, and the doctor survey is both. Polling a
/// store every 30 seconds from a machine that re-probed the kernel each time would be
/// a volunteer that costs its owner a core per poll.
struct Volunteer {
    /// The store named by `--store`/`--remote`.
    store: Opened,
    /// The key that signs leases and attestations, and the seat it holds.
    key: gitiup_keys::signer::Key,
    key_id: String,
    /// Whose signature on a roster and on a round record is believed, and where that
    /// came from — the same rule `gitiup select` uses, and printed for the same reason:
    /// a trust root believed by accident is a trust root that lies.
    trust: Trust,
    trust_via: String,
    /// The anti-rollback ledger, and where it lives (`None` when `--no-ledger`).
    ledger: Option<RosterLedger>,
    ledger_path: Option<PathBuf>,
    /// What this machine can confine, probed once.
    doctor: DoctorReport,
    /// The workspace the job runs in.
    workspace: PathBuf,
    /// This box's capabilities, measured rather than repeated from the roster.
    machine: Machine,
    /// Flags, kept because a pass reads them and nothing else should re-parse them.
    dry_run: bool,
    max_jobs: Option<usize>,
    change: Option<String>,
    job: Option<String>,
    page: usize,
    lease_ttl: Option<i64>,
    sandbox: Option<String>,
    source_date_epoch: i64,
    workflow: Option<String>,
    out: Option<String>,
}

impl Volunteer {
    /// Read the flags, open the store, find the key, measure the box.
    fn open(args: &Args) -> Result<Volunteer, CliError> {
        let store = participant::need_store(args)?;
        let here = participant::keystore()?;
        let key = participant::signing_key(args, &here)?;
        let key_id = key.key_id();
        let (trust, trust_via) = participant::owner_trust(args, &here)?;
        let workspace = PathBuf::from(args.get("--workspace").unwrap_or("."));
        let ledger_path = ledger_path(args, &store.what)?;
        let ledger = match (&ledger_path, args.on("--no-ledger")) {
            (_, true) => None,
            (Some(path), false) => Some(RosterLedger::load(path, &store.what)?),
            (None, false) => None,
        };
        let page = match args.get("--page") {
            Some(text) => text.parse::<usize>().map_err(|_| {
                CliError::usage(format!(
                    "--page wants a count of advertisements, got '{text}'"
                ))
            })?,
            None => PAGE,
        };
        Ok(Volunteer {
            doctor: gitiup_sandbox::doctor::survey(),
            machine: Machine::measure(args, workspace.as_path()),
            store,
            key,
            key_id,
            trust,
            trust_via,
            ledger,
            ledger_path,
            workspace,
            dry_run: args.on("--dry-run"),
            max_jobs: match args.get("--max-jobs") {
                Some(text) => Some(text.parse::<usize>().map_err(|_| {
                    CliError::usage(format!("--max-jobs wants a count, got '{text}'"))
                })?),
                None => None,
            },
            change: args.get("--change").map(str::to_string),
            job: args.get("--job").map(str::to_string),
            page: page.clamp(1, store::MAX_PAGE),
            lease_ttl: args
                .get("--lease-ttl")
                .map(|text| parse_micros("--lease-ttl", text))
                .transpose()?,
            sandbox: args.get("--sandbox").map(str::to_string),
            // Rule 6 of docs/reproducibility.md: the clock a build is told is part of
            // its output. Zero is the documented "no clock" value and the only default
            // two independent volunteers can both arrive at without a conversation.
            source_date_epoch: match args.get("--source-date-epoch") {
                Some(text) => text.trim().parse::<i64>().map_err(|_| {
                    CliError::usage(format!(
                        "--source-date-epoch wants a second count, got '{text}'"
                    ))
                })?,
                None => std::env::var("SOURCE_DATE_EPOCH")
                    .ok()
                    .filter(|text| !text.trim().is_empty())
                    .and_then(|text| text.trim().parse::<i64>().ok())
                    .unwrap_or(0),
            },
            workflow: args.get("--workflow").map(str::to_string),
            out: args.get("--out").map(str::to_string),
        })
    }

    /// One pass over everything the store has addressed to this key.
    fn serve(&self, args: &Args) -> Result<Pass, CliError> {
        let now = TimeUs::now();
        let mut pass = Pass {
            store: self.store.what.clone(),
            key_id: self.key_id.clone(),
            trust_via: self.trust_via.clone(),
            dry_run: self.dry_run,
            sandbox: self.sandbox_line(),
            ledger_epoch: self.ledger.as_ref().map(|ledger| ledger.highest_epoch),
            ledger_path: self
                .ledger_path
                .as_ref()
                .map(|path| path.display().to_string()),
            ledger_skipped: args.on("--no-ledger"),
            machine_notes: self.machine.notes.clone(),
            now_us: now.as_us(),
            rounds: Vec::new(),
            looked: 0,
            truncated: false,
            first_refusal: None,
            exit: 0,
        };
        // The revocations are per-pass: the gate needs the same list the volunteer
        // checks itself against, and one walk beats one walk per round.
        let revocations = store::list_revocations(&*self.store.host, &self.trust)?;
        let mut cursor = Cursor::START;
        let mut served = 0usize;
        loop {
            let page = match store::open_rounds_for(
                &*self.store.host,
                &self.key_id,
                now,
                cursor,
                self.page,
            ) {
                Ok(page) => page,
                Err(error) => {
                    return Err(match reveal_mode_refusal(&error) {
                        Some(refusal) => refusal,
                        None => error.into(),
                    });
                }
            };
            let next = page.next;
            for advertisement in page.items {
                if self
                    .change
                    .as_deref()
                    .is_some_and(|want| want != advertisement.change_id)
                {
                    continue;
                }
                if self
                    .job
                    .as_deref()
                    .is_some_and(|want| want != advertisement.job_id)
                {
                    continue;
                }
                pass.looked += 1;
                let report = self.serve_one(&advertisement, &revocations, now)?;
                if report.published() {
                    served += 1;
                }
                let refusal = report.refusal();
                // The pass carries the worst refusal it saw, and a round that published
                // does not become a failure because it also had something to say.
                if let Some((code, _)) = refusal.filter(|_| !report.published()) {
                    if pass.exit == 0 {
                        pass.exit = code;
                    }
                    pass.first_refusal
                        .get_or_insert_with(|| report.detail.clone());
                }
                pass.rounds.push(report);
                if self.max_jobs.is_some_and(|max| served >= max) {
                    pass.truncated = true;
                    return Ok(pass);
                }
            }
            match next {
                Some(after) => cursor = after,
                None => return Ok(pass),
            }
        }
    }

    /// The whole checklist, then the work, for one advertised round.
    fn serve_one(
        &self,
        advertisement: &Advertisement,
        revocations: &[Revocation],
        now: TimeUs,
    ) -> Result<RoundReport, CliError> {
        let mut report = RoundReport {
            change: advertisement.change_id.clone(),
            job: advertisement.job_id.clone(),
            attempt: advertisement.attempt,
            state: "refused",
            code: Some(6),
            detail: String::new(),
            notes: Vec::new(),
            seat: None,
            seats: advertisement.seats.len(),
            round_digest: None,
            challenge: None,
            roster_epoch: Some(advertisement.roster_epoch),
            tier: None,
            lease: None,
            sandbox: None,
            egress: None,
            workflow: None,
            steps: Vec::new(),
            run_digest: None,
            result_digest: None,
            tier_provenance: None,
            normalisation: None,
            result_failed: false,
            published: None,
            source_date_epoch: None,
        };
        let refused = |report: &mut RoundReport, code: u8, detail: String| {
            report.state = "refused";
            report.code = Some(code);
            report.detail = detail;
        };

        // The advertisement is an index and not an authority: believe it through the
        // round it names, or believe neither (giti-zp1.1).
        let round = match store::round_at(
            &*self.store.host,
            &advertisement.change_id,
            &advertisement.job_id,
            advertisement.attempt,
        ) {
            Ok(Some(round)) => round,
            Ok(None) => {
                refused(
                    &mut report,
                    6,
                    format!(
                        "{} advertises a round the store will not return ({} attempt {}); an \
                         index without its record is not an invitation",
                        store::job_ref(&advertisement.change_id, &advertisement.job_id)
                            .map(|name| name.as_str().to_string())
                            .unwrap_or_default(),
                        advertisement.change_id,
                        advertisement.attempt
                    ),
                );
                return Ok(report);
            }
            Err(error) => return Err(mode_or(error, "round")),
        };
        if let Err(error) = advertisement.matches(&round) {
            refused(
                &mut report,
                error.exit_code(),
                format!("the advertisement and the round disagree: {error}"),
            );
            return Ok(report);
        }
        // The roster must be the epoch the round pinned — a round is only auditable
        // against the pool it was drawn from, not against whatever the store points at
        // now.
        let roster = match store::roster_at(&*self.store.host, round.inputs.roster_epoch) {
            Ok(Some(roster)) => roster,
            Ok(None) => {
                refused(
                    &mut report,
                    6,
                    format!(
                        "the store no longer holds roster epoch {}, which this round pinned; \
                         a selection cannot be re-checked against a different pool",
                        round.inputs.roster_epoch
                    ),
                );
                return Ok(report);
            }
            Err(error) => return Err(mode_or(error, "roster")),
        };
        report.roster_epoch = Some(roster.epoch);

        // Steps 1–4 of ADR-0002 D11 happen inside `check_invitation`; these two are the
        // volunteer's own, because the gate would catch them later — after the build.
        let entry = match gate::approval(&roster, &self.key_id, round.inputs.roster_epoch, now) {
            Ok(entry) => entry,
            Err(rejection) => {
                refused(
                    &mut report,
                    rejection.exit_code.unwrap_or(6),
                    format!("{}: {}", rejection.code, rejection.detail),
                );
                return Ok(report);
            }
        };
        if let Some(revoked) = revocations.iter().find(|revocation| {
            (revocation.key_id == self.key_id || revocation.key_id == entry.identity)
                && revocation.voids(round.inputs.roster_epoch)
        }) {
            refused(
                &mut report,
                6,
                format!(
                    "{}: this key was revoked ({}), which voids a round pinned to epoch {}",
                    gate::code::REVOKED,
                    revoked.reason,
                    round.inputs.roster_epoch
                ),
            );
            return Ok(report);
        }
        if let Some(refusal) =
            self.machine
                .refusal(entry, roster.epoch, &round.inputs.required_capabilities)
        {
            refused(&mut report, 6, refusal);
            return Ok(report);
        }
        let slot_free = store::slot_is_free(&*self.store.host, &round, &self.key_id)?;
        let trusts = Trusts {
            owner: &self.trust,
            selector: &self.trust,
            ledger: self.ledger.as_ref(),
            now,
        };
        let (seat, round_digest, challenge, slot_free) =
            match check_invitation(&roster, &round, &self.key_id, &trusts, slot_free) {
                Invitation::Selected {
                    seat,
                    round_digest,
                    challenge,
                    slot_free,
                } => (seat, round_digest, challenge, slot_free),
                Invitation::NotSelected { reserve_rank } => {
                    report.state = "not-selected";
                    report.code = None;
                    report.detail = match reserve_rank {
                        Some(rank) => {
                            format!("on the reserve list at rank {rank}: a reserve waits")
                        }
                        None => "not among this round's seats".to_string(),
                    };
                    return Ok(report);
                }
                Invitation::Refused { reason, exit_code } => {
                    refused(
                        &mut report,
                        exit_code,
                        format!("the invitation was refused: {reason}"),
                    );
                    return Ok(report);
                }
            };
        if !slot_free {
            report.state = "already";
            report.code = None;
            report.detail = "the slot already holds a submission for this round, so there is \
                            nothing for this key to add"
                .to_string();
            return Ok(report);
        }
        // The checklist passed: remember the epoch, so the next store that offers a
        // lower one is refused before it is believed.
        self.remember(&roster)?;
        report.state = "selected";
        report.code = None;
        report.detail = String::new();
        report.seat = Some(seat.rank);
        report.tier = Some(seat.tier.as_str().to_string());
        report.round_digest = Some(round_digest.to_string());
        report.challenge = Some(challenge.to_string());
        // The lease: advice to the other volunteers, taken before the work and released
        // after it. A live lease held by somebody else is a refusal with a deadline, not
        // a reason to build the same thing twice — and a dry run reports it too, because
        // "that seat is somebody else's for another twelve minutes" is the first thing a
        // volunteer wants to know about a job it cannot do.
        let held = store::lease_at(
            &*self.store.host,
            &round.inputs.change_id,
            &round.inputs.job_id,
            &seat.slot,
        )?;
        if let Some(held) = held.filter(|lease| lease.is_live(now) && lease.holder != self.key_id) {
            refused(
                &mut report,
                6,
                format!(
                    "seat {} of {}/{} (attempt {}) is under a live lease held by {} for                      another {}; it is not mine to run, and the seat is theirs to finish — a                      lease expires, so polling again is the whole waiting strategy",
                    short_slot_text(&seat.slot),
                    round.inputs.change_id,
                    round.inputs.job_id,
                    round.inputs.attempt,
                    participant::short(&held.holder),
                    ttl_text(held.remaining_us(now))
                ),
            );
            return Ok(report);
        }
        let mut lease = None;
        if !self.dry_run {
            let request = LeaseRequest::new(
                &round.inputs.change_id,
                &round.inputs.job_id,
                round.inputs.attempt,
                &seat.slot,
                &self.key,
            )
            .at(now)
            .ttl(self.lease_ttl.unwrap_or(advertisement.lease_ttl_us));
            match store::claim_lease(&*self.store.host, &request)? {
                Claim::Claimed { lease: taken, .. } => {
                    report.lease = Some(taken.ttl_us);
                    lease = Some(request);
                    report.notes.push(format!(
                        "slot {} is leased to this key",
                        short_slot_text(&taken.slot)
                    ));
                }
                // Somebody wrote between the read above and this CAS. The seat is not
                // contested advice any more, it is somebody's work: same sentence.
                Claim::Held {
                    holder,
                    remaining_us,
                    ..
                } => {
                    refused(
                        &mut report,
                        6,
                        format!(
                            "seat {} of {}/{} (attempt {}) was taken under this lease: {}                              holds it for another {}",
                            short_slot_text(&seat.slot),
                            round.inputs.change_id,
                            round.inputs.job_id,
                            round.inputs.attempt,
                            participant::short(&holder),
                            ttl_text(remaining_us)
                        ),
                    );
                    return Ok(report);
                }
            }
        }
        // Releasing is best-effort and always attempted: a seat whose work is published
        // has no reason to stay leased until the TTL.
        let outcome = self.run_the_job(&round, &challenge, &mut report);
        if let Some(request) = &lease {
            let forgotten = store::release_lease(&*self.store.host, request)
                .err()
                .map(|error| format!("the lease was not released: {error}"));
            report.notes.extend(forgotten);
        }
        let doc = match outcome? {
            None => return Ok(report),
            Some(doc) => doc,
        };
        if self.dry_run {
            report.state = "simulated";
            report.code = None;
            report.detail = "nothing was published: --dry-run leases nothing and writes \
                             nothing"
                .to_string();
            if let Some(path) = &self.out {
                participant::write_out(path, &doc.manifest.canonical_bytes()?)?;
                report.notes.push(format!("wrote the manifest to {path}"));
            }
            return Ok(report);
        }
        match store::publish_attestation(&*self.store.host, &round, &roster, &doc, revocations, now)
        {
            Ok(oid) => {
                report.published = Some(format!(
                    "{} · {}",
                    store::reveal_ref(&round.inputs.change_id, &round.inputs.job_id, &seat.slot)
                        .map(|name| name.as_str().to_string())
                        .unwrap_or_else(|_| "refs/gitiup/reveal/…".to_string()),
                    oid.hex()
                ));
                report.state = "published";
                report.detail = if report.result_failed {
                    "the run failed and the failure is what was signed and published: a \
                     quorum agrees on what happened, not on green ticks"
                        .to_string()
                } else {
                    String::new()
                };
            }
            Err(error) => {
                // The gate's own token and code, verbatim: the volunteer is being told
                // the same sentence the verdict would have written, and a store that
                // says `wrong_commit` must not be heard as a generic write failure.
                let refusal = gate::admit(&roster, &round, &doc, revocations, now).err();
                let (code, sentence) = match refusal {
                    Some(rejection) => (
                        rejection.exit_code.unwrap_or(6),
                        format!(
                            "the store refused the attestation: {}: {}",
                            rejection.code, rejection.detail
                        ),
                    ),
                    None => (
                        error.exit_code(),
                        format!("the store refused the attestation: {error}"),
                    ),
                };
                refused(&mut report, code, sentence);
            }
        }
        Ok(report)
    }

    /// Plan, run (or simulate), digest and sign. `Ok(None)` means the plan refused and
    /// the report already says so.
    fn run_the_job(
        &self,
        round: &Round,
        challenge: &Digest,
        report: &mut RoundReport,
    ) -> Result<Option<AttestationDoc>, CliError> {
        let (path, text) = match self.workflow_file() {
            Ok(found) => found,
            Err(error) => {
                report.state = "refused";
                report.code = Some(error.code);
                report.detail = error.message.clone();
                return Ok(None);
            }
        };
        let workflow = Workflow::parse(&path, &text)?;
        // The round's `job_id` *is* the plan's job plus its matrix arm, spelled exactly
        // the way `gitiup change submit` spelled it when it opened the round
        // (`build/matrix/<arm>`); matching on the spelling rather than re-deriving it
        // here is what keeps one volunteer from running a different arm than the four
        // others.
        let selector = Selector {
            job: Some(job_of_round_id(&round.inputs.job_id)),
            matrix: Default::default(),
        };
        let plan = Plan::build(&workflow, &selector)?;
        let Some(planned) = plan
            .jobs
            .iter()
            .find(|planned| round_job_id(planned) == round.inputs.job_id)
        else {
            report.state = "refused";
            report.code = Some(6);
            report.detail = format!(
                "{path} plans no run called `{}`; this store's round names a job this \
                 workflow does not: it offers {}",
                round.inputs.job_id,
                plan.jobs
                    .iter()
                    .map(round_job_id)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Ok(None);
        };
        report.workflow = Some(format!("{path} · {}", planned.id));
        report.steps = planned
            .steps
            .iter()
            .map(|step| (step.name.clone(), None))
            .collect();
        self.check_head(round, report)?;
        if report.state == "refused" {
            return Ok(None);
        }
        let source = WorkflowSource::from_text(path, text);
        let runner = format!("gitiup {}", env!("CARGO_PKG_VERSION"));
        let event = workflow.event_for(None)?;
        let manifest = if self.dry_run {
            let mut simulation = Simulation::new(round.inputs.head_oid.clone(), source, &runner);
            simulation.event = event;
            simulation.matrix = planned.matrix.clone();
            simulation.now_us = Some(now_us()?);
            let produced = gitiup_run::simulate_report(&plan, planned, &simulation)?;
            gitiup_run::manifest_for(&produced)?
        } else {
            let admitted = match self.confine() {
                Ok(admitted) => admitted,
                Err(error) => {
                    report.state = "refused";
                    report.code = Some(error.code);
                    report.detail = error.message.clone();
                    if let Some(note) = error.hint {
                        report.notes.push(note);
                    }
                    return Ok(None);
                }
            };
            let sandbox = admitted.seam.as_ref();
            report.sandbox = Some(admitted.backend.clone());
            report.egress = Some(admitted.egress.clone());
            let mut notes = vec![format!(
                "the clock was pinned to SOURCE_DATE_EPOCH={} before the first step \
                 (docs/reproducibility.md §2.3)",
                self.source_date_epoch
            )];
            notes.extend(admitted.warnings);
            let mut execution = Execution::new(
                round.inputs.head_oid.clone(),
                source,
                sandbox.name(),
                &self.workspace,
                &runner,
            );
            execution.event = event;
            execution.now_us = Some(now_us()?);
            execution.notes = notes;
            execution.extra_env = self.reproducibility_env();
            report.source_date_epoch = Some(self.source_date_epoch);
            let produced = gitiup_run::execute(&plan, planned, sandbox, &execution)?;
            let manifest = gitiup_run::manifest_for(&produced)?;
            report.steps = produced
                .steps
                .iter()
                .map(|step| (step.name.clone(), Some(step.exit_code)))
                .collect();
            report.result_failed = produced.steps.iter().any(|step| step.exit_code != 0);
            manifest
        };
        let mut manifest = manifest;
        manifest.claims.verifier_challenge = Some(challenge.clone());
        manifest.normalize();
        report.run_digest = Some(manifest.digest()?.to_string());
        report.result_digest = Some(manifest.result_digest()?.to_string());
        report.tier_provenance = Some(manifest.result.provenance.tier.as_str().to_string());
        report.normalisation = Some(manifest.result.provenance.normalisation_version);
        let mut doc = AttestationDoc::new(manifest);
        doc.sign(&self.key)?;
        Ok(Some(doc))
    }

    /// Record the epoch the checklist just believed, so a later, lower one is a refusal.
    fn remember(&self, roster: &Roster) -> Result<(), CliError> {
        let (Some(ledger), Some(path)) = (&self.ledger, &self.ledger_path) else {
            return Ok(());
        };
        let mut ledger = ledger.clone();
        if ledger.highest_epoch >= roster.epoch && ledger.epochs.contains_key(&roster.epoch) {
            return Ok(());
        }
        ledger.record(roster)?;
        ledger.save(path)?;
        Ok(())
    }

    /// Where this box's work would run, or the refusal that names the ladder it tried.
    fn confine(&self) -> Result<Confined, CliError> {
        confine(&self.doctor, self.sandbox.as_deref(), &self.workspace)
    }

    /// The workflow file to plan from: `--workflow`, or the one file the workspace has.
    fn workflow_file(&self) -> Result<(String, String), CliError> {
        if let Some(path) = &self.workflow {
            let text = std::fs::read_to_string(path)
                .map_err(|why| CliError::io(format!("reading '{path}': {why}")))?;
            return Ok((path.clone(), text));
        }
        let dir = self.workspace.join(".github/workflows");
        let mut found: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yml") | Some("yaml")
                ) {
                    found.push(path);
                }
            }
        }
        found.sort();
        match found.as_slice() {
            [] => Err(CliError::refused(
                format!(
                    "no workflow file in {} to plan the round's job from",
                    dir.display()
                ),
                "point --workspace at the checkout the round is about, or name the file with \
                 --workflow <path>",
            )),
            [only] => {
                let text = std::fs::read_to_string(only)
                    .map_err(|why| CliError::io(format!("reading '{}': {why}", only.display())))?;
                Ok((only.display().to_string(), text))
            }
            many => Err(CliError::refused(
                format!(
                    "{} holds {} workflow files and the round does not say which is its job",
                    dir.display(),
                    many.len()
                ),
                format!(
                    "name one with --workflow <path> ({}); guessing which file a stranger's \
                     round meant is guessing the verdict",
                    many.iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }

    /// The workspace must be a checkout of the commit the round is about.
    ///
    /// The attestation is going to name the round's head oid, so running whatever happens
    /// to be in this directory and signing it as that commit would be the one forgery no
    /// downstream check can see. A directory with no git metadata at all is a note and
    /// not a refusal — a volunteer may stage a checkout any way it likes — but the report
    /// says the binding rests on the store's word alone.
    fn check_head(&self, round: &Round, report: &mut RoundReport) -> Result<(), CliError> {
        match crate::run::repository_head_in(&self.workspace) {
            Some(head) if head == round.inputs.head_oid => Ok(()),
            Some(head) => {
                report.state = "refused";
                report.code = Some(6);
                report.detail = format!(
                    "{} is at {head} and this round is about {}; refusing to attest a run of \
                     a commit the round did not ask about",
                    self.workspace.display(),
                    round.inputs.head_oid
                );
                Ok(())
            }
            None => {
                report.notes.push(format!(
                    "no git metadata in {}: the run is bound to {} on the store's word alone",
                    self.workspace.display(),
                    round.inputs.head_oid
                ));
                Ok(())
            }
        }
    }

    /// The environment that makes two machines' logs hash the same, written into every
    /// step: the clock (§2.3 rule 6), the locale (§2.4 rule 10) and the zone.
    fn reproducibility_env(&self) -> std::collections::BTreeMap<String, String> {
        [
            ("SOURCE_DATE_EPOCH", self.source_date_epoch.to_string()),
            ("LC_ALL", "C".to_string()),
            ("LANG", "C".to_string()),
            ("TZ", "UTC".to_string()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
    }

    /// One line about what a run here would be confined by.
    fn sandbox_line(&self) -> String {
        if self.dry_run {
            return "--dry-run: nothing is executed, so no sandbox is needed".to_string();
        }
        match self.doctor.active.as_deref() {
            Some(name) => format!(
                "{name} — {}",
                self.doctor
                    .backends
                    .iter()
                    .find(|backend| backend.name == name)
                    .map(|backend| backend.enforcement.label())
                    .unwrap_or("?")
            ),
            None => "nothing here may serve a stranger's job".to_string(),
        }
    }
}

/// A backend this machine admitted for a stranger's job, plus the seam that runs it.
struct Confined {
    /// The backend's own name, the word that lands in `provenance.sandbox`.
    backend: String,
    /// How the egress denial is enforced, in the library's words.
    egress: String,
    /// The probe's loud messages (an unverified property, a banner).
    warnings: Vec<String>,
    /// The runner's seam: the same backend opened through `gitiup-run`, which is the
    /// crate that owns what `tier: local` means.
    seam: Box<dyn gitiup_run::sandbox::Sandbox>,
}

/// The gate a stranger's job passes before a single step runs.
///
/// Two gates, and both are the library's own: this machine's doctor must say a
/// stranger's job may be served here, and [`backend::admit`] must admit the named
/// backend for a [`Purpose::Quorum`] spec — which is what refuses the opt-in `plain`
/// rung, and any rung whose egress denial a job could walk around. The refusal names
/// every rung that was tried, because "no sandbox" is a fact about this host and the
/// person reading it has a package to install.
fn confine(
    doctor: &DoctorReport,
    wanted: Option<&str>,
    workspace: &Path,
) -> Result<Confined, CliError> {
    let ladder = doctor
        .backends
        .iter()
        .map(|candidate| format!("{}: {}", candidate.name, candidate.status()))
        .collect::<Vec<_>>()
        .join(", ");
    let name = match wanted {
        Some(name) => name.to_string(),
        None => doctor.active.clone().unwrap_or_default(),
    };
    if name.is_empty() {
        return Err(CliError::refused(
            format!(
                "no sandbox on this machine may serve a stranger's job; the ladder it tried \
                 was {ladder}"
            ),
            "install or enable one rung that denies egress in the kernel (docker, podman, \
             bwrap, landlock on ABI 4+, unshare) and run `gitiup doctor --sandbox` to see \
             which line fails and why; until then `gitiup run` plans and attests as \
             `simulated`, which is the honest tier and says so on its face",
        ));
    }
    let rung = backend::open(&name).map_err(CliError::from)?;
    // The same shape of spec the runner will use: writable checkout, a scratch of its
    // own, no network at all, and the purpose that raises the bar.
    let scratch = scratch_dir()?;
    let spec = Spec::new(workspace, &scratch)
        .with_writable(workspace)
        .with_purpose(Purpose::Quorum);
    let admitted = match backend::admit(rung.as_ref(), &spec) {
        Ok(admitted) => admitted,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&scratch);
            // The refusal is the library's and so is its code; the ladder is added to
            // the hint, because the person reading "this backend may not serve a quorum
            // job" is about to choose between installing something and giving up.
            let hint = match error.hint() {
                Some(hint) => format!("{hint} · the ladder here was {ladder}"),
                None => format!("the ladder here was {ladder}"),
            };
            return Err(CliError::scored(
                error.exit_code(),
                error.to_string(),
                Some(hint),
            ));
        }
    };
    let _ = std::fs::remove_dir_all(&scratch);
    let seam = gitiup_run::sandbox::open(&admitted.backend).map_err(CliError::from)?;
    Ok(Confined {
        backend: admitted.backend,
        egress: admitted.enforcement.label().to_string(),
        warnings: admitted.warnings,
        seam,
    })
}

/// A scratch directory for the admission probe: the runner makes its own for the steps.
fn scratch_dir() -> Result<PathBuf, CliError> {
    let path = std::env::temp_dir().join(format!("gitiup-work-{}", std::process::id()));
    std::fs::create_dir_all(&path)
        .map_err(|why| CliError::io(format!("creating '{}': {why}", path.display())))?;
    Ok(path)
}

/// The refusal an invitation this build cannot honour gets, or `None` when the error is
/// about something else entirely.
///
/// The library already refuses a record whose `reveal_mode` it cannot enforce
/// ([`Round::validate`], [`gitiup_quorum::job::Advertisement::validate`]) and refuses it
/// with 6, so this function does not decide the code — it makes sure the *sentence* the
/// volunteer reads says the thing that matters: the mode was refused, not quietly read
/// as `open`.
fn reveal_mode_refusal(error: &gitiup_quorum::Error) -> Option<CliError> {
    let detail = error.to_string();
    if !detail.contains("reveal mode") && !detail.contains("reveal_mode") {
        return None;
    }
    Some(CliError::refused(
        format!("an invitation this build cannot honour: {detail}"),
        format!(
            "this build implements \"{REVEAL_MODE_OPEN}\" and nothing else; a sealed round \
             needs the sealed grant path (ADR-0002 D11, giti-zp1.6) and is refused rather \
             than downgraded, because a mode you cannot enforce is a mode you cannot honour"
        ),
    ))
}

/// Same, for an error the caller is about to return instead of a round fetch.
fn mode_or(error: gitiup_quorum::Error, what: &str) -> CliError {
    match reveal_mode_refusal(&error) {
        Some(refusal) => refusal,
        None => {
            let _ = what;
            error.into()
        }
    }
}

/// One round's outcome, as the report prints it and as the JSON carries it.
pub(crate) struct RoundReport {
    change: String,
    job: String,
    attempt: u64,
    /// `published` · `simulated` · `selected` (should not survive a pass) · `refused` ·
    /// `not-selected` · `already`.
    state: &'static str,
    code: Option<u8>,
    detail: String,
    notes: Vec<String>,
    seat: Option<u32>,
    seats: usize,
    tier: Option<String>,
    round_digest: Option<String>,
    challenge: Option<String>,
    roster_epoch: Option<u64>,
    lease: Option<i64>,
    sandbox: Option<String>,
    egress: Option<String>,
    workflow: Option<String>,
    steps: Vec<(String, Option<i64>)>,
    run_digest: Option<String>,
    result_digest: Option<String>,
    tier_provenance: Option<String>,
    normalisation: Option<u32>,
    result_failed: bool,
    published: Option<String>,
    source_date_epoch: Option<i64>,
}

impl RoundReport {
    /// Whether this report is one a supervisor should act on, and its code.
    fn refusal(&self) -> Option<(u8, String)> {
        match self.state {
            "refused" => Some((self.code.unwrap_or(6), self.detail.clone())),
            _ => None,
        }
    }

    /// Whether the seat got an attestation, which is the only thing that resets
    /// `--max-jobs`.
    fn published(&self) -> bool {
        matches!(self.state, "published" | "simulated")
    }

    fn json(&self) -> Value {
        json!({
            "change": self.change,
            "job": self.job,
            "attempt": self.attempt,
            "state": self.state,
            "exit": self.code,
            "detail": self.detail,
            "seat": self.seat,
            "seats": self.seats,
            "tier": self.tier,
            "round_digest": self.round_digest,
            "challenge": self.challenge,
            "roster_epoch": self.roster_epoch,
            "lease_ttl_us": self.lease,
            "sandbox": self.sandbox,
            "egress": self.egress,
            "workflow": self.workflow,
            "steps": self.steps.iter().map(|(name, exit)| json!({
                "name": name, "exit": exit
            })).collect::<Vec<Value>>(),
            "run_digest": self.run_digest,
            "result_digest": self.result_digest,
            "provenance_tier": self.tier_provenance,
            "normalisation_version": self.normalisation,
            "result_failed": self.result_failed,
            "published": self.published,
            "source_date_epoch": self.source_date_epoch,
            "notes": self.notes,
        })
    }

    fn text(&self) -> String {
        let mut out = format!(
            "\n{} · {} · attempt {}\n",
            self.change, self.job, self.attempt
        );
        if let Some(seat) = self.seat {
            out.push_str(&format!(
                "  invitation  seat {seat} of {}{} · round {}",
                self.seats,
                self.tier
                    .as_deref()
                    .map(|tier| format!(" · tier {tier}"))
                    .unwrap_or_default(),
                short(self.round_digest.as_deref().unwrap_or("?")),
            ));
            out.push('\n');
        }
        if let Some(epoch) = self.roster_epoch {
            out.push_str(&format!("  roster      epoch {epoch}\n"));
        }
        if let Some(ttl) = self.lease {
            out.push_str(&format!("  lease       taken for {}\n", ttl_text(ttl)));
        }
        if let Some(sandbox) = &self.sandbox {
            out.push_str(&format!(
                "  sandbox     {sandbox} · egress denied, {}\n",
                self.egress.as_deref().unwrap_or("?")
            ));
        }
        if let Some(workflow) = &self.workflow {
            out.push_str(&format!("  plan        {workflow}\n"));
        }
        if let Some(epoch) = self.source_date_epoch {
            out.push_str(&format!(
                "  clock       SOURCE_DATE_EPOCH={epoch} · LC_ALL=C · TZ=UTC\n"
            ));
        }
        if !self.steps.is_empty() {
            let steps = self
                .steps
                .iter()
                .map(|(name, exit)| match exit {
                    Some(exit) => format!("{name} exit {exit}"),
                    None => name.clone(),
                })
                .collect::<Vec<_>>()
                .join(" · ");
            out.push_str(&format!(
                "  {}        {steps}\n",
                if self.tier_provenance.is_some() {
                    "ran"
                } else {
                    "steps"
                }
            ));
        }
        if let Some(result) = &self.result_digest {
            out.push_str(&format!(
                "  digest      run {} · result {result}\n  tier        {} · normalisation v{}\n",
                short(self.run_digest.as_deref().unwrap_or("?")),
                self.tier_provenance.as_deref().unwrap_or("?"),
                self.normalisation.unwrap_or_default(),
            ));
        }
        if let Some(where_) = &self.published {
            out.push_str(&format!("  published   {where_}\n"));
        }
        if !self.detail.is_empty() {
            out.push_str(&format!("  {:<11} {}\n", self.state, self.detail));
        }
        for note in &self.notes {
            out.push_str(&format!("  note: {note}\n"));
        }
        out
    }
}

/// A digest shortened for a terminal; never a record.
fn short(digest: &str) -> String {
    let body = digest.split(':').nth(1).unwrap_or(digest);
    if body.len() <= 12 {
        digest.to_string()
    } else {
        format!("{}\u{2026}", &body[..12])
    }
}

/// A seat slot, shortened: the first eight hex digits identify it on a terminal.
fn short_slot_text(slot: &str) -> String {
    if slot.len() <= 8 {
        slot.to_string()
    } else {
        format!("{}\u{2026}", &slot[..8])
    }
}

// ---------------------------------------------------------------------------
// what this box can honestly say about itself
// ---------------------------------------------------------------------------

/// The `Path` component that marks a round's job id as one matrix arm.
///
/// The same spelling `gitiup change submit` wrote (ADR-0002's published vector uses
/// `build/matrix/linux-x86_64`), and it is a seed input, so it is a contract and not a
/// display choice.
const ARM_MARKER: &str = "matrix";

/// What this machine measures about itself, in the roster's vocabulary.
///
/// The roster carries a *claim*; the round carries the requirements that claim was
/// selected against. ADR-0002 D7 says the claim is checked again after the run — but a
/// volunteer that discovers the mismatch after building a stranger's tree has burned a
/// machine and published an attestation the verdict will throw away, so it is measured
/// here first, before the lease and before anything is spawned.
///
/// RAM and disk are read from the machine; the image cache and `can_pull` are not
/// measurable without asking a registry, so they are carried from the roster claim and
/// said out loud as exactly that.
struct Machine {
    caps: Capabilities,
    /// Which numbers were measured here and which were taken on trust, for the report.
    notes: Vec<String>,
}

impl Machine {
    fn measure(args: &Args, workspace: &Path) -> Machine {
        let mut notes = Vec::new();
        let sandboxes: Vec<String> = gitiup_sandbox::doctor::survey()
            .backends
            .iter()
            .filter(|backend| backend.available && !backend.opt_in)
            .map(|backend| backend.name.clone())
            .collect();
        if sandboxes.is_empty() {
            notes.push(
                "no sandbox backend probes clean here, so a stranger's job will be refused \
                 whatever the roster claims"
                    .to_string(),
            );
        }
        let ram_mb = match (args.get("--ram-mb"), measured_ram_mb()) {
            (Some(text), _) => text.parse::<u64>().ok().inspect(|value| {
                notes.push(format!("ram: {value} MB, as typed with --ram-mb"));
            }),
            (None, Some(measured)) => {
                notes.push(format!("ram: {measured} MB, read from /proc/meminfo"));
                Some(measured)
            }
            (None, None) => {
                notes.push("ram: not measurable here, so your roster claim was used".to_string());
                None
            }
        };
        let disk_mb = match (args.get("--disk-mb"), measured_disk_mb(workspace)) {
            (Some(text), _) => text.parse::<u64>().ok().inspect(|value| {
                notes.push(format!("disk: {value} MB, as typed with --disk-mb"));
            }),
            (None, Some(measured)) => {
                notes.push(format!(
                    "disk: {measured} MB free on the filesystem holding {}",
                    workspace.display()
                ));
                Some(measured)
            }
            (None, None) => {
                notes.push("disk: not measurable here, so your roster claim was used".to_string());
                None
            }
        };
        Machine {
            caps: Capabilities {
                arch: vec![std::env::consts::ARCH.to_string()],
                ram_mb: ram_mb.unwrap_or(0),
                disk_mb: disk_mb.unwrap_or(0),
                image_cache: Vec::new(),
                can_pull: false,
                sandboxes,
                sandbox_level: strongest_level(),
            },
            notes,
        }
    }

    /// Fill in what nothing measured from the claim being checked, so the filter that
    /// fires is a real one and not an artefact of a zero nobody measured.
    fn with_claim(&self, claimed: &Capabilities) -> (Capabilities, Vec<String>) {
        let mut caps = self.caps.clone();
        let mut filled = Vec::new();
        if caps.ram_mb == 0 {
            caps.ram_mb = claimed.ram_mb;
            filled.push(format!("ram_mb {}", claimed.ram_mb));
        }
        if caps.disk_mb == 0 {
            caps.disk_mb = claimed.disk_mb;
            filled.push(format!("disk_mb {}", claimed.disk_mb));
        }
        caps.image_cache = claimed.image_cache.clone();
        caps.can_pull = claimed.can_pull;
        if !claimed.image_cache.is_empty() || claimed.can_pull {
            filled.push(format!(
                "image cache and can_pull ({})",
                if claimed.can_pull {
                    "may pull"
                } else {
                    "cache only"
                }
            ));
        }
        (caps, filled)
    }

    /// The refusal this box no longer qualifies for, if any — in the same ordered filter
    /// the selection used, so the reason a volunteer reads is the reason it was picked.
    fn refusal(
        &self,
        entry: &RosterEntry,
        epoch: u64,
        requirements: &Requirements,
    ) -> Option<String> {
        let (caps, filled) = self.with_claim(&entry.capabilities);
        let probe = RosterEntry {
            key_id: entry.key_id.clone(),
            public_key: entry.public_key.clone(),
            identity: entry.identity.clone(),
            tier: entry.tier,
            capabilities: caps.clone(),
            epochs_valid: entry.epochs_valid,
            self_signature: None,
        };
        let exclusion = exclusion_of(
            &probe,
            epoch,
            requirements,
            &BTreeSet::new(),
            RosterTier::Anonymous,
        )?;
        let mut sentence = format!(
            "this box no longer meets what the round asks: {exclusion} — the round needs \
             {} and this machine reports {}",
            asked(requirements, &exclusion),
            measured(&caps, &exclusion)
        );
        if !filled.is_empty() {
            sentence.push_str(&format!(
                " (taken from the roster claim, not measured here: {})",
                filled.join(", ")
            ));
        }
        Some(sentence)
    }
}

/// What the round asked for, for the half-sentence a refusal needs.
fn asked(requirements: &Requirements, exclusion: &Exclusion) -> String {
    match exclusion {
        Exclusion::Arch => requirements.arch.clone(),
        Exclusion::Ram => format!("{} MB ram", requirements.ram_mb),
        Exclusion::Disk => format!("{} MB disk", requirements.disk_mb),
        Exclusion::Images => format!("{} pinned image(s)", requirements.image_digests.len()),
        Exclusion::Sandboxes => requirements.sandboxes.join(" or "),
        Exclusion::SandboxLevel => format!("sandbox level {}", requirements.min_sandbox_level),
        other => other.as_str().to_string(),
    }
}

/// What this box says about the same field.
fn measured(caps: &Capabilities, exclusion: &Exclusion) -> String {
    match exclusion {
        Exclusion::Arch => caps.arch.join("/"),
        Exclusion::Ram => format!("{} MB", caps.ram_mb),
        Exclusion::Disk => format!("{} MB", caps.disk_mb),
        Exclusion::Images => format!(
            "{} cached, and it may {}",
            caps.image_cache.len(),
            if caps.can_pull { "pull" } else { "not pull" }
        ),
        Exclusion::Sandboxes => caps.sandboxes.join("/"),
        Exclusion::SandboxLevel => format!("level {}", caps.sandbox_level),
        other => other.as_str().to_string(),
    }
}

/// What one backend is worth on the roster's `sandbox_level` scale (0 none, 1 user
/// namespace, 2 container, 3 plus an egress denial the kernel enforces).
///
/// The scale is the roster's ([`Capabilities::sandbox_level`]) and a volunteer may not
/// grade itself, so this is a measurement rule and not an opinion: containers are the 2
/// because a container isolates reads as well as writes, and the +1 is what
/// [`Purpose::Quorum`] actually insists on — a denial the job cannot route around.
fn sandbox_level(candidate: &Backend) -> u8 {
    if !candidate.available || candidate.opt_in {
        return 0;
    }
    let base = match candidate.kind {
        Kind::Container => 2,
        Kind::Namespace | Kind::InProcess => 1,
        Kind::Plain => 0,
    };
    let egress = u8::from(candidate.enforcement == Enforcement::Kernel);
    (base + egress).min(3)
}

/// The strongest rung here, which is what the filter compares against.
fn strongest_level() -> u8 {
    gitiup_sandbox::backend::detect()
        .iter()
        .map(sandbox_level)
        .max()
        .unwrap_or(0)
}

/// Usable RAM, from the one file that answers it without a subprocess.
fn measured_ram_mb() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kib: u64 = rest
                .trim_end_matches(" kB")
                .trim()
                .parse()
                .map_err(|_| ())
                .ok()?;
            return Some(kib / 1024);
        }
    }
    None
}

/// Free disk under `path`, from `df -Pk` — POSIX, and the only portable way to ask
/// without a syscall this crate has no business making.
fn measured_disk_mb(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().nth(1)?;
    let kib: u64 = line
        .split_whitespace()
        .nth(3)?
        .parse()
        .map_err(|_| ())
        .ok()?;
    Some(kib / 1024)
}

// ---------------------------------------------------------------------------
// the round's job id, read back
// ---------------------------------------------------------------------------

/// The workflow job a round's `job_id` names.
fn job_of_round_id(job_id: &str) -> String {
    match job_id.split_once(&format!("/{ARM_MARKER}/")) {
        Some((job, _)) => job.to_string(),
        None => job_id.to_string(),
    }
}

/// The round id one planned run spells — the inverse of [`job_of_round_id`], and the
/// same function `gitiup change submit` used, so a volunteer cannot plan a different arm
/// from the one four other volunteers were seated on.
fn round_job_id(job: &PlannedJob) -> String {
    if job.matrix.is_empty() {
        return job.id.clone();
    }
    let arm: Vec<&str> = job.matrix.values().map(String::as_str).collect();
    format!("{}/{}/{}", job.id, ARM_MARKER, arm.join("/"))
}

/// The clock the run will claim. Honours `SOURCE_DATE_EPOCH` the way `gitiup run` does:
/// pin it and two runs agree to the microsecond.
fn now_us() -> Result<i64, CliError> {
    if let Ok(text) = std::env::var("SOURCE_DATE_EPOCH") {
        let text = text.trim();
        if !text.is_empty() {
            let seconds: i64 = text.parse().map_err(|_| {
                CliError::usage(format!("SOURCE_DATE_EPOCH is not a second count: {text}"))
            })?;
            return Ok(TimeUs::from_secs(seconds).0);
        }
    }
    Ok(TimeUs::now().0)
}

/// Where this store's anti-rollback ledger lives.
///
/// Per store on purpose ([`RosterLedger`]): an epoch remembered for one repository must
/// not stop a volunteer from serving another. The file name is a hash of the store's
/// description because a store can be named `s3://bucket/a/b` and a file name cannot.
fn ledger_path(args: &Args, store: &str) -> Result<Option<PathBuf>, CliError> {
    if let Some(path) = args.get("--ledger") {
        return Ok(Some(PathBuf::from(path)));
    }
    if args.on("--no-ledger") {
        return Ok(None);
    }
    let home = crate::keys::paths()?;
    let digest = Digest::sha256(store.as_bytes());
    Ok(Some(home.root().join(format!(
        "roster-ledger-{}.json",
        &digest.hex()[..12]
    ))))
}

// ---------------------------------------------------------------------------
// the pass, and what it reports
// ---------------------------------------------------------------------------

/// One pass over the store's advertisements.
pub(crate) struct Pass {
    store: String,
    key_id: String,
    trust_via: String,
    dry_run: bool,
    sandbox: String,
    ledger_epoch: Option<u64>,
    ledger_path: Option<String>,
    ledger_skipped: bool,
    /// What was measured here and what was taken from the roster claim: a capability
    /// check is only as good as its honesty about this.
    machine_notes: Vec<String>,
    now_us: i64,
    rounds: Vec<RoundReport>,
    looked: usize,
    /// Set when `--max-jobs` stopped the pass early.
    truncated: bool,
    /// The first refusal's sentence, kept so the exit code and the explanation name the
    /// same event.
    first_refusal: Option<String>,
    /// The exit code this pass decided on: 0, or the first refusal's.
    exit: u8,
}

impl Pass {
    fn published(&self) -> usize {
        self.rounds
            .iter()
            .filter(|report| report.state == "published")
            .count()
    }

    fn simulated(&self) -> usize {
        self.rounds
            .iter()
            .filter(|report| report.state == "simulated")
            .count()
    }

    fn refused(&self) -> usize {
        self.rounds
            .iter()
            .filter(|report| report.state == "refused")
            .count()
    }

    fn skipped(&self) -> usize {
        self.looked
            .saturating_sub(self.refused() + self.published() + self.simulated())
    }

    fn json(&self) -> Value {
        json!({
            "store": self.store,
            "key_id": self.key_id,
            "trusted_via": self.trust_via,
            "dry_run": self.dry_run,
            "sandbox": self.sandbox,
            "ledger": {
                "highest_epoch": self.ledger_epoch,
                "path": self.ledger_path,
                "skipped": self.ledger_skipped,
            },
            "now_us": self.now_us,
            "looked": self.looked,
            "published": self.published(),
            "simulated": self.simulated(),
            "skipped": self.skipped(),
            "refused": self.refused(),
            "truncated": self.truncated,
            "measured": self.machine_notes,
            "first_refusal": self.first_refusal,
            "exit": self.exit,
            "rounds": self.rounds.iter().map(RoundReport::json).collect::<Vec<Value>>(),
        })
    }

    fn text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "gitiup work — {}", self.store);
        let _ = writeln!(
            out,
            "  volunteer   {} (trusted via {})",
            participant::short(&self.key_id),
            self.trust_via
        );
        let _ = writeln!(out, "  sandbox     {}", self.sandbox);
        let _ = writeln!(
            out,
            "  ledger      {}",
            match (self.ledger_skipped, &self.ledger_path) {
                (true, _) => "--no-ledger: the anti-rollback guard is OFF, and a store \
                              offering an older epoch will not be caught"
                    .to_string(),
                (false, Some(path)) => format!(
                    "{} (highest epoch {})",
                    path,
                    self.ledger_epoch.unwrap_or(0)
                ),
                (false, None) => "no path".to_string(),
            }
        );
        let _ = writeln!(
            out,
            "  advertised  {} round(s) invite this key{}",
            self.looked,
            if self.dry_run {
                " (dry run: nothing will be published)"
            } else {
                ""
            }
        );
        for note in &self.machine_notes {
            let _ = writeln!(out, "  measure     {note}");
        }
        for report in &self.rounds {
            out.push_str(&report.text());
        }
        let _ = writeln!(
            out,
            "\n{} published, {} simulated, {} skipped, {} refused of {} advertised",
            self.published(),
            self.simulated(),
            self.skipped(),
            self.refused(),
            self.looked,
        );
        if let Some(refusal) = &self.first_refusal {
            let _ = writeln!(out, "exit {} — {refusal}", self.exit);
        }
        out
    }
}

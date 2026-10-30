//! `gitiup quorum retry` — the bounded second chance (giti-zp1.7).
//!
//! A disagreement is an invitation to look, not permission to loop. [`crate::dispute`]
//! reads the evidence; this command spends volunteers on it again, once more and with a
//! last time:
//!
//! ```text
//!  refs/gitiup/round/<change>/<job>/0 ──► the attempt being escalated, and its tally
//!                     │
//!        attempt 1:   new round id · new seed (the attempt is a seed input, ADR-0002 D2)
//!                 →   fresh scores → a fresh selection over the roster as it is now
//!                 →   `escalated_from` names the round and the verdict it answers
//!                     │
//!  refs/gitiup/round/<change>/<job>/1 ──► published, and advertised so volunteers see it
//!  refs/gitiup/job/<change>/<job>      ──► moved forward by CAS: attempts only go forward
//! ```
//!
//! # Nothing is edited, and the new round says what it replaces
//!
//! The superseded round, its commitments, its reveals and its filed verdict all stay where
//! they are: an escalation supersedes, it does not overwrite. The new record carries
//! [`Escalation`] — the attempt and round digest it came from, the verdict digest that
//! prompted it when one was filed, and the reason in a sentence — so the chain is readable
//! from the store rather than from whoever remembers running the command. A verdict that
//! could be *improved* by re-running the tally is how a disagreement gets laundered, and
//! [`store::file_verdict`] refuses exactly that; the way out is a new attempt, and this is
//! the command that opens one.
//!
//! # A fresh seed, and therefore a fresh jury
//!
//! The attempt number is inside the seed message, so `attempt + 1` cannot reproduce the
//! selection it is escalating: different scores, different order, different seats. That is
//! not a nicety — re-running the same five machines and hoping for a different answer is
//! the most expensive way to learn nothing — so the command checks its own work: a new
//! round whose seed equalled the old one's would be a bug in the derivation, and it is
//! refused at exit 8 instead of advertised.
//!
//! The escalation is also **wider** by default: [`SelectionPolicy::escalated`] — `n + 2`
//! seats, `reserves + 1`, `required_agree + 1`, never a lower bar. More machines and more
//! agreement required is the only direction a second chance should move in.
//! `--same-policy` keeps the previous numbers, for a job whose seat count is already its
//! whole roster and where widening would only produce an unfilled round.
//!
//! # The cap, and why a flag cannot raise it
//!
//! Attempts are capped per `(change, job)`: `quorum.max_attempts` in the owner's published
//! policy, [`DEFAULT_MAX_ATTEMPTS`] when it says nothing. Exhausting the cap is a state with
//! a name (`attempt_cap_exhausted`) and its own exit code ([`EXIT_ATTEMPTS_EXHAUSTED`]),
//! because "one attempt left" and "no attempts left" are different operational facts and
//! only one of them is worth waiting for. `--max-attempts` may tighten the cap and never
//! loosen it: how much patience a repository has is data its owner signed, and every
//! attempt is paid for by a roster of strangers. Attempts are counted from the store's own
//! refs, so a cap cannot be escaped by losing a local log.
//!
//! # What is refused, and what is only said
//!
//! * A job whose latest attempt is `verified` with nothing diverging is **not** escalated:
//!   a rerun is not a second opinion. When that is the only state, the command exits 6 —
//!   `retry` with nothing to retry is a mistake worth reporting.
//! * The roster the new round pins must exist and be unexpired: an escalation that pinned a
//!   dead epoch would be seating a jury nobody approves any more.
//! * The author's exclusion is carried forward (from the superseded round's own
//!   `exclusions`, or from `--proposer`) and re-checked with [`ProposerExclusion::check`]
//!   against the *new* pool, because the roster may have grown a second box for that
//!   contributor since. A round that let its author back in is refused, not published.
//! * A cap that cannot be widened into a valid policy is a refusal with `--same-policy` as
//!   the way out, never a silently lower bar.
//!
//! Exit codes: 0 everything asked for was opened · 2 usage · 3 store unreachable · 6 refused
//! (nothing to escalate, no rounds, no roster, the author left in the pool, a policy that
//! cannot be honoured) · 7 a signature in the evidence that does not verify · 8 a digest
//! that is not what it names · 9 the attempt cap is exhausted, which is terminal.

use std::collections::{BTreeMap, BTreeSet};

use gitiup_attest::{Digest, TimeUs, Trust};
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::escalate::{AttemptCap, EXIT_ATTEMPTS_EXHAUSTED, Exhausted};
use gitiup_quorum::policy::{self};
use gitiup_quorum::prelude::*;
use gitiup_quorum::verdict::Evaluation;
use gitiup_quorum::{store, verdict};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::{self, Opened};
use crate::quorum;
use crate::select as select_cli;
use crate::verdict as verdict_cli;

/// Help for `gitiup quorum retry`.
pub const RETRY_HELP: &str = "\
gitiup quorum retry — escalate a disputed job to attempt + 1, with a last time

USAGE:
    gitiup quorum retry <CHANGE> [OPTIONS]

Opens the next attempt of every job of <CHANGE> whose latest attempt did not come out
clean: a new round id, a new seed, a new selection over the roster as it is now, and a
pointer back to the attempt it replaces. Superseded evidence is never edited — the old
round, its reveals and its verdict stay in the store, cited by the new round. A job that
verified with nothing dissenting is left alone and says so.

WHERE AND WHEN
    --store <dir> | --remote <name>   the store (required)
    --job <id>                        only this job (a matrix arm is its own job)
    --owner <key|id>                  repeatable: whose signature counts (default: this
                                      machine's own keys, and the report says which)
    --now <time>                      pin the clock used to judge the evidence being
                                      escalated (µs or RFC 3339)
    --tier <t> --sandbox <n>          repeatable; the same yardstick `quorum verdict` uses
    --max-age <age> --max-skew <age>  ...at full freshness and any skew by default

THE NEW ROUND
    --key <selector>                  the selector: signs the round and derives the seed
                                      (default: this machine's current identity)
    --passphrase-file <path|->        ...when that key is passphrase-protected
    --seed-file <path|->              32 raw bytes (or 64 hex) as the selection secret, for
                                      a delegated selector holding no Ed25519 seed
    --proposer <key>                  repeatable; the author, whose whole key family stays
                                      off the jury; defaults to the exclusions the
                                      previous attempt carried
    --exclude <key>                   repeatable; a key to keep off this attempt too
    --reason <text>                   why this attempt exists; defaults to the verdict's own
                                      sentence and is recorded in the new round
    --same-policy                     keep the previous attempt's seat numbers instead of
                                      widening them (default: n + 2 seats, threshold + 1)
    --max-attempts <n>                tighten the cap; may never raise what the published
                                      policy's `quorum.max_attempts` says

THE ACT
    --dry-run                         derive and report, write nothing
    --out <path|->                    also write the new round record's canonical bytes
    --explain                         the selection audit table for the new round
    -j, --json                        one line: every job, seat, cap and refusal
    -h, --help                        this text

Exit: 0 opened · 2 usage · 3 store unreachable · 6 refused (nothing to escalate, no
roster, the author left in the pool) · 7 a signature in the evidence · 8 a digest that is
not what it names · 9 the attempt cap is exhausted — terminal, and asking again changes
nothing.

Try:
    gitiup quorum retry chg-6a6a8eab778ba4d0 --store ./store
    gitiup quorum retry chg-6a6a --store ./store --job build --dry-run
    gitiup quorum retry chg-6a6a --store ./store --reason 'flaky: test_mmap raced tmpfs'
    gitiup quorum retry chg-6a6a --store ./store --max-attempts 2 --json
";

/// Valued flags.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--job",
    "--owner",
    "--now",
    "--tier",
    "--sandbox",
    "--max-age",
    "--max-skew",
    "--key",
    "--seed-file",
    "--passphrase-file",
    "--proposer",
    "--exclude",
    "--reason",
    "--max-attempts",
    "--out",
];

/// Switches.
const SWITCHES: &[&str] = &["--dry-run", "--same-policy", "--explain", "--json"];

/// `gitiup quorum retry <CHANGE> …`.
pub fn retry(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if args.wants_help() || args.positional.first().is_some_and(|first| first == "help") {
        print!("{RETRY_HELP}");
        return Ok(());
    }
    let Some(handle) = args.positional.first().map(String::as_str) else {
        return Err(CliError::usage(
            "`gitiup quorum retry` needs a change: `gitiup quorum retry <CHANGE> --store \
             <dir>`",
        ));
    };
    if args.positional.len() > 1 {
        return Err(CliError::usage(format!(
            "unexpected extra argument '{}'; the change is the only positional",
            args.positional[1]
        )));
    }

    let opened = participant::need_store(&args)?;
    let here = participant::keystore()?;
    let (trust, trusted_by) = participant::owner_trust(&args, &here)?;
    let evaluation = verdict_cli::evaluation_from(&args)?;
    let change = verdict_cli::change_id(&*opened.host, handle)?;
    let published = store::rounds_for(&*opened.host, &change)?;
    if published.is_empty() {
        return Err(CliError::refused(
            format!("{} has no round for change {change}", opened.what),
            "there is nothing to escalate: `gitiup change submit` opens a round per job, \
             and `gitiup select --change <id> … --publish` opens one by hand",
        ));
    }
    let cap = attempt_cap(&args, &*opened.host)?;
    let jobs = jobs_to_consult(&args, &published)?;

    // The selector: the new round's seed is keyed on this key, and the same key signs and
    // advertises the round — so an agent-held key cannot become a selector by derivation.
    let selector = participant::signing_key(&args, &here)?;
    let secret = select_cli::selection_secret(&args, &selector)?;
    let exclusions = args
        .all("--exclude")
        .iter()
        .map(|value| participant::key_id_of(&here, value))
        .collect::<Result<BTreeSet<String>, _>>()?;
    let proposers = if args.all("--proposer").is_empty() {
        None
    } else {
        Some(
            args.all("--proposer")
                .iter()
                .map(|value| participant::key_id_of(&here, value))
                .collect::<Result<Vec<String>, _>>()?,
        )
    };

    let mut runner = Runner {
        args: &args,
        opened: &opened,
        trust: &trust,
        evaluation: &evaluation,
        change: &change,
        cap: &cap,
        selector: &selector,
        secret: &secret,
        exclusions: &exclusions,
        proposers: &proposers,
        revocations: None,
        rosters: BTreeMap::new(),
        rounds: Vec::new(),
        notes: Vec::new(),
    };
    runner.run(&jobs)?;
    // The runner borrows the change id and the cap it was asked to honour, so its answers
    // are taken out of it before the report takes ownership of them.
    let rounds = std::mem::take(&mut runner.rounds);
    let notes = std::mem::take(&mut runner.notes);
    let report = Report {
        store: opened.what.clone(),
        handle: handle.to_string(),
        change,
        trusted_by,
        now: evaluation.now,
        cap,
        dry_run: args.on("--dry-run"),
        rounds,
        notes,
    };
    if args.on("--json") {
        participant::print_json(report.json());
    } else {
        report.print();
    }
    report.exit()
}

// ---------------------------------------------------------------------------
// the cap
// ---------------------------------------------------------------------------

/// The attempt cap in force, read from the store's published policy.
///
/// A policy this machine does not trust is not a cap it enforces — an untrusted document is
/// not the owner's rule yet — so its absence is a note in the report and never a silent
/// adoption of somebody else's number.
fn attempt_cap(args: &Args, host: &dyn gitiup_host::Host) -> Result<AttemptCap, CliError> {
    let trust = crate::policy::show_trust(args)?;
    let from_policy = match policy::resolve_store(host, &trust, policy::At::now()) {
        Ok(resolved) => resolved
            .document
            .as_ref()
            .and_then(|document| document.quorum.as_ref())
            .map(AttemptCap::from_block),
        Err(error) if quorum::policy_is_not_ours(&error) => None,
        Err(error) => return Err(crate::policy::refused(error)),
    };
    match args.get("--max-attempts") {
        Some(text) => {
            let asked = text.parse::<u32>().map_err(|_| {
                CliError::usage(format!("--max-attempts wants a whole number, got '{text}'"))
            })?;
            AttemptCap::explicit(asked, from_policy.as_ref()).map_err(policy_refusal)
        }
        None => Ok(from_policy.unwrap_or_else(AttemptCap::default_cap)),
    }
}

/// A library refusal that already carries its exit code, shaped for this command line.
fn policy_refusal(error: gitiup_quorum::Error) -> CliError {
    CliError::scored(
        error.exit_code(),
        error.message(),
        error.hint().map(str::to_string),
    )
}

// ---------------------------------------------------------------------------
// which jobs
// ---------------------------------------------------------------------------

/// The latest round of each job, filtered by `--job` when it names one.
fn jobs_to_consult<'a>(args: &Args, rounds: &'a [Round]) -> Result<Vec<&'a Round>, CliError> {
    if let Some(job) = args.get("--job") {
        let latest = rounds
            .iter()
            .filter(|round| round.inputs.job_id == job)
            .max_by_key(|round| round.inputs.attempt);
        return match latest {
            Some(round) => Ok(vec![round]),
            None => Err(CliError::refused(
                format!("this store opens no job '{job}' for this change"),
                format!("the jobs it opens: {}", jobs_named(rounds)),
            )),
        };
    }
    let mut jobs: Vec<&str> = rounds
        .iter()
        .map(|round| round.inputs.job_id.as_str())
        .collect();
    jobs.sort();
    jobs.dedup();
    Ok(jobs
        .into_iter()
        .filter_map(|job| {
            rounds
                .iter()
                .filter(|round| round.inputs.job_id == job)
                .max_by_key(|round| round.inputs.attempt)
        })
        .collect())
}

fn jobs_named(rounds: &[Round]) -> String {
    let mut jobs: Vec<&str> = rounds
        .iter()
        .map(|round| round.inputs.job_id.as_str())
        .collect();
    jobs.sort();
    jobs.dedup();
    if jobs.is_empty() {
        "none".to_string()
    } else {
        jobs.join(", ")
    }
}

// ---------------------------------------------------------------------------
// one job's escalation
// ---------------------------------------------------------------------------

/// What one job's escalation decided, in everything the report needs to say.
struct JobEscalation {
    job: String,
    /// `escalated` · `nothing-to-escalate` · `exhausted`.
    state: &'static str,
    from_attempt: u64,
    to_attempt: Option<u64>,
    from_round_digest: String,
    to_round_digest: Option<String>,
    /// The reason recorded in the new round (`nothing-to-escalate` keeps the agreed digest
    /// here instead, because there is nothing to explain).
    reason: String,
    from_state: String,
    from_agreeing: usize,
    from_required: usize,
    from_divergent: usize,
    from_silent: usize,
    from_rejected: usize,
    from_verdict_digest: Option<String>,
    policy_from: SelectionPolicy,
    policy_to: Option<SelectionPolicy>,
    widened: bool,
    seed_from: String,
    seed_to: Option<String>,
    roster_epoch: Option<u64>,
    roster_digest: Option<String>,
    eligible: Option<usize>,
    sufficient: Option<bool>,
    seats: Vec<Seat>,
    /// The superseded attempt's seats, so the report can say who is new.
    seats_from: Vec<String>,
    published: Option<String>,
    advertised: Option<bool>,
    reference: Option<String>,
    rechecked: Option<bool>,
    exhausted: Option<Exhausted>,
    note: Option<String>,
    explain: Option<String>,
}

impl JobEscalation {
    fn code(&self) -> u8 {
        match self.state {
            "exhausted" => EXIT_ATTEMPTS_EXHAUSTED,
            "nothing-to-escalate" => 6,
            _ => 0,
        }
    }

    /// How many of the new seats held no seat in the superseded attempt.
    fn new_seats(&self) -> usize {
        self.seats
            .iter()
            .filter(|seat| !self.seats_from.contains(&seat.key_id))
            .count()
    }

    fn json(&self) -> Value {
        json!({
            "job": self.job,
            "state": self.state,
            "from_attempt": self.from_attempt,
            "attempt": self.to_attempt,
            "from_round_digest": self.from_round_digest,
            "round_digest": self.to_round_digest,
            "reason": self.reason,
            "previous": {
                "state": self.from_state,
                "agreeing": self.from_agreeing,
                "required_agree": self.from_required,
                "divergent_seats": self.from_divergent,
                "silent": self.from_silent,
                "rejected": self.from_rejected,
                "verdict_digest": self.from_verdict_digest,
            },
            "policy": {
                "from": self.policy_from,
                "to": self.policy_to,
                "widened": self.widened,
            },
            "seed": { "from": self.seed_from, "to": self.seed_to },
            "roster": {
                "epoch": self.roster_epoch,
                "digest": self.roster_digest,
            },
            "eligible": self.eligible,
            "sufficient": self.sufficient,
            "seats": self
                .seats
                .iter()
                .map(|seat| {
                    json!({
                        "rank": seat.rank,
                        "key_id": seat.key_id,
                        "identity": seat.identity,
                        "slot": seat.slot,
                        "tier": seat.tier.as_str(),
                        "carried_over": self.seats_from.contains(&seat.key_id),
                    })
                })
                .collect::<Vec<Value>>(),
            "new_seats": self.new_seats(),
            "wrote": {
                "ref": self.reference,
                "oid": self.published,
                "advertised": self.advertised,
                "rechecked": self.rechecked,
            },
            "exhausted": self.exhausted.as_ref().map(exhaustion_json),
            "note": self.note,
            "explain": self.explain,
        })
    }

    fn print(&self, explain: bool) {
        match self.state {
            "nothing-to-escalate" => {
                println!(
                    "  {:<28} nothing to escalate \u{b7} {} \u{b7} {}/{} agree on {}",
                    self.job,
                    self.from_state,
                    self.from_agreeing,
                    self.from_required,
                    short_digest(&self.reason),
                );
                if let Some(note) = &self.note {
                    println!("      {}", one_line(note));
                }
                return;
            }
            "exhausted" => {
                let exhausted = self.exhausted.as_ref().expect("exhaustion carries itself");
                println!("  {:<28} EXHAUSTED ({})", self.job, exhausted.token());
                println!("      {}", one_line(&exhausted.describe()));
                println!("      {}", one_line(&exhausted.hint()));
                return;
            }
            _ => {}
        }
        println!(
            "  {:<28} attempt {} \u{2192} {}{}",
            self.job,
            self.from_attempt,
            self.to_attempt.unwrap_or(0),
            if self.sufficient == Some(false) {
                " \u{b7} NOT FILLED"
            } else {
                ""
            },
        );
        println!("      reason   {}", one_line(&self.reason));
        println!(
            "      from     round {} (attempt {}) \u{b7} {}/{} agreed \u{b7} {} diverging \u{b7} \
             {} silent \u{b7} {} refused",
            short_digest(&self.from_round_digest),
            self.from_attempt,
            self.from_agreeing,
            self.from_required,
            self.from_divergent,
            self.from_silent,
            self.from_rejected,
        );
        if let Some(digest) = &self.from_verdict_digest {
            println!(
                "      verdict  {} filed against attempt {} \u{b7} cited by the new round, \
                 and left exactly where it was",
                digest, self.from_attempt
            );
        }
        if let Some(to) = &self.policy_to {
            println!(
                "      policy   n {} agree {} \u{2192} n {} agree {} ({})",
                self.policy_from.n,
                self.policy_from.required_agree,
                to.n,
                to.required_agree,
                if self.widened {
                    "wider: more machines, a higher bar"
                } else {
                    "the previous numbers, verbatim"
                },
            );
        }
        println!(
            "      seed     {} \u{2192} {} (a different seed is what makes a different jury)",
            short_digest(&self.seed_from),
            short_digest(self.seed_to.as_deref().unwrap_or_default()),
        );
        if let (Some(epoch), Some(digest)) = (self.roster_epoch, &self.roster_digest) {
            println!(
                "      roster   epoch {} ({}) \u{b7} {} eligible",
                epoch,
                short_digest(digest),
                self.eligible.unwrap_or_default()
            );
        }
        println!(
            "      seats    {} of {} asked for{} \u{b7} {} new to this job",
            self.seats.len(),
            self.policy_to.as_ref().map(|p| p.n).unwrap_or(0),
            match self.sufficient {
                Some(true) => "",
                Some(false) => " \u{b7} insufficient, published and not shrunk",
                None => "",
            },
            self.new_seats()
        );
        for seat in &self.seats {
            println!(
                "        #{:<2} {:<16} {:<9} {}",
                seat.rank,
                participant::short(&seat.key_id),
                seat.tier.as_str(),
                short_digest(&seat.handle),
            );
        }
        match (self.published.as_deref(), self.advertised) {
            (Some(oid), Some(true)) => println!(
                "      wrote    {} \u{b7} {} \u{b7} advertised{}",
                self.reference.as_deref().unwrap_or_default(),
                short_digest(oid),
                if self.rechecked == Some(true) {
                    " \u{b7} re-read and re-derived"
                } else {
                    ""
                }
            ),
            (Some(oid), Some(false)) => println!(
                "      wrote    {} \u{b7} {} \u{b7} NOT advertised: its seats are unfilled, so \
                 there is nothing to recruit for",
                self.reference.as_deref().unwrap_or_default(),
                short_digest(oid)
            ),
            (Some(oid), None) => println!("      would write {}", short_digest(oid)),
            (None, _) => println!(
                "      --dry-run: nothing written; the round above is what `retry` would publish"
            ),
        }
        if let (true, Some(table)) = (explain, self.explain.as_ref()) {
            println!("      explain \u{d7} the selection, seat by seat:");
            for line in table.lines() {
                println!("        {line}");
            }
        }
    }
}

struct Runner<'a> {
    args: &'a Args,
    opened: &'a Opened,
    trust: &'a Trust,
    evaluation: &'a Evaluation,
    change: &'a str,
    cap: &'a AttemptCap,
    selector: &'a gitiup_keys::signer::Key,
    secret: &'a SelectionSecret,
    exclusions: &'a BTreeSet<String>,
    proposers: &'a Option<Vec<String>>,
    revocations: Option<Vec<Revocation>>,
    rosters: BTreeMap<u64, Roster>,
    rounds: Vec<JobEscalation>,
    notes: Vec<String>,
}

impl<'a> Runner<'a> {
    fn run(&mut self, jobs: &[&Round]) -> Result<(), CliError> {
        // Read once: who is dead *now* is a property of the store, not of a round.
        self.revocations = Some(store::list_revocations(&*self.opened.host, self.trust)?);
        for previous in jobs {
            let escalation = self.one(previous)?;
            self.rounds.push(escalation);
        }
        Ok(())
    }

    fn roster_at(&mut self, epoch: u64) -> Result<Roster, CliError> {
        if let Some(roster) = self.rosters.get(&epoch) {
            return Ok(roster.clone());
        }
        let roster = store::roster_at(&*self.opened.host, epoch)?.ok_or_else(|| {
            CliError::refused(
                format!("{} holds no roster epoch {epoch}", self.opened.what),
                "the superseded round is only meaningful against the epoch it pinned",
            )
        })?;
        roster.verify(self.trust, self.evaluation.now)?;
        self.rosters.insert(epoch, roster.clone());
        Ok(roster)
    }

    fn one(&mut self, previous: &Round) -> Result<JobEscalation, CliError> {
        let job = previous.inputs.job_id.clone();
        let pinned = self.roster_at(previous.inputs.roster_epoch)?;
        // The round before its evidence, under a trusted selector signature: a tally of a
        // jury that was hand-picked would be a reason to escalate built out of nothing.
        previous.verify(self.trust, &pinned)?;
        let before = store::tally(
            &*self.opened.host,
            previous,
            &pinned,
            self.revocations.as_deref().unwrap_or_default(),
            self.evaluation,
        )?;
        let filed = store::verdict_at(&*self.opened.host, self.change, &job, self.trust)
            .ok()
            .flatten();
        let mut base = JobEscalation {
            job: job.clone(),
            state: "escalated",
            from_attempt: previous.inputs.attempt,
            to_attempt: None,
            from_round_digest: previous.digest()?.to_string(),
            to_round_digest: None,
            reason: args_reason(self.args, &before),
            from_state: before.state.to_string(),
            from_agreeing: before.agreeing,
            from_required: before.required_agree,
            from_divergent: before.divergent.iter().map(|group| group.keys.len()).sum(),
            from_silent: before.missing.len(),
            from_rejected: before.rejected.len(),
            from_verdict_digest: filed
                .as_ref()
                .and_then(|record| record.digest().ok())
                .map(|digest| digest.to_string()),
            policy_from: previous.inputs.policy.clone(),
            policy_to: None,
            widened: false,
            seed_from: previous.seed.to_string(),
            seed_to: None,
            roster_epoch: None,
            roster_digest: None,
            eligible: None,
            sufficient: None,
            seats: Vec::new(),
            seats_from: previous
                .selected
                .iter()
                .map(|seat| seat.key_id.clone())
                .collect(),
            published: None,
            advertised: None,
            reference: None,
            rechecked: None,
            exhausted: None,
            note: None,
            explain: None,
        };

        // A clean `verified` has nothing to escalate, and saying so is the difference
        // between a bounded retry and a loop with good manners.
        if before.state == QuorumState::Verified && before.divergent.is_empty() {
            base.state = "nothing-to-escalate";
            base.reason = before
                .result_digest
                .as_ref()
                .map(|digest| digest.to_string())
                .unwrap_or_default();
            base.note = Some(
                "this attempt reached its threshold with nothing dissenting; a fresh round \
                 would be a rerun and not a second opinion"
                    .to_string(),
            );
            return Ok(base);
        }
        // The cap, asked before a key is unlocked or a byte is written.
        let next = match self
            .cap
            .next(self.change, &job, Some(previous.inputs.attempt))
        {
            Ok(next) => next,
            Err(exhausted) => {
                base.state = "exhausted";
                base.exhausted = Some(exhausted);
                return Ok(base);
            }
        };

        // The roster as it is now: a fresh selection needs a live pool, and re-pinning the
        // superseded round's epoch would re-pick from a roster nobody approves any more.
        let roster = store::current_roster(&*self.opened.host)?.ok_or_else(|| {
            CliError::refused(
                format!(
                    "{} publishes no roster, so nothing can be selected for attempt {next}",
                    self.opened.what
                ),
                "the owner publishes one with `gitiup participant approve --publish`",
            )
        })?;
        roster.verify(self.trust, self.evaluation.now)?;
        if self.evaluation.now.as_us() > roster.valid_until_us {
            return Err(CliError::refused(
                format!(
                    "roster epoch {} expired at {}; a new attempt may not pin it",
                    roster.epoch,
                    TimeUs(roster.valid_until_us).to_rfc3339()
                ),
                "the owner publishes a fresh epoch (`gitiup participant approve`, ADR-0002 \
                 D8): an escalation against a dead epoch seats a jury nobody approves",
            ));
        }

        let policy = if self.args.on("--same-policy") {
            previous.inputs.policy.clone()
        } else {
            let widened = previous.inputs.policy.escalated();
            widened.clone().validate().map_err(|error| {
                CliError::refused(
                    format!("the widened policy for attempt {next} is not usable: {error}"),
                    "an escalation widens seats by 2 and the threshold by 1 and never lowers \
                     a bar; if this job's numbers cannot take that, `--same-policy` re-runs \
                     them as they are",
                )
            })?;
            widened
        };
        // The owner's quarantines, carried into the new attempt through the exclusion set
        // like every other exclusion (giti-zp1.8): the roster is not edited, and the round
        // record publishes who was kept out and why the store says so.
        let kept = crate::quarantine::kept_out(
            self.opened,
            self.trust,
            roster.epoch,
            self.evaluation.now,
        )?;
        for note in &kept.notes {
            self.notes.push(note.clone());
        }
        let proposers: Vec<String> = match self.proposers {
            Some(named) => named.clone(),
            None => previous.inputs.exclusions.iter().cloned().collect(),
        };
        let inputs = RoundInputs {
            schema_version: gitiup_quorum::select::SELECTION_SCHEMA_VERSION,
            kind: None,
            round_kind: gitiup_quorum::derive::ROUND_KIND.to_string(),
            roster_epoch: roster.epoch,
            roster_digest: roster.digest()?,
            change_id: self.change.to_string(),
            head_oid: previous.inputs.head_oid.clone(),
            job_id: job.clone(),
            attempt: next,
            required_capabilities: previous.inputs.required_capabilities.clone(),
            exclusions: previous
                .inputs
                .exclusions
                .iter()
                .chain(self.exclusions.iter())
                .cloned()
                .collect(),
            policy,
        }
        .excluding(&roster, &proposers)?
        .excluding(&roster, &kept.list())?;
        if proposers.is_empty() {
            self.notes.push(format!(
                "job {job}: attempt {} excluded no author and none was named, so attempt \
                 {next} excludes nobody either; `--proposer <key>` names the author whose \
                 family must stay off the jury",
                previous.inputs.attempt
            ));
        }
        let mut round = Round::open(&inputs, &roster, self.secret)?;
        // The mode is the superseded round's: a policy that seals a change's rounds seals
        // its retries, and an escalation that quietly unseals is the downgrade this build
        // refuses wherever a reveal mode appears.
        round.set_reveal_mode(&previous.reveal_mode)?;
        // The evidence chain, inside what the selector signs.
        let escalation = Escalation::new(
            previous,
            base.from_verdict_digest
                .as_deref()
                .map(|text| text.parse::<Digest>())
                .transpose()
                .map_err(CliError::from)?,
            base.reason.clone(),
        )?;
        round.set_escalation(&escalation)?;
        round.sign(self.selector)?;
        let selection = round.selection(&roster)?;
        let check = ProposerExclusion::check(&roster, &inputs, &selection, &proposers);
        if !check.held() {
            return Err(CliError::refused(
                format!(
                    "{} \u{b7} change {} job {job}",
                    check.describe(),
                    self.change
                ),
                "an escalation that let its author's box back into the pool is not a second \
                 opinion; `--proposer <key>` names the author whose family must stay out",
            ));
        }
        // A fresh seed is the whole point of an attempt bump. If the derivation ever stopped
        // mixing the attempt in, this is where it gets caught rather than in a test
        // somewhere else.
        if round.seed == previous.seed {
            return Err(CliError::scored(
                8,
                format!(
                    "attempt {next} of {job} derived the same seed as attempt {}; the \
                     attempt number is a seed input (ADR-0002 D2), so this round would seat \
                     the very jury it is escalating",
                    previous.inputs.attempt
                ),
                Some("this is a bug in the derivation, not a policy to work around".to_string()),
            ));
        }
        base.to_attempt = Some(next);
        base.policy_to = Some(round.inputs.policy.clone());
        base.widened = !self.args.on("--same-policy");
        base.seed_to = Some(round.seed.to_string());
        base.roster_epoch = Some(roster.epoch);
        base.roster_digest = Some(roster.digest()?.to_string());
        base.eligible = Some(selection.eligible);
        base.sufficient = Some(selection.sufficient);
        base.seats = selection.selected.clone();
        base.reference = Some(
            store::round_ref(self.change, &job, next)?
                .as_str()
                .to_string(),
        );
        if self.args.on("--explain") {
            base.explain = Some(selection.explain(&roster));
        }

        if self.args.on("--dry-run") {
            return Ok(base);
        }
        let oid = store::publish_round(&*self.opened.host, &round)?;
        base.published = Some(oid.to_string());
        // The same rule as `gitiup work`'s opening and as `change submit`: an unfilled
        // round is published, because it is evidence, and not advertised, because
        // recruiting for a quorum that cannot happen wastes five strangers' machines.
        base.advertised = Some(if selection.sufficient {
            store::advertise_round(
                &*self.opened.host,
                &round,
                self.selector,
                self.evaluation.now,
            )?;
            true
        } else {
            false
        });
        if let Some(path) = args_out(self.args) {
            participant::write_out(path, &round.canonical_bytes()?)?;
        }
        // Read it back: the store is an index and not a memory, and "published" is only a
        // claim until the ref has been re-read.
        let back =
            store::round_at(&*self.opened.host, self.change, &job, next)?.ok_or_else(|| {
                CliError::refused(
                    format!(
                        "{} did not come back from the store",
                        base.reference.clone().unwrap_or_default()
                    ),
                    "the round was written and could not be read back, which is a store \
                     fault and not a reason to report a quorum nobody can audit",
                )
            })?;
        let back_selection = back.verify_selection(&roster)?;
        base.rechecked = Some(
            back_selection.selected == selection.selected
                && back.seed == round.seed
                && back.inputs.attempt == next
                && back.escalated_from.as_ref() == Some(&escalation),
        );
        Ok(base)
    }
}

/// The exhaustion as a report: its own fields, the token a caller branches on, the code it
/// exits with, and both sentences — a terminal state that makes the caller go read the
/// source to find out what to do next is not a finished state.
fn exhaustion_json(exhausted: &Exhausted) -> Value {
    let mut record = serde_json::to_value(exhausted).unwrap_or(Value::Null);
    if let Some(map) = record.as_object_mut() {
        map.insert("state".into(), json!(exhausted.token()));
        map.insert("exit".into(), json!(u64::from(exhausted.exit_code())));
        map.insert(
            "max_attempts".into(),
            json!(u64::from(exhausted.cap.max_attempts)),
        );
        map.insert("cap_source".into(), json!(exhausted.cap.source.clone()));
        map.insert("describe".into(), json!(exhausted.describe()));
        map.insert("hint".into(), json!(exhausted.hint()));
    }
    record
}

/// `--out`, when it was given.
fn args_out(args: &Args) -> Option<&str> {
    args.get("--out")
}

/// The reason recorded in the new round: the caller's, or the verdict's own sentence.
fn args_reason(args: &Args, before: &verdict::VerdictRecord) -> String {
    match args.get("--reason") {
        Some(text) => text.trim().to_string(),
        None => one_line(&format!("{}: {}", before.state, before.detail)),
    }
}

/// The report.
struct Report {
    store: String,
    handle: String,
    change: String,
    trusted_by: String,
    now: TimeUs,
    cap: AttemptCap,
    dry_run: bool,
    rounds: Vec<JobEscalation>,
    notes: Vec<String>,
}

impl Report {
    /// The worst code across the jobs. 9 ranks above the verdict classes: a job that has
    /// run out of attempts outranks a job that was escalated, because the change as a whole
    /// cannot be moved forward by asking again.
    ///
    /// "Nothing to escalate" is a refusal only when *nothing* was escalated. A change with
    /// two jobs, one disputed and one clean, has been escalated as far as it can be, and a
    /// caller that retried on 6 would loop on the clean job forever — the same reason the
    /// cap gets its own code.
    fn code(&self) -> u8 {
        let opened = self.opened();
        self.rounds
            .iter()
            .map(JobEscalation::code)
            .filter(|code| !(opened > 0 && *code == 6))
            .fold(
                0,
                |one, other| {
                    if rank(other) > rank(one) { other } else { one }
                },
            )
    }

    fn opened(&self) -> usize {
        self.rounds
            .iter()
            .filter(|round| round.state == "escalated")
            .count()
    }

    fn json(&self) -> Value {
        json!({
            "kind": "escalation",
            "change": self.change,
            "handle": self.handle,
            "store": self.store,
            "trusted": self.trusted_by,
            "now": self.now.to_rfc3339(),
            "dry_run": self.dry_run,
            "cap": {
                "max_attempts": self.cap.max_attempts,
                "source": self.cap.source,
                "last_attempt": self.cap.last_attempt(),
            },
            "opened": self.opened(),
            "exit": u64::from(self.code()),
            "jobs": self
                .rounds
                .iter()
                .map(JobEscalation::json)
                .collect::<Vec<Value>>(),
            "notes": self.notes,
        })
    }

    fn print(&self) {
        println!(
            "escalate \u{b7} change {}{} \u{b7} {} \u{b7} trusted: {}",
            self.change,
            if self.handle == self.change {
                String::new()
            } else {
                format!(" (named {})", self.handle)
            },
            self.store,
            self.trusted_by,
        );
        println!(
            "  cap      {} \u{b7} {}",
            self.cap.describe(),
            self.cap.source
        );
        if self.dry_run {
            println!("  mode     --dry-run: nothing was written to the store");
        }
        for round in &self.rounds {
            round.print(round.explain.is_some());
        }
        for note in &self.notes {
            println!("  note: {}", one_line(note));
        }
        println!(
            "  exit {} \u{b7} {} of {} job(s) escalated{}",
            self.code(),
            self.opened(),
            self.rounds.len(),
            match self.code() {
                EXIT_ATTEMPTS_EXHAUSTED =>
                    " \u{b7} at least one job is terminal: no more \
                                            attempts, whatever else happens",
                6 => " \u{b7} nothing was escalated",
                _ => "",
            }
        );
    }

    fn exit(self) -> Result<(), CliError> {
        let code = self.code();
        if code == 0 {
            return Ok(());
        }
        Err(CliError::verdict(code))
    }
}

/// 9 over 8 over 7 over 6 over 0: exhaustion is terminal, and the rest is ADR-0001 D7's
/// order (integrity before authority).
fn rank(code: u8) -> u8 {
    match code {
        9 => 4,
        8 => 3,
        7 => 2,
        6 => 1,
        _ => 0,
    }
}

/// A digest, shortened for a terminal. Display only, never a record.
fn short_digest(digest: &str) -> String {
    let body = digest.strip_prefix("sha256:").unwrap_or(digest);
    if body.len() <= 12 {
        return digest.to_string();
    }
    format!("{}\u{2026}", &body[..12])
}

/// A sentence an error or a verdict wrote across several lines.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_quorum::sample;

    #[test]
    fn every_flag_the_command_accepts_is_in_the_help() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                RETRY_HELP.contains(flag),
                "{flag} is accepted but not documented"
            );
        }
    }

    #[test]
    fn exhaustion_outranks_every_verdict_class() {
        assert_eq!(rank(EXIT_ATTEMPTS_EXHAUSTED), 4);
        assert!(rank(9) > rank(8));
        assert!(rank(8) > rank(7));
        assert!(rank(6) > rank(0));
    }

    #[test]
    fn a_digest_is_shortened_for_a_terminal_only() {
        assert_eq!(short_digest("sha256:short"), "sha256:short");
        assert_eq!(
            short_digest("sha256:0123456789abcdef0000"),
            "0123456789ab\u{2026}"
        );
    }

    #[test]
    fn a_detail_is_one_line() {
        assert_eq!(one_line("a \n b   c"), "a b c");
    }

    /// Widening adds seats and agreement together: an escalation that added seats without
    /// raising the bar would let the same disagreement through with more abstentions.
    #[test]
    fn widening_adds_seats_and_agreement_together() {
        let base = SelectionPolicy::default();
        let widened = base.escalated();
        assert!(widened.n > base.n);
        assert!(widened.required_agree > base.required_agree);
        assert!(widened.reserves > base.reserves);
        assert_eq!(widened.max_per_identity, base.max_per_identity);
        assert!(widened.validate().is_ok());
    }

    /// The exhausted message has to be actionable: a terminal state that only says "no" is
    /// a dead end with an exit code.
    #[test]
    fn exhaustion_says_what_to_do_instead() {
        let cap = AttemptCap::default_cap();
        let exhausted = cap.next("chg-1", "build", Some(2)).unwrap_err();
        assert_eq!(exhausted.token(), "attempt_cap_exhausted");
        assert_eq!(exhausted.exit_code(), 9);
        assert!(exhausted.hint().contains("new attempt of the change"));
    }

    /// The jobs consulted are the *latest* attempt of each job, never attempt 0 of a job
    /// that has since been escalated.
    #[test]
    fn only_the_latest_attempt_of_each_job_is_consulted() {
        let rounds = [round(0, "build"), round(1, "build"), round(0, "test")];
        let args = Args::parse_with(&["x".to_string()], VALUED, SWITCHES).unwrap();
        let jobs = jobs_to_consult(&args, &rounds).unwrap();
        let seen: Vec<(String, u64)> = jobs
            .iter()
            .map(|round| (round.inputs.job_id.clone(), round.inputs.attempt))
            .collect();
        assert_eq!(
            seen,
            vec![("build".to_string(), 1), ("test".to_string(), 0)]
        );
    }

    #[test]
    fn a_named_job_is_filtered_and_an_unknown_one_names_the_alternatives() {
        let rounds = [round(0, "build"), round(0, "test")];
        let args = Args::parse_with(
            &["x".to_string(), "--job".to_string(), "build".to_string()],
            VALUED,
            SWITCHES,
        )
        .unwrap();
        assert_eq!(
            jobs_to_consult(&args, &rounds).unwrap().len(),
            1,
            "a named job is one job"
        );
        let args = Args::parse_with(
            &["x".to_string(), "--job".to_string(), "nope".to_string()],
            VALUED,
            SWITCHES,
        )
        .unwrap();
        let error = jobs_to_consult(&args, &rounds).unwrap_err();
        assert_eq!(error.code, 6);
        assert!(
            error
                .hint
                .unwrap_or_default()
                .contains("the jobs it opens: build, test"),
            "a refusal that could have named the alternatives would have been a dead end"
        );
    }

    /// A signed round at one attempt of one job, for the job-selection tests.
    fn round(attempt: u64, job: &str) -> Round {
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 5, 41);
        let mut inputs = sample::round_inputs(&roster, "chg-000000000000f00d", job);
        inputs.attempt = attempt;
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
        round.sign(&owner).expect("the selector signs");
        round
    }
}

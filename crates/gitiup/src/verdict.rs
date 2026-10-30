//! `gitiup quorum verdict` — the tally, reachable from a shell (giti-zp1.4).
//!
//! [`VerdictRecord::evaluate`](gitiup_quorum::verdict::VerdictRecord) has always been
//! able to decide a round: fetch the round, fetch what its seats submitted, count
//! distinct identities, say `verified` / `failed` / `insufficient`. What was missing was
//! the *shell* — the line an owner runs, the line a `pre-receive` hook runs, and the
//! line that leaves a signed verdict in the store for everyone else to read:
//!
//! ```text
//!  refs/gitiup/round/<change>/<job>/<attempt> ──► the round, re-verified
//!  refs/gitiup/reveal/<change>/<job>/<slot>   ──► one attestation per seat
//!  refs/gitiup/roster/<epoch>                 ──► the epoch the round pinned
//!  refs/gitiup/revocation/<slot>              ──► who is dead *now*
//!                     │
//!       VerdictRecord::evaluate ──► verified · failed · insufficient
//!                     │                 │
//!              stdout, one report       └──► exit 0 · 6 · 7 · 8
//!                     │
//!        --publish ──► refs/gitiup/verdict/<change>/<job>, signed
//! ```
//!
//! # Everything is re-derived, nothing is trusted from the last run
//!
//! The store is an index, not a memory: this command re-fetches the round, the roster
//! epoch the round pinned, every seat's submission and every revocation record, and
//! then re-checks each attestation from scratch — canonical bytes, signature, the
//! round's own bindings (head oid and per-key challenge), freshness **against the clock
//! it is told** (`--now` pins it, so a verdict is reproducible), the tier, and the
//! capability claim against the signed environment. Revocation is evaluated *as of now*
//! for the same reason ([ADR-0002 D9](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)):
//! a key revoked this afternoon voids what it signed last week, and a verdict that
//! remembered the old answer is a verdict that cannot be audited.
//!
//! The round itself is re-verified too, and that is not ceremony. A round record whose
//! seats were hand-picked, or whose roster quietly changed, produces a `verified` tally
//! from perfectly good signatures — it is the one document whose forgery no attestation
//! can notice. So `Round::verify` runs first (seats must be the ones the published seed
//! derives, exit 8 if they are not) and a *trusted* selector signature is required, from
//! the same roots that decide whose roster to believe.
//!
//! # The exit code, and why it is not always the state's
//!
//! | exit | the answer |
//!|------|------------|
//!| 0 | `verified` — enough distinct identities signed the same result digest |
//!| 6 | `failed` or `insufficient` — refused, or not yet |
//!| 7 | a signature in this round's evidence does not verify |
//!| 8 | a digest does not match what it names: non-canonical bytes, the wrong bound commit, a result that is not the one expected |
//!
//! 7 and 8 are not states a tally can be in, so they come from the *evidence*, and
//! [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)'s order decides which one
//! wins: integrity before authority, so a round whose tally came out `verified` anyway
//! still exits 8 when one submission did not hash to what it claimed. That is
//! deliberate. A tally is `verified` when the threshold was met *after* discarding what
//! had to be discarded, and the discarded pile is exactly what the owner has not yet
//! explained; a tool that printed 0 over a broken signature would be telling the gate
//! that the disagreement was resolved when it was only outvoted.
//!
//! A verdict is a result, so it is printed on stdout and carried in the exit code and
//! **stderr stays empty** — one place for a hook to read. Usage (2) and an unreadable
//! store (3) are not verdicts and keep their own codes and their own stream.
//!
//! # `--publish`, or: a verdict is superseded, never edited
//!
//! Filing means signing as this machine's key and CAS-writing
//! `refs/gitiup/verdict/<change>/<job>` ([`store::file_verdict`]). The ref moves when it
//! is empty, when it already holds *this* answer (a retry is not an edit), and when this
//! tally is about a **later attempt** than the one filed. Anything else is refused, with
//! both verdicts printed: the way to launder a disagreement out of a quorum record would
//! be to re-run the tally after the awkward verifier went home and write the tidy answer
//! over the old one, and "the evidence moved" is answered by attempt + 1 with a fresh
//! seed — not by an edit.
//!
//! # `--attest`: the verdict, at the tier a policy can ask for
//!
//! A verdict says what the quorum decided; a `tier: quorum` **attestation** is the same
//! fact stated in the one vocabulary a merge gate's `allowed_tiers` speaks. It is not a
//! second opinion and cannot be a first one: the document is built
//! [`QuorumAttestation::from_verdict`] out of a `verified` verdict — round id and digest,
//! roster epoch and digest, the agreed `ResultDigest`, the seats that carried it — and
//! nothing else can build it ([`gitiup_quorum::attestation`](../gitiup_quorum/attestation/index.rs)).
//! `--attest store` files it in the attestation store for the round's head; `--attest
//! <path|->` hands you the canonical signed bytes. A verdict that is not `verified`
//! produces no document and says why: there is no agreement to attest.
//!
//! # What this command will not do
//!
//! * **re-open a round.** If the seats are wrong, that is `gitiup select`; if they are
//!   voided, that is escalation (giti-zp1.7). A verdict that could fix its own jury is
//!   not a verdict.
//! * **decide what a vote is worth from a flag.** `n`, `required_agree` and the seat list
//!   come from the published round; the only numbers here are the clock and the
//!   attestation policy (`--tier`, `--max-age`), which is the same split `gitiup verify
//!   change` keeps.

use std::collections::BTreeMap;

use gitiup_attest::{Tier, TimeUs, Trust};
use gitiup_host::attest;
use gitiup_quorum::attestation::QuorumAttestation;
use gitiup_quorum::prelude::*;
use gitiup_quorum::verdict::Evaluation;
use gitiup_quorum::{store, verdict};
use serde_json::{Value, json};

use crate::CliError;
use crate::change as change_cli;
use crate::keys::Args;
use crate::participant::{self, Opened};

/// Help for `gitiup quorum verdict`.
pub const VERDICT_HELP: &str = "\
gitiup quorum verdict — what the quorum says about a change, and why

USAGE:
    gitiup quorum verdict <CHANGE> [OPTIONS]

<CHANGE> is a change id (`chg-…`), a 4+ hex prefix of one, or — when rounds were
opened without a change record — the change id those rounds name. Every round the
store holds for it is tallied: one per job, each at its latest attempt.

WHERE TO LOOK
    --store <dir> | --remote <name>   the store (required: a tally is a fact about a store)
    --job <id>                        only this job (a matrix arm is its own job)
    --attempt <n>                     this attempt, not the latest one the store has
    --owner <key|id>                  repeatable: whose signature on a roster, a round,
                                      a revocation or a verdict counts (default: this
                                      machine's own keys, and the output says which)

WHEN, AND HOW STRICT
    --now <time>                      pin the clock (µs or RFC 3339): freshness and
                                      revocation are judged at that instant
    --tier <tier>                     repeatable: provenance tiers accepted (default: local)
    --sandbox <name>                  repeatable: sandbox backends accepted (default: any)
    --max-age <age>                   freshness window: 90s, 24h, 30d, `never`
    --max-skew <age>                  clock skew allowed (default: 5m)

WHAT IT LEAVES BEHIND
    --publish                         sign the verdict with this key and file it at
                                      refs/gitiup/verdict/<change>/<job>; a verdict is
                                      superseded by a later attempt, never edited
    --attest <store|path|->           also emit the `tier: quorum` attestation this verdict
                                      earns: `store` files it among the attestations of
                                      the round's head, a path (or -) gets the canonical
                                      signed bytes. Only a `verified` verdict produces
                                      one, and it is signed with the same key
    --key <selector>                  which key signs (default: the current identity)
    --out <path|->                    the canonical signed verdict bytes
    -j, --json                        one line: every field of the record, plus the store,
                                      the clock and what publishing did
    -h, --help                        this text

A verdict is printed on stdout and carried in the exit code; stderr stays empty.

Exit codes: 0 verified · 2 usage · 3 I/O, store unreachable · 6 refused or not yet
(`failed`, `insufficient`, no rounds, a publish the record refuses) · 7 a signature in
the evidence that does not verify · 8 a digest that is not what it names (a round whose
seats are not the ones its seed derives, a submission bound to another commit).

Try:
    gitiup quorum verdict chg-6a6a8eab778ba4d0 --store ./store
    gitiup quorum verdict chg-6a6a --store ./store --json
    gitiup quorum verdict chg-6a6a --store ./store --job build/matrix/linux-x86_64
    gitiup quorum verdict chg-6a6a --store ./store --publish --key owner
    gitiup quorum verdict chg-6a6a --store ./store --attest store --key owner
    gitiup quorum verdict chg-6a6a --store ./store --now 2026-10-24T00:01:01Z
";

/// Valued flags `gitiup quorum verdict` accepts.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--job",
    "--attempt",
    "--owner",
    "--now",
    "--tier",
    "--sandbox",
    "--max-age",
    "--max-skew",
    "--key",
    "--out",
    "--attest",
];

/// Switches: the two acts, and the two output modes.
const SWITCHES: &[&str] = &["--publish", "--json"];

/// `gitiup quorum verdict <CHANGE> …`.
pub fn verdict(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    // `help` where the change would go, as every other verb in this binary spells it.
    if args.wants_help() || args.positional.first().is_some_and(|first| first == "help") {
        print!("{VERDICT_HELP}");
        return Ok(());
    }
    let Some(handle) = args.positional.first().map(String::as_str) else {
        return Err(CliError::usage(
            "`gitiup quorum verdict` needs a change: `gitiup quorum verdict <CHANGE> --store <dir>`",
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
    let evaluation = evaluation_from(&args)?;
    let tally = tally(&args, &opened, trust, &trusted_by, &evaluation, handle)?;

    if participant::only_bytes(&args) || args.get("--attest").is_some_and(|sink| sink == "-") {
        if args.on("--json") {
            return Err(CliError::usage(
                "--out - and --json cannot share stdout: one is the record's bytes, the \
                 other is the report",
            ));
        }
        // `--out -` means stdout is the record's bytes, so the report stays off it; the
        // note about what was written is in the file's own defence, not on the stream.
    } else if args.on("--json") {
        participant::print_json(tally.json());
    } else {
        tally.print();
    }
    tally.exit()
}

// ---------------------------------------------------------------------------
// the flags
// ---------------------------------------------------------------------------

/// The attestation policy the tally applies, from the flags and the defaults.
///
/// `Evaluation::default()` is the same one a merge gate uses — `local` only, 24h fresh,
/// 5m of skew — so a verdict reached here is the verdict a gate would reach. What the
/// flags may change is *what an attestation has to be* (tier, sandbox, freshness, the
/// clock); what they may never change is *who was asked and how many must agree*, which
/// is the round's and not the caller's to restate.
pub(crate) fn evaluation_from(args: &Args) -> Result<Evaluation, CliError> {
    let mut evaluation = Evaluation::default();
    if let Some(text) = args.get("--now") {
        evaluation.now =
            TimeUs::parse(text).map_err(|e| CliError::usage(format!("--now '{text}': {e}")))?;
    }
    let tiers = args.all("--tier");
    if !tiers.is_empty() {
        evaluation.allowed_tiers = tiers
            .iter()
            .map(|tier| Tier::parse(tier))
            .collect::<Result<Vec<_>, _>>()?;
    }
    evaluation.allowed_sandboxes = args.all("--sandbox");
    if let Some(text) = args.get("--max-age") {
        evaluation.max_age_us = age(text, "--max-age")?.unwrap_or(i64::MAX);
    }
    if let Some(text) = args.get("--max-skew") {
        evaluation.max_clock_skew_us = age(text, "--max-skew")?.unwrap_or(0);
    }
    Ok(evaluation)
}

/// A window spelled the way `gitiup attest gc` spells it, so one `--max-age 30d` means
/// one thing in every command in this binary.
fn age(text: &str, flag: &str) -> Result<Option<i64>, CliError> {
    attest::parse_age(text).map_err(|e| CliError::usage(format!("{flag}: {e}")))
}

// ---------------------------------------------------------------------------
// the tally
// ---------------------------------------------------------------------------

/// One round, tallied: the record, what was written about it, and what writing it did.
struct RoundTally {
    /// The job id, as the round spells it.
    job: String,
    /// The attempt.
    attempt: u64,
    /// The round digest, because the verdict cites it and a reviewer checks it.
    round_digest: String,
    /// The roster epoch the round pinned, and its digest.
    roster_epoch: u64,
    roster_digest: String,
    /// The verdict, signed if a sink asked for bytes.
    record: verdict::VerdictRecord,
    /// Key ids whose signature is on the verdict (empty until `--publish`/`--out`).
    signed_by: Vec<String>,
    /// What `--publish` did, when `--publish` was given.
    filing: Option<store::Filing>,
    /// Where the `tier: quorum` attestation went, when `--attest` was given.
    attestation: Option<Emitted>,
    /// Where the verdict went, for the human line.
    filed_at: Option<String>,
    /// What the round demanded of its seats: `open`, or `sealed` (giti-zp1.6). Printed
    /// because a `verified` over a sealed round and one over an open round are not the same
    /// claim, and whoever reads the line should know which one they got.
    reveal_mode: String,
    /// How many seats had committed, when the round was sealed (`0` otherwise).
    committed: usize,
}

/// What emitting a `tier: quorum` attestation did.
struct Emitted {
    /// The document's own digest — its name in the store.
    digest: String,
    /// Where the bytes went: `store`, or the path they were written to.
    sink: String,
    /// The attestation ref, when they went to a store.
    reference: Option<String>,
    /// Whether that ref already held exactly these bytes (a retry, not a change).
    already: bool,
}

impl RoundTally {
    /// The exit code for this one round: the state's, unless the evidence is broken,
    /// and unless `--publish` was refused.
    fn code(&self) -> u8 {
        let mut code = code_of(&self.record);
        if matches!(self.filing, Some(store::Filing::Refused { .. })) {
            code = worst(code, 6);
        }
        code
    }

    fn json(&self) -> Value {
        // The record verbatim: whatever `gitiup quorum verdict --publish` filed is
        // exactly what `--json` prints, so a script can diff the two.
        let mut body = serde_json::to_value(&self.record).unwrap_or(Value::Null);
        let Some(map) = body.as_object_mut() else {
            return body;
        };
        map.insert("round_digest".into(), json!(self.round_digest));
        map.insert("roster_digest".into(), json!(self.roster_digest));
        map.insert("roster_epoch".into(), json!(self.roster_epoch));
        map.insert(
            "verdict_digest".to_string(),
            json!(self.record.digest().map(|d| d.to_string()).ok()),
        );
        map.insert("signed_by".into(), json!(self.signed_by));
        map.insert("reveal_mode".into(), json!(self.reveal_mode));
        if self.reveal_mode == "sealed" {
            map.insert("committed".into(), json!(self.committed));
        }
        if let Some(filing) = &self.filing {
            let mut out = json!({ "state": filing.token(), "ref": ref_name(&self.record) });
            if let Some(oid) = filing.oid() {
                out["oid"] = json!(oid.hex());
            }
            if let Some(reason) = filing.refusal() {
                out["detail"] = json!(reason);
            }
            if let store::Filing::Superseded {
                previous_attempt, ..
            } = filing
            {
                out["superseded_attempt"] = json!(previous_attempt);
            }
            map.insert("publish".into(), out);
        }
        if let Some(attestation) = &self.attestation {
            map.insert(
                "attestation".into(),
                json!({
                    "tier": "quorum",
                    "digest": attestation.digest,
                    "sink": attestation.sink,
                    "ref": attestation.reference,
                    "already": attestation.already,
                }),
            );
        }
        body
    }

    fn print(&self) {
        println!(
            "{}  {} · {} · attempt {} \u{b7} {} of {} identities agree on {}",
            self.record.state,
            self.record.change_id,
            self.job,
            self.attempt,
            self.record.agreeing,
            self.record.required_agree,
            self.short_result(),
        );
        println!("  {}", self.record.detail);
        println!(
            "  round {} \u{b7} roster epoch {} ({}) \u{b7} seats {} \u{b7} threshold {}",
            short_digest(&self.round_digest),
            self.roster_epoch,
            short_digest(&self.roster_digest),
            self.record.seats,
            self.record.required_agree,
        );
        if self.reveal_mode == "sealed" {
            println!(
                "  sealed (commit-reveal): {}/{} seats committed \u{b7} reveals are counted \
                 against their own promise",
                self.committed, self.record.seats
            );
        }
        if !self.record.counted.is_empty() {
            println!("  counted ({}):", self.record.counted.len());
            for vote in &self.record.counted {
                println!(
                    "    {}  {}  {}  \u{b7} {}",
                    participant::short(&vote.key_id),
                    short_digest(&vote.result_digest.to_string()),
                    vote.tier.as_str(),
                    participant::short(&vote.identity),
                );
            }
        }
        if !self.record.divergent.is_empty() {
            println!("  divergent results ({}):", self.record.divergent.len());
            for group in &self.record.divergent {
                println!(
                    "    {}  \u{2190} {}",
                    short_digest(&group.result_digest.to_string()),
                    group
                        .keys
                        .iter()
                        .map(|k| participant::short(k))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        if !self.record.missing.is_empty() {
            println!(
                "  silent ({}): {}",
                self.record.missing.len(),
                self.record
                    .missing
                    .iter()
                    .map(|k| participant::short(k))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !self.record.rejected.is_empty() {
            println!("  rejected ({}):", self.record.rejected.len());
            for rejection in &self.record.rejected {
                println!(
                    "    {}  {} (exit {})  [{}]",
                    participant::short(&rejection.key_id),
                    rejection.code,
                    rejection.exit_code.unwrap_or(6),
                    rejection
                        .identity
                        .as_deref()
                        .map(participant::short)
                        .unwrap_or_else(|| "no roster entry".to_string()),
                );
                println!("      {}", one_line(&rejection.detail));
            }
        }
        if let (Some(where_), Some(filing)) = (&self.filed_at, &self.filing) {
            match filing.refusal() {
                Some(reason) => println!("  publish refused: {}", one_line(reason)),
                None => println!("  verdict {} at {where_}", filing.token()),
            }
        }
        if let Some(attestation) = &self.attestation {
            println!(
                "  tier: quorum attestation {} \u{b7} {}{}",
                short_digest(&attestation.digest),
                attestation.sink,
                attestation
                    .reference
                    .as_ref()
                    .map(|reference| format!(
                        " \u{b7} {reference}{}",
                        if attestation.already {
                            " (already there)"
                        } else {
                            ""
                        }
                    ))
                    .unwrap_or_default(),
            );
        }
    }

    fn short_result(&self) -> String {
        self.record
            .result_digest
            .as_ref()
            .map(|d| short_digest(&d.to_string()))
            .unwrap_or_else(|| "nothing".to_string())
    }
}

/// The verdict's own code: the state, unless the evidence is broken.
///
/// [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md) orders the classes by what has
/// to be true before the next check means anything: bytes before signatures before
/// policy. So a submission that did not hash to what it names (8), or whose signature
/// did not verify (7), decides the code even when the remaining votes carried the tally
/// — a broken thing in the evidence is not made whole by being outvoted.
pub(crate) fn code_of(record: &verdict::VerdictRecord) -> u8 {
    let state = if record.state.mergeable() { 0 } else { 6 };
    record
        .rejected
        .iter()
        .filter_map(|rejection| rejection.exit_code)
        // Only the integrity classes outrank the tally; a refusal (6) is what the tally
        // already decided to refuse, so it cannot make the answer worse than itself.
        .filter(|code| matches!(code, 7 | 8))
        .fold(state, worst)
}

/// ADR-0001 D7's precedence, expressed as "which of two codes survives": 8 over 7 over 6
/// over 0. Numeric order would put 6 over 0 and 8 over 6 by accident and neither is the
/// rule, so the ranking is written out.
pub(crate) fn worst(one: u8, other: u8) -> u8 {
    if rank(other) > rank(one) { other } else { one }
}

fn rank(code: u8) -> u8 {
    match code {
        8 => 3,
        7 => 2,
        6 => 1,
        _ => 0,
    }
}

/// `refs/gitiup/verdict/<change>/<job>`, or the reason the command has to know it.
fn ref_name(record: &verdict::VerdictRecord) -> String {
    store::verdict_ref(&record.change_id, &record.job_id)
        .map(|name| name.as_str().to_string())
        .unwrap_or_else(|_| format!("verdict/{}/{}", record.change_id, record.job_id))
}

/// Everything one run decided.
struct Tally {
    /// Where the facts came from, in the words the operator used.
    store: String,
    /// The handle that was typed, and the change id it resolved to.
    handle: String,
    change: String,
    /// The clock the verdict is a function of, and the tiers it accepted.
    now: TimeUs,
    allowed_tiers: Vec<Tier>,
    /// Whose signature was believed, said out loud: a verdict believed by accident is
    /// the failure this line exists to prevent.
    trusted_by: String,
    /// One entry per job tallied, in `(job, attempt)` order.
    rounds: Vec<RoundTally>,
    /// Things worth saying that are not about one round.
    notes: Vec<String>,
}

impl Tally {
    /// The worst code across every round tallied — the answer to "may this change
    /// merge on its quorum", which is a question about all of its jobs and not one of
    /// them.
    fn code(&self) -> u8 {
        self.rounds.iter().map(RoundTally::code).fold(0, worst)
    }

    /// The state a human skims: the state of the round that decided the code.
    fn headline(&self) -> String {
        let decided = self.code();
        self.rounds
            .iter()
            .find(|round| round.code() == decided)
            .map(|round| round.record.state.to_string())
            .unwrap_or_else(|| "verified".to_string())
    }

    fn json(&self) -> Value {
        let jobs: Vec<Value> = self.rounds.iter().map(RoundTally::json).collect();
        json!({
            "change": self.change,
            "handle": self.handle,
            "store": self.store,
            "trusted": self.trusted_by,
            "now": self.now.to_rfc3339(),
            "now_us": self.now.as_us(),
            "allowed_tiers": self.allowed_tiers.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
            "state": self.headline(),
            "exit": u64::from(self.code()),
            "jobs": jobs,
            "notes": self.notes,
        })
    }

    fn print(&self) {
        for round in &self.rounds {
            round.print();
        }
        if self.rounds.len() > 1 {
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for round in &self.rounds {
                *counts.entry(round.record.state.as_str()).or_default() += 1;
            }
            println!(
                "  {} \u{b7} {} job(s): {}",
                self.headline(),
                self.rounds.len(),
                counts
                    .iter()
                    .map(|(state, count)| format!("{state} ×{count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!(
            "  exit {} \u{b7} {} \u{b7} read from {} \u{b7} trusted: {}",
            self.code(),
            self.headline(),
            self.store,
            self.trusted_by,
        );
        for note in &self.notes {
            println!("  note: {note}");
        }
    }

    /// The report is already on stdout; the code is the answer.
    fn exit(self) -> Result<(), CliError> {
        let code = self.code();
        if code == 0 {
            return Ok(());
        }
        Err(CliError::verdict(code))
    }
}

/// One run's state while it walks a change's rounds.
///
/// The caches are the reason this is a struct and not one long function: a change with
/// six matrix arms pins one roster epoch and the store carries one revocation list, and
/// fetching — or worse, re-verifying — either of them once per round is how a tally turns
/// into a ref-fetch storm on a store that has other things to do.
struct Runner<'a> {
    args: &'a Args,
    opened: &'a Opened,
    trust: Trust,
    evaluation: &'a Evaluation,
    /// One fetch and one signature check per roster epoch.
    rosters: BTreeMap<u64, Roster>,
    /// Fetched once, on the first round that needs it.
    revocations: Option<Vec<Revocation>>,
    /// `Some` only when a sink (`--publish`, `--out`) asked for bytes to be signed.
    signing: Option<gitiup_keys::signer::Key>,
    /// `--attest`: where the `tier: quorum` attestation goes, when one is earned.
    attest: Option<String>,
    notes: Vec<String>,
    /// The verdicts, in `(job, attempt)` order.
    tallies: Vec<RoundTally>,
}

impl<'a> Runner<'a> {
    fn new(
        args: &'a Args,
        opened: &'a Opened,
        trust: Trust,
        evaluation: &'a Evaluation,
    ) -> Result<Runner<'a>, CliError> {
        // Opening a key is an act, so it happens only for a run that will sign
        // something: a read-only tally needs no keystore at all, which is what lets an
        // auditor with an empty home reach the same answer.
        let signing = if args.on("--publish")
            || args.get("--out").is_some()
            || args.get("--attest").is_some()
        {
            Some(participant::signing_key(args, &participant::keystore()?)?)
        } else {
            None
        };
        Ok(Runner {
            args,
            opened,
            trust,
            evaluation,
            rosters: BTreeMap::new(),
            revocations: None,
            signing,
            attest: args.get("--attest").map(str::to_string),
            notes: Vec::new(),
            tallies: Vec::new(),
        })
    }

    fn run(&mut self, rounds: &[&Round]) -> Result<(), CliError> {
        // Fetched once per run, before any round is tallied: "who is dead" is a property
        // of the store, not of a round, and re-reading it per job would be a store's
        // worth of ref queries for one fact.
        self.revocations = Some(store::list_revocations(&*self.opened.host, &self.trust)?);
        for round in rounds {
            let tally = self.one(round)?;
            self.tallies.push(tally);
        }
        Ok(())
    }

    /// One round: believe the roster, re-derive the round, gather its seats, tally, then
    /// hand the record to whichever sink the flags named.
    fn one(&mut self, round: &Round) -> Result<RoundTally, CliError> {
        let roster = self.roster(round.inputs.roster_epoch)?;
        // The round is the one document no attestation can audit: its seats have to be
        // the seats its own seed derives, under a roster this machine trusts, signed by
        // the selector who was entitled to pick them.
        let facts = round.verify(&self.trust, &roster)?;
        let attestations = store::submissions(&*self.opened.host, round)?;
        if attestations.is_empty() {
            self.notes.push(format!(
                "job {} attempt {}: no seat had submitted anything when the clock said {}",
                round.inputs.job_id,
                round.inputs.attempt,
                self.evaluation.now.to_rfc3339()
            ));
        }
        // A sealed round's other half: how many seats promised something. Read here,
        // separately from the tally's own fetch, because this is reporting: the tally does
        // its own reading and takes nobody's word for what was committed (giti-zp1.6).
        let committed = if round.is_sealed() {
            let filed = store::commitments(&*self.opened.host, round)?;
            if filed.len() < round.selected.len() {
                self.notes.push(format!(
                    "job {} attempt {}: {}/{} seats had committed when the clock said {}; a \
                     sealed seat that committed nothing cannot have its answer counted",
                    round.inputs.job_id,
                    round.inputs.attempt,
                    filed.len(),
                    round.selected.len(),
                    self.evaluation.now.to_rfc3339()
                ));
            }
            filed.len()
        } else {
            0
        };
        let revocations = self.revocations.as_deref().unwrap_or_default();
        // The round picks the flow: a sealed round is tallied against its commitments and
        // an open round is not, and this command is not where that choice gets made.
        let mut record = store::tally(
            &*self.opened.host,
            round,
            &roster,
            revocations,
            self.evaluation,
        )?;
        let signed_by = self.sign(&mut record)?;
        self.write_out(&record)?;
        let filing = self.file(&record)?;
        let attestation = self.emit(round, &record)?;
        let filed_at = filing.as_ref().map(|_| {
            format!(
                "{}{}",
                ref_name(&record),
                filing
                    .as_ref()
                    .and_then(|filing| filing.oid())
                    .map(|oid| format!(" \u{b7} {}", oid.hex()))
                    .unwrap_or_default()
            )
        });
        Ok(RoundTally {
            job: round.inputs.job_id.clone(),
            attempt: round.inputs.attempt,
            round_digest: facts.round_digest.to_string(),
            roster_epoch: roster.epoch,
            roster_digest: facts.roster_digest.to_string(),
            record,
            signed_by,
            filing,
            attestation,
            filed_at,
            reveal_mode: round.reveal_mode.clone(),
            committed,
        })
    }

    /// The epoch a round pinned, fully checked — once per epoch, because `verify` is
    /// signature work and a matrix has many rounds and one roster.
    fn roster(&mut self, epoch: u64) -> Result<Roster, CliError> {
        if let Some(roster) = self.rosters.get(&epoch) {
            return Ok(roster.clone());
        }
        let roster = store::roster_at(&*self.opened.host, epoch)?.ok_or_else(|| {
            CliError::refused(
                format!(
                    "{} holds no roster epoch {epoch} for this round",
                    self.opened.what
                ),
                "the round is only meaningful against the epoch it pinned; fetch that \
                     epoch (`gitiup participant list --epoch`) or the round is unauditable",
            )
        })?;
        roster.verify(&self.trust, self.evaluation.now)?;
        self.rosters.insert(epoch, roster.clone());
        Ok(roster)
    }

    /// Sign the verdict, if a sink needs it to be signed. Returns who signed it.
    fn sign(&self, record: &mut verdict::VerdictRecord) -> Result<Vec<String>, CliError> {
        match &self.signing {
            None => Ok(Vec::new()),
            Some(key) => {
                record.sign(key)?;
                Ok(record.signatures.iter().map(|s| s.key_id.clone()).collect())
            }
        }
    }

    /// `--out` gets the exact canonical bytes a store would hold.
    fn write_out(&mut self, record: &verdict::VerdictRecord) -> Result<(), CliError> {
        if let Some(path) = self.args.get("--out") {
            participant::write_out(path, &record.canonical_bytes()?)?;
            self.notes.push(format!(
                "wrote the signed verdict for {} to {}",
                record.job_id,
                if path == "-" { "stdout" } else { path }
            ));
        }
        Ok(())
    }

    /// `--publish` files the signed record, and says which of the four things filing a
    /// verdict can do just happened.
    fn file(&self, record: &verdict::VerdictRecord) -> Result<Option<store::Filing>, CliError> {
        if self.args.on("--publish") {
            Ok(Some(store::file_verdict(
                &*self.opened.host,
                record,
                &self.trust,
            )?))
        } else {
            Ok(None)
        }
    }

    /// `--attest`: turn the verdict into the `tier: quorum` attestation it earns.
    ///
    /// There is no path here that invents a quorum. The document comes out of
    /// [`QuorumAttestation::from_verdict`], which refuses a verdict that is not
    /// `verified`, and a refused verdict is a note and not a second failure: the tally
    /// already exited 6 because the quorum did not agree, and saying so twice with two
    /// different numbers is how a log becomes unreadable.
    fn emit(
        &mut self,
        round: &Round,
        record: &verdict::VerdictRecord,
    ) -> Result<Option<Emitted>, CliError> {
        let Some(sink) = self.attest.clone() else {
            return Ok(None);
        };
        let attestation = match QuorumAttestation::from_verdict(round, record) {
            Ok(attestation) => attestation,
            Err(error) => {
                self.notes.push(format!(
                    "no quorum attestation for {}: {}",
                    record.job_id,
                    one_line(&error.message())
                ));
                return Ok(None);
            }
        };
        let key = self.signing.as_ref().ok_or_else(|| {
            CliError::refused(
                "a quorum attestation has to be signed by the key that asserts it",
                "`--attest` signs with this machine's key; `--key <name>` names one",
            )
        })?;
        let mut attestation = attestation;
        attestation.sign(key)?;
        let bytes = attestation.canonical_bytes()?;
        let digest = attestation.digest()?.to_string();
        if sink == "store" {
            let subject = gitiup_host::Oid::from_hex(&record.head_oid.hex())
                .map_err(|e| CliError::io(format!("the round's head is not an oid: {e}")))?;
            let actor = gitiup_host::Actor::from(
                participant::short(&attestation.signatures[0].key_id).as_str(),
            );
            let published = attest::publish(&*self.opened.host, &subject, &bytes, actor)
                .map_err(|e| CliError::io(format!("publish the quorum attestation: {e}")))?;
            return Ok(Some(Emitted {
                digest,
                sink: "store".to_string(),
                reference: Some(published.reference.as_str().to_string()),
                already: published.already,
            }));
        }
        participant::write_out(&sink, &bytes)?;
        Ok(Some(Emitted {
            digest,
            sink: if sink == "-" {
                "stdout".to_string()
            } else {
                sink
            },
            reference: None,
            already: false,
        }))
    }
}

/// Fetch, verify, evaluate, and — if asked — sign and file.
fn tally(
    args: &Args,
    opened: &Opened,
    trust: Trust,
    trusted_by: &str,
    evaluation: &Evaluation,
    handle: &str,
) -> Result<Tally, CliError> {
    let change = change_id(&*opened.host, handle)?;
    let published = store::rounds_for(&*opened.host, &change)?;
    let rounds = select_rounds(args, &published)?;
    if rounds.is_empty() {
        return Err(no_rounds(args, opened, &change));
    }
    let mut runner = Runner::new(args, opened, trust, evaluation)?;
    runner.run(&rounds)?;
    Ok(Tally {
        store: opened.what.clone(),
        handle: handle.to_string(),
        change,
        now: evaluation.now,
        allowed_tiers: evaluation.allowed_tiers.clone(),
        trusted_by: trusted_by.to_string(),
        rounds: runner.tallies,
        notes: runner.notes,
    })
}

/// The answer when a change has no quorum to tally — which is a *not yet*, and says how
/// it stops being one.
fn no_rounds(args: &Args, opened: &Opened, change: &str) -> CliError {
    CliError::refused(
        format!(
            "{} has no round for change {change}{}",
            opened.what,
            match args.get("--job") {
                Some(job) => format!(" / job {job}"),
                None => String::new(),
            }
        ),
        "a quorum is opened, not assumed: `gitiup change submit` opens a round per job, \
         and `gitiup select --change <id> --job <id> … --publish` opens one by hand",
    )
}

/// Which rounds to tally: the latest attempt per job by default, `--attempt` to pin one,
/// `--job` to name one.
pub(crate) fn select_rounds<'a>(
    args: &Args,
    rounds: &'a [Round],
) -> Result<Vec<&'a Round>, CliError> {
    let wanted = match_job(args, rounds)?;
    let wanted = match_attempt(args, &wanted)?;
    Ok(latest_attempt_per_job(&wanted))
}

/// `--job`: one arm of a matrix, named. Refusing with the jobs the store *does* open is
/// the whole difference between a typo and a wrong answer.
fn match_job<'a>(args: &Args, rounds: &'a [Round]) -> Result<Vec<&'a Round>, CliError> {
    let Some(job) = args.get("--job") else {
        return Ok(rounds.iter().collect());
    };
    let wanted: Vec<&Round> = rounds
        .iter()
        .filter(|round| round.inputs.job_id == job)
        .collect();
    if wanted.is_empty() {
        return Err(CliError::refused(
            format!("this store opens no job '{job}' for this change"),
            format!(
                "the jobs it opens: {}",
                if rounds.is_empty() {
                    "none".to_string()
                } else {
                    rounds
                        .iter()
                        .map(|round| round.inputs.job_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        ));
    }
    Ok(wanted)
}

/// `--attempt`, or every attempt and the caller keeps the latest.
fn match_attempt<'a>(args: &Args, rounds: &[&'a Round]) -> Result<Vec<&'a Round>, CliError> {
    let Some(text) = args.get("--attempt") else {
        return Ok(rounds.to_vec());
    };
    let attempt = text
        .parse::<u64>()
        .map_err(|_| CliError::usage(format!("--attempt wants a number, got '{text}'")))?;
    let wanted: Vec<&Round> = rounds
        .iter()
        .copied()
        .filter(|round| round.inputs.attempt == attempt)
        .collect();
    if wanted.is_empty() {
        return Err(CliError::refused(
            format!("this store has no attempt {attempt} for this change"),
            "`--attempt 0` is the first one, and each escalation adds one",
        ));
    }
    Ok(wanted)
}

/// The last round of each run of jobs — the input is already ordered by `(job, attempt)`,
/// so this is "keep the last of each run", not a sort.
///
/// "the latest" is the rule because that is what an escalation *means*: attempt 1 exists
/// to replace attempt 0's answer, and a command that reported both would be reporting a
/// quorum that has already been superseded.
fn latest_attempt_per_job<'a>(rounds: &[&'a Round]) -> Vec<&'a Round> {
    let mut latest: Vec<&Round> = Vec::new();
    for round in rounds {
        match latest.last_mut() {
            Some(previous) if previous.inputs.job_id == round.inputs.job_id => {
                *previous = round;
            }
            _ => latest.push(round),
        }
    }
    latest
}

/// The change the rounds are filed under.
///
/// A handle may be the id itself, a 4+ hex prefix of a published change, or an id that
/// only rounds know about (a round can be opened for a change that was never published
/// through `change submit`, and auditing *that* is the point of `gitiup select`'s audit
/// mode). So the store's round index is tried first, verbatim; only a handle with no
/// rounds there gets the prefix treatment.
pub(crate) fn change_id(host: &dyn gitiup_host::Host, handle: &str) -> Result<String, CliError> {
    if !store::rounds_for(host, handle)?.is_empty() {
        return Ok(handle.to_string());
    }
    match change_cli::resolve_handle(host, handle) {
        Ok(found) => Ok(found.change_id.as_str().to_string()),
        // Not a published change either: the caller named a change by hand, and the
        // "no round for change X" refusal below is the honest answer.
        Err(_) => Ok(handle.to_string()),
    }
}

// ---------------------------------------------------------------------------
// formatting
// ---------------------------------------------------------------------------

/// `sha256:abcd…wxyz`, for a terminal. A digest shortened is a digest a human compares by
/// its ends, so this is for reading and never for a record.
fn short_digest(digest: &str) -> String {
    let body = digest.strip_prefix("sha256:").unwrap_or(digest);
    if body.len() <= 12 {
        return digest.to_string();
    }
    format!("sha256:{}\u{2026}{}", &body[..4], &body[body.len() - 4..])
}

/// A detail that may have been written across ten lines by an error message.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_help_text_documents_every_exit_code_it_can_return() {
        for code in ["0", "2", "3", "6", "7", "8"] {
            assert!(
                VERDICT_HELP.contains(code),
                "exit {code} is missing from the help"
            );
        }
        // Every flag the parser accepts is documented, or it does not exist.
        for flag in VALUED {
            assert!(
                VERDICT_HELP.contains(flag),
                "{flag} is accepted but not in the help"
            );
        }
        for flag in SWITCHES {
            assert!(
                VERDICT_HELP.contains(flag),
                "{flag} is accepted but not in the help"
            );
        }
    }

    #[test]
    fn the_exit_code_precedence_is_integrity_first() {
        // 8 over 7 over 6 over 0, which is not the numeric order.
        assert_eq!(worst(0, 6), 6);
        assert_eq!(worst(6, 7), 7);
        assert_eq!(worst(7, 8), 8);
        assert_eq!(worst(8, 6), 8);
        assert_eq!(worst(6, 0), 6);
    }

    #[test]
    fn a_digest_is_shortened_for_a_terminal_only() {
        assert_eq!(
            short_digest("sha256:0123456789abcdef"),
            "sha256:0123\u{2026}cdef"
        );
        assert_eq!(short_digest("sha256:short"), "sha256:short");
        assert_eq!(
            short_digest(&format!("sha256:{}", "a".repeat(64))),
            "sha256:aaaa\u{2026}aaaa"
        );
    }

    #[test]
    fn a_detail_is_one_line() {
        assert_eq!(one_line("a \n b   c"), "a b c");
    }
}

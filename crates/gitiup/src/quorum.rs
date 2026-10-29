//! The quorum half of the command line.
//!
//! Two things live here, because they are the same subject seen from two ends:
//!
//! * [`quorum`] is the `gitiup quorum` verb — today one command, `verdict`, whose own
//!   logic is in [`crate::verdict`];
//! * [`plan`] is the half of `gitiup change submit` that opens a change's rounds.
//!
//! The second is why the first is in this file rather than its own: opening a round and
//! tallying one are the two ends of one mechanism, and a submit that opened rounds no
//! command could decide on would be a half-feature.
//!
//! "Five random users per PR" is only automatic if the command that publishes the change
//! also opens its rounds, so this module turns a change about to be published into the
//! rounds its published policy asked for:
//!
//! ```text
//!  workflow files ──► gitiup-run's planner ──► one round per arm ─┐
//!  the store's policy ──► quorum.default / by_job[glob] ──────────┤ the numbers
//!  the store's policy ──► quorum.requirements ─────────────────────┤ eligibility
//!  the store's roster  ──► epoch + digest + entries ───────────────┤ the pool
//!  the change record   ──► change id · head oid · attempt · author┘ RoundInputs
//!                                                     │
//!                                 Round::open ──► ProposerExclusion::check ──► publish
//! ```
//!
//! # Where every number comes from
//!
//! None of them is a flag. [ADR-0004 D5](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)
//! decided that the tier a repository demands is *data the owner signed* — `quorum.default`
//! and `quorum.by_job[<glob>]` are `SelectionPolicy` verbatim, `quorum.requirements` is
//! `Requirements` verbatim — precisely so this ticket could read a round's numbers out of
//! the policy instead of accepting them from whoever typed the command:
//!
//! * **whether a quorum is demanded** — the resolved policy allows the `quorum` tier *and*
//!   gates the branch the change merges into (`protects`). A policy this machine does not
//!   trust is reported and never applied
//!   ([D3](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)), so a
//!   fork's weaker policy cannot decide what an upstream change needs.
//! * **the job set** — the repository's workflow files through [`gitiup_run`]'s planner, so
//!   a matrix is one round per arm, each with its own seed (ADR-0002 D7). The record's
//!   `workflow.jobs` hint is the fallback for a submit that drafts from no checkout.
//! * **the seats and the eligibility floor** — the policy, per job, longest `by_job` glob
//!   winning, exactly as
//!   [`QuorumBlock::selection_for`](gitiup_quorum::policy::QuorumBlock::selection_for)
//!   spells it.
//! * **the pool** — the store's current roster epoch, pinned by epoch *and* digest so a
//!   later roster rewrite cannot change what this round meant.
//! * **the seed** — keyed on the submitter's own key
//!   ([ADR-0002 D2](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!   That is what "the submitter is the selector" means operationally: whoever publishes the
//!   change is whoever can derive the ordering — and their own boxes are the first thing out
//!   of the pool, which is the only reason the two roles do not collapse into
//!   self-refereeing.
//!
//! # The refusals, and what is only said out loud
//!
//! * Nothing is opened for a change whose policy is absent, untrusted, unsigned or expired.
//!   Those are answers about *whose authority applies*, not about this submit, so they are
//!   printed as notes and the change still publishes: a contributor proposing work into a
//!   store whose policy their keystore does not vouch for is not doing anything wrong, and
//!   the selector who does trust that policy opens the rounds.
//! * A quorum that **is** demanded and **cannot** be opened is a refusal (exit 6) raised
//!   before a single byte is written — no roster in the store, no `quorum.requirements` to
//!   select against, no selector key that can derive a seed, no job to select for, a round
//!   that would seat its own author. Publishing a change that can never reach a verdict while
//!   saying nothing is exactly the silent failure this design exists to avoid. `--no-quorum`
//!   is the way to publish anyway, and the output then says the rounds are missing.
//! * A round that could not fill its `n` seats is **published** with `sufficient: false`, is
//!   not advertised (recruiting for a quorum that cannot happen is worse than escalating —
//!   see [giti-zp1.1](../../../docs/quorum.md)), and is reported with what the D7 filters
//!   rejected. `n` is never lowered to make a round look filled.
//! * Every round is read back from the store and re-derived before the command reports
//!   success: "the published round is re-checked" is the acceptance criterion, and a re-read
//!   is the only check that could notice a store that stored something else.
//!
//! Exit codes are the table the rest of `gitiup` uses (ADR-0001 D7): 0 — including an
//! insufficient round · 6 refused · 7 a signature that does not verify · 8 bytes that are
//! not their own canonical form.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gitiup_attest::{GitOid, Signer as _, Tier, TimeUs};
use gitiup_host::change::ChangeRecord;
use gitiup_quorum::policy::{self, token};
use gitiup_quorum::prelude::*;
use gitiup_quorum::{derive::SelectionSecret, store};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::{self, Args};
use crate::participant::{self, Opened};
use crate::select;
use crate::verdict;

/// Help for `gitiup quorum`.
pub const QUORUM_HELP: &str = "\
gitiup quorum — the owner's questions about a quorum, asked of a store

USAGE:
    gitiup quorum <COMMAND> [OPTIONS]

COMMANDS:
    verdict <CHANGE> [OPTIONS]  tally every round this store holds for a change:
                                verified / failed / insufficient, with the count, the
                                threshold, the divergent digests and every rejection
                                with its reason. --publish signs the verdict and files
                                it at refs/gitiup/verdict/<change>/<job>.
                                (0 verified · 6 refused or not yet · 7 bad signature ·
                                 8 digest mismatch)
    help                        this text

`gitiup quorum verdict help` lists the flags: which store, which job and attempt, whose
signature counts, which clock to judge freshness by, and what to accept as a tier.

The other two questions a quorum raises are not here yet: a dispute report and a bounded
escalation (`gitiup quorum dispute|retry`, giti-zp1.7) are the next tickets, and they are
the ones that *move* a round. Nothing under `verdict` changes a round, a roster or a
seat: a verdict is an opinion about evidence, signed, and that is the whole job.

Try:
    gitiup quorum verdict chg-6a6a8eab778ba4d0 --store ./store
    gitiup quorum verdict chg-6a6a --store ./store --json
    gitiup quorum verdict chg-6a6a --store ./store --publish --key owner
";

/// `gitiup quorum …` — the verdict side of the quorum, from a shell.
pub fn quorum(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{QUORUM_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{QUORUM_HELP}");
            Ok(())
        }
        "verdict" => verdict::verdict(&args[1..]),
        other => Err(CliError::usage(format!(
            "unknown `gitiup quorum` command '{other}'; `gitiup quorum help` lists what exists"
        ))),
    }
}

/// The path component that marks a round's job id as one matrix arm.
///
/// `build/matrix/linux-x86_64` is the spelling ADR-0002's own selection vector uses for
/// `job_id`, and `job_id` is a seed input — so the spelling is part of a round's identity
/// and not a display choice. `the_arm_id_is_the_vector_the_adr_publishes` pins it.
const ARM_MARKER: &str = "matrix";

/// A policy refusal that means "no rule of ours applies here", not "this store is broken":
/// nothing published, nothing we trust, nothing currently in force.
fn policy_is_not_ours(error: &policy::PolicyError) -> bool {
    matches!(
        error.token(),
        token::NO_POLICY_PUBLISHED
            | token::UNSIGNED
            | token::SIGNER_UNTRUSTED
            | token::OWNER_MISMATCH
            | token::EXPIRED
            | token::FUTURE_DATED
    )
}

/// One round this submit opened — or found already open.
pub(crate) struct RoundOutcome {
    /// The round's `job_id`: a job id, plus `/matrix/<arm>…` for a matrix arm.
    job: String,
    /// Where the job came from, for the human line (`.github/workflows/ci.yml`).
    from: String,
    /// The inputs, kept for the report: they *are* the audit question.
    inputs: RoundInputs,
    /// The signed round record — unwritten until [`Quorum::publish`] runs.
    round: Round,
    /// The selection the published seed derives.
    selection: Selection,
    /// The proposer rule, checked against this round before it was written.
    check: ProposerExclusion,
    /// `refs/gitiup/round/<change>/<job>/<attempt>`.
    reference: String,
    /// The store already held this round, so nothing was written for it.
    existing: bool,
    /// The `kv/round/<hex>` oid the record was filed under.
    published: Option<String>,
    /// The advertisement's oid, when the round filled its seats.
    advertised: Option<String>,
    /// Whether the round read back from the store reproduced its own published seats.
    rechecked: bool,
}

impl RoundOutcome {
    /// The D7 filter tallies: every roster entry that did not make it, by the *first* filter
    /// that rejected it (that order is normative, ADR-0002 D7, so the tally is reproducible).
    fn rejections(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for row in &self.selection.candidates {
            if let Some(reason) = row.excluded_by.as_deref() {
                *out.entry(reason.to_string()).or_default() += 1;
            }
        }
        out
    }

    /// Eligible candidates a cap held back, by cap (`identity`, `tier_cap`).
    fn skipped(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for row in &self.selection.candidates {
            if row.greedy == gitiup_quorum::select::Greedy::Skip {
                *out.entry(row.greedy_reason.clone()).or_default() += 1;
            }
        }
        out
    }

    /// Why this round did not fill its seats, in the words a person acts on.
    ///
    /// `explain()` is the audit trail ADR-0002 D3 specifies; the tally is what fits on a
    /// terminal without printing a table per matrix arm, and is the same information one
    /// level up. Both name the filters, because "insufficient" without a reason is a shrug.
    fn shortfalls(&self) -> Vec<String> {
        let mut out = Vec::new();
        let filters = self.rejections();
        let tally = if filters.is_empty() {
            "no roster entry was filtered out".to_string()
        } else {
            format!(
                "the eligibility filters rejected {}",
                filters
                    .iter()
                    .map(|(reason, count)| format!("{reason} ×{count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        out.push(format!(
            "{} of {} roster entries were eligible for {} seats; {tally}",
            self.selection.eligible, self.inputs.policy.n, self.inputs.policy.n
        ));
        let caps = self.skipped();
        if !caps.is_empty() {
            out.push(format!(
                "the caps held back {}",
                caps.iter()
                    .map(|(cap, count)| format!("{count} ({cap})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out.push(format!(
            "`n` was not lowered: this round asks for {} and records `sufficient: false`. \
             Widening the roster or the filters is the fix; `--n {}` is not",
            self.inputs.policy.n, self.inputs.policy.n
        ));
        out
    }

    fn json(&self, roster: Option<&Roster>, explain: bool) -> Value {
        let seats: Vec<Value> = self
            .selection
            .selected
            .iter()
            .map(|seat| {
                json!({
                    "rank": seat.rank,
                    "key_id": seat.key_id,
                    "identity": seat.identity,
                    "slot": seat.slot,
                    "tier": seat.tier.as_str(),
                })
            })
            .collect();
        json!({
            "job": self.job,
            "from": self.from,
            "attempt": self.inputs.attempt,
            "round_ref": self.reference,
            "round_digest": self.round.digest().ok(),
            "seed": self.round.seed,
            "policy_digest": self.round.policy_digest,
            "inputs": self.inputs,
            "n": self.inputs.policy.n,
            "required_agree": self.inputs.policy.required_agree,
            "eligible": self.selection.eligible,
            "sufficient": self.selection.sufficient,
            "seats": seats,
            "reserves": self.selection.reserves.len(),
            "rejected_by_filter": self.rejections(),
            "skipped_by_cap": self.skipped(),
            "author_family": &self.check.family,
            "already": self.existing,
            "published": self.published,
            "advertised": self.advertised,
            "rechecked": self.rechecked,
            "explain": match (explain, roster) {
                (true, Some(roster)) => Some(self.selection.explain(roster)),
                _ => None,
            },
        })
    }
}

/// What this submit decided about quorums, and what it did about it.
pub(crate) struct Quorum {
    /// `not-required` · `declined` · `opened`.
    state: &'static str,
    /// The answer to "why is there no quorum here?", whenever there is none.
    reason: Option<String>,
    /// Whether the policy in force demanded a quorum for this change.
    demanded: bool,
    /// The policy the decision came from, with its provenance.
    policy: Option<Value>,
    /// The roster the rounds pinned, kept for the re-check and the audit table.
    roster: Option<Roster>,
    /// The same roster as the report prints it.
    roster_brief: Option<Value>,
    /// The key that derived the seeds and signed the rounds — and so the only key allowed
    /// to advertise them (giti-zp1.1).
    selector: Option<gitiup_keys::signer::Key>,
    selector_brief: Option<Value>,
    /// The author, as the exclusion rule spells them.
    proposer: Vec<String>,
    rounds: Vec<RoundOutcome>,
    notes: Vec<String>,
    explain: bool,
}

impl Quorum {
    /// Nothing was asked for.
    fn not_required(reason: impl Into<String>, notes: Vec<String>) -> Quorum {
        Quorum {
            state: "not-required",
            reason: Some(reason.into()),
            demanded: false,
            policy: None,
            roster: None,
            roster_brief: None,
            selector: None,
            selector_brief: None,
            proposer: Vec::new(),
            rounds: Vec::new(),
            notes,
            explain: false,
        }
    }

    /// The submitter opted out with `--no-quorum`.
    fn declined(reason: impl Into<String>, policy: Option<Value>) -> Quorum {
        Quorum {
            state: "declined",
            reason: Some(reason.into()),
            demanded: policy.is_some(),
            policy,
            roster: None,
            roster_brief: None,
            selector: None,
            selector_brief: None,
            proposer: Vec::new(),
            rounds: Vec::new(),
            notes: vec![
                "no round was opened, so nothing is being verified: `gitiup verify change` \
                 will refuse this change until a selector opens one (`gitiup select --change \
                 <id> … --publish`)"
                    .to_string(),
            ],
            explain: false,
        }
    }

    /// Whether there is anything to write.
    pub(crate) fn opened(&self) -> bool {
        self.state == "opened"
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "state": self.state,
            "demanded": self.demanded,
            "reason": self.reason,
            "policy": self.policy,
            "roster": self.roster_brief,
            "selector": self.selector_brief,
            "proposer": self.proposer,
            "rounds": self
                .rounds
                .iter()
                .map(|round| round.json(self.roster.as_ref(), self.explain))
                .collect::<Vec<Value>>(),
            "notes": self.notes,
        })
    }

    pub(crate) fn text(&self) {
        match self.state {
            "not-required" => println!(
                "  quorum   not asked for: {}",
                self.reason.clone().unwrap_or_default()
            ),
            "declined" => println!(
                "  quorum   --no-quorum: {}",
                self.reason.clone().unwrap_or_default()
            ),
            _ => {
                let digest = self
                    .policy
                    .as_ref()
                    .and_then(|policy| policy.get("body_digest"))
                    .and_then(Value::as_str)
                    .map(short_digest)
                    .unwrap_or_else(|| "the published policy".to_string());
                let filled = self
                    .rounds
                    .iter()
                    .filter(|round| round.selection.sufficient)
                    .count();
                println!(
                    "  quorum   demanded by policy rev {} ({}) — {filled} of {} rounds filled \
                     their seats",
                    self.policy
                        .as_ref()
                        .and_then(|policy| policy.get("revision"))
                        .and_then(Value::as_u64)
                        .unwrap_or_default(),
                    digest,
                    self.rounds.len()
                );
                if let Some(roster) = &self.roster_brief {
                    println!(
                        "           roster epoch {} · {} entries · {}",
                        roster["epoch"].as_u64().unwrap_or_default(),
                        roster["entries"].as_u64().unwrap_or_default(),
                        short_digest(roster["digest"].as_str().unwrap_or_default()),
                    );
                }
                if let Some(selector) = &self.selector_brief {
                    println!(
                        "           selector {} · {}",
                        selector["key_id"]
                            .as_str()
                            .map(participant::short)
                            .unwrap_or_default(),
                        selector["seed_source"].as_str().unwrap_or_default(),
                    );
                }
                for round in &self.rounds {
                    let policy = &round.inputs.policy;
                    println!(
                        "    {:<32} {}/{} seats · agree {} · seed {} · {}",
                        round.job,
                        round.selection.selected.len(),
                        policy.n,
                        policy.required_agree,
                        short_digest(&round.round.seed.to_string()),
                        match (round.selection.sufficient, round.existing) {
                            (true, false) => "published",
                            (false, false) => "published, NOT FILLED",
                            (_, true) => "already published",
                        },
                    );
                    if !round.selection.sufficient {
                        for line in round.shortfalls() {
                            println!("        {line}");
                        }
                    }
                    if let Some(oid) = &round.published {
                        println!(
                            "        {} · {}{}",
                            round.reference,
                            short_digest(oid),
                            match &round.advertised {
                                Some(_) => " · advertised",
                                None if round.selection.sufficient => "",
                                None =>
                                    " · not advertised: its seats are unfilled, so \
                                         there is nothing to recruit for",
                            }
                        );
                    }
                }
                if let (true, Some(roster)) = (self.explain, &self.roster) {
                    for round in &self.rounds {
                        println!();
                        println!("# {} — the audit table (ADR-0002 D3)", round.job);
                        print!("{}", round.selection.explain(roster));
                    }
                }
            }
        }
        for note in &self.notes {
            println!("  note: {note}");
        }
    }
}

/// A digest, shortened for a terminal. Display only, never a record.
fn short_digest(digest: &str) -> String {
    let body = digest.split(':').nth(1).unwrap_or(digest);
    if body.len() <= 12 {
        digest.to_string()
    } else {
        format!("{}\u{2026}", &body[..12])
    }
}

/// Decide — and derive, but not yet write — the rounds this change needs.
///
/// Everything here is read-only on purpose: a refusal raised in this function means nothing
/// was published, which is the only way "a round that left the author's second box in the
/// pool is refused, not republished" can be true.
pub(crate) fn plan(args: &Args, store: &Opened, record: &ChangeRecord) -> Result<Quorum, CliError> {
    let explain = args.on("--explain");
    let trust = crate::policy::show_trust(args)?;
    let resolved = match policy::resolve_store(&*store.host, &trust, policy::At::now()) {
        Ok(resolved) => resolved,
        Err(error) if policy_is_not_ours(&error) => {
            return Ok(Quorum::not_required(
                format!("{}: {}", error.token(), error.detail),
                error.hint.clone().into_iter().collect::<Vec<_>>(),
            ));
        }
        Err(error) => return Err(crate::policy::refused(error)),
    };
    let brief = policy_brief(&resolved);
    let Some(document) = resolved.document.as_ref() else {
        return Ok(Quorum::not_required(
            format!(
                "the policy in force came from {} and carries no quorum block",
                resolved
                    .provenance
                    .source
                    .map(|source| source.as_str())
                    .unwrap_or("nowhere")
            ),
            Vec::new(),
        ));
    };
    let branch_ref = format!("refs/heads/{}", record.base.branch);
    let allows_quorum = resolved.policy.allowed_tiers.contains(&Tier::Quorum);
    let gates_this = document.protects_ref(&branch_ref);
    if !allows_quorum || !gates_this {
        let reason = if !allows_quorum {
            format!(
                "the published policy (rev {}, {}) allows {} and not `quorum`",
                resolved.provenance.revision.unwrap_or_default(),
                short_digest(
                    resolved
                        .provenance
                        .body_digest
                        .as_deref()
                        .unwrap_or_default()
                ),
                resolved
                    .policy
                    .allowed_tiers
                    .iter()
                    .map(|tier| tier.as_str())
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        } else {
            format!(
                "the published policy gates {} and this change merges into {branch_ref}",
                document.protects.join(", ")
            )
        };
        return Ok(Quorum {
            state: "not-required",
            reason: Some(reason),
            demanded: false,
            policy: Some(brief),
            roster: None,
            roster_brief: None,
            selector: None,
            selector_brief: None,
            proposer: Vec::new(),
            rounds: Vec::new(),
            notes: Vec::new(),
            explain,
        });
    }
    if args.on("--no-quorum") {
        return Ok(Quorum::declined(
            format!(
                "the policy in force does demand a quorum for {branch_ref}, and this change \
                 was published without a round"
            ),
            Some(brief),
        ));
    }
    let block = document.quorum.clone().unwrap_or_default();
    let requirements = block.requirements.clone().ok_or_else(|| {
        CliError::refused(
            format!(
                "the published policy demands a quorum (rev {}) but names no \
             `quorum.requirements`, so nothing can be asked of a volunteer",
                resolved.provenance.revision.unwrap_or_default()
            ),
            "a round selects for one architecture and a minimum sandbox; publish a policy whose \
         `quorum` block carries them, or submit --no-quorum and let a selector choose the \
         requirements with `gitiup select --require-*`",
        )
    })?;

    // The pool. Pinned by epoch and digest, checked for expiry, and — when this machine can
    // vouch for it — verified, with the difference between the two said out loud rather
    // than assumed.
    let now = TimeUs::now();
    let roster = store::current_roster(&*store.host)?.ok_or_else(|| {
        CliError::refused(
            format!(
                "{} publishes no roster, and this change's policy demands a quorum",
                store.what
            ),
            "the owner publishes one with `gitiup participant approve --publish`; a round with no \
         roster has no pool, and an empty quorum is not a smaller one",
        )
    })?;
    roster.validate()?;
    let mut notes = Vec::new();
    let believed: Option<Vec<String>> = match roster.verify(&trust, now) {
        Ok(signers) => Some(signers),
        Err(error) => {
            notes.push(format!(
                "the roster's owner signature was not believed here ({error}); the rounds pin \
                 epoch {} and digest {}, and a volunteer re-checks that epoch against its own \
                 trust roots before it runs anything",
                roster.epoch,
                roster.digest().map(|d| d.to_string()).unwrap_or_default()
            ));
            None
        }
    };
    if now.as_us() > roster.valid_until_us {
        return Err(CliError::refused(
            format!(
                "roster epoch {} expired at {}; a new round may not pin it",
                roster.epoch,
                TimeUs(roster.valid_until_us).to_rfc3339()
            ),
            "the owner publishes a fresh epoch with `gitiup participant approve` (ADR-0002 \
             D8: an expired epoch is a departure, not a rounding error)",
        ));
    }

    // The selector: whoever publishes the change derives the seed, unless a delegated
    // secret is handed over. An agent-held key cannot: HKDF-Extract needs the seed, and an
    // agent — correctly — will not hand it out.
    let here = participant::keystore()?;
    let selector = match args.get("--selector") {
        Some(name) => gitiup_keys::signer::open(&here.keys, name, &keys::passphrase_source(args))?,
        None => participant::signing_key(args, &here)?,
    };
    let selector_id = selector.key_id();
    let delegated = args.get("--selector").is_some() || args.get("--seed-file").is_some();
    let secret: SelectionSecret = match args.get("--seed-file") {
        Some(path) => select::read_secret_file(path)?,
        None => select::selection_secret(args, &selector)?,
    };
    // "the submitter is the selector" is the usual case and worth one clause; a *different*
    // key signing the change is the interesting one, and the reader should see which they
    // are looking at rather than two near-identical fingerprints.
    let signs_the_change = !delegated;
    let selector_brief = json!({
        "key_id": selector_id,
        "signs_the_change": signs_the_change,
        "seed_source": match args.get("--seed-file") {
            Some(path) => format!(
                "the selection secret in {path}, which is all a delegated selector needs \
                 (ADR-0002 D2)"
            ),
            None if signs_the_change => "the key that signs the change; its seed is the \
                 selection secret, hidden until these rounds are published and public from \
                 then on (ADR-0002 D2)"
                .to_string(),
            None => format!(
                "the keystore key {}, which is not the key that signs the change; its seed is \
                 the selection secret (ADR-0002 D2)",
                participant::short(&selector_id)
            ),
        },
    });

    // The job set, expanded to arms by the planner rather than guessed from names.
    let jobs = planned_jobs(args, record)?;
    if jobs.is_empty() {
        return Err(CliError::refused(
            "this change's policy demands a quorum and no job was found to open a round for",
            "one round is one job on one matrix arm: name the workflow with --workflow <path> \
             (or give the record its hint with `gitiup change new --job <id>`), or submit \
             --no-quorum and open the rounds with `gitiup select`",
        ));
    }

    // The author, as ADR-0002 D4 spells them: one key id, whose whole identity family
    // `RoundInputs::excluding` then takes out of the pool.
    let proposer = vec![record.author.key_id.clone()];
    let head: GitOid = record.head.parse().map_err(CliError::from)?;
    let attempt = u64::from(record.attempts.index);

    let mut rounds = Vec::new();
    for job in jobs {
        let policy = block.selection_for(&job.id).cloned().ok_or_else(|| {
            CliError::refused(
                format!(
                    "the published policy has no quorum numbers for job `{}`",
                    job.id
                ),
                format!(
                    "`quorum.by_job` covers {} and there is no `quorum.default`; publish a \
                     revision that covers this job (ADR-0004 D5)",
                    block
                        .by_job
                        .as_ref()
                        .map(|map| if map.is_empty() {
                            "nothing".to_string()
                        } else {
                            map.keys().cloned().collect::<Vec<_>>().join(", ")
                        })
                        .unwrap_or_else(|| "nothing".to_string())
                ),
            )
        })?;
        let reference = store::round_ref(record.change_id.as_str(), &job.id, attempt)?;
        if let Some(existing) =
            store::round_at(&*store.host, record.change_id.as_str(), &job.id, attempt)?
        {
            // This attempt already has a round. Read it, check it, write nothing: one job,
            // one round per attempt is the property the seed exists to make impossible, and
            // a second selector opening one is the bug, not the fix.
            let selection = existing.selection(&roster)?;
            let check = ProposerExclusion::check(&roster, &existing.inputs, &selection, &proposer);
            if !check.held() {
                return Err(CliError::refused(
                    format!(
                        "{} · change {} job {}",
                        check.describe(),
                        record.change_id,
                        job.id
                    ),
                    "the round this store already holds for this attempt lets its author's box \
                     into the pool. This command does not repair a published round; escalating \
                     it (attempt + 1, exclusion in the record) is the way",
                ));
            }
            rounds.push(RoundOutcome {
                job: job.id,
                from: job.from,
                inputs: existing.inputs.clone(),
                rechecked: true,
                existing: true,
                published: None,
                advertised: None,
                round: existing,
                selection,
                check,
                reference: reference.as_str().to_string(),
            });
            continue;
        }
        let inputs = RoundInputs {
            schema_version: gitiup_quorum::select::SELECTION_SCHEMA_VERSION,
            kind: None,
            round_kind: gitiup_quorum::derive::ROUND_KIND.to_string(),
            roster_epoch: roster.epoch,
            roster_digest: roster.digest()?,
            change_id: record.change_id.as_str().to_string(),
            head_oid: head.clone(),
            job_id: job.id.clone(),
            attempt,
            required_capabilities: requirements.clone(),
            exclusions: Default::default(),
            policy,
        }
        // Applied before the seed is derived, so the audit record says `excluded` for every
        // one of the author's boxes instead of leaving it to whichever filter happened to
        // bite first.
        .excluding(&roster, &proposer)?;
        let mut round = Round::open(&inputs, &roster, &secret)?;
        round.sign(&selector)?;
        let selection = round.selection(&roster)?;
        let check = ProposerExclusion::check(&roster, &inputs, &selection, &proposer);
        if !check.held() {
            return Err(CliError::refused(
                format!(
                    "{} · change {} job {}",
                    check.describe(),
                    record.change_id,
                    job.id
                ),
                "the exclusion was applied and this round still lets the author's box into the \
                 pool; that is a bug in the exclusion and not a policy to negotiate — the \
                 round is refused, and nothing has been published",
            ));
        }
        rounds.push(RoundOutcome {
            job: job.id,
            from: job.from,
            inputs,
            rechecked: false,
            existing: false,
            published: None,
            advertised: None,
            round,
            selection,
            check,
            reference: reference.as_str().to_string(),
        });
    }

    Ok(Quorum {
        state: "opened",
        reason: None,
        demanded: true,
        policy: Some(brief),
        roster_brief: Some(json!({
            "epoch": roster.epoch,
            "digest": roster.digest().ok(),
            "entries": roster.entries.len(),
            "identities": roster.identities().len(),
            "source": format!("{} · refs/gitiup/roster", store.what),
            "owner_signatures_believed": believed,
        })),
        roster: Some(roster),
        selector: Some(selector),
        selector_brief: Some(selector_brief),
        proposer,
        rounds,
        notes,
        explain,
    })
}

impl Quorum {
    /// Write the rounds, advertise the ones worth advertising, then read them back.
    ///
    /// The order matters twice. A round has to be in the store before the advertisement
    /// that indexes it, because an advertisement is an index and not an authority
    /// ([giti-zp1.1](../../../docs/quorum.md)). And every round is fetched back and
    /// re-derived before this returns: a re-read is the only check that could notice a store
    /// that stored something other than what it was handed.
    pub(crate) fn publish(&mut self, store: &Opened) -> Result<(), CliError> {
        if !self.opened() {
            return Ok(());
        }
        let now = TimeUs::now();
        let roster = self
            .roster
            .clone()
            .expect("an opened quorum pinned a roster in plan()");
        let selector = self
            .selector
            .as_ref()
            .expect("an opened quorum has its selector key");
        for round in &mut self.rounds {
            if round.existing {
                continue;
            }
            let oid = store::publish_round(&*store.host, &round.round)?;
            round.published = Some(oid.hex().to_string());
            // An unfilled round is not advertised: recruiting volunteers for a quorum that
            // cannot reach its threshold is a worse answer than an escalation, and
            // `advertise_round` refuses one anyway (giti-zp1.1).
            if round.selection.sufficient {
                let advertised = store::advertise_round(&*store.host, &round.round, selector, now)?;
                round.advertised = Some(advertised.hex().to_string());
            }
        }
        for round in &mut self.rounds {
            let back = store::round_at(
                &*store.host,
                &round.inputs.change_id,
                &round.job,
                round.inputs.attempt,
            )?;
            let Some(back) = back else {
                return Err(CliError::refused(
                    format!("{} did not come back from the store", round.reference),
                    "the round was published and then could not be read, which is a store \
                     fault and not a reason to report a quorum nobody can audit",
                ));
            };
            // `verify_selection` re-runs the whole selection from the published seed and
            // refuses a record whose seats were edited; the proposer check then runs over
            // what the store actually holds, not over what this command meant to write.
            let selection = back.verify_selection(&roster)?;
            let check = ProposerExclusion::check(&roster, &back.inputs, &selection, &self.proposer);
            if !check.held() {
                return Err(CliError::refused(
                    format!(
                        "{} · change {} job {}",
                        check.describe(),
                        back.inputs.change_id,
                        back.inputs.job_id
                    ),
                    "the round the store returned lets the author's box into the pool; it is \
                     refused here rather than believed because it is published",
                ));
            }
            round.rechecked = selection.selected == round.selection.selected
                && selection.seed == round.selection.seed;
        }
        Ok(())
    }
}

/// The policy, as the report prints it: enough to cite it, and to see whose word it is.
fn policy_brief(resolved: &policy::ResolvedPolicy) -> Value {
    let provenance = &resolved.provenance;
    json!({
        "revision": provenance.revision,
        "body_digest": provenance.body_digest,
        "record_digest": provenance.record_digest,
        "signed_by": provenance.signed_by,
        "owner": provenance.owner,
        "source": provenance.source.map(|source| source.as_str()),
        "allowed_tiers": resolved
            .policy
            .allowed_tiers
            .iter()
            .map(|tier| tier.as_str())
            .collect::<Vec<&str>>(),
        "protects": resolved
            .document
            .as_ref()
            .map(|document| document.protects.clone())
            .unwrap_or_default(),
    })
}

/// One round's worth of work: the id the round is named by, and where it came from.
struct RoundJob {
    id: String,
    from: String,
}

/// Which jobs — and which arms of them — a change needs rounds for.
///
/// The planner is what makes a matrix a *set* of rounds: `build` with three arms is three
/// rounds with three seeds, because one seed for three architectures would be one jury
/// asked to judge machines two of them cannot run on (ADR-0002 D7).
fn planned_jobs(args: &Args, record: &ChangeRecord) -> Result<Vec<RoundJob>, CliError> {
    let root = PathBuf::from(args.get("--repository").or(args.get("-C")).unwrap_or("."));
    let mut out: Vec<RoundJob> = Vec::new();
    for (path, text) in workflow_files(args, &root)? {
        let workflow = gitiup_run::Workflow::parse(&path, &text)?;
        for job in &workflow.jobs {
            let selector = gitiup_run::Selector {
                job: Some(job.id.clone()),
                matrix: Default::default(),
            };
            let plan = gitiup_run::Plan::build(&workflow, &selector)?;
            for planned in plan.jobs {
                let id = round_job_id(&planned);
                // Round ids become ref components; catch a hostile matrix value here, with
                // the workflow file named, rather than in the middle of a publish.
                check_round_id(record.change_id.as_str(), &id, &path).map_err(|error| {
                    CliError::refused(
                        format!("{path}: job `{id}` cannot be a round id: {error}"),
                        "a job id becomes a ref component, so matrix values have to be \
                         [A-Za-z0-9._-] with no empty or dot components",
                    )
                })?;
                out.push(RoundJob {
                    id,
                    from: path.clone(),
                });
            }
        }
    }
    if out.is_empty() {
        // No checkout, or no workflow file: the record's own hint is the job set. A record
        // drafted `--no-jobs` says so by carrying none, and the caller refuses that.
        for job in &record.workflow.jobs {
            check_round_id(record.change_id.as_str(), job, "the change record").map_err(
                |error| {
                    CliError::refused(
                        format!("the record's job `{job}` cannot be a round id: {error}"),
                        "a job id becomes a ref component; see `gitiup change new --job <id>`",
                    )
                },
            )?;
            out.push(RoundJob {
                id: job.clone(),
                from: "the change record's job hint".to_string(),
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    Ok(out)
}

/// Would this job id make a legal round ref?
fn check_round_id(change: &str, job: &str, from: &str) -> Result<(), gitiup_quorum::Error> {
    store::round_ref(change, job, 0)
        .map(|_| ())
        .map_err(|error| {
            gitiup_quorum::Error::invalid("round", format!("{} names job `{job}`: {error}", from))
        })
}

/// The round's `job_id` for one planned run.
///
/// A job with no matrix is itself; an arm is `<job>/matrix/<value>[/…]`, axes in sorted
/// order, which is the spelling ADR-0002's published selection vector uses and is therefore
/// pinned by a test rather than invented per call.
fn round_job_id(job: &gitiup_run::PlannedJob) -> String {
    if job.matrix.is_empty() {
        return job.id.clone();
    }
    let arm: Vec<&str> = job.matrix.values().map(String::as_str).collect();
    format!("{}/{}/{}", job.id, ARM_MARKER, arm.join("/"))
}

/// The workflow files to plan, named the way `gitiup change new` names them.
///
/// Several files and none named is a refusal *here* rather than a silently empty job set: a
/// quorum has to be opened for a known set of jobs, and guessing which of three workflow
/// files the owner meant is guessing the quorum.
fn workflow_files(args: &Args, root: &Path) -> Result<Vec<(String, String)>, CliError> {
    if let Some(path) = args.get("--workflow").or(args.get("-w")) {
        let text = std::fs::read_to_string(path).map_err(|e| {
            CliError::refused(
                format!("reading '{path}': {e}"),
                "the workflow the rounds are planned from has to be readable — name one that \
                 exists, or submit --no-quorum",
            )
        })?;
        return Ok(vec![(path.to_string(), text)]);
    }
    let dir = root.join(".github/workflows");
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
        [] => Ok(Vec::new()),
        [only] => Ok(vec![(display_path(only, root), read_to_string(only)?)]),
        many => Err(CliError::refused(
            format!(
                "{} holds {} workflow files and none was named",
                dir.display(),
                many.len()
            ),
            format!(
                "a round is opened per job, so the job set cannot be guessed: name one with \
                 --workflow <path> ({})",
                many.iter()
                    .map(|path| display_path(path, root))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

fn read_to_string(path: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(|e| {
        CliError::refused(
            format!("reading '{}': {e}", path.display()),
            "the workflow file the rounds are planned from has to be readable",
        )
    })
}

fn display_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-0002's published vector calls its matrix arm `build/matrix/linux-x86_64`, and
    /// `job_id` is a seed input, so this spelling decides which jury a round gets.
    #[test]
    fn the_arm_id_is_the_vector_the_adr_publishes() {
        let planned = gitiup_run::PlannedJob {
            id: "build".to_string(),
            name: None,
            runs_on: None,
            matrix: [("target".to_string(), "linux-x86_64".to_string())]
                .into_iter()
                .collect(),
            env: Vec::new(),
            services: Vec::new(),
            assumptions: Vec::new(),
            steps: Vec::new(),
        };
        assert_eq!(round_job_id(&planned), "build/matrix/linux-x86_64");

        let plain = gitiup_run::PlannedJob {
            matrix: Default::default(),
            ..planned
        };
        assert_eq!(round_job_id(&plain), "build");

        // Two axes: sorted by axis name, so the id does not depend on the order the YAML
        // happened to list them in — two authors writing the same matrix get one round.
        let two = gitiup_run::PlannedJob {
            matrix: [
                ("target".to_string(), "linux-x86_64".to_string()),
                ("rust".to_string(), "1.88".to_string()),
            ]
            .into_iter()
            .collect(),
            ..plain
        };
        assert_eq!(round_job_id(&two), "build/matrix/1.88/linux-x86_64");
    }

    /// A ref component cannot be empty or a dot, and a matrix value can be `..`.
    #[test]
    fn a_job_id_that_cannot_be_a_ref_component_is_refused_where_it_is_found() {
        assert!(check_round_id("chg-1", "build/matrix/linux-x86_64", "ci.yml").is_ok());
        assert!(check_round_id("chg-1", "build/matrix/..", "ci.yml").is_err());
        assert!(check_round_id("chg-1", "build//test", "ci.yml").is_err());
    }

    /// The only refusals that are the submitter's business are the store's own facts;
    /// everything else about a policy is an authority question and stays a note.
    #[test]
    fn only_a_policy_that_is_not_ours_becomes_a_note() {
        for token in [
            token::NO_POLICY_PUBLISHED,
            token::UNSIGNED,
            token::SIGNER_UNTRUSTED,
            token::EXPIRED,
        ] {
            let error = policy::PolicyError::new(token, "x");
            assert!(policy_is_not_ours(&error), "{token} is about authority");
        }
        for token in [
            token::NOT_CANONICAL,
            token::POLICY_HISTORY_MISSING,
            token::FIELD_UNKNOWN,
            token::REQUIRED_AGREE_UNREACHABLE,
        ] {
            let error = policy::PolicyError::new(token, "x");
            assert!(!policy_is_not_ours(&error), "{token} is a broken policy");
        }
    }

    #[test]
    fn a_digest_is_shortened_for_a_terminal_and_not_for_a_record() {
        assert_eq!(
            short_digest("sha256:0123456789abcdef"),
            "0123456789ab\u{2026}"
        );
        assert_eq!(short_digest("short"), "short");
    }
}

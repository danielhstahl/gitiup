//! `gitiup verify change` — the merge gate over every attestation a change has.
//!
//! `gitiup verify attestation` answers a question about one document. A merge is not
//! one document: a change's head can have three attestations from two keys, a quorum
//! verdict, an owner's policy that was tightened last week, and a policy that was in
//! force when the runs actually happened that is not the one in force now. The gate has
//! to answer *one* question with *one* exit code, and say how it got there:
//!
//! ```text
//! gitiup verify change chg-6a6a8eab778ba4d0 --store ./store --json
//! ```
//!
//! # The ladder, and what each rung decides
//!
//! | code | check | what it establishes |
//!|------|-------|---------------------|
//!| `change` | the change resolves, its head record reads and verifies, and it is not abandoned |
//!| `policy` | a gate-eligible policy was resolved — the published one, walked to a timestamp, or an operator's `--policy` (ADR-0004 D4) |
//!| `protects` | that policy gates the ref this change merges into |
//!| `attestations` | the store advertises at least one proof for the change's head, and can produce the bytes for every one it advertises |
//!| `quorum` | every verdict the store advertises for this head is one the owner signed, about this head, and says `verified` |
//!| `min_signatures` | some *combination* of the accepted attestations adds up to what the policy demands |
//!
//! Then one exit code: **0** may merge · **6** refused · **7** a signature that does not
//! verify · **8** a digest that is not the bytes it names. 2 and 3 are not verdicts
//! (usage, and a store that did not answer); as everywhere in `verify`, a verdict is a
//! result, so it is printed on stdout and carried in the exit code, and **stderr stays
//! empty** — that is the contract a `pre-receive` hook depends on, because a hook that
//! merges the two streams must still be able to parse the report.
//!
//! # Which policy, and from when
//!
//! Two timestamps, because two questions are being asked ([ADR-0004 D6](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)):
//!
//! * **each attestation** is judged by the revision in force **when that run happened**
//!   — its own claimed time — which is D6's whole point: today's rules must not refuse
//!   last week's correct run, and last week's rules must not quietly pass today's change.
//! * **the merge** — what is demanded at all, `protects`, and how many signatures make
//!   a set — is judged by the revision in force **now** (or at `--at`), because the
//!   merge is the act happening now and a merge record cites *today's* policy digest.
//!
//! Freshness is measured against the reader's clock (`--now` pins it, for replay), never
//! against the proof's own claim: a proof may be dated when it was made, but it has to
//! still be fresh *now* to carry a merge. That is what bounds D6's "how long can a policy
//! change be dodged with an old proof".
//!
//! Neither the tiers nor `min_signatures` can be overridden by a flag here, unlike
//! `verify attestation`: this command's subject *is* the owner's policy, so the numbers
//! come from the document the owner signed. The only flags about *what is demanded* are
//! `--policy` (an operator's act, gate-eligible by D4) and the clock.
//!
//! # When several attestations "add up"
//!
//! `min_signatures` counts *distinct trusted signers certifying one result*. So the
//! combination must agree: three attestations from one key are one signature, and two
//! that certify different `ResultDigest`s certify two different claims — which is the
//! quorum's own rule ([`required_agree`](gitiup_quorum::select)) expressed as the policy
//! field a repository actually writes. The command names the combination it accepted, so
//! a gate is never left guessing which file it was told to trust.
//!
//! A quorum verdict is read from `refs/gitiup/verdict/<change>/**` — *listed*, not
//! guessed from the change's job hint, because the rounds somebody opened are the
//! store's business and not the change record's. It is believed only as far as the
//! owner's signature (the same roots that decide whose policy to apply), it must be
//! about this head, and a `failed` verdict is a refusal: the gate does not merge over a
//! recorded disagreement, and it does not merge "yet".

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use gitiup_attest::{
    AttestationDoc, CheckOutcome, Digest, Error as AttestError, ErrorKind, GitOid, Reason,
    ResultDigest, Tier, TimeUs, Trust, VerdictReport,
};
use gitiup_host::attest;
use gitiup_host::change as change_host;
use gitiup_host::refs::ns;
use gitiup_host::{Oid, RefQuery};
use gitiup_quorum::policy::{self, PolicyError, Purpose, ResolvedPolicy};
use gitiup_quorum::store as quorum_store;
use gitiup_quorum::verdict::{QuorumState, VerdictRecord};
use serde_json::{Map, Value, json};

use crate::CliError;
use crate::change as change_cli;
use crate::keys::Args;
use crate::participant::Opened;
use crate::policy as policy_cli;
use crate::verify::{self, Facts, Row};

/// Help for `gitiup verify change`.
pub const VERIFY_CHANGE_HELP: &str = " \
gitiup verify change — may this change merge, given everything the store says about it?

USAGE:
    gitiup verify change <ID> [OPTIONS]

<ID> is a change id (`chg-…`) or 4+ hex of one. The change is resolved in the store,
its head commit is read, and every attestation the store advertises for that head is
verified — plus the quorum verdict, if the store carries one.

WHERE THE CHANGE IS:
    --store <dir>                the store to read (fs directory)
    --remote <name>              …or a remote from gitiup.toml
    --change <ID>                the change, if you would rather not use a positional
    --attempt <n>                verify one attempt rather than the head the ref names
    --expect-result <digest>     refuse unless the accepted result is exactly this

WHICH POLICY APPLIES:
    --policy <path>              the operator's act: replaces anything published (D4)
    --tree-file <path>           default ./gitiup-policy.json when present: a draft, and
                                 never gate-eligible, so a gate refuses over it
    --trust <key|id>             repeatable: whose *policy* you accept. Default: this
                                 keystore's own keys. Who may sign a proof is the
                                 policy's `trust_key_ids`, never this flag
    --at <time>                  judge the policy chain as of then (µs or RFC 3339)
    --now <time>                 the clock freshness is measured against (default: now)

There is no --tier, --min-signatures or --trust-any-key here on purpose: this command's
subject is the owner's policy, so those numbers come from the signed document. Only the
clock is a flag, because the clock is not an opinion about what is demanded.

OUTPUT:
    -j, --json                   one line, keys sorted: the verdict, every check, every
                                 failure, the policy cited, one section per attestation,
                                 and the combination that was accepted
    -q, --quiet                  one word: `ok`, or the code that decided the verdict
    -h, --help                   this text

Every failure is reported, not just the first; the first — integrity before authority,
the same precedence as the attestation ladder — is what the exit code reports.

Exit codes: 0 may merge · 2 usage · 3 I/O, store unreachable · 6 refused (no policy
published, nothing proved, too few distinct signatures, a tier or signer the policy
refuses, a stale proof, a change that is abandoned, a quorum that did not agree) ·
7 a signature that does not verify · 8 digest mismatch (non-canonical bytes, a store
that returned bytes other than the ones its name promises, a proof about another
commit, a verdict about another head).

Try:
    gitiup verify change chg-6a6a8eab778ba4d0 --store ./store
    gitiup verify change chg-6a6a --store ./store --json
    gitiup verify change chg-6a6a --store ./store --now 2026-10-27T10:00:00Z
";

/// Valued flags `gitiup verify change` accepts.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--change",
    "--attempt",
    "--expect-result",
    "--policy",
    "--tree-file",
    "--trust",
    "--at",
    "--now",
];

/// Switches `gitiup verify change` accepts.
const SWITCHES: &[&str] = &["-q", "--quiet"];

/// The change-level checks, in the order a reader checks them.
///
/// These are not the attestation ladder's codes — the per-attestation ladder runs
/// underneath, unchanged, one section per proof — and they are appended after it in the
/// `checks` array so a script that knows the old codes still finds them in the old order.
/// `pub(crate)` because `gitiup policy explain change` prints *these* as its subject-level
/// rules: one promised order, not two that happen to agree today.
pub(crate) const CHANGE_CHECKS: &[&str] = &[
    "change",
    "policy",
    "protects",
    "attestations",
    "quorum",
    "min_signatures",
];

/// `gitiup verify change …`
pub fn change(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if let Some(()) = args.help(VERIFY_CHANGE_HELP) {
        return Ok(());
    }
    let handle = match args
        .positional
        .first()
        .cloned()
        .or_else(|| args.get("--change").map(str::to_string))
    {
        Some(handle) => handle,
        None => {
            return Err(CliError::usage(
                "say which change to verify: `gitiup verify change <ID> --store <dir>` \
                 (a change id, or 4+ hex of one)",
            ));
        }
    };
    let store = change_cli::read_store(&args)?;
    let now = match args.get("--now") {
        Some(text) => gitiup_attest::TimeUs::parse(text)
            .map_err(|e| CliError::usage(format!("--now '{text}': {e}")))?,
        None => gitiup_attest::TimeUs::now(),
    };
    let at = match args.get("--at") {
        Some(text) => Some(
            gitiup_attest::TimeUs::parse(text)
                .map_err(|e| CliError::usage(format!("--at '{text}': {e}")))?,
        ),
        None => None,
    };
    let attempt = match args.get("--attempt") {
        Some(text) => Some(text.parse::<u32>().map_err(|_| {
            CliError::usage(format!("--attempt '{text}' is not an attempt number"))
        })?),
        None => None,
    };
    let expect = match args.get("--expect-result") {
        Some(text) => Some(
            text.parse::<Digest>()
                .map_err(|e| CliError::usage(format!("--expect-result '{text}': {e}")))?,
        ),
        None => None,
    };

    let report = assess(&store, &handle, &args, attempt, expect.as_ref(), now, at)?;
    let report = report.finish();

    if args.on("--quiet") || args.on("-q") {
        println!("{}", report.primary_code());
        return report.exit();
    }
    if args.json() {
        println!(
            "{}",
            serde_json::to_string(&report.json()).unwrap_or_else(|_| "{}".into())
        );
        return report.exit();
    }
    print!("{}", report.text());
    report.exit()
}

// ---------------------------------------------------------------------------
// the parts of a verdict
// ---------------------------------------------------------------------------

/// One attestation the store advertised, and how it scored.
///
/// `doc` is `None` when the store could not produce the bytes, or produced bytes that
/// are not a document: both are verdicts (8 and 6) rather than panics, and both still
/// get a section, because "which of the five proofs was broken" is the question.
///
/// `pub(crate)` because `gitiup policy check` asks the same question about a commit
/// instead of a change: one reading of "what does the store say about this commit", two
/// renderings of it.
pub(crate) struct Section {
    /// The store's content address for the bytes (`sha256:…`).
    pub(crate) digest: Oid,
    /// The ref that advertised it.
    pub(crate) reference: String,
    /// `doc`, when the bytes were a document this build speaks.
    pub(crate) doc: Option<AttestationDoc>,
    /// What the document says, when there was a document to ask.
    pub(crate) facts: Option<Facts>,
    /// The attestation's own report — the `verify attestation` shape, unchanged.
    pub(crate) report: VerdictReport,
    /// The policy this proof was judged by, with the revision it applied.
    pub(crate) policy: Option<ResolvedPolicy>,
    /// Why no policy could be found for this proof's timestamp, when that happened.
    pub(crate) policy_error: Option<PolicyError>,
}

impl Section {
    fn unread(digest: Oid, reference: String, code: &'static str, error: AttestError) -> Section {
        Section {
            digest,
            reference,
            doc: None,
            facts: None,
            report: VerdictReport::refusing(code, error),
            policy: None,
            policy_error: None,
        }
    }

    /// This proof's own failures, said *about* this proof: the attestation ladder's
    /// reasons, prefixed with which attestation they belong to, because "the signature
    /// does not verify" across four proofs names nothing.
    ///
    /// `pub(crate)` because `gitiup policy check` asks the same questions about a bare
    /// commit and has to report a proof's failure in the words a merge gate uses — a
    /// second paraphrase would be a second thing to keep true.
    pub(crate) fn lifted_reasons(&self) -> Vec<Reason> {
        let what = format!("attestation {}", short(&self.digest.hex()));
        self.report
            .reasons
            .iter()
            .map(|one| {
                let mut copy = one.clone();
                let mut error = AttestError::new(
                    one.error.kind(),
                    one.error.context(),
                    format!("{what}: {}", one_line(one.error.detail())),
                );
                if let Some(hint) = one.error.hint() {
                    error = error.with_hint(hint.to_string());
                }
                copy.error = error;
                copy
            })
            .collect()
    }

    /// The key ids on this proof that the policy applied to it would trust.
    pub(crate) fn signers(&self) -> Vec<String> {
        let Some(doc) = &self.doc else {
            return Vec::new();
        };
        let offered: BTreeSet<String> = doc
            .signatures
            .iter()
            .map(|entry| entry.key_id.clone())
            .collect();
        match self
            .policy
            .as_ref()
            .map(|resolved| resolved.policy.trust.clone())
        {
            Some(Trust::KeyIds(ids)) => offered.intersection(&ids).cloned().collect(),
            // Anything that verified counts: this is the diagnosis case, and it says so
            // in every output it produces.
            Some(Trust::AnyKeyForTests) => offered.into_iter().collect(),
            _ => Vec::new(),
        }
    }

    pub(crate) fn accepted(&self) -> bool {
        self.report.accepted()
    }

    pub(crate) fn result_digest(&self) -> Option<String> {
        self.facts
            .as_ref()
            .and_then(|facts| facts.result_digest().map(str::to_string))
    }

    pub(crate) fn job(&self) -> Option<&str> {
        self.facts.as_ref().and_then(|facts| facts.job())
    }

    /// The section as JSON: the attestation report shape, plus where it came from and
    /// which rules it was judged by.
    fn json(&self) -> Value {
        let mut out = verify::report_shape(&self.report);
        out.insert("digest".into(), Value::String(tagged(&self.digest)));
        out.insert("ref".into(), Value::String(self.reference.clone()));
        out.insert(
            "source".into(),
            Value::String(format!("kv/attestation/{}", self.digest.hex())),
        );
        out.insert(
            "policy".into(),
            match (&self.policy, &self.policy_error) {
                (Some(resolved), _) => policy_block(resolved),
                (None, Some(error)) => {
                    json!({ "refused": { "token": error.token(), "detail": error.detail } })
                }
                (None, None) => Value::Null,
            },
        );
        out.insert(
            "attestation".into(),
            self.facts.as_ref().map(Facts::json).unwrap_or(Value::Null),
        );
        Value::Object(out)
    }

    /// The human section: a header line, the facts, the policy it was judged by, and
    /// the ladder it walked.
    fn text(&self, index: usize, now: TimeUs, out: &mut String) {
        let word = if self.accepted() {
            "ACCEPTED".to_string()
        } else {
            self.report.verdict().to_uppercase()
        };
        out.push_str(&format!(
            "\n  [{}] {}  {} (exit {})\n",
            index + 1,
            tagged(&self.digest),
            word,
            self.report.exit_code()
        ));
        let mut rows: Vec<Row> = Vec::new();
        if let Some(facts) = &self.facts {
            facts.rows(now, &mut rows);
        }
        for row in &rows {
            out.push_str(&format!("      {}", row.render().trim_start()));
        }
        match &self.policy {
            Some(resolved) => out.push_str(&format!(
                "      policy   {}\n",
                one_line(&policy_summary(resolved))
            )),
            None if self.policy_error.is_some() => out.push_str(&format!(
                "      policy   refused: {}\n",
                self.policy_error
                    .as_ref()
                    .map(|error| format!("{}: {}", error.token(), one_line(&error.detail)))
                    .unwrap_or_default()
            )),
            None => out.push_str("      policy   none was resolved for this proof\n"),
        }
        out.push_str("      checks\n");
        for line in verify::render_checks(&self.report).lines() {
            out.push_str(&format!("    {line}\n"));
        }
        for (index, r) in self.report.reasons.iter().enumerate() {
            let label = if index == 0 { "reason" } else { "also" };
            out.push_str(&format!(
                "      {:<9}[{}] {}\n",
                label,
                r.code,
                one_line(r.detail())
            ));
        }
    }
}

/// A quorum verdict the store advertised, or the reason it could not be read.
pub(crate) struct VerdictEntry {
    /// The ref that carried it.
    reference: String,
    /// The record, when it was readable, canonical, and signed by a trusted owner.
    record: Option<VerdictRecord>,
    /// Why not, when it was not: `(<exit code>, <sentence>)`.
    problem: Option<(u8, String)>,
}

impl VerdictEntry {
    fn broken(reference: String, exit: u8, detail: impl Into<String>) -> VerdictEntry {
        VerdictEntry {
            reference,
            record: None,
            problem: Some((exit, detail.into())),
        }
    }

    fn json(&self) -> Value {
        let mut out = Map::new();
        out.insert("ref".into(), Value::String(self.reference.clone()));
        match (&self.record, &self.problem) {
            (Some(verdict), _) => {
                out.insert("state".into(), verdict.state.as_str().into());
                out.insert("reason".into(), verdict.reason.as_str().into());
                out.insert("job".into(), verdict.job_id.clone().into());
                out.insert("head".into(), verdict.head_oid.to_string().into());
                out.insert("attempt".into(), verdict.attempt.into());
                out.insert("seats".into(), (verdict.seats as u64).into());
                out.insert(
                    "required_agree".into(),
                    (verdict.required_agree as u64).into(),
                );
                out.insert("agreeing".into(), (verdict.agreeing as u64).into());
                out.insert(
                    "result_digest".into(),
                    verdict
                        .result_digest
                        .as_ref()
                        .map(|digest| Value::String(digest.to_string()))
                        .unwrap_or(Value::Null),
                );
                out.insert(
                    "counted".into(),
                    Value::Array(
                        verdict
                            .counted
                            .iter()
                            .map(|vote| {
                                json!({
                                    "key_id": vote.key_id,
                                    "identity": vote.identity,
                                    "tier": vote.tier.as_str(),
                                })
                            })
                            .collect(),
                    ),
                );
                out.insert("detail".into(), verdict.detail.clone().into());
                out.insert(
                    "issued_at".into(),
                    TimeUs(verdict.issued_at_us).to_rfc3339().into(),
                );
            }
            (None, Some((exit, detail))) => {
                out.insert("refused".into(), json!({ "detail": detail, "exit": *exit }));
            }
            (None, None) => {}
        }
        Value::Object(out)
    }
}

/// The combination the gate accepted, and why it is *that* one.
///
/// `pub(crate)`, and `Clone`, for the same reason [`Section`] is: `gitiup policy check`
/// answers the signature question about a commit and has to name the combination it
/// counted in the same words a merge gate uses.
#[derive(Clone)]
pub(crate) struct Accepted {
    /// `attestations` or `quorum verdict`.
    pub(crate) via: &'static str,
    /// The one result the combination certifies.
    pub(crate) result_digest: Option<String>,
    /// The distinct trusted signers counted.
    pub(crate) signers: Vec<String>,
    /// What was counted: attestation digests, or the verdict's ref.
    pub(crate) counted: Vec<String>,
    /// What the policy demanded.
    pub(crate) required: usize,
    /// The verdict's ref, when the combination was a verdict.
    pub(crate) reference: Option<String>,
}

impl Accepted {
    fn json(&self) -> Value {
        json!({
            "via": self.via,
            "result_digest": self.result_digest.clone(),
            "signers": self.signers,
            "counted": self.counted,
            "required": self.required,
            "ref": self.reference,
        })
    }
}

// ---------------------------------------------------------------------------
// the verdict
// ---------------------------------------------------------------------------

/// Everything one `verify change` run established.
///
/// The fields are `pub(crate)` so that `gitiup policy explain change` can render *this*
/// verdict rule by rule: one assessment, two renderings, and no chance for the merge
/// gate and the explainer to disagree about what the same evidence meant.
pub(crate) struct Report {
    /// The store that was read.
    pub(crate) store: String,
    /// The handle the caller used.
    pub(crate) handle: String,
    /// The change id it resolved to, when it resolved.
    pub(crate) change: Option<String>,
    /// `open` · `merged` · `abandoned`.
    pub(crate) state: Option<String>,
    /// The head commit the proofs are about.
    pub(crate) head: Option<String>,
    /// The ref this change would merge into.
    pub(crate) target: Option<String>,
    /// Which attempt was verified.
    pub(crate) attempt: Option<u32>,
    /// The change's title, because a gate log that says `chg-9f2c…` is not a log.
    pub(crate) title: Option<String>,
    /// The change-level checks, in [`CHANGE_CHECKS`] order.
    pub(crate) checks: Vec<(&'static str, CheckOutcome)>,
    /// Every failure: the change-level ones and, prefixed with what they are about,
    /// every attestation's own. First decides the exit code after [`Self::finish`].
    pub(crate) reasons: Vec<Reason>,
    /// The policy the *merge* was judged by, with its provenance (D4).
    pub(crate) policy: Option<ResolvedPolicy>,
    /// One section per attestation the store advertised.
    pub(crate) sections: Vec<Section>,
    /// The quorum verdicts found for this change.
    pub(crate) verdicts: Vec<VerdictEntry>,
    /// The combination accepted, when there was one.
    pub(crate) accepted: Option<Accepted>,
    /// The clock the run used.
    pub(crate) now: gitiup_attest::TimeUs,
    /// Anything worth saying that is neither a check nor a failure.
    pub(crate) notes: Vec<String>,
}

impl Report {
    /// A report that refuses before it could look at anything.
    fn refused(
        store: &Opened,
        handle: &str,
        code: &'static str,
        error: &CliError,
        now: gitiup_attest::TimeUs,
    ) -> Report {
        let kind = match error.code {
            7 => ErrorKind::Signature,
            8 => ErrorKind::DigestMismatch,
            _ => ErrorKind::Policy,
        };
        let detail = match &error.hint {
            Some(hint) => format!("{} ({})", error.message, one_line(hint)),
            None => error.message.clone(),
        };
        Report {
            store: store.what.clone(),
            handle: handle.to_string(),
            change: None,
            state: None,
            head: None,
            target: None,
            attempt: None,
            title: None,
            // Every check is still listed, the rest of them `not_run`: a reader parsing
            // this in a hook sees the whole ladder and can see how far it got.
            checks: CHANGE_CHECKS
                .iter()
                .map(|one| {
                    (
                        *one,
                        if *one == code {
                            CheckOutcome::Failed
                        } else {
                            CheckOutcome::NotRun
                        },
                    )
                })
                .collect(),
            reasons: vec![reason(code, kind, detail, None)],
            policy: None,
            sections: Vec::new(),
            verdicts: Vec::new(),
            accepted: None,
            now,
            notes: Vec::new(),
        }
    }

    fn new(store: &Opened, handle: &str, now: gitiup_attest::TimeUs) -> Report {
        Report {
            store: store.what.clone(),
            handle: handle.to_string(),
            change: None,
            state: None,
            head: None,
            target: None,
            attempt: None,
            title: None,
            checks: CHANGE_CHECKS
                .iter()
                .map(|code| (*code, CheckOutcome::NotRun))
                .collect(),
            reasons: Vec::new(),
            policy: None,
            sections: Vec::new(),
            verdicts: Vec::new(),
            accepted: None,
            now,
            notes: Vec::new(),
        }
    }

    /// How one change-level check ended, for a caller that must not overwrite a decision.
    pub(crate) fn outcome_of(&self, code: &str) -> CheckOutcome {
        self.checks
            .iter()
            .find(|(one, _)| *one == code)
            .map_or(CheckOutcome::NotRun, |(_, outcome)| *outcome)
    }

    fn set(&mut self, code: &'static str, outcome: CheckOutcome) {
        if let Some(row) = self.checks.iter_mut().find(|(one, _)| *one == code) {
            row.1 = outcome;
            return;
        }
        self.checks.push((code, outcome));
    }

    fn fail(&mut self, code: &'static str, error: Reason) {
        self.reasons.push(error);
        self.set(code, CheckOutcome::Failed);
    }

    /// Copy every attestation's failures up, then order them the way the attestation
    /// ladder orders its own: integrity first, then authority, then policy. The first
    /// is what the exit code reports, and everything is still printed.
    pub(crate) fn finish(mut self) -> Report {
        let mut lifted: Vec<Reason> = Vec::new();
        for section in &self.sections {
            // A proof that was never judged because this command has no policy at all is
            // the change-level `policy` failure, told once: repeating it per attestation
            // would be five reasons for one fact. The section still carries the refusal it
            // hit, so nothing is hidden — it is just not counted twice.
            if self.policy.is_none() && section.policy_error.is_some() {
                continue;
            }
            for one in section.lifted_reasons() {
                lifted.push(one);
            }
        }
        self.reasons.extend(lifted);
        self.reasons.sort_by_key(|one| rank(one.class()));
        // Some proofs agreeing is one of the answers, not the whole question. A policy
        // that does not gate this ref, or a quorum that recorded a disagreement, outranks
        // "some attestations add up", and a report that said `accepted: true` next to a
        // refusal would be two answers at once — the exit code has to come from the
        // failure that is still standing.
        if !self.reasons.is_empty() {
            self.accepted = None;
        }
        self
    }

    /// The jobs the accepted combination actually names, so an asked-for-but-unproved job
    /// can be pointed out — and pointed out as a note, because the policy names no per-job
    /// rule for refusing with, and inventing one here would be the gate writing policy the
    /// owner never signed.
    fn accepted_jobs(&self) -> BTreeSet<String> {
        let Some(accepted) = &self.accepted else {
            return BTreeSet::new();
        };
        self.sections
            .iter()
            .filter(|section| accepted.counted.contains(&tagged(&section.digest)))
            .filter_map(|section| section.job().map(str::to_string))
            .collect()
    }

    pub(crate) fn exit_code(&self) -> u8 {
        if self.accepted.is_some() {
            return 0;
        }
        self.reasons.first().map_or(6, |reason| reason.exit_code())
    }

    pub(crate) fn accepted_now(&self) -> bool {
        self.accepted.is_some()
    }

    pub(crate) fn verdict_word(&self) -> &'static str {
        if self.accepted_now() {
            return "pass";
        }
        self.reasons
            .first()
            .map_or("policy", |reason| reason.class().as_str())
    }

    pub(crate) fn primary_code(&self) -> &'static str {
        if self.accepted_now() {
            return "ok";
        }
        self.reasons.first().map_or("policy", |reason| reason.code)
    }

    fn exit(self) -> Result<(), CliError> {
        if self.accepted_now() {
            return Ok(());
        }
        Err(CliError::verdict(self.exit_code()))
    }

    fn json(&self) -> Value {
        let mut out = Map::new();
        out.insert("record_type".into(), "change-verdict".into());
        out.insert("verdict".into(), self.verdict_word().into());
        out.insert("exit".into(), (self.exit_code() as u64).into());
        out.insert("accepted".into(), self.accepted_now().into());
        out.insert("store".into(), self.store.clone().into());
        out.insert("handle".into(), self.handle.clone().into());
        out.insert(
            "change".into(),
            self.change
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "state".into(),
            self.state.clone().map(Value::String).unwrap_or(Value::Null),
        );
        out.insert(
            "head".into(),
            self.head.clone().map(Value::String).unwrap_or(Value::Null),
        );
        out.insert(
            "target".into(),
            self.target
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "attempt".into(),
            self.attempt
                .map(|attempt| (attempt as u64).into())
                .unwrap_or(Value::Null),
        );
        out.insert(
            "title".into(),
            self.title.clone().map(Value::String).unwrap_or(Value::Null),
        );
        out.insert(
            "checks".into(),
            Value::Array(
                self.checks
                    .iter()
                    .map(|(code, outcome)| json!({ "code": code, "outcome": outcome.as_str() }))
                    .collect(),
            ),
        );
        out.insert(
            "reasons".into(),
            Value::Array(verify::reasons_json(&self.reasons)),
        );
        out.insert(
            "policy".into(),
            self.policy
                .as_ref()
                .map(policy_block)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "attestations".into(),
            Value::Array(self.sections.iter().map(Section::json).collect()),
        );
        out.insert(
            "quorum".into(),
            Value::Array(self.verdicts.iter().map(VerdictEntry::json).collect()),
        );
        out.insert(
            "accepts".into(),
            self.accepted
                .as_ref()
                .map(Accepted::json)
                .unwrap_or(Value::Null),
        );
        out.insert("now".into(), self.now.to_rfc3339().into());
        out.insert("now_us".into(), (self.now.0).into());
        if !self.notes.is_empty() {
            out.insert(
                "notes".into(),
                Value::Array(
                    self.notes
                        .iter()
                        .map(|note| Value::String(note.clone()))
                        .collect(),
                ),
            );
        }
        Value::Object(out)
    }

    fn text(&self) -> String {
        let mut rows: Vec<Row> = Vec::new();
        // The answer first. A gate's output is read by a person in a hurry, and a report
        // that buries "no" under forty lines of evidence is a report that gets skimmed.
        rows.push(Row::new(
            "verdict",
            match &self.accepted {
                Some(accepted) => format!("MAY MERGE  \u{b7}  {}", accepted_line(accepted)),
                None => format!(
                    "REFUSED (exit {})  \u{b7}  {}",
                    self.exit_code(),
                    self.reasons.first().map_or_else(
                        || "nothing proved this change".to_string(),
                        |reason| format!("[{}] {}", reason.code, one_line(reason.detail())),
                    )
                ),
            },
        ));
        rows.push(Row::new(
            "change",
            format!(
                "{}{}{}",
                self.change.clone().unwrap_or_else(|| self.handle.clone()),
                self.state
                    .as_ref()
                    .map(|state| format!("  ·  {state}"))
                    .unwrap_or_default(),
                self.attempt
                    .map(|attempt| format!("  ·  attempt {attempt}"))
                    .unwrap_or_default()
            ),
        ));
        rows.push(Row::new("store", self.store.clone()));
        if let Some(head) = &self.head {
            rows.push(Row::new(
                "head",
                format!(
                    "{}{}",
                    head,
                    self.target
                        .as_ref()
                        .map(|target| format!("  →  {target}"))
                        .unwrap_or_default()
                ),
            ));
        }
        if let Some(title) = &self.title {
            rows.push(Row::new("title", title.clone()));
        }
        if let Some(policy) = &self.policy {
            rows.push(Row::new("policy", one_line(&policy_summary(policy))));
        }
        rows.push(Row::new("clock", self.now.to_rfc3339()));
        for note in &self.notes {
            rows.push(Row::new("note", note.clone()));
        }

        let mut text = String::new();
        for row in &rows {
            text.push_str(&row.render());
        }

        text.push_str(&format!(
            "\nquorum \
                 {}\n",
            match self.verdicts.len() {
                0 => "none advertised for this change".to_string(),
                1 => verdict_line(&self.verdicts[0]),
                many => format!(
                    "{} verdicts: {}",
                    many,
                    self.verdicts
                        .iter()
                        .map(verdict_line)
                        .collect::<Vec<_>>()
                        .join(" | ")
                ),
            }
        ));
        text.push_str(&format!(
            "\nattestations  {} advertised for {}\n",
            self.sections.len(),
            self.head.clone().unwrap_or_else(|| "?".to_string())
        ));
        if self.sections.is_empty() {
            text.push_str("  (nothing: the store advertises no proof for this head)\n");
        }
        for (index, section) in self.sections.iter().enumerate() {
            section.text(index, self.now, &mut text);
        }

        text.push_str("\nchecks\n");
        for (code, outcome) in &self.checks {
            let detail = self
                .reasons
                .iter()
                .find(|reason| reason.code == *code && outcome.is_failure())
                .map_or(String::new(), |reason| {
                    format!(" \u{b7} {}", one_line(reason.detail()))
                });
            let line = format!(
                "  {:<15} {:<10}{}",
                code,
                verify::state_word(*outcome),
                detail
            );
            text.push_str(line.trim_end());
            text.push('\n');
        }

        text.push('\n');
        match &self.accepted {
            Some(accepted) => {
                text.push_str(&Row::new("accepted", accepted_line(accepted)).render())
            }
            None => text
                .push_str(&Row::new("accepted", "nothing: no combination met the policy").render()),
        }
        for (index, reason) in self.reasons.iter().enumerate() {
            let label = if index == 0 { "reason" } else { "also" };
            text.push_str(
                &Row::new(
                    label,
                    format!("[{}] {}", reason.code, one_line(reason.detail())),
                )
                .render(),
            );
        }
        text
    }
}

/// 8 before 7 before 6: the attestation ladder checks integrity before it asks
/// authority anything, so the failure that decides the exit code is the one that has to
/// be fixed before the others even mean something.
pub(crate) fn rank(kind: ErrorKind) -> u8 {
    match kind {
        ErrorKind::DigestMismatch => 0,
        ErrorKind::Signature => 1,
        _ => 2,
    }
}

/// One change-level failure.
pub(crate) fn reason(
    code: &'static str,
    kind: ErrorKind,
    detail: impl Into<String>,
    hint: Option<String>,
) -> Reason {
    let error = AttestError::new(kind, "change", detail);
    Reason {
        code,
        error: match hint {
            Some(hint) => error.with_hint(hint),
            None => error,
        },
    }
}

/// A published-policy refusal keeps ADR-0004 D9's token in the sentence: the token is
/// the interface, and the exit code is already the library's.
pub(crate) fn policy_reason(error: &PolicyError) -> Reason {
    let kind = match error.exit_code() {
        7 => ErrorKind::Signature,
        8 => ErrorKind::DigestMismatch,
        _ => ErrorKind::Policy,
    };
    let detail = format!("{}: {}", error.token(), error.detail);
    reason("policy", kind, detail, error.hint.clone())
}

/// The `policy` block: D4's provenance and the rules that will actually be applied.
///
/// A verdict is only interpretable next to the question it answered, so both halves are
/// printed: which revision, from where, cited by which digest, and what it demands.
pub(crate) fn policy_block(resolved: &ResolvedPolicy) -> Value {
    json!({
        "provenance": resolved.provenance.json(),
        "rules": policy_cli::rules(resolved),
    })
}

/// The one line a report prints for a policy: source, revision, citation, and the
/// numbers that decided the answer.
pub(crate) fn policy_summary(resolved: &ResolvedPolicy) -> String {
    let provenance = &resolved.provenance;
    let source = provenance
        .source
        .map(|source| source.as_str())
        .unwrap_or("nothing");
    let mut parts = vec![match provenance.revision {
        Some(revision) => format!("{source} revision {revision}"),
        None => source.to_string(),
    }];
    if let Some(digest) = &provenance.body_digest {
        parts.push(format!("cited {digest}"));
    }
    if let Some(at) = provenance.at_us {
        parts.push(format!(
            "judged {} ({})",
            gitiup_attest::TimeUs(at).to_rfc3339(),
            provenance.at_from.clone().unwrap_or_default()
        ));
    }
    parts.push(if provenance.gate_eligible {
        "gate-eligible".to_string()
    } else {
        "NOT gate-eligible".to_string()
    });
    if let Some(rules) = policy_block(resolved).get("rules") {
        parts.push(rules_line(rules));
    }
    parts.join(" · ")
}

/// The numbers a reader branches on, in the order the ladder uses them.
fn rules_line(rules: &Value) -> String {
    let tiers = rules["allowed_tiers"]
        .as_array()
        .map(|tiers| {
            tiers
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("+")
        })
        .unwrap_or_default();
    let trusted = rules["trust_key_ids"]
        .as_array()
        .map(|ids| ids.len().to_string())
        .unwrap_or_default();
    format!(
        "trust {trusted} key(s) · tiers {tiers} · min {} · max age {}",
        rules["min_signatures"].as_u64().unwrap_or(0),
        rules["max_age_us"]
            .as_i64()
            .map(verify::human_age)
            .unwrap_or_default()
    )
}

/// The one line a verdict gets in the human report.
fn verdict_line(entry: &VerdictEntry) -> String {
    match (&entry.record, &entry.problem) {
        (Some(verdict), _) => format!(
            "{} · {} · {}/{} agreed on {} (job {})",
            entry.reference,
            verdict.state.as_str(),
            verdict.agreeing,
            verdict.required_agree,
            verdict
                .result_digest
                .as_ref()
                .map(|digest| short(&digest.hex()))
                .unwrap_or_else(|| "nothing".to_string()),
            verdict.job_id
        ),
        (None, Some((exit, detail))) => {
            format!(
                "{} · refused ({exit}): {}",
                entry.reference,
                one_line(detail)
            )
        }
        (None, None) => format!("{} · unread", entry.reference),
    }
}

/// What the gate accepted, in one line: the combination, who signed it, and the result
/// it certifies. This is the sentence that stops a gate from guessing which file to trust.
fn accepted_line(accepted: &Accepted) -> String {
    let mut out = format!("{}: {}", accepted.via, accepted.counted.join(", "));
    // The *who* belongs in the line as much as the *what*: `min_signatures` is a count of
    // distinct signers, so a reader checking the answer needs to see whose signatures
    // were counted, not only how many.
    if !accepted.signers.is_empty() {
        let mut names: Vec<String> = accepted
            .signers
            .iter()
            .take(3)
            .map(|key_id| verify_short_key(key_id))
            .collect();
        if accepted.signers.len() > names.len() {
            names.push(format!("+{} more", accepted.signers.len() - names.len()));
        }
        out.push_str(&format!("  \u{b7}  from {}", names.join(", ")));
    }
    out.push_str(&format!(
        "  ({} distinct signer(s) of {}; result {})",
        accepted.signers.len(),
        accepted.required,
        accepted.result_digest.clone().unwrap_or_else(|| "?".into())
    ));
    out
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

/// Everything the flags decided, gathered so the phases below take no flags at all.
///
/// `pub(crate)` because `gitiup policy check` asks the same question of a commit: the
/// ladder, the two clocks and the trust roots are one decision and it is made once, here.
pub(crate) struct Question<'a> {
    /// The store to walk a published policy from, when the caller has one. `None` is a
    /// real answer, not a placeholder: `gitiup policy explain attestation <file>` asks a
    /// question about bytes in no store, and the ladder still runs — it just lands on the
    /// local-only sources, which is itself the thing a gate needs to be told.
    pub(crate) store: Option<&'a Opened>,
    pub(crate) roots: Trust,
    /// The reader's clock: what freshness and expiry are measured against.
    pub(crate) now: gitiup_attest::TimeUs,
    /// An explicit walk timestamp, when `--at` pinned one.
    pub(crate) at: Option<gitiup_attest::TimeUs>,
    pub(crate) expect: Option<Digest>,
    pub(crate) policy_file: Option<PathBuf>,
    pub(crate) policy_env: Option<PathBuf>,
    pub(crate) tree_file: Option<PathBuf>,
    /// Which ladder this walk belongs to. A merge gate asks the gate ladder; a command
    /// answering a different question sets this field, which is how `policy explain
    /// --advisory` walks the advisory ladder instead of describing the gate's.
    pub(crate) purpose: Purpose,
}

impl Question<'_> {
    /// Read the policy question out of the flags, the same way `verify change` does: the
    /// same trust rule (whose policy will this machine apply), the same two clocks, and
    /// the same "a tree file is there unless you say otherwise" default.
    pub(crate) fn new<'a>(
        store: Option<&'a Opened>,
        args: &'a Args,
        now: gitiup_attest::TimeUs,
        at: Option<gitiup_attest::TimeUs>,
        expect: Option<Digest>,
    ) -> Result<Question<'a>, CliError> {
        Ok(Question {
            store,
            roots: policy_cli::show_trust(args)?,
            now,
            at,
            expect,
            policy_file: args.get("--policy").map(PathBuf::from),
            policy_env: std::env::var(gitiup_attest::POLICY_PATH_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from),
            tree_file: match args.get("--tree-file") {
                Some(text) => Some(PathBuf::from(text)),
                None => {
                    let default = std::path::Path::new("gitiup-policy.json");
                    default.exists().then(|| default.to_path_buf())
                }
            },
            // A merge gate's question by default. `gitiup policy explain --advisory`
            // is the caller that says otherwise, and it says so on the field.
            purpose: Purpose::Gate,
        })
    }

    /// Ask the advisory ladder instead of the gate's: the same walk, the second set of
    /// trust roots, and a revision that is not eligible to carry a merge.
    pub(crate) fn ask_advisory(&mut self) {
        self.purpose = Purpose::Advisory;
    }

    /// Resolve the policy for one timestamp through the whole D4 ladder, in gate mode.
    ///
    /// This is `.2`'s entry point and nothing else: the ladder, the chain walk, the
    /// trust check and the refusal tokens all come from the library, so `policy show`,
    /// `verify change` and the hook cannot disagree about which revision applies.
    pub(crate) fn resolve(
        &self,
        at: gitiup_attest::TimeUs,
        from: &'static str,
    ) -> Result<ResolvedPolicy, PolicyError> {
        let moment = match from {
            "run-claim" => policy::At::run_claim(at),
            _ => policy::At::now_at(at),
        };
        let mut request = policy::Request {
            host: self.store.map(|opened| opened.host.as_ref()),
            trust: &self.roots,
            at: Some(moment),
            now: Some(self.now),
            policy_file: None,
            policy_env: None,
            tree_file: None,
            purpose: Purpose::Gate,
        };
        request.purpose = self.purpose;
        request.now = Some(self.now);
        request.policy_file = self.policy_file.clone();
        request.policy_env = self.policy_env.clone();
        request.tree_file = self.tree_file.clone();
        policy::resolve(&request)
    }
}

/// Read the change, judge every proof the store advertises for its head, and decide.
pub(crate) fn assess(
    store: &Opened,
    handle: &str,
    args: &Args,
    attempt: Option<u32>,
    expect: Option<&Digest>,
    now: gitiup_attest::TimeUs,
    at: Option<gitiup_attest::TimeUs>,
) -> Result<Report, CliError> {
    let question = Question::new(Some(store), args, now, at, expect.cloned())?;

    // 1. the change. Unresolvable is a refusal, not a fault: a hook handed a change that
    //    is gone still asked a question, and the answer is "no, and here is why".
    let found = match change_cli::resolve_handle(&*store.host, handle) {
        Ok(found) => found,
        Err(error) => return Ok(Report::refused(store, handle, "change", &error, now)),
    };
    let id = found.change_id.clone();
    let mut report = Report::new(store, handle, now);
    report.change = Some(id.as_str().to_string());
    report.state = Some(found.state.as_str().to_string());
    report.attempt = attempt;

    let reference = match attempt {
        Some(index) => gitiup_host::change::attempt_ref(&id, index),
        None => gitiup_host::change::change_head_ref(&id),
    };
    let fetched = match gitiup_host::change::change_at(&*store.host, &reference) {
        Ok(fetched) => fetched,
        Err(error) => {
            let fault = change_cli::host_error("read the change", error);
            return Ok(match verdictly(&fault) {
                Ok(()) => Report::refused(store, handle, "change", &fault, now),
                Err(fault) => return Err(fault),
            });
        }
    };
    let change_host::StoredRecord::Change(record) = fetched.record else {
        return Ok(Report::refused(
            store,
            handle,
            "change",
            &CliError::refused(
                format!(
                    "{} holds a {} record",
                    fetched.reference,
                    fetched.record.record_type()
                ),
                "a change's head holds a change record",
            ),
            now,
        ));
    };
    report.attempt = Some(record.attempts.index);
    report.title = Some(record.title.clone());
    report.target = Some(record.base.branch.clone());
    let head = match verify::commit_id(&record.head) {
        Ok(head) => head,
        Err(error) => return Ok(Report::refused(store, handle, "change", &error, now)),
    };
    let subject = match verify::store_oid(&head) {
        Ok(oid) => oid,
        Err(error) => return Ok(Report::refused(store, handle, "change", &error, now)),
    };
    report.head = Some(record.head.clone());
    report.set("change", CheckOutcome::Passed);
    if found.state == change_host::State::Abandoned {
        report.fail(
            "change",
            reason(
                "change",
                ErrorKind::Policy,
                format!(
                    "{id} is abandoned, so there is nothing for a proof to be good enough for",
                ),
                Some("a closed change keeps its proofs for the audit; it does not get merged".to_string()),
            ),
        );
    }

    // 2. the policy for the merge itself: what is demanded now, or at `--at`.
    //
    // The provenance notes come along with it: "my tree file is not what the gate
    // applied" is the question this command gets asked most, and D4 made that a note
    // for exactly that reason.
    let merge_at = at.unwrap_or(now);
    match question.resolve(merge_at, if at.is_some() { "run-claim" } else { "now" }) {
        Ok(resolved) => {
            let mut notes: Vec<String> = resolved.provenance.notes.clone();
            notes.extend(
                resolved
                    .provenance
                    .warnings
                    .iter()
                    .map(|warning| format!("warning: {warning}")),
            );
            report.notes.extend(notes);
            report.set("policy", CheckOutcome::Passed);
            report.policy = Some(resolved);
        }
        Err(error) => report.fail("policy", policy_reason(&error)),
    }

    // 3. does this policy gate the ref the change would merge into? A policy that does
    //    not name the ref is not in force for it (D5), and a gate that applied it anyway
    //    would be gating a ref nobody signed rules for.
    //
    // A `--policy` file has no `protects` at all, so there is nothing to compare: that is
    // `not_asked`, not a pass, and the report says which.
    let protects = report.policy.as_ref().map(|resolved| {
        resolved.document.as_ref().map(|document| {
            (
                document.protects().to_vec(),
                document.protects_ref(&record.base.branch),
            )
        })
    });
    match protects {
        Some(Some((_, true))) => report.set("protects", CheckOutcome::Passed),
        Some(Some((globs, false))) => report.fail(
            "protects",
            reason(
                "protects",
                ErrorKind::Policy,
                format!(
                    "the policy in force gates [{}] and not {}, so it does not govern a merge into it",
                    globs.join(", "),
                    record.base.branch
                ),
                Some(
                    "publish a revision whose `protects` covers the ref, or accept that this \
                     ref is ungoverned and do not gate it (ADR-0004 D1: a policy gates what is \
                     trusted, never what is merely offered)"
                        .to_string(),
                ),
            ),
        ),
        Some(None) => {
            report.set("protects", CheckOutcome::NotAsked);
            report.notes.push(
                "the policy came from a file, which has no `protects`: it gates whatever it is \
                 pointed at"
                    .to_string(),
            );
        }
        None => report.set("protects", CheckOutcome::NotRun),
    }

    // 4 and 5. every attestation the store advertises for this head, each judged by the
    // revision in force when its run happened (D6).
    let proofs = read_proofs(&*store.host, &subject, &head, &record.head, &question)?;
    for failure in proofs.failures {
        report.fail("attestations", failure);
    }
    report.notes.extend(proofs.notes);
    if proofs.advertised == 0 {
        report.set("attestations", CheckOutcome::NotRun);
        report.set("min_signatures", CheckOutcome::NotRun);
    }
    report.sections = proofs.sections;
    if !report.sections.is_empty()
        && !report
            .reasons
            .iter()
            .any(|reason| reason.code == "attestations")
    {
        report.set("attestations", CheckOutcome::Passed);
    }

    // 6. the quorum verdict — listed, not guessed, and believed only as far as the
    //    owner's signature on it.
    report.verdicts = read_verdicts(&*store.host, &id, &question.roots)?;
    let required = report
        .policy
        .as_ref()
        .map(|resolved| resolved.policy.min_signatures)
        .unwrap_or(1);
    let demands_quorum = report
        .policy
        .as_ref()
        .is_some_and(|resolved| resolved.policy.allowed_tiers.contains(&Tier::Quorum));
    let quorum = judge_quorum(
        &report.verdicts,
        &report.sections,
        &head,
        required,
        demands_quorum,
    );
    for failure in quorum.reasons {
        report.fail("quorum", failure);
    }
    report.notes.extend(quorum.notes);
    report.set("quorum", quorum.outcome);

    // 7. do the attestations add up? The verdict is tried second: the gate prefers to
    //    name the individual proofs it used, and falls back to the owner's tally when the
    //    proofs alone do not reach the bar the policy sets.
    let combination = combine(&report.sections, required);
    report.accepted = combination.accepted.or(quorum.accepted);
    match report.accepted {
        Some(_) => report.set("min_signatures", CheckOutcome::Passed),
        None => {
            for failure in combination.reasons {
                report.fail("min_signatures", failure);
            }
        }
    }
    report.notes.extend(combination.notes);

    // 8. and if nothing at all was proved, that is the headline — said here rather than
    //    in step 4 because the quorum verdict had to be read first.
    if report.accepted.is_none()
        && report.sections.is_empty()
        && !report.reasons.iter().any(|one| one.code == "quorum")
    {
        report.fail(
            "attestations",
            reason(
                "attestations",
                ErrorKind::Policy,
                format!(
                    "{} has no attestation and no verdict in {}; nothing is proved about it",
                    record.head, store.what
                ),
                Some(
                    "`gitiup attest list --commit … --store …` shows what the store holds, \
                     and `gitiup attest push` files one for a run"
                        .to_string(),
                ),
            ),
        );
    } else if report.accepted.is_some()
        && report.sections.is_empty()
        && report.outcome_of("attestations") == CheckOutcome::NotRun
    {
        report.set("attestations", CheckOutcome::NotAsked);
        report.notes.push(
            "no individual attestation is advertised for this head: the quorum verdict is \
             what carried it"
                .to_string(),
        );
    }

    // A policy that does not govern this ref asked nothing of these proofs. They are
    // still listed below, because a reader who came here wants to know what the store
    // says about this head — but they are not an answer, and a check that ran against
    // the wrong rule must not be reported as having run at all.
    if report.outcome_of("protects") == CheckOutcome::Failed {
        for code in ["attestations", "quorum", "min_signatures"] {
            report.set(code, CheckOutcome::NotRun);
        }
        report.accepted = None;
        report.reasons.retain(|one| one.code == "protects");
    }

    // A declared job nobody proved is not a refusal — the policy names no per-job rule to
    // refuse with, and inventing one here would be the gate making policy the owner never
    // signed. It is said out loud, because it is almost always what the reader wanted to
    // know.
    let covered = report.accepted_jobs();
    for job in &record.workflow.jobs {
        if !covered.contains(job) {
            report.notes.push(format!(
                "the change asks for job `{job}` and no accepted attestation names it"
            ));
        }
    }
    Ok(report)
}

/// What the store says about one commit: every proof it advertises, each judged by the
/// policy revision that was in force when that run happened (D6).
///
/// A function rather than a stretch of [`assess`], because `gitiup policy check` asks the
/// same question of a bare commit — no change record, no target ref, no round — and the
/// answer has to be the *same* reading of the store rather than a second implementation
/// of it (ADR-0004 T15: four tickets, one policy).
pub(crate) fn read_proofs(
    host: &dyn gitiup_host::Host,
    subject: &Oid,
    head: &GitOid,
    about: &str,
    question: &Question<'_>,
) -> Result<Proofs, CliError> {
    // Every attestation the store advertises for this commit. Read and parsed first,
    // because which policy applies to one is a fact about the attestation.
    let catalog = attest::list_for(host, subject)
        .map_err(|e| change_cli::host_error("list attestations", e))?;
    let mut failures: Vec<Reason> = Vec::new();
    // Anything the ladder decided that is advice rather than a refusal.
    let mut notes: Vec<String> = Vec::new();
    for unexpected in &catalog.unexpected {
        failures.push(
            reason(
                "attestations",
                ErrorKind::Policy,
                format!(
                    "{} is filed under this head in a shape gitiup does not write, so it is \
                     not evidence",
                    unexpected
                ),
                Some("a ref that is neither layout is reported rather than skipped: `gitiup attest list` shows what the store really holds".to_string()),
            ),
        );
    }

    let mut sections: Vec<Section> = Vec::new();
    let mut read_failures: Vec<Section> = Vec::new();
    for entry in &catalog.entries {
        let reference = entry.reference.as_str().to_string();
        let bytes = match attest::fetch(host, &entry.digest) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                read_failures.push(Section::unread(
                    entry.digest,
                    reference,
                    "stored",
                    AttestError::new(
                        ErrorKind::DigestMismatch,
                        "store",
                        format!(
                            "{} is advertised for {} but the store cannot return its bytes",
                            short(&entry.digest.hex()),
                            about
                        ),
                    )
                    .with_hint(
                        "a ref naming a missing object is a broken store, not a missing proof",
                    ),
                ));
                continue;
            }
            Err(error) if verify::corrupt(&error) => {
                read_failures.push(Section::unread(
                    entry.digest,
                    reference,
                    "stored",
                    AttestError::new(
                        ErrorKind::DigestMismatch,
                        "store",
                        format!(
                            "{} would not hand over what is filed under it: {error}",
                            short(&entry.digest.hex())
                        ),
                    )
                    .with_hint(
                        "the bytes filed under a digest must hash to it; anything built on \
                         this proof is built on nothing",
                    ),
                ));
                continue;
            }
            Err(error) => {
                return Err(change_cli::host_error(
                    &format!("fetch {}", entry.digest.hex()),
                    error,
                ));
            }
        };
        if Oid::hash_bytes(&bytes) != entry.digest {
            let hashed = Oid::hash_bytes(&bytes);
            sections.push(Section::unread(
                entry.digest,
                reference,
                "stored",
                AttestError::new(
                    ErrorKind::DigestMismatch,
                    "store",
                    format!(
                        "the bytes returned for {} hash to {}, not to the name they are filed under",
                        short(&entry.digest.hex()),
                        short(&hashed.hex())
                    ),
                )
                .with_hint("this host is not storing blobs verbatim"),
            ));
            continue;
        }
        match AttestationDoc::from_canonical_bytes(&bytes) {
            Ok(doc) => sections.push(Section {
                digest: entry.digest,
                reference,
                facts: Some(Facts::of(&doc)),
                doc: Some(doc),
                // Filled in below, once the policy for this proof's timestamp is known.
                report: VerdictReport::default(),
                policy: None,
                policy_error: None,
            }),
            Err(error) => {
                sections.push(Section::unread(entry.digest, reference, "structure", error))
            }
        }
    }

    // 5. each proof is judged by the revision in force when its run happened (D6), with
    //    the change head as the commit binding and the reader's clock for freshness.
    let mut resolved_cache: BTreeMap<i64, Result<ResolvedPolicy, PolicyError>> = BTreeMap::new();
    for section in sections.iter_mut() {
        let Some(doc) = section.doc.clone() else {
            continue;
        };
        let claimed = doc.manifest.claims.claimed_at_us;
        let at = question.at.unwrap_or(gitiup_attest::TimeUs(claimed));
        let entry = resolved_cache
            .entry(at.0)
            .or_insert_with(|| question.resolve(at, "run-claim"));
        match entry {
            Ok(resolved) => {
                let mut judged = resolved.clone();
                judged.policy.now = Some(question.now);
                judged.policy.expected_commit = Some(head.clone());
                if let Some(digest) = &question.expect {
                    judged.policy.expected_result_digest = Some(ResultDigest(digest.clone()));
                }
                // The policy's `min_signatures` is a question about the *set* of proofs
                // for a change — how many distinct trusted keys certify this result — and
                // [`combine`] below is where it is answered. Running the same number
                // against one document first would make `min_signatures: 2` satisfiable
                // only by co-signature, and two independently signed attestations from two
                // trusted keys would never add up, which is the case it exists for. So the
                // ladder checks this document's own signatures and no more, and the report
                // says where the count was applied.
                let mut ladder = judged.policy.clone();
                let demanded = ladder.min_signatures;
                if demanded > 1 {
                    ladder.min_signatures = 1;
                }
                section.report = doc.verify_report(&ladder);
                if demanded > 1 {
                    if let Some(check) = section
                        .report
                        .checks
                        .iter_mut()
                        .find(|check| check.code == "min_signatures")
                    {
                        check.outcome = CheckOutcome::NotAsked;
                    }
                    notes.push(format!(
                        "{}: the policy requires {demanded} distinct signatures; that count is \
                         about the attestations for this change together, so this one was \
                         checked for its own signatures only",
                        short(&section.digest.hex())
                    ));
                }
                section.policy = Some(judged);
            }
            Err(error) => {
                section.policy_error = Some(error.clone());
                section.report = VerdictReport::refusing(
                    "structure",
                    AttestError::new(
                        ErrorKind::Policy,
                        "policy",
                        format!("{}: {}", error.token(), error.detail),
                    ),
                );
            }
        }
    }
    sections.extend(read_failures);
    // The store's order is `(subject, digest)`; a section list in that order is what a
    // reader can match against `gitiup attest list`.
    sections.sort_by_key(|section| section.digest.hex().to_string());
    Ok(Proofs {
        sections,
        advertised: catalog.entries.len(),
        failures,
        notes,
    })
}

/// The set of proofs one commit has, as [`read_proofs`] gathered it.
pub(crate) struct Proofs {
    /// One section per advertised attestation, in the store's own order.
    pub(crate) sections: Vec<Section>,
    /// How many attestations the store advertised. `0` is itself an answer, and what it
    /// *means* is the caller's: a change can be carried by a quorum verdict with no
    /// individual attestation at all, so refusing is decided after every piece of
    /// evidence is on the table.
    pub(crate) advertised: usize,
    /// Refusals about the set as a whole — a ref filed in a shape gitiup does not write,
    /// which is not evidence and is not silently skipped either.
    pub(crate) failures: Vec<Reason>,
    /// Anything worth printing that is advice rather than a refusal.
    pub(crate) notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// the quorum verdict
// ---------------------------------------------------------------------------

/// What the verdicts found for one change say about the merge question.
struct QuorumCall {
    /// The combination a verdict carries, when one reached the bar.
    accepted: Option<Accepted>,
    /// Every way in which the quorum refuses this merge.
    reasons: Vec<Reason>,
    notes: Vec<String>,
    outcome: CheckOutcome,
}

/// Read every verdict the store advertises for this change.
///
/// The change's own job list is *not* used to guess where to look: rounds are opened by
/// somebody else, for jobs the record may never have mentioned, so the question "what
/// does the store say about this change" is asked of the store by listing its prefix
/// ([`quorum_store::verdict_dir`]). Deriving the answer from the change would let a
/// verdict filed under an unexpected job go unread, which is a silent pass.
fn read_verdicts(
    host: &dyn gitiup_host::Host,
    id: &gitiup_host::change::ChangeId,
    roots: &Trust,
) -> Result<Vec<VerdictEntry>, CliError> {
    let dir = quorum_store::verdict_dir(id.as_str())
        .map_err(|e| CliError::scored(e.exit_code(), e.message(), e.hint().map(str::to_string)))?;
    let refs = host
        .list_refs(&RefQuery::prefix(format!("{ns}/{dir}", ns = ns::GITIUP)))
        .map_err(|e| change_cli::host_error("list verdicts", e))?;
    let mut out = Vec::new();
    for reference in refs {
        let name = reference.name.as_str().to_string();
        let bytes = match host.get(&reference.oid) {
            Ok(Some(bytes)) if Oid::hash_bytes(&bytes) == reference.oid => bytes,
            Ok(Some(_)) => {
                out.push(VerdictEntry::broken(
                    name,
                    8,
                    "the bytes there do not hash to the ref that names them",
                ));
                continue;
            }
            Ok(None) => {
                out.push(VerdictEntry::broken(
                    name,
                    8,
                    "the store advertises a verdict it cannot return",
                ));
                continue;
            }
            Err(error) if verify::corrupt(&error) => {
                out.push(VerdictEntry::broken(
                    name,
                    8,
                    format!("the store refused to hand over the verdict: {error}"),
                ));
                continue;
            }
            Err(error) => return Err(change_cli::host_error("read a verdict", error)),
        };
        match VerdictRecord::from_canonical_bytes(&bytes, roots) {
            Ok(verdict) => out.push(VerdictEntry {
                reference: name,
                record: Some(verdict),
                problem: None,
            }),
            Err(error) => out.push(VerdictEntry::broken(
                name,
                error.exit_code(),
                error.message(),
            )),
        }
    }
    out.sort_by(|one, other| one.reference.cmp(&other.reference));
    Ok(out)
}

/// Decide what the verdicts mean.
///
/// Three refusals and one gift:
///
/// * a verdict about another head or another change is a **digest mismatch** (8) — it is
///   not the thing that was asked about, which is how the attestation ladder spells a
///   wrong binding too;
/// * `failed` is a refusal whatever the policy says, because a recorded disagreement is
///   evidence against the merge and a gate that ignores it is choosing not to look;
/// * `insufficient` refuses only where the policy demands the `quorum` tier — elsewhere
///   it is "nobody voted yet", which is worth printing and not worth refusing a merge for;
/// * `verified` is quorum-tier evidence: the round's own `agreeing` count is what has to
///   reach `min_signatures`, and the keys are named from the verdict's counted votes.
fn judge_quorum(
    verdicts: &[VerdictEntry],
    sections: &[Section],
    head: &gitiup_attest::GitOid,
    required: usize,
    demands_quorum: bool,
) -> QuorumCall {
    let mut call = QuorumCall {
        accepted: None,
        reasons: Vec::new(),
        notes: Vec::new(),
        outcome: CheckOutcome::NotAsked,
    };
    if verdicts.is_empty() {
        // No verdict in the store is only a refusal where the owner's policy asks for a
        // quorum proof and nothing else about the change can pay for the merge: a policy
        // whose tiers include `local` is normally satisfied by one good attestation, and
        // refusing that because a round was never opened would be inventing a rule.
        if demands_quorum && !sections.iter().any(Section::accepted) {
            call.reasons.push(reason(
                "quorum",
                ErrorKind::Policy,
                "this change has no quorum verdict in the store, and the policy's accepted \
                 tiers are the ones a verdict is proof of"
                    .to_string(),
                Some(
                    "a round has to be run and tallied first; until a verdict exists nothing \
                     certifies this head at the tier the policy asks for, and whatever                      attestations it does have were refused above"
                        .to_string(),
                ),
            ));
            call.outcome = CheckOutcome::Failed;
        }
        return call;
    }
    call.outcome = CheckOutcome::Passed;
    for entry in verdicts {
        let Some(verdict) = &entry.record else {
            if let Some((exit, detail)) = &entry.problem {
                call.reasons.push(reason(
                    "quorum",
                    kind_of_exit(*exit),
                    format!("{}: {detail}", entry.reference),
                    None,
                ));
            }
            call.outcome = CheckOutcome::Failed;
            continue;
        };
        if verdict.head_oid != *head {
            call.reasons.push(reason(
                "quorum",
                ErrorKind::DigestMismatch,
                format!(
                    "{} is drawn against {}, not this change's head {}",
                    entry.reference, verdict.head_oid, head
                ),
                Some("a verdict is bound to the head it was computed from; re-run the round for this attempt".to_string()),
            ));
            call.outcome = CheckOutcome::Failed;
            continue;
        }
        let agreed = verdict
            .result_digest
            .as_ref()
            .map(|digest| digest.to_string())
            .unwrap_or_default();
        // Any proof this command is otherwise about to accept has to certify the same
        // result the quorum did, or the gate would be merging two different claims.
        for section in sections.iter().filter(|section| section.accepted()) {
            let same_job = section.job().is_none_or(|job| job == verdict.job_id);
            let clash = section
                .result_digest()
                .filter(|result| same_job && *result != agreed);
            if let Some(result) = clash {
                call.reasons.push(reason(
                    "quorum",
                    ErrorKind::Policy,
                    format!(
                        "the quorum agreed {} for job `{}` while {} certifies {}",
                        short(agreed.split(':').next_back().unwrap_or(&agreed)),
                        verdict.job_id,
                        short(&section.digest.hex()),
                        short(result.split(':').next_back().unwrap_or(&result))
                    ),
                    Some(
                        "the gate merges one result, not whichever one arrives first; \
                                 the disagreement is what the quorum's escalation round is for"
                            .to_string(),
                    ),
                ));
                call.outcome = CheckOutcome::Failed;
            }
        }
        match verdict.state {
            QuorumState::Verified => {
                if !demands_quorum {
                    // The owner signed a policy that does not accept the `quorum` tier,
                    // so a verdict — which *is* a quorum-tier proof — cannot satisfy it,
                    // however good it is. Trusting it anyway would be the gate deciding
                    // the owner's tier policy for them.
                    if sections.is_empty() {
                        call.reasons.push(reason(
                            "quorum",
                            ErrorKind::Policy,
                            format!(
                                "{} says `verified`, but the policy does not accept the `quorum` tier \
                                     ({}) and no attestation that it does accept is advertised",
                                entry.reference,
                                verdict.reason.as_str()
                            ),
                            Some(
                                "either publish a revision whose allowed_tiers includes quorum, \
                                 or file the individual attestations the policy does accept"
                                    .to_string(),
                            ),
                        ));
                        call.outcome = CheckOutcome::Failed;
                    } else {
                        call.notes.push(format!(
                            "{} says `verified` but the policy does not accept the `quorum` tier, \
                             so it is evidence and not a verdict this gate may rest on",
                            entry.reference
                        ));
                    }
                } else if verdict.agreeing >= required {
                    let signers: BTreeSet<String> = verdict
                        .counted
                        .iter()
                        .map(|vote| vote.key_id.clone())
                        .collect();
                    let candidate = Accepted {
                        via: "quorum verdict",
                        result_digest: verdict
                            .result_digest
                            .as_ref()
                            .map(|digest| digest.to_string()),
                        signers: signers.into_iter().collect(),
                        counted: vec![entry.reference.clone()],
                        required,
                        reference: Some(entry.reference.clone()),
                    };
                    if call
                        .accepted
                        .as_ref()
                        .is_none_or(|best| candidate.signers.len() > best.signers.len())
                    {
                        call.accepted = Some(candidate);
                    }
                } else {
                    call.reasons.push(reason(
                        "min_signatures",
                        ErrorKind::Policy,
                        format!(
                            "{} says `verified`, {} agreeing identities, and the policy requires {required} distinct signatures",
                            entry.reference, verdict.agreeing
                        ),
                        Some("the verdict's own round decided `verified` on its `required_agree`; the proof rule is the policy's, and the two have to agree".to_string()),
                    ));
                    call.outcome = CheckOutcome::Failed;
                }
            }
            QuorumState::Failed => {
                call.reasons.push(reason(
                    "quorum",
                    ErrorKind::Policy,
                    format!(
                        "{}: the verifiers disagree ({}): {}",
                        entry.reference,
                        verdict.reason.as_str(),
                        verdict.detail
                    ),
                    Some("escalation exists for exactly this (giti-msi.8); merging over a recorded disagreement is not what a gate is for".to_string()),
                ));
                call.outcome = CheckOutcome::Failed;
            }
            QuorumState::Insufficient => {
                if demands_quorum {
                    call.reasons.push(reason(
                        "quorum",
                        ErrorKind::Policy,
                        format!(
                            "{}: not enough eligible votes to decide ({}): {}",
                            entry.reference,
                            verdict.reason.as_str(),
                            verdict.detail
                        ),
                        Some("grow the roster or wait for the round; the policy demands this tier and the round cannot yet answer it".to_string()),
                    ));
                    call.outcome = CheckOutcome::Failed;
                } else {
                    call.notes.push(format!(
                        "{} says `insufficient` ({}): the policy does not demand the quorum tier, so this is not a refusal",
                        entry.reference,
                        verdict.reason.as_str()
                    ));
                }
            }
        }
    }
    call
}

// ---------------------------------------------------------------------------
// do the attestations add up
// ---------------------------------------------------------------------------

/// The combination of attestations that met the policy, or why none did.
pub(crate) struct Combination {
    pub(crate) accepted: Option<Accepted>,
    pub(crate) reasons: Vec<Reason>,
    pub(crate) notes: Vec<String>,
}

/// Group the accepted attestations by the result they certify, and take the widest.
///
/// `min_signatures` counts distinct trusted *signers*, and signers only add up if they
/// sign the same thing: three attestations from one key are one signature, and two that
/// certify different `ResultDigest`s certify different claims. That is the quorum's
/// `required_agree` rule expressed as the one field a repository writes for "how many
/// proofs make a set", and it is why the answer names the combination rather than the
/// count.
pub(crate) fn combine(sections: &[Section], required: usize) -> Combination {
    if sections.is_empty() {
        return Combination {
            accepted: None,
            reasons: Vec::new(),
            notes: Vec::new(),
        };
    }
    let accepted: Vec<&Section> = sections
        .iter()
        .filter(|section| section.accepted())
        .collect();
    if accepted.is_empty() {
        // Not a `min_signatures` refusal: nothing here got as far as counting. Every one
        // of these attestations was refused for a reason of its own, and each of those is
        // already in the report with its digest attached — a second, vaguer line on top
        // would be noise, and the exit code is decided by the reasons that are specific.
        return Combination {
            accepted: None,
            reasons: Vec::new(),
            notes: vec![format!(
                "none of the {} attestation(s) the store advertises passed on its own, so \
                 nothing could add up to the {required} the policy requires",
                sections.len()
            )],
        };
    }
    // digest → (distinct trusted signers, the attestations behind them)
    let mut groups: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    let mut resultless = 0usize;
    for section in &accepted {
        let Some(result) = section.result_digest() else {
            resultless += 1;
            continue;
        };
        let group = groups.entry(result).or_default();
        for signer in section.signers() {
            group.0.insert(signer);
        }
        group.1.insert(tagged(&section.digest));
    }
    let mut ordered: Vec<(String, BTreeSet<String>, BTreeSet<String>)> = groups
        .into_iter()
        .map(|(digest, (signers, attestations))| (digest, signers, attestations))
        .collect();
    // Widest agreement first; ties broken by the digest itself so the choice is a fact
    // about the store and not an artefact of a hash map's order.
    ordered.sort_by(|one, other| {
        other
            .1
            .len()
            .cmp(&one.1.len())
            .then_with(|| one.0.cmp(&other.0))
    });
    match ordered.first() {
        Some((digest, signers, attestations)) if signers.len() >= required => Combination {
            accepted: Some(Accepted {
                via: "attestations",
                result_digest: Some(digest.clone()),
                signers: signers.iter().cloned().collect(),
                counted: attestations.iter().cloned().collect(),
                required,
                reference: None,
            }),
            reasons: Vec::new(),
            notes: if accepted.len() > attestations.len() {
                vec![format!(
                    "{} other accepted attestation(s) certify a different result and were \
                         not counted",
                    accepted.len() - attestations.len()
                )]
            } else {
                Vec::new()
            },
        },
        Some((digest, signers, _)) => Combination {
            accepted: None,
            reasons: vec![reason(
                "min_signatures",
                ErrorKind::Policy,
                format!(
                    "the widest agreement among the accepted attestations is {} distinct \
                         trusted signer(s) on {digest} ({})",
                    signers.len(),
                    if signers.is_empty() {
                        "nobody trusted".to_string()
                    } else {
                        signers
                            .iter()
                            .map(|id| verify_short_key(id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
                Some(format!(
                    "the policy requires {required}; `min_signatures` counts distinct \
                         trusted signers certifying one result, so N copies of one key, or \
                         attestations that disagree, are not N signatures"
                )),
            )],
            notes: Vec::new(),
        },
        None => Combination {
            accepted: None,
            reasons: vec![reason(
                "min_signatures",
                ErrorKind::Policy,
                format!(
                    "{resultless} accepted attestation(s) carry no ResultDigest, so there \
                         is nothing for them to agree on"
                ),
                Some("a run that produced no result cannot certify a result".to_string()),
            )],
            notes: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// small shared pieces
// ---------------------------------------------------------------------------

/// Is an error a **verdict** (6, 7, 8: printed on stdout, carried in the exit code) or a
/// **fault** (2, 3: nothing was decided, so it goes to stderr)?
///
/// `Ok(())` means "this is a verdict"; `Err` hands back the fault for `main` to print.
/// The line is the same one `verify attestation` draws, and for the same reason: a hook
/// that has to parse stderr to find out it was refused will parse nothing.
fn verdictly(error: &CliError) -> Result<(), CliError> {
    if matches!(error.code, 6..=8) {
        Ok(())
    } else {
        Err(CliError::scored(
            error.code,
            error.message.clone(),
            error.hint.clone(),
        ))
    }
}

/// The failure class an exit code the library already decided came from.
fn kind_of_exit(code: u8) -> ErrorKind {
    match code {
        7 => ErrorKind::Signature,
        8 => ErrorKind::DigestMismatch,
        _ => ErrorKind::Policy,
    }
}

/// `sha256:<hex>`, the way a digest is spelled everywhere else in the report.
fn tagged(oid: &Oid) -> String {
    format!("sha256:{}", oid.hex())
}

/// Shorten a hex digest for a line of prose.
fn short(hex: &str) -> String {
    crate::attest::short(hex)
}

/// Shorten a `SHA256:…` key id the way the other commands do.
fn verify_short_key(key_id: &str) -> String {
    crate::participant::short(key_id)
}

/// Collapse a wrapped sentence onto one line.
fn one_line(text: &str) -> String {
    verify::one_line(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The help text is the contract a stranger reads, so it is checked against the
    /// parser rather than against anyone's memory of it.
    #[test]
    fn the_help_lists_every_flag_the_parser_accepts() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                VERIFY_CHANGE_HELP.contains(flag),
                "{flag} is accepted but not documented"
            );
        }
        for code in ["0", "2", "3", "6", "7", "8"] {
            assert!(
                VERIFY_CHANGE_HELP.contains(code),
                "exit {code} is missing from the help"
            );
        }
        assert!(VERIFY_CHANGE_HELP.contains("gitiup verify change <ID>"));
    }

    #[test]
    fn integrity_is_reported_before_authority() {
        assert!(
            rank(ErrorKind::DigestMismatch) < rank(ErrorKind::Signature),
            "a digest that is not the bytes it names has to be fixed before a signature \
             opinion means anything"
        );
        assert!(rank(ErrorKind::Signature) < rank(ErrorKind::Policy));
        assert_eq!(kind_of_exit(7), ErrorKind::Signature);
        assert_eq!(kind_of_exit(8), ErrorKind::DigestMismatch);
        assert_eq!(kind_of_exit(6), ErrorKind::Policy);
    }

    #[test]
    fn a_verdict_is_stdout_and_a_fault_is_stderr() {
        // 0 is not here because it is the `Ok(())` the caller already returned; 2 and 3
        // are not verdicts and must reach `main` as faults.
        for code in [6u8, 7, 8] {
            let error = CliError::scored(code, "refused", None);
            assert!(verdictly(&error).is_ok(), "exit {code} is a verdict");
        }
        for code in [2u8, 3] {
            let error = CliError::scored(code, "fault", None);
            assert!(verdictly(&error).is_err(), "exit {code} is a fault");
        }
    }

    #[test]
    fn no_attestations_is_nothing_to_combine() {
        let combination = combine(&[], 2);
        assert!(combination.accepted.is_none());
        assert!(
            combination.reasons.is_empty(),
            "an empty store is not a `min_signatures` refusal; the `attestations` check \
             is where that is said"
        );
    }
}

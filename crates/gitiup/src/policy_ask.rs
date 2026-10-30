//! `gitiup policy check` and `gitiup policy explain` — the policy, asked about a commit.
//!
//! [`crate::policy`] publishes the rules and answers "which policy is in force?". These
//! two commands are the other half of the surface: they take the effective policy and
//! apply it to something, then say *why* the answer is what it is.
//!
//! ```text
//! gitiup policy check  --commit <oid> --store ./store    # does what is stored satisfy it?
//! gitiup policy explain attestation proof.json          # every rule, its outcome, the evidence
//! gitiup policy explain change chg-6a6a --store ./store
//! ```
//!
//! # The split between the two
//!
//! They decide the same thing and differ in how much they show. `check` answers the gate's
//! question — satisfied, or not, and the one reason that decided it — because a CI step
//! that only needs a number should get a number. `explain` prints every rule, including
//! the ones that passed, each with both halves of the evidence: what the policy demands
//! and what the run actually claimed. That is the document a person posts in a bug report
//! and a CI step posts as a comment, and it is why the shape of it is a contract (below).
//!
//! `verify change` is the merge gate over a *change*: the change record, the ref it would
//! merge into, the quorum verdict. These two commands ask about a *subject* — a commit, a
//! document, a change — and say nothing about a merge they were not asked about. All of
//! them read the same store through the same code ([`crate::verify_change::read_proofs`]),
//! because four commands with four readings of "what does the store say about this commit"
//! is [ADR-0004 T15](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md):
//! the same evidence, four different answers.
//!
//! # Why `explain` lists the rules that passed
//!
//! A report of only the failures teaches "these are wrong"; a report of every rule teaches
//! "this is what the gate knows", which is the difference between a log someone can act on
//! and one they re-run with more flags. It is also the only way to see a rule that
//! *silently did nothing*: `environment: not asked` is how you notice that the machine
//! class you published is not being compared, and `min_signatures: not asked` is how you
//! notice the policy's number is being applied to the set of proofs and not to this one.
//!
//! # The order is the answer
//!
//! Rules print in [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)'s
//! order — structure, digests, bindings, environment, signatures, trust, count, tier,
//! sandbox, freshness — which is not a display preference. That order is the one
//! `AttestationDoc::verify_report` evaluates in and the one whose **first** failure decides
//! the exit code, so printing in that order makes the first failing line of `explain`
//! literally the reason a gate refused, in the same words, from the same code. Reordering
//! the display for readability would put a symptom above its cause, which is the exact
//! failure D7 exists to prevent.
//!
//! # The `--json` document is what a CI step posts
//!
//! One entry per rule, always the same keys:
//!
//! ```text
//! {"rule":"tier","outcome":"failed",
//!  "evidence":{"policy":"one of: local","claim":"simulated"},
//!  "detail":"provenance tier 'simulated' is not accepted here",
//!  "hint":"a simulated run plans but does not execute…","exit":6}
//! ```
//!
//! `rule` is the same stable code a `gitiup verify --json` report uses (ADR-0001 D7's
//! ladder), `outcome` is `passed · failed · not_asked · not_run` — the same four words
//! `verify --json` prints, so one parser reads both — and `evidence` holds the two sides
//! of the comparison: what the policy demands and what the subject claimed. `detail`,
//! `hint` and `exit` are present exactly when the rule failed, and are the library's own
//! sentence, not a paraphrase of it: a CI comment that says something the verifier did not
//! say is a CI comment nobody can trust.
//!
//! # Exit codes
//!
//! The same table as `verify`, because these commands are verdicts and not tools that
//! happen to print one: **0** satisfied · **2** usage · **3** I/O or an unreachable store
//! · **6** refused (no policy published, no proof stored, a tier, sandbox, key, age or
//! machine class the policy refuses, too few distinct signatures) · **7** a signature that
//! does not verify · **8** bytes that are not what they are named for. 0, 6, 7 and 8 print
//! the report on **stdout** and say nothing on stderr, so a hook can branch on `$?` and a
//! CI step can post stdout unmodified.

use gitiup_attest::{
    AttestationDoc, CheckOutcome, GitOid, Policy, Reason, TimeUs, Trust, VerdictReport,
};
use gitiup_quorum::policy::{Purpose, ResolvedPolicy, Source};
use serde_json::{Map, Value, json};

use crate::CliError;
use crate::change as change_cli;
use crate::keys::Args;
use crate::participant::Opened;
use crate::verify::{self, human_age, one_line};
use crate::verify_change::{self, Accepted, Question, Section, read_proofs};

/// Valued flags for `policy check`.
const CHECK_VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--commit",
    "--policy",
    "--tree-file",
    "--trust",
    "--at",
    "--now",
    "--ref",
];

/// Switches for `policy check`.
const CHECK_SWITCHES: &[&str] = &["--json", "-j", "-q", "--quiet", "--gate", "--advisory"];

/// Valued flags for `policy explain`.
///
/// `--commit` does double duty: with a document it is the binding to check, and with
/// `--store` it is how the proof is found in the first place (the same duality `gitiup
/// verify attestation` already has, kept the same on purpose).
const EXPLAIN_VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--digest",
    "--commit",
    "--change",
    "--attempt",
    "--expect-result",
    "--policy",
    "--tree-file",
    "--trust",
    "--at",
    "--now",
    "--ref",
];

/// Switches for `policy explain`.
const EXPLAIN_SWITCHES: &[&str] = &["--json", "-j", "-q", "--quiet", "--gate", "--advisory"];

/// The checks `check` and `explain` run over a commit: the policy, then the proofs.
///
/// Deliberately not `verify change`'s list. There is no change record here to resolve and
/// no target ref to gate, and a check that did not run is printed as `not_run` rather than
/// left out — an absent line is a silent answer, and a `not_run` line is an honest one.
const COMMIT_CHECKS: &[&str] = &["policy", "protects", "attestations", "min_signatures"];

// ---------------------------------------------------------------------------
// the rules
// ---------------------------------------------------------------------------

/// One rule of the effective policy: what it demands, what the subject claims, how it
/// went, and the library's own sentence when it went wrong.
///
/// This is the unit of the whole command: the ticket's promise is "every rule, whether it
/// passed, and the sentence that explains the failure", and a rule with only an outcome
/// attached is the ladder `verify` already prints. The two halves of the evidence are the
/// new content, and they are kept as two strings rather than one so that a CI template can
/// put them in two table cells and a human can see the mismatch without reading prose.
pub(crate) struct Rule {
    /// The stable code, from the attestation ladder or [`COMMIT_CHECKS`].
    pub(crate) code: &'static str,
    pub(crate) outcome: CheckOutcome,
    /// What the policy demands of this rule, in words.
    pub(crate) demands: String,
    /// What the subject claims, or what the store holds, in words.
    pub(crate) claims: String,
    /// The library's sentence, when the rule failed.
    pub(crate) detail: Option<String>,
    /// The library's hint, when it has one.
    pub(crate) hint: Option<String>,
    /// The exit code this rule alone would produce.
    pub(crate) exit: Option<u8>,
}

impl Rule {
    fn pass(code: &'static str, demands: impl Into<String>, claims: impl Into<String>) -> Rule {
        Rule {
            code,
            outcome: CheckOutcome::Passed,
            demands: demands.into(),
            claims: claims.into(),
            detail: None,
            hint: None,
            exit: None,
        }
    }

    fn outcome(
        code: &'static str,
        outcome: CheckOutcome,
        demands: impl Into<String>,
        claims: impl Into<String>,
    ) -> Rule {
        Rule {
            code,
            outcome,
            demands: demands.into(),
            claims: claims.into(),
            detail: None,
            hint: None,
            exit: None,
        }
    }

    /// The same rule, filled in from the reason that decided it.
    ///
    /// The detail and the hint are the library's words, copied and not rewritten: the
    /// sentence in an `explain` output has to be the sentence the verifier evaluated, or
    /// the report is a rumour about the verdict.
    fn with(mut self, reason: Option<&Reason>) -> Rule {
        if let Some(reason) = reason {
            self.detail = Some(one_line(reason.detail()));
            self.hint = reason.hint().map(one_line);
            self.exit = Some(reason.exit_code());
        }
        self
    }

    fn json(&self) -> Value {
        let mut out = Map::new();
        out.insert("rule".into(), self.code.into());
        out.insert("outcome".into(), self.outcome.as_str().into());
        out.insert(
            "evidence".into(),
            json!({ "policy": self.demands, "claim": self.claims }),
        );
        if let Some(detail) = &self.detail {
            out.insert("detail".into(), detail.clone().into());
        }
        if let Some(hint) = &self.hint {
            out.insert("hint".into(), hint.clone().into());
        }
        if let Some(exit) = self.exit {
            out.insert("exit".into(), (exit as u64).into());
        }
        Value::Object(out)
    }

    fn render(&self) -> String {
        let mut line = format!(
            "  {:<15} {:<10}needs: {}  ·  claims: {}",
            self.code,
            verify::state_word(self.outcome),
            self.demands,
            self.claims,
        );
        let mut out = String::new();
        // The evidence line is long; a failure's sentence belongs under it, aligned, so a
        // reader scans the outcomes in one column and reads the sentence of the one they
        // care about without losing their place.
        out.push_str(line.trim_end());
        out.push('\n');
        line.clear();
        if let Some(detail) = &self.detail {
            out.push_str(&format!("  {:<15} {:<10}→ {detail}", "", ""));
            out.push('\n');
        }
        if let Some(hint) = &self.hint {
            out.push_str(&format!("  {:<15} {:<10}  hint: {hint}", "", ""));
            out.push('\n');
        }
        out
    }
}

/// The reason that decides one code, if any. `verify_report` keeps every failure it found
/// in D7 order, so this is the sentence that *made* the outcome and not a guess at one.
fn reason_for<'a>(report: &'a [Reason], code: &str) -> Option<&'a Reason> {
    report
        .iter()
        .find(|reason| reason.code == code && reason.exit_code() != 0)
}

/// Every rule of the attestation ladder, in ADR-0001 D7's order, with both halves of the
/// evidence.
///
/// The outcomes come from the report — they *are* what the verifier evaluated — and the
/// `demands`/`claims` strings are built here from the same two inputs the checks read: the
/// resolved [`Policy`] and the document. That is the whole risk of this module: a paraphrase
/// that drifts from the check it describes. So the strings name values the checks name
/// (the tier, the sandbox, the key ids, the window and the age, the required architecture)
/// and quote nothing the library did not compute.
pub(crate) fn ladder(
    policy: Option<&Policy>,
    doc: Option<&AttestationDoc>,
    report: &VerdictReport,
    source: &str,
    now: TimeUs,
) -> Vec<Rule> {
    let reasons = &report.reasons;
    gitiup_attest::CHECK_ORDER
        .iter()
        .map(|code| {
            let outcome = report.outcome(code);
            let rule = Rule::outcome(
                code,
                outcome,
                demanded(code, policy),
                claimed(code, policy, doc, source, report, now),
            );
            rule.with(reason_for(reasons, code))
        })
        .collect()
}

/// What the policy demands of one rule, in the words a reader needs to act on.
fn demanded(code: &str, policy: Option<&Policy>) -> String {
    /// The honest answer when there is no policy to read demands from: not a guess at one.
    const UNKNOWN: &str = "unknown - no policy was resolved, so nothing was demanded";
    let tiers: Vec<&str> = policy
        .map(|policy| {
            policy
                .allowed_tiers
                .iter()
                .map(|tier| tier.as_str())
                .collect()
        })
        .unwrap_or_default();
    match code {
        "structure" => "a canonical attestation this build speaks".to_string(),
        "digest" => "the manifest re-hashes to the run digest it names".to_string(),
        "commit" => policy
            .and_then(|policy| policy.expected_commit.clone())
            .map_or_else(
                || "nothing was bound: any commit is accepted".to_string(),
                |commit| format!("about {commit}"),
            ),
        "result" => policy
            .and_then(|policy| policy.expected_result_digest.clone())
            .map_or_else(
                || "no result was required".to_string(),
                |digest| format!("result {digest}"),
            ),
        "challenge" => policy
            .and_then(|policy| policy.expected_challenge.clone())
            .map_or_else(
                || "no challenge was asked".to_string(),
                |digest| format!("challenge {digest}"),
            ),
        "normalisation" => policy
            .and_then(|policy| policy.normalisation_version)
            .map_or_else(
                || "any normalisation version".to_string(),
                |version| format!("normalisation v{version}"),
            ),
        "environment" => policy
            .and_then(|policy| policy.environment_requirement())
            .map_or_else(
                || "nothing required of the machine".to_string(),
                |requirement| {
                    format!(
                        "{requirement} ({})",
                        policy
                            .map(|policy| policy.require_env_match.as_str())
                            .unwrap_or("?")
                    )
                },
            ),
        "signature" => {
            "every signature verifies, and each key id is that key's fingerprint".to_string()
        }
        "trust" => match policy.map(|policy| &policy.trust) {
            None => UNKNOWN.to_string(),
            Some(Trust::None) => "nobody: this policy accepts no signer".to_string(),
            Some(Trust::AnyKeyForTests) => {
                "any key whose signature verifies (diagnosis only)".to_string()
            }
            Some(Trust::KeyIds(ids)) => {
                let ids: Vec<String> = ids.iter().map(|id| crate::participant::short(id)).collect();
                format!("{} trusted key(s): {}", ids.len(), shorten_list(&ids))
            }
        },
        "min_signatures" => policy.map_or_else(
            || UNKNOWN.to_string(),
            |policy| format!("{} distinct trusted signature(s)", policy.min_signatures),
        ),
        "tier" => {
            if tiers.is_empty() {
                UNKNOWN.to_string()
            } else {
                format!("one of: {}", tiers.join("+"))
            }
        }
        "sandbox" => match policy {
            None => UNKNOWN.to_string(),
            Some(policy) if policy.allowed_sandboxes.is_empty() => {
                "any sandbox a `local` run may name".to_string()
            }
            Some(policy) => format!("one of: {}", policy.allowed_sandboxes.join("+")),
        },
        "freshness" => match policy {
            None => UNKNOWN.to_string(),
            Some(policy) => format!(
                "no older than {}, skew up to {}",
                human_age(policy.max_age_us),
                human_age(policy.max_clock_skew_us)
            ),
        },
        "expiry" => "the attestation's own validity window still open".to_string(),
        other => other.to_string(),
    }
}

/// What the subject claims, or — when there was no document to ask — what went wrong
/// before any rule could be evaluated.
fn claimed(
    code: &str,
    policy: Option<&Policy>,
    doc: Option<&AttestationDoc>,
    source: &str,
    report: &VerdictReport,
    now: TimeUs,
) -> String {
    let Some(doc) = doc else {
        return report
            .primary()
            .map(|reason| format!("nothing was read: {}", one_line(reason.detail())))
            .unwrap_or_else(|| "nothing was read".to_string());
    };
    let manifest = &doc.manifest;
    let provenance = &manifest.result.provenance;
    let environment = &manifest.result.environment;
    let signers: Vec<String> = doc
        .signatures
        .iter()
        .map(|entry| entry.key_id.clone())
        .collect();
    let trusted: Vec<String> = signers
        .iter()
        .filter(|id| policy.is_some_and(|policy| policy.trust.trusts(id)))
        .map(|id| crate::participant::short(id))
        .collect();
    let offered = shorten_list(
        &signers
            .iter()
            .map(|id| crate::participant::short(id))
            .collect::<Vec<String>>(),
    );
    match code {
        "structure" => source.to_string(),
        "digest" => doc
            .run_digest()
            .map(|digest| digest.to_string())
            .unwrap_or_else(|_| "the manifest will not re-hash".to_string()),
        "commit" => manifest.result.source.commit.to_string(),
        "result" => doc
            .result_digest()
            .ok()
            .map(|digest| digest.to_string())
            .unwrap_or_else(|| "no result digest".to_string()),
        "challenge" => manifest
            .claims
            .verifier_challenge
            .as_ref()
            .map(|digest| digest.to_string())
            .unwrap_or_else(|| "none claimed".to_string()),
        "normalisation" => format!("v{}", provenance.normalisation_version),
        "environment" => format!(
            "{} · fingerprint {}",
            environment.describe(),
            crate::attest::short(&environment.fingerprint.to_string())
        ),
        "signature" if signers.is_empty() => "nobody signed it".to_string(),
        "signature" => format!("{offered} ({})", doc.signatures.len()),
        "trust" if signers.is_empty() => "no signature to trust".to_string(),
        "trust" => match trusted.len() {
            0 => format!("{offered}: none of them trusted here"),
            n => format!("{n} of {} trusted here", signers.len()),
        },
        "min_signatures" if trusted.is_empty() => {
            "0 trusted signatures on this document".to_string()
        }
        "min_signatures" => {
            format!("{} trusted signature(s) on this document", trusted.len())
        }
        "tier" => match provenance.tier.trust_warning() {
            Some(warning) => format!("{} — {}", provenance.tier.as_str(), one_line(warning)),
            None => provenance.tier.as_str().to_string(),
        },
        "sandbox" => provenance
            .sandbox
            .clone()
            .unwrap_or_else(|| "none named".to_string()),
        "freshness" => format!(
            "claimed {}, {} old against {}",
            gitiup_attest::TimeUs(manifest.claims.claimed_at_us).to_rfc3339(),
            human_age((now.0 - manifest.claims.claimed_at_us).max(0)),
            now.to_rfc3339()
        ),
        "expiry" => manifest.claims.not_after_us.map_or_else(
            || "no window of its own".to_string(),
            |us| format!("closes {}", gitiup_attest::TimeUs(us).to_rfc3339()),
        ),
        other => other.to_string(),
    }
}

/// A list short enough to print on one line, with the count kept honest by the caller.
fn shorten_list(items: &[String]) -> String {
    const MOST: usize = 3;
    if items.len() <= MOST {
        return items.join(", ");
    }
    format!("{}, +{} more", items[..MOST].join(", "), items.len() - MOST)
}

// ---------------------------------------------------------------------------
// the answer
// ---------------------------------------------------------------------------

/// One proof the store advertised, rendered as rules instead of as a check list.
struct Proof {
    digest: String,
    reference: String,
    source: String,
    verdict: &'static str,
    exit: u8,
    accepted: bool,
    policy: Option<ResolvedPolicy>,
    rules: Vec<Rule>,
    notes: Vec<String>,
}

impl Proof {
    /// The one line `check` prints per proof: which proof, and what it came to. The
    /// rule-by-rule detail underneath it is what `explain` is for.
    fn summary(&self, index: usize) -> String {
        format!(
            "\n  [{}] {}  {} (exit {})",
            index + 1,
            self.digest,
            if self.accepted { "ACCEPTED" } else { "REFUSED" },
            self.exit
        )
    }

    fn json(&self) -> Value {
        let mut out = Map::new();
        out.insert("digest".into(), self.digest.clone().into());
        out.insert("ref".into(), self.reference.clone().into());
        out.insert("source".into(), self.source.clone().into());
        out.insert("verdict".into(), self.verdict.into());
        out.insert("exit".into(), (self.exit as u64).into());
        out.insert("accepted".into(), self.accepted.into());
        out.insert(
            "policy".into(),
            self.policy
                .as_ref()
                .map(verify_change::policy_block)
                .unwrap_or(Value::Null),
        );
        out.insert(
            "rules".into(),
            Value::Array(self.rules.iter().map(Rule::json).collect()),
        );
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

    fn render(&self, index: usize, out: &mut String) {
        out.push_str(&self.summary(index));
        out.push('\n');
        for note in &self.notes {
            out.push_str(&format!("      note     {}\n", one_line(note)));
        }
        out.push_str("      rules\n");
        for rule in &self.rules {
            for line in rule.render().lines() {
                out.push_str(&format!("    {line}\n"));
            }
        }
    }
}

/// Everything one `check` or `explain` run established, in the shape both commands print.
///
/// One structure and two renderings, so the terse gate answer and the long explanation
/// cannot disagree about the same evidence — they are the same value with a different
/// amount of it shown.
pub(crate) struct Explanation {
    /// `policy-check` or `policy-explanation`: what a script is parsing.
    record: &'static str,
    /// `commit` · `attestation` · `change`.
    kind: &'static str,
    /// Where the subject came from, in the words the reader asked with.
    source: String,
    /// The subject, as labelled rows: commit, change, run, claim, signed, claimed.
    subject: Vec<(String, String)>,
    policy: Option<ResolvedPolicy>,
    /// The subject-level rules, in [`COMMIT_CHECKS`] or [`CHANGE_CHECKS`] order — the
    /// rules *above* the ladder, for a subject that has them.
    rules: Vec<Rule>,
    /// The ladder itself: one rule set per proof (one entry for an attestation subject).
    proofs: Vec<Proof>,
    /// The combination that reached the policy's number, when one did.
    accepted: Option<Accepted>,
    reasons: Vec<Reason>,
    notes: Vec<String>,
    now: TimeUs,
    verdict: &'static str,
    exit: u8,
    satisfied: bool,
}

impl Explanation {
    fn new(
        record: &'static str,
        kind: &'static str,
        source: impl Into<String>,
        now: TimeUs,
    ) -> Explanation {
        Explanation {
            record,
            kind,
            source: source.into(),
            subject: Vec::new(),
            policy: None,
            rules: Vec::new(),
            proofs: Vec::new(),
            accepted: None,
            reasons: Vec::new(),
            notes: Vec::new(),
            now,
            verdict: "policy",
            exit: 6,
            satisfied: false,
        }
    }

    /// Close the document: sort the failures the way the ladder sorts them — integrity
    /// before authority before policy, because the first one is the exit code and a reader
    /// deserves the cause rather than the loudest symptom.
    /// sort the failures, and let the highest-ranking one decide the
    /// exit code and the headline. `satisfied` is always the caller's verdict — the gate's
    /// own, never something recomputed here, because a recomputed one could disagree with
    /// the gate it claims to explain.
    fn finish(mut self, satisfied: bool) -> Explanation {
        self.reasons
            .sort_by_key(|reason| verify_change::rank(reason.class()));
        self.satisfied = satisfied;
        self.verdict = if self.satisfied {
            "pass"
        } else {
            self.reasons
                .first()
                .map_or("policy", |reason| reason.class().as_str())
        };
        self.exit = if self.satisfied {
            0
        } else {
            self.reasons.first().map_or(6, |reason| reason.exit_code())
        };
        self
    }

    /// The verdict as the process exit code — `pub(crate)` for the same reason the
    /// renderer is: a `pre-receive` hook that recomputed this number would be a second
    /// gate, and two gates disagree.
    pub(crate) fn code(&self) -> u8 {
        self.exit
    }

    pub(crate) fn satisfied(&self) -> bool {
        self.satisfied
    }

    /// The process exit code is the verdict, and it is the same ladder `gitiup verify`
    /// uses, so a hook cannot get one answer from one command and a different one from
    /// this one.
    fn exit(&self) -> Result<(), CliError> {
        if self.satisfied {
            return Ok(());
        }
        Err(CliError::verdict(self.exit))
    }

    /// The word a `--quiet` gate prints, and the word a one-line hook summary leads with.
    pub(crate) fn quiet(&self) -> String {
        if self.satisfied {
            return "satisfied".to_string();
        }
        self.reasons
            .first()
            .map_or("policy", |reason| reason.code)
            .to_string()
    }

    /// The primary reason, as the one-line sentence every report leads with.
    pub(crate) fn headline(&self) -> String {
        match self.reasons.first() {
            Some(reason) => format!("[{}] {}", reason.code, one_line(reason.detail())),
            None if self.satisfied => "every rule the policy names was satisfied".to_string(),
            None => "nothing satisfied the policy".to_string(),
        }
    }

    fn policy_json(&self) -> Value {
        match &self.policy {
            Some(resolved) => verify_change::policy_block(resolved),
            None => Value::Null,
        }
    }

    fn subject_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("kind".into(), self.kind.into());
        out.insert("source".into(), self.source.clone().into());
        for (label, value) in &self.subject {
            out.insert(
                label.clone().replace(' ', "_"),
                Value::String(value.clone()),
            );
        }
        Value::Object(out)
    }

    /// The stable machine-readable document: see this module's docs for why each key is
    /// there and why none of them is optional. `pub(crate)` so that the hook's `--json`
    /// carries *this* document and not a summary of it.
    pub(crate) fn json(&self) -> Value {
        let mut out = Map::new();
        out.insert("record_type".into(), self.record.into());
        out.insert("verdict".into(), self.verdict.into());
        out.insert("exit".into(), (self.exit as u64).into());
        out.insert("satisfies".into(), self.satisfied.into());
        out.insert("subject".into(), self.subject_json());
        out.insert("policy".into(), self.policy_json());
        out.insert(
            "checks".into(),
            Value::Array(
                self.rules
                    .iter()
                    .map(|rule| json!({"code": rule.code, "outcome": rule.outcome.as_str()}))
                    .collect::<Vec<Value>>(),
            ),
        );
        out.insert(
            "rules".into(),
            Value::Array(self.rules.iter().map(Rule::json).collect()),
        );
        out.insert(
            "attestations".into(),
            Value::Array(self.proofs.iter().map(Proof::json).collect()),
        );
        out.insert(
            "accepts".into(),
            self.accepted
                .as_ref()
                .map(|accepted| {
                    json!({
                        "via": accepted.via,
                        "result_digest": accepted.result_digest,
                        "signers": accepted.signers,
                        "counted": accepted.counted,
                        "required": accepted.required,
                        "ref": accepted.reference,
                    })
                })
                .unwrap_or(Value::Null),
        );
        out.insert(
            "reasons".into(),
            Value::Array(verify::reasons_json(&self.reasons)),
        );
        out.insert("clock".into(), self.now.to_rfc3339().into());
        out.insert("clock_us".into(), (self.now.0 as u64).into());
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

    /// The human report. `full` is the difference between `check` and `explain`: the same
    /// answer, and — in `explain` — every rule that ran, passed or not. `pub(crate)`
    /// because a refused push prints this report, unchanged, on the other end of a
    /// network: the sentence the hook saw is the sentence the pusher reads.
    pub(crate) fn text(&self, full: bool) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{}  {}\n",
            if self.satisfied {
                "SATISFIED".to_string()
            } else {
                format!("REFUSED (exit {})", self.exit)
            },
            if self.satisfied {
                self.accepted_line()
            } else {
                self.headline()
            }
        ));
        out.push_str(&format!("{:<14}{}\n", "subject", self.kind));
        for (label, value) in &self.subject {
            out.push_str(&format!("{:<14}{}\n", label, value));
        }
        out.push_str(&format!("{:<14}{}\n", "source", self.source));
        if let Some(policy) = &self.policy {
            out.push_str(&format!(
                "{:<14}{}\n",
                "policy",
                one_line(&verify_change::policy_summary(policy))
            ));
        }
        out.push_str(&format!("{:<14}{}\n", "clock", self.now.to_rfc3339()));
        for note in &self.notes {
            out.push_str(&format!("{:<14}{}\n", "note", one_line(note)));
        }

        out.push_str("\nrules\n");
        for rule in &self.rules {
            out.push_str(&rule.render());
        }
        for (index, proof) in self.proofs.iter().enumerate() {
            if full {
                proof.render(index, &mut out);
            } else {
                // `check` names the proofs and their verdicts; the rule-by-rule detail is
                // what `explain` is for, and printing it here would be a wall of text on a
                // gate that asked for a number.
                out.push_str(&proof.summary(index));
                out.push('\n');
            }
        }
        for (index, reason) in self.reasons.iter().enumerate() {
            let label = if index == 0 { "reason" } else { "also" };
            out.push_str(&format!(
                "{:<14}[{}] {}\n",
                label,
                reason.code,
                one_line(reason.detail())
            ));
        }
        out
    }

    /// The sentence that says *what was accepted*, because "satisfied" without the
    /// combination is a claim a reader cannot check. `pub(crate)` because the accepted line
    /// is what a pusher is told when a gate lets their branch move: "proven", plus by what.
    pub(crate) fn accepted_line(&self) -> String {
        let Some(accepted) = &self.accepted else {
            return self.headline();
        };
        format!(
            "{}: {}  ·  {} distinct trusted signer(s) of {}  ·  result {}",
            accepted.via,
            accepted.counted.join(", "),
            accepted.signers.len(),
            accepted.required,
            accepted.result_digest.clone().unwrap_or_else(|| "?".into())
        )
    }
}

// ---------------------------------------------------------------------------
// `gitiup policy check`
// ---------------------------------------------------------------------------

/// The clock the verdict is judged against: `--now` for a replay, the wall clock otherwise.
pub(crate) fn clock(args: &Args) -> Result<TimeUs, CliError> {
    match args.get("--now") {
        Some(text) => {
            TimeUs::parse(text).map_err(|e| CliError::usage(format!("--now '{text}': {e}")))
        }
        None => Ok(TimeUs::now()),
    }
}

/// An explicit walk timestamp, when `--at` pinned one.
pub(crate) fn walked(args: &Args) -> Result<Option<TimeUs>, CliError> {
    match args.get("--at") {
        Some(text) => TimeUs::parse(text)
            .map(Some)
            .map_err(|e| CliError::usage(format!("--at '{text}': {e}"))),
        None => Ok(None),
    }
}

/// Why the policy is being resolved. A gate by default — these commands exist to answer
/// gate questions — and `--advisory` is the honest way to ask a question instead.
pub(crate) fn purpose(args: &Args) -> Purpose {
    if args.on("--advisory") && !args.on("--gate") {
        Purpose::Advisory
    } else {
        Purpose::Gate
    }
}

/// The rule above all the others, spelled once because every report has to say it and a
/// paraphrase in twelve places is a paraphrase that drifts.
const POLICY_DEMAND: &str =
    "a policy a merge may rest on: published, signed by a key you trust, and in force";

/// `gitiup policy check --commit <oid>`: does what the store holds about this commit
/// satisfy the policy in force?
pub(crate) fn check(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, CHECK_VALUED, CHECK_SWITCHES)?;
    if args.help(crate::policy::POLICY_HELP).is_some() {
        return Ok(());
    }
    let named = match args.get("--commit") {
        Some(text) => text.to_string(),
        None => match args.positional.first() {
            Some(text) => text.clone(),
            None => {
                return Err(CliError::usage(
                    "say which commit: `gitiup policy check --commit <oid> --store <dir>`. A \
                     change is a different question, and `gitiup verify change` answers it.",
                ));
            }
        },
    };
    let commit = verify::commit_id(&named)?;
    let store = change_cli::read_store(&args)?;
    let now = clock(&args)?;
    let at = walked(&args)?;
    let mut question = Question::new(Some(&store), &args, now, at, None)?;
    if purpose(&args) == Purpose::Advisory {
        question.ask_advisory();
    }

    let out = verdict_for_commit(&store, &commit, args.get("--ref"), &question, now)?;
    print(out, &args, false)
}

/// The verdict about one commit at one ref, as one document.
///
/// `gitiup policy check` prints this, and so does the `pre-receive` hook
/// (`gitiup hook run pre-receive`), which is the only way the box that accepted a push
/// and the person who pushed at it can be *known* to have seen the same answer: one
/// assessment, two renderings ([`crate::policy_ask::Explanation`]'s own trick, one level
/// up). The hook hand-builds its [`Question`] because [ADR-0004
/// D4](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md) says it
/// takes no override; that is the only difference between the two callers.
pub(crate) fn verdict_for_commit(
    store: &Opened,
    commit: &GitOid,
    reference: Option<&str>,
    question: &Question<'_>,
    now: TimeUs,
) -> Result<Explanation, CliError> {
    let mut out = Explanation::new("policy-check", "commit", store.what.clone(), now);
    out.subject.push(("commit".to_string(), commit.to_string()));
    // A gate that names the ref it was asked about says which rule applied to it; a
    // commit on its own is not a ref, and `protects` knows the difference.
    if let Some(reference) = reference {
        out.subject.push(("ref".to_string(), reference.to_string()));
    }
    ask_commit(store, commit, reference, question, &mut out)?;
    // Some proofs adding up is one of the answers, not the whole of it. A store holding
    // one broken proof and one good one is not a store a merge may trust, so any standing
    // refusal means `not satisfied` — and, exactly as `verify change` does, the accepted
    // combination is not printed while a refusal stands, because `accepts: …` next to a
    // refusal would be two answers at once. The rule itself keeps its own honest outcome:
    // the count *did* add up, and saying otherwise would blame the wrong rule.
    let satisfied = out.accepted.is_some() && out.reasons.is_empty();
    if !satisfied {
        out.accepted = None;
    }
    Ok(out.finish(satisfied))
}

/// Judge every proof the store advertises for one commit against the effective policy.
///
/// The same three questions `verify change` asks, minus the ones a bare commit cannot
/// answer: is there a policy at all, does the store have a proof of this commit whose
/// bytes are what they claim, and do the accepted ones add up to what the policy counts as
/// a proof? Nothing here is decided twice; the reading of the store and the counting of the
/// signatures are the merge gate's own functions.
fn ask_commit(
    store: &Opened,
    commit: &GitOid,
    reference: Option<&str>,
    question: &Question<'_>,
    out: &mut Explanation,
) -> Result<(), CliError> {
    let at = question.at.unwrap_or(question.now);
    let from = if question.at.is_some() {
        "run-claim"
    } else {
        "now"
    };
    let resolved = match question.resolve(at, from) {
        Ok(resolved) => {
            out.notes.extend(notes_of(&resolved));
            out.rules.push(policy_rule(&resolved));
            Some(resolved)
        }
        Err(error) => {
            let reason = verify_change::policy_reason(&error);
            out.rules.push(
                Rule::outcome(
                    "policy",
                    CheckOutcome::Failed,
                    POLICY_DEMAND,
                    "nothing was resolved",
                )
                .with(Some(&reason)),
            );
            out.reasons.push(reason);
            None
        }
    };
    out.policy = resolved.clone();
    let Some(resolved) = resolved else {
        // Nothing to judge by. Every other rule is `not_run` rather than missing: a reader
        // parsing this in a hook sees how far the gate got, which is the whole point of
        // listing the checks that never ran.
        for code in COMMIT_CHECKS.iter().skip(1) {
            out.rules.push(Rule::outcome(
                code,
                CheckOutcome::NotRun,
                "the policy that was refused above",
                "nothing was judged",
            ));
        }
        return Ok(());
    };
    let policy = resolved.policy.clone();

    // Does this policy even govern the ref the caller cares about? Only answerable when the
    // caller names one: a commit is not a ref, and a gate that guessed which branch was
    // meant would be applying `protects` rules nobody asked it to apply.
    out.rules.push(match reference {
        None => Rule::outcome(
            "protects",
            CheckOutcome::NotAsked,
            "the ref a push or a merge would land on",
            "no --ref was given: a commit is not a ref, so this was not asked",
        ),
        Some(reference) => match resolved.document.as_ref() {
            None => Rule::outcome(
                "protects",
                CheckOutcome::NotAsked,
                "a published policy's `protects` globs",
                "the policy came from a file, which gates whatever it is pointed at",
            ),
            Some(document) => {
                let globs = document.protects().to_vec();
                let governs = document.protects_ref(reference);
                let rule = Rule::outcome(
                    "protects",
                    if governs {
                        CheckOutcome::Passed
                    } else {
                        CheckOutcome::Failed
                    },
                    format!("one of: {}", globs.join(", ")),
                    reference.to_string(),
                );
                if governs {
                    rule
                } else {
                    let failure = verify_change::reason(
                        "protects",
                        gitiup_attest::ErrorKind::Policy,
                        format!(
                            "the policy in force gates [{}] and not {reference}, so it does \
                             not govern a push to it",
                            globs.join(", ")
                        ),
                        Some(
                            "publish a revision whose `protects` covers the ref, or do not \
                             gate a ref nobody signed rules for (ADR-0004 D1)"
                                .to_string(),
                        ),
                    );
                    out.reasons.push(failure.clone());
                    rule.with(Some(&failure))
                }
            }
        },
    });

    let subject = verify::store_oid(commit)?;
    let proofs = read_proofs(
        &*store.host,
        &subject,
        commit,
        &commit.to_string(),
        question,
    )?;
    for failure in &proofs.failures {
        out.reasons.push(failure.clone());
    }
    out.notes.extend(proofs.notes.clone());
    for section in &proofs.sections {
        out.proofs.push(proof_of(section, question.now));
        // A proof's own failures are said about that proof — the same lifting a merge gate
        // does, because two spellings of the same fact is two chances to get one wrong.
        out.reasons.extend(section.lifted_reasons());
    }
    let accepted = proofs
        .sections
        .iter()
        .filter(|section| section.accepted())
        .count();
    out.rules.push(if proofs.advertised == 0 {
        let failure = verify_change::reason(
            "attestations",
            gitiup_attest::ErrorKind::Policy,
            format!(
                "{commit} has no attestation in {}; nothing is proved about it",
                store.what
            ),
            Some(
                "`gitiup attest list --commit … --store …` shows what the store holds, and \
                 `gitiup attest push` files one for a run"
                    .to_string(),
            ),
        );
        out.reasons.push(failure.clone());
        Rule::outcome(
            "attestations",
            CheckOutcome::Failed,
            "at least one proof the store can produce",
            format!("{} advertises nothing about {commit}", store.what),
        )
        .with(Some(&failure))
    } else {
        Rule::outcome(
            "attestations",
            if proofs.failures.is_empty() {
                CheckOutcome::Passed
            } else {
                CheckOutcome::Failed
            },
            "a proof the store can produce, whose bytes are the ones its name promises",
            format!(
                "{} advertised, {} accepted by the revision in force for its own run",
                proofs.advertised, accepted
            ),
        )
    });

    // And do they add up? `min_signatures` counts distinct trusted signers certifying one
    // result, which is a question about the *set* and is answered by the merge gate's own
    // `combine` so that the same two attestations cannot be enough here and not enough
    // there.
    let combination = verify_change::combine(&proofs.sections, policy.min_signatures);
    out.notes.extend(combination.notes.clone());
    for failure in &combination.reasons {
        out.reasons.push(failure.clone());
    }
    out.accepted = combination.accepted.clone();
    out.rules
        .push(match (&out.accepted, combination.reasons.first()) {
            (Some(accepted), _) => Rule::pass(
                "min_signatures",
                format!("{} distinct trusted signature(s)", accepted.required),
                format!(
                    "{} on {}",
                    accepted.signers.len(),
                    accepted.result_digest.clone().unwrap_or_default()
                ),
            ),
            (None, Some(failure)) => Rule::outcome(
                "min_signatures",
                CheckOutcome::Failed,
                format!("{} distinct trusted signature(s)", policy.min_signatures),
                "nothing added up",
            )
            .with(Some(failure)),
            (None, None) => Rule::outcome(
                "min_signatures",
                CheckOutcome::NotRun,
                format!("{} distinct trusted signature(s)", policy.min_signatures),
                "nothing was accepted, so nothing was counted",
            ),
        });
    Ok(())
}

// ---------------------------------------------------------------------------
// `gitiup policy explain`
// ---------------------------------------------------------------------------

/// `gitiup policy explain <attestation|change>`: every rule, its outcome, and the
/// evidence, in the order that makes the first failure the reason.
pub(crate) fn explain(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, EXPLAIN_VALUED, EXPLAIN_SWITCHES)?;
    if args.help(crate::policy::POLICY_HELP).is_some() {
        return Ok(());
    }
    let now = clock(&args)?;
    let at = walked(&args)?;
    let store = crate::participant::store_from(&args)?;
    // Which subject was named. The explicit words always win; a bare `chg-…` cannot be a
    // file, and a path that exists cannot be a change, so the two guesses below are not
    // guesses about ambiguous input — they only make `gitiup policy explain proof.json`
    // and `gitiup policy explain chg-9f2c…` work without a subcommand.
    let (kind, skip) = match args.positional.first().map(String::as_str) {
        Some("attestation") | Some("attest") | Some("proof") | Some("doc") => ("attestation", 1),
        Some("change") => ("change", 1),
        Some(handle) if handle.starts_with("chg-") => ("change", 0),
        Some(handle) if handle != "-" => {
            if std::path::Path::new(handle).exists() || store.is_none() {
                ("attestation", 0)
            } else {
                ("change", 0)
            }
        }
        Some(_) => ("attestation", 0),
        None => {
            return Err(CliError::usage(
                "say what to explain: `gitiup policy explain attestation <DOC|->`, or \
                 `gitiup policy explain change <ID> --store <dir>`",
            ));
        }
    };
    if kind == "change" {
        let opened = store.ok_or_else(|| {
            CliError::refused(
                "no store was named, and a change lives in one",
                "--store <dir> or --remote <name> (see `gitiup doctor --remotes`)",
            )
        })?;
        let handle = args
            .get("--change")
            .map(str::to_string)
            .or_else(|| args.positional.get(skip).cloned())
            .ok_or_else(|| {
                CliError::usage("say which change: `gitiup policy explain change <ID>`")
            })?;
        let attempt = match args.get("--attempt") {
            Some(text) => Some(text.parse::<u32>().map_err(|_| {
                CliError::usage(format!("--attempt '{text}' is not an attempt number"))
            })?),
            None => None,
        };
        let expect = match args.get("--expect-result") {
            Some(text) => Some(
                text.parse::<gitiup_attest::Digest>()
                    .map_err(|e| CliError::usage(format!("--expect-result '{text}': {e}")))?,
            ),
            None => None,
        };
        // The merge gate's own assessment, rendered rule by rule. Not a second gate:
        // `gitiup verify change` and this command cannot disagree, because this one *is*
        // that assessment with more of it printed.
        let report =
            verify_change::assess(&opened, &handle, &args, attempt, expect.as_ref(), now, at)?
                .finish();
        let out = Explanation::from_change(&report, now);
        return print(out, &args, true);
    }

    // `verify attestation` reads a named store *instead of* a file, because for it a
    // store means "the attestation lives in there". Here the two are different questions:
    // the path is the subject and the store is where the policy comes from — so the store
    // flag is taken out of the read and kept for the walk. Without that, `policy explain
    // attestation ./proof.json --store ./s` would be a usage error for naming both things
    // a reader has to name.
    let named = args.positional.get(skip).map(String::as_str).unwrap_or("-");
    let subject_args = if skip == 1 || named == "-" || std::path::Path::new(named).exists() {
        without_store(&below(&args, skip))
    } else {
        below(&args, skip)
    };
    let out = explain_attestation(&subject_args, store.as_ref(), now, at, purpose(&args))?;
    print(out, &args, true)
}

/// The same flags with the store no longer named, for a subject that came from a file.
fn without_store(args: &Args) -> Args {
    let mut copy = Args {
        positional: args.positional.clone(),
        values: Default::default(),
        repeats: Vec::new(),
        annotations: args.annotations.clone(),
        switches: args.switches.clone(),
    };
    for (name, value) in &args.values {
        if name != "--store" && name != "--remote" {
            copy.values.insert(name.clone(), value.clone());
        }
    }
    for (name, value) in &args.repeats {
        if name != "--store" && name != "--remote" {
            copy.repeats.push((name.clone(), value.clone()));
        }
    }
    copy
}

/// The same flags, with the subject word no longer a positional.
fn below(args: &Args, skip: usize) -> Args {
    Args {
        positional: args.positional.iter().skip(skip).cloned().collect(),
        values: args.values.clone(),
        repeats: args.repeats.clone(),
        annotations: args.annotations.clone(),
        switches: args.switches.clone(),
    }
}

/// Explain one attestation: the policy that applies to *it* (which is the revision in
/// force when that run happened, D6), then every rule of it.
fn explain_attestation(
    args: &Args,
    store: Option<&Opened>,
    now: TimeUs,
    at: Option<TimeUs>,
    why: Purpose,
) -> Result<Explanation, CliError> {
    let input = verify::read(args)?;
    let claimed = input
        .doc
        .as_ref()
        .map(|doc| TimeUs(doc.manifest.claims.claimed_at_us));
    let moment = at.or(claimed).unwrap_or(now);
    let mut question = Question::new(
        store,
        args,
        now,
        at,
        match args.get("--expect-result") {
            Some(text) => Some(
                text.parse::<gitiup_attest::Digest>()
                    .map_err(|e| CliError::usage(format!("--expect-result '{text}': {e}")))?,
            ),
            None => None,
        },
    )?;
    if why == Purpose::Advisory {
        question.ask_advisory();
    }

    let mut out = Explanation::new(
        "policy-explanation",
        "attestation",
        input.source.clone(),
        now,
    );
    if let Some(doc) = &input.doc {
        let manifest = &doc.manifest;
        out.subject.push((
            "run".to_string(),
            doc.run_digest()
                .map(|digest| digest.to_string())
                .unwrap_or_else(|_| "?".to_string()),
        ));
        out.subject.push((
            "claim".to_string(),
            format!(
                "tier {} · runner {} · sandbox {} · normalisation v{}",
                manifest.result.provenance.tier.as_str(),
                manifest.result.provenance.runner,
                manifest
                    .result
                    .provenance
                    .sandbox
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                manifest.result.provenance.normalisation_version
            ),
        ));
        out.subject.push((
            "commit".to_string(),
            manifest.result.source.commit.to_string(),
        ));
        out.subject.push((
            "signed".to_string(),
            if doc.signatures.is_empty() {
                "nobody: the document carries no signature".to_string()
            } else {
                doc.signatures
                    .iter()
                    .map(|entry| crate::participant::short(&entry.key_id))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ));
        out.subject.push((
            "claimed".to_string(),
            format!(
                "{} ({} old)",
                TimeUs(manifest.claims.claimed_at_us).to_rfc3339(),
                human_age((now.0 - manifest.claims.claimed_at_us).max(0))
            ),
        ));
    }

    let from = if at.is_some() || claimed.is_some() {
        "run-claim"
    } else {
        "now"
    };
    let resolved = match question.resolve(moment, from) {
        Ok(resolved) => {
            out.notes.extend(notes_of(&resolved));
            out.policy = Some(resolved.clone());
            Some(resolved)
        }
        Err(error) => {
            let reason = verify_change::policy_reason(&error);
            out.rules.push(
                Rule::outcome(
                    "policy",
                    CheckOutcome::Failed,
                    POLICY_DEMAND,
                    "nothing was resolved",
                )
                .with(Some(&reason)),
            );
            out.reasons.push(reason);
            None
        }
    };
    if let Some(resolved) = &resolved {
        out.rules.push(policy_rule(resolved));
    }

    match (&input.doc, &input.failure) {
        (Some(doc), None) => match &resolved {
            Some(resolved) => {
                let mut judged = resolved.policy.clone();
                // Two clocks, said apart: the walk used the run's claim, and freshness is
                // measured against the reader — a proof may be dated when it was made but
                // it has to still be fresh *now* to carry anything.
                judged.now = Some(now);
                if let Some(text) = args.get("--commit") {
                    judged.expected_commit = Some(verify::commit_id(text)?);
                }
                let report = doc.verify_report(&judged);
                out.rules.extend(ladder(
                    Some(&judged),
                    Some(doc),
                    &report,
                    &input.source,
                    now,
                ));
                out.reasons.extend(report.reasons.iter().cloned());
                Ok(out.finish(report.accepted()))
            }
            // The policy refusal *is* the verdict; running the ladder with no rules would
            // be inventing some.
            None => Ok(out.finish(false)),
        },
        // The bytes were never a document this build speaks. The ladder still runs: every
        // rung after the one that stopped is `not_run`, which is how a reader learns *how
        // far* it got rather than only that it did not.
        (_, Some((code, error))) => {
            let report = VerdictReport::refusing(code, error.clone());
            out.rules.extend(ladder(
                resolved.as_ref().map(|resolved| &resolved.policy),
                None,
                &report,
                &input.source,
                now,
            ));
            out.reasons.extend(report.reasons.iter().cloned());
            Ok(out.finish(false))
        }
        // Nothing was read and nothing failed: `verify::read` cannot return that pair, but
        // an empty explanation beats a panic if it ever did.
        (None, None) => Ok(out.finish(false)),
    }
}

// ---------------------------------------------------------------------------
// shared pieces
// ---------------------------------------------------------------------------

/// Print the answer, in whichever shape was asked for, and exit with the verdict.
fn print(out: Explanation, args: &Args, full: bool) -> Result<(), CliError> {
    if args.on("--quiet") || args.on("-q") {
        println!("{}", out.quiet());
        return out.exit();
    }
    if args.json() {
        println!(
            "{}",
            serde_json::to_string(&out.json()).unwrap_or_else(|_| "{}".to_string())
        );
        return out.exit();
    }
    print!("{}", out.text(full));
    out.exit()
}

/// The provenance notes and warnings, in the one list the report prints.
fn notes_of(resolved: &ResolvedPolicy) -> Vec<String> {
    let mut notes: Vec<String> = resolved.provenance.notes.clone();
    notes.extend(
        resolved
            .provenance
            .warnings
            .iter()
            .map(|warning| format!("warning: {warning}")),
    );
    notes
}

/// The rule above all the others: was there a policy at all, and may a merge rest on it.
fn policy_rule(resolved: &ResolvedPolicy) -> Rule {
    let provenance = &resolved.provenance;
    let source = provenance
        .source
        .map(Source::as_str)
        .unwrap_or("nothing")
        .to_string();
    Rule::outcome(
        "policy",
        if provenance.gate_eligible {
            CheckOutcome::Passed
        } else {
            CheckOutcome::Failed
        },
        "a policy a merge may rest on: published, signed by a key you trust, and in force",
        format!(
            "{}{}{}{}",
            source,
            provenance
                .revision
                .map(|revision| format!(" revision {revision}"))
                .unwrap_or_default(),
            provenance
                .body_digest
                .as_ref()
                .map(|digest| format!(" · cited {digest}"))
                .unwrap_or_default(),
            if provenance.gate_eligible {
                String::new()
            } else {
                " · NOT gate-eligible: a draft, and a merge may not rest on one".to_string()
            }
        ),
    )
}

/// One section of the gate's assessment, rendered as rules.
fn proof_of(section: &Section, now: TimeUs) -> Proof {
    let digest = format!("sha256:{}", section.digest.hex());
    let source = format!("kv/attestation/{}", section.digest.hex());
    let rules = match (&section.doc, &section.policy, &section.policy_error) {
        (Some(doc), Some(resolved), _) => ladder(
            Some(&resolved.policy),
            Some(doc),
            &section.report,
            &source,
            now,
        ),
        (_, _, Some(error)) => vec![
            Rule::outcome(
                "policy",
                CheckOutcome::Failed,
                "the policy that was in force when this run happened",
                "none could be resolved for its timestamp",
            )
            .with(Some(&verify_change::policy_reason(error))),
        ],
        _ => {
            let primary = section.report.primary();
            vec![
                Rule::outcome(
                    "structure",
                    CheckOutcome::Failed,
                    "a canonical attestation this build speaks",
                    "nothing was read",
                )
                .with(primary),
            ]
        }
    };
    Proof {
        digest,
        reference: section.reference.clone(),
        source,
        verdict: section.report.verdict(),
        exit: section.report.exit_code(),
        accepted: section.report.accepted(),
        policy: section.policy.clone(),
        rules,
        notes: Vec::new(),
    }
}

/// A copy of the accepted combination: the report owns it, the explanation prints it.
fn clone_accepted(accepted: &Accepted) -> Accepted {
    accepted.clone()
}

impl Explanation {
    /// The merge gate's assessment of a change, seen rule by rule.
    fn from_change(report: &verify_change::Report, now: TimeUs) -> Explanation {
        let mut out = Explanation::new("policy-explanation", "change", report.store.clone(), now);
        for (label, value) in [
            ("change", report.change.clone().unwrap_or_default()),
            ("state", report.state.clone().unwrap_or_default()),
            (
                "head",
                format!(
                    "{}{}",
                    report.head.clone().unwrap_or_default(),
                    report
                        .target
                        .as_ref()
                        .map(|target| format!("  →  {target}"))
                        .unwrap_or_default()
                ),
            ),
            ("title", report.title.clone().unwrap_or_default()),
        ] {
            if !value.is_empty() {
                out.subject.push((label.to_string(), value));
            }
        }
        out.policy = report.policy.clone();
        out.notes.clone_from(&report.notes);
        for code in verify_change::CHANGE_CHECKS.iter().copied() {
            let outcome = report.outcome_of(code);
            let (demands, claims) = change_evidence(code, report);
            let rule = Rule::outcome(code, outcome, demands, claims);
            let failure = outcome
                .is_failure()
                .then(|| report.reasons.iter().find(|reason| reason.code == code))
                .flatten();
            out.rules.push(rule.with(failure));
        }
        for section in &report.sections {
            out.proofs.push(proof_of(section, now));
        }
        out.accepted = report.accepted.as_ref().map(clone_accepted);
        out.reasons.clone_from(&report.reasons);
        out.finish(report.accepted_now())
    }
}

/// The two sides of each change-level rule: what the merge must show, and what this one
/// shows. Same discipline as the ladder's evidence — the values are the gate's own.
fn change_evidence(code: &str, report: &verify_change::Report) -> (String, String) {
    let required = report
        .policy
        .as_ref()
        .map(|resolved| resolved.policy.min_signatures)
        .unwrap_or(1);
    let accepted = report
        .sections
        .iter()
        .filter(|section| section.accepted())
        .count();
    match code {
        "change" => (
            "a change that resolves, whose head record reads, and that is not abandoned"
                .to_string(),
            format!(
                "{}{}",
                report.change.clone().unwrap_or_default(),
                report
                    .state
                    .as_ref()
                    .map(|state| format!(" · {state}"))
                    .unwrap_or_default()
            ),
        ),
        "policy" => (
            "a policy a merge may rest on, signed by a key you trust".to_string(),
            report.policy.as_ref().map_or_else(
                || "none could be resolved".to_string(),
                |resolved| {
                    resolved
                        .provenance
                        .source
                        .map(Source::as_str)
                        .unwrap_or("nothing")
                        .to_string()
                },
            ),
        ),
        "protects" => (
            report
                .policy
                .as_ref()
                .and_then(|resolved| resolved.document.as_ref())
                .map(|doc| format!("one of: {}", doc.protects().join(", ")))
                .unwrap_or_else(|| "a published policy's `protects` globs".to_string()),
            report
                .target
                .clone()
                .unwrap_or_else(|| "no target ref".to_string()),
        ),
        "attestations" => (
            "at least one proof the store can produce, whose bytes are the ones it names"
                .to_string(),
            format!(
                "{} advertised for {}, {} accepted",
                report.sections.len(),
                report.head.clone().unwrap_or_default(),
                accepted
            ),
        ),
        "quorum" => (
            "no verdict the store advertises disagrees about this head".to_string(),
            match report.verdicts.len() {
                0 => "none advertised".to_string(),
                one => format!("{one} verdict(s) advertised"),
            },
        ),
        "min_signatures" => (
            format!("{required} distinct trusted signature(s) on one result"),
            report.accepted.as_ref().map_or_else(
                || "nothing added up".to_string(),
                |accepted| {
                    format!(
                        "{} on {}",
                        accepted.signers.len(),
                        accepted.result_digest.clone().unwrap_or_default()
                    )
                },
            ),
        ),
        other => (other.to_string(), String::new()),
    }
}

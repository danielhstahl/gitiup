//! The verification report: every check a document is put through, and every reason
//! it was refused
//! ([ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//!
//! [`AttestationDoc::verify`](crate::AttestationDoc::verify) answers one question
//! with one error, which is what a caller who only wants to know "may I merge?"
//! needs. A caller *printing* a verdict needs more than that: a CI log that says
//! "refused" and nothing else is a log nobody can act on, and a script that
//! re-derives the reason by string-matching the message is a script that breaks
//! when the message is reworded. So the same verification run, in the same order,
//! also produces:
//!
//! * one [`Check`] per check, with its outcome — including the checks that were
//!   not asked for (`--commit` was not given) and the ones that never ran
//!   because something earlier made them meaningless; and
//! * one [`Reason`] per problem found, each carrying the library's own
//!   [`Error`] — so its class, its exit code, its detail and its hint — under a
//!   stable machine-readable `code`.
//!
//! # The order is the contract
//!
//! [`CHECK_ORDER`] is the sequence ADR-0001 D7 fixes: structure → digest →
//! bindings → environment → signatures → trust → count → tier → sandbox →
//! freshness → the document's own window. The **first** reason is what decides the
//! exit code, and `verify` (which stops at the first error) and
//! [`AttestationDoc::verify_report`](crate::AttestationDoc::verify_report) (which
//! keeps going to collect the rest) agree on it by construction, because they are
//! the same code: `verify` is `verify_report` with the tail dropped.
//!
//! That is the whole reason this module exists. A verdict printed by the CLI and a
//! verdict computed by a `pre-receive` hook calling `verify` cannot disagree, and
//! the codes a script branches on are written down once.

use crate::envelope::Verdict;
use crate::error::{Error, ErrorKind};

/// The checks a report can contain, in the order verification performs them.
///
/// Names are stable: they appear in `gitiup verify attestation --json` and a
/// `pre-receive` hook. Adding a check means appending here and to the verification
/// sequence, never renaming one.
pub const CHECK_ORDER: &[&str] = &[
    "structure",
    "digest",
    "commit",
    "result",
    "challenge",
    "normalisation",
    "environment",
    "signature",
    "trust",
    "min_signatures",
    "tier",
    "sandbox",
    "freshness",
    "expiry",
];

/// How one check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The check ran and had nothing to complain about.
    Passed,
    /// The check ran and produced at least one [`Reason`].
    Failed,
    /// Nothing was asked of this check: no expected commit was given, no
    /// environment requirement is published. Not a pass — nothing was compared.
    NotAsked,
    /// Verification stopped before this check, because something it depends on
    /// already failed. `NotRun` is honest in a way that quietly omitting the line
    /// is not: a reader can see what was *not* established.
    NotRun,
}

impl CheckOutcome {
    /// Stable name for `--json`.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckOutcome::Passed => "passed",
            CheckOutcome::Failed => "failed",
            CheckOutcome::NotAsked => "not_asked",
            CheckOutcome::NotRun => "not_run",
        }
    }

    /// Did this check go wrong?
    pub fn is_failure(self) -> bool {
        matches!(self, CheckOutcome::Failed)
    }
}

/// One check and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// One of [`CHECK_ORDER`], or a code the caller added itself.
    pub code: &'static str,
    /// How it went.
    pub outcome: CheckOutcome,
}

/// One reason a document was refused, under a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Which check said it — the code a script branches on.
    pub code: &'static str,
    /// The library's own error: class, detail, hint, and therefore exit code.
    ///
    /// Kept as an [`Error`] rather than flattened into strings so that a caller
    /// which already handles `verify`'s errors handles a report's too, and so the
    /// taxonomy in [`crate::error`] stays the only place an exit code is decided.
    pub error: Error,
}

impl Reason {
    /// The failure class (policy, signature, digest mismatch, …).
    pub fn class(&self) -> ErrorKind {
        self.error.kind()
    }

    /// The exit code this reason alone would produce.
    pub fn exit_code(&self) -> u8 {
        self.error.exit_code()
    }

    /// The specifics, in a sentence.
    pub fn detail(&self) -> &str {
        self.error.detail()
    }

    /// What to do about it, if the library has a suggestion.
    pub fn hint(&self) -> Option<&str> {
        self.error.hint()
    }

    /// The reason back as an [`Error`] — what `verify` returns for the first one.
    pub fn into_error(self) -> Error {
        self.error
    }
}

/// Everything one verification run established: which checks ran, how each went,
/// and the [`Verdict`] if there was one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictReport {
    /// The checks, in [`CHECK_ORDER`] order (with any caller-added code after them).
    pub checks: Vec<Check>,
    /// Every reason found, most important first: `reasons[0]` is what `verify`
    /// returns and what [`Self::exit_code`] describes.
    pub reasons: Vec<Reason>,
    /// Present exactly when the document was accepted *and* is a run manifest.
    pub verdict: Option<Verdict>,
    /// Set when the document was accepted but has no run-manifest facts to hand back —
    /// a `tier: quorum` attestation, whose facts are a round's and a tally's, not a
    /// run's. Kept separate from [`Self::verdict`] so that field keeps meaning exactly
    /// what [ADR-0001 D4](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
    /// says it means.
    accepted_document: bool,
}

impl VerdictReport {
    /// An empty ladder: every check [`CHECK_ORDER`] lists, none of it run yet.
    pub(crate) fn new() -> VerdictReport {
        VerdictReport {
            checks: CHECK_ORDER
                .iter()
                .map(|code| Check {
                    code,
                    outcome: CheckOutcome::NotRun,
                })
                .collect(),
            reasons: Vec::new(),
            verdict: None,
            accepted_document: false,
        }
    }

    /// Record the outcome of a check that a caller *outside this crate* performed.
    ///
    /// A `tier: quorum` attestation is checked by `gitiup-quorum` — the round, the
    /// roster, the tally — and its verdict is printed with the same ladder, the same
    /// codes and the same exit taxonomy as a run manifest's. This is the seam that lets
    /// one report type carry both without either crate pretending to know the other's
    /// checks.
    pub fn record(&mut self, code: &'static str, outcome: CheckOutcome) {
        self.set(code, outcome);
    }

    /// Accept a document whose facts are not a run manifest's.
    ///
    /// The exit code stays `0` and [`Self::verdict`] stays `None` — nothing here pretends
    /// a quorum attestation has a `RunDigest` — while [`Self::accepted`] answers the only
    /// question a gate asks.
    pub fn accept_document(&mut self) {
        self.accepted_document = true;
    }

    /// A report that refuses before the document could be put through the checks at
    /// all — the bytes were not a document, or not the bytes their name says.
    ///
    /// Public because the *transport* can be the thing that failed: a store that
    /// returns bytes which do not re-hash to the key they are filed under has
    /// produced a reason (exit 8) and not a stack panic, and the caller that found
    /// it is often not in this crate.
    pub fn refusing(code: &'static str, error: Error) -> VerdictReport {
        let mut report = VerdictReport::new();
        report.fail(code, error);
        report
    }

    /// A caller's own reason, added to a report it was given — the way a merge gate
    /// records "the signature is fine and the policy is fine, and *I* still refuse
    /// it because this commit is not the one I was asked about".
    pub fn add_reason(&mut self, code: &'static str, error: Error) {
        self.fail(code, error);
    }

    /// Record a check that ran clean.
    pub(crate) fn pass(&mut self, code: &'static str) {
        self.set(code, CheckOutcome::Passed);
    }

    /// Record a check that had nothing to compare against.
    pub(crate) fn not_asked(&mut self, code: &'static str) {
        self.set(code, CheckOutcome::NotAsked);
    }

    /// Record that a check was deliberately skipped because an earlier one decided
    /// the question — `sandbox` is not asked when the tier already failed.
    pub(crate) fn not_run(&mut self, code: &'static str) {
        self.set(code, CheckOutcome::NotRun);
    }

    /// Record a failure and return: everything this check guarded is still
    /// [`CheckOutcome::NotRun`], which is what makes "we did not get that far"
    /// visible instead of looking like a pass.
    pub(crate) fn stop(&mut self, code: &'static str, error: Error) {
        self.fail(code, error);
    }

    /// Record a failure, and keep going: the remaining checks may each have their
    /// own complaint, and a reader wants to hear all of them at once.
    pub(crate) fn fail(&mut self, code: &'static str, error: Error) {
        self.reasons.push(Reason { code, error });
        self.set(code, CheckOutcome::Failed);
    }

    /// Set one check's outcome, without ever overwriting a decision that has been
    /// made: a failure is not downgraded by a later "nothing was asked here".
    fn set(&mut self, code: &'static str, outcome: CheckOutcome) {
        match self.checks.iter_mut().find(|check| check.code == code) {
            Some(check) => {
                if check.outcome == CheckOutcome::NotRun || outcome == CheckOutcome::Failed {
                    check.outcome = outcome;
                }
            }
            None => self.checks.push(Check { code, outcome }),
        }
    }

    /// Accept, and hand back what was established.
    pub(crate) fn accept(&mut self, verdict: Verdict) {
        self.verdict = Some(verdict);
    }

    /// Was the document accepted?
    ///
    /// A report carrying a reason is not accepted, even when the ladder reached a verdict.
    /// The exit code has always been "the first reason's", so a report that said
    /// `accepted: true` while holding a reason was answering its own question wrongly —
    /// and a caller that branched on `accepted()` instead of `exit_code()` would have
    /// merged what it had just refused. This matters as soon as a *caller* adds a reason
    /// of its own ([`Self::add_reason`], and ADR-0005 D5: "I will not gate a merge on a
    /// copy" is exactly such a reason).
    pub fn accepted(&self) -> bool {
        (self.verdict.is_some() || self.accepted_document) && self.reasons.is_empty()
    }

    /// The outcome of one check.
    pub fn outcome(&self, code: &str) -> CheckOutcome {
        self.checks
            .iter()
            .find(|check| check.code == code)
            .map_or(CheckOutcome::NotRun, |check| check.outcome)
    }

    /// Did this check fail?
    pub fn failed(&self, code: &str) -> bool {
        self.outcome(code).is_failure()
    }

    /// The reason that decides the verdict.
    pub fn primary(&self) -> Option<&Reason> {
        self.reasons.first()
    }

    /// The exit code: 0 when accepted, otherwise the first reason's
    /// ([`ErrorKind::exit_code`]).
    pub fn exit_code(&self) -> u8 {
        self.primary().map_or(0, |reason| reason.exit_code())
    }

    /// The verdict as one stable word, for `--json` and for logs.
    ///
    /// `pass`, or the class of the deciding failure: `policy`, `invalid`,
    /// `unsupported_schema`, `bad_signature`, `digest_mismatch`. Same vocabulary as
    /// [`ErrorKind::as_str`], so a script can branch on this or on the exit code
    /// and cannot get two different answers.
    pub fn verdict(&self) -> &'static str {
        if self.accepted() {
            "pass"
        } else {
            self.primary()
                .map_or("policy", |reason| reason.class().as_str())
        }
    }

    /// The first reason back as an error — how `verify` keeps its exact taxonomy
    /// while `verify_report` collects the rest.
    pub fn error(&self) -> Option<Error> {
        self.primary().map(|reason| reason.error.clone())
    }

    /// The reasons as `(code, detail)` pairs, in order.
    pub fn reason_codes(&self) -> Vec<&'static str> {
        self.reasons.iter().map(|reason| reason.code).collect()
    }
}

impl Default for VerdictReport {
    fn default() -> Self {
        VerdictReport::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationDoc, Policy, TimeUs, sample};

    #[test]
    fn the_ladder_is_listed_before_anything_runs() {
        // A report that stopped at the first check still shows the rest as
        // "not run", so a reader sees what was never established.
        let report =
            VerdictReport::refusing("structure", Error::invalid("attestation", "not a document"));
        assert_eq!(report.outcome("digest"), CheckOutcome::NotRun);
        assert_eq!(report.outcome("freshness"), CheckOutcome::NotRun);
        assert_eq!(report.outcome("structure"), CheckOutcome::Failed);
        assert!(!report.accepted());
        assert_eq!(report.exit_code(), 6);
        assert_eq!(report.verdict(), "invalid");
    }

    #[test]
    fn a_second_failure_on_the_same_code_does_not_duplicate_the_check() {
        let mut report = VerdictReport::new();
        report.fail("signature", Error::invalid("a", "one"));
        report.fail("signature", Error::invalid("a", "two"));
        assert_eq!(report.reasons.len(), 2);
        assert_eq!(
            report
                .checks
                .iter()
                .filter(|check| check.code == "signature")
                .count(),
            1
        );
        assert_eq!(report.outcome("signature"), CheckOutcome::Failed);
    }

    #[test]
    fn a_clean_document_reports_no_reasons_and_no_failure() {
        // The clock is pinned, as it is everywhere else that judges freshness: the fixture
        // is a fixed moment, so an unpinned `now` would turn this test into a calendar and
        // it would start failing one day after it was written.
        let policy = Policy {
            now: Some(TimeUs::from_secs(1_793_092_600)),
            ..Default::default()
        };
        let report = AttestationDoc::new(sample::local()).verify_report(&policy);
        // No signatures at all: refused, and the reason is a policy one (exit 6),
        // not a signature one — nothing forged anything, nobody signed anything.
        assert_eq!(report.exit_code(), 6);
        assert_eq!(report.reason_codes(), vec!["min_signatures"]);
        assert_eq!(report.verdict(), "policy");
        assert!(report.verdict.is_none());
    }

    #[test]
    fn codes_come_from_the_list_or_from_the_caller() {
        let mut report = VerdictReport::new();
        report.add_reason("merge_window", Error::invalid("gate", "outside the window"));
        assert_eq!(report.outcome("merge_window"), CheckOutcome::Failed);
        assert_eq!(report.exit_code(), 6);
    }

    #[test]
    fn every_listed_check_has_an_outcome() {
        let report = AttestationDoc::new(sample::local()).verify_report(&Policy::for_tests());
        for code in CHECK_ORDER {
            assert_ne!(
                report.outcome(code),
                CheckOutcome::NotRun,
                "{code} was never even placed in the ladder"
            );
        }
    }
}

//! Bounded escalation: the second chance that has a last one (giti-zp1.7).
//!
//! A disagreement is not an instruction to re-run forever. The two failure modes either
//! way are worth naming, because the code is written against both:
//!
//! * **no bound**, and a flaky test becomes an infinite loop — every retry costs five
//!   volunteers their afternoon, and the change never merges and never fails, it just
//!   keeps asking. A quorum that cannot decide is a decision;
//! * **a bound nobody can see**, and the operator cannot tell "one try left" from
//!   "out of retries", which is the difference between waiting and escalating to a human.
//!
//! So the bound is a number, it is the owner's to set, and exhausting it is a state with
//! its own name and its own exit code:
//!
//! | | |
//!|---|---|
//!| the knob | `quorum.max_attempts` in the published policy ([`crate::policy::QuorumBlock`]) |
//!| the default | [`DEFAULT_MAX_ATTEMPTS`] = 3, i.e. attempt 0 plus two retries |
//!| the count | per `(change, job)`, because attempt numbers are per job |
//!| the terminal state | [`Exhausted`] — token `attempt_cap_exhausted`, exit [`EXIT_ATTEMPTS_EXHAUSTED`] |
//!
//! # Why the cap belongs to the policy and not to a flag
//!
//! The same reason `n` and `required_agree` do ([ADR-0004 D5](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)):
//! how much patience a repository has is the owner's signed statement, and whoever is
//! standing in front of a terminal at 2am is exactly the person least able to tell whether
//! the fifth attempt is worth five volunteers' afternoon. A flag that could raise the cap
//! is a fork's way to weaken it, and a retry loop's way to never stop.
//!
//! [`AttemptCap::from_block`] is therefore the only path a store's cap takes, and
//! [`AttemptCap::explicit`] exists for the case the policy genuinely cannot speak about —
//! a round opened by hand with no published policy in force — and refuses to *raise* what a
//! policy does say.
//!
//! # Escalation is `attempt + 1`, and nothing else
//!
//! A new attempt is a new round: a new round id, a new seed (the attempt number is a seed
//! input, [ADR-0002 D2](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)),
//! and therefore a fresh selection over the roster as it is now. Nothing is edited and
//! nothing is deleted — the superseded round, its reveals, its commitments and its verdict
//! all stay in the store, and the new round *names* the one it replaces
//! ([`crate::round::Escalation`]) so the chain is readable from the records rather than
//! from somebody's shell history.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::policy::QuorumBlock;
use crate::round::Round;

/// How many attempts a job gets when no policy says: the first round and two retries.
///
/// Three because it is enough to outlast an ordinary flake and small enough that a
/// genuinely broken test stops costing volunteers in an afternoon. It is a default and not
/// an opinion about anybody's repository: `quorum.max_attempts` says otherwise.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// The largest cap a policy may name.
///
/// A bound on the bound, because `max_attempts: 4000000000` is a way of saying "never
/// stop" in a field that exists to say "stop", and every attempt costs a roster of
/// volunteers a build.
pub const MAX_MAX_ATTEMPTS: u32 = 32;

/// The exit code of a change that has run out of attempts.
///
/// A new number, deliberately: 6 is "refused, and something about the request is wrong",
/// and an exhausted cap is neither — the requests were all fine, the evidence disagrees,
/// and the loop is over. A wrapper that wants to stop retrying branches on this one number
/// rather than grepping for a sentence.
pub const EXIT_ATTEMPTS_EXHAUSTED: u8 = 9;

/// The stable token for `--json` and for a wrapper that branches on text.
pub const TOKEN_EXHAUSTED: &str = "attempt_cap_exhausted";

/// Check a cap value. Refused rather than clamped: a policy that says `0` means something
/// confused, and quietly reading it as `1` would publish a policy that does not mean what
/// its owner typed.
pub fn validate_max_attempts(value: u32) -> Result<()> {
    if value == 0 {
        return Err(Error::policy(
            "policy",
            "`quorum.max_attempts` of 0 would allow no attempt at all, including the first",
        )
        .with_hint(
            "1 means \"one shot, no retry\"; the default is \
             {DEFAULT_MAX_ATTEMPTS}, which is the first round plus two retries",
        ));
    }
    if value > MAX_MAX_ATTEMPTS {
        return Err(Error::policy(
            "policy",
            format!(
                "`quorum.max_attempts` of {value} is above the {MAX_MAX_ATTEMPTS} this build \
                 allows"
            ),
        )
        .with_hint(
            "every attempt costs a roster a build; if a job really needs more retries than \
             this, the flake is the bug and not the cap",
        ));
    }
    Ok(())
}

/// The cap in force, and where it came from.
///
/// The source is part of the struct because "3" without provenance is the question a
/// reviewer asks next, and because a report that says *which* 3 it is cannot be confused
/// with a default nobody noticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCap {
    /// How many attempts the job may have in total: `n` means attempts `0 ..= n-1`.
    pub max_attempts: u32,
    /// Where the number came from, in the words the operator can act on.
    pub source: String,
}

impl AttemptCap {
    /// The built-in default, for a store with no policy that says.
    pub fn default_cap() -> AttemptCap {
        AttemptCap {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            source: format!(
                "the built-in default ({DEFAULT_MAX_ATTEMPTS}); no published policy names \
                 `quorum.max_attempts`"
            ),
        }
    }

    /// The cap a published policy sets, or the default when it says nothing.
    pub fn from_block(block: &QuorumBlock) -> AttemptCap {
        match block.max_attempts {
            Some(max_attempts) => AttemptCap {
                max_attempts,
                source: format!("the published policy's `quorum.max_attempts` = {max_attempts}"),
            },
            None => AttemptCap {
                max_attempts: block.effective_max_attempts(),
                source: format!(
                    "the built-in default ({DEFAULT_MAX_ATTEMPTS}); the published policy's \
                     `quorum` block does not name `max_attempts`"
                ),
            },
        }
    }

    /// A cap named on the command line, for a store whose policy does not name one.
    ///
    /// `policy` is the cap that *is* in force when the policy speaks, and a flag may never
    /// raise it — the parameter is there so the refusal can name the number that outranks
    /// the flag, not as an invitation to argue with it.
    pub fn explicit(max_attempts: u32, policy: Option<&AttemptCap>) -> Result<AttemptCap> {
        validate_max_attempts(max_attempts)?;
        if let Some(policy) = policy {
            if max_attempts > policy.max_attempts {
                return Err(Error::policy(
                    "policy",
                    format!(
                        "--max-attempts {max_attempts} would raise the cap the policy sets \
                         ({} from {})",
                        policy.max_attempts, policy.source
                    ),
                )
                .with_hint(
                    "the cap is the owner's signed rule, so a flag may tighten it and not \
                     loosen it; publish a policy revision to change it",
                ));
            }
            return Ok(AttemptCap {
                max_attempts,
                source: format!(
                    "--max-attempts {max_attempts}, below the policy's {} ({})",
                    policy.max_attempts, policy.source
                ),
            });
        }
        Ok(AttemptCap {
            max_attempts,
            source: format!("--max-attempts {max_attempts}; no published policy names a cap"),
        })
    }

    /// May attempt `attempt` exist?
    pub fn allows(&self, attempt: u64) -> bool {
        attempt < self.max_attempts as u64
    }

    /// The highest attempt number that may exist.
    pub fn last_attempt(&self) -> u64 {
        self.max_attempts.saturating_sub(1) as u64
    }

    /// The next attempt after `latest`, or the fact that there isn't one.
    ///
    /// `latest` is the highest attempt the store holds for this job; a job that has never
    /// been attempted has no `latest` and starts at 0, which is not an escalation and is
    /// never refused for the cap.
    pub fn next(
        &self,
        change: &str,
        job: &str,
        latest: Option<u64>,
    ) -> std::result::Result<u64, Exhausted> {
        let Some(latest) = latest else {
            return Ok(0);
        };
        let next = latest.saturating_add(1);
        if self.allows(next) {
            return Ok(next);
        }
        Err(Exhausted {
            change_id: change.to_string(),
            job_id: job.to_string(),
            attempts_run: latest.saturating_add(1),
            cap: self.clone(),
        })
    }

    /// "3 attempts (0, 1, 2)" — the sentence a report quotes.
    pub fn describe(&self) -> String {
        format!(
            "{} attempt{} (0\u{2026}{})",
            self.max_attempts,
            if self.max_attempts == 1 { "" } else { "s" },
            self.last_attempt()
        )
    }
}

impl Default for AttemptCap {
    fn default() -> Self {
        AttemptCap::default_cap()
    }
}

/// A job that has used every attempt it was given.
///
/// This is a *state*, not a fault: the attempts all happened, each one was checked, and
/// the last of them did not agree either. What it means is that a person has to look, which
/// is the only thing left that can help.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exhausted {
    /// The change whose job ran out.
    pub change_id: String,
    /// The job (a matrix arm is its own job, and its own count).
    pub job_id: String,
    /// How many attempts the store holds, i.e. `1 +` the highest attempt number.
    pub attempts_run: u64,
    /// The cap, with its provenance.
    pub cap: AttemptCap,
}

impl Exhausted {
    /// The stable token.
    pub fn token(&self) -> &'static str {
        TOKEN_EXHAUSTED
    }

    /// The exit code: [`EXIT_ATTEMPTS_EXHAUSTED`].
    pub fn exit_code(&self) -> u8 {
        EXIT_ATTEMPTS_EXHAUSTED
    }

    /// The highest attempt number the store holds.
    pub fn last_attempt(&self) -> u64 {
        self.attempts_run.saturating_sub(1)
    }

    /// The sentence a report prints, including what would have to change.
    pub fn describe(&self) -> String {
        format!(
            "{} job {} has used all {} allowed: attempts 0\u{2026}{} exist and attempt {} \
             would be one too many. This is terminal — the change does not get another round \
             by asking again",
            self.change_id,
            self.job_id,
            self.cap.describe(),
            self.last_attempt(),
            self.attempts_run,
        )
    }

    /// What to do about it, which is never "retry".
    pub fn hint(&self) -> String {
        format!(
            "a flaky test that survives {} attempts is a bug in the test or in the change, \
             not a run to wait out: reproduce it locally, fix it, and submit the fix as a new \
             attempt of the change (`gitiup change submit`), which is a different head and \
             starts its own count. Raising {} means publishing a policy revision",
            self.attempts_run, self.cap.max_attempts
        )
    }
}

/// The highest attempt the store holds for `job` (or for any job of the change when
/// `job` is `None`).
///
/// A ref listing, not a counter: the store is the record, so "how many attempts have there
/// been" is read from the rounds and cannot drift from them.
pub fn latest_attempt<'a>(
    rounds: impl Iterator<Item = &'a Round>,
    job: Option<&str>,
) -> Option<u64> {
    rounds
        .filter(|round| job.is_none_or(|job| round.inputs.job_id == job))
        .map(|round| round.inputs.attempt)
        .max()
}

/// Attempts a job has had: `1 +` its highest attempt number, or 0 for a job the store has
/// never seen.
pub fn attempts_run<'a>(rounds: impl Iterator<Item = &'a Round>, job: Option<&str>) -> u64 {
    latest_attempt(rounds, job)
        .map(|attempt| attempt + 1)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_first_round_plus_two_retries() {
        let cap = AttemptCap::default_cap();
        assert_eq!(cap.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(cap.last_attempt(), 2);
        assert!(cap.allows(0) && cap.allows(1) && cap.allows(2));
        assert!(!cap.allows(3));
    }

    #[test]
    fn the_next_attempt_is_the_one_after_the_latest_the_store_holds() {
        let cap = AttemptCap::default_cap();
        // A job that has never been attempted is not an escalation and cannot be refused.
        assert_eq!(cap.next("chg-1", "build", None).unwrap(), 0);
        assert_eq!(cap.next("chg-1", "build", Some(0)).unwrap(), 1);
        assert_eq!(cap.next("chg-1", "build", Some(1)).unwrap(), 2);
        // Attempt 2 is the last one the cap allows, so the next one is the terminal state.
        let exhausted = cap.next("chg-1", "build", Some(2)).unwrap_err();
        assert_eq!(exhausted.token(), TOKEN_EXHAUSTED);
        assert_eq!(exhausted.exit_code(), EXIT_ATTEMPTS_EXHAUSTED);
        assert_eq!(exhausted.attempts_run, 3);
        assert_eq!(exhausted.last_attempt(), 2);
        assert!(exhausted.describe().contains("terminal"));
    }

    #[test]
    fn a_cap_of_one_means_no_retry_at_all() {
        let cap = AttemptCap::explicit(1, None).unwrap();
        assert_eq!(cap.next("c", "j", Some(0)).unwrap_err().attempts_run, 1);
        // And the sentences agree with the number rather than with the default.
        assert!(cap.describe().starts_with("1 attempt "));
    }

    #[test]
    fn a_flag_may_tighten_the_policy_cap_and_never_raise_it() {
        let policy = AttemptCap {
            max_attempts: 2,
            source: "the published policy's `quorum.max_attempts` = 2".to_string(),
        };
        assert_eq!(
            AttemptCap::explicit(1, Some(&policy)).unwrap().max_attempts,
            1
        );
        assert_eq!(
            AttemptCap::explicit(2, Some(&policy)).unwrap().max_attempts,
            2
        );
        let error = AttemptCap::explicit(5, Some(&policy)).unwrap_err();
        assert_eq!(error.exit_code(), 6);
        assert!(error.message().contains("raise"));
    }

    #[test]
    fn a_cap_of_zero_or_of_a_billion_is_refused_rather_than_clamped() {
        assert_eq!(validate_max_attempts(0).unwrap_err().exit_code(), 6);
        assert_eq!(
            validate_max_attempts(MAX_MAX_ATTEMPTS + 1)
                .unwrap_err()
                .exit_code(),
            6
        );
        assert!(validate_max_attempts(MAX_MAX_ATTEMPTS).is_ok());
        assert_eq!(AttemptCap::explicit(0, None).unwrap_err().exit_code(), 6);
    }

    #[test]
    fn a_policy_block_that_says_nothing_leaves_the_default_alone() {
        let block = QuorumBlock::default();
        assert_eq!(
            AttemptCap::from_block(&block).max_attempts,
            DEFAULT_MAX_ATTEMPTS
        );
        let block = QuorumBlock {
            max_attempts: Some(5),
            ..Default::default()
        };
        let cap = AttemptCap::from_block(&block);
        assert_eq!(cap.max_attempts, 5);
        assert!(cap.source.contains("published policy"));
    }
}

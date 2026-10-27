//! The profile: a named, versioned set of rules that implements
//! [`gitiup_attest::run::Normaliser`].
//!
//! This is the seam giti-1rs.2 left open. The digest computation does not know
//! what a timestamp looks like; it knows that some component rewrites logs so
//! independent reruns converge, and that the rules used must be recorded, because
//! two results normalised by different rules are not comparable (ADR-0001 D4/D5).

use gitiup_attest::run::Normaliser;

use crate::grammar::{PROFILE_NAME, PROFILE_VERSION, Rule, Rules};
use crate::log;
use crate::rewrite::{Rewrites, Stream};

/// How many individual rewrites one stream records in full.
///
/// Beyond this the record aggregates ("`duration`: 1284 further rewrites omitted")
/// rather than growing with the log: a 200 MB build log must not produce a 200 MB
/// report, and a count that says *how much* was dropped is honest in a way that a
/// silently truncated list is not.
pub const MAX_REWRITES: usize = 512;

/// The standard reproducibility profile.
///
/// ```
/// use gitiup_normalise::Profile;
/// use gitiup_attest::run::Normaliser;
///
/// let profile = Profile::standard();
/// assert_eq!(profile.version(), 1);
/// let log = "Finished release [optimized] in 41.283s\n";
/// assert_eq!(profile.normalise(log), "Finished release [optimized] in <dur>\n");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    version: u32,
    name: &'static str,
    rules: Rules,
}

/// A normalised stream plus the record of what happened to it.
#[derive(Debug, Clone)]
pub struct Normalised {
    /// The text to hash.
    pub text: String,
    /// Every rewrite, in application order.
    pub rewrites: Rewrites,
}

impl Normalised {
    /// True when the normaliser had nothing to do.
    pub fn unchanged(&self) -> bool {
        self.rewrites.is_empty()
    }
}

impl Profile {
    /// The profile whose version is [`PROFILE_VERSION`], with every rule on.
    pub const fn standard() -> Profile {
        Profile {
            version: PROFILE_VERSION,
            name: PROFILE_NAME,
            rules: Rules::all(),
        }
    }

    /// The standard profile minus one rule (the common question in review: "what
    /// is this rule actually buying?").
    pub fn without(rule: Rule) -> Profile {
        Profile {
            rules: Rules::all().without(rule),
            ..Profile::standard()
        }
    }

    /// A profile with an exact rule set, still version 1.
    ///
    /// Any rule set may be used, but the *version recorded in the manifest is this
    /// profile's version*, so a non-standard rule set recorded as version 1 would
    /// be a lie. Use this to explore, and name your own rule set as its own version
    /// when it goes into a runner.
    pub fn with_rules(rules: Rules) -> Profile {
        Profile {
            rules,
            ..Profile::standard()
        }
    }

    /// The profile's name, as a runner reports it (`repro`).
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The value recorded in `provenance.normalisation_version`.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The rules that produced this profile's output.
    pub const fn rules(&self) -> Rules {
        self.rules
    }

    /// Normalise a log stream, keeping only the text.
    ///
    /// Shorthand for [`Profile::normalise_stream`] with stdout; the stream matters
    /// only for the handful of facts that are about a stream rather than a line.
    pub fn normalise(&self, text: &str) -> String {
        self.normalise_stream(text, Stream::Stdout)
    }

    /// Normalise one named stream, keeping only the text.
    pub fn normalise_stream(&self, text: &str, stream: Stream) -> String {
        self.normalise_recorded_stream(text, stream).text
    }

    /// Normalise a log stream and record every rewrite.
    ///
    /// The record is per line and per rule ([`crate::Rewrite`]); call
    /// [`crate::Rewrites::aggregate`] for the form a manifest can carry.
    pub fn normalise_recorded(&self, text: &str) -> Normalised {
        self.normalise_recorded_stream(text, Stream::Stdout)
    }

    /// Normalise one named stream and record every rewrite.
    pub fn normalise_recorded_stream(&self, text: &str, stream: Stream) -> Normalised {
        let mut rewrites = Rewrites::with_cap(MAX_REWRITES);
        let text = log::normalise(text, self.rules, stream, &mut rewrites);
        Normalised { text, rewrites }
    }
}

impl Default for Profile {
    fn default() -> Profile {
        Profile::standard()
    }
}

impl Normaliser for Profile {
    fn version(&self) -> u32 {
        self.version
    }

    fn name(&self) -> &str {
        self.name
    }

    fn normalise(&self, text: &str) -> String {
        Profile::normalise(self, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_is_a_normaliser() {
        let profile = Profile::standard();
        let dyn_ref: &dyn Normaliser = &profile;
        assert_eq!(dyn_ref.version(), PROFILE_VERSION);
        assert_eq!(dyn_ref.name(), "repro");
        assert_eq!(dyn_ref.normalise("a\n"), "a\n");
    }

    #[test]
    fn dropping_a_rule_changes_the_output() {
        let log = "Finished in 12.4s\n";
        assert_eq!(Profile::standard().normalise(log), "Finished in <dur>\n");
        let no_durations = Profile::without(Rule::Duration);
        assert!(!no_durations.rules().contains(Rule::Duration));
        assert_eq!(no_durations.normalise(log), log);
    }
}

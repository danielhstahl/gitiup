//! Rewrites and their record: what changed, and how it is reported.
//!
//! Two record types, because two different readers exist:
//!
//! * [`Rewrites`] is the **full** record — one entry per line per rule — which is
//!   what `gitiup normalise` prints and what a runner logs. It is deliberately not
//!   what goes into a manifest;
//! * [`NormalisationDiff`]s are the **aggregate** ([`Rewrites::aggregate`],
//!   [`Divergences::aggregate`]): at most one per (step, kind), which is what the
//!   signed format can carry — `RunManifest::normalize` dedups that list by
//!   `(step, kind)`, so a producer emitting twelve `timestamp` rewrites for one
//!   step would silently keep one. Aggregating explicitly means the count is in
//!   the document instead of being a mystery.
//!
//! Both are sanitized on the way in ([`sanitize`]) because `before` is machine text
//! by definition: a control byte or an ESC in it would make the *manifest*
//! unencodable, which is a worse failure than the one being reported.

use std::collections::BTreeMap;

use gitiup_attest::NormalisationDiff;

use crate::grammar::Rule;

/// How many example rewrites an aggregate names.
///
/// Small on purpose: this text is signed and shipped to every verifier, and the
/// point of an aggregate is "this rule fired here, like this", not the whole log.
pub const MAX_SAMPLES: usize = 3;

/// Byte budget for one `before`/`after` field of an aggregate.
///
/// Well under `manifest::MAX_STRING_LEN` (16 KiB), because several samples are
/// joined and because nobody reads past the third.
pub const MAX_DIFF_TEXT: usize = 2048;

/// The text used when a rewrite deleted or added a whole line, so that
/// `before`/`after` always says something.
pub const DELETED: &str = "(line deleted)";

/// The separator between samples in an aggregate.
const SAMPLE_SEPARATOR: &str = " || ";

/// Replace control characters and over-long text with something a manifest can
/// carry and a terminal can print.
///
/// `gitiup_attest::manifest` refuses control characters in several strings it
/// signs, and a diff containing a raw ESC would be the second bug in the story.
/// Tabs become `\t`, newlines `\n`, other control bytes `\xNN`; nothing else
/// changes.
pub fn sanitize(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_DIFF_TEXT));
    for ch in text.chars() {
        match ch {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
        if out.len() >= MAX_DIFF_TEXT {
            out.truncate(MAX_DIFF_TEXT.saturating_sub(3));
            out.push('…');
            break;
        }
    }
    out
}

/// Which log stream a record belongs to.
///
/// The manifest keys normalisation diffs by `(step, kind)` and will not carry two
/// with one key, so the stream goes into the kind: `timestamp` for stdout,
/// `timestamp:stderr` for stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// The step's stdout.
    Stdout,
    /// The step's stderr.
    Stderr,
}

impl Stream {
    /// The kind suffix for this stream (`""` / `":stderr"`).
    pub const fn suffix(&self) -> &'static str {
        match self {
            Stream::Stdout => "",
            Stream::Stderr => ":stderr",
        }
    }

    /// The stream's name, for output.
    pub const fn name(&self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }
}

/// One rewrite of one line by one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    /// 1-based line number in the stream as it arrived.
    pub line: usize,
    /// The rule that did it; its name is the diff `kind`.
    pub rule: Rule,
    /// The line before the rewrite (sanitized).
    pub before: String,
    /// The line after it (sanitized).
    pub after: String,
}

impl Rewrite {
    /// Build a rewrite, sanitizing both sides.
    pub fn new(line: usize, rule: Rule, before: &str, after: &str) -> Rewrite {
        Rewrite {
            line,
            rule,
            before: sanitize(before),
            after: sanitize(after),
        }
    }

    /// A rewrite that is a fact about the stream rather than about a line — CRLF
    /// converted to LF, say. There is no line to point at, so `line` is zero, and
    /// there is no stream name to extract, so the diff kind is the rule's own name.
    pub(crate) fn stream(rule: Rule, before: &str, after: &str) -> Rewrite {
        Rewrite::new(0, rule, before, after)
    }
}

/// The full record of one stream's rewrites, in order, capped.
///
/// The cap is what lets a normaliser run over a 200 MB log without producing a
/// 200 MB report: `rewrote X, showing the first N` is the honest form, and
/// `truncated` says out loud when detail was dropped rather than dropping it
/// silently.
#[derive(Debug, Clone, Default)]
pub struct Rewrites {
    items: Vec<Rewrite>,
    /// Rewrites seen beyond the cap, per rule.
    dropped: BTreeMap<Rule, usize>,
    cap: usize,
    dropped_lines: usize,
}

impl Rewrites {
    /// An empty record allowing `cap` entries.
    pub fn with_cap(cap: usize) -> Rewrites {
        Rewrites {
            items: Vec::new(),
            dropped: BTreeMap::new(),
            cap,
            dropped_lines: 0,
        }
    }

    /// The rewrites recorded, in application order.
    pub fn items(&self) -> &[Rewrite] {
        &self.items
    }

    /// True when nothing was rewritten.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.dropped.is_empty()
    }

    /// Rewrites dropped because of the cap, per rule.
    pub fn dropped(&self) -> &BTreeMap<Rule, usize> {
        &self.dropped
    }

    /// Progress lines the pipeline dropped (see [`crate::grammar::Rule::Progress`]).
    pub fn dropped_lines(&self) -> usize {
        self.dropped_lines
    }

    pub(crate) fn line_dropped(&mut self) {
        self.dropped_lines += 1;
    }

    pub(crate) fn push(&mut self, rewrite: Rewrite) {
        if self.items.len() < self.cap {
            self.items.push(rewrite);
        } else {
            *self.dropped.entry(rewrite.rule).or_insert(0) += 1;
        }
    }

    /// Collapse to at most one [`NormalisationDiff`] per (rule, step, stream): the
    /// form the signed format can carry without `normalize()` dropping anything.
    ///
    /// `suffix` distinguishes the two log streams of one step (`":stderr"`, or
    /// `""` for stdout) because the manifest keys this list by `(step, kind)` and
    /// two diffs with one key would collapse into one.
    pub fn aggregate(&self, step: &str, suffix: &str) -> Vec<NormalisationDiff> {
        let mut by_rule: BTreeMap<Rule, Vec<(String, String)>> = BTreeMap::new();
        for item in &self.items {
            by_rule
                .entry(item.rule)
                .or_default()
                .push((item.before.clone(), item.after.clone()));
        }
        let mut out: Vec<NormalisationDiff> = by_rule
            .into_iter()
            .map(|(rule, pairs)| NormalisationDiff {
                step: step.to_string(),
                kind: format!("{}{suffix}", rule.name()),
                before: join_samples(pairs.iter().map(|(before, _)| before.clone()).collect()),
                after: join_samples(pairs.iter().map(|(_, after)| after.clone()).collect()),
            })
            .collect();
        // A rewrite we could not show is still a divergence we must not hide.
        for (rule, count) in &self.dropped {
            out.push(NormalisationDiff {
                step: step.to_string(),
                kind: format!("{}{suffix}:truncated", rule.name()),
                before: format!("{count} further rewrites omitted"),
                after: "see `gitiup normalise` for the full record".into(),
            });
        }
        out.sort_by(|a, b| (&a.step, &a.kind).cmp(&(&b.step, &b.kind)));
        out
    }

    /// A short human-readable summary, e.g. for `--quiet`-adjacent output.
    pub fn counts(&self) -> Vec<(Rule, usize)> {
        let mut counts: BTreeMap<Rule, usize> = BTreeMap::new();
        for item in &self.items {
            *counts.entry(item.rule).or_insert(0) += 1;
        }
        counts.into_iter().collect()
    }
}

/// A divergence that is not a rewrite: two runs disagreeing about a step, an
/// output, an artifact, or the run's inputs.
///
/// Same aggregation rule as [`Rewrites::aggregate`], because it lands in the same
/// manifest field.
#[derive(Debug, Clone, Default)]
pub struct Divergences {
    entries: Vec<(String, String, String)>,
}

impl Divergences {
    /// Record one divergence between `before` (run A) and `after` (run B).
    pub fn push(
        &mut self,
        kind: impl Into<String>,
        before: impl Into<String>,
        after: impl Into<String>,
    ) {
        self.entries.push((
            kind.into(),
            sanitize(&before.into()),
            sanitize(&after.into()),
        ));
    }

    /// True when the two sides agreed on everything compared.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The raw entries, in the order recorded.
    pub fn entries(&self) -> &[(String, String, String)] {
        &self.entries
    }

    /// Collapse to at most one diff per (step, kind). See
    /// [`Rewrites::aggregate`] for why there is at most one.
    pub fn aggregate(&self, step: &str, suffix: &str) -> Vec<NormalisationDiff> {
        let mut by_kind: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for (kind, before, after) in &self.entries {
            by_kind
                .entry(format!("{kind}{suffix}"))
                .or_default()
                .push((before.clone(), after.clone()));
        }
        let mut out: Vec<NormalisationDiff> = by_kind
            .into_iter()
            .map(|(kind, pairs)| NormalisationDiff {
                step: step.to_string(),
                kind,
                before: join_samples(pairs.iter().map(|(before, _)| before.clone()).collect()),
                after: join_samples(pairs.iter().map(|(_, after)| after.clone()).collect()),
            })
            .collect();
        out.sort_by(|a, b| (&a.step, &a.kind).cmp(&(&b.step, &b.kind)));
        out
    }
}

/// Up to [`MAX_SAMPLES`] values, joined, with the remainder counted.
fn join_samples(samples: Vec<String>) -> String {
    if samples.is_empty() {
        return String::new();
    }
    let mut out = samples
        .iter()
        .take(MAX_SAMPLES)
        .cloned()
        .collect::<Vec<_>>()
        .join(SAMPLE_SEPARATOR);
    if samples.len() > MAX_SAMPLES {
        out.push_str(&format!(" (+{} more)", samples.len() - MAX_SAMPLES));
    }
    if out.len() > MAX_DIFF_TEXT {
        out.truncate(MAX_DIFF_TEXT.saturating_sub(3));
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_bytes_never_reach_a_diff() {
        let clean = sanitize("built\x1b[0m in 1.2s\r\n");
        assert!(!clean.bytes().any(|b| b < 0x20 || b == 0x7f), "{clean:?}");
        assert!(clean.contains("\\x1b"));
        assert!(clean.contains("\\r") && clean.contains("\\n"));
    }

    #[test]
    fn long_text_is_cut_not_dropped() {
        let long = sanitize(&"x".repeat(MAX_DIFF_TEXT * 2));
        assert!(long.len() <= MAX_DIFF_TEXT);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn rewrites_aggregate_one_per_rule_and_survive_a_manifest() {
        let mut rewrites = Rewrites::with_cap(10);
        for index in 0..5 {
            rewrites.push(Rewrite::new(
                index,
                Rule::Timestamp,
                &format!("line {index} at 2026-10-27T09:11:12Z"),
                &format!("line {index} at <ts>"),
            ));
        }
        let diffs = rewrites.aggregate("build", "");
        assert_eq!(diffs.len(), 1, "one rule fires once per step");
        assert_eq!(diffs[0].kind, "timestamp");
        assert!(diffs[0].after.contains("<ts>"));
        assert!(diffs[0].before.contains("(+2 more)"), "{}", diffs[0].before);
    }

    #[test]
    fn a_capped_record_says_so() {
        let mut rewrites = Rewrites::with_cap(2);
        for index in 0..5 {
            rewrites.push(Rewrite::new(index, Rule::Duration, "in 1.2s", "in <dur>"));
        }
        assert_eq!(rewrites.items().len(), 2);
        assert_eq!(rewrites.dropped()[&Rule::Duration], 3);
        let diffs = rewrites.aggregate("build", ":stderr");
        assert!(diffs.iter().any(|d| d.kind == "duration:stderr:truncated"));
    }

    #[test]
    fn divergences_aggregate_by_kind() {
        let mut log = Divergences::default();
        log.push("stdout", "a", "b");
        log.push("stdout", "c", "d");
        log.push("exit-code", "0", "101");
        let diffs = log.aggregate("test", "");
        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].kind, "exit-code");
        assert_eq!(diffs[1].kind, "stdout");
        assert!(diffs[1].before.contains(" || "));
    }
}

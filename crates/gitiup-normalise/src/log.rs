//! The pipeline: text in, text out, and the record of what was rewritten.
//!
//! The order of the passes is the design (see [`crate::grammar::RULE_ORDER`]), and
//! the one property that makes the whole thing trustworthy is that it is a
//! *projection*: applying it twice is applying it once. A normaliser that was not
//! idempotent would make `provenance.normalisation_version` meaningless, because
//! the digest would depend on how many times whoever produced it happened to
//! pipe the log through. `tests/properties.rs` checks the property over every line
//! of the corpus and over every single-rule profile.

use crate::Rules;
use crate::grammar::Rule;
use crate::paths;
use crate::rewrite::Stream;
use crate::rewrite::{DELETED, Rewrite, Rewrites};
use crate::term;
use crate::values;

/// Normalise one log stream, recording every rewrite.
///
/// `stream` is used only to label stream-wide facts (CRLF → LF) so that a diff of the
/// stdout stream and one of the stderr stream do not collide in a manifest keyed by
/// step and kind.
pub(crate) fn normalise(text: &str, rules: Rules, stream: Stream, rec: &mut Rewrites) -> String {
    if text.is_empty() {
        return String::new();
    }
    // CRLF is a fact about the stream rather than about a line, so it is recorded
    // once for the stream instead of as one identical entry per line: on a 200 MB
    // Windows build log, per-line records would fill the cap with nothing but `\r`
    // and crowd out every other kind of rewrite.
    if rules.contains(Rule::LineEndings) && text.contains("\r\n") {
        rec.push(Rewrite::stream(
            Rule::LineEndings,
            &format!("{}: CRLF line endings", stream.name()),
            &format!("{}: LF line endings", stream.name()),
        ));
    }
    let mut lines = term::split(text);
    let mut dropped = vec![false; lines.len()];
    // The index is the line number: it addresses both the line and its dropped flag,
    // and it is what the rewrite record reports.
    #[allow(clippy::needless_range_loop)]
    for index in 0..lines.len() {
        if apply_line_rules(&mut lines, index, rules, rec) {
            dropped[index] = true;
        }
    }
    // A dropped progress line is *gone*, not blank: leaving an empty line where the
    // redraw was would make one machine's refresh rate change the line count, which
    // is the very thing being normalised away. From here on a line carries its
    // original line number with it, so that a line number in the record is a line
    // number in the log a reader can open — not one shifted by what was removed.
    let mut kept: Vec<(usize, String)> = (0..lines.len())
        .filter(|index| !dropped[*index])
        .map(|index| (index + 1, std::mem::take(&mut lines[index])))
        .collect();
    // An empty stream is empty in every spelling: `""`, `"\n"`, `"\n\n\n"` and a
    // stream of nothing-but-dropped progress lines all hash the same, instead of
    // hashing differently because of how many blank lines a shell echo left behind.
    if kept.iter().all(|(_, line)| line.is_empty()) {
        return String::new();
    }
    if rules.contains(Rule::Spacing) {
        collapse_blank_runs(&mut kept, rec);
    }
    while kept.last().is_some_and(|(_, line)| line.is_empty()) {
        kept.pop();
    }
    if rules.contains(Rule::Listing) {
        sort_listings(&mut kept, rec);
    }
    term::join(
        &kept
            .iter()
            .map(|(_, line)| line.clone())
            .collect::<Vec<_>>(),
    )
}

/// Collapse runs of blank lines into one.
///
/// How many blank lines a tool emits between stages is a matter of taste and version,
/// and a build log that adds a blank line is not a different result.
fn collapse_blank_runs(lines: &mut Vec<(usize, String)>, rec: &mut Rewrites) {
    let mut keep: Vec<bool> = vec![true; lines.len()];
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].1.is_empty() {
            let start = index;
            while index < lines.len() && lines[index].1.is_empty() {
                index += 1;
            }
            if index - start > 1 {
                for slot in &mut keep[start + 1..index] {
                    *slot = false;
                }
                runs.push((start, index));
            }
        }
        index += 1;
    }
    if runs.is_empty() {
        return;
    }
    for (start, end) in runs {
        rec.push(Rewrite::new(
            lines[start].0,
            Rule::Spacing,
            &format!("{} blank lines", end - start),
            "1 blank line",
        ));
    }
    let mut kept_lines: Vec<(usize, String)> = Vec::with_capacity(lines.len());
    for (slot, line) in lines.drain(..).enumerate() {
        if keep[slot] {
            kept_lines.push(line);
        }
    }
    *lines = kept_lines;
}

/// Every rule that works line by line, in pipeline order.
///
/// Apply the line rules to one line, recording every rewrite. Returns `true` when
/// the line was dropped: `Progress` is the one rule that removes a line rather
/// than rewriting it, and a dropped line still has to be recorded, or the record
/// would claim the stream was shorter than it was.
fn apply_line_rules(lines: &mut [String], index: usize, rules: Rules, rec: &mut Rewrites) -> bool {
    let line_number = index + 1;
    let mut line = std::mem::take(&mut lines[index]);

    if rules.contains(Rule::LineEndings) {
        // The `\r` of a CRLF pair goes here, without a per-line record, because the
        // stream-level marker above already says it happened. Everything else the
        // rule does — tabs, trailing blanks, form feeds — is recorded per line.
        line = line.strip_suffix('\r').map(str::to_string).unwrap_or(line);
        if let Some(next) = term::line_endings(&line) {
            rec.push(Rewrite::new(line_number, Rule::LineEndings, &line, &next));
            line = next;
        }
    }

    if rules.contains(Rule::Ansi)
        && let Some(next) = term::ansi(&line)
    {
        rec.push(Rewrite::new(line_number, Rule::Ansi, &line, &next));
        line = next;
    }

    if rules.contains(Rule::Progress) && term::progress(&line) {
        rec.push(Rewrite::new(line_number, Rule::Progress, &line, DELETED));
        rec.line_dropped();
        lines[index].clear();
        return true;
    }
    if rules.contains(Rule::Progress)
        && let Some(next) = term::progress_bar(&line)
    {
        rec.push(Rewrite::new(line_number, Rule::Progress, &line, &next));
        line = next;
    }

    if rules.contains(Rule::Path)
        && let Some(next) = paths::paths(&line)
    {
        rec.push(Rewrite::new(line_number, Rule::Path, &line, &next));
        line = next;
    }

    if rules.contains(Rule::Identity) {
        let context = paths::host_context(&line);
        if let Some(next) = paths::identity(&line, context) {
            rec.push(Rewrite::new(line_number, Rule::Identity, &line, &next));
            line = next;
        }
    }

    for (rule, pass) in [
        (
            Rule::Timestamp,
            values::timestamps as fn(&str) -> Option<String>,
        ),
        (Rule::Duration, values::durations),
        (Rule::Percent, values::percents),
        (Rule::Number, values::numbers),
        (Rule::Size, values::sizes),
        (Rule::Spacing, spacing),
    ] {
        if rules.contains(rule)
            && let Some(next) = pass(&line)
        {
            rec.push(Rewrite::new(line_number, rule, &line, &next));
            line = next;
        }
    }

    lines[index] = line;
    false
}

/// `Spacing`: one canonical separator between fields.
///
/// Leading indentation is kept as *one* space per indent level (enough to keep a
/// nested shape, not enough for column alignment to matter), and internal runs of
/// whitespace collapse to one space. Alignment padding is machine-visible: a
/// table whose columns are sized by the widest value on that machine moves every
/// other column when one value is a byte wider.
fn spacing(line: &str) -> Option<String> {
    // A line-final `CR` is a line ending, not whitespace to tidy: `line-ending` owns
    // it. Handled here it would make that rule look redundant, and a rule that is
    // never load-bearing is a rule that quietly stops working.
    let (body, cr) = match line.strip_suffix('\r') {
        Some(body) => (body, "\r"),
        None => (line, ""),
    };
    let indent = body.len() - body.trim_start_matches([' ', '\u{a0}']).len();
    let mut out = String::with_capacity(line.len());
    if indent > 0 {
        out.push(' ');
    }
    let mut in_space = false;
    for ch in body.trim().chars() {
        let space = ch == ' ' || ch == '\u{a0}' || ch == '\u{2009}' || ch == '\u{202f}';
        if space {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
            continue;
        }
        in_space = false;
        out.push(ch);
    }
    out.push_str(cr);
    (out != line).then_some(out)
}

// ------------------------------------------------------------- listings ---

/// The shape of a line that is one entry of an unordered listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// An `ls -l` style row.
    Directory,
    /// A bare path, one per line.
    Path,
    /// `- path` or `* path`.
    Bullet,
}

/// The smallest run of same-shaped lines that is a listing: one line is a
/// mention, two is a list.
const MIN_LISTING: usize = 2;

fn shape(line: &str) -> Option<Shape> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if crate::grammar::ls_row(line) {
        return Some(Shape::Directory);
    }
    let bullet = trimmed
        .strip_prefix("- ")
        .or_else(|| trimmed.strip_prefix("* "));
    if let Some(rest) = bullet
        && !rest.is_empty()
        && !rest.contains(' ')
    {
        return Some(Shape::Bullet);
    }
    if !trimmed.contains(' ') && path_like(trimmed) {
        return Some(Shape::Path);
    }
    None
}

/// A path-like token, so that a block of *those* can be sorted.
fn path_like(token: &str) -> bool {
    token.len() >= 3
        && (token.contains('/') || token.contains('.'))
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'-' | b'_' | b'+'))
}

/// Sort runs of listing lines.
///
/// Only a *run* of same-shaped lines with the same indentation is sorted, so a
/// single path in a sentence is left alone, and only when the run is not already
/// sorted, which is what makes the rule a no-op on output that was sorted by the
/// workflow (the first line of defence in the reproducibility contract).
fn sort_listings(lines: &mut [(usize, String)], rec: &mut Rewrites) {
    let mut index = 0usize;
    while index < lines.len() {
        let text = lines[index].1.clone();
        let Some(entry) = shape(&text) else {
            index += 1;
            continue;
        };
        let indent = text.len() - text.trim_start().len();
        let mut end = index + 1;
        while end < lines.len() {
            let candidate = lines[end].1.clone();
            if shape(&candidate) != Some(entry)
                || candidate.len() - candidate.trim_start().len() != indent
            {
                break;
            }
            end += 1;
        }
        // Only a run of same-shaped, same-indented lines is a listing, and only one
        // that is not already in order — which is what makes this rule a no-op on
        // output the workflow already sorted.
        if end - index >= MIN_LISTING {
            let mut block: Vec<(usize, String)> = lines[index..end].to_vec();
            let mut sorted = block.clone();
            sorted.sort_by(|a, b| a.1.cmp(&b.1));
            if sorted != block {
                rec.push(Rewrite::new(
                    lines[index].0,
                    Rule::Listing,
                    &lines[index..end]
                        .iter()
                        .map(|(_, line)| line.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                    &sorted
                        .iter()
                        .map(|(_, line)| line.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ));
                block = sorted;
            }
            for (offset, line) in block.into_iter().enumerate() {
                lines[index + offset] = line;
            }
        }
        index = end.max(index + 1);
    }
}

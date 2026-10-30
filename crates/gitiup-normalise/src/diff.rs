//! The diff normalisation cannot make: two logs, side by side, raw and after the profile.
//!
//! [`crate::Profile`] answers "do these two runs *mean* the same thing?" by rewriting
//! everything that is a fact about the machine rather than a fact about the result, and
//! digests the rest. That answer is the one a digest needs and a poor one for a human:
//! when two verifiers disagree, the first question is not whether the hashes differ (they
//! do — that is why anyone is looking) but
//!
//! * **which lines differ**, and
//! * **which of those differences normalisation erased**.
//!
//! The second is the whole reason both views are printed together. A difference that
//! survives normalisation is a fact about the build — a test that ran, a version that
//! moved, an artifact that changed size. A difference that does not survive it is a fact
//! about the machine, and the person reading the report needs to be told which of the two
//! they are looking at rather than shown a diff and left to guess.
//!
//! ```
//! use gitiup_normalise::{Profile, diff_text};
//!
//! let left = "Finished in 12.5s\ntest result: ok. 42 passed\n";
//! let right = "Finished in 4.1s\ntest result: ok. 42 passed\n";
//! let profile = Profile::standard();
//!
//! // Raw: the two logs differ.
//! assert!(diff_text(left, right).changed());
//! // After the profile: that difference was a duration, so it is about the machine.
//! assert!(!diff_text(&profile.normalise(left), &profile.normalise(right)).changed());
//! assert!(!diff_text(left, right).surviving(&profile)
//!     .iter().any(|change| change.survives_normalisation(&profile)));
//! ```
//!
//! # Size is bounded, and says so
//!
//! A build log can be a hundred megabyte of progress spam, and a diff of two of them is
//! the one place a quadratic algorithm gets noticed. Common prefix and suffix are cut off
//! first (the overwhelmingly common case: two logs that share a head and a tail), the LCS
//! table is refused past [`MAX_DIFF_CELLS`], and a diff that had to be approximated sets
//! [`TextDiff::approximate`] rather than printing a confident wrong answer.

use serde::{Deserialize, Serialize};

use crate::profile::Profile;

/// Largest number of lines diffed with the exact algorithm.
///
/// Beyond it the middle of the log is reported as one block change, which is slower to
/// read and better than a tool that OOMs on a stranger's log.
pub const MAX_DIFF_LINES: usize = 20_000;

/// Largest LCS table (left lines × right lines) the exact algorithm will build.
pub const MAX_DIFF_CELLS: usize = 4_000_000;

/// How a line in one log relates to the line opposite it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowKind {
    /// The same text on both sides.
    Equal,
    /// Different text on both sides — one removed line paired with one added line.
    Changed,
    /// A line only the left log has.
    Removed,
    /// A line only the right log has.
    Added,
}

impl RowKind {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            RowKind::Equal => "equal",
            RowKind::Changed => "changed",
            RowKind::Removed => "removed",
            RowKind::Added => "added",
        }
    }

    /// The marker a side-by-side rendering puts between the two columns.
    pub fn marker(self) -> char {
        match self {
            RowKind::Equal => ' ',
            RowKind::Changed => '|',
            RowKind::Removed => '<',
            RowKind::Added => '>',
        }
    }

    /// Whether this row is a difference at all.
    pub fn is_change(self) -> bool {
        self != RowKind::Equal
    }
}

/// One row of a side-by-side diff.
///
/// A row carries *both* sides, because the thing being read is the pair: "this line, and
/// that line opposite it". An unmatched line has `None` on the side that does not have it,
/// which is a different fact from an empty line and is rendered as a gap rather than as
/// whitespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRow {
    /// How the two sides relate.
    pub kind: RowKind,
    /// 1-based line number on the left, absent when the left has no such line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_no: Option<u64>,
    /// The left text, absent when the left has no such line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<String>,
    /// 1-based line number on the right.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_no: Option<u64>,
    /// The right text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<String>,
}

/// A run of changed rows: one "hunk" in diff vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Change {
    /// The left lines it replaces, with their numbers.
    pub left: Vec<(u64, String)>,
    /// The right lines that replace them.
    pub right: Vec<(u64, String)>,
}

impl Change {
    /// The left text as one block, newline-joined.
    pub fn left_text(&self) -> String {
        self.left
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The right text as one block.
    pub fn right_text(&self) -> String {
        self.right
            .iter()
            .map(|(_, line)| line.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Does this difference survive `profile`?
    ///
    /// The two sides are normalised *as the block they are* and compared. That is a local
    /// measure — stream-wide rules (a CRLF conversion, dropped progress lines) are decided
    /// over a whole stream, not over a hunk — and it answers the question a reader is
    /// asking about a hunk: would the profile have made these two blocks agree?
    ///
    /// `true` is the interesting answer: a difference the profile does not touch is a
    /// difference about the build.
    pub fn survives_normalisation(&self, profile: &Profile) -> bool {
        profile.normalise(&self.left_text()) != profile.normalise(&self.right_text())
    }
}

/// Counts, for a line that says how big the disagreement is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiffStats {
    /// Lines the two logs share.
    pub equal: u64,
    /// Lines only the right log has.
    pub added: u64,
    /// Lines only the left log has.
    pub removed: u64,
    /// Runs of changed lines.
    pub changes: u64,
}

/// The diff of two texts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextDiff {
    /// Every row, in order, equal rows included (a renderer decides what to print).
    pub rows: Vec<DiffRow>,
    /// Lines on each side, so a reader can tell "identical" from "identical so far".
    pub left_lines: u64,
    /// Lines on the right.
    pub right_lines: u64,
    /// Whether each side ended with a newline: two logs whose only difference is a
    /// missing final newline are *not* the same text, and saying so beats pretending.
    pub left_newline: bool,
    /// The right side's final newline.
    pub right_newline: bool,
    /// True when the two texts were too large for the exact algorithm and the middle was
    /// reported as one block.
    pub approximate: bool,
}

impl TextDiff {
    /// Every row, equal ones included.
    pub fn rows(&self) -> &[DiffRow] {
        &self.rows
    }

    /// Do the two texts differ at all?
    pub fn changed(&self) -> bool {
        self.rows.iter().any(|row| row.kind.is_change())
            || self.left_newline != self.right_newline
            || self.left_lines != self.right_lines
    }

    /// The counts a summary line prints.
    pub fn stats(&self) -> DiffStats {
        let mut stats = DiffStats::default();
        for row in &self.rows {
            match row.kind {
                RowKind::Equal => stats.equal += 1,
                RowKind::Changed => {
                    stats.removed += 1;
                    stats.added += 1;
                }
                RowKind::Removed => stats.removed += 1,
                RowKind::Added => stats.added += 1,
            }
        }
        stats.changes = self.changes().len() as u64;
        stats
    }

    /// The changed runs, in order.
    pub fn changes(&self) -> Vec<Change> {
        let mut out: Vec<Change> = Vec::new();
        let mut current = Change::default();
        let mut open = false;
        for row in &self.rows {
            if row.kind == RowKind::Equal {
                if open {
                    out.push(std::mem::take(&mut current));
                    open = false;
                }
                continue;
            }
            open = true;
            if let (Some(no), Some(text)) = (row.left_no, row.left.as_deref()) {
                current.left.push((no, text.to_string()));
            }
            if let (Some(no), Some(text)) = (row.right_no, row.right.as_deref()) {
                current.right.push((no, text.to_string()));
            }
        }
        if open {
            out.push(current);
        }
        out
    }

    /// Every change that survives `profile`, i.e. the differences that are about the
    /// build and not about the machine.
    pub fn surviving(&self, profile: &Profile) -> Vec<Change> {
        self.changes()
            .into_iter()
            .filter(|change| change.survives_normalisation(profile))
            .collect()
    }

    /// Render side by side: left column, a marker, right column.
    ///
    /// `width` is the total width available, and a column is truncated rather than
    /// wrapped — a wrapped line stops being one line opposite another line, which is the
    /// only property a side-by-side diff has. Equal runs longer than `context` lines are
    /// collapsed to a count, because the point of the view is the differences.
    pub fn side_by_side(&self, width: usize, context: usize) -> String {
        self.side_by_side_annotated(width, context, &|_| None)
    }

    /// The side-by-side view with one line of annotation after each changed block.
    ///
    /// This is what makes the view answer the question a dispute is about: the annotator
    /// is handed each [`Change`] and says what the reader should take from it — usually
    /// whether the profile erases the difference or not
    /// ([`Change::survives_normalisation`]). `None` prints no note, which is how
    /// [`TextDiff::side_by_side`] is spelled.
    pub fn side_by_side_annotated(
        &self,
        width: usize,
        context: usize,
        annotate: &dyn Fn(&Change) -> Option<String>,
    ) -> String {
        // `{left_no:>N} {left:<col} M {right_no:<N} {right}`: two line-number columns of
        // N digits, a marker and four spaces. The width is spent on the text and not on
        // the numbers, so a 6-digit log line does not push the right column off screen.
        let digits = self
            .left_lines
            .max(self.right_lines)
            .to_string()
            .len()
            .max(2);
        let column = ((width.saturating_sub(2 * digits + 4)) / 2).max(12);
        let mut out = String::new();
        let mut block = Change::default();
        for item in self.collapsed(context) {
            match item {
                Rendered::Collapsed(count) => {
                    finish(&mut out, &mut block, annotate);
                    let _ = std::fmt::write(
                        &mut out,
                        format_args!("    \u{22ee} {count} unchanged line(s)\n"),
                    );
                }
                Rendered::Row(row) => {
                    if row.kind == RowKind::Equal {
                        finish(&mut out, &mut block, annotate);
                    } else {
                        if let (Some(no), Some(text)) = (row.left_no, row.left.as_deref()) {
                            block.left.push((no, text.to_string()));
                        }
                        if let (Some(no), Some(text)) = (row.right_no, row.right.as_deref()) {
                            block.right.push((no, text.to_string()));
                        }
                    }
                    let _ = std::fmt::write(
                        &mut out,
                        format_args!(
                            "{left_no:>digits$} {left:<column$} {marker} {right_no:<digits$} {right}\n",
                            left_no = row.left_no.map(|no| no.to_string()).unwrap_or_default(),
                            left = row
                                .left
                                .as_deref()
                                .map(|t| clip(t, column))
                                .unwrap_or_default(),
                            marker = row.kind.marker(),
                            right_no = row.right_no.map(|no| no.to_string()).unwrap_or_default(),
                            right = row
                                .right
                                .as_deref()
                                .map(|t| clip(t, column))
                                .unwrap_or_default(),
                        ),
                    );
                }
            }
        }
        finish(&mut out, &mut block, annotate);
        if self.approximate {
            let _ = std::fmt::write(
                &mut out,
                format_args!(
                    "    (the middle of a log longer than {MAX_DIFF_LINES} lines is shown as \
                     one block: the diff is approximate)\n"
                ),
            );
        }
        if self.left_newline != self.right_newline {
            let _ = std::fmt::write(
                &mut out,
                format_args!(
                    "    (only the final newline differs: {} ends the line, {} does not)\n",
                    if self.left_newline { "left" } else { "right" },
                    if self.left_newline { "right" } else { "left" },
                ),
            );
        }
        out
    }

    /// A unified-style rendering, for a caller that wants one column.
    pub fn unified(&self, context: usize) -> String {
        let mut out = String::new();
        for row in &self.collapsed(context) {
            match row {
                Rendered::Collapsed(count) => {
                    let _ = std::fmt::write(&mut out, format_args!("   \u{22ee} {count}\n"));
                }
                Rendered::Row(row) => match row.kind {
                    RowKind::Equal => {
                        let _ = std::fmt::write(
                            &mut out,
                            format_args!(
                                "  {} {}\n",
                                row.left_no.unwrap_or(0),
                                row.left.as_deref().unwrap_or_default()
                            ),
                        );
                    }
                    RowKind::Removed | RowKind::Changed => {
                        let _ = std::fmt::write(
                            &mut out,
                            format_args!(
                                "- {} {}\n",
                                row.left_no.unwrap_or(0),
                                row.left.as_deref().unwrap_or_default()
                            ),
                        );
                        if row.kind == RowKind::Changed {
                            // A changed row is one line replaced by another, and a unified
                            // view that showed only the left side would hide the answer.
                            let _ = std::fmt::write(
                                &mut out,
                                format_args!(
                                    "+ {} {}\n",
                                    row.right_no.unwrap_or(0),
                                    row.right.as_deref().unwrap_or_default()
                                ),
                            );
                        }
                    }
                    RowKind::Added => {
                        let _ = std::fmt::write(
                            &mut out,
                            format_args!(
                                "+ {} {}\n",
                                row.right_no.unwrap_or(0),
                                row.right.as_deref().unwrap_or_default()
                            ),
                        );
                    }
                },
            }
        }
        out
    }

    /// Rows with long equal runs collapsed, `context` lines kept at each end.
    fn collapsed(&self, context: usize) -> Vec<Rendered> {
        let mut out: Vec<Rendered> = Vec::with_capacity(self.rows.len());
        let mut run: Vec<&DiffRow> = Vec::new();
        for row in &self.rows {
            if row.kind == RowKind::Equal {
                run.push(row);
                continue;
            }
            flush_run(&mut out, &mut run, context);
            out.push(Rendered::Row(row.clone()));
        }
        flush_run(&mut out, &mut run, context);
        out
    }
}

/// A rendered row, or the collapsed middle of an equal run.
enum Rendered {
    Row(DiffRow),
    Collapsed(u64),
}

/// Close a changed block: print its annotation, if the annotator had one.
fn finish(out: &mut String, block: &mut Change, annotate: &dyn Fn(&Change) -> Option<String>) {
    if block.left.is_empty() && block.right.is_empty() {
        return;
    }
    if let Some(note) = annotate(block) {
        let _ = std::fmt::write(out, format_args!("    {note}\n"));
    }
    block.left.clear();
    block.right.clear();
}

fn flush_run(out: &mut Vec<Rendered>, run: &mut Vec<&DiffRow>, context: usize) {
    if run.is_empty() {
        return;
    }
    if run.len() <= context.saturating_mul(2).saturating_add(1) {
        out.extend(run.drain(..).map(|row| Rendered::Row(row.clone())));
        return;
    }
    for row in run.drain(..context) {
        out.push(Rendered::Row(row.clone()));
    }
    // Whatever is left is the middle; the tail keeps `context` lines.
    let tail = run.len().saturating_sub(context);
    out.push(Rendered::Collapsed(tail as u64));
    for row in run.drain(tail..) {
        out.push(Rendered::Row(row.clone()));
    }
}

/// Shorten a line to `width` display columns without wrapping it.
fn clip(text: &str, width: usize) -> String {
    let text = sanitize(text);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text;
    }
    let mut out: String = chars.iter().take(width.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// Control characters and tabs made visible: a side-by-side diff whose columns are
/// broken by a `\r` is not side by side any more.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect()
}

/// Diff two texts line by line.
///
/// Alignment is the longest common subsequence, which is what makes the output mean
/// something: a naive positional compare calls every line after an insertion different.
pub fn diff_text(left: &str, right: &str) -> TextDiff {
    let (left_lines, left_newline) = lines_of(left);
    let (right_lines, right_newline) = lines_of(right);
    let (rows, approximate) = diff_lines(&left_lines, &right_lines);
    TextDiff {
        rows,
        left_lines: left_lines.len() as u64,
        right_lines: right_lines.len() as u64,
        left_newline,
        right_newline,
        approximate,
    }
}

/// Split into lines, and say whether the text ended with a newline.
fn lines_of(text: &str) -> (Vec<&str>, bool) {
    if text.is_empty() {
        return (Vec::new(), false);
    }
    let newline = text.ends_with('\n');
    let body = if newline {
        &text[..text.len() - 1]
    } else {
        text
    };
    (body.split('\n').collect(), newline)
}

/// The LCS diff, with prefix/suffix trimming and a size guard.
fn diff_lines<'a>(left: &[&'a str], right: &[&'a str]) -> (Vec<DiffRow>, bool) {
    let mut approximate = false;
    // The shared head and tail are cut first: two build logs almost always agree at both
    // ends, and that turns "diff two 5 000-line logs that differ in one line" into a
    // handful of cells instead of twenty-five million.
    let mut head = 0usize;
    while head < left.len() && head < right.len() && left[head] == right[head] {
        head += 1;
    }
    let mut tail = 0usize;
    while tail + head < left.len()
        && tail + head < right.len()
        && left[left.len() - 1 - tail] == right[right.len() - 1 - tail]
    {
        tail += 1;
    }
    let mid_left = &left[head..left.len() - tail];
    let mid_right = &right[head..right.len() - tail];
    let mut middle: Vec<DiffRow> = Vec::new();
    if mid_left.len() as u64 * mid_right.len() as u64 > MAX_DIFF_CELLS as u64
        || mid_left.len() > MAX_DIFF_LINES
        || mid_right.len() > MAX_DIFF_LINES
    {
        // Too big to align. Report the block, and say the alignment is not exact.
        approximate = true;
        middle.extend(pair(mid_left, mid_right, head as u64 + 1));
    } else {
        middle.extend(lcs_rows(mid_left, mid_right, head as u64 + 1));
    }

    let mut rows: Vec<DiffRow> = Vec::with_capacity(left.len() + right.len());
    for index in 0..head {
        rows.push(DiffRow {
            kind: RowKind::Equal,
            left_no: Some(index as u64 + 1),
            left: Some(left[index].to_string()),
            right_no: Some(index as u64 + 1),
            right: Some(right[index].to_string()),
        });
    }
    rows.append(&mut middle);
    for offset in 0..tail {
        let index = left.len() - tail + offset;
        rows.push(DiffRow {
            kind: RowKind::Equal,
            left_no: Some(index as u64 + 1),
            left: Some(left[index].to_string()),
            right_no: Some((right.len() - tail + offset) as u64 + 1),
            right: Some(right[right.len() - tail + offset].to_string()),
        });
    }
    (rows, approximate)
}

/// The exact LCS table over two middles, turned into rows starting at line `first`.
fn lcs_rows<'a>(left: &[&'a str], right: &[&'a str], first: u64) -> Vec<DiffRow> {
    // `table[i][j]` = LCS length of the suffixes left[i..] and right[j..].
    let mut table = vec![vec![0u32; right.len() + 1]; left.len() + 1];
    for i in (0..left.len()).rev() {
        for j in (0..right.len()).rev() {
            table[i][j] = if left[i] == right[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    let mut ops: Vec<(usize, usize)> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            ops.push((i, j));
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            ops.push((i, usize::MAX));
            i += 1;
        } else {
            ops.push((usize::MAX, j));
            j += 1;
        }
    }
    while i < left.len() {
        ops.push((i, usize::MAX));
        i += 1;
    }
    while j < right.len() {
        ops.push((usize::MAX, j));
        j += 1;
    }
    let mut rows = Vec::with_capacity(ops.len());
    let mut removed: Vec<(u64, String)> = Vec::new();
    let mut added: Vec<(u64, String)> = Vec::new();
    for (l, r) in ops {
        if l == usize::MAX {
            added.push((first + r as u64, right[r].to_string()));
            continue;
        }
        if r == usize::MAX {
            removed.push((first + l as u64, left[l].to_string()));
            continue;
        }
        drain(&mut removed, &mut added, &mut rows);
        rows.push(DiffRow {
            kind: RowKind::Equal,
            left_no: Some(first + l as u64),
            left: Some(left[l].to_string()),
            right_no: Some(first + r as u64),
            right: Some(right[r].to_string()),
        });
    }
    drain(&mut removed, &mut added, &mut rows);
    rows
}

/// Turn a run of removed lines and a run of added lines into paired rows.
///
/// Pairing is what makes the view readable: a removal next to its addition is one
/// changed line, and a wall of `<` followed by a wall of `>` says nothing about which
/// line went where.
fn drain(
    removed: &mut Vec<(u64, String)>,
    added: &mut Vec<(u64, String)>,
    rows: &mut Vec<DiffRow>,
) {
    let (left, right) = (std::mem::take(removed), std::mem::take(added));
    rows.extend(pair_owned(left, right));
}

/// Pair two runs of lines into rows, starting from whatever is left over.
fn pair_owned(left: Vec<(u64, String)>, right: Vec<(u64, String)>) -> Vec<DiffRow> {
    let mut rows = Vec::with_capacity(left.len().max(right.len()));
    for index in 0..left.len().max(right.len()) {
        let l = left.get(index).cloned();
        let r = right.get(index).cloned();
        let kind = match (&l, &r) {
            (Some(_), Some(_)) => RowKind::Changed,
            (Some(_), None) => RowKind::Removed,
            (None, Some(_)) => RowKind::Added,
            (None, None) => unreachable!("the loop stops at the longer side"),
        };
        rows.push(DiffRow {
            kind,
            left_no: l.as_ref().map(|(no, _)| *no),
            left: l.map(|(_, text)| text),
            right_no: r.as_ref().map(|(no, _)| *no),
            right: r.map(|(_, text)| text),
        });
    }
    rows
}

/// The approximate path: two middles reported as one changed block.
fn pair<'a>(left: &[&'a str], right: &[&'a str], first: u64) -> Vec<DiffRow> {
    pair_owned(
        left.iter()
            .enumerate()
            .map(|(index, text)| (first + index as u64, text.to_string()))
            .collect(),
        right
            .iter()
            .enumerate()
            .map(|(index, text)| (first + index as u64, text.to_string()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_text_is_not_changed() {
        let diff = diff_text("a\nb\n", "a\nb\n");
        assert!(!diff.changed());
        assert_eq!(diff.stats().equal, 2);
        assert_eq!(diff.stats().changes, 0);
    }

    #[test]
    fn one_changed_line_is_one_change() {
        let diff = diff_text("a\nb\nc\n", "a\nB\nc\n");
        assert!(diff.changed());
        let changes = diff.changes();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].left_text(), "b");
        assert_eq!(changes[0].right_text(), "B");
        assert_eq!(diff.stats().changes, 1);
    }

    /// The reason the alignment is an LCS and not a positional zip: one inserted line in
    /// the middle of a log must not make every later line look different.
    #[test]
    fn an_insertion_moves_the_rest_rather_than_changing_it() {
        let left = "one\ntwo\nthree\nfour\n";
        let right = "one\ninsert\ntwo\nthree\nfour\n";
        let diff = diff_text(left, right);
        assert_eq!(diff.changes().len(), 1);
        assert_eq!(diff.stats().added, 1);
        assert_eq!(diff.stats().removed, 0);
        assert_eq!(diff.stats().equal, 4);
    }

    #[test]
    fn a_removal_and_an_addition_apart_are_two_changes() {
        let diff = diff_text("a\nb\nc\nd\n", "a\nc\nd\nx\n");
        assert_eq!(diff.changes().len(), 2);
        assert_eq!(diff.stats().removed, 1);
        assert_eq!(diff.stats().added, 1);
        assert_eq!(diff.stats().equal, 3);
    }

    #[test]
    fn a_missing_final_newline_is_a_difference() {
        let diff = diff_text("a\n", "a");
        assert!(diff.changed());
        assert!(!diff.rows().iter().any(|row| row.kind.is_change()));
        assert!(diff.left_newline);
        assert!(!diff.right_newline);
    }

    #[test]
    fn empty_sides_are_empty_rather_than_one_blank_line() {
        assert_eq!(diff_text("", "").left_lines, 0);
        assert!(!diff_text("", "").changed());
        let diff = diff_text("", "x\n");
        assert_eq!(diff.changes().len(), 1);
        assert_eq!(diff.stats().added, 1);
    }

    #[test]
    fn a_change_survives_normalisation_only_when_normalisation_cannot_erase_it() {
        let profile = Profile::standard();
        // A duration: machine noise, and the profile turns both sides into `<dur>`.
        let noise = Change {
            left: vec![(1, "Finished in 12.5s".to_string())],
            right: vec![(1, "Finished in 4.1s".to_string())],
        };
        assert!(!noise.survives_normalisation(&profile));
        // A test that did not pass: no rule touches it.
        let real = Change {
            left: vec![(1, "test result: ok. 42 passed".to_string())],
            right: vec![(1, "test result: FAILED. 41 passed".to_string())],
        };
        assert!(real.survives_normalisation(&profile));
    }

    #[test]
    fn side_by_side_puts_both_sides_on_the_row_and_collapses_the_middle() {
        let left = "head\n".to_string() + &"same\n".repeat(40) + "left only\n";
        let right = "head\n".to_string() + &"same\n".repeat(40) + "right only\n";
        let rendered = diff_text(&left, &right).side_by_side(80, 1);
        assert!(rendered.contains("head"));
        assert!(rendered.contains("left only"));
        assert!(rendered.contains("right only"));
        assert!(rendered.contains("unchanged line(s)"));
        // Every rendered line stays inside the width it was given.
        for line in rendered.lines() {
            assert!(line.chars().count() <= 80, "over-wide line: {line:?}");
        }
    }

    #[test]
    fn an_annotated_view_says_what_the_profile_cannot_erase() {
        let profile = Profile::standard();
        // Two differences, far enough apart that the context cannot fold them into one
        // hunk: a duration, which the profile erases, and a test result, which it must not.
        let left = "cargo build\nFinished in 12.5s\nstep one\nstep two\nstep three\n\
                    test result: ok. 42 passed\n";
        let right = "cargo build\nFinished in 4.1s\nstep one\nstep two\nstep three\n\
                     test result: FAILED. 41 passed\n";
        let rendered = diff_text(left, right).side_by_side_annotated(90, 1, &|change| {
            Some(if change.survives_normalisation(&profile) {
                "survives".to_string()
            } else {
                "noise".to_string()
            })
        });
        assert_eq!(
            rendered.matches("noise").count(),
            1,
            "exactly the duration hunk is machine noise: {rendered}"
        );
        assert_eq!(
            rendered.matches("survives").count(),
            1,
            "exactly the test-result hunk is a build fact: {rendered}"
        );
        // …and the unannotated view prints the same rows and no notes.
        let plain = diff_text(left, right).side_by_side(90, 1);
        assert!(!plain.contains("noise"));
        assert!(plain.contains("Finished in 12.5s"));
    }

    /// A hunk that mixes machine noise with a real difference **is** a real difference.
    /// The report counts hunks, so counting a mixed one as noise would be counting away
    /// the line that matters — and the honest alternative, calling it both, would let a
    /// single duration excuse a FAILED.
    #[test]
    fn a_hunk_that_mixes_both_kinds_is_a_difference() {
        let profile = Profile::standard();
        let mixed = diff_text(
            "Finished in 12.5s\ntest result: ok. 42 passed\n",
            "Finished in 4.1s\ntest result: FAILED. 41 passed\n",
        )
        .changes()
        .remove(0);
        assert!(mixed.survives_normalisation(&profile));
        // The same profile does erase that duration on its own — which is the whole point
        // of `does not survive normalisation` being a statement about a hunk and not
        // about a line.
        let noise = diff_text("Finished in 12.5s\n", "Finished in 4.1s\n")
            .changes()
            .remove(0);
        assert!(!noise.survives_normalisation(&profile));
    }

    #[test]
    fn control_characters_cannot_break_the_columns() {
        let diff = diff_text("a\rmost\tb\n", "a\n");
        let rendered = diff.side_by_side(60, 1);
        assert!(!rendered.contains('\t'));
        assert!(!rendered.contains('\r'));
    }

    /// A log with a long shared head and tail is the common case, and trimming makes it
    /// cheap: the guard is only ever reached by the middle.
    #[test]
    fn a_large_log_with_a_small_middle_is_still_exact() {
        let shared: String = (0..3_000).map(|i| format!("line {i}\n")).collect();
        let left = format!("{shared}one version\n");
        let right = format!("{shared}another\n");
        let diff = diff_text(&left, &right);
        assert!(!diff.approximate);
        assert_eq!(diff.changes().len(), 1);
        assert_eq!(diff.stats().equal, 3_000);
    }

    #[test]
    fn a_huge_middle_is_reported_as_approximate_instead_of_hanging() {
        let left: String = (0..20_001).map(|i| format!("l{i}\n")).collect();
        let right: String = (0..20_001).map(|i| format!("r{i}\n")).collect();
        let diff = diff_text(&left, &right);
        assert!(diff.approximate);
        assert!(diff.changed());
        assert!(
            diff.unified(1).contains("approximate")
                || diff.side_by_side(80, 1).contains("approximate")
        );
    }

    #[test]
    fn unified_collapses_a_long_equal_run() {
        let left = "a\n".to_string() + &"same\n".repeat(30) + "b\n";
        let right = "a\n".to_string() + &"same\n".repeat(30) + "c\n";
        let rendered = diff_text(&left, &right).unified(1);
        assert!(rendered.contains("same"));
        assert!(rendered.contains('\u{22ee}'));
        assert!(rendered.contains("- 32 b"));
        assert!(rendered.contains("+ 32 c"));
    }
}

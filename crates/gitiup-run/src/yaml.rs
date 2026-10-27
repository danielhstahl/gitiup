//! A subset reader for the YAML a workflow file is made of.
//!
//! # Why this exists instead of a library
//!
//! `gitiup` plans runs, so it has to read what `.github/workflows/*.yml` says. A
//! full YAML 1.2 implementation is a large, subtle thing — anchors, merge keys,
//! tags, multi-document streams, the YAML 1.1 boolean zoo — and none of it makes a
//! better plan. What matters for provenance is the opposite of guessing: a
//! construct this reader does not understand is **refused, with the line it gave up
//! on**, not quietly dropped, because a dropped `if:` changes which steps run and
//! therefore what the attestation claims.
//!
//! So the rule for every function here is: parse the shapes workflows actually
//! use, and return an [`Error`] (line number and hint included) for anything else.
//!
//! # Accepted
//!
//! | shape | example |
//!|-------|---------|
//!| block mappings | `jobs:` then indented `build:` |
//!| block sequences, incl. `- key: value` | `- name: Test` |
//!| flow collections on one line | `branches: [main, release]` |
//!| single/double quoted scalars | `runs-on: "ubuntu-24.04"` |
//!| block scalars, clipped, folded, kept | `run: \|` … |
//!| comments and blank lines | `# note` |
//!| one leading `---` | a document marker, not a stream |
//!
//! Keys are kept as written: `on:` stays the key `on`. Nothing here applies YAML 1.1
//! truthiness, which would turn that key into `true` and lose the trigger list — and
//! a trigger list is not something to lose quietly.
//!
//! # Refused, by name
//!
//! Tabs used for indentation, anchors (`&a`), aliases (`*a`), tags (`!!str`), merge
//! keys (`<<:`), explicit complex keys (`? a : b`), flow collections spanning lines,
//! a second document, unterminated quotes, duplicate keys, and content the indent
//! does not account for.
//!
//! ```
//! use gitiup_run::yaml::{Mapping, Yaml, parse};
//!
//! let doc = parse("name: CI\non:\n  push:\n    branches: [main]\n").unwrap();
//! let map = doc.as_map().unwrap();
//! assert_eq!(map.get("name").and_then(Yaml::as_str), Some("CI"));
//! let on = map.get("on").unwrap().as_map().unwrap();
//! let push = on.get("push").unwrap().as_map().unwrap();
//! let branches = push.get("branches").unwrap().as_seq().unwrap();
//! assert_eq!(branches[0].as_str(), Some("main"));
//!
//! // What is not understood is refused, with the line that caused it.
//! let err = parse("jobs:\n  a:\n    steps: *shared\n").unwrap_err();
//! assert!(err.detail().contains("line 3"), "{err}");
//! assert!(err.detail().contains("alias"), "{err}");
//!
//! // Block scalars keep their newlines: a `run:` body is a script, not a line.
//! let doc = parse("steps:\n  - run: |\n      make a\n      make b\n").unwrap();
//! let steps = doc.as_map().unwrap().get("steps").unwrap().as_seq().unwrap();
//! let step = steps[0].as_map().unwrap();
//! assert_eq!(step.get("run").unwrap().as_str(), Some("make a\nmake b\n"));
//! let _ = Mapping::default;
//! ```

use gitiup_attest::{Error, ErrorKind, Result};

/// A parsed YAML value: the three shapes a workflow needs.
///
/// Scalars stay text, because what decides a scalar's type is what the field means
/// (`matrix.os` is a list, `inputs.jobs` is a number, `if` is an expression) and
/// that is the workflow layer's business, not the reader's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Yaml {
    /// A mapping, in document order, with the lookup helpers on [`Mapping`].
    Map(Mapping),
    /// A sequence.
    Seq(Vec<Yaml>),
    /// A scalar: plain, quoted or block. An empty value is `""`, never "absent" —
    /// `foo:` and no `foo` at all are different statements.
    Scalar(String),
}

/// A mapping that keeps document order and answers lookups by key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mapping {
    /// The entries, in the order they appeared.
    pub entries: Vec<(String, Yaml)>,
}

impl Mapping {
    /// The value under `key`, if present.
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// The scalar under `key`, as text.
    pub fn str_field(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Yaml::as_str)
    }

    /// The nested mapping under `key`.
    pub fn map_field(&self, key: &str) -> Option<&Mapping> {
        self.get(key).and_then(Yaml::as_map)
    }

    /// The sequence under `key`.
    pub fn seq_field(&self, key: &str) -> Option<&[Yaml]> {
        self.get(key).and_then(Yaml::as_seq)
    }

    /// Keys not in `known` — advice, not an error: workflow syntax grows faster
    /// than this reader, and an unrecognised *key* must not stop a plan the way an
    /// unrecognised *shape* must.
    pub fn unknown_keys(&self, known: &[&str]) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(name, _)| !known.contains(&name.as_str()))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

impl Yaml {
    /// The scalar text, or `None` for a collection.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Scalar(text) => Some(text),
            _ => None,
        }
    }

    /// The mapping, or `None`.
    pub fn as_map(&self) -> Option<&Mapping> {
        match self {
            Yaml::Map(map) => Some(map),
            _ => None,
        }
    }

    /// The sequence, or `None`.
    pub fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::Seq(items) => Some(items),
            _ => None,
        }
    }

    /// True for the empty scalar: how YAML writes "present, no value".
    pub fn is_empty_scalar(&self) -> bool {
        matches!(self, Yaml::Scalar(text) if text.is_empty())
    }

    /// One string or a list of them (`on: push` and `branches: [main]` are both
    /// single-element lists here).
    pub fn as_str_list(&self) -> Option<Vec<String>> {
        match self {
            Yaml::Seq(items) => items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect(),
            Yaml::Scalar(text) if !text.is_empty() => Some(vec![text.clone()]),
            _ => None,
        }
    }
}

/// One input line: indentation, text with the indent removed, and the 1-based
/// number to report in errors.
#[derive(Debug, Clone)]
struct Line<'a> {
    indent: usize,
    text: &'a str,
    number: usize,
    /// Blank or comment-only: skipped by the block parser, but *kept in the file*,
    /// because a `run:` script body contains both and dropping them would silently
    /// change the script that gets executed.
    trivia: bool,
}

/// The parser's cursor over the lines of the file.
struct Reader<'a> {
    lines: Vec<Line<'a>>,
    at: usize,
}

/// A parse failure that names the line, phrased as an attestation error so callers
/// need no translation layer (and get ADR-0001's exit code for free).
pub fn error(line: Option<usize>, what: impl Into<String>, hint: impl Into<String>) -> Error {
    let where_ = match line {
        Some(number) => format!("line {number}: "),
        None => String::new(),
    };
    Error::new(
        ErrorKind::Invalid,
        "workflow",
        format!("{where_}{}", what.into()),
    )
    .with_hint(hint.into())
}

/// Parse a workflow-sized YAML document.
///
/// An empty file is an error rather than an empty map: there is no plan in an empty
/// file, and saying so now beats a job that quietly does nothing in three days.
pub fn parse(text: &str) -> Result<Yaml> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines: Vec<Line> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = raw.trim_end();
        let indent = trimmed.len() - trimmed.trim_start().len();
        let content = trimmed.trim_start();
        if trimmed[..indent].contains('\t') {
            return Err(error(
                Some(number),
                "a tab was used for indentation",
                "YAML indentation is spaces only",
            ));
        }
        lines.push(Line {
            indent,
            text: content,
            number,
            trivia: content.is_empty() || content.starts_with('#'),
        });
    }
    if lines
        .first()
        .is_some_and(|line| line.indent == 0 && line.text == "---")
    {
        lines.remove(0);
    }
    if lines
        .iter()
        .any(|line| line.indent == 0 && line.text == "---")
    {
        return Err(error(
            None,
            "more than one document (`---` separator)",
            "a workflow file is one document",
        ));
    }
    let mut reader = Reader { lines, at: 0 };
    reader.skip_trivia();
    if reader.at >= reader.lines.len() {
        return Err(error(
            None,
            "the document is empty",
            "a workflow has at least `on:` and `jobs:`",
        ));
    }
    if reader.lines[reader.at].indent != 0 {
        let number = reader.lines[reader.at].number;
        return Err(error(
            Some(number),
            "the first content line is indented",
            "top-level keys start at column 1",
        ));
    }
    let value = reader.node(0)?;
    reader.skip_trivia();
    if let Some(line) = reader.lines.get(reader.at) {
        return Err(error(
            Some(line.number),
            format!("unexpected content `{}`", line.text),
            "check the indentation of the block this line belongs to",
        ));
    }
    Ok(value)
}

impl<'a> Reader<'a> {
    fn peek(&mut self) -> Option<&Line<'a>> {
        self.skip_trivia();
        self.lines.get(self.at)
    }

    /// Move past blank and comment lines (which are not trivia inside a block
    /// scalar, because there they are the script).
    fn skip_trivia(&mut self) {
        while self.lines.get(self.at).is_some_and(|line| line.trivia) {
            self.at += 1;
        }
    }

    /// Parse the node at the cursor, which starts a block at or below `indent`.
    fn node(&mut self, indent: usize) -> Result<Yaml> {
        let Some(line) = self.peek() else {
            return Ok(Yaml::Scalar(String::new()));
        };
        let line_indent = line.indent;
        if line_indent < indent {
            return Ok(Yaml::Scalar(String::new()));
        }
        let number = line.number;
        let text = line.text;
        if is_seq_entry(text) {
            return self.sequence(line_indent);
        }
        if key_of(text).is_some() {
            return self.mapping(line_indent, line_indent);
        }
        // A bare scalar node where a block was expected: one line, then stop.
        self.at += 1;
        check_value_prefix(text, number)?;
        scalar_value(text, number).map(|(value, _)| value)
    }

    /// `- ` entries, including the `- key: value` form a step list is made of.
    fn sequence(&mut self, indent: usize) -> Result<Yaml> {
        let mut items = Vec::new();
        while let Some(line) = self.peek() {
            if line.indent != indent || !is_seq_entry(line.text) {
                break;
            }
            let (number, text) = (line.number, line.text);
            let after = text[1..].trim_start();
            let offset = indent + (text.len() - after.len());
            if after.is_empty() {
                self.at += 1;
                items.push(self.node(indent + 1)?);
                continue;
            }
            // Re-read the entry with the dash removed: `- name: Test` becomes the
            // mapping `name: Test`, whose keys start at the column after the dash —
            // which is where the entry's other keys already are.
            self.lines[self.at] = Line {
                indent: offset,
                text: after,
                number,
                trivia: false,
            };
            items.push(self.entry_node(offset, indent)?);
        }
        Ok(Yaml::Seq(items))
    }

    /// The node after a `- `: a mapping entry, a nested sequence, or a scalar.
    ///
    /// `dash` is the column of the `-` itself, which is what a block scalar in this
    /// entry is allowed to be indented against — GitHub's step convention writes
    ///
    /// ```yaml
    /// - name: Run
    ///   run: |
    ///     make
    /// ```
    ///
    /// with the script level with the key, so comparing it to the key column (6 here)
    /// would end the script before it started.
    fn entry_node(&mut self, indent: usize, dash: usize) -> Result<Yaml> {
        let Some(line) = self.peek() else {
            return Ok(Yaml::Scalar(String::new()));
        };
        let (line_indent, number, text) = (line.indent, line.number, line.text);
        if line_indent != indent {
            return self.node(indent);
        }
        check_value_prefix(text, number)?;
        if is_seq_entry(text) {
            return self.sequence(indent);
        }
        if key_of(text).is_some() {
            return self.mapping(indent, dash);
        }
        self.at += 1;
        scalar_value(text, number).map(|(value, _)| value)
    }

    /// A block mapping at `indent`. `scalar_parent` is the indentation a block
    /// scalar under this mapping must exceed to belong to it — the mapping's own
    /// column normally, the enclosing `-`'s column inside a compact entry.
    fn mapping(&mut self, indent: usize, scalar_parent: usize) -> Result<Yaml> {
        let mut entries: Vec<(String, Yaml)> = Vec::new();
        while let Some(line) = self.peek() {
            if line.indent != indent {
                break;
            }
            // Copied out so the rest of the body may move `self`'s cursor.
            let (number, text) = (line.number, line.text);
            let Some((key, rest)) = key_of(text) else {
                // Not a key: it belongs to whoever asked for this block, or it is
                // stray content that the caller reports.
                break;
            };
            self.at += 1;
            check_value_prefix(rest, number)?;
            let value = if let Some((fold, keep)) = block_indicator(rest) {
                self.block_scalar(scalar_parent, indent, fold, keep)?
            } else if rest.is_empty() {
                match self.peek() {
                    Some(next) if next.indent > indent => {
                        let child_indent = next.indent;
                        self.node(child_indent)?
                    }
                    _ => Yaml::Scalar(String::new()),
                }
            } else {
                let (value, trailing) = scalar_value(rest, number)?;
                if !trailing.is_empty() {
                    return Err(error(
                        Some(number),
                        format!("unexpected `{trailing}` after `{key}`"),
                        "quote the value if it contains a `#`",
                    ));
                }
                value
            };
            if key.starts_with('?') || key == "<<" {
                return Err(error(
                    Some(number),
                    format!("`{key}` is a YAML feature this reader does not support"),
                    "use plain `key: value` mapping keys",
                ));
            }
            if entries.iter().any(|(existing, _)| existing == &key) {
                return Err(error(
                    Some(number),
                    format!("duplicate key `{key}`"),
                    "a duplicate key silently replaces the first one; keep one",
                ));
            }
            entries.push((key, value));
        }
        Ok(Yaml::Map(Mapping { entries }))
    }

    /// Gather the indented body of a `|` or `>` block scalar, blank lines and
    /// `#` lines included: inside a block scalar the trivia *is* the script.
    ///
    /// Two bounds, because workflows are written both ways and a script that got cut
    /// off halfway is the failure mode worth preventing:
    ///
    /// * the body must be deeper than `floor` — the column of the block that owns it
    ///   (the `-` of a compact `- run: |` entry, otherwise the mapping's column);
    /// * a line at the *key* column that parses as `key:` ends it, so the next step
    ///   key (`env:` after a `run: |`) is never swallowed into the script.
    fn block_scalar(
        &mut self,
        floor: usize,
        key_indent: usize,
        fold: bool,
        keep: char,
    ) -> Result<Yaml> {
        let mut body: Vec<String> = Vec::new();
        let mut block_indent: Option<usize> = None;
        while let Some(line) = self.lines.get(self.at) {
            if line.text.is_empty() {
                // A blank line carries no indentation of its own, so it belongs to
                // the block only if the block continues after it; otherwise the
                // block has ended and the file carries on.
                let mut probe = self.at + 1;
                while self
                    .lines
                    .get(probe)
                    .is_some_and(|later| later.text.is_empty())
                {
                    probe += 1;
                }
                match self.lines.get(probe) {
                    Some(next)
                        if next.indent > floor
                            && !(next.indent <= key_indent && key_of(next.text).is_some()) =>
                    {
                        body.push(String::new());
                        self.at += 1;
                        continue;
                    }
                    _ => break,
                }
            }
            if line.indent <= floor || (line.indent <= key_indent && key_of(line.text).is_some()) {
                break;
            }
            let indent = *block_indent.get_or_insert(line.indent);
            body.push(" ".repeat(line.indent.saturating_sub(indent)) + line.text);
            self.at += 1;
        }
        let mut text = if fold {
            // `>` folds newlines between non-empty lines into spaces. Not
            // pretty-printing: the folded text is what the script would otherwise
            // have to quote.
            let mut folded = String::new();
            for (index, line) in body.iter().enumerate() {
                if index > 0 {
                    folded.push(if line.is_empty() || body[index - 1].is_empty() {
                        '\n'
                    } else {
                        ' '
                    });
                }
                folded.push_str(line);
            }
            folded
        } else {
            body.join("\n")
        };
        if keep != '-' {
            text.push('\n');
        }
        Ok(Yaml::Scalar(text))
    }
}

/// Is this line a sequence entry (`-` or `- …`)?
fn is_seq_entry(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

/// Split `key: value`, honouring quotes, and spotting `?`/`<<` so they can be
/// refused by name rather than mis-parsed.
fn key_of(text: &str) -> Option<(String, &str)> {
    if text.starts_with("? ") || text.starts_with("<<") {
        let (key, rest) = match text.find(':') {
            Some(index) => (text[..index].trim_end(), text[index + 1..].trim_start()),
            None => (text, ""),
        };
        return Some((key.to_string(), rest));
    }
    let bytes = text.as_bytes();
    if matches!(bytes.first(), Some(b'"') | Some(b'\'')) {
        let quote = bytes[0] as char;
        let end = find_quote(text, 1, quote)?;
        let inner = &text[1..end];
        let after = text[end + 1..].trim_start();
        return after
            .strip_prefix(':')
            .map(|rest| (unquote(inner, quote), rest.trim_start()));
    }
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] as char {
            ':' => {
                let after = &text[index + 1..];
                if after.is_empty() || after.starts_with([' ', '\t']) {
                    let key = text[..index].trim_end();
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key.to_string(), after.trim_start()));
                }
            }
            '#' if index > 0 && matches!(bytes[index - 1] as char, ' ' | '\t') => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

/// The index of the closing `quote`, starting after the opening one.
fn find_quote(text: &str, from: usize, quote: char) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = from;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if quote == '"' && ch == '\\' {
            index += 2;
            continue;
        }
        if ch == quote {
            if quote == '\'' && bytes.get(index + 1) == Some(&b'\'') {
                index += 2;
                continue;
            }
            return Some(index);
        }
        index += 1;
    }
    None
}

fn unquote(text: &str, quote: char) -> String {
    match quote {
        '\'' => text.replace("''", "'"),
        _ => unescape_double(text).unwrap_or_else(|_| text.to_string()),
    }
}

/// `|`, `|-`, `>`, `>+` … as `(fold?, chomping)`.
fn block_indicator(text: &str) -> Option<(bool, char)> {
    let mut chars = text.chars();
    let first = chars.next()?;
    if first != '|' && first != '>' {
        return None;
    }
    let rest: String = chars.collect();
    let trimmed = rest.trim_end();
    if trimmed
        .chars()
        .any(|c| !(c.is_ascii_digit() || c == '-' || c == '+'))
    {
        return None;
    }
    let keep = if trimmed.ends_with('-') {
        '-'
    } else if trimmed.ends_with('+') {
        '+'
    } else {
        ' '
    };
    Some((first == '>', keep))
}

/// Refuse, by name, the YAML features that appear where a value should be.
fn check_value_prefix(text: &str, line: usize) -> Result<()> {
    let Some(first) = text.chars().next() else {
        return Ok(());
    };
    match first {
        '&' => Err(error(
            Some(line),
            "an anchor (`&…`) is not supported",
            "duplicate the block instead of anchoring it",
        )),
        '*' => Err(error(
            Some(line),
            "an alias (`*…`) is not supported",
            "duplicate the block instead of aliasing it",
        )),
        '!' => Err(error(
            Some(line),
            format!("a tag (`{text}`) is not supported"),
            "scalars are read as text",
        )),
        '%' => Err(error(
            Some(line),
            "a directive is not supported here",
            "`%YAML` belongs at the top of a document",
        )),
        _ => Ok(()),
    }
}

/// Parse a one-line value: flow collection, quoted or plain scalar.
///
/// Returns the value plus trailing text a caller must reject (an unquoted `#`
/// comment tail is content the parser cannot account for).
fn scalar_value(text: &str, line: usize) -> Result<(Yaml, String)> {
    let text = text.trim();
    if text.starts_with('[') || text.starts_with('{') {
        let open = text.chars().next().expect("checked above");
        let close = if open == '[' { ']' } else { '}' };
        if !text.ends_with(close) {
            return Err(error(
                Some(line),
                "a flow collection spans more than one line",
                "put `[…]` / `{…}` on one line, or use a block layout",
            ));
        }
        let body = &text[1..text.len() - 1];
        return Ok((parse_flow(body, open == '{', line)?, String::new()));
    }
    if matches!(text.as_bytes().first(), Some(b'"') | Some(b'\'')) {
        let quote = text.as_bytes()[0] as char;
        let Some(end) = find_quote(text, 1, quote) else {
            return Err(error(
                Some(line),
                format!(
                    "an unterminated {}-quoted string",
                    if quote == '"' { "double" } else { "single" }
                ),
                "close the quote (write '' for a quote inside a single-quoted scalar)",
            ));
        };
        if quote == '"' {
            unescape_double(&text[1..end])
                .map_err(|why| error(Some(line), why, "fix the escape"))?;
        }
        let value = unquote(&text[1..end], quote);
        return Ok((Yaml::Scalar(value), text[end + 1..].trim().to_string()));
    }
    // A ` #` inside a plain scalar is a comment, not content and not an error:
    // `timeout-minutes: 10 # generous` is a normal line in a real workflow.
    let (value, _comment) = split_plain(text);
    Ok((Yaml::Scalar(value.to_string()), String::new()))
}

/// Where a plain scalar ends and a comment begins (` #` starts a comment).
fn split_plain(text: &str) -> (&str, &str) {
    let bytes = text.as_bytes();
    for index in 1..bytes.len() {
        if bytes[index] == b'#' && matches!(bytes[index - 1] as char, ' ' | '\t') {
            return (text[..index].trim_end(), &text[index..]);
        }
    }
    (text, "")
}

fn unescape_double(text: &str) -> std::result::Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('0') => out.push('\0'),
            Some(other) => return Err(format!("`\\{other}` is not an escape this reader knows")),
            None => return Err("a string ends with a backslash".to_string()),
        }
    }
    Ok(out)
}

/// `[a, b]` / `{a: b}` bodies, brackets already stripped, one line only.
fn parse_flow(body: &str, is_map: bool, line: usize) -> Result<Yaml> {
    let parts = split_flow(body)?;
    if is_map {
        let mut entries = Vec::new();
        for part in parts.iter().filter(|part| !part.is_empty()) {
            let Some((key, value)) = key_of(part) else {
                return Err(error(
                    Some(line),
                    format!("`{part}` inside `{{…}}` is not `key: value`"),
                    "flow mappings need `key: value` pairs",
                ));
            };
            let (value, _) = scalar_value(value, line)?;
            entries.push((key, value));
        }
        return Ok(Yaml::Map(Mapping { entries }));
    }
    let mut items = Vec::new();
    for part in parts.iter().filter(|part| !part.is_empty()) {
        let (value, _) = scalar_value(part, line)?;
        items.push(value);
    }
    Ok(Yaml::Seq(items))
}

/// Split a flow body on commas that are inside neither quotes nor brackets.
fn split_flow(body: &str) -> Result<Vec<&str>> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    let bytes = body.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        match quote {
            Some(mark) => {
                if mark == '"' && ch == '\\' {
                    index += 2;
                    continue;
                }
                if ch == mark {
                    quote = None;
                }
            }
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '[' | '{' => depth += 1,
                ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    parts.push(body[start..index].trim());
                    start = index + 1;
                }
                _ => {}
            },
        }
        index += 1;
    }
    if quote.is_some() || depth != 0 {
        return Err(error(
            None,
            "an unbalanced flow collection",
            "check `[`, `]`, `{`, `}` and the quotes inside them",
        ));
    }
    parts.push(body[start..].trim());
    Ok(parts)
}

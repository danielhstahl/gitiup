//! The terminal-shaped passes: line endings, escape sequences, progress churn.
//!
//! These run first, before anything looks for a value in the text, because the
//! bytes they remove are exactly the bytes that would confuse a value scanner: a
//! `\x1b[K` in the middle of `1.2s` and the duration is gone.

/// Split a stream into lines the way the pipeline wants them.
///
/// `LineEndings` means "LF, no trailing blanks, no tabs, no BOM, exactly one final
/// newline", which is easier to apply than to argue about if the split happens
/// here: CRLF becomes LF by dropping the `\r`, the BOM goes with the first
/// character, and the final newline is decided at assembly rather than kept from
/// the input, because "file ends with one newline" is a property of the file, not
/// of a line.
///
/// A lone `\r` is *not* a line ending: it is a terminal overwrite, and the ANSI
/// pass resolves it. Treating it as an ending would silently reorder a progress
/// bar into a poem.
pub(crate) fn split(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    // A trailing `\r` is *kept*: turning CRLF into LF is the `line-ending` rule's job,
    // not an invisible part of tokenising, so that a profile without that rule really
    // behaves differently.
    text.split('\n').map(str::to_string).collect()
}

/// Join them again. `ends_with_newline` is the canonical form: a non-empty stream
/// ends with exactly one LF.
pub(crate) fn join(lines: &[String]) -> String {
    if lines.is_empty() || (lines.len() == 1 && lines[0].is_empty()) {
        return String::new();
    }
    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// `LineEndings`: tabs to spaces, no trailing blanks.
///
/// Tabs become one space rather than a tab stop because a tab stop is a property
/// of the viewer, not of the log.
pub(crate) fn line_endings(line: &str) -> Option<String> {
    let mut out = String::with_capacity(line.len());
    let mut changed = false;
    for ch in line.chars() {
        match ch {
            '\t' => {
                out.push(' ');
                changed = true;
            }
            // Other control characters are the ANSI pass's business, except the
            // form feed and vertical tab, which are layout noise.
            '\u{0b}' | '\u{0c}' => changed = true,
            c => out.push(c),
        }
    }
    let trimmed = out.trim_end();
    if trimmed.len() != out.len() {
        changed = true;
    }
    if changed {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// `Ansi`: strip escape sequences, resolve carriage and backspace overwrites.
///
/// What a carriage return means is the interesting part. `foo\rbar` is not two
/// things, it is one line that a terminal shows as `bar` over `foo`, so the
/// reproducible text is *what the terminal showed*: the last non-empty segment.
/// Keeping both would put a machine's refresh rate into a digest — a progress bar
/// that redraws 60 times and one that redraws 3 times would never agree.
pub(crate) fn ansi(line: &str) -> Option<String> {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut changed = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\u{1b}' => {
                changed = true;
                skip_escape(&mut chars);
            }
            '\u{08}' => {
                // Backspace overwrites: `ab\b\bXY` shows `XY`.
                changed = true;
                out.pop();
            }
            '\r' => {
                if chars.peek().is_none() {
                    // A `CR` as the last character of a line is a line terminator
                    // (the CRLF pair), not a redraw: `line-ending` owns it, and this
                    // rule leaving it alone is what makes that rule load-bearing
                    // rather than cosmetic.
                    out.push('\r');
                    break;
                }
                // Resolve the whole carriage run at once: the text after the
                // last non-empty segment is what stays.
                let rest: String = chars.collect();
                let mut segments = vec![out.clone()];
                segments.extend(rest.split('\r').map(str::to_string));
                let winner = segments
                    .iter()
                    .rfind(|segment| !segment.is_empty())
                    .cloned()
                    .unwrap_or_default();
                return Some(strip_escapes(&winner));
            }
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                // Control bytes that survived the rules above are churn.
                changed = true;
            }
            c => out.push(c),
        }
    }
    if changed { Some(out) } else { None }
}

/// Consume one escape sequence after the `ESC`.
fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    match chars.next() {
        None => false,
        // CSI: parameters until a final byte in `@`..`~`.
        Some('[') => {
            for ch in chars.by_ref() {
                if ('@'..='~').contains(&ch) {
                    return true;
                }
            }
            false
        }
        // OSC / DC / SOS / PM / APC: terminated by BEL or ST (`ESC \`).
        Some(']') | Some('P') | Some('X') | Some('^') | Some('_') => {
            while let Some(ch) = chars.next() {
                if ch == '\u{7}' {
                    return true;
                }
                if ch == '\u{1b}' {
                    chars.next();
                    return true;
                }
            }
            false
        }
        // Two-character escapes (`ESC 7`, `ESC c`, …).
        Some(_) => true,
    }
}

/// Strip escape sequences without touching carriage (used after carriage
/// resolution, where the order of the two does not matter).
fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            skip_escape(&mut chars);
            continue;
        }
        out.push(ch);
    }
    out
}

/// The characters a progress bar is made of.
fn is_bar(ch: char) -> bool {
    matches!(
        ch,
        '#' | '=' | '*' | '█' | '▓' | '▒' | '░' | '-' | '>' | '.' | '_'
    )
}

/// `Progress`: drop a line that is only decoration.
///
/// A line made of bar characters, percentages and nothing alphabetic is a redraw
/// rather than output. This is a heuristic and is documented as one — the contract
/// asks workflows not to print progress at all (`CI=true`, `--no-progress`,
/// `--quiet`), and this rule is the net under that, not the wall.
pub(crate) fn progress(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.len() > 200 {
        return false;
    }
    let decoration = |c: char| {
        c.is_ascii_digit()
            || is_bar(c)
            || matches!(
                c,
                '[' | ']'
                    | '|'
                    | '/'
                    | '\\'
                    | '%'
                    | ' '
                    | ':'
                    | ','
                    | '<'
                    | '·'
                    | '•'
                    | '█'
                    | '▓'
                    | '▒'
                    | '░'
            )
    };
    if !trimmed.chars().all(decoration) {
        return false;
    }
    let bars = trimmed.chars().filter(|c| is_bar(*c)).count();
    let percent = trimmed.contains('%') && trimmed.chars().any(|c| c.is_ascii_digit());
    // A divider someone drew (`-----`, `=====`) is not a bar: it carries no more
    // information than a blank line, but dropping a line a human put there is
    // dropping content, and the difference between a bar and a divider is that a bar
    // is drawn from more than dash characters.
    let divider = trimmed
        .chars()
        .all(|c| c == '-' || c == '=' || c == ' ' || c == '_');
    // A spinner is a line of nothing but rotating glyphs. Rotating means at least two
    // different glyphs, for the same reason.
    let spinner = !divider
        && trimmed
            .chars()
            .all(|c| matches!(c, '|' | '/' | '-' | '\\' | ' '))
        && trimmed
            .chars()
            .filter(|c| matches!(c, '|' | '/' | '-' | '\\'))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            >= 2;
    (bars >= 5 && !divider) || percent || spinner
}

/// `Progress`: the bar behind a percentage.
///
/// `Progress [####------] 45%` and `Progress 45%` are one fact, so the bar goes
/// and the percentage stays for the `percent` rule to place-holder. Redraw counts
/// and bar widths are exactly the churn a refresh rate decides.
pub(crate) fn progress_bar(line: &str) -> Option<String> {
    if !line.contains('%') {
        return None;
    }
    let mut out = String::with_capacity(line.len());
    let mut run = String::new();
    for ch in line.chars() {
        if is_bar(ch) {
            run.push(ch);
            continue;
        }
        if run.chars().count() >= 5 && ch == ']' && out.ends_with('[') {
            // The bar filled its brackets: the brackets are part of the bar.
            out.pop();
            run.clear();
            continue;
        }
        flush_run(&mut out, &mut run);
        out.push(ch);
    }
    flush_run(&mut out, &mut run);
    let collapsed = collapse(&out);
    (collapsed != line).then_some(collapsed)
}

fn flush_run(out: &mut String, run: &mut String) {
    if !run.is_empty() {
        if run.chars().count() < 5 {
            out.push_str(run);
        }
        run.clear();
    }
}

/// Undo the whitespace a removed bar used to separate.
fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous_space = false;
    for ch in text.chars() {
        let space = ch == ' ';
        if space && previous_space {
            continue;
        }
        previous_space = space;
        out.push(ch);
    }
    let trimmed = out.trim_end();
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        split(text)
    }

    #[test]
    fn splitting_keeps_the_carriage_return_for_the_rule_that_owns_it() {
        assert_eq!(lines("a\r\nb\n"), ["a\r", "b", ""]);
        assert_eq!(lines("\u{feff}a\n"), ["a", ""]);
        assert_eq!(lines(""), [""]);
    }

    #[test]
    fn joining_canonicalises_the_final_newline() {
        assert_eq!(join(&[]), "");
        assert_eq!(join(&["".to_string()]), "");
        assert_eq!(join(&["a".to_string()]), "a\n");
        assert_eq!(join(&["a".to_string(), "b".to_string()]), "a\nb\n");
    }

    #[test]
    fn layout_noise_is_canonical_but_content_is_not_touched() {
        assert_eq!(line_endings("a\tb  ").as_deref(), Some("a b"));
        assert_eq!(line_endings("a\u{0c}b").as_deref(), Some("ab"));
        assert_eq!(line_endings("plain"), None);
        assert_eq!(line_endings(" leading kept"), None);
    }

    #[test]
    fn a_carriage_return_in_the_middle_is_a_redraw_and_the_last_one_wins() {
        assert_eq!(
            ansi("Downloading 12%\rDownloading 47%\rDownloading 100%").as_deref(),
            Some("Downloading 100%")
        );
        // An empty segment never wins: a redraw over nothing leaves the text shown.
        assert_eq!(ansi("abc\r\r\r").as_deref(), Some("abc"));
    }

    #[test]
    fn a_line_ending_carriage_is_left_for_the_line_ending_rule() {
        // If this rule ate it, `line-ending` would never be load-bearing.
        assert_eq!(ansi("text\r"), None);
        assert_eq!(ansi("\u{1b}[31mred\u{1b}[0m\r").as_deref(), Some("red\r"));
    }

    #[test]
    fn escapes_and_backspaces_resolve_to_what_was_shown() {
        assert_eq!(
            ansi("\u{1b}[1m\u{1b}[32mCompiling\u{1b}[0m x").as_deref(),
            Some("Compiling x")
        );
        assert_eq!(ansi("abc\u{8}\u{8}XY").as_deref(), Some("aXY"));
        assert_eq!(ansi("plain text"), None);
    }

    #[test]
    fn a_line_that_is_only_a_bar_or_a_spinner_is_progress() {
        assert!(progress("####------ 45%"));
        assert!(progress("[##--------]"));
        assert!(progress("\\|/-"));
        assert!(!progress("-----"), "a divider someone drew is not a bar");
        assert!(!progress("===="));
        assert!(!progress("Progress: 45% of 100 files"));
        assert!(!progress("test result: ok"));
    }

    #[test]
    fn a_bar_inside_a_real_line_is_removed_and_the_text_kept() {
        assert_eq!(
            progress_bar("Progress [#######-----] 60% of build").as_deref(),
            Some("Progress 60% of build")
        );
        assert_eq!(progress_bar("nothing #### to see here"), None);
        assert_eq!(progress_bar("no bar here"), None);
    }
}

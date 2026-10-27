//! The vocabulary: placeholders, rule names, and the shape tests this crate's
//! matchers share.
//!
//! Two things live here because both are *public surface that outlives the code*:
//!
//! * the **placeholders** a normalised log contains. They are part of the digest:
//!   a second implementation must emit `<ts>` where this one emits `<ts>`, so
//!   they are named once, here, and never spelled inline again;
//! * the **matchers** (`digit_run`, `unit_at`, `ls_row`, …). Hand-written rather
//!   than a regex crate on purpose — this crate is linked by anything that has to
//!   *produce* a digest, and a scanner that can be read line by line beats a
//!   pattern that has to be decoded, besides keeping the dependency list empty.
//!   Every matcher is documented with what it accepts and what it deliberately
//!   refuses, and `tests/recognisers.rs` pins both sides of each.

use std::fmt;

/// The normalisation version whose rules are implemented here.
///
/// Recorded in `provenance.normalisation_version`. Version `0` is
/// [`gitiup_attest::run::RawText`] — "rewrote nothing" — and lives in the format
/// crate; `1` is the first profile that actually rewrites, and the one this
/// version of this crate implements.
pub const PROFILE_VERSION: u32 = 1;

/// Name recorded in diagnostics and in `gitiup normalise --json` output.
pub const PROFILE_NAME: &str = "repro";

/// The placeholder vocabulary.
///
/// Placeholders are angle-bracketed lowercase words. A rule only ever *replaces*
/// with one of these, so "what did normalisation do to my log" has a short answer
/// and a greppable one, and the normaliser is idempotent by construction: none of
/// these strings is something another rule matches.
pub mod ph {
    /// An absolute date and/or time, in any recognised spelling (RFC 3339, ISO,
    /// syslog stamp, ctime, RFC-2822 — a `git log` committer date is the last of
    /// these).
    pub const TS: &str = "<ts>";
    /// A duration: `1.234s`, `500 ms`, `2m 3s`, `1h`, `0.1s`.
    pub const DUR: &str = "<dur>";
    /// A percentage, with or without a trailing bar graph.
    pub const PCT: &str = "<pct>";
    /// A machine-specified build/workspace root, e.g. `/home/runner/work/x/x`.
    pub const BUILD: &str = "<build>";
    /// A temporary-directory root: `$RUNNER_TEMP`, `$TMPDIR`, `/tmp`, `/var/tmp`,
    /// the Darwin `/private/var/folders/…` tree.
    pub const TMP: &str = "<tmp>";
    /// A home directory: `/home/…`, `/Users/…`, `$HOME`.
    pub const HOME: &str = "<home>";
    /// One path component that looks generated (a random suffix, a hash, a pid):
    /// `/tmp/tmp.Ab12Cd/target` is `<tmp>/<rand>/target` on every machine.
    pub const RAND: &str = "<rand>";
    /// A hostname (`runner-7.internal`, `build-03`, `$HOSTNAME`).
    pub const HOST: &str = "<host>";
    /// A user name (`runner@host`, `uid=1001(runner)`, `user: runner`).
    pub const USER: &str = "<user>";
    /// A numeric uid, gid, pid or tid.
    pub const ID: &str = "<id>";
    /// A file size in bytes: `1.5 KiB`, `4.0K`, `1,234 bytes` all become `1536B`,
    /// `4096B`, `1234B`.
    ///
    /// Unlike the others this is not a hole in the log, it is the same fact in one
    /// spelling: two locales of one file size converge instead of vanishing.
    pub fn size(bytes: u64) -> String {
        format!("{bytes}B")
    }
}

/// A normalisation rule.
///
/// Each rule has a stable [`str`] name (its "kind" in a
/// [`gitiup_attest::NormalisationDiff`]) and may be turned off in a [`crate::Profile`].
/// Names are never reused or renamed: they appear in signed attestations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Canonical line endings (CRLF/CR → LF), no trailing whitespace, no BOM,
    /// exactly one trailing newline, no tabs.
    LineEndings,
    /// Strip ANSI/VT escape sequences, resolve carriage-return and backspace
    /// overwrites to what a terminal would show.
    Ansi,
    /// Drop progress-bar and spinner lines, and the bar behind a percentage.
    Progress,
    /// Machine-specified roots → `<build>`/`<tmp>`/`<home>`, generated path
    /// components → `<rand>`.
    Path,
    /// Hostnames, user names and numeric ids → `<host>`/`<user>`/`<id>`.
    Identity,
    /// Absolute dates and times, `git` committer dates among them → `<ts>`.
    Timestamp,
    /// Durations → `<dur>`.
    Duration,
    /// Percentages (and the progress bar behind them) → `<pct>`.
    Percent,
    /// Digit grouping (`1,234,567`, `1 234 567`) → `1234567`.
    Number,
    /// File sizes → a canonical byte count (`1.5 KiB` → `1536B`).
    Size,
    /// One canonical space separator between fields, so column alignment cannot
    /// move a digest.
    Spacing,
    /// Sort runs of listing lines (an `ls -l` block, a list of paths) that have no
    /// meaning of their own.
    Listing,
}

/// All rules, in the order the pipeline applies them.
///
/// The order matters: ANSI and carriage churn go first so nothing else has to
/// know about escape bytes; identity and path go before the numeric rules so a
/// uid inside a path is not read as a size; listing sort goes last so it sorts
/// the *final* text of each line and is therefore idempotent.
pub const RULE_ORDER: [Rule; 12] = [
    Rule::LineEndings,
    Rule::Ansi,
    Rule::Progress,
    Rule::Path,
    Rule::Identity,
    Rule::Timestamp,
    Rule::Duration,
    Rule::Percent,
    Rule::Number,
    Rule::Size,
    Rule::Spacing,
    Rule::Listing,
];

/// A rule set, as a bit flag per rule.
///
/// A set rather than a `Vec` so "the rules that produced this digest" is one
/// comparable value, printable as names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rules(u32);

impl Rules {
    /// Nothing at all: the empty profile, useful as a starting point in a test.
    pub const fn none() -> Rules {
        Rules(0)
    }

    /// Every rule, which is what [`crate::Profile::standard`] uses.
    pub const fn all() -> Rules {
        let mut bits = 0u32;
        let mut index = 0usize;
        while index < RULE_ORDER.len() {
            bits |= 1 << rule_bit(RULE_ORDER[index]);
            index += 1;
        }
        Rules(bits)
    }

    const fn bit(rule: Rule) -> u32 {
        1 << rule_bit(rule)
    }

    /// True when `rule` is in the set.
    pub const fn contains(&self, rule: Rule) -> bool {
        self.0 & Self::bit(rule) != 0
    }

    /// This set plus `rule`.
    #[must_use]
    pub const fn with(mut self, rule: Rule) -> Rules {
        self.0 |= Self::bit(rule);
        self
    }

    /// This set without `rule`.
    #[must_use]
    pub const fn without(mut self, rule: Rule) -> Rules {
        self.0 &= !Self::bit(rule);
        self
    }

    /// The rules in [`RULE_ORDER`] order.
    pub fn iter(&self) -> impl Iterator<Item = Rule> {
        RULE_ORDER
            .iter()
            .copied()
            .filter(|rule| self.contains(*rule))
    }

    /// Machine-readable form: the rule names, in pipeline order.
    pub fn names(&self) -> Vec<String> {
        self.iter().map(|rule| rule.name().to_string()).collect()
    }

    /// Parse a comma-separated list of rule names (`timestamp,path`), as the CLI
    /// takes it. Unknown names are an error, not a silent no-op: a typo that
    /// silently disables nothing would produce a digest nobody else can reproduce.
    pub fn parse_list(list: &str) -> Result<Rules, String> {
        if list.trim().is_empty() {
            return Ok(Rules::none());
        }
        let mut out = Rules::none();
        for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            out = out.with(Rule::parse(name)?);
        }
        Ok(out)
    }
}

impl Default for Rules {
    fn default() -> Rules {
        Rules::all()
    }
}

const fn rule_bit(rule: Rule) -> u32 {
    match rule {
        Rule::LineEndings => 0,
        Rule::Ansi => 1,
        Rule::Progress => 2,
        Rule::Path => 3,
        Rule::Identity => 4,
        Rule::Timestamp => 5,
        Rule::Duration => 6,
        Rule::Percent => 7,
        Rule::Number => 8,
        Rule::Size => 9,
        Rule::Spacing => 10,
        Rule::Listing => 11,
    }
}

impl Rule {
    /// The stable name, and the `kind` a `NormalisationDiff` records.
    pub const fn name(&self) -> &'static str {
        match self {
            Rule::LineEndings => "line-ending",
            Rule::Ansi => "ansi",
            Rule::Progress => "progress",
            Rule::Path => "path",
            Rule::Identity => "identity",
            Rule::Timestamp => "timestamp",
            Rule::Duration => "duration",
            Rule::Percent => "percent",
            Rule::Number => "number",
            Rule::Size => "size",
            Rule::Spacing => "spacing",
            Rule::Listing => "listing",
        }
    }

    /// Parse a rule name (case-insensitive), for `--rules` and for reading a
    /// recorded `kind` back.
    pub fn parse(name: &str) -> Result<Rule, String> {
        RULE_ORDER
            .iter()
            .find(|rule| rule.name().eq_ignore_ascii_case(name.trim()))
            .copied()
            .ok_or_else(|| format!("unknown normalisation rule '{name}'"))
    }

    /// One line of documentation, reused by `--help` and by the contract doc test
    /// so the two cannot drift.
    pub const fn summary(&self) -> &'static str {
        match self {
            Rule::LineEndings => {
                "CRLF/CR to LF, no trailing blanks, no tabs, no BOM, one final newline"
            }
            Rule::Ansi => "strip ANSI/VT sequences; resolve CR and backspace overwrites",
            Rule::Progress => {
                "drop progress-bar and spinner lines; drop the bar behind a percentage"
            }
            Rule::Path => {
                "$RUNNER_TEMP/$TMPDIR/build/workspace roots to <tmp>/<build>/<home>; generated components to <rand>"
            }
            Rule::Identity => "hostname, user, uid/gid/pid to <host>/<user>/<id>",
            Rule::Timestamp => "absolute dates and times (incl. git committer dates) to <ts>",
            Rule::Duration => "durations to <dur>",
            Rule::Percent => "percentages to <pct>",
            Rule::Number => "digit grouping (1,234,567 / 1 234 567) to 1234567",
            Rule::Size => "file sizes to a canonical byte count (1.5 KiB to 1536B)",
            Rule::Spacing => {
                "one canonical space between fields, so column alignment cannot move a digest"
            }
            Rule::Listing => "sort runs of listing lines whose order nothing means",
        }
    }
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rules({})", self.names().join(","))
    }
}

impl fmt::Display for Rules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.names().join(","))
    }
}

// ------------------------------------------------------------- scanning ---

/// True for the separators that may precede a value token.
///
/// Anything that is not a letter, digit or one of the connective punctuation
/// marks — so `in 1.2s`, `took=500ms`, `(42 ms)` all start a token, while
/// `foo1.2s`, `v1.2s` and `sha/abc123def` do not.
pub fn token_start(bytes: &[u8], i: usize) -> bool {
    i == 0
        || !matches!(bytes[i - 1], b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'.' | b'/' | b'-')
}

/// True when the byte at `i` ends a value token (see [`token_start`]).
pub fn token_end(bytes: &[u8], i: usize) -> bool {
    i >= bytes.len()
        || !matches!(bytes[i], b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'.' | b'/' | b'-')
}

/// The run of ASCII digits starting at `i`, or `None` if there is none.
pub fn digit_run(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
    if bytes.get(i).is_none_or(|b| !b.is_ascii_digit()) {
        return None;
    }
    let mut j = i + 1;
    while bytes.get(j).is_some_and(u8::is_ascii_digit) {
        j += 1;
    }
    Some((i, j))
}

/// `digits[,digits]*` starting at `i`: a grouped number. `len` counts the bytes,
/// including separators, so a caller can splice the replacement in one pass.
pub fn grouped_digits(bytes: &[u8], i: usize) -> Option<(usize, usize, usize)> {
    let (start, mut end) = digit_run(bytes, i)?;
    let mut digits = end - start;
    loop {
        if bytes.get(end) != Some(&b',') {
            break;
        }
        let Some((_, next)) = digit_run(bytes, end + 1) else {
            break;
        };
        if next - (end + 1) != 3 {
            break;
        }
        digits += next - (end + 1);
        end = next;
    }
    Some((start, end, digits))
}

/// A month name (three letters is enough: `Jan`…`Dec`, any case).
pub fn month(bytes: &[u8], i: usize) -> Option<usize> {
    const MONTHS: [&[u8]; 12] = [
        b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov",
        b"dec",
    ];
    let word = bytes.get(i..i + 3)?;
    let lower: Vec<u8> = word.iter().map(u8::to_ascii_lowercase).collect();
    MONTHS.iter().position(|m| *m == &lower[..]).map(|_| 3)
}

/// A weekday name (three letters is enough).
pub fn weekday(bytes: &[u8], i: usize) -> Option<usize> {
    const DAYS: [&[u8]; 7] = [b"mon", b"tue", b"wed", b"thu", b"fri", b"sat", b"sun"];
    let word = bytes.get(i..i + 3)?;
    let lower: Vec<u8> = word.iter().map(u8::to_ascii_lowercase).collect();
    DAYS.iter().position(|d| *d == &lower[..]).map(|_| 3)
}

/// `hh` `:` `mm` [ `:` `ss` [ `.` frac ] ] starting at `i`, as `(len, hour)`.
///
/// Range-checked (24-hour clock, minutes and seconds < 60) so a version number
/// like `1:123:4` is not a clock time.
pub fn clock(bytes: &[u8], i: usize) -> Option<(usize, u32)> {
    let (hs, he) = digit_run(bytes, i)?;
    if he - hs > 2 {
        return None;
    }
    let hour: u32 = std::str::from_utf8(&bytes[hs..he]).ok()?.parse().ok()?;
    if hour > 23 || bytes.get(he) != Some(&b':') {
        return None;
    }
    let (_, m_end) = digit_run(bytes, he + 1)?;
    if m_end - (he + 1) != 2 {
        return None;
    }
    let minute: u32 = std::str::from_utf8(&bytes[he + 1..m_end])
        .ok()?
        .parse()
        .ok()?;
    if minute > 59 {
        return None;
    }
    let mut len = m_end - i;
    if bytes.get(m_end) == Some(&b':')
        && let Some((_, s_end)) = digit_run(bytes, m_end + 1)
        && s_end - (m_end + 1) == 2
    {
        let second: u32 = std::str::from_utf8(&bytes[m_end + 1..s_end])
            .ok()?
            .parse()
            .ok()?;
        if second <= 60 {
            len = s_end - i;
            if bytes.get(s_end) == Some(&b'.')
                && let Some((_, f_end)) = digit_run(bytes, s_end + 1)
            {
                len = f_end - i;
            }
        }
    }
    Some((len, hour))
}

/// A duration unit starting at `i`, as `(len, scale_nanos)`.
///
/// The unit list is deliberately short and every multi-letter form is checked
/// longest-first, so `ms` never parses as `m` + `s`. Plural and possessive
/// (`1.5 seconds'`) are fine; a unit must be followed by a token boundary.
pub fn duration_unit(bytes: &[u8], i: usize) -> Option<(usize, u64)> {
    const UNITS: &[(&str, u64)] = &[
        ("nanoseconds", 1),
        ("nanosecond", 1),
        ("nsecs", 1),
        ("nsec", 1),
        ("nsecond", 1),
        ("ns", 1),
        ("microseconds", 1_000),
        ("microsecond", 1_000),
        ("µs", 1_000),
        ("μs", 1_000),
        ("msecs", 1_000_000),
        ("msec", 1_000_000),
        ("milliseconds", 1_000_000),
        ("millisecond", 1_000_000),
        ("ms", 1_000_000),
        ("seconds", 1_000_000_000),
        ("second", 1_000_000_000),
        ("secs", 1_000_000_000),
        ("sec", 1_000_000_000),
        ("minutes", 60_000_000_000),
        ("minute", 60_000_000_000),
        ("mins", 60_000_000_000),
        ("min", 60_000_000_000),
        ("hours", 3_600_000_000_000),
        ("hour", 3_600_000_000_000),
        ("hrs", 3_600_000_000_000),
        ("hr", 3_600_000_000_000),
        ("days", 86_400_000_000_000),
        ("day", 86_400_000_000_000),
        ("h", 3_600_000_000_000),
        ("m", 60_000_000_000),
        ("s", 1_000_000_000),
        ("d", 86_400_000_000_000),
    ];
    // Longest first, so `ms` is never read as `m` followed by something else.
    // Comparing case-insensitively means `Finished in 1.2S` and `12MS` converge
    // with the lower-case spelling too. The caller checks the boundary after the
    // unit with [`unit_end`].
    let mut best: Option<(usize, u64)> = None;
    for (unit, scale) in UNITS {
        if !starts_case_insensitive(bytes, i, unit) {
            continue;
        }
        if best.is_none_or(|(len, _)| unit.len() > len) {
            best = Some((unit.len(), *scale));
        }
    }
    best
}

/// True when `bytes[i..]` starts with `word`, ASCII-case-insensitively.
pub fn starts_case_insensitive(bytes: &[u8], i: usize, word: &str) -> bool {
    let word = word.as_bytes();
    let Some(rest) = bytes.get(i..i + word.len()) else {
        return false;
    };
    rest.iter()
        .zip(word.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// True when the byte at `i` ends a *unit* token.
///
/// Looser than [`token_end`] on purpose: `finished in 1.2s.` and `built in 40s in
/// 0.4s` have to parse, so a following `.` or `/` is allowed while a letter (which
/// would mean the unit was really a longer word) is not.
pub fn unit_end(bytes: &[u8], i: usize) -> bool {
    i >= bytes.len() || !matches!(bytes[i], b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'-')
}

/// A file-size unit starting at `i`, as `(len, scale_bytes)`.
///
/// `K`/`M`/`G`/`T` alone are the 1024-based tools (`ls -lh`, `du`, `df`);
/// `KB`/`MB`/… are the SI ones (`du --si`, most installers). The distinction is
/// real and is *not* guessed from the magnitude: the contract (docs/reproducibility.md)
/// tells workflows to print byte counts, and this rule exists for the ones that
/// ignore it.
/// A file-size unit starting at `i`, as `(len, scale_bytes)`.
///
/// `K`/`M`/`G`/`T` alone are the 1024-based tools (`ls -lh`, `du`, `df`);
/// `KB`/`MB`/… are the SI ones (`du --si`, most installers). The distinction is
/// real and is *not* guessed from the magnitude: the contract
/// (docs/reproducibility.md) tells workflows to print byte counts, and this rule
/// exists for the ones that ignore it.
pub fn size_unit(bytes: &[u8], i: usize) -> Option<(usize, u64)> {
    // The spelled-out words, checked first because the bare `B` rule would match
    // the `b` of `bytes` and stop there.
    for (word, scale) in [("bytes", 1u64), ("byte", 1)] {
        if starts_case_insensitive(bytes, i, word) && unit_end(bytes, i + word.len()) {
            return Some((word.len(), scale));
        }
    }
    let byte = *bytes.get(i)?;
    let mut two = [byte, 0];
    if let Some(next) = bytes.get(i + 1) {
        two[1] = *next;
    }
    let upper = [two[0].to_ascii_uppercase(), two[1].to_ascii_uppercase()];
    if upper[1] == b'B' {
        let scale = match upper[0] {
            b'K' => 1000,
            b'M' => 1_000_000,
            b'G' => 1_000_000_000,
            b'T' => 1_000_000_000_000,
            b'P' => 1_000_000_000_000_000,
            _ => return None,
        };
        return Some((2, scale));
    }
    if two[1] == b'i'
        && bytes
            .get(i + 2)
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'B'))
    {
        let scale = match upper[0] {
            b'K' => 1024,
            b'M' => 1024 * 1024,
            b'G' => 1024u64.pow(3),
            b'T' => 1024u64.pow(4),
            b'P' => 1024u64.pow(5),
            _ => return None,
        };
        return Some((3, scale));
    }
    if unit_end(bytes, i + 1) {
        let scale = match upper[0] {
            b'B' => 1,
            b'K' => 1024,
            b'M' => 1024 * 1024,
            b'G' => 1024u64.pow(3),
            b'T' => 1024u64.pow(4),
            _ => return None,
        };
        return Some((1, scale));
    }
    None
}

/// A `user@host` pair starting at `i`, as `(len, user_len)`.
///
/// Both sides must be plausible name material and the pair must be delimited, so
/// an email address inside a URL (`mailto:a@b`) and a `ssh://user@host` URL are
/// still rewritten, while `a@b.example.com/path` (a bare email) is left alone.
pub fn user_at_host(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
    if !token_start(bytes, i) {
        return None;
    }
    let mut j = i;
    while bytes
        .get(j)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'.')
    {
        j += 1;
    }
    if j == i || bytes.get(j) != Some(&b'@') {
        return None;
    }
    let user = j - i;
    let start = j + 1;
    j = start;
    while bytes
        .get(j)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    {
        j += 1;
    }
    if j == start || !token_end(bytes, j) {
        return None;
    }
    Some((j - i, user))
}

/// A hostname-looking token starting at `i`: contains a `-` or a `.`, is
/// delimited, and is not a URL or a filename with a well-known suffix.
///
/// This is the weakest recogniser here, and it is only ever applied to a *narrowed*
/// line (see [`crate::log`]'s identity pass): a hostname is invisible without
/// context, so the rule trades a little recall for never mangling a path or a
/// version.
pub fn hostname_token(bytes: &[u8], i: usize) -> Option<usize> {
    if !token_start(bytes, i) {
        return None;
    }
    let mut j = i;
    let mut dots = 0;
    let mut dashes = 0;
    let mut alpha = false;
    while bytes
        .get(j)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
    {
        match bytes[j] {
            b'.' => dots += 1,
            b'-' => dashes += 1,
            _ => alpha = true,
        }
        j += 1;
    }
    if j == i || !alpha || !token_end(bytes, j) {
        return None;
    }
    if dots == 0 && dashes == 0 {
        return None;
    }
    let word = &bytes[i..j];
    // A version (`v0.1.0`, `1.2.3`) is not a host: every dot-separated part is a
    // number or a letter-and-number, and there is no word in it.
    if word.iter().any(u8::is_ascii_digit)
        && word.split(|b| *b == b'.').all(|part| {
            !part.is_empty()
                && part.iter().all(u8::is_ascii_alphanumeric)
                && part.iter().filter(|b| b.is_ascii_alphabetic()).count() <= 1
                && part.len() <= 2
        })
    {
        return None;
    }
    // A file (`workflow.json`, `main.rs`, `x.tar.gz`) is not a host; a host with a
    // resolver suffix is.
    if let Some(dot) = word.iter().rposition(|b| *b == b'.') {
        let suffix = &word[dot + 1..];
        let hostish = ["internal", "local", "lan", "corp", "example", "test", "dev"];
        let known_file = suffix.len() <= 5
            && suffix.iter().all(u8::is_ascii_alphabetic)
            && !hostish
                .iter()
                .any(|host| suffix.eq_ignore_ascii_case(host.as_bytes()));
        if known_file {
            return None;
        }
    }
    Some(j - i)
}

/// The `ls -l`-style row shape, used by the listing sort and by the identity rule's
/// "numeric uid/gid columns" case.
///
/// Columns: a 10-byte mode (plus an optional `+`/`.`/`@`), a link count, owner,
/// group, a size, a date, and a name. `ls` is not reproducible (mtimes, block
/// sizes, uid names) — the contract says do not print it — but when a build does
/// anyway, a *sorted and placeholdered* row is much closer to reproducible than a
/// raw one.
pub fn ls_row(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    let Some(mode) = fields.next() else {
        return false;
    };
    let mode = mode.trim_end_matches(['+', '.', '@']);
    if mode.len() != 10 {
        return false;
    }
    if !matches!(
        mode.as_bytes()[0],
        b'-' | b'd' | b'l' | b'c' | b'b' | b'p' | b's'
    ) {
        return false;
    }
    if !mode[1..]
        .bytes()
        .all(|b| matches!(b, b'r' | b'w' | b'x' | b'-' | b's' | b'S' | b't' | b'T'))
    {
        return false;
    }
    // link count, owner, group, size, then at least a date and a name.
    let rest: Vec<&str> = fields.collect();
    rest.len() >= 5 && rest[0].bytes().all(|b| b.is_ascii_digit()) && !rest[0].is_empty()
}

/// True for the components of a path that look generated rather than typed: a
/// random suffix, a hash, a content-addressed name.
///
/// The test is "has digits *and* letters, is at least six long, and is not a
/// version or a word with a digit in it like `python3.11`" — deliberately
/// conservative. False positives cost a little detail; false negatives cost
/// convergence, so the rule errs toward rewriting.
pub fn looks_generated(component: &str) -> bool {
    if component.len() < 6 || component.starts_with('.') {
        return false;
    }
    let bytes = component.as_bytes();
    let digits = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    let alpha = bytes.iter().filter(|b| b.is_ascii_alphabetic()).count();
    if digits == 0 || alpha == 0 {
        return false;
    }
    // A name with a digit in it (`python3.11`, `gitea-1.22.3`,
    // `x86_64-unknown-linux-gnu`, `node_modules`) has a word in it; a generated
    // name does not.
    if component
        .split(['-', '_', '.'])
        .any(|word| word.len() >= 4 && word.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return false;
    }
    if component.starts_with("tmp.") || component.starts_with("tmp-") {
        return true;
    }
    // A hex string of hash length.
    if bytes.iter().all(u8::is_ascii_hexdigit) && digits >= 8 {
        return true;
    }
    // Lower-case alphanumerics with a healthy mix of digits and letters:
    // `build0a9f`, `gitiup0001`.
    if bytes.iter().all(u8::is_ascii_alphanumeric) && digits >= 2 && alpha >= 4 {
        return true;
    }
    // Mixed case with a digit: `Ab12Cd`.
    bytes.iter().any(u8::is_ascii_uppercase) && digits >= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Vec<u8> {
        s.bytes().collect()
    }

    #[test]
    fn every_rule_has_a_name_and_parses_back() {
        for rule in RULE_ORDER {
            assert_eq!(Rule::parse(rule.name()).unwrap(), rule);
            assert!(!rule.summary().is_empty());
        }
        assert_eq!(RULE_ORDER.len(), 12);
        assert_eq!(Rules::all().names().len(), 12);
        assert_eq!(Rules::none().names().len(), 0);
        assert!(Rules::all().contains(Rule::Listing));
        assert!(!Rules::none().contains(Rule::Listing));
        assert!(Rule::parse("nonsense").unwrap_err().contains("nonsense"));
        assert_eq!(Rules::parse_list("").unwrap(), Rules::none());
        assert_eq!(
            Rules::parse_list("timestamp, path").unwrap(),
            Rules::none().with(Rule::Timestamp).with(Rule::Path)
        );
        assert!(Rules::parse_list("bogus").is_err());
    }

    #[test]
    fn digit_scanners() {
        assert_eq!(digit_run(&b("123a"), 0).unwrap(), (0, 3));
        assert!(digit_run(&b("a1"), 0).is_none());
        assert_eq!(grouped_digits(&b("1,234,567 rest"), 0).unwrap(), (0, 9, 7));
        // Only full groups of three count, so a list of numbers survives.
        assert_eq!(grouped_digits(&b("1,23 rest"), 0).unwrap().1, 1);
    }

    #[test]
    fn names_and_clocks() {
        assert_eq!(month(&b("Oct"), 0), Some(3));
        assert_eq!(month(&b("oct"), 0), Some(3));
        assert_eq!(month(&b("Nov1"), 0), Some(3));
        assert!(month(&b("Foo"), 0).is_none());
        assert_eq!(weekday(&b("Mon,"), 0), Some(3));
        assert_eq!(clock(&b("04:47:07 x"), 0).unwrap().0, 8);
        assert_eq!(clock(&b("9:05 x"), 0).unwrap().0, 4);
        assert!(clock(&b("24:00 x"), 0).is_none());
        assert!(clock(&b("4:7 x"), 0).is_none());
    }

    #[test]
    fn duration_units_are_matched_longest_first() {
        assert_eq!(duration_unit(&b("ms "), 0).unwrap().0, 2);
        assert_eq!(duration_unit(&b("ms "), 0).unwrap().1, 1_000_000);
        assert_eq!(duration_unit(&b("seconds "), 0).unwrap().0, 7);
        assert_eq!(duration_unit(&b("s "), 0).unwrap().1, 1_000_000_000);
        assert_eq!(duration_unit(&b("µs "), 0).unwrap().1, 1_000);
        assert_eq!(duration_unit(&b("h "), 0).unwrap().1, 3_600_000_000_000);
        assert!(duration_unit(&b("xyz"), 0).is_none());
    }

    #[test]
    fn size_units_keep_binary_and_si_apart() {
        assert_eq!(size_unit(b"KiB ", 0).unwrap(), (3, 1024));
        assert_eq!(size_unit(b"KB ", 0).unwrap(), (2, 1000));
        assert_eq!(size_unit(b"K ", 0).unwrap(), (1, 1024));
        assert_eq!(size_unit(b"bytes ", 0), Some((5, 1)));
        assert_eq!(size_unit(b"B ", 0).unwrap(), (1, 1));
        assert_eq!(size_unit(b"by the way", 0), None);
    }

    #[test]
    fn identity_recognisers() {
        assert_eq!(user_at_host(&b("runner@build-03:"), 0).unwrap().1, 6);
        assert!(user_at_host(&b("plain word"), 0).is_none());
        assert!(hostname_token(&b("build-03 "), 0).is_some());
        assert!(hostname_token(&b("host.internal "), 0).is_some());
        assert!(hostname_token(&b("main.rs "), 0).is_none());
        assert!(hostname_token(&b("plain "), 0).is_none());
    }

    #[test]
    fn generated_path_components() {
        assert!(looks_generated("tmp.Ab12Cd"));
        assert!(looks_generated("a1b2c3d4e5"));
        assert!(looks_generated("build0a9f"));
        assert!(looks_generated("gitiup0001"));
        assert!(!looks_generated("target"));
        assert!(!looks_generated("python3.11"));
        assert!(!looks_generated(".cache"));
        assert!(!looks_generated("node_modules"));
        assert!(!looks_generated("x86_64-unknown-linux-gnu"));
        assert!(!looks_generated("sha256"));
        assert!(!looks_generated("gitea-1.22.3"));
    }

    #[test]
    fn ls_rows_are_recognised() {
        assert!(ls_row("drwxr-xr-x  4 alice wheel 128 Oct 27 09:11 target"));
        assert!(ls_row(
            "-rw-r--r--  1 root root 1234 Jan  1  2020 README.md"
        ));
        assert!(!ls_row("total 8"));
        assert!(!ls_row("just some prose here"));
    }
}

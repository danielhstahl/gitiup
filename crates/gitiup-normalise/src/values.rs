//! The value-shaped passes: timestamps, durations, percentages, numbers, sizes.
//!
//! One scanner per rule, each returning the rewritten line, so a rewrite can be
//! recorded under the rule that made it (`kind: timestamp`, `kind: size`, …) and
//! so a rule can be switched off without touching the others.
//!
//! Every matcher is ASCII-digit based and range-checked. That is what makes it
//! safe to run over log text that mentions version numbers, hashes and target
//! triples: `1.99.1`, `a1b2c3d4e5` and `x86_64-unknown-linux-gnu` must survive,
//! while `2026-10-27T09:11:12.481392Z` and `in 12.441s` must not. The refusals are
//! pinned in `tests/recognisers.rs` as firmly as the matches.

use crate::grammar::{
    self as g, clock, digit_run, duration_unit, grouped_digits, month, ph, size_unit, token_start,
    unit_end,
};

/// A decimal number: `12`, `1.5`, `1,5`, `.5`.
///
/// A comma is accepted as a decimal separator because that is how half the world's
/// locales print the `1,5 seconds` another machine prints as `1.5 seconds`; the
/// cost is that a grouping comma must be handled first, by [`numbers`].
pub(crate) struct Number {
    /// Byte index just past the number.
    pub end: usize,
    pub int: u64,
    pub frac: u64,
    pub frac_digits: u32,
}

impl Number {
    /// The value scaled by `scale`, rounded, with no floating point anywhere.
    pub fn scaled(&self, scale: u64) -> u64 {
        let whole = self.int.saturating_mul(scale);
        if self.frac_digits == 0 || self.frac == 0 {
            return whole;
        }
        let divisor = 10u64.pow(self.frac_digits);
        let part = (self.frac.saturating_mul(scale) + divisor / 2) / divisor;
        whole.saturating_add(part)
    }
}

pub(crate) fn numeric(bytes: &[u8], i: usize) -> Option<Number> {
    let (start, mut j) = digit_run(bytes, i)?;
    let mut frac_digits = 0u32;
    let int: u64 = std::str::from_utf8(&bytes[start..j])
        .ok()?
        .parse()
        .unwrap_or(u64::MAX);
    let mut frac = 0u64;
    if matches!(bytes.get(j), Some(b'.') | Some(b','))
        && let Some((_, f_end)) = digit_run(bytes, j + 1)
    {
        // A trailing separator (`1.`) is not a decimal number, and a long run
        // of fraction digits is a hash or a build stamp, not a measurement.
        let digits = f_end - (j + 1);
        if digits <= 9 {
            frac = std::str::from_utf8(&bytes[j + 1..f_end])
                .ok()?
                .parse()
                .unwrap_or(0);
            frac_digits = digits as u32;
            j = f_end;
        }
    }
    Some(Number {
        end: j,
        int,
        frac,
        frac_digits,
    })
}

/// Run `matcher` over every token start in `line` and splice the replacements in.
///
/// `None` when nothing matched, so the caller can tell "unchanged" from "changed to
/// the same thing" without comparing strings twice.
pub(crate) fn replace_all(
    line: &str,
    mut matcher: impl FnMut(&[u8], usize) -> Option<(String, usize)>,
) -> Option<String> {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;
    let mut hit = false;
    let mut last = 0usize;
    while i < bytes.len() {
        if token_start(bytes, i)
            && let Some((replacement, len)) = matcher(bytes, i)
            && len > 0
        {
            hit = true;
            out.push_str(&line[last..i]);
            out.push_str(&replacement);
            i += len;
            last = i;
            continue;
        }
        i += 1;
    }
    if hit {
        out.push_str(&line[last..]);
        Some(out)
    } else {
        None
    }
}

// ---------------------------------------------------------- timestamps ---

/// `Timestamp`: an absolute date, optionally with a time.
pub(crate) fn timestamps(line: &str) -> Option<String> {
    replace_all(line, |bytes, i| {
        let len = numeric_date(bytes, i)
            .or_else(|| ctime(bytes, i))
            .or_else(|| day_first(bytes, i))
            .or_else(|| clock_only(bytes, i))?;
        Some((ph::TS.to_string(), len))
    })
}

/// `2026-10-27`, `2026/10/27`, `2026-10-27T09:11:12.481392Z`,
/// `2026-10-27 09:11:12 +0200`.
fn numeric_date(bytes: &[u8], i: usize) -> Option<usize> {
    let (ys, ye) = digit_run(bytes, i)?;
    if ye - ys != 4 {
        return None;
    }
    let year: u32 = std::str::from_utf8(&bytes[ys..ye]).ok()?.parse().ok()?;
    if !(1000..=2999).contains(&year) {
        return None;
    }
    let sep = *bytes.get(ye)?;
    if sep != b'-' && sep != b'/' {
        return None;
    }
    let (ms, me) = digit_run(bytes, ye + 1)?;
    if me - (ye + 1) != 2 {
        return None;
    }
    let month: u32 = std::str::from_utf8(&bytes[ms..me]).ok()?.parse().ok()?;
    if month > 12 {
        return None;
    }
    if bytes.get(me) != Some(&sep) {
        return None;
    }
    let (ds, de) = digit_run(bytes, me + 1)?;
    if de - (me + 1) != 2 {
        return None;
    }
    let day: u32 = std::str::from_utf8(&bytes[ds..de]).ok()?.parse().ok()?;
    if day > 31 {
        return None;
    }
    let mut end = de;
    // A time may follow, separated by `T` or a single space. The space form is
    // what `date`, `tar -tvf` and most build logs print.
    if matches!(bytes.get(end), Some(b'T') | Some(b' '))
        && let Some((len, _)) = clock(bytes, end + 1)
    {
        let mut after = end + 1 + len;
        after = offset(bytes, after).unwrap_or(after);
        // Swallow the time only when it is really attached to the date, so that
        // `2026-10-27 4 files changed` keeps its count.
        if g::unit_end(bytes, after) {
            end = after;
        }
    }
    Some(end - i)
}

/// `Z`, `+0200`, `+02:00` after a clock time.
fn offset(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes.get(i) {
        Some(b'Z') => Some(i + 1),
        Some(b'+') | Some(b'-') => {
            let (_, he) = digit_run(bytes, i + 1)?;
            if he - (i + 1) != 2 {
                return None;
            }
            if bytes.get(he) == Some(&b':') {
                let (_, me) = digit_run(bytes, he + 1)?;
                if me - (he + 1) == 2 {
                    return Some(me);
                }
                return None;
            }
            Some(he)
        }
        _ => None,
    }
}

/// ctime and syslog forms, and the RFC-2822 date a `git log` prints:
/// `Mon Oct 27 09:11:12 2026`, `Oct 27 09:11:12`, `Oct 27  2020`, `Oct 27 09:11`
/// (the `ls -l` shape), `Mon, 27 Oct 2026 09:11:15 +0000`.
fn ctime(bytes: &[u8], i: usize) -> Option<usize> {
    let mut p = i;
    let mut weekday = false;
    if let Some(word) = g::weekday(bytes, p) {
        p += word;
        if bytes.get(p) == Some(&b',') {
            p += 1;
        }
        p = skip_spaces(bytes, p)?;
        weekday = true;
    }
    // `Mon Oct 27 …` and `Mon, 27 Oct 2026 …` are the same fact in two orders.
    let len = month_first(bytes, p).or_else(|| if weekday { day_first(bytes, p) } else { None })?;
    Some(p + len - i)
}

/// `Oct 27 09:11:12 2026`, with the time and the year both optional but at least
/// one of them required: `Oct 27` alone is a date fragment in prose.
fn month_first(bytes: &[u8], i: usize) -> Option<usize> {
    let mut p = i;
    let word = month(bytes, p)?;
    p += word;
    p = skip_spaces(bytes, p)?;
    let (_, de) = digit_run(bytes, p)?;
    if de - p > 2 {
        return None;
    }
    p = de;
    if bytes.get(p) == Some(&b',') {
        p += 1;
    }
    p = skip_spaces(bytes, p).unwrap_or(p);
    let mut matched_time_or_year = false;
    if let Some((len, _)) = clock(bytes, p) {
        p += len;
        matched_time_or_year = true;
        p = skip_spaces(bytes, p).unwrap_or(p);
    }
    if let Some((_, ye)) = digit_run(bytes, p)
        && ye - p == 4
    {
        p = ye;
        matched_time_or_year = true;
    }
    if !matched_time_or_year || !g::unit_end(bytes, p) {
        return None;
    }
    Some(p - i)
}

/// `27 Oct 2026`, `27 October 2026 09:11`.
fn day_first(bytes: &[u8], i: usize) -> Option<usize> {
    let (_, mut p) = digit_run(bytes, i)?;
    if p - i > 2 {
        return None;
    }
    p = skip_spaces(bytes, p)?;
    let word = month(bytes, p)?;
    p += word;
    // A bare `27 Oct` is prose; require the year or a time.
    p = skip_spaces(bytes, p)?;
    if let Some((_, ye)) = digit_run(bytes, p)
        && ye - p == 4
    {
        let mut end = ye;
        if let Some(after) = skip_spaces(bytes, end)
            && let Some((len, _)) = clock(bytes, after)
        {
            end = after + len;
        }
        return (g::unit_end(bytes, end)).then_some(end - i);
    }
    let (len, _) = clock(bytes, p)?;
    (g::unit_end(bytes, p + len)).then_some(p + len - i)
}

/// A bare clock time, `09:11` or `09:11:12`.
///
/// Rendered as `<ts>` rather than `<dur>` because "at 09:11" is far more common
/// than an elapsed `12:34`, and both are volatile either way. A duration written
/// as a clock is covered by the contract instead.
fn clock_only(bytes: &[u8], i: usize) -> Option<usize> {
    let (len, _) = clock(bytes, i)?;
    // Not part of a longer dotted run (`1.99.1`, a version).
    if i > 0 && matches!(bytes[i - 1], b'.' | b'-' | b'/' | b':') {
        return None;
    }
    (g::unit_end(bytes, i + len)).then_some(len)
}

fn skip_spaces(bytes: &[u8], i: usize) -> Option<usize> {
    let mut p = i;
    while bytes.get(p) == Some(&b' ') {
        p += 1;
    }
    if p == i { None } else { Some(p) }
}

// ------------------------------------------------------------ durations ---

/// `Duration`: `1.234s`, `500 ms`, `2m 3s`, `1h 5m 30s`, `1.5 seconds`.
pub(crate) fn durations(line: &str) -> Option<String> {
    replace_all(line, |bytes, i| {
        let len = duration_span(bytes, i)?;
        Some((ph::DUR.to_string(), len))
    })
}

fn duration_span(bytes: &[u8], i: usize) -> Option<usize> {
    let mut pos = i;
    let mut total = 0usize;
    while let Some(number) = numeric(bytes, pos) {
        let mut after = number.end;
        if bytes.get(after) == Some(&b' ') {
            after += 1;
        }
        let Some((unit_len, _scale)) = duration_unit(bytes, after) else {
            break;
        };
        if !unit_end(bytes, after + unit_len) {
            break;
        }
        pos = after + unit_len;
        total = pos - i;
        // A composite continues with whitespace or `and`: `1m 2s`, `1 h and 5 m`.
        let mut next = pos;
        while bytes.get(next) == Some(&b' ') {
            next += 1;
        }
        if g::starts_case_insensitive(bytes, next, "and") {
            next += 3;
            while bytes.get(next) == Some(&b' ') {
                next += 1;
            }
        }
        if next == pos || numeric(bytes, next).is_none() {
            break;
        }
        pos = next;
    }
    (total > 0).then_some(total)
}

/// `Percent`: `45%`, `99.9 %`.
pub(crate) fn percents(line: &str) -> Option<String> {
    replace_all(line, |bytes, i| {
        let number = numeric(bytes, i)?;
        let mut after = number.end;
        while bytes.get(after) == Some(&b' ') {
            after += 1;
        }
        if bytes.get(after) != Some(&b'%') {
            return None;
        }
        Some((ph::PCT.to_string(), after + 1 - i))
    })
}

// ------------------------------------------------------- numbers, sizes ---

/// `Number`: strip digit grouping so that `1,234,567`, `1 234 567` and `1234567`
/// are one value.
///
/// The comma form needs no context; the space form is refused unless every group
/// after the first is exactly three digits and the number has at least four
/// digits, which is what makes `test 1 2 3` and `v 1 23` survive while `1 234`
/// (one locale's `1234`) converges.
pub(crate) fn numbers(line: &str) -> Option<String> {
    let grouped = replace_all(line, |bytes, i| {
        let (start, end, digits) = grouped_digits(bytes, i)?;
        if end == start || bytes[start] == b',' {
            return None;
        }
        let commas = bytes[start..end].iter().filter(|b| **b == b',').count();
        if commas == 0 {
            return None;
        }
        let digits_only: String = bytes[start..end]
            .iter()
            .filter(|b| b.is_ascii_digit())
            .map(|b| *b as char)
            .collect();
        (digits >= 4).then(|| (digits_only, end - start))
    });
    let spaced = {
        let base = grouped.as_deref().unwrap_or(line);
        replace_all(base, |bytes, i| {
            let (start, mut end) = digit_run(bytes, i)?;
            let mut digits = end - start;
            let mut joined: String = bytes[start..end].iter().map(|b| *b as char).collect();
            let mut groups = 0usize;
            loop {
                let mut probe = end;
                while bytes.get(probe) == Some(&b' ') {
                    probe += 1;
                }
                let Some((_, group_end)) = digit_run(bytes, probe) else {
                    break;
                };
                if group_end - probe != 3 {
                    break;
                }
                joined.push_str(
                    bytes[probe..group_end]
                        .iter()
                        .map(|b| *b as char)
                        .collect::<String>()
                        .as_str(),
                );
                groups += 1;
                digits += 3;
                end = group_end;
            }
            if groups == 0 || digits < 4 || !g::unit_end(bytes, end) {
                return None;
            }
            Some((joined, end - start))
        })
    };
    // Both passes are needed and either can fire alone: a comma grouping on one
    // machine, a space grouping on the other, and frequently only one of the two
    // matches a given line.
    let current = grouped.unwrap_or_else(|| line.to_string());
    let out = spaced.unwrap_or_else(|| current.clone());
    (out != line).then_some(out)
}

/// `Size`: a file size in any spelling, written as a byte count.
///
/// `1.5 KiB`, `1536 bytes`, `4.0K` and `1,5 kB` all become a number of bytes
/// (`1536B`, `1536B`, `4096B`, `1500B`). This is the one rule that *keeps* a value
/// instead of replacing it: two locales describing one file should agree on the
/// size, not both forget it.
pub(crate) fn sizes(line: &str) -> Option<String> {
    replace_all(line, |bytes, i| {
        let number = numeric(bytes, i)?;
        let mut after = number.end;
        if bytes.get(after) == Some(&b' ') {
            after += 1;
        }
        let (unit_len, scale) = size_unit(bytes, after)?;
        if !unit_end(bytes, after + unit_len) {
            return None;
        }
        // `2026 B` is more likely a count of something than a file size, and a
        // year followed by a bare `B` is common enough prose to be worth the
        // exception. The spelled-out `bytes` is never a year.
        if number.frac_digits == 0
            && (1000..=2999).contains(&number.int)
            && scale == 1
            && unit_len == 1
        {
            return None;
        }
        Some((ph::size(number.scaled(scale)), after + unit_len - i))
    })
}

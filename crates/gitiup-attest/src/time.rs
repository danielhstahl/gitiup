//! Microsecond wall-clock time, with a display form.
//!
//! The wire format stores integers ([ADR-0001 D6](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md));
//! humans want `2026-10-27T09:15:02.500Z`. Both live here so the conversion is
//! written once. `gitiup-host` has a seconds-resolution sibling for ref and blob
//! bookkeeping; the two are deliberately separate — a blob's mtime and an
//! attestation's claimed time are different claims with different tolerance.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Microseconds since the Unix epoch, UTC.
///
/// POSIX-style: leap seconds are ignored (an attestation is a statement about a
/// run, not an astronomical record), and negative values are allowed so a
/// pre-1970 reproduction of an old run can still be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeUs(pub i64);

impl TimeUs {
    /// Now, as best the system clock can say.
    pub fn now() -> TimeUs {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => TimeUs(d.as_micros().min(i64::MAX as u128) as i64),
            // Pre-epoch system clocks exist on hardware with a dead battery.
            Err(e) => TimeUs(-(e.duration().as_micros().min(i64::MAX as u128) as i64)),
        }
    }

    /// From whole seconds.
    pub fn from_secs(secs: i64) -> TimeUs {
        TimeUs(secs * 1_000_000)
    }

    /// The value in microseconds.
    pub fn as_us(self) -> i64 {
        self.0
    }

    /// Whole seconds since the epoch (rounded down).
    pub fn as_secs(self) -> i64 {
        self.0.div_euclid(1_000_000)
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`, or with `.NNNNNN` when there is a fraction.
    ///
    /// Always `Z`: an attestation's claimed time is UTC by definition, and
    /// letting a local offset into the rendering is exactly the ambiguity the
    /// integer form was chosen to avoid.
    pub fn to_rfc3339(self) -> String {
        let secs = self.0.div_euclid(1_000_000);
        let micros = self.0.rem_euclid(1_000_000);
        let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
        let rem = secs.rem_euclid(86_400);
        if micros == 0 {
            format!(
                "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
                rem / 3_600,
                (rem % 3_600) / 60,
                rem % 60
            )
        } else {
            // Trailing zeros trimmed: `1.5s`, not `1.500000s`.
            let mut frac = format!("{micros:06}");
            while frac.ends_with('0') {
                frac.pop();
            }
            format!(
                "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac}Z",
                rem / 3_600,
                (rem % 3_600) / 60,
                rem % 60
            )
        }
    }

    /// Parse [`Self::to_rfc3339`], or a bare integer of microseconds.
    pub fn parse(s: &str) -> Result<TimeUs> {
        let s = s.trim();
        if let Ok(us) = s.parse::<i64>() {
            return Ok(TimeUs(us));
        }
        let bytes = s.as_bytes();
        if bytes.len() < 20 || &bytes[10..11] != b"T" || !bytes.ends_with(b"Z") {
            return Err(bad(s));
        }
        let num = |v: &str| v.parse::<i64>().map_err(|_| bad(s));
        let (year, month, day) = (num(&s[0..4])?, num(&s[5..7])?, num(&s[8..10])?);
        let (hh, mm, ss) = (num(&s[11..13])?, num(&s[14..16])?, num(&s[17..19])?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
            return Err(bad(s));
        }
        let mut days = days_from_civil(year, month, day) * 86_400 + hh * 3_600 + mm * 60 + ss;
        let rest = &s[19..s.len() - 1];
        let mut micros = 0i64;
        if let Some(frac) = rest.strip_prefix('.') {
            if frac.is_empty() || frac.len() > 6 || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad(s));
            }
            micros = format!("{:0<6}", frac).parse::<i64>().map_err(|_| bad(s))?;
        } else if !rest.is_empty() {
            return Err(bad(s));
        }
        days = days
            .checked_mul(1_000_000)
            .and_then(|v| v.checked_add(micros))
            .ok_or_else(|| bad(s))?;
        Ok(TimeUs(days))
    }
}

fn bad(s: &str) -> Error {
    Error::invalid("timestamp", format!("'{s}' is not a timestamp"))
        .with_hint("use RFC 3339 in UTC (2026-10-27T00:00:00Z) or integer microseconds")
}

impl std::fmt::Display for TimeUs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as i64, d as i64)
}

/// Human wording for a duration in microseconds (`1.5s`, `3600s`).
pub fn human_duration_us(us: i64) -> String {
    let sign = if us < 0 { "-" } else { "" };
    let us = us.unsigned_abs();
    if us < 1_000 {
        format!("{sign}{us}us")
    } else if us < 60_000_000 {
        let whole = us / 1_000_000;
        let frac = us % 1_000_000;
        if frac == 0 {
            format!("{sign}{whole}s")
        } else {
            let mut digits = format!("{frac:06}");
            while digits.ends_with('0') {
                digits.pop();
            }
            format!("{sign}{whole}.{digits}s")
        }
    } else {
        format!(
            "{sign}{}m{}s",
            us / 60_000_000,
            (us % 60_000_000) / 1_000_000
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(TimeUs(0).to_rfc3339(), "1970-01-01T00:00:00Z");
        assert_eq!(
            TimeUs::from_secs(1_761_523_200).to_rfc3339(),
            "2025-10-27T00:00:00Z"
        );
        assert_eq!(
            TimeUs(1_761_523_200_500_000).to_rfc3339(),
            "2025-10-27T00:00:00.5Z"
        );
        assert_eq!(
            TimeUs::from_secs(-86_400).to_rfc3339(),
            "1969-12-31T00:00:00Z"
        );
    }

    #[test]
    fn parses_and_round_trips() {
        for text in [
            "1970-01-01T00:00:00Z",
            "2024-02-29T23:59:59Z",
            "2026-10-27T09:15:02.5Z",
            "2026-10-27T09:15:02.000001Z",
        ] {
            let parsed = TimeUs::parse(text).unwrap();
            assert_eq!(parsed.to_rfc3339(), text, "round trip of {text}");
        }
        assert_eq!(
            TimeUs::parse("1761523200000000").unwrap(),
            TimeUs::from_secs(1_761_523_200)
        );
        for bad in [
            "",
            "2026-10-27",
            "2026-10-27T00:00:00",
            "2026-13-01T00:00:00Z",
            "2026-10-27T00:00:00+02:00",
        ] {
            assert!(TimeUs::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn durations_read_well() {
        assert_eq!(human_duration_us(1_500_000), "1.5s");
        assert_eq!(human_duration_us(500), "500us");
        assert_eq!(human_duration_us(2_000_000), "2s");
        assert_eq!(human_duration_us(90 * 1_000_000), "1m30s");
    }
}

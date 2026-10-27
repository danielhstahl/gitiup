//! A tiny wall-clock type so the host crate stays dependency-free.
//!
//! Stored as whole seconds since the Unix epoch; that is plenty for ref/blob
//! bookkeeping (`updated_at`, blob creation times) and it round-trips through
//! JSON and TOML without a date library.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::HostError;

/// Seconds since the Unix epoch, with an RFC 3339 (UTC) display form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The current time.
    pub fn now() -> Timestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| Timestamp(d.as_secs()))
            .unwrap_or(Timestamp(0))
    }

    /// From a file's modified time (falls back to the epoch for times before
    /// 1970, which some filesystems produce).
    pub fn from_file_modified(meta: &std::fs::Metadata) -> Timestamp {
        meta.modified()
            .ok()
            .map(|t| {
                t.duration_since(UNIX_EPOCH)
                    .map(|d| Timestamp(d.as_secs()))
                    .unwrap_or(Timestamp(0))
            })
            .unwrap_or(Timestamp(0))
    }

    /// From whole seconds since the epoch.
    pub fn from_unix(secs: u64) -> Timestamp {
        Timestamp(secs)
    }

    /// Whole seconds since the epoch.
    pub fn as_unix(self) -> u64 {
        self.0
    }

    /// The epoch itself.
    pub fn zero() -> Timestamp {
        Timestamp(0)
    }

    /// Parse the RFC 3339-ish form produced by [`Timestamp::to_rfc3339`], plus
    /// bare integers (seconds since the epoch).
    pub fn parse(s: &str) -> Result<Timestamp, HostError> {
        let s = s.trim();
        if let Ok(secs) = s.parse::<u64>() {
            return Ok(Timestamp(secs));
        }
        // 2026-10-27T00:00:00Z  /  2026-10-27T00:00:00+02:00
        let (date, time) = s.split_once(['T', ' ']).ok_or_else(|| bad(s))?;
        if s.len() < 19 {
            return Err(bad(s));
        }
        let mut d = date.split('-');
        let (year, month, day) = match (d.next(), d.next(), d.next()) {
            (Some(y), Some(m), Some(dd)) => (y, m, dd),
            _ => return Err(bad(s)),
        };
        let mut t = time.split(':');
        let (hh, mm, ss) = match (t.next(), t.next(), t.next()) {
            (Some(h), Some(m), Some(sec)) => (h, m, &sec[..sec.len().min(2)]),
            _ => return Err(bad(s)),
        };
        let num = |v: &str| v.parse::<i64>().map_err(|_| bad(s));
        let (year, month, day, hh, mm, ss) = (
            num(year)?,
            num(month)?,
            num(day)?,
            num(hh)?,
            num(mm)?,
            num(ss)?,
        );
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
            return Err(bad(s));
        }
        let offset = {
            let tail = &s[19..];
            match tail {
                "" | "Z" | "z" => 0,
                _ => {
                    let sign = match tail.as_bytes().first() {
                        Some(b'+') => 1,
                        Some(b'-') => -1,
                        _ => return Err(bad(s)),
                    };
                    let mut parts = tail[1..].split(':');
                    let oh: i64 = parts.next().unwrap_or("0").parse().map_err(|_| bad(s))?;
                    let om: i64 = parts.next().unwrap_or("0").parse().unwrap_or(0);
                    sign * (oh * 3600 + om * 60)
                }
            }
        };
        let days = days_from_civil(year, month, day);
        let secs = days * 86_400 + hh * 3600 + mm * 60 + ss - offset;
        u64::try_from(secs)
            .map(Timestamp)
            .map_err(|_| HostError::invalid("timestamp", format!("'{s}' is before the epoch")))
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn to_rfc3339(self) -> String {
        let secs = self.0 as i64;
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }
}

fn bad(s: &str) -> HostError {
    HostError::invalid("timestamp", format!("'{s}' is not a timestamp"))
        .with_hint("use RFC 3339 (2026-10-27T00:00:00Z) or seconds since the epoch")
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
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
fn civil_from_days(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Timestamp(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_and_known_dates() {
        assert_eq!(Timestamp(0).to_rfc3339(), "1970-01-01T00:00:00Z");
        assert_eq!(
            Timestamp(1_761_523_200).to_rfc3339(),
            "2025-10-27T00:00:00Z"
        );
        // leap day round-trip
        assert_eq!(
            Timestamp::parse("2024-02-29T23:59:59Z")
                .unwrap()
                .to_rfc3339(),
            "2024-02-29T23:59:59Z"
        );
    }

    #[test]
    fn parses_rfc3339_offsets_and_integers() {
        let utc = Timestamp::parse("2026-10-27T00:00:00Z").unwrap();
        let offset = Timestamp::parse("2026-10-27T02:00:00+02:00").unwrap();
        assert_eq!(utc, offset);
        assert_eq!(
            Timestamp::parse("1761523200").unwrap(),
            Timestamp(1_761_523_200)
        );
        assert!(Timestamp::parse("not a date").is_err());
        assert!(Timestamp::parse("2026-13-45T00:00:00Z").is_err());
    }

    #[test]
    fn serde_is_integer_seconds() {
        let json = serde_json::to_string(&Timestamp(5)).unwrap();
        assert_eq!(json, "5");
        assert_eq!(
            serde_json::from_str::<Timestamp>(&json).unwrap(),
            Timestamp(5)
        );
    }
}

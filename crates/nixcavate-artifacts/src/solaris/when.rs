//! Time text shared by the Solaris logs.

use crate::Input;
use nixcavate_core::time::{month_from_abbrev, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Precision, Timestamp};

/// `Fri Nov 13 01:15:46 2026`: the `ctime(3)` form (no zone, a year). Wall-clock seconds.
pub(super) fn ctime_wall(text: &str) -> Option<i64> {
    let mut words = text.split_whitespace();
    let (_weekday, month, day, clock, year) =
        (words.next()?, words.next()?, words.next()?, words.next()?, words.next()?);
    let mut hms = clock.split(':');
    let (h, m, s) = (hms.next()?, hms.next()?, hms.next()?);
    let num = |t: &str| parse_uint(t.as_bytes());
    secs_from_civil(
        i64::try_from(num(year)?).ok()?,
        month_from_abbrev(month.as_bytes())?,
        u32::try_from(num(day)?).ok()?,
        u32::try_from(num(h)?).ok()?,
        u32::try_from(num(m)?).ok()?,
        u32::try_from(num(s)?).ok()?,
    )
}

/// A host-local `ctime` time as a timestamp, marked as assumed in the host's zone.
pub(super) fn ctime_time(input: &Input, text: &str) -> Option<Timestamp> {
    Some(input.local_time(ctime_wall(text)?, 0, Precision::Seconds))
}

/// A time with no year (`Nov 13 01:16:51`, or `11/13 01:16`): the year is inferred from the file's
/// modification time, as for classic syslog.
pub(super) fn yearless(input: &Input, month: u32, day: u32, h: u32, m: u32, s: u32) -> Option<Timestamp> {
    crate::common::year::utc_without_year(month, day, h, m, s, input.mtime, &input.host.tz)
        .map(|utc| Timestamp::from_secs(utc, Basis::InferredYearAssumedZone))
}

/// `Nov 13 01:16:51` (month name, day, `HH:MM:SS`), the form SMF logs use.
pub(super) fn month_name_time(input: &Input, month: &str, day: &str, clock: &str) -> Option<Timestamp> {
    let mut hms = clock.split(':');
    let (h, m, s) = (hms.next()?, hms.next()?, hms.next()?);
    let num = |t: &str| u32::try_from(parse_uint(t.as_bytes())?).ok();
    yearless(input, month_from_abbrev(month.as_bytes())?, num(day)?, num(h)?, num(m)?, num(s)?)
}

/// `20261113T011444Z` or `20250503T092906.342281Z`: the compact UTC form IPS writes.
pub(super) fn ips_time(text: &str) -> Option<Timestamp> {
    let text = text.trim().strip_suffix('Z')?;
    let (date, clock) = text.split_once('T')?;
    let (clock, fraction) = clock.split_once('.').unwrap_or((clock, ""));
    if date.len() != 8 || clock.len() != 6 || !date.bytes().chain(clock.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |t: &str| parse_uint(t.as_bytes());
    let secs = secs_from_civil(
        i64::try_from(num(&date[..4])?).ok()?,
        u32::try_from(num(&date[4..6])?).ok()?,
        u32::try_from(num(&date[6..8])?).ok()?,
        u32::try_from(num(&clock[..2])?).ok()?,
        u32::try_from(num(&clock[2..4])?).ok()?,
        u32::try_from(num(&clock[4..6])?).ok()?,
    )?;
    if fraction.is_empty() {
        return Some(Timestamp::from_secs(secs, Basis::Recorded));
    }
    // Up to six digits of fraction are microseconds, left-aligned.
    let digits: String = fraction.chars().take(6).collect();
    let micros = num(&format!("{digits:0<6}"))?;
    Some(Timestamp::from_secs_nanos(
        secs,
        u32::try_from(micros).ok()?.checked_mul(1000)?,
        Precision::Micros,
        Basis::Recorded,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ips_times_are_read() {
        assert_eq!(ips_time("20261113T011444Z").map(|t| t.to_rfc3339()).as_deref(), Some("2026-11-13T01:14:44Z"));
        assert_eq!(
            ips_time("20250503T092906.342281Z").map(|t| t.to_rfc3339()).as_deref(),
            Some("2025-05-03T09:29:06.342281Z")
        );
        assert!(ips_time("2026-11-13").is_none() && ips_time("20261313T011444Z").is_none() && ips_time("").is_none());
    }

    #[test]
    fn ctime_is_read() {
        assert_eq!(ctime_wall("Fri Nov 13 01:15:46 2026"), Some(1_794_532_546));
        assert_eq!(ctime_wall("Fri Nov  3 01:15:46 2026"), secs_from_civil(2026, 11, 3, 1, 15, 46));
        assert_eq!(ctime_wall("Fri Nov 13 01:15 2026"), None);
        assert_eq!(ctime_wall("Fri Foo 13 01:15:46 2026"), None);
        assert_eq!(ctime_wall("Fri Nov 99999999999999999999 01:15:46 2026"), None);
    }
}

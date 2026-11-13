//! Times as AIX tools print them. None carries a zone the analyst can trust (`UTC` or `EDT`
//! are abbreviations, which are ambiguous), so callers turn the wall-clock value into a
//! timestamp with the host zone applied (`Input::local_time`).

use nixcavate_core::time::{month_from_abbrev, secs_from_civil};

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// `[Wed ]Mar 10 01:02:03[ UTC] 2024` (ctime(3), `date`, the cron log, `errpt -a`, `auditpr`)
/// as wall-clock seconds since the epoch.
pub fn ctime(text: &str) -> Option<i64> {
    let mut words = text.split_whitespace().peekable();
    if words.peek().is_some_and(|w| WEEKDAYS.contains(w)) {
        words.next();
    }
    let month = month_from_abbrev(words.next()?.as_bytes())?;
    let day: u32 = words.next()?.parse().ok()?;
    let (hour, minute, second) = clock(words.next()?)?;
    let mut year = words.next()?;
    // A zone abbreviation sits between the time and the year.
    if year.bytes().all(|b| b.is_ascii_alphabetic()) {
        year = words.next()?;
    }
    if year.len() != 4 || words.next().is_some() {
        return None;
    }
    secs_from_civil(year.parse().ok()?, month, day, hour, minute, second)
}

/// `HH:MM:SS`, or `HH;MM;SS` (`lslpp -c` cannot print the colon: it is its field separator).
pub fn clock(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split([':', ';']);
    let (h, m, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || [h, m, s].iter().any(|p| p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some((h.parse().ok()?, m.parse().ok()?, s.parse().ok()?))
}

/// A two-digit year as AIX tools print it: 70..=99 are 19xx, the rest 20xx.
pub fn two_digit_year(yy: u32) -> i64 {
    i64::from(if yy >= 70 { 1900 + yy } else { 2000 + yy })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctime_forms() {
        let expected = Some(1_710_032_523);
        assert_eq!(ctime("Sun Mar 10 01:02:03 2024"), expected);
        assert_eq!(ctime("Sun Mar 10 01:02:03 UTC 2024"), expected);
        assert_eq!(ctime("Mar 10 01:02:03 2024"), expected);
        assert_eq!(ctime("Sun Mar  10 01:02:03   EDT 2024"), expected);
        for bad in [
            "",
            "Mar 10 2024",
            "Mar 10 01:02:03",
            "Mar 32 01:02:03 2024",
            "Mar 10 25:02:03 2024",
            "Mar 10 01:02:03 24",
            "x y z",
        ] {
            assert_eq!(ctime(bad), None, "{bad}");
        }
    }

    #[test]
    fn clock_with_semicolons() {
        assert_eq!(clock("12;55;38"), Some((12, 55, 38)));
        assert_eq!(clock("1:2"), None);
    }
}

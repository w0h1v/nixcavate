//! Year inference for timestamps written without a year (classic syslog, `yum.log`).

use nixcavate_core::time::{civil_from_days, secs_from_civil};
use nixcavate_source::Tz;

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Resolves a host-local wall-clock time that has no year to UTC seconds.
///
/// The year is the latest one that does not put the time more than a day after `reference`,
/// the file's modification time: a log's lines were written before the file was last changed.
/// The rule needs no state from other lines, so split files infer the same years. It is wrong
/// for lines more than a year older than the file's last write.
///
/// Returns `None` when there is no reference (`0`) or the fields are not a real date.
pub fn utc_without_year(month: u32, day: u32, hour: u32, min: u32, sec: u32, reference: i64, tz: &Tz) -> Option<i64> {
    if reference <= 0 || day == 0 {
        return None;
    }
    let local_reference = reference.checked_add(tz.offset_at(reference) as i64)?;
    let latest = reference.checked_add(86_400)?;
    let (mut year, _, _) = civil_from_days(local_reference.div_euclid(86_400));
    for _ in 0..8 {
        let valid_day = match month {
            2 => day <= if is_leap(year) { 29 } else { 28 },
            4 | 6 | 9 | 11 => day <= 30,
            _ => day <= 31,
        };
        if valid_day {
            let utc = tz.to_utc(secs_from_civil(year, month, day, hour, min, sec)?);
            if utc <= latest {
                return Some(utc);
            }
        }
        year -= 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAR_10_2024: i64 = 1_710_028_800; // 2024-03-10T00:00:00Z

    #[test]
    fn picks_the_reference_year_or_the_one_before() {
        let utc = Tz::utc();
        assert_eq!(utc_without_year(3, 9, 12, 0, 0, MAR_10_2024, &utc), Some(MAR_10_2024 - 43_200));
        // December lines in a file last written in March belong to the previous year.
        assert_eq!(utc_without_year(12, 31, 0, 0, 0, MAR_10_2024, &utc), Some(1_703_980_800));
        // Up to a day after the reference is tolerated (clock skew, zone guesses).
        assert_eq!(utc_without_year(3, 10, 23, 0, 0, MAR_10_2024, &utc), Some(MAR_10_2024 + 82_800));
    }

    #[test]
    fn leap_days_fall_back_to_a_leap_year() {
        let utc = Tz::utc();
        let feb_2025 = 1_738_368_000; // 2025-02-01T00:00:00Z
        assert_eq!(utc_without_year(2, 29, 0, 0, 0, feb_2025, &utc), Some(1_709_164_800));
        // 2024-02-29
    }

    #[test]
    fn rejects_missing_reference_and_bad_dates() {
        let utc = Tz::utc();
        assert_eq!(utc_without_year(3, 9, 12, 0, 0, 0, &utc), None);
        assert_eq!(utc_without_year(3, 9, 12, 0, 0, i64::MAX, &utc), None);
        assert_eq!(utc_without_year(4, 31, 0, 0, 0, MAR_10_2024, &utc), None);
        assert_eq!(utc_without_year(13, 1, 0, 0, 0, MAR_10_2024, &utc), None);
        assert_eq!(utc_without_year(1, 0, 0, 0, 0, MAR_10_2024, &utc), None);
    }
}

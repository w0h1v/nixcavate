//! Timestamps: a UTC instant plus what we know about its precision and origin.

use serde::{Serialize, Serializer};

pub const NANOS_PER_SEC: i64 = 1_000_000_000;
const SECS_PER_DAY: i64 = 86_400;

/// The resolution of the source value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Precision {
    Nanos = 0,
    Micros = 1,
    Millis = 2,
    Seconds = 3,
    Day = 4,
}

/// How the UTC instant was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Basis {
    /// The source records a complete instant (epoch value or date with zone).
    Recorded = 0,
    /// The source has no year; it was inferred from the file's modification time.
    InferredYear = 1,
    /// The source has no zone; the host zone (or UTC when unknown) was assumed.
    AssumedZone = 2,
    /// Both the year and the zone were filled in (classic syslog).
    InferredYearAssumedZone = 3,
}

impl Precision {
    pub fn as_str(self) -> &'static str {
        match self {
            Precision::Nanos => "nanos",
            Precision::Micros => "micros",
            Precision::Millis => "millis",
            Precision::Seconds => "seconds",
            Precision::Day => "day",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        [Self::Nanos, Self::Micros, Self::Millis, Self::Seconds, Self::Day].get(v as usize).copied()
    }

    fn fraction_digits(self) -> usize {
        match self {
            Precision::Nanos => 9,
            Precision::Micros => 6,
            Precision::Millis => 3,
            Precision::Seconds | Precision::Day => 0,
        }
    }
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Recorded => "recorded",
            Basis::InferredYear => "inferred_year",
            Basis::AssumedZone => "assumed_zone",
            Basis::InferredYearAssumedZone => "inferred_year_assumed_zone",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        [Self::Recorded, Self::InferredYear, Self::AssumedZone, Self::InferredYearAssumedZone].get(v as usize).copied()
    }
}

impl Serialize for Precision {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl Serialize for Basis {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A UTC instant. It cannot be built without stating its precision and basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Nanoseconds since the Unix epoch, UTC.
    pub utc: i64,
    pub precision: Precision,
    pub basis: Basis,
}

impl Timestamp {
    pub fn new(utc_nanos: i64, precision: Precision, basis: Basis) -> Self {
        Self { utc: utc_nanos, precision, basis }
    }

    pub fn from_secs(secs: i64, basis: Basis) -> Self {
        Self::new(secs.saturating_mul(NANOS_PER_SEC), Precision::Seconds, basis)
    }

    pub fn from_millis(millis: i64, basis: Basis) -> Self {
        Self::new(millis.saturating_mul(1_000_000), Precision::Millis, basis)
    }

    pub fn from_micros(micros: i64, basis: Basis) -> Self {
        Self::new(micros.saturating_mul(1_000), Precision::Micros, basis)
    }

    pub fn from_nanos(nanos: i64, basis: Basis) -> Self {
        Self::new(nanos, Precision::Nanos, basis)
    }

    /// Seconds plus a sub-second part given in nanoseconds.
    pub fn from_secs_nanos(secs: i64, nanos: u32, precision: Precision, basis: Basis) -> Self {
        Self::new(secs.saturating_mul(NANOS_PER_SEC).saturating_add(nanos as i64), precision, basis)
    }

    /// Like [`Timestamp::from_secs_nanos`], but `None` when the instant does not fit: an i64
    /// of nanoseconds spans 1677 to 2262. Use this for values read from untrusted fields,
    /// where a saturated time would look like a real (and recorded) date.
    pub fn checked(secs: i64, nanos: u32, precision: Precision, basis: Basis) -> Option<Self> {
        let utc = secs.checked_mul(NANOS_PER_SEC)?.checked_add(nanos as i64)?;
        Some(Self::new(utc, precision, basis))
    }

    /// A timestamp from fractional seconds since the Unix epoch, as SQLite REAL columns and
    /// Apple absolute times hold them. `None` for NaN, infinities and out-of-range values.
    /// The fraction is good to about a microsecond.
    pub fn from_secs_f64(secs: f64, precision: Precision, basis: Basis) -> Option<Self> {
        // Whole seconds and the fraction are converted apart: together they would not fit
        // the 53 bits of an f64 and the fraction would be rounded away.
        let whole = secs.floor();
        if !(whole > -1e10 && whole < 1e10) {
            return None;
        }
        let nanos = ((secs - whole) * NANOS_PER_SEC as f64).round().min(999_999_999.0) as u32;
        Self::checked(whole as i64, nanos, precision, basis)
    }

    /// Midnight UTC of a day count since the Unix epoch (`shadow` ages).
    pub fn from_days(days: i64, basis: Basis) -> Self {
        Self::new(days.saturating_mul(SECS_PER_DAY * NANOS_PER_SEC), Precision::Day, basis)
    }

    /// Writes RFC 3339 in UTC, with as many fraction digits as the precision carries.
    pub fn format(&self, buf: &mut TimeBuf) -> usize {
        format_rfc3339(self.utc, self.precision.fraction_digits(), buf)
    }

    pub fn to_rfc3339(&self) -> String {
        let mut buf = [0u8; 30];
        let n = self.format(&mut buf);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 30];
        let n = self.format(&mut buf);
        // The formatter only writes ASCII.
        s.serialize_str(std::str::from_utf8(&buf[..n]).unwrap_or_default())
    }
}

/// Large enough for `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`.
pub type TimeBuf = [u8; 30];

/// Days since the Unix epoch for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`]: `(year, month, day)`.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Seconds since the epoch for a civil date and time, with no zone applied.
/// Returns `None` when a field is out of range.
pub fn secs_from_civil(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => return None,
    };
    // Second 60 is accepted so that a recorded leap second still parses.
    if day == 0 || day > days_in_month || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // The years an i64 of nanoseconds can hold in full; anything else would saturate.
    if !(1678..=2261).contains(&year) {
        return None;
    }
    Some(days_from_civil(year, month, day) * SECS_PER_DAY + (hour * 3600 + min * 60 + sec) as i64)
}

fn format_rfc3339(utc_nanos: i64, fraction_digits: usize, buf: &mut TimeBuf) -> usize {
    let secs = utc_nanos.div_euclid(NANOS_PER_SEC);
    let nanos = utc_nanos.rem_euclid(NANOS_PER_SEC) as u32;
    let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
    let tod = secs.rem_euclid(SECS_PER_DAY) as u32;
    // An i64 of nanoseconds spans the years 1677 to 2262, so the year has four digits.
    put_digits(&mut buf[0..4], year as u32);
    buf[4] = b'-';
    put_digits(&mut buf[5..7], month);
    buf[7] = b'-';
    put_digits(&mut buf[8..10], day);
    buf[10] = b'T';
    put_digits(&mut buf[11..13], tod / 3600);
    buf[13] = b':';
    put_digits(&mut buf[14..16], tod / 60 % 60);
    buf[16] = b':';
    put_digits(&mut buf[17..19], tod % 60);
    let mut n = 19;
    if fraction_digits > 0 {
        buf[n] = b'.';
        let mut digits = [0u8; 9];
        put_digits(&mut digits, nanos);
        buf[n + 1..n + 1 + fraction_digits].copy_from_slice(&digits[..fraction_digits]);
        n += 1 + fraction_digits;
    }
    buf[n] = b'Z';
    n + 1
}

fn put_digits(out: &mut [u8], mut value: u32) {
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
}

/// Parses a run of ASCII digits. Rejects empty input, non-digits and overflow.
pub fn parse_uint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &b| {
        if b.is_ascii_digit() {
            acc.checked_mul(10)?.checked_add((b - b'0') as u64)
        } else {
            None
        }
    })
}

/// A date and time parsed from text, before any zone decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedTime {
    /// Seconds since the epoch. UTC when `offset` is `Some`, otherwise local wall time.
    pub secs: i64,
    pub nanos: u32,
    pub precision: Precision,
    /// The zone offset in seconds east of UTC, when the text carried one.
    pub offset: Option<i32>,
}

impl ParsedTime {
    /// The timestamp when the text carried a zone.
    pub fn recorded(&self) -> Option<Timestamp> {
        self.offset.map(|_| Timestamp::from_secs_nanos(self.secs, self.nanos, self.precision, Basis::Recorded))
    }
}

/// Parses `YYYY-MM-DD[T| ]HH:MM:SS[.fraction][Z|±HH[:]MM]` from the start of `text`.
/// Returns the parsed time and the number of bytes consumed.
///
/// With a zone, `secs` is already UTC. Without one, `secs` is wall time and the
/// caller must apply the host zone and mark the result `AssumedZone`.
pub fn parse_iso8601(text: &[u8]) -> Option<(ParsedTime, usize)> {
    if text.len() < 19 || text[4] != b'-' || text[7] != b'-' || text[13] != b':' || text[16] != b':' {
        return None;
    }
    if text[10] != b'T' && text[10] != b' ' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| parse_uint(&text[range]).map(|v| v as u32);
    let mut secs =
        secs_from_civil(num(0..4)? as i64, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?)?;
    let mut pos = 19;
    let mut nanos = 0u32;
    let mut precision = Precision::Seconds;
    if matches!(text.get(pos), Some(b'.' | b',')) {
        let digits = text[pos + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        let used = digits.min(9);
        nanos = parse_uint(&text[pos + 1..pos + 1 + used])? as u32 * 10u32.pow(9 - used as u32);
        precision = match digits {
            1..=3 => Precision::Millis,
            4..=6 => Precision::Micros,
            _ => Precision::Nanos,
        };
        pos += 1 + digits;
    }
    let offset = match text.get(pos) {
        Some(b'Z' | b'z') => {
            pos += 1;
            Some(0)
        }
        Some(&sign @ (b'+' | b'-')) => {
            let rest = &text[pos + 1..];
            let hours = parse_uint(rest.get(0..2)?)? as i32;
            let (minutes, len) = match rest.get(2) {
                Some(b':') => (parse_uint(rest.get(3..5)?)? as i32, 5),
                Some(b) if b.is_ascii_digit() => (parse_uint(rest.get(2..4)?)? as i32, 4),
                _ => (0, 2),
            };
            if hours > 23 || minutes > 59 {
                return None;
            }
            pos += 1 + len;
            let east = hours * 3600 + minutes * 60;
            Some(if sign == b'-' { -east } else { east })
        }
        _ => None,
    };
    if let Some(east) = offset {
        secs -= east as i64;
    }
    Some((ParsedTime { secs, nanos, precision, offset }, pos))
}

/// The month number for an English three-letter abbreviation (`Jan` is 1).
pub fn month_from_abbrev(name: &[u8]) -> Option<u32> {
    const MONTHS: [&[u8; 3]; 12] =
        [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];
    let name = name.get(..3)?;
    MONTHS.iter().position(|m| m.eq_ignore_ascii_case(name)).map(|i| i as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        for days in [-719_468, -1, 0, 1, 59, 60, 11_016, 19_723, 20_000, 100_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 2, 29), 11_016);
    }

    #[test]
    fn formats_each_precision() {
        let nanos = 1_700_000_000 * NANOS_PER_SEC + 123_456_789;
        let text = |p| Timestamp::new(nanos, p, Basis::Recorded).to_rfc3339();
        assert_eq!(text(Precision::Nanos), "2023-11-14T22:13:20.123456789Z");
        assert_eq!(text(Precision::Micros), "2023-11-14T22:13:20.123456Z");
        assert_eq!(text(Precision::Millis), "2023-11-14T22:13:20.123Z");
        assert_eq!(text(Precision::Seconds), "2023-11-14T22:13:20Z");
        assert_eq!(Timestamp::from_days(19_723, Basis::Recorded).to_rfc3339(), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn checked_constructors_reject_what_would_saturate() {
        let ok = Timestamp::checked(1_700_000_000, 5, Precision::Nanos, Basis::Recorded).unwrap();
        assert_eq!(ok.to_rfc3339(), "2023-11-14T22:13:20.000000005Z");
        assert!(Timestamp::checked(50_000_000_000, 0, Precision::Seconds, Basis::Recorded).is_none());
        assert!(Timestamp::checked(i64::MIN, 0, Precision::Seconds, Basis::Recorded).is_none());
        let real = Timestamp::from_secs_f64(1_700_000_000.25, Precision::Micros, Basis::Recorded).unwrap();
        assert_eq!(real.to_rfc3339(), "2023-11-14T22:13:20.250000Z");
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e300, -1e300, 5e10, -5e10] {
            assert!(Timestamp::from_secs_f64(bad, Precision::Seconds, Basis::Recorded).is_none(), "{bad}");
        }
    }

    #[test]
    fn formats_before_the_epoch() {
        assert_eq!(Timestamp::from_nanos(-1, Basis::Recorded).to_rfc3339(), "1969-12-31T23:59:59.999999999Z");
    }

    #[test]
    fn parses_iso8601_variants() {
        let (t, n) = parse_iso8601(b"2024-03-10T01:02:03.250+02:00 rest").unwrap();
        assert_eq!(
            (t.secs, t.nanos, t.precision, t.offset, n),
            (1_710_025_323, 250_000_000, Precision::Millis, Some(7200), 29)
        );
        let (t, _) = parse_iso8601(b"2024-03-10 01:02:03").unwrap();
        assert_eq!((t.secs, t.offset), (1_710_032_523, None));
        assert!(t.recorded().is_none());
        let (t, n) = parse_iso8601(b"2024-03-10T01:02:03.123456789Z").unwrap();
        assert_eq!((t.nanos, t.precision, n), (123_456_789, Precision::Nanos, 30));
        let (t, _) = parse_iso8601(b"2024-03-10T01:02:03-0530").unwrap();
        assert_eq!(t.offset, Some(-19_800));
        assert!(parse_iso8601(b"2024-13-10T01:02:03Z").is_none());
        assert!(parse_iso8601(b"2024-02-30T01:02:03Z").is_none(), "no such day");
        assert!(parse_iso8601(b"2023-02-29T01:02:03Z").is_none(), "not a leap year");
        assert!(parse_iso8601(b"2024-02-29T01:02:03Z").is_some());
        assert!(parse_iso8601(b"9999-01-01T00:00:00Z").is_none(), "would saturate");
        assert!(parse_iso8601(b"not a date at all!!").is_none());
    }

    #[test]
    fn month_names() {
        assert_eq!(month_from_abbrev(b"Jan"), Some(1));
        assert_eq!(month_from_abbrev(b"dec 5"), Some(12));
        assert_eq!(month_from_abbrev(b"Xyz"), None);
        assert_eq!(month_from_abbrev(b"Ja"), None);
    }
}

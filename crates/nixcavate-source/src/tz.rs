//! Host time zone support: converts local wall-clock seconds to UTC using a TZif file
//! (RFC 8536) and its POSIX TZ footer. Depends on `std` only.

/// A transition date rule from a POSIX TZ string.
#[derive(Clone, Debug)]
struct Spec {
    kind: u8, // b'M', b'J' or b'N'
    m: i64,
    w: i64,
    d: i64,
    time: i64,
}

/// A parsed POSIX TZ string. Offsets are seconds east of UTC.
#[derive(Clone, Debug)]
struct Rule {
    std: i32,
    dst: Option<(i32, Spec, Spec)>,
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn year_of_days(days: i64) -> i64 {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + if mp >= 10 { 1 } else { 0 }
}

impl Spec {
    /// Local wall-clock seconds (as if UTC) at which this rule fires in `year`.
    fn local_secs(&self, year: i64) -> i64 {
        let jan1 = days_from_civil(year, 1, 1);
        let days = match self.kind {
            b'M' => {
                let first = days_from_civil(year, self.m, 1);
                let dow = (first + 4).rem_euclid(7);
                let mut day = 1 + (self.d - dow).rem_euclid(7) + (self.w - 1) * 7;
                let mlen = match self.m {
                    2 if is_leap(year) => 29,
                    2 => 28,
                    4 | 6 | 9 | 11 => 30,
                    _ => 31,
                };
                while day > mlen {
                    day -= 7;
                }
                first + day - 1
            }
            b'J' => jan1 + self.m - 1 + i64::from(is_leap(year) && self.m >= 60),
            _ => jan1 + self.m,
        };
        days * 86400 + self.time
    }
}

impl Rule {
    fn offset_at(&self, t: i64) -> i32 {
        let Some((dst, start, end)) = &self.dst else { return self.std };
        let year = year_of_days(t.saturating_add(i64::from(self.std)).div_euclid(86400));
        let s = start.local_secs(year) - i64::from(self.std);
        let e = end.local_secs(year) - i64::from(*dst);
        let in_dst = if s < e { t >= s && t < e } else { t >= s || t < e };
        if in_dst {
            *dst
        } else {
            self.std
        }
    }
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        let ok = self.peek() == Some(c);
        if ok {
            self.i += 1;
        }
        ok
    }
    fn name(&mut self) -> Option<()> {
        let start = self.i;
        if self.eat(b'<') {
            while self.peek()? != b'>' {
                self.i += 1;
            }
            self.i += 1;
            return (self.i - start > 2).then_some(());
        }
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.i += 1;
        }
        (self.i - start >= 3).then_some(())
    }
    fn num(&mut self, max: i64) -> Option<i64> {
        let start = self.i;
        let mut v: i64 = 0;
        while let Some(c) = self.peek().filter(u8::is_ascii_digit) {
            v = v * 10 + i64::from(c - b'0');
            if v > max {
                return None;
            }
            self.i += 1;
        }
        (self.i > start).then_some(v)
    }
    /// `[+-]hh[:mm[:ss]]` in seconds, hours up to 167 (RFC 9636 extended range).
    fn hms(&mut self) -> Option<i64> {
        let sign = if self.eat(b'-') {
            -1
        } else {
            self.eat(b'+');
            1
        };
        let mut secs = self.num(167)? * 3600;
        if self.eat(b':') {
            secs += self.num(59)? * 60;
            if self.eat(b':') {
                secs += self.num(59)?;
            }
        }
        Some(sign * secs)
    }
    fn spec(&mut self) -> Option<Spec> {
        let mut sp = Spec { kind: b'N', m: 0, w: 0, d: 0, time: 7200 };
        if self.eat(b'M') {
            sp.kind = b'M';
            sp.m = self.num(12).filter(|&m| m >= 1)?;
            self.eat(b'.').then_some(())?;
            sp.w = self.num(5).filter(|&w| w >= 1)?;
            self.eat(b'.').then_some(())?;
            sp.d = self.num(6)?;
        } else if self.eat(b'J') {
            sp.kind = b'J';
            sp.m = self.num(365).filter(|&n| n >= 1)?;
        } else {
            sp.m = self.num(365)?;
        }
        if self.eat(b'/') {
            sp.time = self.hms()?;
        }
        Some(sp)
    }
}

/// Parses a POSIX TZ string such as `EST5EDT,M3.2.0,M11.1.0`. POSIX offsets are west-positive.
fn parse_posix(s: &str) -> Option<Rule> {
    let mut p = P { s: s.as_bytes(), i: 0 };
    p.name()?;
    let std = i32::try_from(-p.hms()?).ok()?;
    if p.peek().is_none() {
        return Some(Rule { std, dst: None });
    }
    p.name()?;
    let dst = if matches!(p.peek(), None | Some(b',')) { std + 3600 } else { i32::try_from(-p.hms()?).ok()? };
    let (a, b) = if p.eat(b',') {
        let a = p.spec()?;
        p.eat(b',').then_some(())?;
        (a, p.spec()?)
    } else {
        // POSIX leaves this implementation-defined; use the common US default.
        let mut q = P { s: b"M3.2.0,M11.1.0", i: 0 };
        let a = q.spec()?;
        q.eat(b',');
        (a, q.spec()?)
    };
    (p.peek().is_none()).then_some(Rule { std, dst: Some((dst, a, b)) })
}

/// A host time zone: UTC offsets over time.
#[derive(Clone, Debug)]
pub struct Tz {
    trans: Vec<i64>,
    /// Offset (seconds east) in effect after each transition.
    after: Vec<i32>,
    /// Offset in effect before the first transition.
    first: i32,
    rule: Option<Rule>,
    fallback: bool,
}

fn be(b: &[u8], pos: usize, n: usize) -> Option<i64> {
    let s = b.get(pos..pos.checked_add(n)?)?;
    let mut v = i64::from(s[0] as i8);
    for &x in &s[1..] {
        v = (v << 8) | i64::from(x);
    }
    Some(v)
}

impl Tz {
    /// UTC, used when the host zone is unknown.
    pub fn utc() -> Tz {
        Tz { trans: Vec::new(), after: Vec::new(), first: 0, rule: None, fallback: true }
    }

    /// A zone from a POSIX TZ string such as `CST6CDT,M3.2.0,M11.1.0` (what AIX keeps in
    /// `/etc/environment`). `None` when the string does not parse.
    pub fn from_posix(spec: &str) -> Option<Tz> {
        let rule = parse_posix(spec)?;
        let mut tz = Tz { trans: Vec::new(), after: Vec::new(), first: rule.std, rule: Some(rule), fallback: false };
        tz.materialize_rule();
        Some(tz)
    }

    /// Parses TZif (RFC 8536) version 1, 2, 3 or 4. Returns None for anything malformed. Never panics on any input.
    pub fn parse(tzif: &[u8]) -> Option<Tz> {
        if tzif.get(..4)? != b"TZif" || !matches!(*tzif.get(4)?, 0 | b'2' | b'3' | b'4') {
            return None;
        }
        // Header counts: isut, isstd, leap, time, type, char; returns (counts, data block length).
        let header = |at: usize, t: usize| -> Option<([usize; 6], usize)> {
            let mut c = [0usize; 6];
            for (i, slot) in c.iter_mut().enumerate() {
                *slot = usize::try_from(be(tzif, at.checked_add(20 + 4 * i)?, 4)? as u32).ok()?;
            }
            let len = c[3]
                .checked_mul(t + 1)?
                .checked_add(c[4].checked_mul(6)?)?
                .checked_add(c[5])?
                .checked_add(c[2].checked_mul(t + 4)?)?
                .checked_add(c[1])?
                .checked_add(c[0])?;
            Some((c, len))
        };
        let (mut at, mut t) = (0usize, 4usize);
        let (mut c, mut len) = header(at, t)?;
        if tzif[4] != 0 {
            at = 44usize.checked_add(len)?;
            t = 8;
            (c, len) = header(at, t)?;
        }
        let body = at.checked_add(44)?;
        let end = body.checked_add(len)?;
        let data = tzif.get(body..end)?;
        let (timecnt, typecnt) = (c[3], c[4]);
        if typecnt == 0 {
            return None;
        }
        let types_at = timecnt * (t + 1); // cannot overflow: already bounded by `len`
        let mut types = Vec::with_capacity(typecnt);
        for i in 0..typecnt {
            let off = be(data, types_at + 6 * i, 4)?;
            if off == i64::from(i32::MIN) {
                return None;
            }
            types.push((off as i32, *data.get(types_at + 6 * i + 4)? != 0));
        }
        let mut trans = Vec::with_capacity(timecnt);
        let mut after = Vec::with_capacity(timecnt);
        for i in 0..timecnt {
            trans.push(be(data, i * t, t)?);
            after.push(types.get(usize::from(*data.get(timecnt * t + i)?))?.0);
        }
        let first = types.iter().find(|x| !x.1).unwrap_or(&types[0]).0;
        let rule = if tzif[4] != 0 {
            let rest = tzif.get(end..)?;
            rest.strip_prefix(b"\n")
                .and_then(|r| r.split(|&b| b == b'\n').next())
                .and_then(|f| std::str::from_utf8(f).ok())
                .and_then(parse_posix)
        } else {
            None
        };
        let mut tz = Tz { trans, after, first, rule, fallback: false };
        tz.materialize_rule();
        Some(tz)
    }

    /// Appends the footer rule's transitions through 2100 to the table. A rule lookup does
    /// calendar math; with this, every lookup in that range is one binary search, which
    /// matters because zone-less logs need one per line.
    fn materialize_rule(&mut self) {
        let Some(Rule { std, dst: Some((dst, start, end)) }) = &self.rule else { return };
        let mut last = self.trans.last().copied();
        if last.is_none() {
            // A rule-only zone: what holds before the first rule transition we add.
            self.first = self.rule.as_ref().map_or(self.first, |r| r.offset_at(-1));
        }
        for year in year_of_days(last.unwrap_or(0).div_euclid(86400)).max(1970)..=2100 {
            let mut pair =
                [(start.local_secs(year) - i64::from(*std), *dst), (end.local_secs(year) - i64::from(*dst), *std)];
            pair.sort_unstable();
            for (at, offset) in pair {
                if last.is_none_or(|l| at > l) {
                    self.trans.push(at);
                    self.after.push(offset);
                    last = Some(at);
                }
            }
        }
    }

    /// Seconds east of UTC in effect at the UTC instant `utc_secs`.
    pub fn offset_at(&self, utc_secs: i64) -> i32 {
        let n = self.trans.partition_point(|&x| x <= utc_secs);
        if n == 0 {
            return self.first;
        }
        if n == self.trans.len() {
            if let Some(r) = &self.rule {
                return r.offset_at(utc_secs);
            }
        }
        self.after[n - 1]
    }

    /// Converts local wall-clock seconds (a civil time encoded as if it were UTC) to UTC seconds.
    ///
    /// In a DST gap (the local time never occurred) or overlap (it occurred twice), the earlier offset, the one
    /// in effect before the transition, is used.
    pub fn to_utc(&self, local_secs: i64) -> i64 {
        let before = self.offset_at(local_secs.saturating_sub(86400));
        let after = self.offset_at(local_secs.saturating_add(86400));
        let c1 = local_secs.saturating_sub(i64::from(before));
        let c2 = local_secs.saturating_sub(i64::from(after));
        if before != after && self.offset_at(c1) != before && self.offset_at(c2) == after {
            c2
        } else {
            c1
        }
    }

    /// True when this is the UTC fallback (no transitions, zero offset, built by `utc()`).
    pub fn is_utc_fallback(&self) -> bool {
        self.fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(ver: u8, wide: bool, trans: &[(i64, u8)], types: &[(i32, bool)]) -> Vec<u8> {
        let mut v = b"TZif".to_vec();
        v.push(ver);
        v.extend([0u8; 15]);
        for n in [0, 0, 0, trans.len(), types.len(), 1] {
            v.extend((n as u32).to_be_bytes());
        }
        for (t, _) in trans {
            if wide {
                v.extend(t.to_be_bytes());
            } else {
                v.extend((*t as i32).to_be_bytes());
            }
        }
        v.extend(trans.iter().map(|x| x.1));
        for (off, dst) in types {
            v.extend(off.to_be_bytes());
            v.extend([*dst as u8, 0]);
        }
        v.push(0);
        v
    }

    fn file(v2: bool, trans: &[(i64, u8)], types: &[(i32, bool)], footer: &str) -> Vec<u8> {
        if !v2 {
            return block(0, false, trans, types);
        }
        let mut v = block(b'2', false, &[], types);
        v.extend(block(b'2', true, trans, types));
        v.extend(format!("\n{footer}\n").bytes());
        v
    }

    const NY: &str = "EST5EDT,M3.2.0,M11.1.0";

    #[test]
    fn utc_fallback() {
        let tz = Tz::utc();
        assert!(tz.is_utc_fallback());
        assert_eq!((tz.offset_at(123), tz.to_utc(123)), (0, 123));
        let parsed = Tz::parse(&file(false, &[], &[(0, false)], "")).unwrap();
        assert!(!parsed.is_utc_fallback());
    }

    #[test]
    fn fixed_offset() {
        let tz = Tz::parse(&file(true, &[], &[(10800, false)], "<+03>-3")).unwrap();
        assert_eq!(tz.offset_at(0), 10800);
        assert_eq!(tz.to_utc(10800), 0);
        let tz = Tz::parse(&file(false, &[], &[(-3600, false)], "")).unwrap();
        assert_eq!(tz.offset_at(i64::MAX), -3600);
    }

    #[test]
    fn transitions_v1_and_v2() {
        let types = [(3600, false), (7200, true)];
        let trans = [(1000, 1), (2000, 0)];
        for v2 in [false, true] {
            let tz = Tz::parse(&file(v2, &trans, &types, "")).unwrap();
            assert_eq!(tz.offset_at(999), 3600);
            assert_eq!(tz.offset_at(1000), 7200);
            assert_eq!(tz.offset_at(1999), 7200);
            assert_eq!(tz.offset_at(2000), 3600);
            assert_eq!(tz.offset_at(1_000_000), 3600);
        }
        // Footer takes over after the last transition.
        let tz = Tz::parse(&file(true, &trans, &types, "<+09>-9")).unwrap();
        assert_eq!((tz.offset_at(1500), tz.offset_at(2000)), (7200, 32400));
    }

    #[test]
    fn footer_only_dst() {
        let tz = Tz::parse(&file(true, &[], &[(-18000, false)], NY)).unwrap();
        assert_eq!(tz.offset_at(1710054000 - 1), -18000);
        assert_eq!(tz.offset_at(1710054000), -14400);
        assert_eq!(tz.offset_at(1730613600 - 1), -14400);
        assert_eq!(tz.offset_at(1730613600), -18000);
    }

    #[test]
    fn southern_and_extended_hours() {
        let tz = Tz::parse(&file(true, &[], &[(36000, false)], "AEST-10AEDT,M10.1.0,M4.1.0/3")).unwrap();
        assert_eq!(tz.offset_at(1704067200), 39600); // 2024-01-01
        assert_eq!(tz.offset_at(1719792000), 36000); // 2024-07-01
        let tz = Tz::parse(&file(true, &[], &[(-10800, false)], "<-03>3<-02>,M3.5.0/-2,M10.5.0/-1")).unwrap();
        assert_eq!(tz.offset_at(1704067200), -10800);
        assert_eq!(tz.offset_at(1719792000), -7200);
    }

    #[test]
    fn julian_rules() {
        let r = parse_posix("XXX0YYY,J60/0,300").unwrap();
        let jan1_2023 = days_from_civil(2023, 1, 1) * 86400;
        assert_eq!(r.offset_at(jan1_2023 + 59 * 86400 - 1), 0); // J60 = Mar 1 in non-leap years
        assert_eq!(r.offset_at(jan1_2023 + 59 * 86400), 3600);
        assert_eq!(r.offset_at(jan1_2023 + 300 * 86400 + 3599), 3600); // rule 300 ends 02:00 DST = +3600 UTC
        assert_eq!(r.offset_at(jan1_2023 + 300 * 86400 + 3600), 0);
        assert!(parse_posix("EST5EDT,M13.1.0,M11.1.0").is_none());
        assert!(parse_posix("EST").is_none());
    }

    #[test]
    fn to_utc_behavior() {
        let tz = Tz::parse(&file(true, &[], &[(-18000, false)], NY)).unwrap();
        let noon = days_from_civil(2024, 7, 1) * 86400 + 43200;
        assert_eq!(tz.to_utc(noon), noon + 14400);
        assert_eq!(tz.to_utc(noon - 180 * 86400), noon - 180 * 86400 + 18000);
        for t in [noon, noon + 86400 * 100, noon - 86400 * 150] {
            let u = tz.to_utc(t);
            assert_eq!(u + i64::from(tz.offset_at(u)), t);
        }
        // Gap: 02:30 on 2024-03-10 never happened; earlier offset (EST) applies.
        let gap = 1710054000 - 18000 + 1800;
        assert_eq!(tz.to_utc(gap), gap + 18000);
        // Overlap: 01:30 on 2024-11-03 happened twice; earlier offset (EDT) applies.
        let ov = 1730613600 - 18000 + 1800 - 3600;
        assert_eq!(tz.to_utc(ov), ov + 14400);
        assert_eq!(tz.to_utc(i64::MIN), tz.to_utc(i64::MIN)); // no panic
        let _ = tz.to_utc(i64::MAX);
    }

    #[test]
    fn malformed_input() {
        let full = file(true, &[(1000, 1)], &[(3600, false), (7200, true)], NY);
        assert!(Tz::parse(&full).is_some());
        for n in 0..full.len() {
            let _ = Tz::parse(&full[..n]);
        }
        assert!(Tz::parse(&full[..full.len() - 100]).is_none());
        assert!(Tz::parse(b"").is_none());
        assert!(Tz::parse(b"not a tzif file at all, really not, no way, nope nope").is_none());
        let mut huge = full.clone();
        huge[20..44].fill(0xff);
        assert!(Tz::parse(&huge).is_none());
        let mut bad_idx = file(false, &[(1000, 5)], &[(3600, false)], "");
        assert!(Tz::parse(&bad_idx).is_none());
        bad_idx[4] = b'9';
        assert!(Tz::parse(&bad_idx).is_none());
    }

    /// The precomputed table must agree with the rule itself, here on the analyst machine's
    /// own zone database when it has one.
    #[test]
    fn materialized_rule_matches_real_zones() {
        for (zone, winter, summer) in
            [("America/New_York", -18000, -14400), ("Europe/Berlin", 3600, 7200), ("Asia/Tokyo", 32400, 32400)]
        {
            let Ok(bytes) = std::fs::read(format!("/usr/share/zoneinfo/{zone}")) else { continue };
            let tz = Tz::parse(&bytes).unwrap();
            for year in [2024i64, 2026, 2090, 2150] {
                let jan15 = days_from_civil(year, 1, 15) * 86400 + 43200;
                let jul15 = days_from_civil(year, 7, 15) * 86400 + 43200;
                assert_eq!((tz.offset_at(jan15), tz.offset_at(jul15)), (winter, summer), "{zone} {year}");
                assert_eq!(tz.to_utc(jul15 + i64::from(summer)), jul15, "{zone} {year}");
            }
        }
    }
}

//! Failed-login counters kept by PAM modules and shadow, one artifact per format:
//!
//! * `faillock`: `var/run/faillock/<user>` (also `run/faillock`, `var/log/faillock`), written by
//!   `pam_faillock`. One file per user, an array of 64-byte `struct tally` (a 52-byte source,
//!   2 reserved, a 16-bit status, a 64-bit time), one per failed attempt. Reference: Linux-PAM
//!   `modules/pam_faillock/faillock.h` and `faillock(8)`.
//! * `tallylog`: `var/log/tallylog`, written by `pam_tally2` (Linux-PAM before 1.5). Indexed by
//!   UID, one 64-byte `struct tallylog` per UID (a 52-byte line, 2 reserved, a 16-bit count, a
//!   64-bit time of the last failure). Reference: `modules/pam_tally2/tallylog.h`.
//! * `faillog`: `var/log/faillog`, written by `pam_tally`. Indexed by UID, one `struct faillog`
//!   from shadow's `faillog(5)`: a 16-bit count and limit, a 12-byte line, a time and a lock time.
//!   The times are `time_t` and `long`, so records are 32 bytes on 64-bit systems and 24 on
//!   32-bit ones, and big-endian on s390x and older PowerPC. The file says none of this: the
//!   layout is chosen by the file length and, when that does not decide, by which one makes the
//!   records plausible, as for `lastlog`.
//!
//! None of these keeps the failed user's attempts as a log: faillock keeps the recent ones until
//! they are reset by a successful login, the other two only the latest.

use super::passwd_lookup;
use super::utmp::field;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const FAILLOCK: Artifact = Artifact::new(
    "faillock",
    "pam_faillock failed-login tallies",
    Category::Accounts,
    LINUX,
    &["var/run/faillock/*", "run/faillock/*", "var/log/faillock/*"],
    parse_faillock,
)
.companions(&["etc/passwd"]);

pub const TALLYLOG: Artifact = Artifact::new(
    "tallylog",
    "pam_tally2 failed-login counters (tallylog)",
    Category::Accounts,
    LINUX,
    &["var/log/tallylog"],
    parse_tallylog,
)
.companions(&["etc/passwd"]);

pub const FAILLOG: Artifact = Artifact::new(
    "faillog",
    "shadow failed-login counters (faillog)",
    Category::Accounts,
    LINUX,
    &["var/log/faillog"],
    parse_faillog,
)
.companions(&["etc/passwd"]);

const TALLY_RECORD: usize = 64;
const STATUS_VALID: u16 = 0x1;
const STATUS_RHOST: u16 = 0x2;
const STATUS_TTY: u16 = 0x4;

fn timestamp(secs: i64) -> Option<Timestamp> {
    Timestamp::checked(secs, 0, Precision::Seconds, Basis::Recorded)
}

/// Byte-order-aware reads from a record.
#[derive(Clone, Copy)]
struct Bytes<'a> {
    data: &'a [u8],
    big: bool,
}

impl Bytes<'_> {
    fn array<const N: usize>(&self, at: usize) -> [u8; N] {
        self.data.get(at..at + N).and_then(|b| <[u8; N]>::try_from(b).ok()).unwrap_or([0; N])
    }

    fn u16(&self, at: usize) -> u16 {
        let raw = self.array(at);
        if self.big {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        }
    }

    fn u64(&self, at: usize) -> u64 {
        let raw = self.array(at);
        if self.big {
            u64::from_be_bytes(raw)
        } else {
            u64::from_le_bytes(raw)
        }
    }

    fn i32(&self, at: usize) -> i32 {
        let raw = self.array(at);
        if self.big {
            i32::from_be_bytes(raw)
        } else {
            i32::from_le_bytes(raw)
        }
    }

    fn i64(&self, at: usize) -> i64 {
        self.u64(at) as i64
    }
}

/// True when the file's byte order is big-endian: the one under which more of the non-empty
/// records (at `time_at`, `wide` bytes) hold a time a failure could have had: this century and
/// not after the file was written.
fn is_big_endian(data: &[u8], size: usize, time_at: usize, wide: bool, mtime: i64) -> bool {
    let latest = if mtime > 0 { mtime.saturating_add(86_400) } else { 4_102_444_800 };
    let plausible = |big: bool| {
        data.chunks_exact(size)
            .filter(|r| r.iter().any(|&b| b != 0))
            .filter(|r| {
                let b = Bytes { data: r, big };
                let secs = if wide { b.i64(time_at) } else { i64::from(b.i32(time_at)) };
                (946_684_800..=latest).contains(&secs)
            })
            .count()
    };
    plausible(true) > plausible(false)
}

// ---- faillock ----

#[derive(Serialize)]
struct Failure<'a> {
    user: &'a str,
    uid: Option<u32>,
    time: Option<Timestamp>,
    /// `rhost` (a remote address or name), `tty`, or empty when neither flag is set.
    source_type: &'static str,
    source: Cow<'a, str>,
    /// False once the lock expired or the tally was cleared: the entry no longer counts.
    valid: bool,
}

impl Record for Failure<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = if self.source.is_empty() { String::new() } else { format!(" from {}", self.source) };
        let note = if self.valid { "" } else { " (no longer counted)" };
        let message = format!("failed login for {}{from}{note}", self.user);
        self.time.map(|ts| Event::new(ts, "failed_login", message)).into_iter()
    }
}

fn parse_faillock(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty tally file"));
    }
    let user = input.path.rsplit('/').next().unwrap_or("");
    let uid = passwd_lookup::by_name(input.host).get(user).copied();
    for (index, record) in data.chunks_exact(TALLY_RECORD).enumerate() {
        let b = Bytes { data: record, big: false };
        let status = b.u16(54);
        sink.emit(
            Loc::Offset(input.offset + (index * TALLY_RECORD) as u64),
            &Failure {
                user,
                uid,
                time: timestamp(b.u64(56) as i64),
                source_type: match (status & STATUS_RHOST != 0, status & STATUS_TTY != 0) {
                    (true, _) => "rhost",
                    (false, true) => "tty",
                    _ => "",
                },
                source: field(record.get(..52).unwrap_or(&[])),
                valid: status & STATUS_VALID != 0,
            },
        )?;
    }
    if data.len() % TALLY_RECORD != 0 {
        sink.warn(format!("size {} is not a multiple of {TALLY_RECORD}; trailing bytes ignored", data.len()));
    }
    Ok(())
}

// ---- tallylog ----

#[derive(Serialize)]
struct Tally<'a> {
    uid: u64,
    user: &'a str,
    failures: u16,
    /// The terminal or remote host of the last failure.
    last_source: Cow<'a, str>,
    last_failure: Option<Timestamp>,
}

impl Record for Tally<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { format!("uid {}", self.uid) } else { self.user.to_string() };
        let message = format!("{} failed login(s) for {who}; the last one from {}", self.failures, self.last_source);
        self.last_failure.map(|ts| Event::new(ts, "failed_login", message)).into_iter()
    }
}

fn parse_tallylog(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let big = is_big_endian(data, TALLY_RECORD, 56, true, input.mtime);
    let users = passwd_lookup::by_uid(input.host);
    // The file is sparse (index = UID): nearly every record is zero.
    for (uid, record) in data.chunks_exact(TALLY_RECORD).enumerate().filter(|(_, r)| r.iter().any(|&b| b != 0)) {
        let b = Bytes { data: record, big };
        let secs = b.i64(56);
        sink.emit(
            Loc::Offset(input.offset + (uid * TALLY_RECORD) as u64),
            &Tally {
                uid: uid as u64,
                user: u32::try_from(uid).ok().and_then(|u| users.get(&u)).map_or("", String::as_str),
                failures: b.u16(54),
                last_source: field(record.get(..52).unwrap_or(&[])),
                last_failure: if secs == 0 { None } else { timestamp(secs) },
            },
        )?;
    }
    if data.len() % TALLY_RECORD != 0 {
        sink.warn(format!("size {} is not a multiple of {TALLY_RECORD}; trailing bytes ignored", data.len()));
    }
    Ok(())
}

// ---- faillog ----

#[derive(Serialize)]
struct Faillog<'a> {
    uid: u64,
    user: &'a str,
    failures: i16,
    /// The failure limit set with `faillog -m`; 0 means none.
    max_failures: i16,
    line: Cow<'a, str>,
    last_failure: Option<Timestamp>,
    /// Seconds the account stays locked after a failure (`faillog -l`).
    lock_seconds: i64,
}

impl Record for Faillog<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { format!("uid {}", self.uid) } else { self.user.to_string() };
        let message = format!("{} failed login(s) for {who}; the last one on {}", self.failures, self.line);
        self.last_failure.map(|ts| Event::new(ts, "failed_login", message)).into_iter()
    }
}

/// Record sizes: 64-bit `time_t` and `long` (32 bytes), then 32-bit ones (24 bytes).
const FAILLOG_SIZES: [usize; 2] = [32, 24];

/// Under the right size every used record has a printable line field and a time a failure could
/// have had (this century, not after the file was written) in the right byte order; under the
/// wrong one the fields drift into each other. The score is used records that fit minus those
/// that do not, in the better of the two byte orders; an unset time is neutral.
fn faillog_score(data: &[u8], size: usize, mtime: i64) -> i64 {
    let latest = if mtime > 0 { mtime.saturating_add(86_400) } else { 4_102_444_800 };
    [false, true]
        .into_iter()
        .map(|big| {
            data.chunks_exact(size)
                .filter(|r| r.iter().any(|&b| b != 0))
                .map(|r| {
                    let b = Bytes { data: r, big };
                    let line = r.get(4..16).unwrap_or(&[]);
                    let text = line.get(..memchr::memchr(0, line).unwrap_or(line.len())).unwrap_or(&[]);
                    let secs = if size == FAILLOG_SIZES[0] { b.i64(16) } else { i64::from(b.i32(16)) };
                    match (text.iter().all(|c| c.is_ascii_graphic()), secs) {
                        (false, _) => -1,
                        (true, 0) => 0,
                        (true, t) if (946_684_800..=latest).contains(&t) => 1,
                        _ => -1,
                    }
                })
                .sum::<i64>()
        })
        .max()
        .unwrap_or(0)
}

fn parse_faillog(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let [wide, narrow] = FAILLOG_SIZES;
    let size = match (data.len() % wide == 0, data.len() % narrow == 0) {
        (true, false) => wide,
        (false, true) => narrow,
        _ if faillog_score(data, narrow, input.mtime) > faillog_score(data, wide, input.mtime) => narrow,
        _ => wide,
    };
    let is_wide = size == wide;
    let big = is_big_endian(data, size, 16, is_wide, input.mtime);
    let users = passwd_lookup::by_uid(input.host);
    for (uid, record) in data.chunks_exact(size).enumerate().filter(|(_, r)| r.iter().any(|&b| b != 0)) {
        let b = Bytes { data: record, big };
        let (secs, lock) = if is_wide { (b.i64(16), b.i64(24)) } else { (i64::from(b.i32(16)), i64::from(b.i32(20))) };
        sink.emit(
            Loc::Offset(input.offset + (uid * size) as u64),
            &Faillog {
                uid: uid as u64,
                user: u32::try_from(uid).ok().and_then(|u| users.get(&u)).map_or("", String::as_str),
                failures: b.u16(0) as i16,
                max_failures: b.u16(2) as i16,
                line: field(record.get(4..16).unwrap_or(&[])),
                last_failure: if secs == 0 { None } else { timestamp(secs) },
                lock_seconds: lock,
            },
        )?;
    }
    if data.len() % size != 0 {
        sink.warn(format!("size {} is not a multiple of {size}; trailing bytes ignored", data.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run_on_host};
    use nixcavate_core::time::secs_from_civil;
    use serde_json::Value;

    fn records(out: &str) -> Vec<Value> {
        out.lines()
            .take_while(|l| !l.starts_with("---"))
            .filter(|l| l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn on_host(artifact: &Artifact, dir: &str, path: &str, data: &[u8]) -> String {
        let passwd = fixture(&format!("failed-logins/{dir}/passwd"));
        run_on_host(artifact, &[(path, data), ("etc/passwd", &passwd)], path, 0)
    }

    fn text(name: &str) -> String {
        String::from_utf8(fixture(name)).unwrap()
    }

    fn rfc3339(secs: i64) -> String {
        Timestamp::from_secs(secs, Basis::Recorded).to_rfc3339()
    }

    /// `faillock --user X` prints `2026-11-13 02:13:24 RHOST 192.0.2.5   V`, in file order.
    fn check_faillock(dir: &str) -> usize {
        let mut total = 0;
        for user in ["alice", "bob", "carol"] {
            let data = fixture(&format!("failed-logins/{dir}/faillock/{user}"));
            let recs = records(&on_host(&FAILLOCK, dir, &format!("var/run/faillock/{user}"), &data));
            let truth = text(&format!("failed-logins/{dir}/faillock-{user}.txt"));
            let lines: Vec<&str> = truth.lines().skip(2).collect();
            assert_eq!(recs.len(), lines.len(), "{dir} {user}");
            for (rec, line) in recs.iter().zip(&lines) {
                let at = format!("{dir} {user}: {line}");
                let d: Vec<u32> = line[..19].split(['-', ':', ' ']).map(|v| v.parse().unwrap()).collect();
                let secs = secs_from_civil(d[0].into(), d[1], d[2], d[3], d[4], d[5]).unwrap();
                assert_eq!(rec["time"].as_str().unwrap(), rfc3339(secs), "{at}");
                let fields: Vec<&str> = line[20..].split_whitespace().collect();
                assert_eq!(rec["source_type"].as_str().unwrap().to_uppercase(), fields[0], "{at}");
                assert_eq!(rec["source"].as_str().unwrap(), fields[1], "{at}");
                assert_eq!(rec["valid"].as_bool().unwrap(), fields[2] == "V", "{at}");
                assert_eq!(rec["user"].as_str().unwrap(), user, "{at}");
                total += 1;
            }
        }
        total
    }

    #[test]
    fn faillock_matches_the_faillock_tool() {
        let total: usize = ["debian12", "rocky9", "centos7"].iter().map(|d| check_faillock(d)).sum();
        assert_eq!(total, 3 * 8, "alice 3, bob 3, carol 2 on each of three hosts");
    }

    #[test]
    fn faillock_invalid_entries_and_event() {
        let data = fixture("failed-logins/rocky9/faillock/carol");
        let out = on_host(&FAILLOCK, "rocky9", "var/run/faillock/carol", &data);
        assert!(out.contains("failed login for carol from ssh (no longer counted)"), "{out}");
        assert!(out.contains(r#""source_type":"tty""#) && out.contains(r#""valid":false"#), "{out}");
        insta::assert_snapshot!(out);
    }

    /// `pam_tally2 -u X` prints `alice  3  11/13/26 02:14:45  pts/3`.
    #[test]
    fn tallylog_matches_pam_tally2() {
        let data = fixture("failed-logins/centos7/tallylog");
        let recs = records(&on_host(&TALLYLOG, "centos7", "var/log/tallylog", &data));
        let mut compared = 0;
        for user in ["alice", "bob"] {
            let truth = text(&format!("failed-logins/centos7/tally2-{user}.txt"));
            let f: Vec<&str> = truth.lines().nth(1).unwrap().split_whitespace().collect();
            let rec = recs.iter().find(|r| r["user"] == user).unwrap();
            assert_eq!(rec["failures"].as_u64().unwrap(), f[1].parse::<u64>().unwrap());
            let (date, time): (Vec<u32>, Vec<u32>) = (
                f[2].split('/').map(|v| v.parse().unwrap()).collect(),
                f[3].split(':').map(|v| v.parse().unwrap()).collect(),
            );
            let secs = secs_from_civil(2000 + i64::from(date[2]), date[0], date[1], time[0], time[1], time[2]).unwrap();
            assert_eq!(rec["last_failure"].as_str().unwrap(), rfc3339(secs));
            assert_eq!(rec["last_source"].as_str().unwrap(), f[4]);
            compared += 1;
        }
        assert_eq!((recs.len(), compared), (2, 2), "only users with failures have a record");
        insta::assert_snapshot!(on_host(&TALLYLOG, "centos7", "var/log/tallylog", &data));
    }

    /// `faillog -a` prints `alice  2  5  11/13/26 02:30:36 +0000  pts/3 [593s left]`. The 64-bit
    /// file (32064 bytes, which both record sizes divide) and the real 32-bit x86 file (24048
    /// bytes, 24-byte records) are each compared with their own listing.
    #[test]
    fn faillog_matches_faillog_a_in_both_layouts() {
        for (dir, size) in [("debian9", 32), ("debian9-i386", 24)] {
            let data = fixture(&format!("failed-logins/{dir}/faillog.shadow"));
            let recs = records(&on_host(&FAILLOG, dir, "var/log/faillog", &data));
            assert_eq!(data.len() % size, 0, "{dir}");
            let truth = text(&format!("failed-logins/{dir}/faillog-a.txt"));
            let mut compared = 0;
            for line in truth.lines().skip(1).filter(|l| !l.trim().is_empty()) {
                let f: Vec<&str> = line.split_whitespace().collect();
                let failures: i64 = f[1].parse().unwrap();
                let rec = recs.iter().find(|r| r["user"] == f[0]);
                if failures == 0 && f[2] == "0" {
                    assert!(rec.is_none(), "{dir} {line}: an empty slot must not become a record");
                    continue;
                }
                let rec = rec.unwrap_or_else(|| panic!("{dir}: no record for {line}"));
                assert_eq!(rec["failures"].as_i64().unwrap(), failures, "{line}");
                assert_eq!(rec["max_failures"].as_i64().unwrap(), f[2].parse::<i64>().unwrap(), "{line}");
                let (date, time): (Vec<u32>, Vec<u32>) = (
                    f[3].split('/').map(|v| v.parse().unwrap()).collect(),
                    f[4].split(':').map(|v| v.parse().unwrap()).collect(),
                );
                let secs =
                    secs_from_civil(2000 + i64::from(date[2]), date[0], date[1], time[0], time[1], time[2]).unwrap();
                assert_eq!(rec["last_failure"].as_str().unwrap(), rfc3339(secs), "{line}");
                assert_eq!(rec["line"].as_str().unwrap(), f[6], "{line}");
                compared += 1;
            }
            assert_eq!(compared, 2, "{dir}: alice and bob");
            assert_eq!(
                recs.iter().find(|r| r["user"] == "alice").unwrap()["lock_seconds"],
                600,
                "{dir}: faillog -l 600"
            );
        }
        insta::assert_snapshot!(on_host(
            &FAILLOG,
            "debian9-i386",
            "var/log/faillog",
            &fixture("failed-logins/debian9-i386/faillog.shadow")
        ));
    }

    /// The 32-bit and 64-bit layouts are told apart by length alone when only one divides it,
    /// and big-endian files (s390x) by which order gives plausible times.
    #[test]
    fn faillog_layouts_and_byte_order() {
        let mut wide = vec![0u8; 32 * 1002];
        let at = 32 * 1000;
        wide[at..at + 4].copy_from_slice(&[3, 0, 5, 0]);
        wide[at + 4..at + 9].copy_from_slice(b"pts/1");
        wide[at + 16..at + 24].copy_from_slice(&1_700_000_000i64.to_le_bytes());
        let out = on_host(&FAILLOG, "debian9", "var/log/faillog", &wide);
        assert!(
            out.contains(r#""uid":1000"#)
                && out
                    .contains(r#""failures":3,"max_failures":5,"line":"pts/1","last_failure":"2023-11-14T22:13:20Z""#),
            "{out}"
        );
        // The same record, big-endian
        let mut big = vec![0u8; 32 * 1002];
        big[at..at + 4].copy_from_slice(&[0, 3, 0, 5]);
        big[at + 4..at + 9].copy_from_slice(b"pts/1");
        big[at + 16..at + 24].copy_from_slice(&1_700_000_000i64.to_be_bytes());
        let out = run_on_host(&FAILLOG, &[("var/log/faillog", &big)], "var/log/faillog", 1_700_000_100);
        assert!(
            out.contains(r#""failures":3,"max_failures":5,"line":"pts/1","last_failure":"2023-11-14T22:13:20Z""#),
            "{out}"
        );
        // Garbage times become no time, not a panic.
        let mut bad = wide.clone();
        bad[at + 16..at + 24].copy_from_slice(&i64::MAX.to_le_bytes());
        assert!(run_on_host(&FAILLOG, &[("var/log/faillog", &bad)], "var/log/faillog", 0)
            .contains(r#""last_failure":null"#));
    }

    #[test]
    fn empty_truncated_and_damaged_files() {
        for (artifact, path, fix) in [
            (&FAILLOCK, "var/run/faillock/alice", "failed-logins/debian12/faillock/alice"),
            (&TALLYLOG, "var/log/tallylog", "failed-logins/centos7/tallylog"),
            (&FAILLOG, "var/log/faillog", "failed-logins/debian9/faillog.shadow"),
            (&FAILLOG, "var/log/faillog", "failed-logins/debian9-i386/faillog.shadow"),
        ] {
            assert!(on_host(artifact, "debian12", path, b"").contains("skipped"));
            let data = fixture(fix);
            let cut = on_host(artifact, "debian12", path, &data[..data.len() - 5]);
            assert!(cut.contains("trailing bytes ignored"), "{cut}");
            let mut seed = 0x1234_5678_9abc_def1u64;
            for round in 0..1500 {
                let mut copy = data.clone();
                for _ in 0..(1 + round % 9) {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    let at = (seed % copy.len() as u64) as usize;
                    copy[at] = (seed >> 32) as u8;
                }
                on_host(artifact, "debian12", path, &copy);
            }
        }
    }
}

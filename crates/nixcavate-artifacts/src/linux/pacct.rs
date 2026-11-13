//! BSD process accounting: `var/account/pacct`, `var/log/account/pacct`, `var/log/pacct`,
//! `var/adm/pacct` and their rotations (written by the kernel after `accton(8)`).
//! Format: acct(5) and the kernel's `include/uapi/linux/acct.h`; the older layouts and the
//! byte-order flag follow the GNU `acct` tools, whose `dump-acct` output is the reference.
//!
//! One fixed 64-byte record per process that has finished. The record is written when the
//! process exits, so the file is ordered by exit time, while `ac_btime` is the START time.
//!
//! * version 3 (kernel 2.6.8 onwards, the default): 32-bit uid/gid, pid and ppid, a
//!   floating-point elapsed time.
//! * version 2 and 0 (older kernels, `CONFIG_BSD_PROCESS_ACCT_V3` off): 64 bytes too, but
//!   no pid or ppid; version 0 has 16-bit ids and a `comp_t` elapsed time. Written only by
//!   old kernels; the fixtures for them were converted from version 3 by `dump-acct`.
//!
//! Version 1 (m68k) and 4/5 (a 128-byte layout the kernel never shipped) are not read.
//! The top bit of the version byte says the file is big-endian; version 0 has no version
//! byte, so a big-endian version 0 file is read as little-endian.
//! Times are in ticks of `AHZ` (100 on Linux; version 2 stores it per record).

use super::passwd_lookup;
use super::utmp::field;
use crate::text::decompressed;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "pacct",
    "Process accounting records (one per finished process)",
    Category::Execution,
    LINUX,
    &["var/account/pacct*", "var/log/account/pacct*", "var/log/pacct*", "var/adm/pacct*"],
    parse,
)
.companions(&["etc/passwd"]);

const RECORD: usize = 64;
const AFORK: u8 = 0x01;
const ASU: u8 = 0x02;
const ACORE: u8 = 0x08;
const AXSIG: u8 = 0x10;
const DEFAULT_AHZ: u32 = 100;

#[derive(Serialize)]
struct Process<'a> {
    /// When the process started (`ac_btime`).
    started: Option<Timestamp>,
    /// `started` plus the elapsed time: when the process ended and the record was written.
    ended: Option<Timestamp>,
    elapsed_seconds: Option<f64>,
    /// From `etc/passwd`; empty when the UID is not listed there.
    user: &'a str,
    uid: u32,
    gid: u32,
    /// None in versions 0 and 2, which do not store it.
    pid: Option<u32>,
    ppid: Option<u32>,
    command: Cow<'a, str>,
    /// `pts/0`, `tty1`..., or `major:minor`; empty when the process had no terminal.
    tty: String,
    /// The exit status (`exit(n)`), from the high byte of the wait status.
    exit_status: u32,
    /// The signal that killed the process, from the low bits of the wait status.
    term_signal: Option<u32>,
    /// The process forked and never called exec (`AFORK`).
    forked_without_exec: bool,
    /// The process used superuser privileges (`ASU`).
    used_superuser: bool,
    /// The process dumped core (`ACORE`).
    dumped_core: bool,
    /// The process was killed by a signal (`AXSIG`).
    killed_by_signal: bool,
    cpu_user_seconds: f64,
    cpu_system_seconds: f64,
    /// Average memory use in KiB (`ac_mem`).
    memory_kib: u64,
    minor_faults: u64,
    major_faults: u64,
    swaps: u64,
    /// The record layout version (0, 2 or 3).
    version: u8,
}

impl Record for Process<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { format!("uid {}", self.uid) } else { self.user.to_string() };
        let pid = self.pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
        let ran = self.elapsed_seconds.map(|s| format!(" for {s:.2} s")).unwrap_or_default();
        let how = if self.dumped_core {
            ", dumped core"
        } else if self.killed_by_signal {
            ", killed by a signal"
        } else {
            ""
        };
        // The process is only in the log once it has exited.
        let message = format!("{who} ran {}{pid}{ran}{how} (written at exit)", self.command);
        self.started.map(|ts| Event::new(ts, "executed", message)).into_iter()
    }
}

/// Fixed-width reads from one record in the file's byte order. Every read is bounds-checked.
struct Reader<'a> {
    record: &'a [u8],
    big: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> u16 {
        let raw = self.record.get(at..at + 2).and_then(|b| <[u8; 2]>::try_from(b).ok()).unwrap_or([0; 2]);
        if self.big {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        }
    }

    fn u32(&self, at: usize) -> u32 {
        let raw = self.record.get(at..at + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()).unwrap_or([0; 4]);
        if self.big {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        }
    }
}

/// `comp_t`: a 3-bit base-8 exponent over a 13-bit mantissa.
fn comp(value: u16) -> u64 {
    u64::from(value & 0x1fff) << (3 * u32::from(value >> 13))
}

/// `comp2_t`: 24 bits, a 5-bit base-2 exponent over a 20-bit fraction without its leading 1.
fn comp2(value: u32) -> u64 {
    let exponent = (value >> 19) & 0x1f;
    let fraction = u64::from(value & 0x7_ffff);
    if exponent == 0 {
        fraction
    } else {
        (fraction | 1 << 19) << (exponent - 1)
    }
}

/// The terminal from the old 16-bit device number (`major << 8 | minor`).
fn terminal(dev: u16) -> String {
    let (major, minor) = (dev >> 8, dev & 0xff);
    match (dev, major) {
        (0, _) => String::new(),
        (_, 136..=143) => format!("pts/{}", u32::from(major - 136) * 256 + u32::from(minor)),
        (_, 4) if minor < 64 => format!("tty{minor}"),
        (_, 4) => format!("ttyS{}", minor - 64),
        (_, 5) if minor == 0 => "tty".to_string(),
        (_, 5) if minor == 1 => "console".to_string(),
        _ => format!("{major}:{minor}"),
    }
}

/// Rounds away float noise so the same tick count always prints the same.
fn seconds(ticks: f64, ahz: u32) -> f64 {
    (ticks / f64::from(ahz.max(1)) * 1e6).round() / 1e6
}

fn decode<'a>(record: &'a [u8], users: &'a std::collections::HashMap<u32, String>) -> Option<Process<'a>> {
    let flag = *record.first()?;
    let version_byte = *record.get(1)?;
    let big = version_byte & 0x80 != 0;
    let version = version_byte & 0x7f;
    let r = Reader { record, big };
    let (uid, gid, pid, ppid, started, tty, exit, ahz, elapsed_ticks, times, counters, comm);
    match version {
        3 => {
            tty = r.u16(2);
            exit = r.u32(4);
            uid = r.u32(8);
            gid = r.u32(12);
            pid = Some(r.u32(16));
            ppid = Some(r.u32(20));
            started = r.u32(24);
            let etime = f32::from_bits(r.u32(28));
            elapsed_ticks = (etime.is_finite() && etime >= 0.0).then(|| f64::from(etime));
            ahz = DEFAULT_AHZ;
            times = (comp(r.u16(32)), comp(r.u16(34)), comp(r.u16(36)));
            counters = (comp(r.u16(42)), comp(r.u16(44)), comp(r.u16(46)));
            comm = record.get(48..64)?;
        }
        0 | 2 => {
            tty = r.u16(6);
            started = r.u32(8);
            exit = r.u32(32);
            times = (comp(r.u16(12)), comp(r.u16(14)), comp(r.u16(18)));
            counters = (comp(r.u16(24)), comp(r.u16(26)), comp(r.u16(28)));
            comm = record.get(36..52)?;
            pid = None;
            ppid = None;
            if version == 2 {
                uid = r.u32(56);
                gid = r.u32(60);
                // Elapsed time: 24 bits split over a byte and a 16-bit word.
                let raw = u32::from(*record.get(53)?) << 16 | u32::from(r.u16(54));
                elapsed_ticks = Some(comp2(raw) as f64);
                ahz = match r.u16(30) {
                    0 => DEFAULT_AHZ,
                    hz => u32::from(hz),
                };
            } else {
                // Version 0 has 16-bit ids; the 32-bit ones were added later in padding, and
                // are used only when they agree with the 16-bit ones.
                let (uid16, gid16) = (u32::from(r.u16(2)), u32::from(r.u16(4)));
                let (uid32, gid32) = (r.u32(56), r.u32(60));
                (uid, gid) = if uid32 as u16 == uid16 as u16 && gid32 as u16 == gid16 as u16 {
                    (uid32, gid32)
                } else {
                    (uid16, gid16)
                };
                elapsed_ticks = Some(comp(r.u16(16)) as f64);
                ahz = DEFAULT_AHZ;
            }
        }
        _ => return None,
    }
    let elapsed_seconds = elapsed_ticks.map(|t| seconds(t, ahz));
    let started_ts = (started != 0).then(|| Timestamp::from_secs(i64::from(started), Basis::Recorded));
    let ended = match (started != 0, elapsed_seconds) {
        (true, Some(s)) => Timestamp::checked(
            i64::from(started).saturating_add(s.round() as i64),
            0,
            Precision::Seconds,
            Basis::Recorded,
        ),
        _ => None,
    };
    Some(Process {
        started: started_ts,
        ended,
        elapsed_seconds,
        user: users.get(&uid).map_or("", String::as_str),
        uid,
        gid,
        pid,
        ppid,
        command: field(comm),
        tty: terminal(tty),
        exit_status: (exit >> 8) & 0xff,
        term_signal: Some(exit & 0x7f).filter(|s| *s != 0),
        forked_without_exec: flag & AFORK != 0,
        used_superuser: flag & ASU != 0,
        dumped_core: flag & ACORE != 0,
        killed_by_signal: flag & AXSIG != 0,
        cpu_user_seconds: seconds(times.0 as f64, ahz),
        cpu_system_seconds: seconds(times.1 as f64, ahz),
        memory_kib: times.2,
        minor_faults: counters.0,
        major_faults: counters.1,
        swaps: counters.2,
        version,
    })
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let users = passwd_lookup::by_uid(input.host);
    let mut unknown: Option<(u8, usize)> = None;
    let mut skipped = 0usize;
    let mut emitted = 0usize;
    for (index, record) in data.chunks_exact(RECORD).enumerate() {
        // A file preallocated or damaged by a crash can hold whole empty records.
        if record.iter().all(|&b| b == 0) {
            continue;
        }
        match decode(record, &users) {
            Some(process) => {
                emitted += 1;
                sink.emit(Loc::Offset(input.offset + (index * RECORD) as u64), &process)?;
            }
            None => {
                skipped += 1;
                unknown.get_or_insert((record.get(1).copied().unwrap_or(0), index));
            }
        }
    }
    if emitted == 0 && skipped > 0 {
        let version = unknown.map_or(0, |(v, _)| v & 0x7f);
        return Err(Error::format(format!(
            "not a Linux process accounting file: unsupported accounting version {version} (versions 0, 2 and 3 are read)"
        )));
    }
    if let Some((version_byte, index)) = unknown {
        sink.warn(format!(
            "{skipped} records skipped: unsupported accounting version {} (first at record {index})",
            version_byte & 0x7f
        ));
    }
    if data.len() % RECORD != 0 {
        sink.warn(format!(
            "size {} is not a multiple of {RECORD}; {} trailing bytes ignored",
            data.len(),
            data.len() % RECORD
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use nixcavate_core::time::{month_from_abbrev, secs_from_civil};
    use serde_json::Value;

    const DIRS: [&str; 4] = ["debian12", "ubuntu2404", "rocky9", "centos7"];

    fn records(out: &str) -> Vec<Value> {
        out.lines()
            .take_while(|l| !l.starts_with("---"))
            .filter(|l| l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn parse_file(dir: &str, file: &str) -> String {
        let files: [(&str, &[u8]); 2] = [
            ("var/log/pacct", &fixture(&format!("pacct/{dir}/{file}"))),
            ("etc/passwd", &fixture(&format!("pacct/{dir}/passwd"))),
        ];
        run_on_host(&ARTIFACT, &files, "var/log/pacct", 0)
    }

    /// `Fri Nov 13 02:01:59 2026` (ctime; the containers ran in UTC) as epoch seconds.
    fn ctime(text: &str) -> i64 {
        let t: Vec<&str> = text.split_whitespace().collect();
        let hms: Vec<u32> = t[3].split(':').map(|v| v.parse().unwrap()).collect();
        let month = month_from_abbrev(t[1].as_bytes()).unwrap();
        secs_from_civil(t[4].parse().unwrap(), month, t[2].parse().unwrap(), hms[0], hms[1], hms[2]).unwrap()
    }

    /// Compares every record with what `dump-acct` printed for the same file (and `lastcomm`
    /// for the user, terminal and flags). Returns how many records were compared.
    fn check_against_dump(dir: &str, file: &str, dump: &str, version: u64) -> usize {
        let parsed = records(&parse_file(dir, file));
        let truth = String::from_utf8(fixture(&format!("pacct/{dir}/{dump}"))).unwrap();
        let lines: Vec<&str> = truth.lines().collect();
        assert_eq!(parsed.len(), lines.len(), "{dir}/{file}: record count");
        for (n, (rec, line)) in parsed.iter().zip(&lines).enumerate() {
            let f: Vec<&str> = line.split('|').collect();
            let at = format!("{dir}/{file} record {n}: {line}");
            let num = |v: &str| v.trim().parse::<f64>().unwrap();
            assert_eq!(rec["command"].as_str().unwrap(), f[0].trim_end(), "{at}");
            assert_eq!(rec["version"].as_u64().unwrap(), version, "{at}");
            for (field, text) in [("cpu_user_seconds", f[2]), ("cpu_system_seconds", f[3]), ("elapsed_seconds", f[4])] {
                let got = rec[field].as_f64().unwrap() * 100.0;
                assert!((got - num(text)).abs() < 1e-3, "{field} {got} vs {text}: {at}");
            }
            assert_eq!(rec["uid"].as_u64().unwrap(), num(f[5]) as u64, "{at}");
            assert_eq!(rec["gid"].as_u64().unwrap(), num(f[6]) as u64, "{at}");
            assert_eq!(rec["memory_kib"].as_u64().unwrap(), num(f[7]) as u64, "{at}");
            let started = Timestamp::from_secs(ctime(f.last().unwrap()), Basis::Recorded).to_rfc3339();
            assert_eq!(rec["started"].as_str().unwrap(), started, "{at}");
            if f.len() == 15 {
                let ids = (rec["pid"].as_u64(), rec["ppid"].as_u64());
                let expected =
                    if version == 3 { (Some(num(f[9]) as u64), Some(num(f[10]) as u64)) } else { (None, None) };
                assert_eq!(ids, expected, "{at}");
                let letters: Vec<char> = f[11].chars().collect();
                let flags = [
                    ("used_superuser", 0, 'S'),
                    ("forked_without_exec", 1, 'F'),
                    ("dumped_core", 3, 'D'),
                    ("killed_by_signal", 4, 'X'),
                ];
                for (field, i, letter) in flags {
                    assert_eq!(rec[field].as_bool().unwrap(), letters[i] == letter, "{field}: {at}");
                }
                assert_eq!(rec["exit_status"].as_u64().unwrap(), num(f[12]) as u64, "{at}");
                let tty = f[13].trim();
                assert_eq!(rec["tty"].as_str().unwrap(), if tty == "__" { "" } else { tty }, "{at}");
            } else {
                // The older dump-acct prints no flags, status or terminal, and joins pid and ppid.
                let ids: Vec<u64> = f[9].split_whitespace().map(|v| v.parse().unwrap()).collect();
                let expected = if version == 3 { (Some(ids[0]), Some(ids[1])) } else { (None, None) };
                assert_eq!((rec["pid"].as_u64(), rec["ppid"].as_u64()), expected, "{at}");
            }
        }
        // lastcomm lists the newest record first: command, flags, user, terminal.
        if file == "pacct" {
            let comm = String::from_utf8(fixture(&format!("pacct/{dir}/lastcomm.txt"))).unwrap();
            for (rec, line) in parsed.iter().rev().zip(comm.lines()) {
                let flags = line.get(17..22).unwrap_or("     ");
                let rest: Vec<&str> = line.get(22..).unwrap_or("").split_whitespace().collect();
                assert_eq!(rec["command"].as_str().unwrap(), line.get(..16).unwrap().trim_end(), "{line}");
                assert_eq!(rec["user"].as_str().unwrap(), rest[0], "{line}");
                assert_eq!(rec["used_superuser"].as_bool().unwrap(), flags.contains('S'), "{line}");
                assert_eq!(rec["forked_without_exec"].as_bool().unwrap(), flags.contains('F'), "{line}");
                assert_eq!(rec["dumped_core"].as_bool().unwrap(), flags.contains('D'), "{line}");
                assert_eq!(rec["killed_by_signal"].as_bool().unwrap(), flags.contains('X'), "{line}");
                let tty = rec["tty"].as_str().unwrap();
                assert_eq!(rest[1], if tty.is_empty() { "__" } else { tty }, "{line}");
            }
        }
        parsed.len()
    }

    /// Kernel-written version 3 files from four distribution userlands, record by record
    /// against `dump-acct` and `lastcomm`.
    #[test]
    fn version_3_matches_dump_acct_and_lastcomm() {
        let mut total = 0;
        for dir in DIRS {
            total += check_against_dump(dir, "pacct", "dump-acct.txt", 3);
            total += check_against_dump(dir, "pacct.swapped", "dump-acct.swapped.txt", 3);
        }
        assert!(total > 100, "{total}");
    }

    /// Versions 2 and 0, little- and big-endian, written by `dump-acct --format`.
    #[test]
    fn versions_2_and_0_and_byte_order_match_dump_acct() {
        for dir in DIRS {
            check_against_dump(dir, "pacct.v2", "dump-acct.v2.txt", 2);
            check_against_dump(dir, "pacct.v0", "dump-acct.v0.txt", 0);
            check_against_dump(dir, "pacct.v2swapped", "dump-acct.v2swapped.txt", 2);
        }
    }

    #[test]
    fn signals_core_dumps_forks_and_setuid_are_reported() {
        let out = parse_file("debian12", "pacct");
        let recs = records(&out);
        assert!(recs.iter().any(|r| r["dumped_core"] == true && r["killed_by_signal"] == true && r["command"] == "sh"));
        assert!(recs.iter().any(|r| r["forked_without_exec"] == true));
        assert!(recs.iter().any(|r| r["exit_status"] == 42 && r["command"] == "sh"));
        assert!(recs.iter().any(|r| r["user"] == "bob" && r["command"] == "t"));
        assert!(out.contains("alice ran sleep"), "{out}");
    }

    #[test]
    fn rotations_unknown_versions_and_damage() {
        let data = fixture("pacct/debian12/pacct");
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&data).unwrap();
            enc.finish().unwrap();
        }
        assert_eq!(records(&run(&ARTIFACT, "var/log/pacct.1.gz", &gz, 0)).len(), data.len() / 64);
        // Unknown version bytes: records skipped with one warning; all unknown is a format error.
        let mut mixed = data.clone();
        mixed[64 + 1] = 9;
        let out = run(&ARTIFACT, "var/log/pacct", &mixed, 0);
        assert_eq!(out.matches("--- warning").count(), 1, "{out}");
        assert!(out.contains("1 records skipped: unsupported accounting version 9 (first at record 1)"), "{out}");
        let all_bad: Vec<u8> = data.chunks(64).flat_map(|r| [&r[..1], &[7u8], &r[2..]].concat()).collect();
        assert!(run(&ARTIFACT, "var/log/pacct", &all_bad, 0).contains("unsupported accounting version 7"));
        let out = run(&ARTIFACT, "var/log/pacct", &data[..data.len() - 10], 0);
        assert!(out.contains("trailing bytes ignored"), "{out}");
        assert!(run(&ARTIFACT, "var/log/pacct", b"", 0).contains("skipped: empty file"));
        assert_eq!(run(&ARTIFACT, "var/log/pacct", &[0u8; 640], 0), "");
    }

    #[test]
    fn compressed_time_encodings() {
        assert_eq!(comp(0x0001), 1);
        assert_eq!(comp(0x2001), 8);
        assert_eq!(comp(0xffff), 0x1fff << 21);
        assert_eq!(comp2(0), 0);
        assert_eq!(comp2(5), 5);
        assert_eq!(comp2(1 << 19), 1 << 19);
        assert_eq!(comp2(2 << 19), 1 << 20);
    }

    #[test]
    fn snapshot_of_a_real_file() {
        insta::assert_snapshot!(parse_file("rocky9", "pacct"));
    }

    #[test]
    fn mutations_never_panic() {
        let data = fixture("pacct/debian12/pacct");
        for len in (0..data.len()).step_by(5) {
            run(&ARTIFACT, "var/log/pacct", &data[..len], 0);
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..3000 {
            let mut copy = data.clone();
            for _ in 0..(1 + round % 12) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed % copy.len() as u64) as usize;
                copy[at] = (seed >> 32) as u8;
            }
            run(&ARTIFACT, "var/log/pacct", &copy, 0);
        }
    }
}

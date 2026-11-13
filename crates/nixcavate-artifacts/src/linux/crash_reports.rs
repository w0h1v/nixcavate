//! Crash evidence left by the systems that catch crashing programs:
//!
//! * `coredump`: `var/lib/systemd/coredump/core.<comm>.<uid>.<bootid>.<pid>.<usec>[.zst|.lz4|.xz]`,
//!   stored by `systemd-coredump(8)`. The NAME says what crashed, for whom, and when (the comm
//!   is escaped as `\xNN`, for `.`, `/` and space among others). The core itself is not
//!   analysed. Only when it is an ELF64 core (plain, zstd, xz or lz4) its first 1 MiB is
//!   searched for the `NT_PRPSINFO` note, whose `pr_psargs` holds the first 80 bytes of the
//!   command line: a bounded read that never touches the memory image.
//! * `apport-crash`: `var/crash/*.crash`, Ubuntu apport reports. An RFC 822-like file of
//!   `Key: value` fields with `Key: value` continuation lines that start with a space. The
//!   text fields come first and the binary ones (`CoreDump`, base64) after them, and can be
//!   hundreds of MB: reading stops at the first binary field, so no more than the text
//!   header is ever looked at. Format: apport's `problem_report.py`.
//! * `abrt-problem`: `var/spool/abrt/<dir>/` (also `var/lib/abrt`, `var/tmp/abrt`), the
//!   problem directories of RHEL's ABRT: small one-value files (`time`, `executable`,
//!   `cmdline`, `reason`, `uid`, `pid`, `package`...). The `time` file is the input, the
//!   sibling files are read through the host; the (huge) `coredump` file is never opened.
//! * `kernel-crash`: kdump's `var/crash/<addr>-<date>/vmcore-dmesg.txt` (and Ubuntu's
//!   `var/crash/<stamp>/dmesg.<stamp>`): the kernel log saved at a panic. One record per
//!   file with the directory's date and the panic line; only the first 256 KiB is searched.
//!   Synthetic fixtures only: no real kernel crash could be made in a container.

use super::utmp::field;
use crate::text::lossy;
use crate::{Artifact, Category, Input, LINUX};
use memchr::{memchr, memmem};
use nixcavate_core::time::{parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::io::Read;

pub const COREDUMP: Artifact = Artifact::new(
    "coredump",
    "systemd-coredump core files (the file name is the evidence)",
    Category::Execution,
    LINUX,
    &["var/lib/systemd/coredump/core.*"],
    parse_coredump,
);

pub const APPORT: Artifact = Artifact::new(
    "apport-crash",
    "Ubuntu apport crash reports",
    Category::Execution,
    LINUX,
    &["var/crash/*.crash"],
    parse_apport,
);

/// One task per problem directory: `time` exists in every one of them.
pub const ABRT: Artifact = Artifact::new(
    "abrt-problem",
    "ABRT problem directories",
    Category::Execution,
    LINUX,
    &["var/spool/abrt/*/time", "var/lib/abrt/*/time", "var/tmp/abrt/*/time"],
    parse_abrt,
);

pub const KERNEL_CRASH: Artifact = Artifact::new(
    "kernel-crash",
    "Kernel crash dumps (kdump dmesg)",
    Category::System,
    LINUX,
    &["var/crash/*/vmcore-dmesg.txt", "var/crash/*/dmesg.*"],
    parse_kernel_crash,
);

fn timestamp(secs: i64, nanos: u32, precision: Precision) -> Option<Timestamp> {
    Timestamp::checked(secs, nanos, precision, Basis::Recorded)
}

// ---- coredump ----

#[derive(Serialize)]
struct CoreFile<'a> {
    time: Option<Timestamp>,
    uid: u32,
    user: &'a str,
    pid: u32,
    command: String,
    boot_id: &'a str,
    /// `zstd`, `lz4`, `xz`, or empty for an uncompressed core.
    compression: &'static str,
    /// The file's size on disk (compressed, when it is).
    size_bytes: u64,
    /// The start of the command line, from the core's `NT_PRPSINFO` note; empty when the core
    /// is not an ELF64 core or the note is not within the first 1 MiB.
    core_command: String,
}

impl Record for CoreFile<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} crashed (pid {}, uid {}); core file kept", self.command, self.pid, self.uid);
        self.time.map(|ts| Event::new(ts, "crashed", message)).into_iter()
    }
}

/// Replaces `\xNN` escapes (what systemd writes for `.`, `/`, space and control characters).
fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let hex = |at: usize| bytes.get(at).and_then(|c| (*c as char).to_digit(16));
        match (b, bytes.get(i + 1), hex(i + 2), hex(i + 3)) {
            (b'\\', Some(b'x'), Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                i += 4;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

const PREFIX: usize = 1 << 20;

/// The first bytes of a core, decompressed when needed. Errors (a truncated or damaged
/// stream) end the read: what was decoded before them is still usable.
fn core_prefix(data: &[u8], compression: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut take = |reader: &mut dyn Read| {
        let _ = reader.take(PREFIX as u64).read_to_end(&mut out);
    };
    match compression {
        "zstd" => {
            if let Ok(mut d) = zstd::stream::read::Decoder::new(data) {
                take(&mut d);
            }
        }
        "xz" => {
            if let Ok(stream) = xz2::stream::Stream::new_stream_decoder(64 << 20, 0) {
                take(&mut xz2::read::XzDecoder::new_stream(data, stream));
            }
        }
        "lz4" => take(&mut lz4_flex::frame::FrameDecoder::new(data)),
        _ => out.extend_from_slice(data.get(..PREFIX).unwrap_or(data)),
    }
    out
}

fn le_or_be<const N: usize>(bytes: &[u8], at: usize, big: bool) -> Option<[u8; N]> {
    let mut raw: [u8; N] = bytes.get(at..at.checked_add(N)?)?.try_into().ok()?;
    if big {
        raw.reverse();
    }
    Some(raw)
}

fn u16_at(b: &[u8], at: usize, big: bool) -> Option<u64> {
    le_or_be::<2>(b, at, big).map(|r| u64::from(u16::from_le_bytes(r)))
}
fn u32_at(b: &[u8], at: usize, big: bool) -> Option<u64> {
    le_or_be::<4>(b, at, big).map(|r| u64::from(u32::from_le_bytes(r)))
}
fn u64_at(b: &[u8], at: usize, big: bool) -> Option<u64> {
    le_or_be::<8>(b, at, big).map(u64::from_le_bytes)
}

/// `pr_psargs` of the `NT_PRPSINFO` note of an ELF64 core (the Linux x86-64/aarch64 layout:
/// the argument text sits 56 bytes into the 136-byte descriptor).
fn prpsinfo_args(core: &[u8]) -> Option<String> {
    if core.get(..4)? != b"\x7fELF" || *core.get(4)? != 2 || u16_at(core, 16, *core.get(5)? == 2)? != 4 {
        return None;
    }
    let big = *core.get(5)? == 2;
    let (phoff, phentsize, phnum) = (u64_at(core, 32, big)?, u16_at(core, 54, big)?, u16_at(core, 56, big)?);
    for index in 0..phnum.min(4096) {
        let ph = usize::try_from(phoff.checked_add(index.checked_mul(phentsize)?)?).ok()?;
        if u32_at(core, ph, big)? != 4 {
            continue; // not PT_NOTE
        }
        let (offset, size) =
            (usize::try_from(u64_at(core, ph + 8, big)?).ok()?, usize::try_from(u64_at(core, ph + 32, big)?).ok()?);
        let notes = core.get(offset..offset.checked_add(size.min(PREFIX))?)?;
        let (mut at, mut seen) = (0usize, 0);
        while at + 12 <= notes.len() && seen < 4096 {
            seen += 1;
            let (namesz, descsz, kind) =
                (u32_at(notes, at, big)?, u32_at(notes, at + 4, big)?, u32_at(notes, at + 8, big)?);
            let name_at = at + 12;
            let desc_at = name_at.checked_add(usize::try_from(namesz).ok()?.checked_add(3)? & !3)?;
            let desc_len = usize::try_from(descsz).ok()?;
            if kind == 3 && notes.get(name_at..name_at + 4) == Some(b"CORE") && desc_len >= 136 {
                return Some(field(notes.get(desc_at + 56..desc_at + 136)?).into_owned());
            }
            at = desc_at.checked_add(desc_len.checked_add(3)? & !3)?;
        }
    }
    None
}

fn parse_coredump(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or("");
    let (stem, compression) = match name.rsplit_once('.') {
        Some((stem, "zst")) => (stem, "zstd"),
        Some((stem, "lz4")) => (stem, "lz4"),
        Some((stem, "xz")) => (stem, "xz"),
        _ => (name, ""),
    };
    let parts: Vec<&str> = stem.strip_prefix("core.").unwrap_or("").split('.').collect();
    let [comm, uid, boot, pid, usec] = parts[..] else {
        return Err(Error::format(format!("{name}: not a systemd-coredump file name (core.COMM.UID.BOOTID.PID.USEC)")));
    };
    let (Some(uid), Some(pid), Some(usec)) =
        (parse_uint(uid.as_bytes()), parse_uint(pid.as_bytes()), parse_uint(usec.as_bytes()))
    else {
        return Err(Error::format(format!("{name}: uid, pid or time in the file name is not a number")));
    };
    let users = super::passwd_lookup::by_uid(input.host);
    let uid32 = u32::try_from(uid).unwrap_or(u32::MAX);
    let prefix = core_prefix(input.data, compression);
    sink.emit(
        Loc::None,
        &CoreFile {
            time: i64::try_from(usec / 1_000_000)
                .ok()
                .and_then(|s| timestamp(s, (usec % 1_000_000) as u32 * 1000, Precision::Micros)),
            uid: uid32,
            user: users.get(&uid32).map_or("", String::as_str),
            pid: u32::try_from(pid).unwrap_or(u32::MAX),
            command: unescape(comm),
            boot_id: boot,
            compression,
            size_bytes: input.data.len() as u64,
            core_command: prpsinfo_args(&prefix).map(|a| a.trim_end().to_string()).unwrap_or_default(),
        },
    )
}

// ---- apport ----

#[derive(Serialize)]
struct Apport<'a> {
    problem_type: &'a str,
    time: Option<Timestamp>,
    time_basis: Basis,
    executable: &'a str,
    command_line: &'a str,
    uid: Option<u32>,
    user: &'a str,
    /// The signal number of a crash (`Signal`), empty for other problem types.
    signal: &'a str,
    package: &'a str,
    architecture: &'a str,
    /// The size of the whole report; the part after the text header (the core) is not read.
    size_bytes: u64,
}

impl Record for Apport<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let sig = if self.signal.is_empty() { String::new() } else { format!(", signal {}", self.signal) };
        let message = format!("{} report for {}{sig}", self.problem_type, self.executable);
        self.time.map(|ts| Event::new(ts, "crashed", message)).into_iter()
    }
}

/// `Wed Mar 10 12:00:00 2023` (C `ctime`), the form apport writes in `Date`.
fn ctime_secs(text: &str) -> Option<i64> {
    let t: Vec<&str> = text.split_whitespace().collect();
    let [_, month, day, clock, year] = t[..] else { return None };
    let month = nixcavate_core::time::month_from_abbrev(month.as_bytes())?;
    let mut hms = clock.split(':').map(|v| v.parse::<u32>().ok());
    secs_from_civil(year.parse().ok()?, month, day.parse().ok()?, hms.next()??, hms.next()??, hms.next()??)
}

fn parse_apport(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    let mut fields: Vec<(&[u8], String)> = Vec::new();
    let (mut at, mut current): (usize, Option<usize>) = (0, None);
    let wanted: [&[u8]; 8] = [
        b"ProblemType",
        b"Date",
        b"ExecutablePath",
        b"ProcCmdline",
        b"Signal",
        b"Package",
        b"Architecture",
        b"ProcStatus",
    ];
    while at < data.len() {
        let end = memchr(b'\n', &data[at..]).map_or(data.len(), |i| at + i);
        let line = &data[at..end];
        at = end + 1;
        if let Some(rest) = line.strip_prefix(b" ") {
            // A continuation line: kept only for the fields wanted (ProcStatus carries the uid).
            if let Some((_, value)) = current.and_then(|i| fields.get_mut(i)) {
                if value.len() < 8192 {
                    value.push('\n');
                    value.push_str(&lossy(rest));
                }
            }
            continue;
        }
        current = None;
        let Some(colon) = memchr(b':', line) else { continue };
        let (key, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        // The first binary field (`CoreDump: base64`) ends the text header.
        if value.starts_with(b"base64") || value.starts_with(b"gzip, base64") {
            break;
        }
        if wanted.contains(&key) {
            current = Some(fields.len());
            fields.push((key, lossy(value).into_owned()));
        }
    }
    let get = |name: &[u8]| fields.iter().find(|(k, _)| *k == name).map_or("", |(_, v)| v.as_str());
    if get(b"ProblemType").is_empty() {
        return Err(Error::format("no ProblemType field: not an apport report"));
    }
    let uid = get(b"ProcStatus")
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse::<u32>().ok());
    let users = super::passwd_lookup::by_uid(input.host);
    let time = ctime_secs(get(b"Date")).map(|wall| input.local_time(wall, 0, Precision::Seconds));
    sink.emit(
        Loc::None,
        &Apport {
            problem_type: get(b"ProblemType"),
            time,
            time_basis: Basis::AssumedZone,
            executable: get(b"ExecutablePath"),
            command_line: get(b"ProcCmdline"),
            uid,
            user: uid.and_then(|u| users.get(&u)).map_or("", String::as_str),
            signal: get(b"Signal"),
            package: get(b"Package"),
            architecture: get(b"Architecture"),
            size_bytes: data.len() as u64,
        },
    )
}

// ---- abrt ----

#[derive(Serialize)]
struct Abrt {
    problem_dir: String,
    /// `CCpp` (native crash), `Python3`, `Kerneloops`, `vmcore`, `xorg`...
    problem_type: String,
    time: Option<Timestamp>,
    /// The latest occurrence, when the problem repeated (`count` times).
    last_occurrence: Option<Timestamp>,
    count: Option<u64>,
    uid: Option<u32>,
    user: String,
    pid: Option<u32>,
    executable: String,
    command_line: String,
    reason: String,
    package: String,
    hostname: String,
}

impl Record for Abrt {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{}: {}", self.executable, self.reason);
        let first = self.time.map(|ts| Event::new(ts, "crashed", message.clone()));
        let last = self
            .last_occurrence
            .filter(|l| Some(*l) != self.time)
            .map(|ts| Event::new(ts, "crashed", format!("{message} (latest occurrence)")));
        first.into_iter().chain(last)
    }
}

/// A small text file beside the anchor: at most 4 KiB, trailing newline removed.
fn small(input: &Input, dir: &str, name: &str) -> String {
    let Some(data) = input.host.read(&format!("{dir}/{name}")) else { return String::new() };
    lossy(data.get(..4096).unwrap_or(&data)).trim_end().to_string()
}

fn parse_abrt(input: &Input, sink: &mut Sink) -> Result<()> {
    let dir = input.path.rsplit_once('/').map_or("", |(d, _)| d);
    let epoch =
        |name: &str| small(input, dir, name).parse::<i64>().ok().and_then(|s| timestamp(s, 0, Precision::Seconds));
    let uid = small(input, dir, "uid").parse::<u32>().ok();
    let users = super::passwd_lookup::by_uid(input.host);
    let cmdline = small(input, dir, "cmdline");
    sink.emit(
        Loc::None,
        &Abrt {
            problem_dir: dir.rsplit('/').next().unwrap_or("").to_string(),
            problem_type: small(input, dir, "type"),
            time: epoch("time"),
            last_occurrence: epoch("last_occurrence"),
            count: small(input, dir, "count").parse().ok(),
            uid,
            user: uid.and_then(|u| users.get(&u)).cloned().unwrap_or_default(),
            pid: small(input, dir, "pid").parse().ok(),
            executable: small(input, dir, "executable"),
            command_line: cmdline,
            reason: small(input, dir, "reason"),
            package: small(input, dir, "package"),
            hostname: small(input, dir, "hostname"),
        },
    )
}

// ---- kernel-crash ----

#[derive(Serialize)]
struct KernelCrash<'a> {
    /// The crash directory's name: the crashed host's address (kdump) or a stamp (Ubuntu).
    directory: &'a str,
    time: Option<Timestamp>,
    time_basis: Basis,
    /// The first line of the saved kernel log.
    first_line: String,
    /// The first `Kernel panic`, `BUG:`, `Oops` or `Call Trace` line.
    reason: String,
    size_bytes: u64,
}

impl Record for KernelCrash<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "kernel crash dump saved: {}",
            if self.reason.is_empty() { &self.first_line } else { &self.reason }
        );
        self.time.map(|ts| Event::new(ts, "crashed", message)).into_iter()
    }
}

/// `127.0.0.1-2023-03-10-12:00:00` (kdump) or `202303101200` (Ubuntu) as wall-clock seconds.
fn crash_dir_secs(name: &str) -> Option<i64> {
    let stamp = name.rsplit_once('-').map(|_| name).unwrap_or(name);
    let digits: Vec<&str> = stamp.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
    match digits[..] {
        // kdump: the address's own numbers come first; the date is the last six groups.
        [.., y, mo, d, h, mi, s] if y.len() == 4 => secs_from_civil(
            y.parse().ok()?,
            mo.parse().ok()?,
            d.parse().ok()?,
            h.parse().ok()?,
            mi.parse().ok()?,
            s.parse().ok()?,
        ),
        [stamp] if stamp.len() == 12 => secs_from_civil(
            stamp.get(..4)?.parse().ok()?,
            stamp.get(4..6)?.parse().ok()?,
            stamp.get(6..8)?.parse().ok()?,
            stamp.get(8..10)?.parse().ok()?,
            stamp.get(10..12)?.parse().ok()?,
            0,
        ),
        _ => None,
    }
}

fn parse_kernel_crash(input: &Input, sink: &mut Sink) -> Result<()> {
    let head = input.data.get(..256 << 10).unwrap_or(input.data);
    let directory = input.path.rsplit('/').nth(1).unwrap_or("");
    let first_line = lossy(head.split(|&b| b == b'\n').next().unwrap_or(&[])).into_owned();
    let reason = [&b"Kernel panic"[..], b"BUG:", b"Oops", b"Call Trace"]
        .iter()
        .filter_map(|needle| memmem::find(head, needle))
        .min()
        .map(|at| {
            let start = head[..at].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            let end = memchr(b'\n', &head[at..]).map_or(head.len(), |i| at + i);
            lossy(&head[start..end]).into_owned()
        })
        .unwrap_or_default();
    sink.emit(
        Loc::None,
        &KernelCrash {
            directory,
            time: crash_dir_secs(directory).map(|wall| input.local_time(wall, 0, Precision::Seconds)),
            time_basis: Basis::AssumedZone,
            first_line,
            reason,
            size_bytes: input.data.len() as u64,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};
    use serde_json::Value;

    fn records(out: &str) -> Vec<Value> {
        out.lines()
            .take_while(|l| !l.starts_with("---"))
            .filter(|l| l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn text(name: &str) -> String {
        String::from_utf8(fixture(name)).unwrap()
    }

    /// The core files, as systemd-coredump wrote them.
    fn core_files() -> Vec<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/coredump/debian12");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with("core."))
            .collect();
        names.sort();
        names
    }

    /// Record by record against `coredumpctl list` and the journal's `COREDUMP_*` fields.
    #[test]
    fn coredump_names_match_coredumpctl_and_the_journal() {
        let list = text("coredump/debian12/coredumpctl-list.txt");
        let journal: Vec<Value> =
            text("coredump/debian12/journal-fields.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(journal.len(), 3);
        let rows: Vec<&str> = list.lines().skip(1).collect();
        for (row, fields) in rows.iter().zip(&journal) {
            let cols: Vec<&str> = row.split_whitespace().collect();
            let file = fields["COREDUMP_FILENAME"].as_str().unwrap().rsplit('/').next().unwrap();
            let path = format!("var/lib/systemd/coredump/{file}");
            let out = run(&COREDUMP, &path, &fixture(&format!("coredump/debian12/{file}")), 0);
            let rec = &records(&out)[0];
            // `Fri 2026-11-13 02:23:42 UTC` is cols[1..4]; PID UID GID SIG COREFILE EXE SIZE follow.
            assert_eq!(rec["time"].as_str().unwrap()[..19].replace('T', " "), format!("{} {}", cols[1], cols[2]));
            assert_eq!(rec["pid"].to_string(), cols[4]);
            assert_eq!(rec["uid"].to_string(), cols[5]);
            assert_eq!(rec["command"], fields["COREDUMP_COMM"]);
            assert_eq!(rec["pid"].to_string(), fields["COREDUMP_PID"].as_str().unwrap());
            assert_eq!(rec["uid"].to_string(), fields["COREDUMP_UID"].as_str().unwrap());
            let micros: i64 = fields["COREDUMP_TIMESTAMP"].as_str().unwrap().parse().unwrap();
            assert_eq!(rec["time"].as_str().unwrap(), Timestamp::from_micros(micros, Basis::Recorded).to_rfc3339());
            // SIZE is the file size in KiB with one decimal.
            let kib = rec["size_bytes"].as_f64().unwrap() / 1024.0;
            let listed: f64 = cols.last().unwrap().trim_end_matches('K').parse().unwrap();
            assert!((kib - listed).abs() < 0.1, "{kib} vs {listed}");
            assert_eq!(rec["compression"], "zstd");
            // The command line from the core's own note is the start of the journal's.
            let cmdline = fields["COREDUMP_CMDLINE"].as_str().unwrap().trim_start_matches("$'").replace("' ", " ");
            assert_eq!(rec["core_command"].as_str().unwrap(), cmdline, "{out}");
            assert!(out.contains("crashed (pid"), "{out}");
        }
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn coredump_names_unescape_and_reject() {
        let name = "var/lib/systemd/coredump/core.my\\x2dapp\\x2ev2.1001.de5e571206794cb9bde01e489b870e71.42.1700000000123456.xz";
        let out = run(&COREDUMP, name, b"not a core", 0);
        assert!(
            out.contains(r#""time":"2023-11-14T22:13:20.123456Z""#) && out.contains(r#""command":"my-app.v2""#),
            "{out}"
        );
        assert!(out.contains(r#""compression":"xz""#) && out.contains(r#""core_command":"""#), "{out}");
        for bad in ["core.x.1.2.3", "core.a.b.c.d.e", "core.a.1.id.2.3.4.5", "core"] {
            let out = run(&COREDUMP, &format!("var/lib/systemd/coredump/{bad}"), b"x", 0);
            assert!(
                out.contains("failed: ") && out.contains("not a systemd-coredump file name")
                    || out.contains("not a number"),
                "{bad}: {out}"
            );
        }
    }

    /// The same core stored the other ways systemd-coredump can store it gives the same answer.
    #[test]
    fn cores_in_every_storage_form_give_the_command_line() {
        use std::io::Write;
        let real = fixture(&format!("coredump/debian12/{}", core_files()[2]));
        let mut plain = Vec::new();
        zstd::stream::copy_decode(&real[..], &mut plain).unwrap();
        let mut xz = Vec::new();
        let mut encoder = xz2::write::XzEncoder::new(&mut xz, 1);
        encoder.write_all(&plain).unwrap();
        encoder.finish().unwrap();
        let mut lz4 = Vec::new();
        let mut encoder = lz4_flex::frame::FrameEncoder::new(&mut lz4);
        encoder.write_all(&plain).unwrap();
        encoder.finish().unwrap();
        for (name, data, compression) in [
            ("core.web-server.1000.id.3838.1794537099000000", &plain, ""),
            ("core.web-server.1000.id.3838.1794537099000000.xz", &xz, "xz"),
            ("core.web-server.1000.id.3838.1794537099000000.lz4", &lz4, "lz4"),
        ] {
            let out = run(&COREDUMP, &format!("var/lib/systemd/coredump/{name}"), data, 0);
            assert!(out.contains(r#""core_command":"/tmp/web-server 1000""#), "{compression}: {out}");
            assert!(out.contains(&format!(r#""compression":"{compression}""#)), "{out}");
        }
    }

    #[test]
    fn damaged_cores_never_panic() {
        let name = "var/lib/systemd/coredump/core.a.1.id.2.3.zst";
        let real = fixture(&format!("coredump/debian12/{}", core_files()[2]));
        let mut plain = Vec::new();
        zstd::stream::copy_decode(&real[..], &mut plain).unwrap();
        let mut seed = 0x0123_4567_89ab_cdefu64;
        for round in 0..400 {
            let mut copy = plain.clone();
            for _ in 0..(1 + round % 16) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed % 2048) as usize;
                copy[at] = (seed >> 32) as u8;
            }
            run(&COREDUMP, "var/lib/systemd/coredump/core.a.1.id.2.3", &copy, 0);
            run(&COREDUMP, name, &real[..(seed % real.len() as u64) as usize], 0);
        }
    }

    #[test]
    fn apport_report_matches_apport_unpack() {
        let data = fixture("apport-crash/_tmp_my-daemon.1001.crash");
        let passwd = fixture("apport-crash/passwd");
        let files: [(&str, &[u8]); 2] = [("var/crash/_tmp_my-daemon.1001.crash", &data), ("etc/passwd", &passwd)];
        let out = run_on_host(&APPORT, &files, "var/crash/_tmp_my-daemon.1001.crash", 0);
        let rec = &records(&out)[0];
        // reference.txt: the fields `apport-unpack` wrote, one `Key=value` per line.
        for line in text("apport-crash/reference.txt").lines() {
            let (key, value) = line.split_once('=').unwrap_or(("Uid:\t", line.trim_start_matches("Uid:\t")));
            let field = match key {
                "ProblemType" => "problem_type",
                "ExecutablePath" => "executable",
                "ProcCmdline" => "command_line",
                "Signal" => "signal",
                "Package" => "package",
                "Architecture" => "architecture",
                "Date" => {
                    assert!(rec["time"].as_str().unwrap().starts_with("2026-11-13T02:28:34"), "{out}");
                    continue;
                }
                _ => {
                    assert_eq!(rec["uid"].to_string(), value.split_whitespace().next().unwrap(), "{out}");
                    continue;
                }
            };
            assert_eq!(rec[field].as_str().unwrap(), value, "{field}: {out}");
        }
        assert_eq!(rec["user"], "alice");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn apport_stops_at_the_binary_field() {
        let report =
            b"ProblemType: Crash\nSignal: 11\nCoreDump: base64\n H4sIAAAA\n ZZZZ\nExecutablePath: /after/core\n";
        let out = run(&APPORT, "var/crash/x.crash", report, 0);
        assert!(out.contains(r#""signal":"11""#) && out.contains(r#""executable":"""#), "{out}");
        assert!(run(&APPORT, "var/crash/x.crash", b"hello\n", 0).contains("not an apport report"));
    }

    /// Reports that are not crashes (a failed package installation) have no executable or uid.
    #[test]
    fn apport_package_report_has_no_executable() {
        let report = b"ProblemType: Package\nArchitecture: amd64\nDate: Tue Nov  7 23:20:05 2017\nPackage: example-installer 1.0-1\nErrorMessage: subprocess installed post-installation script returned error exit status 1\n";
        let out = run(&APPORT, "var/crash/example-installer.0.crash", report, 0);
        assert!(
            out.contains(r#""problem_type":"Package","time":"2017-11-07T23:20:05Z""#)
                && out.contains(r#""executable":"","command_line":"","uid":null"#),
            "{out}"
        );
        assert!(out.contains("Package report for"), "{out}");
    }

    #[test]
    fn abrt_directory_is_read_through_the_anchor() {
        let files: [(&str, &[u8]); 8] = [
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/time", b"1700000000\n"),
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/last_occurrence", b"1700000900"),
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/count", b"3"),
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/uid", b"1000"),
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/executable", b"/usr/bin/crashy"),
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/reason", b"crashy killed by SIGSEGV"),
            ("var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/type", b"CCpp"),
            ("etc/passwd", b"alice:x:1000:1000::/home/alice:/bin/bash\n"),
        ];
        let out = run_on_host(&ABRT, &files, "var/spool/abrt/ccpp-2023-11-14-22:13:20-4242/time", 0);
        assert!(
            out.contains(r#""user":"alice""#) && out.contains(r#""count":3"#) && out.contains("(latest occurrence)"),
            "{out}"
        );
        insta::assert_snapshot!(out);
    }

    #[test]
    fn kernel_crash_directory_and_panic_line() {
        let log = b"[    0.000000] Linux version 5.14.0\n[ 1234.5] BUG: unable to handle kernel NULL pointer dereference\n[ 1234.6] Kernel panic - not syncing: Fatal exception\n";
        let out = run(&KERNEL_CRASH, "var/crash/127.0.0.1-2023-11-14-22:13:20/vmcore-dmesg.txt", log, 0);
        assert!(out.contains(r#""time":"2023-11-14T22:13:20Z""#) && out.contains("BUG: unable to handle"), "{out}");
        let out = run(&KERNEL_CRASH, "var/crash/202311142213/dmesg.202311142213", log, 0);
        assert!(out.contains(r#""time":"2023-11-14T22:13:00Z""#), "{out}");
        insta::assert_snapshot!(out);
    }
}

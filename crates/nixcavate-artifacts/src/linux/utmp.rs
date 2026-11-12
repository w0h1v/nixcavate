//! `wtmp`, `btmp` and `utmp`: login records. Format: utmp(5), little-endian, as glibc writes it.
//!
//! The record size depends on the architecture. x86-64 keeps 32-bit session and time fields
//! for compatibility with 32-bit programs (384 bytes); aarch64 uses 64-bit ones (400 bytes).
//! The file does not say which it is, so the layout is chosen by which one makes the records'
//! type fields plausible (see `detect`).

use crate::text::{decompressed, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const WTMP: Artifact =
    Artifact::new("wtmp", "Logins, logouts and boots", Category::Accounts, LINUX, &["var/log/wtmp*"], parse);
pub const BTMP: Artifact =
    Artifact::new("btmp", "Failed login attempts", Category::Accounts, LINUX, &["var/log/btmp*"], parse);
pub const UTMP: Artifact = Artifact::new(
    "utmp",
    "Sessions open at collection time",
    Category::Accounts,
    LINUX,
    &["run/utmp", "var/run/utmp"],
    parse,
);

/// Where the fields after the common 336-byte prefix are.
#[derive(Clone, Copy)]
struct Layout {
    size: usize,
    session: usize,
    secs: usize,
    micros: usize,
    address: usize,
    /// Session and time fields are 8 bytes wide instead of 4.
    wide: bool,
}

const X86_64: Layout = Layout { size: 384, session: 336, secs: 340, micros: 344, address: 348, wide: false };
const AARCH64: Layout = Layout { size: 400, session: 336, secs: 344, micros: 352, address: 360, wide: true };

/// Picks the layout under which more whole records carry a real type (1..=9). Empty slots
/// (type 0) fit every layout and say nothing; a type outside 0..=9 counts against it. A
/// remainder that is not a whole record is ignored, so a trailing byte cannot flip the choice.
/// Ties go to x86-64.
fn detect(data: &[u8]) -> Layout {
    let score = |layout: &Layout| -> i64 {
        data.chunks_exact(layout.size)
            .map(|r| match i16::from_le_bytes([r[0], r[1]]) {
                0 => 0,
                1..=9 => 1,
                _ => -1,
            })
            .sum()
    };
    if score(&AARCH64) > score(&X86_64) {
        AARCH64
    } else {
        X86_64
    }
}

#[derive(Serialize)]
struct Login<'a> {
    time: Timestamp,
    #[serde(rename = "type")]
    kind: &'static str,
    user: Cow<'a, str>,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
    address: String,
    pid: i32,
    id: Cow<'a, str>,
    session: i64,
    exit_termination: i16,
    exit_status: i16,
    #[serde(skip)]
    failed: bool,
}

impl Record for Login<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let (kind, message) = match (self.failed, self.kind) {
            (true, _) => {
                ("failed_login", format!("failed login as {} on {} from {}", self.user, self.line, self.origin()))
            }
            (_, "user_process") => {
                ("login", format!("{} logged in on {} from {}", self.user, self.line, self.origin()))
            }
            (_, "dead_process") => ("logout", format!("session ended on {}", self.line)),
            (_, "boot_time") => ("boot", "system boot".to_string()),
            (_, "run_level") => ("run_level", format!("run level change ({})", self.user)),
            (_, "new_time" | "old_time") => ("time_change", format!("system clock changed ({})", self.kind)),
            // Getty and init bookkeeping carries no analyst-relevant time.
            _ => return None.into_iter(),
        };
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

impl Login<'_> {
    fn origin(&self) -> &str {
        match (self.remote_host.is_empty(), self.address.is_empty()) {
            (false, _) => &self.remote_host,
            (true, false) => &self.address,
            (true, true) => "local",
        }
    }
}

fn type_name(kind: i16) -> Option<&'static str> {
    Some(match kind {
        1 => "run_level",
        2 => "boot_time",
        3 => "new_time",
        4 => "old_time",
        5 => "init_process",
        6 => "login_process",
        7 => "user_process",
        8 => "dead_process",
        9 => "accounting",
        _ => return None,
    })
}

/// A fixed-width, NUL-padded text field.
pub(crate) fn field(bytes: &[u8]) -> Cow<'_, str> {
    lossy(&bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())])
}

fn address(raw: &[u8; 16]) -> String {
    if raw.iter().all(|&b| b == 0) {
        String::new()
    } else if raw[4..].iter().all(|&b| b == 0) {
        Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string()
    } else {
        Ipv6Addr::from(*raw).to_string()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let layout = detect(&data);
    if data.len() % layout.size != 0 {
        sink.warn(format!("size {} is not a multiple of {}; trailing bytes ignored", data.len(), layout.size));
    }
    let failed = input.path.rsplit('/').next().is_some_and(|name| name.starts_with("btmp"));
    for (index, record) in data.chunks_exact(layout.size).enumerate() {
        let offset = (index * layout.size) as u64;
        let i16_at = |at: usize| i16::from_le_bytes([record[at], record[at + 1]]);
        let i32_at = |at: usize| i32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]]);
        let wide_at = |at: usize| match layout.wide {
            true => i64::from(i32_at(at) as u32) | i64::from(i32_at(at + 4)) << 32,
            false => i32_at(at).into(),
        };
        let kind = i16_at(0);
        if kind == 0 {
            continue; // EMPTY slot
        }
        let Some(kind) = type_name(kind) else {
            sink.warn(format!("offset {offset}: unknown record type {kind}"));
            continue;
        };
        let micros = wide_at(layout.micros).clamp(0, 999_999) as u32;
        let mut raw_address = [0u8; 16];
        raw_address.copy_from_slice(&record[layout.address..layout.address + 16]);
        sink.emit(
            Loc::Offset(offset),
            &Login {
                time: Timestamp::from_secs_nanos(
                    wide_at(layout.secs),
                    micros * 1000,
                    Precision::Micros,
                    Basis::Recorded,
                ),
                kind,
                user: field(&record[44..76]),
                line: field(&record[8..40]),
                remote_host: field(&record[76..332]),
                address: address(&raw_address),
                pid: i32_at(4),
                id: field(&record[40..44]),
                session: wide_at(layout.session),
                exit_termination: i16_at(332),
                exit_status: i16_at(334),
                failed,
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// Builds one utmp record the way utmp(5) lays it out.
    fn record(kind: i16, pid: i32, line: &str, user: &str, host: &str, secs: i32, micros: i32, addr: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; X86_64.size];
        r[0..2].copy_from_slice(&kind.to_le_bytes());
        r[4..8].copy_from_slice(&pid.to_le_bytes());
        r[8..8 + line.len()].copy_from_slice(line.as_bytes());
        r[40..44].copy_from_slice(b"ts/0");
        r[44..44 + user.len()].copy_from_slice(user.as_bytes());
        r[76..76 + host.len()].copy_from_slice(host.as_bytes());
        r[340..344].copy_from_slice(&secs.to_le_bytes());
        r[344..348].copy_from_slice(&micros.to_le_bytes());
        r[348..348 + addr.len()].copy_from_slice(addr);
        r
    }

    fn sample() -> Vec<u8> {
        let v6 = "2001:db8::7".parse::<Ipv6Addr>().unwrap().octets();
        [
            record(2, 0, "~", "reboot", "6.1.0-18-amd64", 1_700_000_000, 5, &[]),
            record(7, 4242, "pts/0", "alice", "203.0.113.9", 1_700_000_100, 250_000, &[203, 0, 113, 9]),
            vec![0u8; X86_64.size],
            record(7, 4300, "pts/1", "bob", "", 1_700_000_150, 0, &v6),
            record(8, 4242, "pts/0", "", "", 1_700_000_200, 0, &[]),
            record(42, 1, "x", "x", "x", 1, 0, &[]),
        ]
        .concat()
    }

    #[test]
    fn parses_wtmp() {
        insta::assert_snapshot!(run(&WTMP, "var/log/wtmp", &sample(), 0));
    }

    /// Both fixtures were written by `utmpdump -r` in Debian 12 from `test_files/wtmp/utmpdump.txt`.
    #[test]
    fn real_files_from_both_architectures_parse_the_same() {
        let x86 = run(&WTMP, "var/log/wtmp", &fixture("wtmp/wtmp.x86_64"), 0);
        let arm = run(&WTMP, "var/log/wtmp", &fixture("wtmp/wtmp.aarch64"), 0);
        insta::assert_snapshot!(x86);
        // Offsets differ with the record size; everything else must match.
        let fields = |out: &str| -> Vec<String> {
            out.lines().filter_map(|l| l.split_once("\"time\"").map(|(_, rest)| rest.to_string())).collect()
        };
        assert_eq!(fields(&x86), fields(&arm));
        assert_eq!(fields(&arm).len(), 4);
        assert!(arm.contains("\"source_offset\":400,"));
    }

    #[test]
    fn aarch64_with_a_trailing_byte_keeps_its_layout() {
        let mut data = fixture("wtmp/wtmp.aarch64");
        data.push(0);
        let out = run(&WTMP, "var/log/wtmp", &data, 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 4, "{out}");
        assert!(out.contains("trailing bytes ignored") && out.contains("\"time\":\"20"), "{out}");
    }

    #[test]
    fn size_divisible_by_both_layouts_still_prefers_the_better_one() {
        // 9600 bytes is 24 aarch64 records and 25 x86-64 records.
        let mut data = fixture("wtmp/wtmp.aarch64").repeat(6);
        data[5 * AARCH64.size..5 * AARCH64.size + 2].copy_from_slice(&42i16.to_le_bytes());
        assert_eq!(data.len(), 9600);
        let out = run(&WTMP, "var/log/wtmp", &data, 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 23, "{out}");
        assert!(out.contains("offset 2000: unknown record type 42"), "{out}");
    }

    #[test]
    fn btmp_entries_are_failed_logins() {
        let data = record(6, 99, "ssh:notty", "admin", "198.51.100.4", 1_700_000_300, 0, &[198, 51, 100, 4]);
        insta::assert_snapshot!(run(&BTMP, "var/log/btmp", &data, 0));
    }

    #[test]
    fn truncated_and_empty_files() {
        let mut data = sample();
        data.truncate(X86_64.size + 100);
        let out = run(&WTMP, "var/log/wtmp", &data, 0);
        assert!(out.contains("boot_time") && out.contains("trailing bytes ignored"), "{out}");
        assert!(run(&WTMP, "var/log/wtmp", b"", 0).contains("skipped: empty file"));
    }
}

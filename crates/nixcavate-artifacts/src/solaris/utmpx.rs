//! `wtmpx` and `utmpx`: login records. Format: `struct futmpx` of `utmpx.h` (utmpx(4)), the
//! on-disk form Solaris and illumos write; the files are named `wtmpx` and `utmpx`.
//!
//! Every record is 372 bytes, whatever the architecture: `ut_user[32]`, `ut_id[4]`, `ut_line[32]`,
//! `ut_pid`, `ut_type`, `ut_exit` (two 16-bit values), a 32-bit `ut_tv` (seconds, microseconds),
//! `ut_session`, five reserved words, `ut_syslen` and `ut_host[257]`. There is no address field.
//! The integers are big-endian on SPARC and little-endian on x86; the file does not say, so the
//! order is the one under which more record types are valid (see `big_endian`).
//!
//! Verified on illumos (OmniOS) x86 against `fwtmp` and `last`. The big-endian form (SPARC) and
//! Oracle Solaris 10/11 files are built from the header and the documentation only.

use crate::text::{decompressed, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const WTMPX: Artifact = Artifact::new(
    "wtmpx",
    "Logins, logouts, boots and shutdowns (Solaris/illumos wtmpx)",
    Category::Accounts,
    SOLARIS,
    &["var/adm/wtmpx*", "var/share/adm/wtmpx*", "var/log/wtmpx*"],
    parse,
);
pub const UTMPX: Artifact = Artifact::new(
    "utmpx",
    "Sessions open at collection time (Solaris/illumos utmpx)",
    Category::Accounts,
    SOLARIS,
    &["var/adm/utmpx", "var/run/utmpx", "system/volatile/utmpx", "etc/utmpx", "var/share/adm/utmpx"],
    parse,
);

/// `sizeof(struct futmpx)`.
const SIZE: usize = 372;
/// The highest `ut_type` (`DOWN_TIME`).
const MAX_TYPE: i16 = 10;

fn type_name(kind: i16) -> Option<&'static str> {
    Some(match kind {
        1 => "run_level",
        2 => "boot_time",
        // Solaris numbers them the other way round from Linux: OLD_TIME is 3, NEW_TIME is 4.
        3 => "old_time",
        4 => "new_time",
        5 => "init_process",
        6 => "login_process",
        7 => "user_process",
        8 => "dead_process",
        9 => "accounting",
        10 => "down_time",
        _ => return None,
    })
}

/// True when the integers are big-endian: more whole records then carry a type in 0..=10. A
/// real type read in the wrong order is a multiple of 256, outside the range. Ties are
/// little-endian.
fn big_endian(data: &[u8]) -> bool {
    let score = |big: bool| -> i64 {
        data.chunks_exact(SIZE)
            .map(|r| {
                let bytes = [r[72], r[73]];
                match if big { i16::from_be_bytes(bytes) } else { i16::from_le_bytes(bytes) } {
                    0 => 0,
                    1..=MAX_TYPE => 1,
                    _ => -1,
                }
            })
            .sum()
    };
    score(true) > score(false)
}

#[derive(Serialize)]
struct Login<'a> {
    time: Timestamp,
    #[serde(rename = "type")]
    kind: &'static str,
    user: Cow<'a, str>,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
    pid: i32,
    id: Cow<'a, str>,
    session: i32,
    /// `e_termination` and `e_exit`. For a run-level record they are the new and previous level
    /// as ASCII codes (`51` is `3`).
    exit_termination: i16,
    exit_status: i16,
    /// `ut_syslen`: how many bytes of the host field are significant.
    host_length: i16,
}

impl Record for Login<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let (kind, message) = match self.kind {
            "user_process" => ("login", format!("{} logged in on {} from {from}", self.user, self.line)),
            "dead_process" => ("logout", format!("session ended on {}", self.line)),
            "boot_time" => ("boot", "system boot".to_string()),
            "down_time" => ("shutdown", "system shutdown".to_string()),
            "run_level" => (
                "run_level",
                format!("{} ({}, was {})", self.line, level(self.exit_termination), level(self.exit_status)),
            ),
            "new_time" | "old_time" => ("time_change", format!("system clock changed ({})", self.kind)),
            // init and getty bookkeeping carries no analyst-relevant time.
            _ => return None.into_iter(),
        };
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

/// A run level stored as an ASCII code (`51` is `3`); anything else is shown as the number.
fn level(code: i16) -> String {
    match u8::try_from(code) {
        Ok(b) if b.is_ascii_alphanumeric() => char::from(b).to_string(),
        _ => code.to_string(),
    }
}

/// A fixed-width, NUL-padded text field.
fn field(bytes: &[u8]) -> Cow<'_, str> {
    lossy(&bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())])
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if data.len() < SIZE {
        return Err(Error::format(format!("{} bytes is less than one 372-byte utmpx record", data.len())));
    }
    let big = big_endian(&data);
    if data.len() % SIZE != 0 {
        sink.warn(format!("size {} is not a multiple of {SIZE}; trailing bytes ignored", data.len()));
    }
    for (index, record) in data.chunks_exact(SIZE).enumerate() {
        let offset = (index * SIZE) as u64;
        let i16_at = |at: usize| {
            let bytes = [record[at], record[at + 1]];
            if big {
                i16::from_be_bytes(bytes)
            } else {
                i16::from_le_bytes(bytes)
            }
        };
        let i32_at = |at: usize| {
            let bytes = [record[at], record[at + 1], record[at + 2], record[at + 3]];
            if big {
                i32::from_be_bytes(bytes)
            } else {
                i32::from_le_bytes(bytes)
            }
        };
        let kind = i16_at(72);
        if kind == 0 {
            continue; // EMPTY slot
        }
        let Some(kind) = type_name(kind) else {
            sink.warn(format!("offset {offset}: unknown record type {kind}"));
            continue;
        };
        let micros = i32_at(84).clamp(0, 999_999) as u32;
        sink.emit(
            Loc::Offset(offset),
            &Login {
                time: Timestamp::from_secs_nanos(i32_at(80).into(), micros * 1000, Precision::Micros, Basis::Recorded),
                kind,
                user: field(&record[0..32]),
                line: field(&record[36..68]),
                remote_host: field(&record[114..371]),
                pid: i32_at(68),
                id: field(&record[32..36]),
                session: i32_at(88),
                exit_termination: i16_at(74),
                exit_status: i16_at(76),
                host_length: i16_at(112),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// One 372-byte record laid out as `struct futmpx` of utmpx.h has it.
    fn record(kind: i16, pid: i32, user: &str, line: &str, host: &str, secs: i32, micros: i32, big: bool) -> Vec<u8> {
        let mut r = vec![0u8; SIZE];
        let i16b = |v: i16| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        let i32b = |v: i32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
        r[0..user.len()].copy_from_slice(user.as_bytes());
        r[36..36 + line.len()].copy_from_slice(line.as_bytes());
        r[68..72].copy_from_slice(&i32b(pid));
        r[72..74].copy_from_slice(&i16b(kind));
        r[80..84].copy_from_slice(&i32b(secs));
        r[84..88].copy_from_slice(&i32b(micros));
        r[112..114].copy_from_slice(&i16b(host.len() as i16));
        r[114..114 + host.len()].copy_from_slice(host.as_bytes());
        r
    }

    #[test]
    fn parses_a_real_wtmpx() {
        insta::assert_snapshot!(run(&WTMPX, "var/adm/wtmpx", &fixture("wtmpx/wtmpx"), 0));
    }

    #[test]
    fn parses_a_real_utmpx() {
        insta::assert_snapshot!(run(&UTMPX, "var/adm/utmpx", &fixture("utmpx/utmpx"), 0));
    }

    /// Every field of every record equals what `fwtmp` printed for the same bytes: the pid, the
    /// type, `e_termination` and `e_exit` (octal in fwtmp), seconds and microseconds, the
    /// session, the host length and the host.
    #[test]
    fn every_field_equals_fwtmp() {
        for (artifact, path, file, reference) in [
            (&WTMPX, "var/adm/wtmpx", "wtmpx/wtmpx", "wtmpx/fwtmp.txt"),
            (&UTMPX, "var/adm/utmpx", "utmpx/utmpx", "utmpx/fwtmp.txt"),
        ] {
            let out = run(artifact, path, &fixture(file), 0);
            let rows: Vec<serde_json::Value> =
                out.lines().filter(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap()).collect();
            let reference = String::from_utf8(fixture(reference)).unwrap();
            let lines: Vec<&str> = reference.lines().filter(|l| !l.trim().is_empty()).collect();
            assert_eq!(rows.len(), lines.len(), "{path}");
            let kinds = [
                "",
                "run_level",
                "boot_time",
                "old_time",
                "new_time",
                "init_process",
                "login_process",
                "user_process",
                "dead_process",
                "accounting",
                "down_time",
            ];
            for (row, line) in rows.iter().zip(&lines) {
                // user is the first 32 columns, id the next 4, line the next 32: all padded.
                let fixed = |from: usize, to: usize| line.get(from..to).unwrap_or_default().trim_end().to_string();
                assert_eq!(row["user"], fixed(0, 32).as_str(), "{line}");
                assert_eq!(row["id"], fixed(33, 37).as_str(), "{line}");
                assert_eq!(row["line"], fixed(38, 70).as_str(), "{line}");
                let rest: Vec<&str> = line[70..].split_whitespace().collect();
                let n = |i: usize| rest[i].parse::<i64>().unwrap();
                let octal = |i: usize| i64::from_str_radix(rest[i], 8).unwrap();
                assert_eq!(row["pid"].as_i64().unwrap(), n(0), "{line}");
                assert_eq!(row["type"], kinds[n(1) as usize], "{line}");
                assert_eq!(row["exit_termination"].as_i64().unwrap(), octal(2), "{line}");
                assert_eq!(row["exit_status"].as_i64().unwrap(), octal(3), "{line}");
                let time = row["time"].as_str().unwrap();
                let parsed = nixcavate_core::time::parse_iso8601(time.as_bytes()).unwrap().0;
                assert_eq!(parsed.secs, n(4), "{line}");
                assert_eq!(i64::from(parsed.nanos / 1000), n(5), "{line}");
                assert_eq!(row["session"].as_i64().unwrap(), n(6), "{line}");
                assert_eq!(row["host_length"].as_i64().unwrap(), n(7), "{line}");
                // The host is what follows the host length, before the date (five words).
                let host = if rest.len() > 13 { rest[8] } else { "" };
                assert_eq!(row["remote_host"], host, "{line}");
            }
        }
    }

    #[test]
    fn solaris_numbers_old_and_new_time_the_other_way_round() {
        let data =
            [record(3, 0, "", "old time", "", 1, 0, false), record(4, 0, "", "new time", "", 2, 0, false)].concat();
        let out = run(&WTMPX, "var/adm/wtmpx", &data, 0);
        assert!(out.contains("\"type\":\"old_time\"") && out.contains("\"type\":\"new_time\""), "{out}");
        assert!(out.find("old_time") < out.find("new_time"));
    }

    /// SPARC writes the integers big-endian; the file does not say so.
    #[test]
    fn a_big_endian_file_is_read_as_one() {
        let data = [
            record(2, 0, "", "system boot", "", 1_700_000_000, 0, true),
            record(7, 588, "alice", "pts/2", "", 1_700_000_100, 250_000, true),
            record(8, 588, "alice", "pts/2", "", 1_700_000_200, 0, true),
        ]
        .concat();
        let out = run(&WTMPX, "var/adm/wtmpx", &data, 0);
        assert!(
            out.contains(r#""time":"2023-11-14T22:15:00.250000Z","type":"user_process","user":"alice","line":"pts/2""#),
            "{out}"
        );
        assert!(out.contains(r#""pid":588"#) && !out.contains("warning"), "{out}");
        // The same records little-endian give the same output but for the byte order.
        let little = [
            record(2, 0, "", "system boot", "", 1_700_000_000, 0, false),
            record(7, 588, "alice", "pts/2", "", 1_700_000_100, 250_000, false),
            record(8, 588, "alice", "pts/2", "", 1_700_000_200, 0, false),
        ]
        .concat();
        assert_eq!(out, run(&WTMPX, "var/adm/wtmpx", &little, 0));
    }

    #[test]
    fn timeline_events() {
        let out = run(&WTMPX, "var/adm/wtmpx", &fixture("wtmpx/wtmpx"), 0);
        let timeline = out.split("--- timeline ---\n").nth(1).unwrap();
        assert!(timeline.contains("alice logged in on pts/2 from 127.0.0.1"), "{timeline}");
        assert!(timeline.contains("system boot") && timeline.contains("system shutdown"), "{timeline}");
        assert!(timeline.contains("run-level 3 (3, was S)"), "{timeline}");
    }

    #[test]
    fn short_odd_and_empty_files() {
        assert!(run(&WTMPX, "var/adm/wtmpx", b"", 0).contains("skipped"));
        assert!(run(&WTMPX, "var/adm/wtmpx", &[0u8; 100], 0).contains("failed"));
        let mut data = fixture("wtmpx/wtmpx");
        data.extend_from_slice(b"tail");
        assert!(run(&WTMPX, "var/adm/wtmpx", &data, 0).contains("not a multiple of 372"));
        // A record of an unknown type is one warning, not output.
        let out = run(&WTMPX, "var/adm/wtmpx", &record(42, 1, "x", "x", "x", 1, 0, false), 0);
        assert!(out.contains("unknown record type 42") && !out.contains("\"user\""), "{out}");
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&WTMPX, "var/adm/wtmpx", &fixture("wtmpx/wtmpx"));
        super::super::never_panics(&UTMPX, "var/adm/utmpx", &fixture("utmpx/utmpx"));
    }
}

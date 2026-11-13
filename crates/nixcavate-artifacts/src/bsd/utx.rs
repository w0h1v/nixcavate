//! FreeBSD login databases: `var/log/utx.log` (every login, logout and boot), `utx.lastlogin`
//! (the last login of each user) and `var/run/utx.active` (sessions open now). Format: the
//! `struct futx` of FreeBSD's `lib/libc/gen/utxdb.h`, written from its published layout and
//! checked against `last(1)` and a libc `getutxent` dump of real files:
//!
//! ```text
//! type (1) | time (8, big-endian, microseconds since the epoch) | id (8) | pid (4, big-endian)
//! | user (32) | line (16) | host (up to 128)
//! ```
//!
//! `utx.log` stores each record behind a big-endian 16-bit length and cuts it after the last
//! field its type uses (a boot record is 9 bytes, a dead-process record 21), so the length
//! decides which fields exist. `utx.lastlogin` and `utx.active` hold full 197-byte records
//! back to back with no length.

use crate::linux::utmp::field;
use crate::text::decompressed;
use crate::{Artifact, Category, Input, FREEBSD};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "utx",
    "FreeBSD logins, logouts and boots (utx.log, utx.lastlogin, utx.active)",
    Category::Accounts,
    FREEBSD,
    &["var/log/utx.log*", "var/log/utx.lastlogin*", "var/run/utx.active"],
    parse,
);

/// Type, time, id, pid, user, line, host: the largest record.
const FULL: usize = 1 + 8 + 8 + 4 + 32 + 16 + 128;
/// Type and time: the smallest record.
const SHORTEST: usize = 9;

#[derive(Serialize)]
struct Login<'a> {
    /// `utx.log`, `utx.lastlogin` or `utx.active`.
    database: &'static str,
    time: Timestamp,
    #[serde(rename = "type")]
    kind: &'static str,
    user: Cow<'a, str>,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
    pid: u32,
    id: Cow<'a, str>,
}

impl Record for Login<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let (kind, message) = match self.kind {
            "user_process" => ("login", format!("{} logged in on {} from {from}", self.user, self.line)),
            "dead_process" => ("logout", format!("session ended on {}", self.line)),
            "boot_time" => ("boot", "system boot".to_string()),
            "shutdown_time" => ("shutdown", "system shutdown".to_string()),
            "old_time" | "new_time" => ("time_change", format!("system clock changed ({})", self.kind)),
            _ => return None.into_iter(),
        };
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

fn type_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "boot_time",
        2 => "old_time",
        3 => "new_time",
        4 => "user_process",
        5 => "init_process",
        6 => "login_process",
        7 => "dead_process",
        8 => "shutdown_time",
        _ => return None,
    })
}

/// A field of a possibly cut record: what exists of `from..to`, empty when none does.
fn part(record: &[u8], from: usize, to: usize) -> &[u8] {
    record.get(from..to.min(record.len())).unwrap_or_default()
}

fn record(database: &'static str, rec: &[u8], offset: u64, sink: &mut Sink) -> Result<()> {
    let Some(kind_byte) = rec.first().copied().filter(|&k| k != 0) else { return Ok(()) };
    let Some(kind) = type_name(kind_byte) else {
        sink.warn(format!("offset {offset}: unknown record type {kind_byte}"));
        return Ok(());
    };
    let micros = u64::from_be_bytes(part(rec, 1, 9).try_into().unwrap_or([0; 8]));
    let Some(time) = Timestamp::checked(
        i64::try_from(micros / 1_000_000).unwrap_or(i64::MAX),
        (micros % 1_000_000) as u32 * 1000,
        Precision::Micros,
        Basis::Recorded,
    ) else {
        sink.warn(format!("offset {offset}: time {micros} is out of range"));
        return Ok(());
    };
    let pid = u32::from_be_bytes(part(rec, 17, 21).try_into().unwrap_or([0; 4]));
    sink.emit(
        Loc::Offset(offset),
        &Login {
            database,
            time,
            kind,
            user: field(part(rec, 21, 53)),
            line: field(part(rec, 53, 69)),
            remote_host: field(part(rec, 69, FULL)),
            pid,
            id: field(part(rec, 9, 17)),
        },
    )
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let name = input.path.rsplit('/').next().unwrap_or_default();
    if name.starts_with("utx.log") {
        let mut pos = 0usize;
        while pos < data.len() {
            let Some(length) = data.get(pos..pos + 2).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]]))) else {
                sink.warn(format!("offset {pos}: cut length prefix; stopping"));
                break;
            };
            if !(SHORTEST..=FULL).contains(&length) {
                // There is no marker to find the next record by.
                sink.warn(format!("offset {pos}: record length {length} is not valid; stopping"));
                break;
            }
            let Some(rec) = data.get(pos + 2..pos + 2 + length) else {
                sink.warn(format!("offset {pos}: record of {length} bytes is cut; stopping"));
                break;
            };
            record("utx.log", rec, pos as u64, sink)?;
            pos += 2 + length;
        }
        return Ok(());
    }
    let database = if name.starts_with("utx.lastlogin") { "utx.lastlogin" } else { "utx.active" };
    if data.len() % FULL != 0 {
        sink.warn(format!("size {} is not a multiple of {FULL}; trailing bytes ignored", data.len()));
    }
    for (index, rec) in data.chunks_exact(FULL).enumerate() {
        record(database, rec, (index * FULL) as u64, sink)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// One `utx.log` record: length prefix, then type, microseconds, id, pid, user, line, host.
    fn log_record(kind: u8, micros: u64, user: &str, line: &str, host: &str, pid: u32) -> Vec<u8> {
        let mut body = vec![kind];
        body.extend_from_slice(&micros.to_be_bytes());
        let mut padded = |text: &str, width: usize| {
            let mut field = text.as_bytes().to_vec();
            field.resize(width, 0);
            body.extend_from_slice(&field);
        };
        padded(line, 8);
        body.extend_from_slice(&pid.to_be_bytes());
        let mut padded = |text: &str, width: usize| {
            let mut field = text.as_bytes().to_vec();
            field.resize(width, 0);
            body.extend_from_slice(&field);
        };
        padded(user, 32);
        padded(line, 16);
        body.extend_from_slice(host.as_bytes());
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    #[test]
    fn reads_a_real_log() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/utx.log", &fixture("utx/utx.log"), 0));
    }

    #[test]
    fn reads_the_last_login_and_active_databases() {
        insta::assert_snapshot!("lastlogin", run(&ARTIFACT, "var/log/utx.lastlogin", &fixture("utx/utx.lastlogin"), 0));
        insta::assert_snapshot!("active", run(&ARTIFACT, "var/run/utx.active", &fixture("utx/utx.active"), 0));
    }

    #[test]
    fn a_record_is_cut_after_its_last_used_field() {
        let mut log = log_record(4, 1_700_000_000_123_456, "alice", "pts/3", "198.51.100.7", 4242);
        // A dead-process record keeps only the type, time, id and pid (21 bytes).
        let mut dead = vec![7u8];
        dead.extend_from_slice(&1_700_000_060_000_000u64.to_be_bytes());
        dead.extend_from_slice(b"pts/3\0\0\0");
        dead.extend_from_slice(&4242u32.to_be_bytes());
        log.extend((dead.len() as u16).to_be_bytes());
        log.extend(dead);
        let out = run(&ARTIFACT, "var/log/utx.log", &log, 0);
        assert!(out.contains("\"time\":\"2023-11-14T22:13:20.123456Z\",\"type\":\"user_process\",\"user\":\"alice\",\"line\":\"pts/3\",\"remote_host\":\"198.51.100.7\",\"pid\":4242"), "{out}");
        assert!(out.contains("\"type\":\"dead_process\",\"user\":\"\",\"line\":\"\",\"remote_host\":\"\",\"pid\":4242,\"id\":\"pts/3\""), "{out}");
        assert!(out.contains("alice logged in on pts/3 from 198.51.100.7") && out.contains("session ended"));
    }

    #[test]
    fn a_bad_length_or_a_cut_record_stops_with_one_warning() {
        let good = log_record(1, 1_700_000_000_000_000, "", "", "", 0);
        let mut bad_length = good.clone();
        bad_length.extend([0xff, 0xff, 0x01]);
        let out = run(&ARTIFACT, "var/log/utx.log", &bad_length, 0);
        assert_eq!(out.matches("--- warning").count(), 1, "{out}");
        assert!(out.contains("record length 65535 is not valid"));
        let mut cut = good;
        cut.extend(&log_record(4, 1_700_000_001_000_000, "bob", "pts/0", "h", 1)[..30]);
        let out = run(&ARTIFACT, "var/log/utx.log", &cut, 0);
        assert!(out.contains("is cut; stopping"), "{out}");
        assert!(out.contains("\"type\":\"boot_time\""));
    }

    #[test]
    fn unknown_types_and_empty_slots() {
        let mut db = vec![0u8; FULL * 2];
        db[FULL] = 99; // unknown type in the second slot; the first is empty
        let out = run(&ARTIFACT, "var/run/utx.active", &db, 0);
        assert!(out.contains("unknown record type 99"), "{out}");
        assert!(!out.contains("\"database\""));
        assert!(run(&ARTIFACT, "var/log/utx.log", b"", 0).contains("skipped: empty file"));
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        for (path, name) in [
            ("var/log/utx.log", "utx/utx.log"),
            ("var/log/utx.lastlogin", "utx/utx.lastlogin"),
            ("var/run/utx.active", "utx/utx.active"),
        ] {
            let data = fixture(name);
            for len in 0..data.len().min(1200) {
                run(&ARTIFACT, path, &data[..len], 0);
            }
            for i in (0..data.len()).step_by(3) {
                for mask in [0xff, 0x80, 0x01] {
                    let mut flipped = data.clone();
                    flipped[i] ^= mask;
                    run(&ARTIFACT, path, &flipped, 0);
                }
            }
        }
    }
}

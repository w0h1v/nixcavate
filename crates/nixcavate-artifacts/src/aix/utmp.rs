//! `var/adm/wtmp`, `etc/utmp` and `etc/security/failedlogin`: AIX login records, all arrays of
//! `struct utmp` from `<utmp.h>`. Integers are big-endian (POWER).
//!
//! # Layout and sources
//!
//! The record is 648 bytes. The declaration, as two public sources give it, is
//! `ut_user[256]`, `ut_id[14]`, `ut_line[64]`, `pid_t ut_pid`, `short ut_type`, (in a 32-bit
//! build only, `int __time_t_space`, "for 32vs64-bit time_t PPC"), `time_t ut_time`,
//! `struct { short e_termination; short e_exit; } ut_exit`, `ut_host[256]`, `int
//! __dbl_word_pad`, `int __reservedA[2]`, `int __reservedV[6]`. With natural alignment this puts:
//!
//! | field | offset | width |
//! |---|---|---|
//! | `ut_user` / `ut_id` / `ut_line` | 0 / 256 / 270 | 256 / 14 / 64 |
//! | `ut_pid` | 336 | 4 |
//! | `ut_type` | 340 | 2 |
//! | `ut_time` | 344 (64-bit build, 8 bytes) or 348 (32-bit build, 4 bytes, after the spare word) | |
//! | `ut_exit` | 352 (`e_termination`) and 354 (`e_exit`) | 2 + 2 |
//! | `ut_host` | 356 | 256 |
//!
//! The spare word exists so a 32-bit and a 64-bit program write the same bytes: the low four
//! bytes of the time are at 348 in both, and the high four are zero in a 64-bit record. The
//! reader takes the 32-bit value at 348 as the time. A nonzero value at 344 cannot be a
//! 64-bit time that is not before the year 2106, so it means a 32-bit program left the spare
//! word unset: the time is still read from 348 and one warning says how many records had it.
//!
//! Sources, and how far they agree:
//! 1. A copy of AIX's `utmp.h` kept in a public hobby-OS repository (MartinErhardt/Lizarx,
//!    `host/newlib_files-*/sys/utmp.h`): field order, the `__time_t_space` word, the sizes of
//!    `ut_user`, `ut_id`, `ut_line`, `ut_host`, the `ut_type` constants 0..=9 and the
//!    `BOOT_MSG`/`RUNLVL_MSG`/`OTIME_MSG`/`TIME_MSG` strings.
//! 2. The `libc` crate's AIX bindings (`src/unix/aix/mod.rs`, written against the AIX headers by
//!    IBM contributors): the same field order and widths for the 64-bit build (`pid_t` 4 bytes,
//!    `ut_type` short, `time64_t`).
//! 3. Kaitai Struct's `aix_utmp.ksy` (from IBM's `utmp.h` documentation page) agrees on the
//!    648-byte size and on `ut_time`, `ut_exit` and `ut_host` at 344, 352 and 356, but lists the
//!    pid as 8 bytes at 334 with the type at 342, which would leave the C struct's padding as
//!    the type. It was not taken as the layout; a file whose types sit at 342 and not 340 is
//!    refused rather than guessed (see `detect`).
//!
//! `utmp.h` (1) and `libc` (2) agree on the C declaration; the offsets above are computed from
//! it by `test_files/aix-utmp/make_fixtures.py`, not read from a real file. **No real AIX file
//! was available**: this is "layout confirmed by two sources, synthetic fixtures only".
//! `etc/security/failedlogin` being the same struct is shown by UAC collecting it with
//! `who <file>` (which reads utmp-format files), nothing more: the `ut_type` that
//! `loginfailed()` stores there is unverified, so every non-empty record of that file is a
//! failed login whatever its type says.

use crate::text::{decompressed, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const WTMP: Artifact = Artifact::new(
    "aix-wtmp",
    "AIX logins, logouts and boots",
    Category::Accounts,
    AIX,
    &["var/adm/wtmp*", "var/adm/acct/nite/wtmp*"],
    parse,
);
pub const UTMP: Artifact =
    Artifact::new("aix-utmp", "AIX sessions open at collection time", Category::Accounts, AIX, &["etc/utmp"], parse);
pub const FAILEDLOGIN: Artifact = Artifact::new(
    "aix-failedlogin",
    "AIX failed login attempts",
    Category::Accounts,
    AIX,
    &["etc/security/failedlogin*"],
    parse,
);

pub(crate) const SIZE: usize = 648;
const TYPE_AT: usize = 340;
/// Where the other source's field list would put the type; used only to refuse such a file.
const ALTERNATIVE_TYPE_AT: usize = 342;

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
    exit_termination: i16,
    exit_status: i16,
    #[serde(skip)]
    failed: bool,
}

impl Record for Login<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let origin = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let (kind, message) = match (self.failed, self.kind) {
            (true, _) => ("failed_login", format!("failed login as {} on {} from {origin}", self.user, self.line)),
            (_, "user_process") => ("login", format!("{} logged in on {} from {origin}", self.user, self.line)),
            (_, "dead_process") => ("logout", format!("session ended on {}", self.line)),
            (_, "boot_time") => ("boot", "system boot".to_string()),
            (_, "run_level") => ("run_level", format!("run level change ({})", self.line)),
            (_, "new_time" | "old_time") => ("time_change", format!("system clock changed ({})", self.kind)),
            _ => return None.into_iter(),
        };
        Some(Event::new(self.time, kind, message)).into_iter()
    }
}

fn type_name(kind: i16) -> Option<&'static str> {
    Some(match kind {
        1 => "run_level",
        2 => "boot_time",
        3 => "old_time",
        4 => "new_time",
        5 => "init_process",
        6 => "login_process",
        7 => "user_process",
        8 => "dead_process",
        9 => "accounting",
        _ => return None,
    })
}

fn be16(record: &[u8], at: usize) -> Option<i16> {
    Some(i16::from_be_bytes(record.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn be32(record: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_be_bytes(record.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// A fixed-width, NUL-padded text field.
fn field(record: &[u8], at: usize, width: usize) -> Cow<'_, str> {
    let bytes = record.get(at..at + width).unwrap_or_default();
    lossy(&bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())])
}

/// Refuses a file whose records do not carry a type where the documented layout has it.
///
/// A real file has types 1..=9 (or 0 for an empty slot) at offset 340. When none of the
/// records does, and the file is not all zeros, the file is in another
/// layout or byte order (Linux's 384 or 400 byte little-endian records, a variant that keeps
/// the type at 342, a damaged file): reading it with this layout would be wrong output.
fn detect(data: &[u8]) -> Result<()> {
    let (mut valid, mut invalid, mut alternative) = (0u64, 0u64, 0u64);
    for record in data.chunks_exact(SIZE) {
        match be16(record, TYPE_AT) {
            Some(0) => {}
            Some(1..=9) => valid += 1,
            _ => invalid += 1,
        }
        if matches!(be16(record, ALTERNATIVE_TYPE_AT), Some(1..=9)) {
            alternative += 1;
        }
    }
    // Only empty slots, and nothing else in the file: a cleared file, nothing to refuse.
    if valid > 0 || (invalid == 0 && data.iter().all(|&b| b == 0)) {
        return Ok(());
    }
    let why = if alternative > 0 {
        "the record types are at offset 342, not at 340 as in the documented layout, which was not verified against a real file"
    } else if data.len() % 384 == 0 || data.len() % 400 == 0 {
        "the size is a Linux utmp record size; this is not an AIX file or is little-endian"
    } else {
        "no record has a valid ut_type at offset 340"
    };
    Err(Error::format(format!("not read as an AIX utmp file: {why}")))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if data.len() < SIZE {
        return Err(Error::format(format!("{} bytes is shorter than one 648-byte AIX utmp record", data.len())));
    }
    detect(&data)?;
    if data.len() % SIZE != 0 {
        sink.warn(format!("size {} is not a multiple of {SIZE}; trailing bytes ignored", data.len()));
    }
    let failed = input.path.contains("failedlogin");
    let mut dirty_spare = 0u64;
    for (index, record) in data.chunks_exact(SIZE).enumerate() {
        let offset = (index * SIZE) as u64;
        let Some(kind) = be16(record, TYPE_AT) else { continue };
        if kind == 0 {
            continue; // EMPTY slot
        }
        let Some(name) = type_name(kind) else {
            sink.warn(format!("offset {offset}: unknown record type {kind}"));
            continue;
        };
        if be32(record, 344).is_some_and(|spare| spare != 0) {
            dirty_spare += 1;
        }
        let secs = be32(record, 348).map_or(0, |secs| i64::from(secs as u32));
        sink.emit(
            Loc::Offset(offset),
            &Login {
                time: Timestamp::from_secs(secs, Basis::Recorded),
                kind: name,
                user: field(record, 0, 256),
                line: field(record, 270, 64),
                remote_host: field(record, 356, 256),
                pid: be32(record, 336).unwrap_or(0),
                id: field(record, 256, 14),
                exit_termination: be16(record, 352).unwrap_or(0),
                exit_status: be16(record, 354).unwrap_or(0),
                failed,
            },
        )?;
    }
    if dirty_spare > 0 {
        sink.warn(format!(
            "{dirty_spare} records have a nonzero word before the time (a 32-bit program's unset spare word); \
             their time was read as the 32-bit value after it"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// The fixtures were written by `test_files/aix-utmp/make_fixtures.py` from the C declaration.
    #[test]
    fn a_32_bit_and_a_64_bit_file_read_the_same() {
        let ilp32 = run(&WTMP, "var/adm/wtmp", &fixture("aix-utmp/wtmp.ilp32"), 0);
        let lp64 = run(&WTMP, "var/adm/wtmp", &fixture("aix-utmp/wtmp.lp64"), 0);
        assert_eq!(ilp32, lp64);
        assert!(ilp32.contains(r#""user":"alice","line":"pts/1","remote_host":"203.0.113.9""#), "{ilp32}");
        insta::assert_snapshot!(ilp32);
    }

    #[test]
    fn an_unset_spare_word_is_named_and_the_time_still_read() {
        let clean = run(&WTMP, "var/adm/wtmp", &fixture("aix-utmp/wtmp.ilp32"), 0);
        let dirty = run(&WTMP, "var/adm/wtmp", &fixture("aix-utmp/wtmp.ilp32-dirty-space"), 0);
        assert!(dirty.contains("8 records have a nonzero word before the time"), "{dirty}");
        assert_eq!(dirty.lines().filter(|l| !l.starts_with("--- warning")).count(), clean.lines().count());
        assert!(dirty.contains(r#""time":"2024-03-10T01:00:00.000000Z""#) || dirty.contains("2024-03-10T01:00:00Z"));
    }

    #[test]
    fn failed_logins_come_from_every_record_of_the_file() {
        let out = run(&FAILEDLOGIN, "etc/security/failedlogin", &fixture("aix-utmp/failedlogin.lp64"), 0);
        assert_eq!(out.matches("failed login as").count(), 2, "{out}");
        assert!(out.contains("failed login as admin on ssh from 198.51.100.4"), "{out}");
    }

    #[test]
    fn a_file_with_the_type_at_the_other_offset_is_refused() {
        let out = run(&WTMP, "var/adm/wtmp", &fixture("aix-utmp/wtmp.alt-type-offset"), 0);
        assert!(out.contains("failed: ") && out.contains("offset 342"), "{out}");
        assert!(!out.contains("\"user\""), "{out}");
    }

    #[test]
    fn linux_records_are_refused_by_name() {
        let mut data = vec![0u8; 384 * 3];
        for record in data.chunks_exact_mut(384) {
            record[0] = 7; // little-endian ut_type
        }
        // 1152 is not a multiple of 648: still one clear error, not output.
        let out = run(&WTMP, "var/adm/wtmp", &data, 0);
        assert!(out.contains("failed: "), "{out}");
        let data = vec![7u8; 648 * 2];
        let out = run(&WTMP, "var/adm/wtmp", &data, 0);
        assert!(out.contains("no record has a valid ut_type"), "{out}");
    }

    #[test]
    fn truncated_empty_and_trailing_input() {
        let data = fixture("aix-utmp/wtmp.lp64");
        assert!(run(&WTMP, "var/adm/wtmp", b"", 0).contains("skipped: empty file"));
        assert!(run(&WTMP, "var/adm/wtmp", &data[..647], 0).contains("shorter than one 648-byte"));
        let out = run(&WTMP, "var/adm/wtmp", &data[..648 * 3 + 100], 0);
        assert!(out.contains("trailing bytes ignored") && out.contains("boot_time"), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 3, "{out}");
    }

    #[test]
    fn an_unknown_type_is_one_warning_and_the_rest_is_read() {
        let mut data = fixture("aix-utmp/wtmp.lp64");
        data[648 * 4 + TYPE_AT..648 * 4 + TYPE_AT + 2].copy_from_slice(&42i16.to_be_bytes());
        let out = run(&WTMP, "var/adm/wtmp", &data, 0);
        assert!(out.contains("offset 2592: unknown record type 42"), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 7, "{out}");
    }

    /// Thousands of byte flips and truncations of both fixtures: no panic, no hang.
    #[test]
    fn mutated_files_do_not_panic() {
        let mut runs = 0;
        for name in ["wtmp.ilp32", "wtmp.lp64", "failedlogin.lp64"] {
            let seed = fixture(&format!("aix-utmp/{name}"));
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            for _ in 0..700 {
                let mut data = seed.clone();
                for _ in 0..1 + next() % 6 {
                    let at = (next() % data.len() as u64) as usize;
                    data[at] = next() as u8;
                }
                if next() % 3 == 0 {
                    data.truncate((next() % data.len() as u64) as usize);
                }
                let _ = run(&WTMP, "var/adm/wtmp", &data, 0);
                runs += 1;
            }
            for cut in (0..seed.len()).step_by(97) {
                let _ = run(&UTMP, "etc/utmp", &seed[..cut], 0);
                runs += 1;
            }
        }
        assert!(runs > 2000, "{runs}");
    }
}

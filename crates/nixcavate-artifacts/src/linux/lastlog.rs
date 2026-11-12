//! `/var/log/lastlog`: last login per UID. Format: lastlog(8) and glibc `struct lastlog`:
//! records indexed by UID holding a time, a 32-byte line and a 256-byte host. The time is
//! 32-bit on x86-64 (292-byte records) and 64-bit on aarch64 (296-byte records); the file
//! does not say which, so the layout is chosen by the file length and, when that does not
//! decide, by which one makes the records plausible.

use super::utmp::field;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

pub const ARTIFACT: Artifact =
    Artifact::new("lastlog", "Last login per user", Category::Accounts, LINUX, &["var/log/lastlog"], parse)
        .companions(&["etc/passwd"]);

/// Record sizes: x86-64 (4-byte time), then aarch64 (8-byte time).
const RECORD_SIZES: [usize; 2] = [292, 296];
static ZEROS: [u8; 296] = [0; 296];

#[derive(Serialize)]
struct LastLogin<'a> {
    uid: u64,
    /// From `etc/passwd`; empty when the UID is not listed there.
    user: &'a str,
    /// None when the stored time is 0 although the record is not empty.
    time: Option<Timestamp>,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
}

impl Record for LastLogin<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { format!("uid {}", self.uid) } else { self.user.to_string() };
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let message = format!("{who} last logged in on {} from {from}", self.line);
        self.time.map(|ts| Event::new(ts, "last_login", message)).into_iter()
    }
}

/// Maps UID to the first account that has it, the one `getpwuid` would return.
fn users(passwd: &str) -> HashMap<u64, &str> {
    let mut map = HashMap::new();
    for line in passwd.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split(':');
        if let (Some(name), Some(uid)) = (fields.next(), fields.nth(1).and_then(|f| f.parse().ok())) {
            map.entry(uid).or_insert(name);
        }
    }
    map
}

/// Under the right record size every used record starts its line field with a terminal
/// name (`pts/0`, `tty1`, `ssh`); under the wrong one the fields drift into each other. The
/// score is used records that fit minus those that do not, over whole records only.
fn score(data: &[u8], size: usize) -> i64 {
    let line = size - 288;
    data.chunks_exact(size)
        .filter(|r| *r != &ZEROS[..size])
        .map(|r| if r[line] == 0 || r[line].is_ascii_graphic() { 1 } else { -1 })
        .sum()
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    // A whole file is a whole number of records: when only one size divides the length, that
    // is the layout. Otherwise (both fit, or the file is cut) the records' content decides.
    let [narrow, wide] = RECORD_SIZES;
    let size = match (data.len() % narrow == 0, data.len() % wide == 0) {
        (true, false) => narrow,
        (false, true) => wide,
        _ if score(data, wide) > score(data, narrow) => wide,
        _ => narrow,
    };
    if data.len() % size != 0 {
        sink.warn(format!("size {} is not a multiple of {size}; trailing bytes ignored", data.len()));
    }
    let passwd = input.host.read_text("etc/passwd").unwrap_or_default();
    let users = users(&passwd);
    let line = size - 288;
    // The file is sparse (index = UID), so nearly every record is zero; one memcmp skips it.
    for (uid, record) in data.chunks_exact(size).enumerate().filter(|(_, r)| *r != &ZEROS[..size]) {
        let uid = uid as u64;
        let low = i32::from_le_bytes([record[0], record[1], record[2], record[3]]);
        let secs = match size {
            292 => i64::from(low),
            _ => {
                i64::from(low as u32)
                    | i64::from(i32::from_le_bytes([record[4], record[5], record[6], record[7]])) << 32
            }
        };
        sink.emit(
            Loc::Offset(uid * size as u64),
            &LastLogin {
                uid,
                user: users.get(&uid).copied().unwrap_or(""),
                time: (secs != 0).then(|| Timestamp::from_secs(secs, Basis::Recorded)),
                line: field(&record[line..line + 32]),
                remote_host: field(&record[line + 32..]),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    fn record(secs: i32, line: &str, host: &str) -> Vec<u8> {
        let mut r = vec![0u8; 292];
        r[..4].copy_from_slice(&secs.to_le_bytes());
        r[4..4 + line.len()].copy_from_slice(line.as_bytes());
        r[36..36 + host.len()].copy_from_slice(host.as_bytes());
        r
    }

    /// Records written at the given UID offsets of an otherwise empty (sparse) file.
    fn sparse(entries: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let end = entries.iter().map(|(uid, _)| (uid + 1) * 292).max().unwrap_or(0);
        let mut data = vec![0u8; end];
        for (uid, r) in entries {
            data[uid * 292..(uid + 1) * 292].copy_from_slice(r);
        }
        data
    }

    #[test]
    fn parses_lastlog_with_user_lookup() {
        let files: [(&str, &[u8]); 2] =
            [("var/log/lastlog", &fixture("lastlog/lastlog")), ("etc/passwd", &fixture("lastlog/passwd"))];
        insta::assert_snapshot!(run_on_host(&ARTIFACT, &files, "var/log/lastlog", 0));
    }

    #[test]
    fn sparse_file_with_distant_uids_and_no_passwd() {
        let data = sparse(&[
            (3, record(1_700_000_000, "pts/0", "")),
            (70_000, record(1_700_000_500, "ssh", "web01.example.com")),
        ]);
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/lastlog", &data, 0));
    }

    /// Verified against Debian 12 `lastlog` on arm64, which printed the same three logins.
    #[test]
    fn aarch64_records_are_recognized() {
        let files: [(&str, &[u8]); 2] =
            [("var/log/lastlog", &fixture("lastlog/lastlog.aarch64")), ("etc/passwd", &fixture("lastlog/passwd"))];
        let out = run_on_host(&ARTIFACT, &files, "var/log/lastlog", 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 3, "{out}");
        assert!(
            out.contains("\"uid\":1,\"user\":\"alice\"")
                && out.contains("\"time\":\"2024-03-10T02:00:00Z\",\"line\":\"pts/1\",\"remote_host\":\"2001:db8::7\""),
            "{out}"
        );
    }

    /// One login on aarch64: under the x86-64 size the record's bytes also look plausible,
    /// so only the file length tells the layouts apart.
    #[test]
    fn a_single_aarch64_record_is_told_apart_by_the_file_length() {
        let mut data = vec![0u8; 1001 * 296];
        data[296_000..296_008].copy_from_slice(&1_700_000_000i64.to_le_bytes());
        data[296_008..296_013].copy_from_slice(b"pts/0");
        data[296_040..296_049].copy_from_slice(b"127.0.0.1");
        let out = run(&ARTIFACT, "var/log/lastlog", &data, 0);
        assert!(!out.contains("warning"), "{out}");
        let login = r#""uid":1000,"user":"","time":"2023-11-14T22:13:20Z","line":"pts/0","remote_host":"127.0.0.1""#;
        assert!(out.contains(login), "{out}");
    }

    #[test]
    fn aarch64_with_a_trailing_byte_keeps_its_layout() {
        let mut data = fixture("lastlog/lastlog.aarch64");
        data.push(0);
        let files: [(&str, &[u8]); 2] = [("var/log/lastlog", &data), ("etc/passwd", &fixture("lastlog/passwd"))];
        let out = run_on_host(&ARTIFACT, &files, "var/log/lastlog", 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 3, "{out}");
        assert!(out.contains("2024-03-10T02:00:00Z") && out.contains("trailing bytes ignored"), "{out}");
    }

    #[test]
    fn truncated_last_record_is_dropped_with_a_warning() {
        let mut data =
            sparse(&[(0, record(1_700_000_000, "tty1", "")), (1, record(1_700_000_100, "pts/1", "198.51.100.7"))]);
        data.truncate(292 + 20); // cuts uid 1 inside its line field
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/lastlog", &data, 0));
    }

    #[test]
    fn empty_and_all_zero_inputs() {
        assert!(run(&ARTIFACT, "var/log/lastlog", b"", 0).contains("skipped: empty file"));
        assert_eq!(run(&ARTIFACT, "var/log/lastlog", &vec![0u8; 292 * 200], 0), "");
    }

    #[test]
    fn truncation_and_corruption_never_panic() {
        let data = fixture("lastlog/lastlog");
        for len in (0..data.len()).step_by(7) {
            run(&ARTIFACT, "var/log/lastlog", &data[..len], 0);
        }
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..200 {
            let mut copy = data.clone();
            for _ in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed % copy.len() as u64) as usize;
                copy[at] = (seed >> 32) as u8;
            }
            run(&ARTIFACT, "var/log/lastlog", &copy, 0);
        }
    }
}

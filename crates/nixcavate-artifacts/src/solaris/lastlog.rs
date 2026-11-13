//! `lastlog.v2` and `lastlog`: the last login of each user, indexed by UID.
//!
//! Newer illumos writes `var/adm/lastlog.v2`: 304-byte records of a 64-bit time, `line[32]` and
//! `host[264]`. Oracle Solaris and older illumos write `var/adm/lastlog`: 28-byte records of a
//! 32-bit time, `line[8]` and `host[16]` (`struct lastlog` of `lastlog.h`). A record is at
//! `uid * size`; a record that is all zeros is a user who never logged in.
//!
//! Verified on illumos (OmniOS r151054 and r151060) against the "Last login" line sshd prints.
//! The 28-byte form is from the documentation only. The byte order (big-endian on SPARC) is
//! the one under which more records hold a plausible time.

use crate::text::lossy;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

pub const ARTIFACT: Artifact = Artifact::new(
    "solaris-lastlog",
    "Last login per user (Solaris/illumos lastlog)",
    Category::Accounts,
    SOLARIS,
    &["var/adm/lastlog.v2", "var/adm/lastlog", "var/share/adm/lastlog*"],
    parse,
)
.companions(&["etc/passwd"]);

#[derive(Clone, Copy)]
struct Layout {
    size: usize,
    wide_time: bool,
    line: usize,
    host: usize,
}

const V2: Layout = Layout { size: 304, wide_time: true, line: 32, host: 264 };
const V1: Layout = Layout { size: 28, wide_time: false, line: 8, host: 16 };

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

fn seconds(record: &[u8], layout: Layout, big: bool) -> i64 {
    if layout.wide_time {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&record[..8]);
        if big {
            i64::from_be_bytes(raw)
        } else {
            i64::from_le_bytes(raw)
        }
    } else {
        let raw = [record[0], record[1], record[2], record[3]];
        i64::from(if big { i32::from_be_bytes(raw) } else { i32::from_le_bytes(raw) })
    }
}

fn field(bytes: &[u8]) -> Cow<'_, str> {
    lossy(&bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())])
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let name = input.path.rsplit('/').next().unwrap_or_default();
    let layout = if name.starts_with("lastlog.v2") { V2 } else { V1 };
    if data.len() % layout.size != 0 {
        sink.warn(format!("size {} is not a multiple of {}; trailing bytes ignored", data.len(), layout.size));
    }
    let zeros = vec![0u8; layout.size];
    // Big-endian (SPARC) when more records hold a time this century and not after the file was written.
    let latest = if input.mtime > 0 { input.mtime.saturating_add(86_400) } else { 4_102_444_800 };
    let plausible = |big: bool| {
        let used = data.chunks_exact(layout.size).filter(|r| *r != &zeros[..]);
        used.filter(|r| (946_684_800..=latest).contains(&seconds(r, layout, big))).count()
    };
    let big = plausible(true) > plausible(false);
    let passwd = input.host.read_text("etc/passwd").unwrap_or_default();
    let users = users(&passwd);
    for (uid, record) in data.chunks_exact(layout.size).enumerate().filter(|(_, r)| *r != &zeros[..]) {
        let uid = uid as u64;
        let secs = seconds(record, layout, big);
        sink.emit(
            Loc::Offset(uid * layout.size as u64),
            &LastLogin {
                uid,
                user: users.get(&uid).copied().unwrap_or(""),
                time: (secs != 0).then(|| Timestamp::from_secs(secs, Basis::Recorded)),
                line: field(&record[layout.size - layout.host - layout.line..layout.size - layout.host]),
                remote_host: field(&record[layout.size - layout.host..]),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    /// `lastlog.v2` and `passwd` were copied just before an interactive login whose banner (`banner.txt`)
    /// printed `Last login: Fri Nov 13 01:21:33 2026 from 127.0.0.1`: the record of that user says the same.
    #[test]
    fn a_real_lastlog_v2_equals_the_ssh_banner() {
        let files: [(&str, &[u8]); 2] = [
            ("var/adm/lastlog.v2", &fixture("solaris-lastlog/lastlog.v2")),
            ("etc/passwd", &fixture("solaris-lastlog/passwd")),
        ];
        let out = run_on_host(&ARTIFACT, &files, "var/adm/lastlog.v2", 0);
        insta::assert_snapshot!(out);
        let banner = String::from_utf8(fixture("solaris-lastlog/banner.txt")).unwrap();
        assert!(banner.contains("Last login: Fri Nov 13 01:21:33 2026 from 127.0.0.1"));
        assert!(
            out.contains(r#""user":"alice","time":"2026-11-13T01:21:33Z","line":"ssh","remote_host":"127.0.0.1""#),
            "{out}"
        );
    }

    fn v1(secs: i32, line: &str, host: &str) -> Vec<u8> {
        let mut r = vec![0u8; 28];
        r[..4].copy_from_slice(&secs.to_le_bytes());
        r[4..4 + line.len()].copy_from_slice(line.as_bytes());
        r[12..12 + host.len()].copy_from_slice(host.as_bytes());
        r
    }

    /// The 28-byte form, from `lastlog.h`: a 32-bit time, `line[8]` and `host[16]`, indexed by uid.
    #[test]
    fn the_old_28_byte_records_are_read() {
        let mut data = vec![0u8; 28 * 3];
        data[28 * 2..].copy_from_slice(&v1(1_700_000_000, "pts/3", "192.0.2.7"));
        let out = run(&ARTIFACT, "var/adm/lastlog", &data, 0);
        assert!(
            out.contains(r#""uid":2,"user":"","time":"2023-11-14T22:13:20Z","line":"pts/3","remote_host":"192.0.2.7""#),
            "{out}"
        );
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 1);
        // SPARC: big-endian.
        let mut be = v1(0, "pts/3", "h");
        be[..4].copy_from_slice(&1_700_000_000i32.to_be_bytes());
        assert!(run(&ARTIFACT, "var/adm/lastlog", &be, 1_700_000_100).contains("2023-11-14T22:13:20Z"));
    }

    #[test]
    fn empty_cut_and_mutated_files() {
        assert!(run(&ARTIFACT, "var/adm/lastlog.v2", b"", 0).contains("skipped"));
        let data = fixture("solaris-lastlog/lastlog.v2");
        assert!(run(&ARTIFACT, "var/adm/lastlog.v2", &data[..data.len() - 5], 0).contains("not a multiple of 304"));
        super::super::never_panics(&ARTIFACT, "var/adm/lastlog.v2", &data);
    }
}
